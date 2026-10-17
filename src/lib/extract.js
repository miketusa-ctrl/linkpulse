// Link extraction from HTML. Regex-based tokenizer (pure JS, runs in Node tests and Workers).
// Not a full HTML5 parser: comments, <script>/<style>/<template>/<textarea> contents are skipped,
// attribute values are entity-decoded, <base href> is honoured.

export const MAX_EXTRACTED = 2000;

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0', sol: '/', colon: ':', period: '.', quest: '?', equals: '=', num: '#', percnt: '%', lpar: '(', rpar: ')', tab: '\t', newline: '\n' };
export function decodeEntities(s) {
  return String(s).replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);?/gi, (m, e) => {
    if (e[0] === '#') {
      const cp = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      if (!Number.isFinite(cp) || cp <= 0 || cp > 0x10ffff) return '\ufffd';
      try { return String.fromCodePoint(cp); } catch { return '\ufffd'; }
    }
    const v = ENTITIES[e.toLowerCase()];
    return v !== undefined ? v : m;
  });
}

// Only tags that can carry links are matched (much less CPU on multi-MB pages than tokenizing every tag).
const TAG_RE = /<(a|area|img|script|link|iframe|frame|source|video|audio|track|embed|object|base)(?=[\s\/>])((?:\s+[^\s"'>\/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'=<>`]+))?)*)\s*\/?>/gi;
const ATTR_RE = /([^\s"'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

const WANTED_ATTRS = new Set(['href', 'src', 'srcset', 'rel', 'poster', 'data']);
/** Parses attributes. opts.only (Set) limits which attributes are kept/decoded (CPU saver on big pages). */
export function parseAttrs(s, { only } = {}) {
  const out = {};
  if (!s) return out;
  ATTR_RE.lastIndex = 0;
  let m;
  while ((m = ATTR_RE.exec(s))) {
    const name = m[1].toLowerCase();
    if (name in out || (only && !only.has(name))) continue; // HTML: first occurrence wins
    const v = m[2] ?? m[3] ?? m[4] ?? '';
    out[name] = v.includes('&') ? decodeEntities(v) : v;
  }
  return out;
}

/** Strips comments and raw-text element contents (keeps the opening tag so <script src> survives). */
export function stripNonMarkup(html) {
  // One pass instead of five (each pass copies the whole page; matters for multi-MB pages).
  return String(html).replace(
    /<!--[\s\S]*?(?:-->|$)|(<script\b[^>]*>)[\s\S]*?(?:<\/script\s*>|$)|(<style\b[^>]*>)[\s\S]*?(?:<\/style\s*>|$)|<template\b[^>]*>[\s\S]*?(?:<\/template\s*>|$)|(<textarea\b[^>]*>)[\s\S]*?(?:<\/textarea\s*>|$)|<!\[CDATA\[[\s\S]*?\]\]>/gi,
    (m, sc, st, ta) => sc || st || ta || ' ',
  );
}

const LINK_REL_SKIP = new Set(['preconnect', 'dns-prefetch', 'prerender', 'prefetch', 'pingback', 'webmention', 'search', 'openid.server', 'openid.delegate']);
// tag -> list of [attribute, kind]
const SOURCES = {
  a: [['href', 'link']],
  area: [['href', 'link']],
  img: [['src', 'image'], ['srcset', 'image']],
  script: [['src', 'script']],
  link: [['href', 'resource']],
  iframe: [['src', 'iframe']],
  frame: [['src', 'iframe']],
  source: [['src', 'media'], ['srcset', 'image']],
  video: [['src', 'media'], ['poster', 'image']],
  audio: [['src', 'media']],
  track: [['src', 'media']],
  embed: [['src', 'embed']],
  object: [['data', 'embed']],
};
export const ASSET_KINDS = new Set(['image', 'script', 'stylesheet', 'icon', 'resource', 'iframe', 'media', 'embed']);
// Mixed content per the W3C spec: "blockable" (active) vs "upgradeable/optionally-blockable" (passive).
export const ACTIVE_MIXED = new Set(['script', 'stylesheet', 'iframe', 'embed', 'resource']);

function srcsetUrls(v) {
  // "a.jpg 1x, b.jpg 2x" -> ["a.jpg","b.jpg"] (URLs may contain commas only if not followed by space; good enough)
  return v.split(/,\s+|,(?=\S+\s+\d)/).map((c) => c.trim().split(/\s+/)[0]).filter(Boolean);
}

const SKIP_SCHEMES = /^(mailto|tel|sms|javascript|data|blob|about|ftp|file|irc|ircs|magnet|skype|whatsapp|callto|geo|market|intent|chrome|view-source|ws|wss|urn|news|nntp|git|ssh|sftp|webcal|bitcoin|spotify|steam|zoommtg|msteams|slack|fb|tg|viber):/i;

/**
 * Extracts links from HTML. Returns { links: [{url, kind, tag, attr, count, firstIndex}], skipped: {reason: count}, base, total }.
 * opts.assets=false limits to <a>/<area> hrefs.
 */
export function extractLinks(html, pageUrl, { assets = true, max = MAX_EXTRACTED } = {}) {
  const src = stripNonMarkup(html);
  let base;
  try { base = new URL(pageUrl); } catch { throw new Error('invalid page URL'); }
  const skipped = {};
  const skip = (r) => { skipped[r] = (skipped[r] || 0) + 1; };
  const map = new Map();
  let total = 0;
  let baseSet = false;
  let truncated = false;
  TAG_RE.lastIndex = 0;
  let m;
  let order = 0;
  while ((m = TAG_RE.exec(src))) {
    const tag = m[1].toLowerCase();
    if (tag === 'base' && !baseSet) {
      const a = parseAttrs(m[2], { only: WANTED_ATTRS });
      if (a.href !== undefined) { try { const b = new URL(a.href.trim(), base); if (b.protocol === 'http:' || b.protocol === 'https:') base = b; } catch { /* ignore */ } baseSet = true; }
      continue;
    }
    const spec = SOURCES[tag];
    if (!spec) continue;
    if (!assets && tag !== 'a' && tag !== 'area') continue;
    const attrs = parseAttrs(m[2], { only: WANTED_ATTRS });
    for (const [attr, kind0] of spec) {
      const val = attrs[attr];
      if (val === undefined) continue;
      let kind = kind0;
      if (tag === 'link') {
        const rels = (attrs.rel || '').toLowerCase().split(/\s+/).filter(Boolean);
        if (!rels.length || rels.some((r) => LINK_REL_SKIP.has(r))) { skip('link_rel_hint'); continue; }
        if (rels.includes('stylesheet')) kind = 'stylesheet';
        else if (rels.some((r) => r.includes('icon'))) kind = 'icon';
        else if (rels.includes('canonical') || rels.includes('alternate') || rels.includes('next') || rels.includes('prev') || rels.includes('author') || rels.includes('license')) kind = 'link';
        else kind = 'resource';
      }
      const values = attr === 'srcset' ? srcsetUrls(val) : [val];
      for (let v of values) {
        total++;
        v = v.trim();
        if (!v) { skip('empty'); continue; }
        if (v.startsWith('#')) { skip('fragment_only'); continue; }
        if (SKIP_SCHEMES.test(v)) { skip('non_http_scheme'); continue; }
        let u;
        try { u = new URL(v, base); } catch { skip('unparseable'); continue; }
        if (u.protocol !== 'http:' && u.protocol !== 'https:') { skip('non_http_scheme'); continue; }
        u.hash = '';
        const key = u.href;
        const e = map.get(key);
        if (e) {
          e.count++;
          if (ACTIVE_MIXED.has(kind) && !ACTIVE_MIXED.has(e.kind)) e.kind = kind; // strongest kind wins (mixed-content severity)
          else if (e.kind === 'link' && kind !== 'link') e.kind = kind;
          continue;
        }
        if (map.size >= max) { truncated = true; skip('over_extract_cap'); continue; }
        map.set(key, { url: key, kind, tag, attr, count: 1, order: order++ });
      }
    }
  }
  return { links: [...map.values()], skipped, base: base.href, total, truncated };
}
