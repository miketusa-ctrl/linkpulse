// Check orchestrator: fetch ONE page -> extract links -> check up to LIMITS.maxLinks links
// (HEAD, GET fallback, manual redirects). EVERY request target (page hops, link URLs, link redirect hops)
// gets the static SSRF rules AND a DNS-over-HTTPS check that all A/AAAA answers are public (cached per host
// within one check). A hard subrequest budget keeps each check bounded (Workers Paid allows 10,000/invocation).
import { normalizeTarget, checkUrl, urlProblem, TargetError } from './target.js';
import { HostResolver } from './dns.js';
import { extractLinks, ASSET_KINDS, ACTIVE_MIXED } from './extract.js';

export const VERSION = '0.3.1';
export const SCHEMA = 'linkpulse.check.v1';
// Workers Paid plan defaults (v0.2.0). v0.1.0 (Workers Free) used maxLinks 40, subrequestBudget 45,
// pageTimeoutMs 8000, linkTimeoutMs 6000, deadlineMs 25000, maxPageBytes 1.5 MB, no DoH for links.
export const LIMITS = Object.freeze({
  pagesPerCheck: 1,
  maxLinks: 200,           // links fetched per check (upper bound and default for ?max=)
  maxHops: 10,             // redirects followed per URL
  longChainRedirects: 3,   // >= this many redirects -> long_chain flag
  subrequestBudget: 1000,  // all outbound fetches incl. DoH; Workers Paid limit is 10,000 per invocation
  pageTimeoutMs: 10000,
  linkTimeoutMs: 8000,
  dnsTimeoutMs: 2500,
  deadlineMs: 45000,       // after this, remaining links are reported as unchecked
  maxPageBytes: 3000000,
  concurrency: 6,          // Workers allow 6 connections waiting for headers per invocation (others queue)
  maxBlockedListed: 100,
  maxExtracted: 5000,
});
// Free-plan fallback values (used if env PLAN_LIMITS="free"; see wrangler.toml).
export const FREE_PLAN_LIMITS = Object.freeze({ ...LIMITS, maxLinks: 40, subrequestBudget: 45, deadlineMs: 25000, pageTimeoutMs: 8000, linkTimeoutMs: 6000, maxPageBytes: 1500000, dnsForLinks: false });

/** Effective limits for this deployment (env overrides are clamped to the paid defaults). */
export function limitsFor(env = {}) {
  const base = String(env.PLAN_LIMITS || 'paid') === 'free' ? FREE_PLAN_LIMITS : { ...LIMITS, dnsForLinks: true };
  const num = (v, max) => { const n = Math.floor(Number(v)); return Number.isFinite(n) && n > 0 ? Math.min(n, max) : undefined; };
  return Object.freeze({
    ...base,
    maxLinks: num(env.MAX_LINKS, LIMITS.maxLinks) ?? base.maxLinks,
    subrequestBudget: num(env.SUBREQUEST_BUDGET, 9000) ?? base.subrequestBudget,
  });
}
export const USER_AGENT = 'Mozilla/5.0 (compatible; LinkPulse/0.1; +https://linkpulse.mike-tusa.workers.dev/docs)';
const REDIRECT = new Set([301, 302, 303, 307, 308]);

export class CheckError extends Error {
  constructor(code, message, httpStatus = 502, extra = {}) { super(message); this.code = code; this.httpStatus = httpStatus; Object.assign(this, extra); }
}

export class Budget {
  constructor(max) { this.max = max; this.used = 0; }
  tryTake() { if (this.used >= this.max) return false; this.used++; return true; }
  take() { if (!this.tryTake()) throw new CheckError('budget_exceeded', 'Subrequest budget exhausted.', 502); }
  get left() { return this.max - this.used; }
}

const clip = (s, n) => { s = String(s ?? ''); return s.length > n ? s.slice(0, n) + '…' : s; };

export function classifyFetchError(e, aborted) {
  if (aborted) return 'timeout';
  if (/too many subrequests/i.test(String(e && e.message))) return 'subrequest_limit';
  const msg = String(e && (e.message || e)).toLowerCase() + ' ' + String(e && e.cause && (e.cause.code || e.cause.message) || '').toLowerCase();
  if (/enotfound|eai_again|getaddrinfo|dns|name not resolved|could not resolve/.test(msg)) return 'dns_error';
  if (/certificate|tls|ssl|handshake/.test(msg)) return 'tls_error';
  return 'connect_error';
}
const ERROR_TEXT = {
  timeout: 'No response within the time limit',
  dns_error: 'DNS lookup failed (host not found)',
  tls_error: 'TLS/certificate error',
  connect_error: 'Could not connect (connection refused/reset, DNS or TLS error)',
  origin_unreachable: 'Cloudflare could not reach the origin (HTTP 530: DNS or origin error)',
  redirect_loop: 'Redirect loop',
  too_many_redirects: 'Too many redirects',
  bad_redirect: 'Invalid redirect Location header',
  blocked_redirect: 'Redirect points to a blocked (non-public) target; not followed',
  dns_not_found: 'DNS lookup failed: the host does not exist (NXDOMAIN) or has no A/AAAA records',
  dns_check_failed: 'Not checked: the DNS safety lookup failed (resolver error)',
  http_error: 'HTTP error status',
  subrequest_limit: 'the platform subrequest limit was reached',
};

/** One request, manual redirects, body cancelled unread. Throws {code} on network failure/timeout. */
async function fetchOnce(fetchImpl, url, method, { timeoutMs, deadline }) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw Object.assign(new Error('deadline'), { code: 'deadline' });
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), Math.min(timeoutMs, remaining));
  const t0 = Date.now();
  try {
    const res = await fetchImpl(url, {
      method, redirect: 'manual', signal: ctl.signal,
      headers: { 'user-agent': USER_AGENT, accept: method === 'HEAD' ? '*/*' : 'text/html,application/xhtml+xml,*/*;q=0.8', 'accept-language': 'en' },
    });
    try { await res.body?.cancel(); } catch { /* closed */ }
    return { status: res.status, location: res.headers.get('location'), cfMitigated: !!res.headers.get('cf-mitigated'), ms: Date.now() - t0 };
  } catch (e) {
    throw Object.assign(new Error('fetch failed'), { code: classifyFetchError(e, ctl.signal.aborted) });
  } finally { clearTimeout(t); }
}

/**
 * Follows redirects manually (max LIMITS.maxHops), re-validating every hop with the static SSRF rules.
 * hops = every request made: {url, status, location?, ms, method}. Never throws.
 */
export async function followChain(start, method, ctx, prior = []) {
  const hops = [...prior];
  const visited = new Set(hops.map((h) => h.url));
  let url = start;
  for (;;) {
    if (hops.length) {
      const p = urlProblem(url, { selfHosts: ctx.selfHosts });
      if (p) return { hops, url, error: 'blocked_redirect', detail: p };
    }
    if (ctx.resolver && ctx.dnsForLinks) {
      // DNS SSRF check for this hop's host (cached per host for this check).
      try { await ctx.resolver.assertPublic(url.hostname); } catch (e) {
        if (e?.code === 'budget_exceeded') return { hops, url, error: 'budget' };
        if (/too many subrequests/i.test(String(e?.message))) { ctx.budget.used = ctx.budget.max; return { hops, url, error: 'budget' }; }
        if (e instanceof TargetError && e.code === 'blocked_target') return { hops, url, error: hops.length ? 'blocked_redirect' : 'blocked_dns', detail: { code: 'blocked_target', message: e.message } };
        if (e instanceof TargetError && e.code === 'dns_not_found') return { hops, url, error: 'dns_not_found', detail: { message: e.message } };
        return { hops, url, error: 'dns_check_failed' };
      }
    }
    if (!ctx.budget.tryTake()) return { hops, url, error: 'budget' };
    let r;
    try { r = await fetchOnce(ctx.fetchImpl, url.href, method, { timeoutMs: ctx.timeoutMs, deadline: ctx.deadline }); } catch (e) {
      if (e.code === 'subrequest_limit') { ctx.budget.used = ctx.budget.max; return { hops, url, error: 'budget' }; } // platform cap hit (e.g. Free plan): stop cleanly
      return { hops, url, error: e.code === 'deadline' ? 'deadline' : e.code };
    }
    visited.add(url.href);
    const hop = { url: url.href, status: r.status, ms: r.ms, method };
    if (REDIRECT.has(r.status) && r.location) {
      let next;
      try { next = new URL(r.location, url); } catch { hop.location = clip(r.location, 300); hops.push(hop); return { hops, url, error: 'bad_redirect', status: r.status }; }
      next.hash = '';
      hop.location = clip(next.href, 2048);
      hops.push(hop);
      if (visited.has(next.href)) return { hops, url, error: 'redirect_loop', status: r.status };
      if (hops.filter((h) => h.location).length >= ctx.maxHops) return { hops, url: next, error: 'too_many_redirects', status: r.status };
      url = next;
      continue;
    }
    hops.push(hop);
    return { hops, url, status: r.status, cfMitigated: r.cfMitigated };
  }
}

/** Checks one extracted link. Never throws. */
export async function checkLink(link, ctx) {
  const t0 = Date.now();
  const out = { url: link.url, kind: link.kind, tag: link.tag, count: link.count, category: 'ok', status: null, finalUrl: null, method: 'HEAD', redirects: 0, hops: [], ms: 0, error: null, flags: [] };
  const start = new URL(link.url);
  // Static flags (no fetch needed)
  if (ctx.pageHttps && start.protocol === 'http:') {
    if (ASSET_KINDS.has(link.kind)) out.flags.push(ACTIVE_MIXED.has(link.kind) ? 'mixed_content_active' : 'mixed_content_passive');
    else out.flags.push('insecure_link');
  }
  let r = await followChain(start, 'HEAD', ctx);
  // GET fallback: many servers mishandle HEAD (405/403/404/501…) or reset it. Retry the failing URL with GET,
  // keeping the redirect hops HEAD already followed.
  const headFailed = (r.status >= 400) || r.status === 0 || r.error === 'connect_error' || r.error === 'tls_error';
  if (headFailed && !['budget', 'deadline', 'blocked_redirect', 'blocked_dns', 'dns_not_found', 'dns_check_failed'].includes(r.error)) {
    const prior = r.status ? r.hops.slice(0, -1) : r.hops;
    const headStatus = r.status || null;
    const g = await followChain(r.url, 'GET', ctx, prior);
    if (g.error !== 'budget' && g.error !== 'deadline') {
      out.method = 'GET';
      if (headStatus && !(g.status >= 400) && !g.error) out.flags.push('head_not_supported');
      r = g;
    } else if (!r.error) {
      out.flags.push('get_fallback_skipped');
    }
  }
  out.hops = r.hops;
  out.redirects = r.hops.filter((h) => h.location).length;
  out.ms = Date.now() - t0;
  const last = r.hops[r.hops.length - 1];
  out.status = r.status ?? (last ? last.status : null);
  out.finalUrl = r.error ? null : r.url.href;
  if (out.redirects >= LIMITS.longChainRedirects) out.flags.push('long_chain');
  // https -> http downgrade anywhere in the chain
  if (r.hops.some((h) => h.url.startsWith('https:') && h.location && h.location.startsWith('http:'))) out.flags.push('https_downgrade');

  if (r.error === 'budget' || r.error === 'deadline') {
    out.category = 'unchecked';
    out.error = { code: r.error === 'budget' ? 'subrequest_budget' : 'deadline', message: r.error === 'budget' ? 'Not checked: per-request subrequest budget used up.' : 'Not checked: overall time limit reached.' };
    return out;
  }
  if (r.error === 'dns_check_failed') {
    out.category = 'unchecked';
    out.error = { code: 'dns_check_failed', message: ERROR_TEXT.dns_check_failed };
    return out;
  }
  if (r.error === 'blocked_dns') {
    out.category = 'blocked';
    out.flags.push('resolves_private');
    out.error = { code: 'blocked_target', message: r.detail.message };
    return out;
  }
  if (r.error === 'dns_not_found') {
    out.category = 'broken';
    out.error = { code: 'dns_error', message: r.detail.message };
    return out;
  }
  if (r.error === 'blocked_redirect') {
    if (/resolves to a non-public address/.test(r.detail.message)) out.flags.push('resolves_private');
    out.category = 'blocked';
    out.flags.push('blocked_redirect');
    out.error = { code: 'blocked_redirect', message: `${ERROR_TEXT.blocked_redirect}: ${r.url.href} (${r.detail.message})`, blockedUrl: r.url.href };
    return out;
  }
  if (r.error) {
    out.category = 'broken';
    if (r.error === 'redirect_loop' || r.error === 'too_many_redirects') out.flags.push(r.error);
    out.error = { code: r.error, message: ERROR_TEXT[r.error] || r.error };
    return out;
  }
  if (out.status === 530) {
    out.category = 'broken';
    out.error = { code: 'origin_unreachable', message: ERROR_TEXT.origin_unreachable };
  } else if (out.status >= 400 || out.status < 100) {
    out.category = 'broken';
    out.error = { code: 'http_error', message: `HTTP ${out.status}` };
    if ([401, 403, 429, 999].includes(out.status) || r.cfMitigated) out.flags.push('maybe_bot_blocked');
  } else if (out.redirects > 0) out.category = 'redirect';
  return out;
}

async function pool(items, n, fn) {
  const results = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; results[k] = await fn(items[k], k); }
  });
  await Promise.all(workers);
  return results;
}

async function readCapped(res, maxBytes) {
  if (!res.body) return { text: '', bytes: 0, truncated: false };
  const reader = res.body.getReader();
  const chunks = [];
  let bytes = 0;
  let truncated = false;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const take = Math.min(value.byteLength, maxBytes - bytes);
    chunks.push(take === value.byteLength ? value : value.subarray(0, take));
    bytes += take;
    if (bytes >= maxBytes) { truncated = true; try { await reader.cancel(); } catch { /* */ } break; }
  }
  const buf = new Uint8Array(bytes);
  let o = 0;
  for (const c of chunks) { buf.set(c, o); o += c.byteLength; }
  return { text: new TextDecoder('utf-8', { fatal: false }).decode(buf), bytes, truncated };
}

/** Fetches the page: manual redirects, static + DoH SSRF check on every hop, capped body. Throws CheckError/TargetError. */
async function fetchPage(startUrl, ctx) {
  const L = ctx.L;
  const hops = [];
  let url = startUrl;
  for (;;) {
    try {
      checkUrl(url, { selfHosts: ctx.selfHosts });
      await ctx.resolver.assertPublic(url.hostname);
    } catch (e) {
      if (e instanceof TargetError && hops.length) {
        if (['blocked_target', 'blocked_port', 'invalid_scheme', 'invalid_url', 'credentials_in_url'].includes(e.code)) { e.code = 'blocked_redirect'; e.httpStatus = 403; }
        e.message = `Redirect blocked: ${e.message}`;
      }
      if (e instanceof CheckError || e instanceof TargetError) { e.redirects = hops; throw e; }
      throw e;
    }
    if (!ctx.budget.tryTake()) throw new CheckError('budget_exceeded', 'Subrequest budget exhausted while fetching the page.', 502, { redirects: hops });
    const remaining = ctx.deadline - Date.now();
    const ctl = new AbortController();
    const tmo = Math.min(L.pageTimeoutMs, remaining);
    const timer = setTimeout(() => ctl.abort(), tmo);
    const t0 = Date.now();
    try {
      let res;
      try {
        res = await ctx.fetchImpl(url.href, { method: 'GET', redirect: 'manual', signal: ctl.signal, headers: { 'user-agent': USER_AGENT, accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.5', 'accept-language': 'en' } });
      } catch (e) {
        const code = classifyFetchError(e, ctl.signal.aborted);
        throw new CheckError(code === 'timeout' ? 'page_timeout' : 'page_fetch_failed', code === 'timeout' ? `No response from ${url.host} within ${Math.round(tmo / 1000)} s.` : `Could not fetch ${url.host}: ${ERROR_TEXT[code]}.`, code === 'timeout' ? 504 : 502, { redirects: hops });
      }
      const loc = res.headers.get('location');
      const hop = { url: url.href, status: res.status, ms: Date.now() - t0, method: 'GET' };
      if (REDIRECT.has(res.status) && loc) {
        try { await res.body?.cancel(); } catch { /* */ }
        let next;
        try { next = new URL(loc, url); } catch { hop.location = clip(loc, 300); hops.push(hop); throw new CheckError('bad_redirect', 'The page sent an invalid redirect Location.', 502, { redirects: hops }); }
        next.hash = '';
        hop.location = clip(next.href, 2048);
        hops.push(hop);
        if (hops.some((h) => h.url === next.href)) throw new CheckError('redirect_loop', 'The page redirects in a loop.', 502, { redirects: hops });
        if (hops.length >= L.maxHops) throw new CheckError('too_many_redirects', `More than ${L.maxHops} redirects; stopped.`, 502, { redirects: hops });
        url = next;
        continue;
      }
      const ct = res.headers.get('content-type') || '';
      const isHtml = /text\/html|application\/xhtml\+xml/i.test(ct) || (!ct);
      let body = { text: '', bytes: 0, truncated: false };
      if (isHtml && res.status < 400) {
        try { body = await readCapped(res, L.maxPageBytes); } catch (e) {
          throw new CheckError(ctl.signal.aborted ? 'page_timeout' : 'page_fetch_failed', ctl.signal.aborted ? 'The page body did not finish downloading in time.' : 'The page body could not be read.', ctl.signal.aborted ? 504 : 502, { redirects: hops });
        }
      } else { try { await res.body?.cancel(); } catch { /* */ } }
      hop.ms = Date.now() - t0;
      hops.push(hop);
      return { finalUrl: url, status: res.status, contentType: clip(ct, 200), isHtml, body, hops, cfMitigated: !!res.headers.get('cf-mitigated') };
    } finally { clearTimeout(timer); }
  }
}

/**
 * Runs a full check. opts: { fetchImpl, selfHosts, resolver, assets=true, max=L.maxLinks, now }.
 * Throws TargetError (bad/blocked input) or CheckError (page could not be fetched).
 */
export async function runCheck(input, opts = {}) {
  const started = Date.now();
  const L = opts.limits || limitsFor({});
  const fetchImpl = opts.fetchImpl || ((...a) => fetch(...a));
  const selfHosts = opts.selfHosts || [];
  const max = Math.max(1, Math.min(L.maxLinks, Number.isFinite(+opts.max) && +opts.max > 0 ? Math.floor(+opts.max) : L.maxLinks));
  const assets = opts.assets !== false;
  const budget = new Budget(opts.budget || L.subrequestBudget);
  const resolver = opts.resolver || new HostResolver({ fetchImpl, budget, timeoutMs: L.dnsTimeoutMs });
  if (!resolver.budget) resolver.budget = budget;
  const deadline = started + (opts.deadlineMs || L.deadlineMs);
  const { url } = normalizeTarget(input, { selfHosts });
  const notes = [];
  const truncatedReasons = [];

  const page = await fetchPage(url, { fetchImpl, selfHosts, resolver, budget, deadline, L });
  const pageMs = Date.now() - started;
  const pageHttps = page.finalUrl.protocol === 'https:';
  const pageInfo = {
    url: url.href, finalUrl: page.finalUrl.href, status: page.status, ok: page.status < 400, contentType: page.contentType,
    bytes: page.body.bytes, bodyTruncated: page.body.truncated, redirects: page.hops.filter((h) => h.location).length, hops: page.hops, ms: pageMs,
  };
  if (page.hops.some((h) => h.url.startsWith('https:') && h.location && h.location.startsWith('http:'))) notes.push({ level: 'warn', text: 'The page itself redirects from HTTPS to plain HTTP.' });
  if (page.body.truncated) { truncatedReasons.push('page_size'); notes.push({ level: 'info', text: `Only the first ${Math.round(L.maxPageBytes / 1000)} KB of the page were scanned for links.` }); }

  let extracted = { links: [], skipped: {}, total: 0, truncated: false };
  if (page.status >= 400) {
    notes.push({ level: 'fail', text: `The page returned HTTP ${page.status}${page.cfMitigated || [401, 403, 429].includes(page.status) ? ' (possibly bot protection against cloud IPs)' : ''}; links were not checked.` });
  } else if (!page.isHtml) {
    notes.push({ level: 'info', text: `The URL is not an HTML page (Content-Type: ${page.contentType || 'none'}); no links to extract.` });
  } else {
    extracted = extractLinks(page.body.text, page.finalUrl.href, { assets, max: L.maxExtracted });
    if (extracted.truncated) truncatedReasons.push('extract_cap');
  }

  // Split: statically blocked (no fetch), queued (<= max), not checked (over cap).
  // Fetchable links are picked fairly: about half hyperlinks, half assets (each in document order), so a page whose
  // <head> has 40 scripts still gets its <a href> links checked. Unused share goes to the other group.
  const blocked = [];
  const anchors = [];
  const assetLinks = [];
  let blockedCount = 0;
  const staticFlags = (l) => {
    if (!pageHttps || !l.url.startsWith('http:')) return [];
    if (ASSET_KINDS.has(l.kind)) return [ACTIVE_MIXED.has(l.kind) ? 'mixed_content_active' : 'mixed_content_passive'];
    return ['insecure_link'];
  };
  for (const l of extracted.links) {
    const p = urlProblem(new URL(l.url), { selfHosts });
    if (p) {
      blockedCount++;
      if (blocked.length < L.maxBlockedListed) blocked.push({ url: l.url, kind: l.kind, tag: l.tag, count: l.count, category: 'blocked', status: null, finalUrl: null, method: null, redirects: 0, hops: [], ms: 0, error: { code: p.code, message: p.message }, flags: staticFlags(l) });
      continue;
    }
    (ASSET_KINDS.has(l.kind) ? assetLinks : anchors).push(l);
  }
  const nA = Math.min(anchors.length, Math.max(Math.ceil(max / 2), max - assetLinks.length));
  const nB = Math.min(assetLinks.length, max - nA);
  const queue = [...anchors.slice(0, nA), ...assetLinks.slice(0, nB)].sort((a, b) => a.order - b.order);
  const rest = [...anchors.slice(nA), ...assetLinks.slice(nB)].sort((a, b) => a.order - b.order);
  const notChecked = rest.map((l) => l.url);
  // Mixed content / insecure links can be detected without fetching: report them even when over the link cap.
  const flaggedUnfetched = rest.filter((l) => staticFlags(l).length).slice(0, L.maxBlockedListed).map((l) => ({
    url: l.url, kind: l.kind, tag: l.tag, count: l.count, category: 'unchecked', status: null, finalUrl: null, method: null, redirects: 0, hops: [], ms: 0,
    error: { code: 'link_cap', message: `Not fetched (over the ${max}-link cap); flagged from the HTML only.` }, flags: staticFlags(l),
  }));
  if (notChecked.length) truncatedReasons.push('link_cap');
  if (blockedCount > blocked.length) truncatedReasons.push('blocked_list_cap');

  const t1 = Date.now();
  const ctx = { fetchImpl, selfHosts, budget, deadline, timeoutMs: L.linkTimeoutMs, maxHops: L.maxHops, pageHttps, resolver, dnsForLinks: L.dnsForLinks !== false };
  const checked = await pool(queue, L.concurrency, (l) => checkLink(l, ctx));
  const linksMs = Date.now() - t1;
  const links = [...checked, ...blocked, ...flaggedUnfetched];
  const unchecked = checked.filter((l) => l.category === 'unchecked');
  if (unchecked.some((l) => l.error.code === 'subrequest_budget')) truncatedReasons.push('subrequest_budget');
  if (unchecked.some((l) => l.error.code === 'deadline')) truncatedReasons.push('deadline');
  if (unchecked.some((l) => l.error.code === 'dns_check_failed')) { truncatedReasons.push('dns_check_failed'); notes.push({ level: 'warn', text: 'Some links were not fetched because the DNS safety lookup failed; retry later.' }); }
  if (checked.some((l) => l.flags.includes('get_fallback_skipped'))) notes.push({ level: 'info', text: 'Some links failed on HEAD and the budget did not allow a GET retry; they are reported with the HEAD result.' });

  const cnt = (f) => links.filter(f).length;
  const summary = {
    linksFound: extracted.total,
    uniqueLinks: extracted.links.length,
    checked: checked.filter((l) => l.category !== 'unchecked').length,
    ok: cnt((l) => l.category === 'ok'),
    redirected: cnt((l) => l.category === 'redirect'),
    broken: cnt((l) => l.category === 'broken'),
    blocked: blockedCount + checked.filter((l) => l.category === 'blocked').length,
    unchecked: unchecked.length + notChecked.length,
    mixedContent: cnt((l) => l.flags.some((f) => f.startsWith('mixed_content'))),
    insecureLinks: cnt((l) => l.flags.includes('insecure_link')),
    longChains: cnt((l) => l.flags.includes('long_chain')),
    redirectLoops: cnt((l) => l.flags.includes('redirect_loop')),
    maybeBotBlocked: cnt((l) => l.flags.includes('maybe_bot_blocked')),
    resolvesPrivate: cnt((l) => l.flags.includes('resolves_private')),
  };
  return {
    schema: SCHEMA,
    version: VERSION,
    checkedAt: new Date(started).toISOString(),
    input: clip(String(input), 300),
    options: { assets, max },
    page: pageInfo,
    summary,
    truncated: truncatedReasons.length > 0,
    truncatedReasons: [...new Set(truncatedReasons)],
    links,
    notChecked: { count: notChecked.length, sample: notChecked.slice(0, 50) },
    skipped: extracted.skipped,
    notes,
    limits: L,
    timings: { totalMs: Date.now() - started, pageMs, linksMs },
    subrequests: budget.used,
    dnsLookups: resolver.lookups ?? null,
  };
}
