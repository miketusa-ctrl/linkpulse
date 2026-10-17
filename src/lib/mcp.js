/**
 * LinkPulse remote MCP server (v0.3.0, agent-ready recipe r2). Hand-rolled JSON-RPC 2.0 over Streamable HTTP; no SDK,
 * no dependencies. Transport copied from SwearGuard/CheckDigit src/lib/mcp.js (BurnerCheck / CertGuard c2606ed /
 * DnsGuard lineage): modern 2026-07-28 tool errors keep _meta["linkpulse/error"] next to serverInfo.
 *
 * Dual-era and stateless: modern 2026-07-28 (server/discover, tools/list, tools/call with per-request _meta and
 * MCP-Protocol-Version / Mcp-Method / Mcp-Name headers) and legacy (initialize, ping, tools/list, tools/call; batches
 * max 10, at most one tools/call). No sessions, no SSE: GET/DELETE -> 405.
 *
 * Auth + limits are NOT implemented here: the router passes authenticate() and runCheck() from app.js, the exact code
 * behind GET/POST /api/check (same SSRF guard, result cache, burst limiter, per-IP hourly quota and global daily cap).
 * One check_links call = one /api/check request.
 */
import { VERSION } from './check.js';

export const MODERN_VERSIONS = ['2026-07-28'];
export const LEGACY_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
export const SUPPORTED_VERSIONS = [...MODERN_VERSIONS, ...LEGACY_VERSIONS];
export const MAX_BODY_BYTES = 64 * 1024;
export const MAX_BATCH = 10;
export const MAX_CHECKS_PER_REQUEST = 1;
export const DISCOVERY_PER_MIN = 120;
export const MAX_URL_LEN = 2048;
export const MAX_LINKS = 200; // = limitsFor(env).maxLinks on the paid profile; the engine clamps to the effective limit
export const MCP_MAX_PROBLEMS = 25; // problem links listed in structuredContent (problems_total stays the full count)
const META_VERSION = 'io.modelcontextprotocol/protocolVersion';
const META_CAPS = 'io.modelcontextprotocol/clientCapabilities';
const META_SERVER = 'io.modelcontextprotocol/serverInfo';
const ERROR_META = 'linkpulse/error';
export const PASS_HEADERS = ['retry-after', 'x-cache', 'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset']; // what /api/check sends
export const E = {
  PARSE: -32700, INVALID_REQUEST: -32600, METHOD_NOT_FOUND: -32601, INVALID_PARAMS: -32602, INTERNAL: -32603,
  SERVER: -32000, HEADER_MISMATCH: -32020, UNSUPPORTED_VERSION: -32022,
};

export const MCP_CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'POST, OPTIONS',
  'access-control-allow-headers': 'content-type, accept, authorization, x-api-key, mcp-protocol-version, mcp-method, mcp-name',
  'access-control-expose-headers': ['mcp-protocol-version', ...PASS_HEADERS].join(', '),
  'access-control-max-age': '86400',
};

export const SERVER_INFO = { name: 'linkpulse', title: 'LinkPulse', version: VERSION };
export const instructions = (L = { perHour: 20, dailyCap: 400, maxLinks: MAX_LINKS, deadlineSec: 45 }) => `LinkPulse checks ONE public web page for broken links, redirect chains (every hop listed), redirect loops and mixed content. Use check_links with "url" (http/https, ports 80/443 only). Optional "assets" (default true: also images, scripts, stylesheets, iframes, media; false = only <a>/<area> links) and "max" (links to check, 1-${L.maxLinks}, default ${L.maxLinks}). It is not a site crawler: it never follows links to other pages. A check takes up to about ${L.deadlineSec} seconds. Private, loopback and cloud-metadata targets are refused, including public hostnames that resolve to them and redirects into them. Limits (no API keys yet): ${L.perHour} checks per hour per IP plus a short burst limit, and ${L.dailyCap} checks per day shared by all users (resets 00:00 UTC). Each check_links call counts as one check; identical calls within about 2 minutes are served from cache. Rate-limit errors include retryAfterSeconds.`;

const LINK_OUT = { type: 'object', properties: {
  url: { type: 'string' }, category: { type: 'string', enum: ['broken', 'blocked', 'unchecked', 'redirect', 'ok'] },
  status: { type: 'integer', description: 'Final HTTP status (omitted when nothing was fetched).' }, final_url: { type: 'string' },
  redirects: { type: 'integer' }, error_code: { type: 'string' }, flags: { type: 'array', items: { type: 'string' } }, kind: { type: 'string' },
}, required: ['url', 'category'] };
const HOP_OUT = { type: 'object', properties: { url: { type: 'string' }, status: { type: 'integer' }, location: { type: 'string' } }, required: ['url'] };
export const RESULT_OUT = { type: 'object', properties: {
  url: { type: 'string', description: 'The page URL as requested.' }, final_url: { type: 'string' },
  page_status: { type: 'integer' }, page_redirects: { type: 'integer' }, page_hops: { type: 'array', items: HOP_OUT, maxItems: 11 },
  summary: { type: 'object', description: 'Counts: linksFound, uniqueLinks, checked, ok, redirected, broken, blocked, unchecked, mixedContent, insecureLinks, longChains, redirectLoops, maybeBotBlocked, resolvesPrivate.', additionalProperties: { type: 'integer' } },
  truncated: { type: 'boolean', description: 'True when not every link on the page was checked (link cap, budget or time limit).' },
  truncated_reasons: { type: 'array', items: { type: 'string' } },
  problems: { type: 'array', items: LINK_OUT, maxItems: MCP_MAX_PROBLEMS, description: `Links needing attention (broken first, then blocked, unchecked, redirects with flags such as long_chain or https_downgrade, then other flagged links). At most ${MCP_MAX_PROBLEMS} here; see problems_total.` },
  problems_total: { type: 'integer' }, problems_returned: { type: 'integer' }, not_checked_count: { type: 'integer' },
  checked_at: { type: 'string' }, version: { type: 'string' },
}, required: ['url', 'page_status', 'summary', 'truncated', 'problems', 'problems_total'] };

export const TOOLS = [
  {
    name: 'check_links',
    title: 'Check one web page for broken links and redirect chains',
    description: `Fetch ONE public web page and check up to ${MAX_LINKS} of its links and assets: broken links (4xx/5xx, hosts that don't exist, connection errors, timeouts), redirect chains hop by hop (long chains, loops, https-to-http downgrades), mixed content and links that may just block bots (401/403/429, flagged maybe_bot_blocked). Not a crawler: other pages are not visited. Private/loopback/metadata targets are refused, including names that resolve to them. Takes up to about 45 seconds. Returns counts plus up to ${MCP_MAX_PROBLEMS} problem links. Read-only. Same engine and limits as GET /api/check.`,
    inputSchema: { type: 'object', properties: {
      url: { type: 'string', description: 'Public http(s) page URL, e.g. https://example.com/. A URL without a scheme is treated as https://.', minLength: 1, maxLength: MAX_URL_LEN },
      assets: { type: 'boolean', description: 'Also check images, scripts, stylesheets, iframes and media (default true). false = only <a>/<area> links.' },
      max: { type: 'integer', description: `How many links to check, 1-${MAX_LINKS} (default ${MAX_LINKS}).`, minimum: 1, maximum: MAX_LINKS },
    }, required: ['url'], additionalProperties: false },
    outputSchema: RESULT_OUT,
    annotations: { title: 'Check links on a page', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  },
];
const ROUTE = Object.fromEntries(TOOLS.map((t) => [t.name, t]));
export const PUBLIC_TOOLS = TOOLS;

const clip = (s, n) => (typeof s === 'string' && s.length > n ? `${s.slice(0, n - 1)}…` : s);
const int = (v) => (Number.isInteger(v) ? v : undefined);
const RANK = (l) => {
  if (l.category === 'broken') return 0;
  if (l.category === 'blocked') return 1;
  if (l.category === 'unchecked') return 2;
  if (l.category === 'redirect' && (l.flags || []).length) return 3;
  if ((l.flags || []).length) return 4;
  return -1; // fine: plain ok, or a short clean redirect
};

function shapeLink(l) {
  const o = { url: clip(String(l.url), 300), category: String(l.category) };
  if (int(l.status) !== undefined) o.status = l.status;
  if (typeof l.finalUrl === 'string' && l.finalUrl !== l.url) o.final_url = clip(l.finalUrl, 300);
  if (int(l.redirects)) o.redirects = l.redirects;
  if (l.error && typeof l.error.code === 'string') o.error_code = clip(l.error.code, 40);
  if (Array.isArray(l.flags) && l.flags.length) o.flags = l.flags.slice(0, 8).map((f) => clip(String(f), 40));
  if (typeof l.kind === 'string') o.kind = clip(l.kind, 20);
  return o;
}

export function shapeResult(b) {
  const links = Array.isArray(b.links) ? b.links : [];
  const ranked = links.map((l, i) => [RANK(l), i, l]).filter(([r]) => r >= 0).sort((x, y) => x[0] - y[0] || x[1] - y[1]);
  const problems = ranked.slice(0, MCP_MAX_PROBLEMS).map(([, , l]) => shapeLink(l));
  const p = b.page || {};
  const summary = {};
  for (const [k, v] of Object.entries(b.summary || {})) if (Number.isInteger(v)) summary[k] = v;
  const out = {
    url: clip(String(b.input ?? p.url ?? ''), 600), page_status: int(p.status) ?? 0, summary,
    truncated: !!b.truncated, problems, problems_total: ranked.length, problems_returned: problems.length,
  };
  if (typeof p.finalUrl === 'string') out.final_url = clip(p.finalUrl, 600);
  if (int(p.redirects) !== undefined) out.page_redirects = p.redirects;
  if (Array.isArray(p.hops) && p.hops.length > 1) {
    out.page_hops = p.hops.slice(0, 11).map((h) => ({ url: clip(String(h.url), 300), ...(int(h.status) !== undefined ? { status: h.status } : {}), ...(typeof h.location === 'string' ? { location: clip(h.location, 300) } : {}) }));
  }
  if (Array.isArray(b.truncatedReasons) && b.truncatedReasons.length) out.truncated_reasons = b.truncatedReasons.slice(0, 10).map((r) => clip(String(r), 40));
  if (b.notChecked && int(b.notChecked.count) !== undefined) out.not_checked_count = b.notChecked.count;
  if (typeof b.checkedAt === 'string') out.checked_at = b.checkedAt;
  if (typeof b.version === 'string') out.version = b.version;
  return out;
}

export function summaryText(o) {
  const s = o.summary;
  let t = `Page ${o.final_url || o.url} answered HTTP ${o.page_status}${o.page_redirects ? ` after ${o.page_redirects} redirect(s)` : ''}. Checked ${s.checked ?? 0} of ${s.uniqueLinks ?? 0} unique links: ${s.ok ?? 0} ok, ${s.redirected ?? 0} redirected, ${s.broken ?? 0} broken, ${s.blocked ?? 0} blocked, ${s.unchecked ?? 0} unchecked.`;
  const broken = o.problems.filter((l) => l.category === 'broken').slice(0, 5);
  if (broken.length) t += ` Broken: ${broken.map((l) => `${l.url} (${l.status ?? l.error_code ?? 'error'})`).join('; ')}.`;
  if (s.longChains) t += ` Long redirect chains: ${s.longChains}.`;
  if (s.mixedContent) t += ` Mixed content: ${s.mixedContent}.`;
  if (o.truncated) t += ` Truncated (${(o.truncated_reasons || []).join(', ') || 'limit'}).`;
  if (o.problems_total > o.problems_returned) t += ` Listing ${o.problems_returned} of ${o.problems_total} problem links.`;
  return t;
}

function toolError(message, data, extra = {}) {
  return { content: [{ type: 'text', text: message }], isError: true, ...(data ? { _meta: { [ERROR_META]: data } } : {}), ...extra };
}

function checkArgs(tool, args) {
  const props = tool.inputSchema.properties;
  const unknown = Object.keys(args).filter((k) => !Object.prototype.hasOwnProperty.call(props, k));
  if (unknown.length) return { code: 'invalid_arguments', msg: `Unknown argument(s): ${clip(unknown.slice(0, 5).join(', '), 80)}. Allowed: ${Object.keys(props).join(', ')}.` };
  if (typeof args.url !== 'string' || !args.url.trim()) return { code: 'missing_url', msg: '"url" (string) is required, e.g. "https://example.com/".' };
  if (args.url.length > MAX_URL_LEN) return { code: 'invalid_url', msg: `"url" is longer than ${MAX_URL_LEN} characters.` };
  if (args.assets !== undefined && typeof args.assets !== 'boolean') return { code: 'invalid_assets', msg: '"assets" must be true or false.' };
  if (args.max !== undefined && (!Number.isInteger(args.max) || args.max < 1 || args.max > MAX_LINKS)) return { code: 'invalid_max', msg: `"max" must be an integer from 1 to ${MAX_LINKS}.` };
  return null;
}

async function callTool(params, deps) {
  const { name } = params;
  const args = params.arguments === undefined ? {} : params.arguments;
  const tool = typeof name === 'string' && Object.prototype.hasOwnProperty.call(ROUTE, name) ? ROUTE[name] : null;
  if (!tool) return { error: { code: E.INVALID_PARAMS, message: `Unknown tool: ${clip(String(name), 80)}` } };
  if (!args || typeof args !== 'object' || Array.isArray(args)) return { error: { code: E.INVALID_PARAMS, message: 'arguments must be an object' } };
  const bad = checkArgs(tool, args);
  if (bad) return { result: toolError(bad.msg, { code: bad.code, httpStatus: 400 }) };
  const input = { raw: args.url, assets: args.assets === undefined ? true : args.assets, max: args.max === undefined ? undefined : args.max };
  const r = await deps.runCheck({ input, auth: deps.auth, env: deps.env, ctx: deps.ctx, ip: deps.ip, request: deps.request });
  const headers = r.headers || {};
  if (!r.ok) {
    const retry = headers['retry-after'] ? Number(headers['retry-after']) : undefined;
    const msg = clip(String(r.message || 'The check could not be completed.'), 600) + (retry ? ` (retry after ${retry} seconds)` : '');
    return { result: toolError(msg, { code: String(r.code || 'error'), httpStatus: r.status, ...(retry ? { retryAfterSeconds: retry } : {}) }), headers };
  }
  const out = shapeResult(r.body);
  return { result: { content: [{ type: 'text', text: summaryText(out) }], structuredContent: out, isError: false }, headers };
}

// ---------- transport helpers ----------

/** Origin policy: absent = OK (CLI / server-side clients). Present: must be a bare https origin or an http loopback
 * origin, or (if MCP_ALLOWED_ORIGINS is set) same-origin / listed. Malformed, "null" and plain-http remote → 403. */
export function originAllowed(origin, selfOrigin, allowList) {
  if (origin === null || origin === undefined) return true;
  if (origin === selfOrigin) return true;
  if (allowList) return String(allowList).split(',').map((s) => s.trim()).filter(Boolean).includes(origin);
  let u;
  try { u = new URL(origin); } catch { return false; }
  if (u.origin !== origin) return false;
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
}

async function readCapped(request, cap) {
  const cl = Number(request.headers.get('content-length'));
  if (Number.isFinite(cl) && cl > cap) return null;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > cap) { try { await reader.cancel(); } catch { /* ignore */ } return null; }
    chunks.push(value);
  }
  const buf = new Uint8Array(size);
  let o = 0;
  for (const c of chunks) { buf.set(c, o); o += c.byteLength; }
  return new TextDecoder().decode(buf);
}

function decodeHeaderValue(v) {
  if (v == null) return v;
  const m = /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/.exec(v);
  if (!m) return v;
  try { return new TextDecoder().decode(Uint8Array.from(atob(m[1]), (ch) => ch.charCodeAt(0))); } catch { return null; }
}

const isId = (id) => typeof id === 'string' || (typeof id === 'number' && Number.isFinite(id));
const rpcError = (id, code, message, data) => ({ jsonrpc: '2.0', ...(id !== undefined ? { id } : {}), error: { code, message, ...(data !== undefined ? { data } : {}) } });
const rpcResult = (id, result) => ({ jsonrpc: '2.0', id, result });

/**
 * Handle one JSON-RPC message. Returns { response?, status?, headers?, isCheck? }.
 * `response` undefined = notification accepted (202 when it's the whole request).
 */
async function handleMessage(msg, { modern, request, deps, auth, checkBudget }) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return { response: rpcError(null, E.INVALID_REQUEST, 'Invalid Request'), status: 400 };
  const hasId = Object.prototype.hasOwnProperty.call(msg, 'id');
  if (msg.jsonrpc !== '2.0') return { response: rpcError(hasId && isId(msg.id) ? msg.id : null, E.INVALID_REQUEST, 'Invalid Request: jsonrpc must be "2.0"'), status: 400 };
  if (typeof msg.method !== 'string') {
    // A JSON-RPC response or garbage. Legacy clients may POST responses → accept like a notification.
    if (!modern && hasId && ('result' in msg || 'error' in msg)) return {};
    return { response: rpcError(hasId && isId(msg.id) ? msg.id : null, E.INVALID_REQUEST, 'Invalid Request: method is required'), status: 400 };
  }
  if (!hasId) return {}; // notification (notifications/initialized, cancelled, …): accepted, nothing to do
  if (!isId(msg.id)) return { response: rpcError(null, E.INVALID_REQUEST, 'Invalid Request: id must be a string or number'), status: 400 };
  const { id, method } = msg;
  const params = msg.params === undefined ? {} : msg.params;
  if (!params || typeof params !== 'object' || Array.isArray(params)) return { response: rpcError(id, E.INVALID_PARAMS, 'params must be an object') };

  // Modern results carry serverInfo in _meta; merge so a tool error's _meta["linkpulse/error"] is kept (CertGuard c2606ed).
  const done = (result) => ({ response: rpcResult(id, modern ? { resultType: 'complete', ...result, _meta: { ...(result._meta || {}), [META_SERVER]: SERVER_INFO } } : result) });
  const notFound = () => ({ response: rpcError(id, E.METHOD_NOT_FOUND, `Method not found: ${clip(method, 80)}`), status: modern ? 404 : 200 });
  const instr = instructions(deps.limits);

  if (modern) {
    // MCP 2026-07-28 per-request validation (version, capabilities, mirrored headers).
    const hName = decodeHeaderValue(request.headers.get('mcp-name'));
    if (request.headers.get('mcp-method') !== method) return { response: rpcError(id, E.HEADER_MISMATCH, 'Header mismatch: Mcp-Method header is missing or does not match the body method'), status: 400 };
    if (!params._meta || typeof params._meta[META_CAPS] !== 'object' || params._meta[META_CAPS] === null) {
      return { response: rpcError(id, E.INVALID_PARAMS, `Missing required _meta field ${META_CAPS}`), status: 400 };
    }
    if (method === 'tools/call' && hName !== params.name) return { response: rpcError(id, E.HEADER_MISMATCH, 'Header mismatch: Mcp-Name header is missing or does not match params.name'), status: 400 };
    if (method === 'server/discover') {
      return done({ supportedVersions: SUPPORTED_VERSIONS, capabilities: { tools: { listChanged: false } }, instructions: instr, ttlMs: 3_600_000, cacheScope: 'public' });
    }
    if (method === 'tools/list') return done({ tools: PUBLIC_TOOLS, ttlMs: 3_600_000, cacheScope: 'public' });
    if (method !== 'tools/call') return notFound(); // includes initialize and ping (removed in 2026-07-28)
  } else {
    if (method === 'initialize') {
      const req = params.protocolVersion;
      const protocolVersion = LEGACY_VERSIONS.includes(req) ? req : LEGACY_VERSIONS[0];
      return done({ protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: instr });
    }
    if (method === 'ping') return done({});
    if (method === 'tools/list') return done({ tools: PUBLIC_TOOLS });
    if (method === 'server/discover') return done({ supportedVersions: SUPPORTED_VERSIONS, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: instr });
    if (method !== 'tools/call') return notFound();
  }

  // tools/call
  if (typeof params.name !== 'string') return { response: rpcError(id, E.INVALID_PARAMS, 'params.name (tool name) is required') };
  if (checkBudget.used >= MAX_CHECKS_PER_REQUEST) {
    return { response: rpcError(id, E.INVALID_REQUEST, `At most ${MAX_CHECKS_PER_REQUEST} tools/call per HTTP request; send each call as its own request.`) };
  }
  checkBudget.used++;
  const r = await callTool(params, { ...deps, request, auth });
  if (r.error) return { response: rpcError(id, r.error.code, r.error.message), isCheck: true };
  return { ...done(r.result), headers: r.headers, isCheck: true };
}

/** Entry point from the router for every request to /mcp. */
export async function handleMcp(request, env, ctx, deps) {
  const base = { ...MCP_CORS, ...deps.security };
  const reply = (status, body, extra = {}) => new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: { ...(body === null ? {} : { 'content-type': 'application/json; charset=utf-8' }), 'cache-control': 'no-store', ...base, ...extra },
  });
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...MCP_CORS, ...deps.security } });
  if (!originAllowed(request.headers.get('origin'), deps.origin, deps.allowedOrigins)) {
    return reply(403, rpcError(undefined, E.SERVER, 'Forbidden: Origin not allowed'));
  }
  if (request.method !== 'POST') {
    return reply(405, rpcError(undefined, E.SERVER, 'Method not allowed. This MCP endpoint is stateless: POST JSON-RPC messages (no SSE stream, no sessions). Docs: /llms.txt'), { allow: 'POST, OPTIONS' });
  }
  const text = await readCapped(request, MAX_BODY_BYTES);
  if (text === null) return reply(413, rpcError(undefined, E.INVALID_REQUEST, `Request body too large (max ${MAX_BODY_BYTES} bytes)`));
  let payload;
  try { payload = JSON.parse(text); } catch { return reply(400, rpcError(null, E.PARSE, 'Parse error: body must be valid JSON')); }

  // Era detection. Modern = per-request _meta version or a modern MCP-Protocol-Version header.
  const hVer = request.headers.get('mcp-protocol-version');
  const single = !Array.isArray(payload);
  const metaVer = single && payload && typeof payload === 'object' && payload.params && typeof payload.params === 'object'
    && payload.params._meta && typeof payload.params._meta === 'object' ? payload.params._meta[META_VERSION] : undefined;
  const modern = metaVer !== undefined || MODERN_VERSIONS.includes(hVer);
  const idOf = (p) => (p && typeof p === 'object' && isId(p.id) ? p.id : null);
  if (modern) {
    if (!single) return reply(400, rpcError(null, E.INVALID_REQUEST, 'JSON-RPC batches are not supported in protocol 2026-07-28; send one message per POST'));
    if (payload && typeof payload === 'object' && Object.prototype.hasOwnProperty.call(payload, 'id')) {
      if (metaVer === undefined && typeof payload.method === 'string') {
        return reply(400, rpcError(idOf(payload), E.INVALID_PARAMS, `Missing required _meta field ${META_VERSION}`));
      }
      if (metaVer !== undefined && !SUPPORTED_VERSIONS.includes(metaVer)) {
        return reply(400, rpcError(idOf(payload), E.UNSUPPORTED_VERSION, 'Unsupported protocol version', { supported: SUPPORTED_VERSIONS, requested: clip(String(metaVer), 40) }));
      }
      if (metaVer !== undefined && !MODERN_VERSIONS.includes(metaVer)) {
        return reply(400, rpcError(idOf(payload), E.UNSUPPORTED_VERSION, `Protocol version ${metaVer} uses the initialize handshake; per-request _meta requires one of: ${MODERN_VERSIONS.join(', ')}`, { supported: SUPPORTED_VERSIONS, requested: metaVer }));
      }
      if (hVer !== metaVer) return reply(400, rpcError(idOf(payload), E.HEADER_MISMATCH, 'Header mismatch: MCP-Protocol-Version header is missing or does not match _meta protocolVersion'));
    }
  } else if (hVer && !LEGACY_VERSIONS.includes(hVer)) {
    return reply(400, rpcError(single ? idOf(payload) : null, E.UNSUPPORTED_VERSION, 'Unsupported protocol version', { supported: SUPPORTED_VERSIONS, requested: clip(hVer, 40) }));
  }

  const msgs = single ? [payload] : payload;
  if (!msgs.length) return reply(400, rpcError(null, E.INVALID_REQUEST, 'Invalid Request: empty batch'));
  if (msgs.length > MAX_BATCH) return reply(400, rpcError(null, E.INVALID_REQUEST, `Batch too large (max ${MAX_BATCH} messages)`));

  // Light per-IP-bucket cap on non-check messages (checks are governed by the /api/check limits inside runCheck).
  const nonCheck = msgs.filter((m) => !(m && m.method === 'tools/call')).length;
  for (let i = 0; i < nonCheck; i++) {
    if (!deps.memLimit(`mcp:${deps.ipBucket}`, DISCOVERY_PER_MIN, 60_000)) {
      return reply(429, rpcError(single ? idOf(payload) : null, E.SERVER, `Too many MCP requests from your IP (about ${DISCOVERY_PER_MIN} per minute). Retry in a minute.`, { code: 'rate_limited', retryAfterSeconds: 60 }), { 'retry-after': '60' });
    }
  }

  // Same gate as /api/check (authenticate() in app.js), once per HTTP request. LinkPulse has no API keys yet: a key header
  // is ignored (the anonymous per-IP limits apply and the result carries a note), exactly like /api/check.
  const auth = await deps.authenticate(request, env, ctx);
  if (!auth.ok) {
    // No WWW-Authenticate on /mcp: MCP clients treat a 401 Bearer challenge as "start OAuth discovery", which this
    // server doesn't offer; the JSON-RPC error body (data.code) is the useful signal.
    return reply(auth.status, rpcError(single ? idOf(payload) : null, E.SERVER, auth.message, { code: auth.code, httpStatus: auth.status }), { ...(auth.headers || {}) });
  }

  const mdeps = { ...deps, env, ctx };
  const checkBudget = { used: 0 };
  const responses = [];
  let status = 200;
  let headers = {};
  for (const m of msgs) {
    let out;
    try {
      out = await handleMessage(m, { modern, request, deps: mdeps, auth, checkBudget });
    } catch {
      out = { response: rpcError(idOf(m), E.INTERNAL, 'Internal error') };
    }
    if (out.response) responses.push(out.response);
    if (single) status = out.status || 200;
    if (out.headers) headers = out.headers; // the (single) tools/call's /api headers, for batches too
  }
  if (!responses.length) return reply(202, null);
  const exposed = {};
  for (const h of PASS_HEADERS) if (headers[h]) exposed[h] = headers[h];
  return reply(status, single ? responses[0] : responses, exposed);
}
