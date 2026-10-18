// Request router. Kept free of Worker-only imports so it can be unit-tested in Node.
import { runCheck, CheckError, VERSION, SCHEMA, limitsFor } from './lib/check.js';
import { normalizeTarget, TargetError } from './lib/target.js';
import { consumeIpQuota, quotaConfig } from './lib/ratelimit.js';
import { handleMcp } from './lib/mcp.js';
import { llmsTxt, openApiSpec, serverCard } from './lib/agentdocs.js';
import { countVisitor } from './lib/visitors.js';
import { GLAMA_JSON } from './lib/glama.js';

export const PROD_HOST = 'linkpulse.mike-tusa.workers.dev';
export const STAGING_HOST = 'linkpulse-staging.mike-tusa.workers.dev';
const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type, x-api-key, authorization',
  'access-control-expose-headers': 'retry-after, x-ratelimit-limit, x-ratelimit-remaining, x-ratelimit-reset, x-cache',
  'access-control-max-age': '86400',
};
const SECURITY = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'x-frame-options': 'DENY',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), usb=(), payment=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
};
const API_SECURITY = { ...SECURITY, 'cross-origin-resource-policy': 'cross-origin' };
export const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const resultCache = new Map();
export const CACHE_TTL_MS = 120_000;
export function _resetForTests() { resultCache.clear(); memLimiter.clear(); }

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...CORS, ...API_SECURITY, ...extra },
  });
}
const apiError = (status, code, message, extra = {}, more = {}) => json({ error: { code, message, ...more }, version: VERSION }, status, extra);

export function staging(env) { return String(env.PUBLIC_LAUNCH || 'false') !== 'true'; }
export { quotaConfig };

async function burstLimited(env, key) {
  const b = env.BURST_LIMITER;
  if (b && typeof b.limit === 'function') {
    try { const { success } = await b.limit({ key: `burst:${key}` }); return !success; } catch { /* ignore */ }
  }
  return false;
}

/** Rate-limit key for anonymous callers: IPv4 as is; IPv6 -> its /64. Same output as workdayapi's. */
export function ipBucket(ip) {
  const s = String(ip || 'unknown').trim().toLowerCase();
  if (!s.includes(':')) return s;
  if (s.includes('.')) return s.slice(s.lastIndexOf(':') + 1); // IPv4-mapped ::ffff:a.b.c.d
  const [h, t] = s.split('::'), head = h ? h.split(':') : [], tail = t ? t.split(':') : [];
  const parts = t === undefined ? head : [...head, ...Array(Math.max(0, 8 - head.length - tail.length)).fill('0'), ...tail];
  return parts.slice(0, 4).map((x) => x.replace(/^0+(?=.)/, '') || '0').join(':') + '::/64';
}

// Per-isolate fixed-window counter (MCP discovery cap only; checks use the burst binding + Durable Object quota).
const memLimiter = new Map();
export function memLimit(key, limit, periodMs = 60_000) {
  const now = Date.now();
  let e = memLimiter.get(key);
  if (!e || now - e.start > periodMs) { e = { start: now, n: 0 }; memLimiter.set(key, e); }
  e.n++;
  if (memLimiter.size > 10_000) memLimiter.clear();
  return e.n <= limit;
}

/**
 * Shared gate for /api/check and /mcp. LinkPulse has no API keys yet: every caller is anonymous and a key header is
 * ignored (the result gets an info note). Never echoes the key. -> { ok: true, tier, keyNote }
 */
export async function authenticate(request) {
  const sent = request.headers.get('x-api-key') || request.headers.get('authorization');
  return { ok: true, tier: 'anonymous', keyNote: sent ? { level: 'info', text: 'API keys are not available yet; the anonymous per-IP limit was applied.' } : null };
}

/**
 * The one check pipeline behind GET/POST /api/check and the MCP check_links tool: SSRF validation -> result cache (HIT:
 * no limiter, no quota) -> burst limiter -> per-IP hourly + global daily quota (Durable Object) -> runCheck. input = {
 * raw, assets, max }.
 * -> { ok: true, body, headers } | { ok: false, status, code, message, headers, more }
 */
export async function runCheckApi({ input, auth, env, ip, doFetch, selfHosts }) {
  const L = limitsFor(env);
  const max = input.max === undefined || input.max === null ? L.maxLinks : input.max;
  try { normalizeTarget(input.raw, { selfHosts }); } catch (e) {
    if (e instanceof TargetError) return { ok: false, status: e.httpStatus, code: e.code, message: e.message, headers: {} };
    throw e;
  }
  const withNote = (body) => (auth && auth.keyNote ? { ...body, notes: [...body.notes, auth.keyNote] } : body);
  const cacheKey = `${input.raw}|${input.assets}|${max}`;
  const hit = resultCache.get(cacheKey);
  if (hit && Date.now() - hit.t < CACHE_TTL_MS) return { ok: true, body: withNote(hit.body), headers: { 'x-cache': 'HIT' } };

  const bucket = ipBucket(ip);
  const q = quotaConfig(env);
  if (await burstLimited(env, bucket)) {
    return { ok: false, status: 429, code: 'rate_limited', message: 'Too many checks in a short time from your IP. Please wait a minute.', headers: { 'retry-after': '60' }, more: { retryAfterSec: 60, scope: 'burst' } };
  }
  const quota = await consumeIpQuota(env, bucket, q);
  const rlHeaders = { 'x-ratelimit-limit': String(q.limit), 'x-ratelimit-remaining': String(quota.remaining), 'x-ratelimit-reset': String(quota.resetSec) };
  if (!quota.ok) {
    const wait = quota.resetSec >= 5400 ? `about ${Math.round(quota.resetSec / 3600)} h` : `about ${Math.ceil(quota.resetSec / 60)} min`;
    const msg = quota.scope === 'global'
      ? `LinkPulse has reached its daily capacity of free checks. Try again in ${wait} (resets at 00:00 UTC).`
      : `Limit reached: ${q.limit} checks per hour per IP. Try again in ${wait}.`;
    return { ok: false, status: 429, code: 'rate_limited', message: msg, headers: { ...rlHeaders, 'retry-after': String(quota.resetSec) }, more: { retryAfterSec: quota.resetSec, scope: quota.scope } };
  }
  try {
    const body = await runCheck(input.raw, { fetchImpl: doFetch, selfHosts, assets: input.assets, max, limits: L });
    resultCache.set(cacheKey, { t: Date.now(), body });
    if (resultCache.size > 200) resultCache.delete(resultCache.keys().next().value);
    return { ok: true, body: withNote(body), headers: { ...rlHeaders, 'x-cache': 'MISS' } };
  } catch (e) {
    const more = e.redirects && e.redirects.length ? { redirects: e.redirects } : {};
    if (e instanceof TargetError || e instanceof CheckError) return { ok: false, status: e.httpStatus, code: e.code, message: e.message, headers: rlHeaders, more };
    return { ok: false, status: 500, code: 'internal_error', message: 'Unexpected error while checking.', headers: rlHeaders };
  }
}

/** Limits as published in llms.txt / OpenAPI / MCP instructions (generated, never hard-coded twice). */
export function publicLimits(env) {
  const L = limitsFor(env), q = quotaConfig(env);
  return { perHour: q.limit, dailyCap: q.dailyCap, burstPerMin: BURST_PER_MIN, maxLinks: L.maxLinks, deadlineSec: Math.round(L.deadlineMs / 1000), budget: L.subrequestBudget, maxPageBytes: L.maxPageBytes };
}
export const BURST_PER_MIN = 10; // = wrangler.toml BURST_LIMITER simple.limit (test asserts they match)
export const REGISTRY_AUTH_RE = /^v=MCPv1; k=(ed25519|ecdsap384); p=[A-Za-z0-9+/=]{20,120}$/;
const AGENT_DOCS = ['/llms.txt', '/openapi.json', '/.well-known/mcp/server-card.json', '/.well-known/mcp-registry-auth', '/.well-known/glama.json'];
// Daily unique visitors: human/API entry points only. Never /api/health, docs, assets, robots or agent docs.
const COUNTED = (path, method) => (method === 'GET' && (path === '/' || path === '/docs'))
  || ((method === 'GET' || method === 'POST') && path === '/api/check') || (method === 'POST' && path === '/mcp');

const bool = (v, dflt) => (v === undefined || v === null || v === '' ? dflt : !/^(0|false|no|off)$/i.test(String(v)));

async function readParams(request, url, L) {
  const p = { url: url.searchParams.get('url'), assets: url.searchParams.get('assets'), max: url.searchParams.get('max') };
  if (request.method === 'POST') {
    const ct = request.headers.get('content-type') || '';
    const text = await request.text();
    if (text.length > 8192) throw new TargetError('invalid_request', 'Request body too large (max 8 KB).', 413);
    if (text.trim()) {
      let body = {};
      if (/application\/x-www-form-urlencoded/i.test(ct)) body = Object.fromEntries(new URLSearchParams(text));
      else { try { body = JSON.parse(text); } catch { throw new TargetError('invalid_request', 'POST body must be JSON like {"url":"https://example.com/"} or form-encoded.'); } }
      if (body && typeof body === 'object') {
        if (body.url !== undefined) p.url = String(body.url);
        if (body.assets !== undefined) p.assets = String(body.assets);
        if (body.max !== undefined) p.max = String(body.max);
      }
    }
  }
  return { raw: p.url ?? '', assets: bool(p.assets, true), max: p.max ? Number(p.max) : L.maxLinks };
}

export function createApp(assets = {}) {
  const route = createRouter(assets);
  return async function handle(request, env = {}, ctx = {}) {
    let res;
    try { res = await route(request, env, ctx); } catch {
      res = apiError(500, 'internal_error', 'Unexpected server error. Please retry.');
    }
    if (staging(env)) res.headers.set('x-robots-tag', 'noindex, nofollow');
    else res.headers.delete('x-robots-tag');
    return res;
  };
}

function createRouter({ html, docs, js, css, action, fetchImpl }) {
  return async function route(request, env = {}, ctx = {}) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const ip = request.headers.get('cf-connecting-ip') || 'local';
    const doFetch = fetchImpl || ((...a) => fetch(...a)); // never pass bare `fetch` (Illegal invocation on Workers)
    const selfHosts = [url.hostname.toLowerCase(), PROD_HOST, STAGING_HOST];
    const method = request.method.toUpperCase();
    if (COUNTED(path, method)) countVisitor(request, env, ctx, ipBucket(ip));

    if (path === '/mcp') {
      return handleMcp(request, env, ctx, {
        authenticate, ip, ipBucket: ipBucket(ip), memLimit, origin: url.origin, allowedOrigins: env.MCP_ALLOWED_ORIGINS,
        limits: publicLimits(env), security: API_SECURITY,
        runCheck: ({ input, auth }) => runCheckApi({ input, auth, env, ip, doFetch, selfHosts }),
      });
    }
    if (AGENT_DOCS.includes(path)) {
      const AGENT_CORS = { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, HEAD, OPTIONS', 'access-control-max-age': '86400' };
      if (method === 'OPTIONS') return new Response(null, { status: 204, headers: { ...AGENT_CORS, ...API_SECURITY } });
      if (method !== 'GET' && method !== 'HEAD') return apiError(405, 'method_not_allowed', 'Use GET.', { allow: 'GET, HEAD, OPTIONS' });
      const doc = (body, type, cache = 'public, max-age=3600', status = 200) => new Response(method === 'HEAD' ? null : body, {
        status, headers: { 'content-type': type, 'cache-control': cache, ...API_SECURITY, 'access-control-allow-origin': '*' },
      });
      const PL = publicLimits(env);
      if (path === '/llms.txt') return doc(llmsTxt(url.origin, PL), 'text/plain; charset=utf-8');
      if (path === '/openapi.json') return doc(JSON.stringify(openApiSpec(url.origin, PL), null, 2), 'application/json; charset=utf-8');
      if (path === '/.well-known/mcp/server-card.json') return doc(JSON.stringify(serverCard(url.origin), null, 2), 'application/json; charset=utf-8');
      if (path === '/.well-known/glama.json') return doc(GLAMA_JSON, 'application/json');
      const v = String(env.MCP_REGISTRY_AUTH || '');
      if (REGISTRY_AUTH_RE.test(v)) return doc(v, 'text/plain; charset=utf-8', 'no-store');
      return doc('Not found\n', 'text/plain; charset=utf-8', 'no-store', 404);
    }

    if (request.method === 'OPTIONS' && path.startsWith('/api/')) return new Response(null, { status: 204, headers: { ...CORS } });

    if (path === '/api/check') {
      if (!['GET', 'POST'].includes(request.method)) return apiError(405, 'method_not_allowed', 'Use GET /api/check?url=… or POST /api/check with JSON {"url": "…"}.', { allow: 'GET, POST, OPTIONS' });
      const L = limitsFor(env);
      let params;
      try {
        params = await readParams(request, url, L);
        normalizeTarget(params.raw, { selfHosts });
      } catch (e) {
        if (e instanceof TargetError) return apiError(e.httpStatus, e.code, e.message);
        throw e;
      }
      const auth = await authenticate(request, env);
      const r = await runCheckApi({ input: params, auth, env, ip, doFetch, selfHosts });
      if (!r.ok) return apiError(r.status, r.code, r.message, r.headers, r.more);
      return json(r.body, 200, r.headers);
    }

    if (path === '/api/health') {
      if (request.method !== 'GET' && request.method !== 'HEAD') return apiError(405, 'method_not_allowed', 'Use GET.', { allow: 'GET, OPTIONS' });
      const q = quotaConfig(env);
      return json({ ok: true, service: 'linkpulse', version: VERSION, schema: SCHEMA, publicLaunch: !staging(env), rateLimit: { checksPerHourPerIp: q.limit, burstPerMinutePerIp: BURST_PER_MIN, dailyCheckCap: q.dailyCap, counter: env.IP_QUOTA ? 'durable_object' : 'memory' }, limits: limitsFor(env) });
    }
    if (path.startsWith('/api/')) return apiError(404, 'not_found', 'Unknown API endpoint. See /docs.');

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response('Method not allowed', { status: 405, headers: { 'content-type': 'text/plain; charset=utf-8', allow: 'GET, HEAD', ...SECURITY } });
    }
    const page = (body, type, cache = 'public, max-age=300', status = 200) => new Response(request.method === 'HEAD' ? null : body, {
      status, headers: { 'content-type': type, 'cache-control': cache, ...SECURITY, 'content-security-policy': CSP },
    });
    const fill = (s) => String(s || '').replaceAll('{{ORIGIN}}', url.origin).replaceAll('{{VERSION}}', VERSION);
    if (path === '/') return page(fill(html), 'text/html; charset=utf-8');
    if (path === '/docs') {
      const yml = String(action || '').replaceAll('https://' + PROD_HOST, url.origin).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
      return page(fill(docs).replace('{{ACTION_YAML}}', () => yml), 'text/html; charset=utf-8');
    }
    if (path === '/app.js') return page(js, 'text/javascript; charset=utf-8');
    if (path === '/style.css') return page(css, 'text/css; charset=utf-8');
    if (path === '/github-action.yml') return page(fill(action).replaceAll('https://' + PROD_HOST, url.origin), 'text/plain; charset=utf-8');
    if (path === '/robots.txt') {
      return page(staging(env) ? 'User-agent: *\nDisallow: /\n' : `User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: ${url.origin}/sitemap.xml\n`, 'text/plain; charset=utf-8');
    }
    if (path === '/sitemap.xml' && !staging(env)) {
      return page(`<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>${url.origin}/</loc></url>\n  <url><loc>${url.origin}/docs</loc></url>\n</urlset>\n`, 'application/xml; charset=utf-8');
    }
    if (path === '/favicon.ico' || path === '/favicon.svg') {
      return page('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#0f766e"/><path d="M13 19l6-6M11.5 15.5l-2 2a3.5 3.5 0 005 5l2-2M20.5 16.5l2-2a3.5 3.5 0 00-5-5l-2 2" stroke="#fff" stroke-width="2.4" fill="none" stroke-linecap="round"/></svg>', 'image/svg+xml', 'public, max-age=86400');
    }
    return page('Not found', 'text/plain; charset=utf-8', 'no-store', 404);
  };
}
