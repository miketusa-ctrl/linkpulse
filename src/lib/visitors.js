/**
 * Privacy-friendly daily unique-visitor counter. Key = uv:<UTC day>:<first 16 hex of SHA-256(salt | day | ipBucket)> in the LINKPULSE_KV namespace, value "1", TTL 9 days. No
 * IP, user agent or submitted URL is stored. Fire-and-forget via ctx.waitUntil; KV writes per isolate per UTC day are capped.
 */
export const VISITOR_TTL_S = 9 * 86400; // long enough for Monday weekly reports
export const DAILY_VISITOR_WRITES = 1000; // per isolate per UTC day
export const DEFAULT_MARKERS = 'fleet-bot,linkpulse-qc,linkpulse-smoke,qc-bot,smitherybot,cloudflare-healthchecks,uptime,cron';

const utcDay = (now) => new Date(now).toISOString().slice(0, 10);
let state = { day: '', writes: 0, seen: new Set() };
export function resetVisitors() { state = { day: '', writes: 0, seen: new Set() }; }

export function isExcludedTraffic(request, env) {
  if (request.headers.get('x-fleet-traffic')) return true;
  if (request.headers.get('cf-worker')) return true; // Worker-to-Worker (cron jobs, other bots on Workers)
  const ua = (request.headers.get('user-agent') || '').toLowerCase();
  const markers = String(env.FLEET_UA_MARKERS || DEFAULT_MARKERS).toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);
  return markers.some((m) => ua.includes(m));
}

async function sha256hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** bucket = ipBucket(cf-connecting-ip) (IPv6 grouped by /64). Returns the promise (tests await it). */
export function countVisitor(request, env, ctx, bucket, now = Date.now()) {
  const kv = env.LINKPULSE_KV;
  if (!kv || typeof kv.put !== 'function' || !env.VISITOR_SALT || isExcludedTraffic(request, env)) return undefined;
  const day = utcDay(now);
  if (state.day !== day) state = { day, writes: 0, seen: new Set() };
  const p = (async () => {
    const h = (await sha256hex(`${env.VISITOR_SALT}|${day}|${bucket}`)).slice(0, 16);
    if (state.seen.has(h)) return;
    if (state.seen.size > 20000) state.seen.clear();
    state.seen.add(h);
    const key = `uv:${day}:${h}`;
    if (await kv.get(key) !== null) return;
    if (state.writes >= DAILY_VISITOR_WRITES) return;
    state.writes++;
    await kv.put(key, '1', { expirationTtl: VISITOR_TTL_S });
  })().catch(() => {});
  if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(p);
  return p;
}
