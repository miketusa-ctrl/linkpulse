// Rate limiting (v0.2.0) with ONE Durable Object request per allowed check:
//  - per-IP hourly cap (exact) and
//  - a GLOBAL daily cap on checks (exact per shard; total <= DAILY_CHECK_CAP), which bounds worst-case
//    CPU/DO usage no matter how many IPs send traffic.
// The IP space is split over QUOTA_SHARDS SQLite-backed DO instances ("shard:N"); each shard stores
//   ip:<sha256(salt:ip)> -> {start,count}   (hourly window per IP)
//   day                 -> {day,count}      (UTC day, this shard's share of the global cap)
// Raw IPs are never stored. A storage alarm (at most one pending per shard) deletes expired ip: rows;
// it re-arms only while rows remain. This is cleanup, not a cron or crawl.
// Isolate-memory "denied until" hints avoid repeat DO calls for IPs/shards that are already over their cap.
// Plain fetch()-style class (no `cloudflare:workers` import) so it is unit-testable in Node.

export const utcDay = (now) => new Date(now).toISOString().slice(0, 10);
export const secsToUtcMidnight = (now) => Math.max(1, Math.ceil((Date.parse(utcDay(now) + 'T00:00:00Z') + 86400_000 - now) / 1000));

export class IpQuota {
  constructor(state, env) { this.state = state; this.storage = state.storage; this.env = env; }

  async fetch(request) {
    const url = new URL(request.url);
    const ip = url.searchParams.get('ip') || '';
    const limit = Number(url.searchParams.get('limit'));
    const windowSec = Number(url.searchParams.get('window'));
    const daily = Number(url.searchParams.get('daily'));
    if (!/^[0-9a-f]{64}$/.test(ip) || !(limit >= 1) || !(windowSec >= 1) || !(daily >= 1)) return Response.json({ error: 'bad_request' }, { status: 400 });
    return Response.json(await this.consume(ip, limit, windowSec, daily, Date.now()));
  }

  async consume(ipHash, limit, windowSec, daily, now) {
    const w = windowSec * 1000;
    const today = utcDay(now);
    let day = (await this.storage.get('day')) || null;
    if (!day || day.day !== today) day = { day: today, count: 0 };
    if (day.count >= daily) return { ok: false, scope: 'global', limit, remaining: 0, resetSec: secsToUtcMidnight(now) };
    const key = `ip:${ipHash}`;
    let rec = (await this.storage.get(key)) || null;
    if (!rec || now >= rec.start + w) rec = { start: now, count: 0 };
    const resetSec = Math.max(1, Math.ceil((rec.start + w - now) / 1000));
    if (rec.count >= limit) return { ok: false, scope: 'ip', limit, remaining: 0, resetSec };
    rec.count++;
    day.count++;
    await this.storage.put({ [key]: rec, day });
    if (rec.count === 1 && !(await this.storage.getAlarm())) await this.storage.setAlarm(rec.start + w + 1000);
    return { ok: true, scope: 'ip', limit, remaining: limit - rec.count, resetSec };
  }

  async alarm() {
    const now = Date.now();
    const rows = await this.storage.list({ prefix: 'ip:' });
    const expired = [];
    let next = Infinity;
    for (const [k, v] of rows) {
      const end = (v && v.start ? v.start : 0) + 3600_000;
      if (end <= now) expired.push(k); else next = Math.min(next, end);
    }
    for (let i = 0; i < expired.length; i += 128) await this.storage.delete(expired.slice(i, i + 128));
    if (next !== Infinity) await this.storage.setAlarm(next + 1000);
  }
}

export async function sha256Hex(s) {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

// Per-isolate state: fallback counters (when the DO is unreachable) and "denied until" hints.
const mem = new Map();
const deniedUntil = new Map();
export function _resetMem() { mem.clear(); deniedUntil.clear(); }

export function memConsume(key, limit, windowSec, daily, now = Date.now()) {
  const w = windowSec * 1000;
  const dayKey = `day:${utcDay(now)}`;
  const d = mem.get(dayKey) || 0;
  if (d >= daily) return { ok: false, scope: 'global', limit, remaining: 0, resetSec: secsToUtcMidnight(now), source: 'memory' };
  let rec = mem.get(key);
  if (!rec || now >= rec.start + w) { rec = { start: now, count: 0 }; mem.set(key, rec); if (mem.size > 5000) { mem.clear(); mem.set(key, rec); } }
  const resetSec = Math.max(1, Math.ceil((rec.start + w - now) / 1000));
  if (rec.count >= limit) return { ok: false, scope: 'ip', limit, remaining: 0, resetSec, source: 'memory' };
  rec.count++;
  mem.set(dayKey, d + 1);
  return { ok: true, scope: 'ip', limit, remaining: limit - rec.count, resetSec, source: 'memory' };
}

export function quotaConfig(env = {}) {
  const n = (v, d) => { const x = Math.floor(Number(v)); return Number.isFinite(x) && x > 0 ? x : d; };
  return { limit: n(env.CHECKS_PER_HOUR, 20), windowSec: 3600, dailyCap: n(env.DAILY_CHECK_CAP, 400), shards: Math.min(64, n(env.QUOTA_SHARDS, 4)) };
}

/** Consumes one check for this IP (and one unit of the global daily cap). */
export async function consumeIpQuota(env, ip, cfg = quotaConfig(env), now = Date.now()) {
  const salt = env.IP_HASH_SALT || 'linkpulse-v1';
  const ipHash = await sha256Hex(`${salt}:${ip}`);
  const shard = parseInt(ipHash.slice(0, 8), 16) % cfg.shards;
  const perShard = Math.max(1, Math.ceil(cfg.dailyCap / cfg.shards));
  for (const [k, scope] of [[`shard:${shard}`, 'global'], [`ip:${ipHash}`, 'ip']]) {
    const until = deniedUntil.get(k);
    if (until && until > now) return { ok: false, scope, limit: cfg.limit, remaining: 0, resetSec: Math.ceil((until - now) / 1000), source: 'isolate_hint' };
  }
  const ns = env.IP_QUOTA;
  let r;
  if (ns && typeof ns.idFromName === 'function') {
    try {
      const stub = ns.get(ns.idFromName(`shard:${shard}`));
      const res = await stub.fetch(`https://quota/consume?ip=${ipHash}&limit=${cfg.limit}&window=${cfg.windowSec}&daily=${perShard}`, { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      r = { ...(await res.json()), source: 'durable_object' };
    } catch { /* fall through */ }
  }
  if (!r) r = memConsume(`ip:${ipHash}`, cfg.limit, cfg.windowSec, perShard, now);
  if (!r.ok) {
    deniedUntil.set(r.scope === 'global' ? `shard:${shard}` : `ip:${ipHash}`, now + r.resetSec * 1000);
    if (deniedUntil.size > 5000) deniedUntil.clear();
  }
  return { ...r, shard };
}
