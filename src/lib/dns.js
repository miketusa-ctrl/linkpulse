// DNS-over-HTTPS lookups so a hostname is only fetched if ALL its A/AAAA answers are public addresses.
// Workers have no DNS API, so this costs subrequests (2 per new host; up to 4 with resolver fallback).
// Used for the page and (since v0.2.0, Workers Paid) for every link host and redirect hop. Cached per host
// for the duration of ONE check (a fresh HostResolver is created per request).
import { blockedIp, TargetError } from './target.js';

const RESOLVERS = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];

export class HostResolver {
  constructor({ fetchImpl, timeoutMs = 2500, budget } = {}) {
    this.fetchImpl = fetchImpl || ((...a) => fetch(...a));
    this.timeoutMs = timeoutMs;
    this.budget = budget;
    this.cache = new Map();
    this.lookups = 0;
  }

  async query(name, type) {
    let lastErr;
    for (const base of RESOLVERS) {
      // Budget exhaustion must propagate (not be mistaken for a resolver failure).
      if (this.budget) this.budget.take();
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), this.timeoutMs);
      try {
        this.lookups++;
        const res = await this.fetchImpl(`${base}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' }, signal: ctl.signal });
        if (!res.ok) throw new Error(`DoH HTTP ${res.status}`);
        const j = await res.json();
        if (j.Status !== 0 && j.Status !== 3) throw new Error(`DoH rcode ${j.Status}`); // SERVFAIL/REFUSED: try next resolver
        return { status: j.Status, answers: (j.Answer || []).filter((a) => a.type === (type === 'A' ? 1 : 28)).map((a) => String(a.data)) };
      } catch (e) {
        if (e instanceof TargetError || e?.code === 'budget_exceeded' || /too many subrequests/i.test(String(e?.message))) throw e;
        lastErr = e;
      } finally { clearTimeout(t); }
    }
    throw lastErr || new Error('DoH failed');
  }

  /**
   * Throws TargetError unless every A/AAAA answer is public:
   *   blocked_target (non-public answer, 403) | dns_not_found (NXDOMAIN / no records, 422) | dns_error (resolvers failed, 502).
   * Rethrows budget errors unchanged. IP literals are checked statically elsewhere.
   */
  async assertPublic(hostname) {
    const host = hostname.replace(/\.$/, '').toLowerCase();
    if (blockedIp(host) !== undefined) return { addresses: [host] };
    if (this.cache.has(host)) return this.cache.get(host);
    const p = (async () => {
      let a, aaaa;
      try {
        [a, aaaa] = await Promise.all([this.query(host, 'A'), this.query(host, 'AAAA')]);
      } catch (e) {
        if (e instanceof TargetError || e?.code === 'budget_exceeded' || /too many subrequests/i.test(String(e?.message))) throw e;
        throw new TargetError('dns_error', `Could not resolve ${host} (DNS lookup failed). Please retry.`, 502);
      }
      const addresses = [...a.answers, ...aaaa.answers];
      if (!addresses.length) {
        throw new TargetError('dns_not_found', `${host} does not resolve to any address (${a.status === 3 ? 'NXDOMAIN' : 'no A/AAAA records'}).`, 422);
      }
      for (const ip of addresses) {
        const why = blockedIp(ip);
        if (why) throw new TargetError('blocked_target', `${host} resolves to a non-public address (${ip}: ${why}). LinkPulse only checks public websites.`, 403);
      }
      return { addresses };
    })();
    this.cache.set(host, p);
    // Failures stay cached too (within this one check) so 50 links to a dead host cost 2 lookups, not 100.
    return p;
  }
}
