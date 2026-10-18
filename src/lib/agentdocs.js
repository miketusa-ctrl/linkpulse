// llms.txt, OpenAPI 3.1 and the MCP server card, generated from code constants and
// limitsFor(env)/quotaConfig(env). Adapted from SwearGuard/CheckDigit src/lib/agentdocs.js. Never hard-code a
// limit here: everything comes from `L` or code constants.
import { TOOLS, SUPPORTED_VERSIONS, DISCOVERY_PER_MIN, MAX_BODY_BYTES as MCP_BODY, SERVER_INFO, RESULT_OUT, MCP_MAX_PROBLEMS, MAX_URL_LEN } from './mcp.js';
import { VERSION, SCHEMA } from './check.js';

export const SUPPORT_EMAIL = 'digitalpromohub.support@gmail.com';
export const mcpClientConfig = (origin) => ({ mcpServers: { linkpulse: { type: 'http', url: `${origin}/mcp` } } });

/** L = { perHour, dailyCap, burstPerMin, maxLinks, deadlineSec, budget, maxPageBytes } */
export const llmsTxt = (origin, L) => `# LinkPulse

> Free broken-link and redirect-chain checker for one web page at a time: fetches the page, checks up to ${L.maxLinks} of its links and assets, and lists every redirect hop, broken link, redirect loop and mixed-content reference. Public JSON API plus a remote MCP server for AI agents. No account, no key.

## For AI agents

- [MCP server](${origin}/mcp): remote MCP over Streamable HTTP (POST only, stateless, JSON responses). Protocol versions: ${SUPPORTED_VERSIONS.join(', ')}. Tools: ${TOOLS.map((t) => `\`${t.name}\` (${Object.keys(t.inputSchema.properties).join(', ')})`).join(', ')}. Read-only. Client config (most MCP clients accept this; some use a different format, for example VS Code uses a \`servers\` key): \`${JSON.stringify(mcpClientConfig(origin))}\`
- [OpenAPI 3.1 spec](${origin}/openapi.json): machine-readable description of the JSON API
- [Docs](${origin}/docs): human-readable API docs, response schema and a GitHub Action

## JSON API

- \`GET ${origin}/api/check?url=https://example.com/\` (optional \`assets=false\` = only <a>/<area> links, \`max=1..${L.maxLinks}\`), or \`POST ${origin}/api/check\` with JSON \`{"url": "...", "assets": true, "max": ${L.maxLinks}}\` (body at most 8 KB). Only public http/https URLs on ports 80/443.
- Result (schema \`${SCHEMA}\`): page (status, finalUrl, redirects, hops), summary counts (ok, redirected, broken, blocked, unchecked, mixedContent, longChains, redirectLoops, maybeBotBlocked, resolvesPrivate), links[] (category ok/redirect/broken/blocked/unchecked, status, every hop, flags), truncated + truncatedReasons, notChecked, limits, timings.
- One page per check, up to ${L.maxLinks} links, about ${L.deadlineSec} s at most. Not a crawler. Links added by JavaScript are not seen.
- Errors: { "error": { "code", "message" } } with 400 (invalid_url, invalid_scheme, credentials_in_url, invalid_request), 403 (blocked_target, blocked_port, blocked_redirect), 404 (not_found), 405 (method_not_allowed), 413 (invalid_request: body over 8 KB), 422 (dns_not_found), 429 (rate_limited, with Retry-After and error.scope ip/global/burst), 500 (internal_error), 502 (page_fetch_failed, dns_error, bad_redirect, redirect_loop, too_many_redirects, budget_exceeded), 504 (page_timeout).
- \`GET ${origin}/api/health\`: version, limits and rate limits.

## Limits and keys

- No API keys yet; everyone is anonymous. ${L.perHour} checks per hour per IP plus a burst limit of about ${L.burstPerMin} per minute, and ${L.dailyCap} checks per day shared by all users (HTTP 429 until 00:00 UTC when used up). The MCP endpoint uses the same counters: each \`check_links\` call is one check (it lists at most ${MCP_MAX_PROBLEMS} problem links; the summary counts are complete). Identical checks within about 2 minutes are served from cache and don't count. Non-call MCP messages don't count as checks, but are capped at about ${DISCOVERY_PER_MIN}/min per IP (HTTP 429 + Retry-After). Max MCP body ${MCP_BODY} bytes; max URL ${MAX_URL_LEN} characters.
- Free. There is no paid plan.

## Optional

- [Privacy](${origin}/#privacy): checked URLs and results are not stored. A keyed hash of your IP is used for the hourly limit and deleted after the hour; a salted, daily-rotating hash of your network is kept for up to 9 days to count unique visitors per day. No IP address is stored.
- Contact: ${SUPPORT_EMAIL}
`;

const H = (d) => ({ description: d, schema: { type: 'string' } });
const errResp = (d, headers) => ({ description: d, ...(headers ? { headers } : {}), content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } });
const rlHeaders = { 'x-ratelimit-limit': H('Checks per hour per IP'), 'x-ratelimit-remaining': H('Checks left in the current hour'), 'x-ratelimit-reset': H('Seconds until the hourly window resets'), 'x-cache': H('MISS, or HIT for a cached identical check (not counted)') };

export function openApiSpec(origin, L) {
  const urlParam = { name: 'url', in: 'query', required: true, description: 'Public http(s) page URL (ports 80/443). Without a scheme, https:// is assumed.', schema: { type: 'string', minLength: 1, maxLength: 2048 } };
  const checkResponses = {
    200: { description: 'Check result (linkpulse.check.v1)', headers: rlHeaders, content: { 'application/json': { schema: { $ref: '#/components/schemas/CheckResult' } } } },
    400: errResp('invalid_url, invalid_scheme, credentials_in_url or invalid_request'),
    403: errResp('blocked_target, blocked_port or blocked_redirect (private/loopback/metadata target, incl. names that resolve to one)'),
    405: errResp('method_not_allowed', { allow: H('GET, POST, OPTIONS') }),
    413: errResp('invalid_request: POST body over 8 KB'),
    422: errResp('dns_not_found'),
    429: errResp('rate_limited (error.scope ip, global or burst; error.retryAfterSec)', { 'retry-after': H('Seconds to wait'), ...rlHeaders }),
    500: errResp('internal_error'),
    502: errResp('page_fetch_failed, dns_error, bad_redirect, redirect_loop, too_many_redirects or budget_exceeded'),
    504: errResp('page_timeout'),
  };
  const allow = { allow: { schema: { type: 'string', enum: ['POST, OPTIONS'] } } };
  return {
    openapi: '3.1.0',
    info: {
      title: 'LinkPulse', version: VERSION, contact: { email: SUPPORT_EMAIL },
      description: `Check ONE web page for broken links, redirect chains (hop by hop), redirect loops and mixed content. Up to ${L.maxLinks} links per check, about ${L.deadlineSec} s max. Free, no key: ${L.perHour} checks/hour per IP (+ burst ~${L.burstPerMin}/min) and ${L.dailyCap} checks/day shared by all users. Private/loopback/metadata targets are refused.`,
    },
    servers: [{ url: origin }],
    security: [{}],
    components: {
      schemas: {
        Error: { type: 'object', properties: { error: { type: 'object', properties: { code: { type: 'string' }, message: { type: 'string' }, retryAfterSec: { type: 'integer' }, scope: { type: 'string', enum: ['ip', 'global', 'burst'] } }, required: ['code', 'message'] }, version: { type: 'string' } }, required: ['error'] },
        CheckResult: { type: 'object', description: 'See /docs#schema for every field.', properties: {
          schema: { type: 'string' }, version: { type: 'string' }, checkedAt: { type: 'string' }, input: { type: 'string' },
          page: { type: 'object' }, summary: { type: 'object', additionalProperties: { type: 'integer' } }, truncated: { type: 'boolean' },
          truncatedReasons: { type: 'array', items: { type: 'string' } }, links: { type: 'array', items: { type: 'object' } },
          notChecked: { type: 'object' }, skipped: { type: 'object' }, notes: { type: 'array', items: { type: 'object' } }, limits: { type: 'object' },
          timings: { type: 'object' }, subrequests: { type: 'integer' }, dnsLookups: { type: 'integer' },
        }, required: ['schema', 'version', 'page', 'summary', 'links', 'truncated'] },
        McpCheckLinksResult: RESULT_OUT,
      },
    },
    paths: {
      '/api/check': {
        get: { operationId: 'checkPage', summary: 'Check one page', parameters: [urlParam,
          { name: 'assets', in: 'query', required: false, description: 'false = only <a>/<area> links (default true)', schema: { type: 'string', enum: ['true', 'false'] } },
          { name: 'max', in: 'query', required: false, description: `Links to check (default ${L.maxLinks})`, schema: { type: 'integer', minimum: 1, maximum: L.maxLinks } }], responses: checkResponses },
        post: { operationId: 'checkPagePost', summary: 'Check one page (JSON or form body, max 8 KB)', requestBody: { required: true, content: {
          'application/json': { schema: { type: 'object', properties: { url: { type: 'string', maxLength: 2048 }, assets: { type: 'boolean' }, max: { type: 'integer', minimum: 1, maximum: L.maxLinks } }, required: ['url'] } },
          'application/x-www-form-urlencoded': { schema: { type: 'object', properties: { url: { type: 'string' }, assets: { type: 'string' }, max: { type: 'string' } }, required: ['url'] } } } }, responses: checkResponses },
      },
      '/api/health': { get: { operationId: 'health', summary: 'Service version, limits and rate limits', responses: {
        200: { description: 'OK', content: { 'application/json': { schema: { type: 'object' } } } }, 405: errResp('method_not_allowed') } } },
      '/mcp': {
        post: { operationId: 'mcp', summary: `MCP JSON-RPC 2.0 (Streamable HTTP, stateless). Protocol versions ${SUPPORTED_VERSIONS.join(', ')}. Max body ${MCP_BODY} bytes.`,
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object' } } } },
          responses: { 200: { description: 'JSON-RPC response (tool errors are results with isError and _meta["linkpulse/error"])', headers: { ...rlHeaders, 'retry-after': H('Seconds (on a rate-limited tools/call)') } }, 202: { description: 'Notification or client response accepted' }, 400: { description: 'Parse error, invalid request, header mismatch or unsupported version' }, 401: { description: 'Reserved (no API keys yet; no WWW-Authenticate)' }, 403: { description: 'Origin not allowed' }, 404: { description: 'Unknown method (2026-07-28)' }, 413: { description: 'Body too large' }, 429: { description: 'Too many MCP requests', headers: { 'retry-after': H('Seconds') } }, 500: { description: 'Internal error' }, 503: { description: 'Unavailable' } } },
        get: { operationId: 'mcpGet', summary: 'Not supported (stateless, no SSE)', responses: { 405: { description: 'Method not allowed', headers: allow } } },
        delete: { operationId: 'mcpDelete', summary: 'Not supported (no sessions)', responses: { 405: { description: 'Method not allowed', headers: allow } } },
      },
    },
  };
}

export const serverCard = (origin) => ({
  serverInfo: { name: SERVER_INFO.name, title: SERVER_INFO.title, version: VERSION },
  transport: { type: 'streamable-http', url: `${origin}/mcp` },
  authentication: { required: false },
  tools: TOOLS, resources: [], prompts: [],
});
