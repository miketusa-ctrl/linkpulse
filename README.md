# LinkPulse

Check one web page for broken links, redirect chains hop by hop and mixed content. Free, no key.

## Live service

- Web app and API: https://linkpulse.mike-tusa.workers.dev/
- Pricing and plans: https://linkpulse.mike-tusa.workers.dev/
- Support: digitalpromohub.support@gmail.com

## Use it from an AI assistant (MCP)

LinkPulse is a remote MCP server (Streamable HTTP) at `https://linkpulse.mike-tusa.workers.dev/mcp`. Tools: `check_links`.

Cursor, Cline and Windsurf accept this config:

```json
{
  "mcpServers": {
    "linkpulse": {
      "type": "http",
      "url": "https://linkpulse.mike-tusa.workers.dev/mcp"
    }
  }
}
```

Claude Desktop: open Settings > Connectors, choose "Add custom connector" and paste `https://linkpulse.mike-tusa.workers.dev/mcp`. Or, for clients that only support local (stdio) servers, use the mcp-remote bridge: `npx mcp-remote https://linkpulse.mike-tusa.workers.dev/mcp`.

VS Code uses a `servers` key instead of `mcpServers`.

The `server.json` file is the [MCP Registry](https://registry.modelcontextprotocol.io) manifest for this server.

## Run your own copy

Requires Node.js 20+ and a Cloudflare account.

```bash
npm install
npx wrangler dev        # local dev server
```

`wrangler.toml` is a template: create your own KV namespaces / D1 databases / rate-limit namespaces and replace the `<PLACEHOLDER>` values before `npx wrangler deploy`. Any secrets the Worker reads go in `wrangler secret put` (or `.dev.vars` locally), never in the repo.

## License

MIT (c) Digital Promo Hub. See [LICENSE](LICENSE).
