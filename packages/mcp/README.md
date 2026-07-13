# @defen.so/mcp

**Give your AI assistant real web-security tools.** Defenso's Model Context Protocol server plugs into Claude Code, Cursor, Windsurf, VS Code, or any assistant that speaks MCP. Deterministic tools, auditable output, safe to run inline — no hallucinated verdicts.

- Scan any domain for TLS, header, cookie, and exposed-file issues
- List and query your Defenso uptime monitors and attack logs
- Explain a WAF verdict in plain language
- One command connect: `npx -y @defen.so/mcp link`

Homepage: [defen.so](https://defen.so) · Docs: [defen.so/mcp](https://defen.so/mcp) · Source: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so)

## Install

```bash
# Global (recommended for interactive use)
npm install -g @defen.so/mcp

# Or per-project via npx
npx -y @defen.so/mcp
```

## Connect

**One-line device-code link.** Opens your browser, waits for approval, stores the token at `~/.defenso/config.json`:

```bash
defenso link
```

Or set `DEFENSO_TOKEN` in your environment / config — either works.

## Wire it into your assistant

### Claude Code (`~/.claude/mcp.json`)

```json
{
  "mcpServers": {
    "defen.so": {
      "command": "npx",
      "args": ["-y", "@defen.so/mcp"]
    }
  }
}
```

### Cursor / Windsurf / VS Code

Same JSON block dropped into the equivalent MCP config file for your editor.

### codex-cli / other MCP clients

Any transport that speaks stdio MCP works. `@defen.so/mcp` is a plain stdio server.

## Tools exposed

| Tool | What it does |
|---|---|
| `scan_domain` | Defenso surface pentest: TLS, HSTS, CSP, cookie flags, exposed `.env`/`.git`, headers. Graded A–F. |
| `check_headers` | Fast header-only check for HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy. |
| `list_monitors` | Every uptime monitor on the authenticated account, with current status and last check. |
| `explain_verdict` | Plain-English explanation of a Defenso attack-log verdict, plus reproduction and mitigation. |

## CLI

```bash
defenso link      # connect this device to your Defenso account
defenso whoami    # print the linked account
defenso status    # ping the Defenso edge
defenso help
```

## Environment

- `DEFENSO_TOKEN` — API key. Auto-loaded from `~/.defenso/config.json` after `defenso link`.
- `DEFENSO_API` — override the API base URL. Default `https://mcp.defen.so`.

## Fail-safe

The server never modifies your app. It only reads. Write actions (deploy rule, block IP, apply fix) require an additional Pro-tier tool and explicit confirmation.

## License

MIT © Defenso

---

**Keywords** — model context protocol · MCP · Claude Code · Cursor · Windsurf · VS Code · codex · AI security · WAF · pentest · security scanner · vibe coder tools · web application firewall · Defenso
