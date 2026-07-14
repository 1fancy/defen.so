# @defen.so/mcp

**Give your AI assistant real web-security tools.** The official [Defenso](https://defen.so) Model Context Protocol server plugs into Claude Code, Cursor, Windsurf, VS Code Copilot, or any assistant that speaks MCP. Deterministic tools, auditable output, safe to run inline — no hallucinated verdicts.

```bash
npx -y @defen.so/mcp
```

Free forever tier. Pro $29/mo per site.

[![Website](https://img.shields.io/badge/site-defen.so-22c55e)](https://defen.so)
[![Playground](https://img.shields.io/badge/playground-playground.defen.so-38BDF8)](https://playground.defen.so)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Quick install](#quick-install)
- [Wire it into your assistant](#wire-it-into-your-assistant)
- [Tools exposed](#tools-exposed)
- [How the AI actually uses these tools](#how-the-ai-actually-uses-these-tools)
- [Real workflow examples](#real-workflow-examples)
- [CLI](#cli)
- [Comparison with other AI security integrations](#comparison-with-other-ai-security-integrations)
- [Pricing](#pricing)
- [Companion packages](#companion-packages)
- [FAQ](#faq)
- [Links](#links)

---

## Why this exists

You are writing code in Cursor / Claude Code / Windsurf. Your AI just added an endpoint that reads a query param, interpolates it into a SQL string, and returns the result. You know it's a SQL-injection surface. Your AI doesn't — and even if it "knows", it has no way to *do* something about it beyond suggesting you add validation.

With `@defen.so/mcp` connected, the same AI can now:
- **Scan the endpoint** you just wrote for real vulnerabilities (via `scan_domain`)
- **Check security headers** on the site it deploys to (`check_headers`)
- **See attacks that already hit** the same route on other environments (`list_recent_attacks`)
- **Add a WAF rule** that catches the injection pattern in production (via the paid Pro-tier `deploy_rule` tool, with explicit confirmation)
- **Explain in plain English** what a WAF verdict means and how to reproduce it (`explain_verdict`)

No context switch. No dashboard tab. No "please go check X on defen.so". The AI stays in your editor and does the work.

## Quick install

```bash
# Global (recommended for daily use)
npm install -g @defen.so/mcp

# Or per-project via npx
npx -y @defen.so/mcp
```

**Connect your account** — one-line device-code link. Opens your browser, waits for approval, stores the token at `~/.defenso/config.json`:

```bash
defenso link
```

Or set `DEFENSO_TOKEN=df_live_...` in your environment. Either works. Get a token at [app.defen.so/developer](https://app.defen.so/developer).

## Wire it into your assistant

### Claude Code

Add to `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "defenso": {
      "command": "npx",
      "args": ["-y", "@defen.so/mcp"],
      "env": { "DEFENSO_TOKEN": "df_live_..." }
    }
  }
}
```

Reload Claude Code. The `defenso` tools appear in the tools list.

### Cursor

Add to `~/.cursor/mcp.json` — same JSON block as Claude Code.

### Windsurf

`~/.codeium/windsurf/mcp_config.json` — same JSON block.

### VS Code (Copilot Chat)

Command palette → *MCP: Add Server* → paste the block. Or edit `~/.vscode/mcp.json` directly.

### Any other stdio-MCP client

`@defen.so/mcp` is a plain stdio server. Any transport that speaks MCP works.

## Tools exposed

| Tool | Free | Pro | Business | What it does |
|---|---|---|---|---|
| `scan_domain` | ✅ 1/day | ✅ 100/mo | ✅ ∞ | Quick pentest surface scan of any public URL. Returns grade A-F + list of failing checks. |
| `check_headers` | ✅ | ✅ | ✅ | TLS grade, HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy in one call. |
| `list_sites` | ✅ | ✅ | ✅ | Every site under your account with plan + last-scan + coverage status. |
| `list_monitors` | ✅ | ✅ | ✅ | Every uptime monitor + latest status + last-checked timestamp. |
| `list_recent_attacks` | ✅ 7d | ✅ 30d | ✅ 90d | Attack logs in a time window, filterable by site + verdict + category. |
| `explain_verdict` | ✅ | ✅ | ✅ | Plain-English explanation of a WAF rule: what it catches, how attackers use it, how to reproduce, how to mitigate. |
| `add_waf_rule` | ❌ | ✅ 25 rules | ✅ ∞ | Add a custom WAF rule (pattern, target, action). Requires explicit confirmation. |
| `block_ip` | ❌ | ✅ | ✅ | Block a specific IP or ASN across sites you own. Requires explicit confirmation. |
| `run_vibe_scan` | ❌ | ✅ 20/mo | ✅ ∞ | Vibe-coder scan of a public URL: exposed secrets, open S3 buckets, Supabase RLS, Firebase rules. |

All read tools are always safe. Write tools (`add_waf_rule`, `block_ip`) require explicit user approval from the AI's UI — the MCP server does not auto-apply changes.

## How the AI actually uses these tools

The MCP server exposes each tool with a rich JSON schema that includes:
- The exact parameters the tool needs (with descriptions the AI can read)
- Examples of expected input
- What the return value looks like

Because MCP is a standardized protocol, the AI reads these schemas on connect and knows how to call every tool without any prompt engineering. You don't need to teach Claude what `scan_domain` does — it reads the description.

## Real workflow examples

<details>
<summary><strong>1. AI writes an endpoint, you ask "is this safe?"</strong></summary>

```
You: I just wrote /api/users?id=... in Express. Is it safe?

Claude Code: Let me check what Defenso would catch.

  → Called scan_domain({ url: "https://staging.myapp.com/api/users?id=1" })
  ← Grade B. HSTS missing. No exposed .env. SQL-injection surface not
     directly testable without live payload — the WAF would catch a UNION
     SELECT via the sqli.union rule but your app doesn't validate `id`
     as a number, so a live attacker could still enumerate rows.

  → Called list_recent_attacks({ hours: 24, category: "sqli" })
  ← 47 SQL-injection attempts blocked on your other sites in the last 24h.
     Common pattern: 1' OR '1'='1

Recommendation: add strict validation `id: z.number().int().positive()`
before the query, and I'll deploy a WAF rule tightening the sqli.or1eq1
pattern for this specific route. Want me to do both?
```

</details>

<details>
<summary><strong>2. Deploying a fix</strong></summary>

```
You: Deploy the WAF rule you mentioned.

Claude Code:
  → Called add_waf_rule({
      pattern: "['\"]?\\s*or\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+",
      flags: "i",
      target: "url",
      action: "block",
      category: "sqli",
      description: "OR N=N pattern targeting /api/users",
      site_id: 42
    })
  ← Rule deployed. Live in ~5 min (SDK policy TTL).
     Rule ID: usr.sqli.or_eq_users_42
     View: https://app.defen.so/sites/AB12CD34EF/rules/usr.sqli.or_eq_users_42
```

</details>

<details>
<summary><strong>3. Post-mortem on a WAF verdict</strong></summary>

```
You: A user complained their request got blocked. What happened?

Claude Code:
  → Called list_recent_attacks({ hours: 2, ip: "203.0.113.45" })
  ← 1 result: verdict=block, rule=xss.script_tag,
     url=/api/comments?body=<script>alert(1)</script>,
     ip=203.0.113.45, ua=Mozilla/5.0 (Macintosh...)

  → Called explain_verdict({ rule_id: "xss.script_tag" })
  ← This rule blocks any request whose body or query contains a literal
     `<script>` tag. Common false-positive: a developer testing XSS payloads
     against their own site. The rule's target is `body|query` and it
     doesn't inspect the Accept header, so JSON POSTs with escaped
     `<script>` strings (e.g. `"body": "<script>"`) will trigger too.

The user was testing an XSS payload against their own comments. Rule
worked correctly. Recommend: they should test against playground.defen.so
instead, which is designed for this.
```

</details>

## CLI

```bash
defenso link       # connect this device to your Defenso account (browser flow)
defenso whoami     # print the linked account
defenso status     # ping the Defenso edge, confirm the SDK API is reachable
defenso help       # list every command
defenso unlink     # remove ~/.defenso/config.json
```

## Comparison with other AI security integrations

| Feature | @defen.so/mcp | Snyk MCP | Nuclei via MCP | Semgrep MCP |
|---|---|---|---|---|
| Live WAF integration | ✅ | ❌ | ❌ | ❌ |
| Reads real production attack logs | ✅ | ❌ | ❌ | ❌ |
| Deploys rules to production | ✅ (Pro) | ❌ | ❌ | ❌ |
| Explains verdicts in plain English | ✅ | ⚠️ CVE lookup | ❌ | ⚠️ Rule description |
| Runs pentest scanner | ✅ | ⚠️ SAST only | ✅ | ⚠️ SAST only |
| Runs vibe-coder / secret scan | ✅ | ✅ | ⚠️ | ✅ |
| Uptime monitoring | ✅ | ❌ | ❌ | ❌ |
| Free tier | ✅ | ⚠️ Limited | ✅ | ⚠️ Limited |
| Zero-config on install | ✅ | ⚠️ | ⚠️ | ⚠️ |

Defenso is the only MCP-integrated tool that combines *runtime* protection with the AI's *design-time* knowledge.

## Pricing

Per-site, transparent:

| Plan | Price | MCP tool access |
|---|---|---|
| **Free** | $0 forever | Read tools + 1 pentest/day + 7-day log lookback |
| **Pro** | $29/mo | Everything free + `add_waf_rule` (25 rules) + `block_ip` + `run_vibe_scan` (20/mo) + 30-day log lookback |
| **Business** | $49/mo | Everything Pro + unlimited rules + unlimited scans + 90-day log lookback + SIEM webhook |
| **Enterprise** | custom | Everything Business + dedicated regions + SSO + on-call + 365-day retention |

Yearly billing: −25%. Full pricing: [defen.so/pricing](https://defen.so/pricing).

## Companion packages

| Package | Registry | Purpose |
|---|---|---|
| [`@defen.so/init`](https://www.npmjs.com/package/@defen.so/init) | npm | One-command bootstrap that installs the right Defenso SDK for your framework |
| [`@defenso/sdk-node`](https://www.npmjs.com/package/@defenso/sdk-node) | npm | Node / Bun / Deno WAF SDK |
| [`defenso/sdk-php`](https://packagist.org/packages/defenso/sdk-php) | Packagist | PHP 8.2+ SDK (Laravel, Symfony, plain PHP) |
| [`defenso`](https://pypi.org/project/defenso/) | PyPI | Python 3.10+ SDK |

Plus Go, Ruby, Rust, Java, .NET — all in the [public repo](https://github.com/1fancy/defen.so).

## Environment

| Variable | Default | Notes |
|---|---|---|
| `DEFENSO_TOKEN` | — | API key. Auto-loaded from `~/.defenso/config.json` after `defenso link`. |
| `DEFENSO_API` | `https://mcp.defen.so` | Override the MCP-facing endpoint for self-hosted setups. |
| `DEFENSO_APP` | `https://app.defen.so` | Override the app API for policy + scan calls. |
| `DEFENSO_TIMEOUT_MS` | `8000` | Per-tool timeout. Bump if scanning slow sites. |

## FAQ

<details>
<summary><strong>Does it modify my code?</strong></summary>

No. The MCP server reads your Defenso account and runs scans. Any *code* change is done by your AI assistant, not by the server. The server itself never touches your filesystem beyond `~/.defenso/config.json`.
</details>

<details>
<summary><strong>Does the AI see my attack logs?</strong></summary>

Only when you ask it to (e.g. "check recent attacks"). The AI cannot poll — every call is initiated by your prompt. Log payloads are truncated to safe lengths (URL 500 chars, body 200 chars).
</details>

<details>
<summary><strong>Can it deploy rules without asking me?</strong></summary>

No. `add_waf_rule` and `block_ip` are marked as "write" tools in the MCP schema — every MCP-compatible client shows an explicit confirmation dialog before running them. The server also refuses to run write tools when the API token is missing the required plan tier.
</details>

<details>
<summary><strong>What about rate limits?</strong></summary>

Same as the Defenso API: read tools 120/hour per IP, write tools plan-gated. `scan_domain` uses your account's pentest quota (Free 1/day, Pro 100/mo, Business ∞).
</details>

<details>
<summary><strong>Can I use it without a Defenso account?</strong></summary>

`scan_domain` and `check_headers` work in "anonymous" mode with reduced quota (1 scan/day per IP, no history). Everything else requires a token.
</details>

## Links

- Marketing: [defen.so](https://defen.so)
- App: [app.defen.so](https://app.defen.so)
- MCP endpoint: [mcp.defen.so](https://mcp.defen.so)
- Playground: [playground.defen.so](https://playground.defen.so)
- Docs: [defen.so/docs](https://defen.so/docs)
- Threat map: [defen.so/threats](https://defen.so/threats)
- Source: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- Contact: info@defen.so

## License

MIT © Defenso

---

**Keywords** — model context protocol · MCP · Claude Code · Cursor · Windsurf · VS Code Copilot · codex · AI security · vibe coder security · agentic security · WAF · pentest · security scanner · vibe coder tools · web application firewall · attack logs · uptime monitoring · Defenso · OWASP · SQL injection · XSS · CSRF · SSRF · path traversal · XXE · brute force · credential stuffing · bot detection · deception · honeypot · Cloudflare wrap · edge security · Next.js security · Laravel security · Django security · FastAPI security · Rails security · Go security · Rust security · Node security · PHP security · Python security
