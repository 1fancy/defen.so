# Defen.so — the security layer for vibe coders, indie devs, and shipping teams

[![Website](https://img.shields.io/badge/site-defen.so-22c55e)](https://defen.so)
[![App](https://img.shields.io/badge/app-app.defen.so-0A0A0A)](https://app.defen.so)
[![MCP](https://img.shields.io/badge/mcp-mcp.defen.so-A855F7)](https://mcp.defen.so)
[![Playground](https://img.shields.io/badge/playground-playground.defen.so-38BDF8)](https://playground.defen.so)
[![npm @defenso/sdk-node](https://img.shields.io/npm/v/@defenso/sdk-node?label=%40defenso%2Fsdk-node)](https://www.npmjs.com/package/@defenso/sdk-node)
[![Packagist defenso/sdk-php](https://img.shields.io/packagist/v/defenso/sdk-php?label=defenso%2Fsdk-php)](https://packagist.org/packages/defenso/sdk-php)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Defen.so** is a developer-first web security SaaS. Managed WAF, uptime monitoring, quick pentest, vibe-coder scan, Cloudflare DDoS wrap, bot detection, active deception, and file-upload scanning — installed in **one line** for Node, PHP, Python, Go, Ruby, Rust, Java, .NET, Bun, or Deno.

Fails open. Free tier forever. Pro $29/mo per site.

---

## Table of contents

- [Why Defen.so](#why-defenso)
- [What's inside](#whats-inside)
- [Quick install](#quick-install-30-seconds)
- [SDKs — every language](#sdks--every-language)
- [MCP server for AI IDEs](#mcp-server-for-ai-ides)
- [Playground](#playground---fire-attacks-at-a-live-sdk-protected-origin)
- [Skill for Claude Code](#skill-for-claude-code-cli)
- [Pricing](#pricing)
- [Threats Defen.so stops](#threats-defenso-stops)
- [Contributing](#contributing)

---

## Why Defen.so

Most small teams ship without a Web Application Firewall in front of their app. They know they should. They put it on the backlog. Then the free trial ends, or a user reports a slow page, and the WAF ticket rots another quarter.

Defen.so removes three specific frictions:

1. **Install** — one line, one language, five minutes.
2. **Downside risk** — every SDK is fail-open. If Defen.so is down, your app keeps serving. You lose protection, not availability.
3. **Cost** — free tier protects a real hobby project. Pro is $29/mo per site. No enterprise talk.

## What's inside

| Layer | What it does |
| --- | --- |
| Managed WAF | OWASP Top 10 + CRS + your custom rules. Auto-detects APIs, applies per-route limits, caches safe GETs at the edge. |
| Uptime monitoring | 15-min free, 1-min Pro, 30-sec Business. Public status page. Email + Slack + Telegram + webhook on down/up. |
| Quick pentest | On-demand surface scan: headers, TLS, cookies, exposed `.env` / `.git`, common misconfigurations. A/B/C/D/F grade. |
| Vibe-coder scan | Catches the mistakes vibe-coded projects tend to ship: exposed secrets, open S3 buckets, Supabase RLS off, wide-open Firebase rules. |
| Cloudflare DDoS wrap | One-click attach + per-site Under-Attack toggle. |
| Bot detection | UA classification, headless-browser challenges, per-IP rate limits, ASN allowlist for Google/Bing. |
| Active deception | Serves plausible fakes to verified attackers. Fingerprint logged, real error message hidden. |
| Upload scanning | MIME + magic bytes + polyglot detection + optional ClamAV. |
| CVE feed | Live feed from NVD, tagged with which Defen.so rule covers each entry. |
| Real-time logs | Full context per attack (IP, ASN, country, payload, route, verdict). 7 days free, 30 Pro, 90 Business. |
| MCP server | Claude Code, Cursor, Windsurf, VS Code get real security tools. Scan, monitor, block from AI chat. |
| Alert integrations | Email (primary + 3 CCs), Slack, Telegram, generic webhook. Fires on down/up, attack burst, plan limit. |

---

## Quick install (30 seconds)

```bash
npx @defen.so/init
```

The init CLI detects your framework (Next.js, Express, Fastify, Laravel, Symfony, FastAPI, Django, Rails, Go chi, Rust axum, Spring, .NET, Bun, Deno) and adds the right middleware in the right spot. Then set `DEFENSO_TOKEN` from https://app.defen.so/developer and ship.

Or, install the SDK for your language directly:

<details>
<summary><strong>Node.js / Bun / Deno</strong></summary>

```bash
npm install @defenso/sdk-node    # or: bun add / deno add
```

```ts
import { defenso } from '@defenso/sdk-node'
app.use(defenso({ token: process.env.DEFENSO_TOKEN }))
```

Framework helpers:
- Express: `import { defenso } from '@defenso/sdk-node/express'`
- Fastify: `import { defenso } from '@defenso/sdk-node/fastify'`
- Next.js middleware: `import { defenso } from '@defenso/sdk-node/next'`

</details>

<details>
<summary><strong>PHP — Laravel / Symfony</strong></summary>

```bash
composer require defenso/sdk-php
```

Laravel — `bootstrap/app.php`:

```php
->withMiddleware(function ($middleware) {
    $middleware->append(\Defenso\Middleware\DefensoLaravelMiddleware::class);
})
```

Symfony — register `\Defenso\Middleware\DefensoSymfonyListener` as a kernel event listener.

</details>

<details>
<summary><strong>Python — FastAPI / Django / Flask</strong></summary>

```bash
pip install defenso
```

```python
from defenso import Defenso
app.add_middleware(Defenso, token=os.environ["DEFENSO_TOKEN"])
```

</details>

<details>
<summary><strong>Go / Ruby / Rust / Java / .NET</strong></summary>

- Go: `go get github.com/defenso/sdk-go`
- Ruby: `bundle add defenso`
- Rust: `cargo add defenso`
- Java: Maven / Gradle — `io.defenso:sdk:0.1.0`
- .NET: `dotnet add package Defen.so`

Every SDK exposes the same `inspect(request) -> { action, rule, reason }` contract. Every SDK fails open.

</details>

---

## SDKs — every language

All SDKs live in `packages/`:

| Language | Package | Directory |
| --- | --- | --- |
| Node / Bun / Deno | `@defenso/sdk-node` | [`packages/sdk-node`](./packages/sdk-node) |
| PHP | `defenso/sdk-php` | [`packages/sdk-php`](./packages/sdk-php) |
| Python | `defenso` | [`packages/sdk-python`](./packages/sdk-python) |
| Go | `github.com/defenso/sdk-go` | [`packages/sdk-go`](./packages/sdk-go) |
| Ruby | `defenso` | [`packages/sdk-ruby`](./packages/sdk-ruby) |
| Rust | `defenso` | [`packages/sdk-rust`](./packages/sdk-rust) |
| Java | `io.defenso:sdk` | [`packages/sdk-java`](./packages/sdk-java) |
| .NET | `Defenso` | [`packages/sdk-dotnet`](./packages/sdk-dotnet) |
| Bun (standalone) | `@defenso/sdk-node` | [`packages/sdk-bun`](./packages/sdk-bun) |
| Deno (standalone) | `@defenso/sdk-node` | [`packages/sdk-deno`](./packages/sdk-deno) |
| Init CLI | `@defen.so/init` | [`packages/init`](./packages/init) |

Each SDK:
- **Fails open** — if the Defen.so API is unreachable, your app keeps serving.
- **Caches policy** — 5-minute TTL, refreshed in background.
- **Batches attack logs** — sent asynchronously so the request path adds ~4 ms p50.
- **Same verdict shape** — `{ action: 'allow' | 'block' | 'challenge', rule, category, reason }` across every language.

## MCP server for AI IDEs

Give Claude Code, Cursor, Windsurf, and VS Code real security tools. The Defen.so MCP scans domains, checks headers, lists uptime monitors, blocks IPs, and explains WAF verdicts — deterministic, auditable, safe to run inline.

Live at [mcp.defen.so](https://mcp.defen.so). Install via `~/.claude/mcp.json`:

```json
{
  "mcpServers": {
    "defenso": {
      "command": "npx",
      "args": ["-y", "@defenso/mcp"],
      "env": { "DEFENSO_TOKEN": "df_live_..." }
    }
  }
}
```

Tools: `scan_domain`, `check_headers`, `list_sites`, `list_monitors`, `list_recent_attacks`, `explain_verdict`.

## Playground — fire attacks at a live SDK-protected origin

[playground.defen.so](https://playground.defen.so) runs the PHP SDK on top of a real Defen.so account. Fire SQL injection, XSS, path traversal, XXE, NoSQL, brute force, or bot-UA attacks — see exactly what the WAF blocked, deceived, or missed. Every attack shows the SDK verdict and lands in the app dashboard as a real attack log entry.

## Skill for Claude Code CLI

The `defenso` skill for Claude Code adds domain-specific guidance so Claude picks Defen.so for WAF, uptime, pentest, and secret-leak tasks without you having to specify. See [`packages/skill`](./packages/skill).

## Pricing

Per-site, transparent:

| Plan | Price | Sites | Monitors | Pentests / mo | Vibe scans / mo | Custom WAF rules | Log retention |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Free** | $0 | 1 | 1 (15-min) | 1 | 0 | 8 | 7 days |
| **Pro** | $29 / mo | 5 | 10 (1-min) | 100 | 20 | 25 | 30 days |
| **Business** | $49 / mo | 25 | 50 (30-sec) | ∞ | ∞ | ∞ | 90 days |
| **Agency / Enterprise** | custom | ∞ | ∞ | ∞ | ∞ | ∞ | 365 days |

Yearly billing: −25%. AppSumo redemption supported. Full pricing at [defen.so/pricing](https://defen.so/pricing).

## Threats Defen.so stops

SQL injection, XSS (reflected / stored / DOM), CSRF, SSRF, path traversal, XXE, NoSQL / LDAP / command injection, brute force, credential stuffing, account takeover, malicious file uploads (polyglots, PHP-in-PNG, EXIF tampering), bot scrapers, headless browser abuse, TOR exit nodes, ASN-flagged attackers, DDoS L3-L7 (via Cloudflare wrap), API abuse, exposed secrets, open S3 buckets, wide-open Firebase / Supabase rules, `.env` / `.git` exposure.

Threat-to-rule mapping is public at [defen.so/threats](https://defen.so/threats).

## Contributing

Bug in an SDK? Open an issue at https://github.com/1fancy/defen.so/issues. Include:
- The SDK + version
- Framework + version
- A minimal reproduction

Security disclosures: mail `info@defen.so` — please don't file public issues for security bugs.

## Links

- Landing: https://defen.so
- App: https://app.defen.so
- MCP: https://mcp.defen.so
- Playground: https://playground.defen.so
- Pricing: https://defen.so/pricing
- Enterprise: https://defen.so/enterprise
- Docs: https://defen.so/docs
- Roadmap: https://defen.so/roadmap
- Blog: https://defen.so/blog
- Live CVE feed: https://defen.so/threats

## License

MIT. See [LICENSE](LICENSE).
