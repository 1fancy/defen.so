# Defen.so — modern security kit for developers & vibe coders

> **Scan your website, apps & GitHub for vulnerabilities. Block attacks & bad bots, rate-limit your APIs, monitor uptime, domain & SSL expiry — all in one security platform.**
>
> 🔎 Scan & pentest · 📈 Monitoring & uptime · 🔔 Instant alerts · 🚦 API rate limits · 🛡️ 360° protection · 🤖 MCP & SDKs
>
> `npx @defen.so/mcp scan yourdomain.com` — free, no signup.

<p align="center">
  <img src="https://defen.so/assets/store/hero-1.png" alt="Monitor everything in one place — uptime, APIs, domains & SSL, with real-time alerts everywhere" width="49%">
  <img src="https://defen.so/assets/store/hero-5.png" alt="Website & apps security scanner — reports you can understand, with a copy-paste AI fix prompt" width="49%">
</p>
<p align="center">
  <img src="https://defen.so/assets/store/hero-3.png" alt="Is your website & app online or slow? 24/7 uptime & performance monitoring" width="32%">
  <img src="https://defen.so/assets/store/hero-4.png" alt="Protect & rate-limit your API endpoints — stop bots & abuse in 2 minutes" width="32%">
  <img src="https://defen.so/assets/store/hero-2.png" alt="MCP & security skills for AI coding — vulnerability scanning and secure-development guidance in your CLI" width="32%">
</p>

[![Website](https://img.shields.io/badge/site-defen.so-22c55e)](https://defen.so)
[![App](https://img.shields.io/badge/app-app.defen.so-0A0A0A)](https://app.defen.so)
[![MCP](https://img.shields.io/badge/mcp-mcp.defen.so-A855F7)](https://mcp.defen.so)
[![Playground](https://img.shields.io/badge/playground-playground.defen.so-38BDF8)](https://playground.defen.so)
[![npm @defen.so/sdk-node](https://img.shields.io/npm/v/@defen.so/sdk-node?label=%40defen.so%2Fsdk-node)](https://www.npmjs.com/package/@defen.so/sdk-node)
[![Packagist defenso/sdk-php](https://img.shields.io/packagist/v/defenso/sdk-php?label=defenso%2Fsdk-php)](https://packagist.org/packages/defenso/sdk-php)
[![WordPress plugin](https://img.shields.io/wordpress/plugin/v/defen-so-connector?label=wp%20plugin)](https://wordpress.org/plugins/defen-so-connector/)
[![Google Play](https://img.shields.io/badge/Google%20Play-Defenso%20Alerts-34A853)](https://play.google.com/store/apps/details?id=so.defen.alerts)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Defen.so** is a developer-first web security SaaS. Managed WAF, uptime monitoring, quick pentest (headers, TLS, **email security** — SPF/DKIM/DMARC — and compliance-style findings), vibe-coder scan, repo/secret scan, Cloudflare DDoS wrap, bot detection, active deception, and file-upload scanning — installed in **one line** for Node, PHP/Laravel, Python, Go, Ruby, Java, .NET, Rust, Bun, or Deno.

**Your security layer. Shipped in 30 seconds.** One line — `npx @defen.so/init` — and every SDK fails open, so if Defen.so is ever down your app keeps serving.

---

## Table of contents

- [Why Defen.so](#why-defenso)
- [What's inside](#whats-inside)
- [Quick install](#quick-install-30-seconds)
- [SDKs — every language](#sdks--every-language)
- [MCP server for AI IDEs](#mcp-server-for-ai-ides)
- [WordPress plugin](#wordpress-plugin)
- [Mobile app — Defenso Alerts](#mobile-app--defenso-alerts)
- [Playground](#playground---fire-attacks-at-a-live-sdk-protected-origin)
- [Free tools](#free-tools)
- [Skill for Claude Code](#skill-for-claude-code-cli)
- [Standards & mappings](#standards--mappings)
- [Pricing](#pricing)
- [Threats Defen.so stops](#threats-defenso-stops)
- [Contributing](#contributing)

---

## Why Defen.so

Most small teams ship without a Web Application Firewall in front of their app. They know they should. They put it on the backlog. Then the free trial ends, or a user reports a slow page, and the WAF ticket rots another quarter.

Defen.so removes three specific frictions:

1. **Install** — one line, one language, 30 seconds.
2. **Downside risk** — every SDK is fail-open. If Defen.so is down, your app keeps serving. You lose protection, not availability.
3. **Cost** — a real free tier protects a hobby project. Pro is $29/mo per site. No enterprise talk to get started.

## What's inside

| Layer | What it does |
| --- | --- |
| Managed WAF | OWASP Top 10 + CRS + your custom rules. Auto-detects APIs, applies per-route limits, caches safe GETs at the edge. |
| Uptime monitoring | 15-min free, 1-min Pro, 30-sec Business. Public status page. Email + Slack + Discord + Telegram + webhook + mobile push on down/up. |
| Quick pentest | On-demand surface scan: headers, TLS, cookies, exposed `.env` / `.git`, **email security (SPF / DKIM / DMARC)**, and compliance-style findings. A/B/C/D/F grade. |
| Vibe-coder scan | Catches the mistakes vibe-coded projects tend to ship: exposed secrets, open S3 buckets, Supabase RLS off, wide-open Firebase rules. |
| Repo / secret scan | Point it at a public `github.com/{org}/{repo}` — probes the default branch for `.env`, service-account JSON, and secret-family patterns. |
| Cloudflare DDoS wrap | One-click attach + per-site Under-Attack toggle. |
| Bot detection | UA classification, headless-browser challenges, per-IP rate limits, ASN allowlist for Google/Bing. |
| Active deception | Serves plausible fakes to verified attackers. Fingerprint logged, real error message hidden. |
| Upload scanning | MIME + magic bytes + polyglot detection + optional ClamAV. |
| CVE feed | Live feed from NVD, tagged with which Defen.so rule covers each entry. |
| Real-time logs | Full context per attack (IP, ASN, country, payload, route, verdict). 7 days free, 30 Pro, 90 Business. |
| MCP server | Claude Code, Cursor, Windsurf, VS Code get real security tools. Scan, monitor, guard, block from AI chat. |
| WordPress plugin | [Defen.so Connector](https://wordpress.org/plugins/defen-so-connector/) — local malware scan, file integrity, login hardening, geo-block, activity log with no account; one-click connect for managed WAF + attack log + uptime + CVE lookups. |
| Mobile app | [Defenso Alerts](https://play.google.com/store/apps/details?id=so.defen.alerts) on Google Play — call-style **Alarm** notifications that ring through silent mode / DND until you acknowledge. iOS coming soon. |
| Alert integrations | Mobile push, email (primary + 3 CCs), Slack, Discord, Telegram, generic webhook. Fires on down/up, attack burst, plan limit. |

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
npm install @defen.so/sdk-node    # or: bun add / deno add
```

```ts
import { defenso } from '@defen.so/sdk-node'
app.use(defenso({ token: process.env.DEFENSO_TOKEN }))
```

Framework helpers:
- Express: `import { defenso } from '@defen.so/sdk-node/express'`
- Fastify: `import { defensoFastify } from '@defen.so/sdk-node/fastify'`
- Next.js middleware: `import { defensoNext } from '@defen.so/sdk-node/next'`

Bun and Deno re-export the Node SDK — `import ... from 'npm:@defen.so/sdk-node'`.

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
<summary><strong>Python / Go / Ruby / Rust / Java / .NET</strong></summary>

Every SDK exposes the same `inspect(request) -> { action, rule, reason }` contract and fails open. Scaffolds for these languages live under [`packages/`](./packages) — see [defen.so/install](https://defen.so/install) for the current registry-publish status of each. You can protect any app today with zero code by signing up at [app.defen.so](https://app.defen.so) (uptime + surface scans turn on immediately) or routing traffic through the edge WAF via CNAME on the Business plan.

</details>

---

## SDKs — every language

All SDKs live in `packages/`:

| Language | Package | Directory |
| --- | --- | --- |
| Node / Bun / Deno | `@defen.so/sdk-node` | [`packages/sdk-node`](./packages/sdk-node) |
| PHP / Laravel | `defenso/sdk-php` | [`packages/sdk-php`](./packages/sdk-php) |
| Python | `defenso` | [`packages/sdk-python`](./packages/sdk-python) |
| Go | `github.com/defenso/sdk-go` | [`packages/sdk-go`](./packages/sdk-go) |
| Ruby | `defenso` | [`packages/sdk-ruby`](./packages/sdk-ruby) |
| Java | `io.defenso:sdk` | [`packages/sdk-java`](./packages/sdk-java) |
| .NET | `Defenso` | [`packages/sdk-dotnet`](./packages/sdk-dotnet) |
| Rust | `defenso` | [`packages/sdk-rust`](./packages/sdk-rust) |
| Bun (re-exports Node) | `@defen.so/sdk-node` | [`packages/sdk-bun`](./packages/sdk-bun) |
| Deno (re-exports Node) | `@defen.so/sdk-node` | [`packages/sdk-deno`](./packages/sdk-deno) |
| Init CLI | `@defen.so/init` | [`packages/init`](./packages/init) |
| MCP server | `@defen.so/mcp` | [`packages/mcp`](./packages/mcp) |

Each SDK:
- **Fails open** — if the Defen.so API is unreachable, your app keeps serving.
- **Caches policy** — 5-minute TTL, refreshed in background.
- **Batches attack logs** — sent asynchronously so the request path stays fast.
- **Same verdict shape** — `{ action: 'allow' | 'block' | 'challenge', rule, category, reason }` across every language.

## MCP server for AI IDEs

Give Claude Code, Cursor, Windsurf, and VS Code real security tools. The Defen.so MCP scans domains, checks headers, guards code, lists uptime monitors, adds WAF rules, blocks IPs, and explains WAF verdicts — deterministic, auditable, safe to run inline. Scan output now also surfaces **email-security (SPF / DKIM / DMARC)** and compliance-style findings alongside the usual header/TLS grade.

Live at [mcp.defen.so](https://mcp.defen.so). Install via `~/.claude/mcp.json`:

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

Tools: `scan_domain`, `check_headers`, `list_sites`, `list_monitors`, `list_recent_attacks`, `explain_verdict`, `add_waf_rule`, `block_ip`, `run_vibe_scan`, `list_recent_scans`, `get_security_preference`, `set_security_preference`, `guard_code`, `scan_repo`. The MCP calls no LLM of its own — it runs on **your** AI assistant's credits and enforces your per-site plan quotas. See [`packages/mcp`](./packages/mcp) for the full tool reference.

## WordPress plugin

[**Defen.so Connector**](https://wordpress.org/plugins/defen-so-connector/) (slug `defen-so-connector`) is **live on the WordPress.org plugin directory**. Source lives in [`packages/wp-plugin`](./packages/wp-plugin).

- **Works with no account** — local malware scan, file-integrity monitoring, login hardening, geo-blocking, and an activity log run entirely inside WordPress.
- **One-click connect** — link a Defen.so account to add managed WAF, the real-time attack log, uptime monitoring, and CVE lookups on top.

## Mobile app — Defenso Alerts

[**Defenso Alerts**](https://play.google.com/store/apps/details?id=so.defen.alerts) (bundle `so.defen.alerts`) is **live on Google Play**. **iOS coming soon.** Marketing page: [defen.so/website-monitor-app](https://defen.so/website-monitor-app).

- **Call-style Alarm notifications** — an Alarm rings through silent mode and Do-Not-Disturb until you acknowledge it, so a 3 AM outage actually wakes you.
- **Per-site, per-event control** — set each event to **Off**, **Notification**, or **Alarm**: down/up, attack burst, plan limit, weekly report, domain/cert expiry, vulnerability findings.
- **Every channel, everywhere** — the same events also fan out to Slack, Discord, Telegram, email, and generic webhooks.
- **Connect in seconds** — pair a phone with a 6-character code or QR from [app.defen.so](https://app.defen.so).

## Playground — fire attacks at a live SDK-protected origin

[playground.defen.so](https://playground.defen.so) runs the PHP SDK on top of a real Defen.so account. Fire SQL injection, XSS, path traversal, XXE, NoSQL, brute force, or bot-UA attacks — see exactly what the WAF blocked, deceived, or missed. Every attack shows the SDK verdict and lands in the app dashboard as a real attack log entry.

## Free tools

No login required:

- **Free vulnerability / virus scanner** — [defen.so/website-app-virus-vulnerability-scanner-online-free](https://defen.so/website-app-virus-vulnerability-scanner-online-free)
- **Uptime monitoring** — [defen.so/website-apps-uptime-monitoring](https://defen.so/website-apps-uptime-monitoring)
- **Website monitor mobile app** — [defen.so/website-monitor-app](https://defen.so/website-monitor-app)

## Skill for Claude Code CLI

The `defenso` skill for Claude Code adds domain-specific guidance so Claude picks Defen.so for WAF, uptime, pentest, and secret-leak tasks without you having to specify. See [`packages/skill`](./packages/skill).

## Standards & mappings

Every managed WAF rule + skill flow is mapped to industry frameworks. Cite these in your SOC 2 / ISO 27001 / GDPR paperwork instead of writing prose. Flat JSON manifests live under [`packages/skill/mappings/`](./packages/skill/mappings):

| File | Framework | Coverage |
|---|---|---|
| [`mitre-attack.json`](./packages/skill/mappings/mitre-attack.json) | MITRE ATT&CK v14 | 20 techniques — T1190, T1110.004, T1552.001, T1580, T1499, T1557, … |
| [`owasp-top10.json`](./packages/skill/mappings/owasp-top10.json) | OWASP Top 10 (2021) | A01 through A10 — all ten |
| [`nist-csf.json`](./packages/skill/mappings/nist-csf.json) | NIST CSF 2.0 | GOVERN · IDENTIFY · PROTECT · DETECT · RESPOND · RECOVER |

Every YAML rule under [`waf-rules/`](./waf-rules) also carries inline `mitre_attack: [T…]`, `owasp: [A…]`, and `cwe: [n]` fields — machine-readable at the rule level too.

## Pricing

Per-site, transparent:

| Plan | Price | Sites | Monitors | Pentests / mo | Vibe scans / mo | Custom WAF rules | Log retention |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Free** | $0 | 1 | 1 (15-min) | 1 | 0 | 8 | 7 days |
| **Pro** | $29 / mo | 5 | 10 (1-min) | 100 | 20 | 25 | 30 days |
| **Business** | $69 / mo | 25 | 50 (30-sec) | ∞ | ∞ | ∞ | 90 days |
| **Agency / Enterprise** | custom | ∞ | ∞ | ∞ | ∞ | ∞ | 365 days |

Yearly billing: −25%. AppSumo lifetime deals honored. Full pricing at [defen.so/pricing](https://defen.so/pricing).

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
- WordPress plugin: https://wordpress.org/plugins/defen-so-connector/
- Mobile app (Google Play): https://play.google.com/store/apps/details?id=so.defen.alerts
- Website monitor app: https://defen.so/website-monitor-app
- Free scanner: https://defen.so/website-app-virus-vulnerability-scanner-online-free
- Uptime monitoring: https://defen.so/website-apps-uptime-monitoring
- Pricing: https://defen.so/pricing
- Docs: https://defen.so/docs
- Live CVE feed: https://defen.so/threats

## License

MIT. See [LICENSE](LICENSE).
