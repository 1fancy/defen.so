# Defen.so — Web &amp; App Pentest, Code Scanning, Uptime Monitoring &amp; WAF for developers

[![Website](https://img.shields.io/badge/site-defen.so-22c55e)](https://defen.so)
[![App](https://img.shields.io/badge/app-app.defen.so-0A0A0A)](https://app.defen.so)
[![MCP](https://img.shields.io/badge/mcp-mcp.defen.so-A855F7)](https://mcp.defen.so)
[![Playground](https://img.shields.io/badge/playground-playground.defen.so-38BDF8)](https://playground.defen.so)
[![npm @defen.so/sdk-node](https://img.shields.io/npm/v/@defen.so/sdk-node?label=%40defen.so%2Fsdk-node)](https://www.npmjs.com/package/@defen.so/sdk-node)
[![Packagist defenso/sdk-php](https://img.shields.io/packagist/v/defenso/sdk-php?label=defenso%2Fsdk-php)](https://packagist.org/packages/defenso/sdk-php)
[![WordPress plugin](https://img.shields.io/wordpress/plugin/v/defen-so-connector?label=wp%20plugin)](https://wordpress.org/plugins/defen-so-connector/)
[![Google Play](https://img.shields.io/badge/Google%20Play-Defenso%20Alerts-34A853)](https://play.google.com/store/apps/details?id=so.defen.alerts)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## Web &amp; App Pentest, Security, Code Scanning &amp; Uptime Monitoring

Pentest and scan your website, web apps, code and GitHub for vulnerabilities and exposed keys. Secure vibe-coded apps, monitor uptime, SSL and domains, and rate-limit APIs. One platform.

**Pentest &amp; scan** · **Code &amp; repo scan** · **Uptime &amp; monitoring** · **Instant alerts** · **API rate limits** · **MCP &amp; SDKs**

---

**Install it, scan it, or plug it into your AI editor:**

```bash
npx @defen.so/init      # add the SDK + protection to your app in 30 seconds
npx @defen.so/scan      # pentest any site or repo from your terminal
npx -y @defen.so/mcp    # security tools inside Claude Code, Cursor, Windsurf
```

**Defen.so** is a developer-first web security platform. It runs a real pentest — surface **and** deep: CVE version fingerprint, port scan, admin-surface enumeration, GraphQL introspection, reflected-origin CORS, reflected XSS, open redirect, subdomain takeover and a login brute-force-resistance probe. The code and repo scanner cross-references every dependency against **OSV** (Google's live vulnerability database) plus an auto-updating malicious-package feed, and catches committed secrets, dangerous code and Supabase/Firebase/S3 misconfigurations. Uptime, SSL and domain-expiry monitoring, alerts, active deception, file-upload scanning and a managed firewall complete the stack — installed in **one line** for Node, PHP/Laravel, Python, Go, Ruby, Java, .NET, Rust, Bun or Deno.

**Your security layer. Shipped in 30 seconds.** One line — `npx @defen.so/init` — and every SDK fails open, so if Defen.so is ever down your app keeps serving.

---

## See it in action

One dashboard for a site's whole security posture — protection status, uptime, pentest grade, email security (SPF/DKIM/DMARC) and compliance — with instant alerts to your phone, Slack, Telegram, Discord, email or a webhook.

![Defen.so dashboard — site overview with protection status, uptime, pentest grade, email security and compliance](https://raw.githubusercontent.com/1fancy/defen.so/main/.github/screenshots/dashboard-overview.png)

**Uptime & performance** — response-time trend, uptime %, P95 and an incident timeline for every page and API you watch.

![Defen.so uptime and performance monitoring — response-time chart, uptime percentages and incident timeline](https://raw.githubusercontent.com/1fancy/defen.so/main/.github/screenshots/uptime-performance.png)

**API rate-limits & rules** — your SDK auto-detects endpoints from real traffic; approve per-endpoint rate caps and WAF rules, or dismiss the ones you don't need.

![Defen.so API rate-limits and WAF rules — auto-detected endpoints with per-endpoint rate caps](https://raw.githubusercontent.com/1fancy/defen.so/main/.github/screenshots/api-rate-limits.png)

---

## Table of contents

- [Why Defen.so](#why-defenso)
- [What's inside](#whats-inside)
- [Quick install](#quick-install-30-seconds)
- [Scan any site from the terminal](#scan-any-site-from-the-terminal)
- [SDKs — every language](#sdks--every-language)
- [MCP server for AI IDEs](#mcp-server-for-ai-ides)
- [WordPress plugin](#wordpress-plugin)
- [Mobile app — Defenso Alerts](#mobile-app--defenso-alerts)
- [Playground](#playground---fire-attacks-at-a-live-sdk-protected-origin)
- [Free tools](#free-tools)
- [Skill for Claude Code](#skill-for-claude-code-cli)
- [Standards & mappings](#standards--mappings)
- [Threats Defen.so stops](#threats-defenso-stops)
- [Contributing](#contributing)

---

## Why Defen.so

Most small teams ship without a Web Application Firewall in front of their app. They know they should. They put it on the backlog. Then the free trial ends, or a user reports a slow page, and the WAF ticket rots another quarter.

Defen.so removes three specific frictions:

1. **Install** — one line, one language, five minutes.
2. **Downside risk** — every SDK is fail-open. If Defen.so is down, your app keeps serving. You lose protection, not availability.
3. **Cost** — there's a real free tier that protects a hobby project. Plans and current pricing live at [defen.so](https://defen.so).

## What's inside

| Layer | What it does |
| --- | --- |
| Managed WAF | OWASP Top 10 + CRS + your custom rules. Auto-detects APIs, applies per-route limits, caches safe GETs at the edge. |
| Uptime monitoring | 15-min free, 1-min Pro, 30-sec Max. 5 / 20 / 50 / 100 monitors by plan. Public status page. Email + Slack + Discord + Telegram + webhook + mobile push on down/up. |
| Quick pentest | On-demand surface scan: headers, TLS, cookies, exposed `.env` / `.git`, **email security (SPF / DKIM / DMARC)**, and compliance-style findings. A/B/C/D/F grade. |
| Vibe-coder scan | Catches the mistakes vibe-coded projects tend to ship: exposed secrets, open S3 buckets, Supabase RLS off, wide-open Firebase rules. |
| Cloudflare DDoS wrap | One-click attach + per-site Under-Attack toggle. |
| Bot detection | UA classification, headless-browser challenges, per-IP rate limits, ASN allowlist for Google/Bing. |
| Active deception | Serves plausible fakes to verified attackers. Fingerprint logged, real error message hidden. |
| Upload scanning | MIME + magic bytes + polyglot detection + optional ClamAV. |
| CVE feed | Live feed from NVD, tagged with which Defen.so rule covers each entry. |
| Real-time logs | Full context per attack (IP, ASN, country, payload, route, verdict). 15 days free, 60 Uptime, 90 Pro, 365 Max. |
| MCP server | Claude Code, Cursor, Windsurf, VS Code get real security tools. Scan, monitor, block from AI chat. |
| WordPress plugin | [Defen.so Connector](https://wordpress.org/plugins/defen-so-connector/) — local malware scan, file integrity, login hardening, geo-block, activity log with no account; one-click connect for managed WAF + attack log + uptime + CVE lookups. |
| Mobile app | [Defenso Alerts](https://play.google.com/store/apps/details?id=so.defen.alerts) on Google Play — call-style **Alarm** notifications that ring through silent mode / DND until you acknowledge. iOS coming soon. |
| Alert integrations | Mobile push, email (primary + 3 CCs), Slack, Discord, Telegram, generic webhook. Fires on down/up, attack burst, plan limit. |

---

## Quick install (30 seconds)

```bash
npx @defen.so/init
```

The init CLI detects your framework (Next.js, Express, Fastify, Laravel, Symfony, FastAPI, Django, Rails, Go chi, Rust axum, Spring, .NET, Bun, Deno) and adds the right middleware in the right spot. Then set `DEFENSO_TOKEN` from https://app.defen.so/developer and ship.

## Scan any site from the terminal

A fast, template-based security scanner. No account needed to start.

```bash
npx @defen.so/scan example.com
```

```text
 █████  ███████ ███████ ███████ ██   ██ ███████  █████
 ██  ██ ██      ██      ██      ███  ██ ██      ██   ██
 ██  ██ █████   █████   █████   ██ █ ██ ███████ ██   ██
 ██  ██ ██      ██      ██      ██  ███      ██ ██   ██
 █████  ███████ ██      ███████ ██   ██ ███████  █████
 pentest · repo scan · uptime · alerts        https://defen.so

 → scanning example.com …
 ✓ 41 checks · grade B (88/100)

   CRITICAL  Exposed .env file            /.env                 CWE-538
   CRITICAL  Stripe secret key in JS      /app.js:1204          CWE-312
   HIGH      Missing Content-Security-Policy                    CWE-693
   MEDIUM    Cookie without Secure flag   session               CWE-614

 Every finding has a fix. Full report: https://app.defen.so
```

It checks security headers, insecure cookies, exposed secrets (AWS, Stripe, GitHub, OpenAI, Supabase `service_role`, private keys and more), exposed `.env`/`.git` files, missing `security.txt`, exposed source maps, and grades the result A–F. Every finding carries a severity, a CWE, the evidence that matched, and a plain-language fix.

Because it runs from **your** machine, a WAF or Cloudflare that would block an external scanner doesn't block it, and you can point it behind your own login:

```bash
npx @defen.so/scan https://app.example.com --cookie "session=…" --crawl 10 --active
```

For CI, emit SARIF into GitHub code scanning, or gate a pipeline:

```bash
npx @defen.so/scan example.com --sarif > results.sarif
npx @defen.so/scan example.com --fail-on high
```

Full docs: [`packages/scan`](./packages/scan) · [npm](https://www.npmjs.com/package/@defen.so/scan).

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
- Fastify: `import { defenso } from '@defen.so/sdk-node/fastify'`
- Next.js middleware: `import { defenso } from '@defen.so/sdk-node/next'`

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
<summary><strong>Python / Go / Ruby / Java / .NET / Rust</strong></summary>

Every SDK exposes the same `inspect(request) -> { action, rule, reason }` contract and fails open. Scaffolds for these languages live under [`packages/`](./packages) — see [defen.so/install](https://defen.so/install) for the current registry-publish status of each. You can protect any app today with zero code by:

- Signing up at [app.defen.so](https://app.defen.so) — uptime monitoring and surface scans turn on immediately.
- On the **Max** plan, routing traffic through the Defen.so edge WAF via CNAME (no code).

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
- **Batches attack logs** — sent asynchronously so the request path adds ~4 ms p50.
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

Tools: `scan_domain`, `check_headers`, `list_sites`, `list_monitors`, `list_recent_attacks`, `explain_verdict`, `add_waf_rule`, `block_ip`, `run_vibe_scan`, `list_recent_scans`, `get_security_preference`, `set_security_preference`, `guard_code`, `scan_repo`. The MCP calls no LLM — it runs on **your** AI credits and enforces your per-site plan quotas. See [`packages/mcp`](./packages/mcp) for the full tool reference.

## WordPress plugin

[**Defen.so Connector**](https://wordpress.org/plugins/defen-so-connector/) (slug `defen-so-connector`) is on the WordPress.org plugin directory. Source lives in [`packages/wp-plugin`](./packages/wp-plugin).

- **Tabbed admin** — Overview, Firewall &amp; hardening, Scans, Rate limits, Uptime &amp; alerts, and Activity log, each one click away; the tab you were on is remembered across reloads.
- **Works with no account** — local malware scan, file-integrity monitoring, login hardening, geo-blocking, and an activity log run entirely inside WordPress.
- **File-modification detection** — take a trusted baseline, then flag any file added, changed, or removed since, catching backdoors and tampered files that signature scanning alone misses.
- **Continuous background scanning** — a weekly sweep keeps malware and vulnerability findings fresh automatically, no manual clicking.
- **Local path rate limiting** — throttle any slug or wildcard pattern on your site by IP, entirely in the plugin.
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

## Threats Defen.so stops

SQL injection, XSS (reflected / stored / DOM), CSRF, SSRF, path traversal, XXE, NoSQL / LDAP / command injection, brute force, credential stuffing, account takeover, malicious file uploads (polyglots, PHP-in-PNG, EXIF tampering), bot scrapers, headless browser abuse, TOR exit nodes, ASN-flagged attackers, DDoS L3-L7 (via Cloudflare wrap), API abuse, exposed secrets, open S3 buckets, wide-open Firebase / Supabase rules, `.env` / `.git` exposure.

Threat-to-rule mapping is public at [defen.so/threats](https://defen.so/threats).

## Contributing

Bug in an SDK? Open an issue at https://github.com/1fancy/defen.so/issues. Include:
- The SDK + version
- Framework + version
- A minimal reproduction

Security disclosures: mail `info@defen.so` — please don't file public issues for security bugs.

## How Defen.so compares

Most teams run four or five tools. Defen.so puts them in one account and one install line.

| | **Defen.so** | Nuclei | Snyk | GitGuardian | UptimeRobot |
|---|:---:|:---:|:---:|:---:|:---:|
| Web pentest (surface + deep) | ✅ | ✅ (templates) | ⚠️ SAST only | ❌ | ❌ |
| Live-CVE dependency scan (OSV) | ✅ | ❌ | ✅ | ❌ | ❌ |
| Committed-secret / repo scan | ✅ | ❌ | ✅ | ✅ | ❌ |
| Malicious-package feed (auto-update) | ✅ | ❌ | ⚠️ | ❌ | ❌ |
| Uptime + SSL + domain monitoring | ✅ | ❌ | ❌ | ❌ | ✅ |
| MCP tools for AI editors | ✅ (18) | ❌ | ⚠️ basic | ❌ | ❌ |
| One-line install (`npx @defen.so/init`) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Managed WAF + rate limits | ✅ | ❌ | ❌ | ❌ | ❌ |
| Free tier with real value | ✅ | ✅ (OSS) | ⚠️ 100 tests | ⚠️ 25 devs | ✅ |

Defen.so is built for indie developers, vibe coders and small teams who want the whole picture — scan, pentest, monitor and fix — without stitching five vendors together.

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
- Docs: https://defen.so/docs
- Roadmap: https://defen.so/roadmap
- Blog: https://defen.so/blog
- Live CVE feed: https://defen.so/threats

## License

MIT. See [LICENSE](LICENSE).
