# @defen.so/init

**The one-command way to install a production web application firewall in any language.** No config files. No DevOps ticket. `npx @defen.so/init` detects your framework, adds the right SDK, wires the middleware, and prints your next step — all in about 30 seconds.

```bash
npx @defen.so/init
```

Free to start. Powered by [Defenso](https://defen.so) — the security layer built for indie developers, vibe coders, AI-first shipping teams, and small startups shipping fast.

[![Website](https://img.shields.io/badge/site-defen.so-22c55e)](https://defen.so)
[![App](https://img.shields.io/badge/app-app.defen.so-0A0A0A)](https://app.defen.so)
[![MCP](https://img.shields.io/badge/mcp-mcp.defen.so-A855F7)](https://mcp.defen.so)
[![Playground](https://img.shields.io/badge/playground-playground.defen.so-38BDF8)](https://playground.defen.so)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<p align="center">
  <img src="https://raw.githubusercontent.com/1fancy/defen.so/main/.github/screenshots/dashboard-overview.png" alt="Defen.so dashboard — one place for protection status, uptime, pentest grade, email security and compliance, with instant phone alerts" width="90%">
</p>

---

## Table of contents

- [Why this exists](#why-this-exists)
- [What Defenso protects against](#what-defenso-protects-against)
- [What `@defen.so/init` actually does](#what-defenso-init-actually-does)
- [Quick start](#quick-start)
- [Framework support](#framework-support)
- [How the underlying SDK works](#how-the-underlying-sdk-works)
- [Comparison with other tools](#comparison-with-other-tools)
- [Uptime monitoring, alerts, pentest, vibe-coder scan](#everything-else-you-get)
- [MCP server for Claude Code, Cursor, Windsurf, VS Code](#mcp-server-for-ai-ides)
- [Playground: live attack sandbox](#live-sdk-playground)
- [Frequently asked questions](#frequently-asked-questions)
- [If you already have a Defenso account](#if-you-already-have-a-defenso-account)
- [Companion packages](#companion-packages)
- [Links](#links)
- [License](#license)

---

## Why this exists

Small teams ship without a Web Application Firewall in front of their app because the friction is real:

1. Enterprise WAFs (AWS WAF, Cloudflare Enterprise, Imperva, F5) are priced for enterprise teams and take days to onboard
2. Cloud provider defaults stop L3/L4 DDoS but not SQL injection, XSS, credential stuffing, exposed `.env` files, or the twenty other things that actually take down small sites
3. Every "install a WAF" backlog ticket rots for another quarter

Defenso removes the friction. `@defen.so/init` is the front door: **one command, every framework, zero config**.

## What Defenso protects against

Every OWASP Top 10 category, plus the modern attacks that actually hit sites shipped fast:

| Category | Attacks blocked |
|---|---|
| **Injection** | SQL injection (classic + blind + time-based), NoSQL injection, LDAP filter injection, command injection, XPath, template injection |
| **Cross-site scripting** | Reflected, stored, DOM-based, mXSS, SVG payloads, event-handler injection |
| **Authentication attacks** | Brute force, credential stuffing (HIBP-backed), account takeover, session fixation |
| **Broken access control** | Path traversal (`../`, `%2e%2e%2f`, Unicode variants), IDOR probes, admin-panel enumeration |
| **Security misconfiguration** | Exposed `.env`, `.git/config`, `wp-config.php`, `.aws/credentials`, wide-open Firebase / Supabase rules, public S3 buckets |
| **Server-side attacks** | SSRF, XXE (XML external entity), deserialization, log4shell-style JNDI |
| **Cross-site + CSRF** | Origin mismatch, missing-token detection, cookie flag misuse |
| **File uploads** | Polyglots, PHP-in-PNG, EXIF tampering, MIME sniffing tricks, optional ClamAV integration |
| **Bots + scrapers** | TLS fingerprinting (JA4), headless browser detection, sqlmap / Nikto / Nuclei UA signatures, behavioral baselines |
| **DDoS L3/L7** | Cloudflare wrap with one-click per-site Under-Attack toggle |
| **API abuse** | Per-endpoint rate limits, per-account velocity limits, ASN + country allowlists |
| **Malicious ASNs** | TOR exit nodes, known-bad ASNs, spam infrastructure |

Full threat-to-rule map with links to the CVEs / research behind each rule: [defen.so/threats](https://defen.so/threats).

## What `@defen.so/init` actually does

When you run `npx @defen.so/init` in a project directory:

| Step | Action |
|---|---|
| 1 | Reads `next.config.*`, `package.json`, `artisan`, `composer.json` / `symfony.lock`, or `manage.py` / `main.py` / `app.py` to detect your framework |
| 2 | Picks the right SDK — `@defen.so/sdk-node` (Node) and `defenso/sdk-php` (PHP) are published today; Python, Go, Ruby, Rust, Java, and .NET SDKs are in development |
| 3 | Installs the SDK with `npm` (Node) or `composer` (PHP); for Python it prints the `pip install defenso` command to run yourself |
| 4 | For Next.js, writes `middleware.ts`; for every other framework it prints the middleware/listener snippet to paste into your wire-up file |
| 5 | Uses `process.env.DEFENSO_TOKEN` in the wire-up — never a hardcoded secret |
| 6 | Appends a `DEFENSO_TOKEN=` stub to your `.env` |
| 7 | Prints a clear next-step checklist so you know exactly what remains |

**Idempotent.** Re-running skips steps already done — an existing `middleware.ts` is left untouched and a `.env` that already has `DEFENSO_TOKEN` is left as-is.

## Quick start

```bash
# 1. Bootstrap
npx @defen.so/init

# 2. Sign up (or log in) at https://app.defen.so
#    Copy your DEFENSO_TOKEN from the Developer tab

# 3. Paste into .env
DEFENSO_TOKEN=df_live_...

# 4. Deploy. That's it.
```

**Token format**: `df_live_` prefix + 40 random characters. Get it at [app.defen.so/developer](https://app.defen.so/developer).

## Framework support

`@defen.so/init` auto-detects and wires the frameworks below. For everything else it prints the manual install snippet and exits.

**Node.js / TypeScript** — installs `@defen.so/sdk-node`

| Framework | Detected by | Wire-up |
|---|---|---|
| Next.js (App + Pages router) | `next.config.*` or `next` dep | Writes `middleware.ts` |
| Express | `express` dep in `package.json` | Prints the `app.use(defenso(...))` snippet |
| Fastify | `fastify` dep in `package.json` | Prints the `app.register(defensoFastify, ...)` snippet |

**PHP** — installs `defenso/sdk-php`

| Framework | Detected by | Wire-up |
|---|---|---|
| Laravel | `artisan` + `composer.json` | Prints the `bootstrap/app.php` middleware snippet |
| Symfony | `symfony/framework-bundle` in `composer.json` or `symfony.lock` | Prints the `services.yaml` listener snippet |

**Python** — prints install + wiring instructions (SDK not auto-installed)

| Framework | Detected by | Wire-up |
|---|---|---|
| Django | `manage.py` | Prints `pip install defenso` + docs link |
| FastAPI | `FastAPI` in `main.py` / `app.py` | Prints `pip install defenso` + docs link |
| Flask | `Flask` in `main.py` / `app.py` | Prints `pip install defenso` + docs link |

If your framework isn't detected, `@defen.so/init` prints the manual install commands (`npm i @defen.so/sdk-node`, `composer require defenso/sdk-php`, or `pip install defenso`) and a link to the docs so you can wire it yourself.

## How the underlying SDK works

Every Defenso SDK — regardless of language — follows the same three-part contract:

1. **Fetches WAF policy** — pulls your rules from `https://app.defen.so/api/policy` every 5 minutes and caches them in-process. Zero per-request network calls.
2. **Inspects the request** — in-process, against the cached policy. Latency: **~0.1 ms per request**. If a rule matches, the SDK returns `{ action: 'allow' | 'block' | 'challenge', rule, reason, category }`.
3. **Logs attacks async** — hits get queued in-memory and batch-flushed to `https://app.defen.so/api/attacks/ingest` every 10 seconds (or when the batch hits 50 events). Your request never blocks on log I/O.

**Fails open.** If Defenso's API is unreachable — degraded network, our incident, whatever — the SDK returns `allow` for every request. Your app keeps serving traffic. You lose protection during the outage, not availability. This is a deliberate design choice: a WAF that takes your site down when *it* has a bad day is worse than no WAF.

## Comparison with other tools

Different tools solve different parts of the problem. Here's how Defenso fits with what you probably already have:

| Feature | Defenso | Cloudflare WAF | AWS WAF | ModSecurity | Vercel Firewall |
|---|---|---|---|---|---|
| Install command | `npx @defen.so/init` | Change nameservers | Terraform + rule wiring | Recompile nginx/apache | Vercel-only |
| Setup time | ~30 seconds | Hours | Days | Days | Minutes |
| Language coverage | 10 SDKs, same API | Any (edge) | Any (edge) | Any (server) | Node only |
| Custom rules from your IDE | ✅ via MCP | Dashboard only | Terraform | Config files | Dashboard only |
| Attack log per site | ✅ 7-90 day retention | Enterprise plan | ✅ (CloudWatch) | Log files | Basic |
| Public status page | ✅ built-in | Extra plan | Extra service | ❌ | ❌ |
| Uptime monitoring included | ✅ 30s-15min | ❌ | ❌ | ❌ | ❌ |
| Pentest scanner included | ✅ | ❌ | ❌ | ❌ | ❌ |
| Vibe-coder / secret scanner | ✅ | ❌ | ❌ | ❌ | ❌ |
| Real free tier for real projects | ✅ | Free plan basic | Pay per request | Free (self-host) | Included |
| Fails open on our incident | ✅ by design | N/A (edge) | N/A (edge) | Config-dependent | Yes |
| MCP for AI IDEs | ✅ | ❌ | ❌ | ❌ | ❌ |

**Defenso complements Cloudflare** — most Defenso customers run both. Cloudflare handles L3/L4 DDoS + TLS termination at the edge. Defenso runs in your app process (or optionally at our edge via CNAME) doing L7 rule matching, deception, custom rules, and detailed logging.

## Everything else you get

`@defen.so/init` gets you the WAF SDK. Your Defenso account also gets you, automatically, per site added:

**Uptime monitoring**

- Auto-created when you add a site — no forms
- Check interval scales with your plan: from 15 min on the free tier down to 30 sec on higher plans
- Latency tier per check: Fast (< 300 ms), OK (< 900 ms), Slow (< 2 s), Bad (≥ 2 s)
- Only 2xx/3xx counts as up — no "warning" state on a 500 for two hours
- Public status page every site gets, embeddable
- Alerts to email (1 primary + up to 3 CCs), Slack, Telegram, or generic webhook
- Down/up + slow-response notifications with a **probable-cause** paragraph tailored to the HTTP status seen ("HTTP 522 → Cloudflare could not reach origin — usually origin down or firewall")
- Anti-spam send policy: max 2 emails per outage (initial + still-down-24h), then silent until recovery

**Quick pentest scanner**

- Grade A-F on TLS, headers, cookies, exposed `.env` / `.git`, WordPress probes, common misconfigurations
- One-click from your dashboard, or auto-run weekly (Sunday 3 AM)
- Monthly scan count scales with your plan (unlimited on higher plans)

**Vibe-coder scan**

- Catches mistakes AI-generated projects tend to ship: hardcoded secrets, open S3 buckets, Supabase RLS off, wide-open Firebase rules, committed `.env`
- Auto-run weekly (Monday 4 AM)
- Monthly scan count scales with your plan (unlimited on higher plans)

**Live CVE feed**

- Pulled from NVD every 6 hours
- Each CVE tagged with which Defenso WAF rule covers it

## MCP server for AI IDEs

Defenso ships an official [Model Context Protocol](https://modelcontextprotocol.io) server that plugs into **Claude Code, Cursor, Windsurf, and VS Code Copilot**. Once installed, your AI coding tool gets six new tools:

| Tool | What it does |
|---|---|
| `scan_domain(url)` | Quick pentest surface scan of any public URL |
| `check_headers(url)` | TLS grade, HSTS, CSP, cookie flags, common exposures |
| `list_sites()` | Every site under your Defenso account with plan + status |
| `list_monitors()` | Uptime monitors + latest status |
| `list_recent_attacks(hours=24)` | Attacks blocked / deceived / allowed in a window |
| `explain_verdict(rule_id)` | Plain-English explanation of what a WAF rule catches |

Install via `~/.claude/mcp.json`:

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

Now Claude can say *"hey, this endpoint you just wrote has an SQL injection surface — want me to add a WAF rule for it?"* and *actually do it* against your real Defenso account, in your IDE, no context switch.

## Live SDK playground

[playground.defen.so](https://playground.defen.so) is a hosted attack sandbox running the PHP SDK in front of a real Defenso paid-tier account. Fire SQL injection, XSS, path traversal, XXE, NoSQL, brute force, or bot-UA attacks at it — the response tells you exactly what the WAF blocked, deceived, or missed. Every attack is logged in the dashboard as a real event. Rate-limited so you can't abuse it.

Perfect for evaluating whether Defenso would catch the specific attack pattern you're worried about before you install it.

## Frequently asked questions

<details>
<summary><strong>Does this replace Cloudflare?</strong></summary>

No — it complements it. Cloudflare handles L3/L4 DDoS + TLS termination at the edge. Defenso runs in your app process (or optionally at our edge via CNAME) doing L7 rule matching, custom rules, deception, and detailed logging. Most Defenso customers run both.
</details>

<details>
<summary><strong>Does it work on Vercel / Netlify / Cloudflare Pages / Deno Deploy?</strong></summary>

Yes. The Node SDK ships an Edge-compatible build. `@defen.so/init` detects the platform and installs the right variant.
</details>

<details>
<summary><strong>Will it slow down my app?</strong></summary>

~0.1 ms per request in-process. Rule evaluation is local — no network call on the hot path. Policy is refreshed every 5 minutes in the background. Attack logs are batched and flushed asynchronously.
</details>

<details>
<summary><strong>What happens if Defenso goes down?</strong></summary>

Every request is allowed. You lose protection until we recover. Your site keeps serving traffic. This is deliberate — a WAF that takes your site down when *it* has a bad day is worse than no WAF.
</details>

<details>
<summary><strong>How does the token get to production?</strong></summary>

Same way you handle any secret. Add `DEFENSO_TOKEN` in Vercel/Netlify/Fly/Railway/Heroku dashboard, or your infra's env-var mechanism. Never commit it. The `@defen.so/init` CLI writes a `DEFENSO_TOKEN=` stub to `.env` with a placeholder value for you to replace — never a real secret.
</details>

<details>
<summary><strong>Can I self-host Defenso?</strong></summary>

The SDK accepts a custom `api` URL. Point it at your own policy + ingest endpoints. Self-host guide is in the docs.
</details>

<details>
<summary><strong>What framework was Defenso built with?</strong></summary>

The app is Laravel 12 + PHP 8.4 + MariaDB, deployed on our own infrastructure. The SDKs are hand-written per language — no framework bloat, no runtime dependencies beyond the language's standard HTTP client.
</details>

<details>
<summary><strong>Is the source public?</strong></summary>

Every SDK is MIT-licensed and public: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so). The core Defenso app (WAF engine, dashboard, billing) is closed-source but the SDKs, MCP server, docs, and this CLI are all open.
</details>

<details>
<summary><strong>Do you sell my data?</strong></summary>

No. Attack logs stay in your account, tied to your plan's retention window. We do not sell, share, or aggregate for third parties. The [privacy policy](https://defen.so/privacy) lists every third party we touch (Stripe for billing, Cloudflare for DDoS wrap on Pro+, N0C for email delivery).
</details>

<details>
<summary><strong>How do I remove Defenso?</strong></summary>

Delete the middleware line the CLI added, then uninstall the SDK (`npm rm @defen.so/sdk-node` or `composer remove defenso/sdk-php`). Your app keeps working.
</details>

## If you already have a Defenso account

`@defen.so/init` doesn't require you to sign up first — you can install the SDK and grab a token later. But if you already have an account:

1. Bootstrap runs the same way: `npx @defen.so/init`
2. When prompted, paste your existing `df_live_...` token
3. The site auto-registers in your dashboard on the first request
4. You get real-time attack logs immediately

If you have **multiple sites**, the token you use determines which account the traffic gets attributed to. One token per account; sites are distinguished by the `Host` header of each request.

If you're on **Pro or Max**, unlock:
- Custom WAF rules editor at [app.defen.so](https://app.defen.so)
- CNAME edge proxying (put Defenso in front of your origin at the DNS level)
- Slack Connect for direct alerts to a shared channel
- 30/90-day log retention
- MCP integration for Claude Code / Cursor / Windsurf / VS Code

## Companion packages

| Package | Registry | Language | Status |
|---|---|---|---|
| [`@defen.so/sdk-node`](https://www.npmjs.com/package/@defen.so/sdk-node) | npm | Node / Bun / Deno | ✅ published |
| [`defenso/sdk-php`](https://packagist.org/packages/defenso/sdk-php) | Packagist | PHP 8.2+ | ✅ published |
| [`@defen.so/mcp`](https://www.npmjs.com/package/@defen.so/mcp) | npm | MCP server (any client) | ✅ published |
| `defenso` | PyPI | Python 3.10+ | 🚧 in development |
| `github.com/defenso/sdk-go` | Go modules | Go 1.21+ | 🚧 in development |
| `defenso` | RubyGems | Ruby 3.0+ | 🚧 in development |
| `defenso` | crates.io | Rust 1.75+ | 🚧 in development |
| `io.defenso:sdk` | Maven Central | Java 17+ | 🚧 in development |
| `Defenso` | NuGet | .NET 8+ | 🚧 in development |

Beyond the SDKs, Defenso also ships the [**Defen.so Connector**](https://wordpress.org/plugins/defen-so-connector/) WordPress plugin (local hardening + one-click managed WAF) and the [**Defenso Alerts**](https://play.google.com/store/apps/details?id=so.defen.alerts) Android app (push the moment a site goes down or is attacked).

## Links

- **Marketing**: [defen.so](https://defen.so)
- **App / dashboard**: [app.defen.so](https://app.defen.so)
- **MCP server**: [mcp.defen.so](https://mcp.defen.so)
- **Playground (attack sandbox)**: [playground.defen.so](https://playground.defen.so)
- **WordPress plugin**: [Defen.so Connector](https://wordpress.org/plugins/defen-so-connector/)
- **Mobile app (Google Play)**: [Defenso Alerts](https://play.google.com/store/apps/details?id=so.defen.alerts)
- **Documentation**: [defen.so/docs](https://defen.so/docs)
- **Uptime monitoring**: [defen.so/uptime](https://defen.so/uptime)
- **Threat coverage map**: [defen.so/threats](https://defen.so/threats)
- **Live CVE feed**: [defen.so/threats](https://defen.so/threats)
- **Blog**: [defen.so/blog](https://defen.so/blog)
- **Public source (SDKs + MCP + docs)**: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so)
- **Issues**: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- **Contact**: info@defen.so
- **Enterprise inquiry**: [defen.so/enterprise](https://defen.so/enterprise)

## License

MIT. Free for commercial use. See [LICENSE](https://github.com/1fancy/defen.so/blob/main/LICENSE).

---

### Keywords for npm and search engines

`security` `WAF` `web application firewall` `DDoS protection` `bot detection` `uptime monitoring` `pentest` `security SaaS` `OWASP` `OWASP Top 10` `SQL injection` `XSS` `brute force` `credential stuffing` `account takeover` `CSRF` `SSRF` `XXE` `NoSQL injection` `path traversal` `deception` `honeypot` `upload scanning` `file upload security` `Cloudflare wrap` `edge security` `vibe coder security` `AI-first security` `Claude Code security` `Cursor security` `Windsurf security` `MCP` `Model Context Protocol` `indie developer security` `small team security` `Next.js security` `Laravel security` `Symfony security` `Django security` `FastAPI security` `Rails security` `Express security` `Fastify security` `Nuxt security` `SvelteKit security` `Astro security` `Vercel security` `Netlify security` `Bun security` `Deno security` `Node security` `PHP security` `Python security` `Go security` `Ruby security` `Rust security` `Java security` `.NET security`
