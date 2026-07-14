# @defen.so/init

**The one-command way to add production-grade web security to any web app.** `@defen.so/init` is the official bootstrap CLI for [Defenso](https://defen.so) — a security layer built for indie developers, vibe coders, AI-first shipping teams, and small startups who need a real WAF, uptime monitoring, quick pentest, and DDoS protection *without* an afternoon of DevOps.

```bash
npx @defen.so/init
```

That single command detects your framework, installs the correct SDK for your language, wires the middleware into the correct file, and drops a `DEFENSO_TOKEN=` line into your `.env`. Every framework, one command, ~30 seconds, no plugins, no infra changes.

Free tier forever. Pro $29/mo per site. No credit card required.

---

## Why does this exist

If you have ever shipped a web app you know the friction:

1. You know you should have a **Web Application Firewall** in front of your app.
2. You put it on the backlog.
3. You never actually do it.

That backlog death spiral is why **every third breach reported publicly** starts with an app that *knew* it needed protection but shipped without any. Enterprise WAFs (AWS WAF, Cloudflare Enterprise, F5) are priced for enterprise teams — thousands of dollars a month, weeks of onboarding, a full-time engineer to tune them. Cloud provider defaults are a false floor: they stop L3/L4 DDoS, but not SQL injection, XSS, credential stuffing, exposed `.env` files, wide-open Firebase rules, or the twenty other things that actually take down small sites.

Defenso is built for the other 99% of the market. **One SDK line, fails open, honest pricing.** `@defen.so/init` is the front door.

## What Defenso protects against

Every OWASP Top 10 category, plus the modern stack of attacks that actually hit small teams shipping fast:

- **SQL injection** — classic and blind, across query params, request bodies, and headers
- **Cross-Site Scripting (XSS)** — reflected, stored, DOM-based, template injection
- **Path traversal** — `../../../etc/passwd`, `%2e%2e%2f`, Unicode variants
- **Cross-Site Request Forgery (CSRF)** — mismatched origin, missing token detection
- **Server-Side Request Forgery (SSRF)** — outbound calls to internal / cloud-metadata IPs
- **Command injection** — shell metacharacter probes in URL and form fields
- **XML External Entity (XXE)** — external entity resolution in XML bodies
- **NoSQL / LDAP injection** — MongoDB operator abuse, LDAP filter injection
- **Brute force + credential stuffing** — per-IP + per-account velocity limits, HIBP-backed
- **Account takeover** — anomaly baselines on login geography, device fingerprint, ASN
- **Malicious file uploads** — MIME + magic-byte + polyglot + optional ClamAV
- **Bot scrapers + headless browsers** — TLS fingerprinting, JA4, behavioral baselines
- **TOR + known-bad ASN traffic** — auto-blocked, dashboard override to allow
- **Exposed secrets** — `.env`, `.git/config`, `wp-config.php`, `.aws/credentials`
- **Wide-open cloud config** — Supabase RLS off, Firebase wildcard rules, public S3 buckets
- **DDoS L3/L7** — Cloudflare wrap with one-click Under-Attack toggle per site

The threat-to-rule map is public at [defen.so/threats](https://defen.so/threats). Every rule links to the CVE or research it comes from — no black boxes.

## What `@defen.so/init` actually does

When you run `npx @defen.so/init` in a project directory, the CLI:

1. **Reads your `package.json`, `composer.json`, `requirements.txt`, `Cargo.toml`, `go.mod`, or `Gemfile`** to detect your language and framework
2. **Picks the right SDK** for you — `@defenso/sdk-node`, `defenso/sdk-php`, `defenso`, `github.com/defenso/sdk-go`, etc.
3. **Installs the SDK** using your project's package manager (npm, pnpm, yarn, composer, pip, poetry, bundle, cargo, go get)
4. **Locates the correct middleware wiring point** — `middleware.ts` for Next.js, `bootstrap/app.php` for Laravel, `main.py` for FastAPI, `config.ru` for Rails, `Program.cs` for .NET, and so on
5. **Inserts the middleware call** with an environment-variable-based token so you never commit a secret
6. **Appends `DEFENSO_TOKEN=` to `.env` or `.env.local`** as a stub for you to fill in
7. **Prints a checklist** of the two things you still need to do: sign up at [app.defen.so](https://app.defen.so), copy your `df_live_...` token from Developer, paste into `.env`

Re-running the command is idempotent — if the SDK is already installed and the middleware is wired, it prints "already bootstrapped" and exits.

## Supported frameworks

**Node.js / TypeScript**

- Express, Fastify, Koa, Hapi, Restify
- Next.js (App Router + Pages Router)
- Remix, Nuxt, SvelteKit, Astro (any Node adapter)
- NestJS
- Bun (native `Bun.serve`)
- Deno (native `Deno.serve`, `deno add npm:@defenso/sdk-node`)
- Hono (Cloudflare Workers, Vercel Edge, Node)
- ElysiaJS
- t3-stack / create-t3-app templates

**PHP** (8.2+, tested against 8.4)

- Laravel 10, 11, 12 — `bootstrap/app.php` or middleware groups
- Symfony 6, 7 — kernel event listener
- Slim, Lumen, plain PHP — direct `\Defenso\Client::inspect()` call

**Python** (3.10+)

- FastAPI, Starlette
- Django (3.x, 4.x, 5.x)
- Flask, Quart
- aiohttp

**Ruby**

- Rails 6, 7, 8
- Sinatra, Roda

**Go**

- chi, gin, echo, fiber, standard `net/http`

**Rust**

- axum, actix-web, warp, tower

**Java / .NET**

- Spring Boot 2/3 filter
- ASP.NET Core middleware

If your framework is not listed, run `npx @defen.so/init --sdk-only` — it installs the SDK and prints the exact snippet to paste yourself.

## How the underlying SDK works

Every Defenso SDK follows the same three-part contract, regardless of language:

1. **Fetches WAF policy** — the SDK pulls your rules from `https://app.defen.so/api/policy` every 5 minutes and caches them in-process. No per-request network call.
2. **Inspects the request** — in-process, against the cached policy. Latency: ~0.1 ms per request. If a rule matches, the SDK returns `{ action: 'block' | 'challenge' | 'allow', rule, reason, category }`.
3. **Logs attacks async** — hits get queued in-memory and batch-flushed to `https://app.defen.so/api/attacks/ingest` every 10 seconds (or when the batch hits 50 events). Your request never blocks on log I/O.

**Fails open.** If Defenso's API is unreachable — degraded network, our incident, wherever — the SDK returns `allow` for every request. Your app keeps serving traffic. You lose protection during the outage, not availability. This is a deliberate design choice: a WAF that takes your site down when *it* has a bad day is worse than no WAF.

## Vibe coder / Cursor / Claude Code friendly

Defenso ships a [Model Context Protocol](https://modelcontextprotocol.io) server at [mcp.defen.so](https://mcp.defen.so) that plugs directly into Claude Code, Cursor, Windsurf, and VS Code Copilot. Once installed, your AI coding tool gets six new tools:

- `scan_domain(url)` — quick pentest surface scan of any public URL
- `check_headers(url)` — TLS grade, HSTS, CSP, cookie flags, common exposures
- `list_sites()` — every site under your Defenso account with plan + status
- `list_monitors()` — uptime monitors + latest status
- `list_recent_attacks(hours=24)` — attacks blocked / deceived / allowed in a window
- `explain_verdict(rule_id)` — plain-English explanation of what a WAF rule catches

Install via `~/.claude/mcp.json`:

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

Now Claude can say "hey, this endpoint you just wrote has an SQL injection surface — want me to add a WAF rule for it?" and *actually do it* against your real Defenso account, in your IDE.

## Live SDK playground

[playground.defen.so](https://playground.defen.so) is a hosted attack sandbox running the PHP SDK in front of a real Defenso Business-tier account. Fire SQL injection, XSS, path traversal, XXE, NoSQL, brute force, or bot-UA attacks at it — the response tells you exactly what the WAF blocked, deceived, or missed. Every attack is logged in the dashboard as a real event. Rate-limited so you can't abuse it.

## Pricing

Per-site, transparent:

| Plan | Price | Sites | Monitors | Interval | Pentests / mo | Vibe scans / mo | Custom WAF rules | Log retention |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Free** | $0 forever | 1 | 1 | 15 min | 1 | 0 | 8 | 7 days |
| **Pro** | $29/mo | 5 | 10 | 1 min | 100 | 20 | 25 | 30 days |
| **Business** | $49/mo | 25 | 50 | 30 sec | ∞ | ∞ | ∞ | 90 days |
| **Agency / Enterprise** | custom | ∞ | ∞ | custom | ∞ | ∞ | ∞ | 365 days |

Yearly billing gets −25%. AppSumo redemption supported. Full pricing at [defen.so/pricing](https://defen.so/pricing).

## Uptime monitoring

Every site added to Defenso automatically gets an uptime monitor at your plan's interval. Down/up alerts fire to email (primary + up to 3 CCs), Slack, Telegram, or generic webhook — configured once per site, not per monitor. Each check gets a latency tier tag (Fast &lt; 300 ms, OK &lt; 900 ms, Slow &lt; 2 s, Bad ≥ 2 s), and a slow-response alert fires after 3 consecutive checks over 3 seconds so you catch regressions before your users do.

## Quick start

```bash
# 1. Bootstrap
npx @defen.so/init

# 2. Sign up (or log in) at https://app.defen.so
#    Copy your DEFENSO_TOKEN from Developer

# 3. Paste into .env
DEFENSO_TOKEN=df_live_...

# 4. Deploy. That's it.
```

## Common questions

**Does this replace Cloudflare?** No, it complements it. Cloudflare handles L3/L4 DDoS and TLS termination. Defenso runs in your app process (or optionally at our edge via CNAME) doing L7 rule matching, deception, custom WAF rules, and detailed logging. Most Defenso customers use both.

**Does it work with Vercel / Netlify / Cloudflare Pages?** Yes — the Node SDK ships an Edge-compatible build. `@defen.so/init` detects the platform and installs the right variant.

**Will it slow down my app?** ~0.1 ms per request in-process (rule evaluation is local, no network call on the hot path). Policy is refreshed every 5 minutes in the background. Attack logs are batched and flushed asynchronously.

**What happens if Defenso goes down?** Every request is allowed. You lose protection until we recover. Your site keeps serving traffic. This is the fail-open design.

**Where can I see the source?** Every SDK is MIT-licensed and public: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so).

**How do I self-host?** The SDK accepts a custom `api` URL. Point it at your own policy + ingest endpoints. Self-host guide is in the docs.

## Companion packages

- [`@defenso/sdk-node`](https://www.npmjs.com/package/@defenso/sdk-node) — the Node/Bun/Deno SDK this CLI installs
- [`defenso/sdk-php`](https://packagist.org/packages/defenso/sdk-php) — the Laravel/Symfony/plain-PHP SDK
- [`@defenso/mcp`](https://www.npmjs.com/package/@defenso/mcp) — the MCP server for Claude Code / Cursor / Windsurf / VS Code
- Python: `pip install defenso`
- Go: `go get github.com/defenso/sdk-go`
- Ruby: `bundle add defenso`
- Rust: `cargo add defenso`
- Java: `io.defenso:sdk`
- .NET: `dotnet add package Defenso`

## Links

- Marketing: [defen.so](https://defen.so)
- App: [app.defen.so](https://app.defen.so)
- MCP: [mcp.defen.so](https://mcp.defen.so)
- Playground: [playground.defen.so](https://playground.defen.so)
- Docs: [defen.so/docs](https://defen.so/docs)
- Pricing: [defen.so/pricing](https://defen.so/pricing)
- Uptime monitoring: [defen.so/uptime](https://defen.so/uptime)
- Threat coverage: [defen.so/threats](https://defen.so/threats)
- Live CVE feed: [defen.so/threats](https://defen.so/threats)
- Source: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- Contact: info@defen.so

## Keywords

security, WAF, web application firewall, DDoS protection, bot detection, uptime monitoring, pentest, security SaaS, OWASP, OWASP Top 10, SQL injection, XSS, brute force, credential stuffing, account takeover, CSRF, SSRF, XXE, NoSQL injection, path traversal, deception, honeypot, upload scanning, file upload security, Cloudflare wrap, edge security, vibe coder security, AI-first security, Claude Code security, Cursor security, Windsurf security, MCP, Model Context Protocol, indie developer security, small team security, Next.js security, Laravel security, Symfony security, Django security, FastAPI security, Rails security, Express security, Fastify security, Nuxt security, SvelteKit security, Astro security, Vercel security, Netlify security, Bun security, Deno security, Node security, PHP security, Python security, Go security, Ruby security, Rust security, Java security, .NET security

## License

MIT
