# @defen.so/scan

**Fast, template-based web security scanner for the terminal and CI.** Scan any URL for exposed secrets, weak security headers, missing HSTS/CSP, insecure cookies, exposed `.env`/`.git` files, outdated libraries with known CVEs, subdomain-takeover signals, GraphQL introspection and TLS issues — graded, with **SARIF** and **JSON** output for GitHub code scanning. Zero config, no account to start.

```bash
npx @defen.so/scan example.com
```

```
defenso-scan v0.3.1  https://example.com/
67 checks · grade B
Grade  B     0 crit  0 high 2 med 2 low 1 info

 MED   Content-Security-Policy missing CWE-1021
      No Content-Security-Policy header — reflected/stored XSS is harder to contain.
      fix Add a Content-Security-Policy, starting with "default-src 'self'".

 MED   HSTS not set CWE-319
      No Strict-Transport-Security header on an HTTPS response.
      fix Add "Strict-Transport-Security: max-age=63072000; includeSubDomains".
 ...
```

## Why

A public one-off scanner only sees the anonymous view of a site, and most CLI scanners are heavy to set up. `@defen.so/scan` is a single command: it runs a set of deterministic, evidence-based templates locally (nothing about your target leaves your machine for the local checks) and augments the result with the Defenso hosted grade. Every finding is real, carries a severity, a CWE, the evidence that matched, and a concrete fix — nothing is hallucinated.

## Install

```bash
# run without installing
npx @defen.so/scan example.com

# or install globally
npm i -g @defen.so/scan
defenso-scan example.com
```

Requires Node 18+.

## Free to run · what an account adds

The local checks are **free and unlimited, forever** — every header, cookie, secret, exposed-file, version-CVE, takeover, GraphQL, CORS and (with `--active`) SQLi/redirect/XSS probe runs entirely on your machine. Nothing about your target leaves your network for the local scan, there's no rate limit, and no account is needed. Run it in CI on every push.

On top of that, each scan asks the Defenso hosted grader for a second opinion:

| | Local checks | Hosted grade |
|---|---|---|
| **No token** | Unlimited, offline-capable | Free daily teaser grade per IP |
| **Free account** (`DEFENSO_TOKEN`) | Unlimited | Full hosted report, generous daily quota |
| **Pro / Business** | Unlimited | Higher quota + continuous scheduled scans |
| **Max / Agency** | Unlimited | Adds the **deep environment pentest** (active probes against your live infra, gated to Max+) on onboarded sites |

Get a free token at [app.defen.so/developer](https://app.defen.so/developer) and set `DEFENSO_TOKEN`. Skip the hosted call entirely with `--offline` — the local scan always stands on its own.

## Usage

```bash
defenso-scan <url> [url2 ...] [options]
```

| Option | What it does |
|---|---|
| `--json` | Full report as JSON |
| `--sarif` | SARIF 2.1.0 for GitHub code scanning / CI |
| `--fail-on <sev>` | Exit non-zero if a finding at/above `<sev>` exists (`info`\|`low`\|`medium`\|`high`\|`critical`) |
| `--crawl <n>` | Also scan up to `n` same-origin pages |
| `--active` | Run the safe active probes (SQLi, open-redirect, reflected-XSS) |
| `--cookie <str>` | Send a `Cookie` header — **scan behind your login** |
| `--bearer <token>` | Send `Authorization: Bearer <token>` |
| `--basic <u:p>` | HTTP Basic auth |
| `--auth-header <h>` | Add a raw request header `"Name: value"` (repeatable) |
| `--no-paths` | Skip probing sensitive files (`.env`/`.git`/…) |
| `--no-deep` | Skip deep surface checks |
| `--offline` | Local checks only; skip the hosted grade |
| `--timeout <ms>` | Per-request timeout (default 12000) |
| `-q, --quiet` | Only print findings |
| `-v`, `-h` | Version / help |

### Runs from your machine — no WAF/Cloudflare to configure

Because the scanner runs from **your** network, a WAF or Cloudflare that would block an external scanner doesn't block it — and you can point it **behind your own login** with `--cookie` / `--bearer`, reaching the authenticated pages an outside pentest never sees:

```bash
# scan the app behind your session
npx @defen.so/scan https://app.example.com --cookie "session=…" --crawl 10
```

## What it checks

Templates are grouped by class, each with a severity and CWE:

- **Security headers** — HSTS, Content-Security-Policy (missing + `unsafe-inline`), X-Content-Type-Options, X-Frame-Options / clickjacking, Referrer-Policy, server-version disclosure, CORS wildcard-with-credentials.
- **Cookies** — session cookies missing `Secure`, `HttpOnly`, `SameSite`.
- **Exposed secrets** in page source — AWS, Stripe, GitHub, Slack, OpenAI, Anthropic, SendGrid, Twilio, Mailgun keys, private-key blocks, Supabase `service_role`, JWTs, credentials in URLs (public-by-design keys like Firebase/Maps are noted, not falsely alarmed).
- **Exposed files** — `.env`, `.git/config`, `.git/HEAD`, `.env.bak`, `config.json`, `.DS_Store`, `Dockerfile`, SQL backups (verified as real files, not SPA fallbacks).
- **Expanded exposure pack** — `.svn`/`.hg` metadata, `web.config`, `wp-config.php.bak`, `.env.production`/`.env.local`, `phpinfo`, Spring **Actuator** (`/actuator/env`), `server-status`, Swagger/OpenAPI specs, `.aws/credentials`, exposed `id_rsa` — each verified by a content signature, not just a 200.
- **Known-CVE version fingerprint** — flags outdated jQuery/Bootstrap with disclosed XSS and old server banners against a known-bad version range (no false alarms on patched builds).
- **Subdomain takeover** — detects dangling-CNAME signatures for S3, GitHub Pages, Heroku, Fastly, Shopify, Netlify and Vercel.
- **GraphQL introspection** — flags a `/graphql` endpoint that leaks its full schema in production.
- **Deep CORS** — catches reflected-origin and `null`-origin misconfig (the real bug), not just wildcard-with-credentials.
- **Surface & misconfig** — missing `security.txt`, directory listing enabled, exposed JavaScript **source maps** (leaked original source).
- **Mixed content** — an HTTPS page loading active scripts or stylesheets over plain `http://`, which a network attacker can tamper with (CWE-311).
- **Active (opt-in `--active`)** — safe, benign probes for **SQL injection** (error-based), **open redirect** (a harmless external target reflected into `Location`), **reflected XSS** (an inert marker that comes back unescaped), and **server-side template injection** (an arithmetic marker the engine evaluates, e.g. `{{7*7}}` returning `49`). No data is touched and no credentials are tried.
- **Tech fingerprint** — detects WordPress, Next.js, Laravel, Nuxt, React, PHP so findings are in context.

Findings are graded A–F, with a multi-page crawl (`--crawl`) and authenticated scanning (`--cookie`/`--bearer`). Add `DEFENSO_TOKEN` (get one at [app.defen.so/developer](https://app.defen.so/developer)) for the full hosted report; without it you still get every local check plus a free daily hosted grade.

## Scan a local repository (offline)

Point the scanner at a working tree instead of a URL. It never touches the network, so it is safe to run on a laptop or inside CI before anything is deployed:

```bash
npx @defen.so/scan repo .                    # scan the current directory
npx @defen.so/scan repo ./service --json
npx @defen.so/scan repo . --sarif > repo.sarif
npx @defen.so/scan repo . --fail-on high     # exit 1 to gate a CI job
```

It walks the tree (skipping `node_modules`, `.git`, build output and binaries) and reports:

- **Committed secrets** — the same key patterns as the URL scanner (AWS, Stripe, GitHub, Slack, OpenAI, SendGrid, Twilio, npm tokens, private-key blocks), plus generic `api_key`/`secret` assignments and database URLs with an inline password. Each finding points to `file:line`. Obvious placeholders (`example`, `changeme`, `<token>`) are skipped.
- **Known-bad dependencies** — reads `package.json` and flags packages with well-known compromised releases (`event-stream`, `ua-parser-js`, `node-ipc`, `coa`, `rc`, `flatmap-stream`).
- **Unsafe Dockerfiles** — base image pinned to `:latest`, a container that runs as root, and secrets baked into `ENV`/`ARG`.
- **Unsafe GitHub Actions** — third-party actions pinned to a mutable tag/branch instead of a commit SHA, and `pull_request_target` workflows that check out untrusted PR code.

Output, grading and `--fail-on` behave exactly like the URL scanner, so the same SARIF upload works for repo findings.

## CI / GitHub code scanning

Emit SARIF and upload it so findings show in the **Security** tab:

```yaml
# .github/workflows/security-scan.yml
name: Security scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - run: npx @defen.so/scan ${{ vars.TARGET_URL }} --sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Or gate a pipeline directly:

```bash
npx @defen.so/scan example.com --fail-on high   # exit 1 if any high/critical
```

## Programmatic use

```js
import { scan } from '@defen.so/scan';

const report = await scan('https://example.com', { paths: true, hosted: false });
console.log(report.grade, report.findings);
```

## The Defenso platform

This scanner is one entry point. The full platform adds continuous pentests, a managed WAF with API rate limiting, uptime + SSL/domain-expiry monitoring, GitHub/GitLab repo secret scanning, a compliance generator, and an [MCP server](https://www.npmjs.com/package/@defen.so/mcp) that gives Claude Code, Cursor and Windsurf the same checks inside your editor.

- Website: https://defen.so
- Scanner page: https://defen.so/online-website-security-scanner
- MCP for AI editors: `npx @defen.so/mcp`
- One-line WAF install: `npx @defen.so/init`

## License

MIT © Next Lab LLC
