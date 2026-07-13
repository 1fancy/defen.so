# Defenso · @defen.so

**The security layer for vibe coders and developers who ship fast.** WAF, DDoS wrap, bot detection, active deception, file-upload scanning, uptime monitors, and an MCP server that plugs security tools straight into Claude Code, Cursor, Windsurf, VS Code, and codex. One install per language. Fails open. Free tier that actually protects.

- 🌐 **Home:** [defen.so](https://defen.so)
- 📦 **npm org:** [@defen.so](https://www.npmjs.com/org/defen.so)
- 🔒 **App:** [app.defen.so](https://app.defen.so)
- 🤖 **MCP:** [mcp.defen.so](https://mcp.defen.so)
- 📖 **Docs:** [defen.so/install](https://defen.so/install)

---

## What's in this repo

| Package | Language | Use |
|---|---|---|
| [`@defen.so/mcp`](./packages/mcp) | Node.js | MCP server for Claude Code / Cursor / Windsurf / VS Code |
| [`@defen.so/sdk-node`](./packages/sdk-node) | Node.js | Express / Fastify / Next.js middleware |
| [`@defen.so/sdk-bun`](./packages/sdk-bun) | Bun | Bun.serve wrapper |
| [`@defen.so/sdk-deno`](./packages/sdk-deno) | Deno | Deno.serve wrapper |
| [`defenso` (composer)](./packages/sdk-php) | PHP | Laravel + Symfony middleware |
| [`defenso` (pip)](./packages/sdk-python) | Python | FastAPI / Django / Flask middleware |
| [`github.com/defenso/sdk-go`](./packages/sdk-go) | Go | net/http, chi, gin middleware |
| [`defenso` (gem)](./packages/sdk-ruby) | Ruby | Rack / Rails middleware |
| [`defenso` (crate)](./packages/sdk-rust) | Rust | Tower layer for axum, warp, actix |
| [`io.defenso:sdk`](./packages/sdk-java) | Java | Servlet Filter (Spring, Jetty, Tomcat) |
| [`Defenso` (NuGet)](./packages/sdk-dotnet) | .NET | ASP.NET Core middleware |

---

## Quick start

### 1. Connect your assistant to Defenso (MCP)

```bash
npx -y @defen.so/mcp link
```

Opens a browser, approve once, and the token is stored at `~/.defenso/config.json`. Then wire into your assistant:

```json
// ~/.claude/mcp.json
{
  "mcpServers": {
    "defen.so": {
      "command": "npx",
      "args": ["-y", "@defen.so/mcp"]
    }
  }
}
```

### 2. Add the SDK to your app

**Node.js / Express:**
```bash
npm i @defen.so/sdk-node
```
```js
import { defenso } from '@defen.so/sdk-node'
app.use(defenso({ token: process.env.DEFENSO_TOKEN }))
```

**PHP / Laravel:**
```bash
composer require defenso/sdk-php
```
```php
// bootstrap/app.php
->withMiddleware(fn ($m) => $m->append(\Defenso\Laravel\DefensoMiddleware::class))
```

**Python / FastAPI:**
```bash
pip install defenso
```
```python
from defenso import Defenso
app.add_middleware(Defenso, token=os.environ["DEFENSO_TOKEN"])
```

More languages in [`packages/`](./packages).

### 3. Alternative: CNAME through us

Point your site at `guard.defen.so`:

```
Type   Name           Value
CNAME  www.yoursite  guard.defen.so
```

We handle WAF + deception + upload scan at the edge. **Pro / Business** plans only.

---

## What Defenso stops

Deterministic patterns, verifiable signals. No ML black box.

- **SQL injection** · union / boolean / time-based
- **XSS** · reflected, stored, DOM-adjacent
- **Path traversal** · encoded, double-encoded, null-byte
- **Command injection** · shell metacharacters + `/etc/passwd` probes
- **NoSQL injection** · Mongo operator injection
- **CLI scanners** · `sqlmap`, `nuclei`, `nikto`, `whatweb`, `wpscan`
- **Headless browsers** · Puppeteer, Playwright, PhantomJS
- **DDoS / rate abuse** · per-IP token bucket + Cloudflare Under-Attack
- **Malicious uploads** · MIME mismatch, polyglots, blocked extensions
- **Attacker recon** · honeypots on `.env`, `wp-login.php`, `phpMyAdmin`, `.git/config`, `xmlrpc.php`, `server-status`, `config.php`
- **Exposed secrets** · AWS, Stripe, OpenAI, Anthropic, Supabase, 8 more
- **Open cloud** · unauth-listable S3, Supabase RLS off, Firebase wide-open

---

## Pricing

Each site has its own plan. Mix and match (Cloudflare-style).

| Plan | Price | Sites | Monitors | Interval | Pentests | Vibe scans | CNAME | WAF | Custom rules |
|---|---|---|---|---|---|---|---|---|---|
| **Free** | $0 | 1 | 1 | 10 min | 1 / mo | 1 / mo | ❌ | Basic | ❌ |
| **Pro** | $29 / mo | 5 | 10 | 1 min | 100 / mo | 20 / mo | ✅ | Full | 25 |
| **Business** | $49 / mo | 25 | 50 | 30 s | Unlimited | Unlimited | ✅ | Full + custom | Unlimited |
| **Agency** | Custom | Unlimited | Unlimited | 30 s | Unlimited | Unlimited | ✅ | Full | Unlimited |

Free tier is real — WAF + deception + a monitor + a monthly scan. No card required.

---

## The fail-open contract

Every SDK caches the last known-good policy for 24 hours. If Defenso is unreachable:

1. Evaluate against the local cache.
2. If cache is empty too, requests pass through with a warning logged.

**Your app never breaks because Defenso is unreachable.** That's the whole design.

---

## Documentation

- [Features](https://defen.so/features)
- [Install per language](https://defen.so/install)
- [Threats covered](https://defen.so/threats)
- [Integrations](https://defen.so/integrations)
- [MCP for AI assistants](https://defen.so/mcp)
- [Pricing](https://defen.so/pricing)
- [Roadmap](https://defen.so/roadmap)

---

## License

MIT © Defenso. See [LICENSE](./LICENSE).

---

**Keywords** — WAF, web application firewall, DDoS protection, bot detection, active deception, honeypot, security SaaS, vibe coder security, MCP for security, Claude Code MCP, Cursor MCP, Windsurf MCP, VS Code MCP, developer security, fail-open middleware, Cloudflare wrap, upload scanner, pentest, defen.so, defenso.
