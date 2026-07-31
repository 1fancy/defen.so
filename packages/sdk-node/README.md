# @defen.so/sdk-node

**One-line WAF, bot detection, and attack logging for Node, Express, Fastify, Next.js, Bun, and Deno.** Part of [Defenso](https://defen.so) — your security layer, shipped in 30 seconds.

- Managed WAF with OWASP Top 10 + Core Rule Set + your custom rules
- Bot detection with UA classification + rate limits
- Attack logging with full context (IP, ASN, country, payload, route, verdict)
- **Fails open** — if Defenso is unreachable, your app keeps serving
- ~0.1 ms in-process latency (rules cached, evaluation is local)
- Attack events queued and flushed in the background
- $0 to start · Pro $29/mo per site

## Install

```bash
npm install @defen.so/sdk-node
```

Get a token at https://app.defen.so/developer.

## Frameworks

### Express

```ts
import express from 'express';
import { defenso } from '@defen.so/sdk-node/express';

const app = express();
app.use(defenso({ token: process.env.DEFENSO_TOKEN! }));

app.get('/', (req, res) => res.send('hi'));
app.listen(3000);
```

### Fastify

```ts
import Fastify from 'fastify';
import { defensoFastify } from '@defen.so/sdk-node/fastify';

const app = Fastify();
await app.register(defensoFastify, { token: process.env.DEFENSO_TOKEN! });

app.get('/', async () => ({ hello: 'world' }));
app.listen({ port: 3000 });
```

### Next.js (App or Pages router)

```ts
// middleware.ts
import { NextResponse } from 'next/server';
import { defensoNext } from '@defen.so/sdk-node/next';

const inspect = defensoNext({ token: process.env.DEFENSO_TOKEN! });

export function middleware(req: Request) {
    const verdict = inspect(req);
    if (verdict.blocked) {
        return new NextResponse(JSON.stringify({ error: verdict.reason }), { status: 403 });
    }
    return NextResponse.next();
}
```

### Bun

`defensoNext` inspects any Web `Request` and returns `{ blocked, reason }`, so
it wires straight into `Bun.serve`:

```ts
import { defensoNext } from '@defen.so/sdk-node/next';

const inspect = defensoNext({ token: Bun.env.DEFENSO_TOKEN! });

Bun.serve({
    fetch(req) {
        const verdict = inspect(req);
        if (verdict.blocked) {
            return new Response(JSON.stringify({ error: verdict.reason }), { status: 403 });
        }
        return new Response('hi');
    },
});
```

### Deno

```ts
import { defensoNext } from 'npm:@defen.so/sdk-node/next';

const inspect = defensoNext({ token: Deno.env.get('DEFENSO_TOKEN')! });

Deno.serve((req) => {
    const verdict = inspect(req);
    if (verdict.blocked) {
        return new Response(JSON.stringify({ error: verdict.reason }), { status: 403 });
    }
    return new Response('hi');
});
```

## How it works

- **Policy** (WAF rules) is pulled from Defenso every 5 min and cached in-memory.
- **Requests** are inspected in-process against the cached policy. Latency ~0.1 ms.
- **Attack events** are queued and flushed to Defenso every 10 s in the background.
- **If Defenso is down**, requests are allowed. Your app never blocks on the network.

## Options

All framework adapters (`defenso`, `defensoFastify`, `defensoNext`) accept the
same options object:

```ts
{
    token: '...',                        // required
    api: 'https://app.defen.so/api',     // override for self-hosted
    policyRefreshMs: 5 * 60_000,         // how often to pull rules
    logFlushMs: 10_000,                  // background log flush cadence
    logBatchSize: 50,                    // immediate flush at this batch size
    policyTimeoutMs: 250,                // fail-open threshold on policy fetch
}
```

## What Defenso stops

SQL injection, XSS (reflected / stored / DOM), CSRF, SSRF, path traversal, XXE, NoSQL / LDAP / command injection, brute force, credential stuffing, malicious file uploads (polyglots, PHP-in-PNG), bot scrapers, headless browser abuse, TOR exit nodes, exposed secrets, wide-open cloud config. Full list at [defen.so/threats](https://defen.so/threats).

## Part of the Defenso platform

This SDK is the in-process WAF layer. It plugs into the same account that powers uptime monitoring, quick pentest (headers, TLS, **email security** SPF/DKIM/DMARC, and compliance-style findings), vibe-coder and repo/secret scans, active deception, and the real-time attack log — all managed from [app.defen.so](https://app.defen.so).

- **[@defen.so/init](https://www.npmjs.com/package/@defen.so/init)** — one-command bootstrap that detects your framework and adds the SDK correctly.
- **[Playground](https://playground.defen.so)** — fire attacks at a live SDK-protected origin and see what got blocked.
- **[MCP for Claude Code / Cursor / Windsurf / VS Code](https://mcp.defen.so)** — give your AI IDE real security tools.
- **[Defen.so Connector for WordPress](https://wordpress.org/plugins/defen-so-connector/)** — local hardening + one-click managed WAF for WP sites.
- **[Defenso Alerts on Google Play](https://play.google.com/store/apps/details?id=so.defen.alerts)** — call-style **Alarm** notifications that ring through silent mode / DND until you acknowledge, plus per-site per-event Off/Notification/Alarm and Slack/Discord/Telegram/email/webhook fan-out ([defen.so/website-monitor-app](https://defen.so/website-monitor-app); iOS coming soon).

## Links

- Marketing site: [defen.so](https://defen.so)
- App: [app.defen.so](https://app.defen.so)
- Source (monorepo): [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-node)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- Pricing: [defen.so/pricing](https://defen.so/pricing)
- Contact: info@defen.so

## License

MIT
