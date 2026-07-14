# @defenso/sdk-node

**One-line WAF, bot detection, and attack logging for Node, Express, Fastify, Next.js, Bun, and Deno.** Part of [Defenso](https://defen.so) — the security layer for indie devs, vibe coders, and shipping teams.

- Managed WAF with OWASP Top 10 + Core Rule Set + your custom rules
- Bot detection with UA classification + rate limits
- Attack logging with full context (IP, ASN, country, payload, route, verdict)
- **Fails open** — if Defenso is unreachable, your app keeps serving
- ~0.1 ms in-process latency (rules cached, evaluation is local)
- Attack events queued and flushed in the background
- Free tier forever · Pro $29/mo per site

## Install

```bash
npm install @defenso/sdk-node
```

Get a token at https://app.defen.so/developer.

## Frameworks

### Express

```ts
import express from 'express';
import { defenso } from '@defenso/sdk-node/express';

const app = express();
app.use(defenso({ token: process.env.DEFENSO_TOKEN! }));

app.get('/', (req, res) => res.send('hi'));
app.listen(3000);
```

### Fastify

```ts
import Fastify from 'fastify';
import { defensoFastify } from '@defenso/sdk-node/fastify';

const app = Fastify();
await app.register(defensoFastify, { token: process.env.DEFENSO_TOKEN! });

app.get('/', async () => ({ hello: 'world' }));
app.listen({ port: 3000 });
```

### Next.js (App or Pages router)

```ts
// middleware.ts
import { NextResponse } from 'next/server';
import { defensoNext } from '@defenso/sdk-node/next';

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

```ts
import { defenso } from '@defenso/sdk-node';
const guard = defenso({ token: Bun.env.DEFENSO_TOKEN });
Bun.serve({ fetch: guard.fetch });
```

### Deno

```ts
import { defenso } from 'npm:@defenso/sdk-node';
const guard = defenso({ token: Deno.env.get('DEFENSO_TOKEN')! });
Deno.serve(guard.handler);
```

## How it works

- **Policy** (WAF rules) is pulled from Defenso every 5 min and cached in-memory.
- **Requests** are inspected in-process against the cached policy. Latency ~0.1 ms.
- **Attack events** are queued and flushed to Defenso every 10 s in the background.
- **If Defenso is down**, requests are allowed. Your app never blocks on the network.

## Options

```ts
defenso({
    token: '...',                        // required
    api: 'https://app.defen.so/api',     // override for self-hosted
    policyRefreshMs: 5 * 60_000,         // how often to pull rules
    logFlushMs: 10_000,                  // background log flush cadence
    logBatchSize: 50,                    // immediate flush at this batch size
    policyTimeoutMs: 250,                // fail-open threshold on policy fetch
});
```

## What Defenso stops

SQL injection, XSS (reflected / stored / DOM), CSRF, SSRF, path traversal, XXE, NoSQL / LDAP / command injection, brute force, credential stuffing, malicious file uploads (polyglots, PHP-in-PNG), bot scrapers, headless browser abuse, TOR exit nodes, exposed secrets, wide-open cloud config. Full list at [defen.so/threats](https://defen.so/threats).

## Companion tools

- **[@defen.so/init](https://www.npmjs.com/package/@defen.so/init)** — one-command bootstrap that detects your framework and adds the SDK correctly.
- **[Playground](https://playground.defen.so)** — fire attacks at a live SDK-protected origin and see what got blocked.
- **[MCP for Claude Code / Cursor / Windsurf / VS Code](https://mcp.defen.so)** — give your AI IDE real security tools.

## Links

- Marketing site: [defen.so](https://defen.so)
- App: [app.defen.so](https://app.defen.so)
- Source (monorepo): [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-node)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- Pricing: [defen.so/pricing](https://defen.so/pricing)
- Contact: info@defen.so

## License

MIT
