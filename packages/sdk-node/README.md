# @defenso/sdk-node

Defenso security in your Node app. WAF + attack logging in one line.

**Fails open.** If Defenso is unreachable, your app keeps serving.

## Install

```bash
npm install @defenso/sdk-node
```

Then get a token at https://app.defen.so/developer.

## Express

```ts
import express from 'express';
import { defenso } from '@defenso/sdk-node/express';

const app = express();
app.use(defenso({ token: process.env.DEFENSO_TOKEN! }));

app.get('/', (req, res) => res.send('hi'));
app.listen(3000);
```

## Fastify

```ts
import Fastify from 'fastify';
import { defensoFastify } from '@defenso/sdk-node/fastify';

const app = Fastify();
await app.register(defensoFastify, { token: process.env.DEFENSO_TOKEN! });

app.get('/', async () => ({ hello: 'world' }));
app.listen({ port: 3000 });
```

## Next.js

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

## How it works

- **Policy** (WAF rules) is pulled from Defenso every 5 min and cached locally.
- **Requests** are inspected in-process against the cached policy. Latency: ~0.1 ms.
- **Attack events** are queued and flushed to Defenso every 10 s in the background.
- **If Defenso is down**, requests are allowed. Your app never blocks on the network.

## Options

```ts
defenso({
    token: '...',                // required
    api: 'https://app.defen.so/api', // override for self-hosted
    policyRefreshMs: 5 * 60_000,     // how often to pull rules
    logFlushMs: 10_000,              // background log flush cadence
    logBatchSize: 50,                // immediate flush at this batch size
    policyTimeoutMs: 250,            // fail-open threshold on policy fetch
});
```

## License

MIT
