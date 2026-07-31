# @defen.so/sdk-bun

Same as `@defen.so/sdk-node` but built for Bun.serve.

## Install

```bash
bun add @defen.so/sdk-node
```

## Use

`defensoNext` inspects any Web `Request` and returns `{ blocked, reason }`, which
wires straight into `Bun.serve`:

```ts
import { defensoNext } from '@defen.so/sdk-node/next'

const inspect = defensoNext({ token: Bun.env.DEFENSO_TOKEN! })

Bun.serve({
  fetch(req) {
    const verdict = inspect(req)
    if (verdict.blocked) {
      return new Response(JSON.stringify({ error: verdict.reason }), { status: 403 })
    }
    return new Response('hi')
  },
})
```

The Node SDK's `@defen.so/sdk-node` already works under Bun. This package is a re-export
to make the discover-and-install story symmetric with other runtimes.

## Status

Alpha alias — use `@defen.so/sdk-node` directly for now.

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-bun)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
