# @defen.so/sdk-deno

Deno-native alias for `@defen.so/sdk-node`.

## Install

```bash
deno add npm:@defen.so/sdk-node
```

## Use

`defensoNext` inspects any Web `Request` and returns `{ blocked, reason }`, which
wires straight into `Deno.serve`:

```ts
import { defensoNext } from 'npm:@defen.so/sdk-node/next'

const inspect = defensoNext({ token: Deno.env.get('DEFENSO_TOKEN')! })

Deno.serve((req) => {
  const verdict = inspect(req)
  if (verdict.blocked) {
    return new Response(JSON.stringify({ error: verdict.reason }), { status: 403 })
  }
  return new Response('hi')
})
```

## Status

Alpha alias — use `npm:@defen.so/sdk-node` directly.

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-deno)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
