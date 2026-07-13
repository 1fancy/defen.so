# @defenso/sdk-bun

Same as `@defenso/sdk-node` but built for Bun.serve.

## Install

```bash
bun add @defenso/sdk-node
```

## Use

```ts
import { defenso } from '@defenso/sdk-node'

Bun.serve({
  fetch: defenso({ token: Bun.env.DEFENSO_TOKEN }).fetch,
})
```

The Node SDK's `@defenso/sdk-node` already works under Bun. This package is a re-export
to make the discover-and-install story symmetric with other runtimes.

## Status

Alpha alias — use `@defenso/sdk-node` directly for now.
