# @defenso/sdk-deno

Deno-native alias for `@defenso/sdk-node`.

## Install

```bash
deno add npm:@defenso/sdk-node
```

## Use

```ts
import { defenso } from 'npm:@defenso/sdk-node'

Deno.serve(defenso({ token: Deno.env.get('DEFENSO_TOKEN') }).handler)
```

## Status

Alpha alias — use `npm:@defenso/sdk-node` directly.
