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

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-deno)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
