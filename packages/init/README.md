# @defen.so/init

One-command bootstrap for Defenso security in a JavaScript, PHP, or Python project.

```bash
npx @defen.so/init
```

Detects your framework (Next.js, Express, Fastify, Laravel, Symfony, FastAPI, Django, Flask), installs the correct SDK, wires the middleware, and adds a stub `DEFENSO_TOKEN` to your `.env`. Re-runs are idempotent.

## Get your token

Sign in at https://app.defen.so, open Developer, copy the `df_live_...` key, paste into `.env`. Free forever tier available.

## Source

- Public repo: [github.com/1fancy/defen.so/tree/main/packages/init](https://github.com/1fancy/defen.so/tree/main/packages/init)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC — info@defen.so
