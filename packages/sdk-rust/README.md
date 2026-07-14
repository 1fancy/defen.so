# defenso (Rust)

Tower layer for axum, warp, actix. Fail-open Defenso middleware.

## Install

```toml
[dependencies]
defenso = "0.1"
```

## Use — axum

```rust
use axum::Router;
use defenso::DefensoLayer;

let app = Router::new()
    .layer(DefensoLayer::new(env::var("DEFENSO_TOKEN")?));
```

## Fail-open contract

Same guarantees as the Node SDK. Cache TTL 24 h.

## Status

Alpha scaffold.

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-rust)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
