# defenso (Rust)

Tower layer for axum, warp, actix. Fail-open Defenso middleware.

## Install

```toml
[dependencies]
defenso = "0.2"
```

## Use — axum

```rust
use axum::Router;
use defenso::DefensoLayer;

let app = Router::new()
    .layer(DefensoLayer::new(env::var("DEFENSO_TOKEN")?));
```

## Status

Scaffold — this SDK currently passes every request through and does not yet inspect, block, cache policy, or forward attack logs. For working protection today use the CNAME edge (point your domain at guard.defen.so — full WAF, no code) or the Node/PHP SDKs.

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-rust)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
