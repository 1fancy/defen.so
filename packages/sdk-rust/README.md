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
