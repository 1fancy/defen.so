# defenso (Go)

Fail-open Defenso middleware for Go web frameworks.

## Install

```bash
go get github.com/defenso/sdk-go
```

## Use — net/http (works with chi and any net/http router)

```go
import "github.com/defenso/sdk-go"

r := chi.NewRouter()
r.Use(defenso.Middleware(defenso.Config{
    Token: os.Getenv("DEFENSO_TOKEN"),
}))
```

## Status

Scaffold — this SDK currently passes every request through and does not yet inspect, block, cache policy, or forward attack logs. For working protection today use the CNAME edge (point your domain at guard.defen.so — full WAF, no code) or the Node/PHP SDKs.

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-go)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
