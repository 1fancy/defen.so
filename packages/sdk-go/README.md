# defenso (Go)

Fail-open Defenso middleware for Go web frameworks.

## Install

```bash
go get github.com/defenso/sdk-go
```

## Use — chi

```go
import "github.com/defenso/sdk-go"

r := chi.NewRouter()
r.Use(defenso.Middleware(defenso.Config{
    Token: os.Getenv("DEFENSO_TOKEN"),
}))
```

## Use — gin

```go
r := gin.Default()
r.Use(defenso.GinMiddleware(defenso.Config{
    Token: os.Getenv("DEFENSO_TOKEN"),
}))
```

## Fail-open contract

- 24 h in-memory cache of last-known-good policy.
- API failure ⇒ evaluate against cache.
- Cache miss + API failure ⇒ pass through.

## Status

Alpha scaffold.
