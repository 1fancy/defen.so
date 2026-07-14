# defenso (Ruby)

Rack + Rails middleware for Defenso.

## Install

```bash
bundle add defenso
```

## Use — Rails

```ruby
# config/application.rb
config.middleware.use Defenso::Middleware, token: ENV.fetch("DEFENSO_TOKEN")
```

## Use — Sinatra / Rack

```ruby
use Defenso::Middleware, token: ENV.fetch("DEFENSO_TOKEN")
```

## Fail-open contract

Same guarantees as the Node SDK. Cache TTL 24 h.

## Status

Alpha scaffold.

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-ruby)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
