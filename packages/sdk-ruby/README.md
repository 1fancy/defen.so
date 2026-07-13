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
