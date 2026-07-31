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

## Status

Scaffold — this SDK currently passes every request through and does not yet inspect, block, cache policy, or forward attack logs. For working protection today use the CNAME edge (point your domain at guard.defen.so — full WAF, no code) or the Node/PHP SDKs.

## Source

- Public repo: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-ruby)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- License: MIT
- Publisher: Next Lab LLC · info@defen.so
