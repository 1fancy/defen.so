# defenso/sdk-php

Defenso security in your PHP app. WAF + attack logging in one line.

**Fails open.** If Defenso is unreachable, your app keeps serving.

## Install

```bash
composer require defenso/sdk-php
```

Then get a token at https://app.defen.so/developer.

## Laravel

Register the client as a singleton in a service provider:

```php
use Defenso\Client;

$this->app->singleton(Client::class, fn () => new Client(config('services.defenso.token')));
```

Then append the middleware in `bootstrap/app.php`:

```php
->withMiddleware(function ($middleware) {
    $middleware->append(\Defenso\Middleware\DefensoLaravelMiddleware::class);
})
```

## Symfony

Register the client and listener in `config/services.yaml`:

```yaml
services:
    Defenso\Client:
        arguments:
            $token: '%env(DEFENSO_TOKEN)%'

    Defenso\Middleware\DefensoSymfonyListener:
        arguments: ['@Defenso\Client']
        tags:
            - { name: kernel.event_subscriber }
```

## Options

```php
new Defenso\Client(
    token: 'rk_live_...',
    api: 'https://app.defen.so/api',   // override for self-hosted
    policyRefreshSeconds: 300,          // pull rules every 5 min
    logBatchSize: 50,                   // flush at this many events
    policyTimeoutSeconds: 1.0,          // fail-open threshold on policy fetch
);
```

## How it works

- **Policy** (WAF rules) pulled from Defenso every 5 min, cached in memory.
- **Requests** inspected in-process. Latency: ~0.1 ms.
- **Attack events** queued and flushed at batch size or client destruction.
- **If Defenso is down**, requests are allowed. Your app never blocks.

## License

MIT
