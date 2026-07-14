# defenso/sdk-php

**One-line WAF, bot detection, and attack logging for PHP — Laravel, Symfony, and plain PHP apps.** Part of [Defenso](https://defen.so) — the security layer for indie devs, vibe coders, and shipping teams.

- Managed WAF with OWASP Top 10 + Core Rule Set + your custom rules
- Bot detection with UA classification + rate limits
- Attack logging with full context (IP, ASN, country, payload, route, verdict)
- **Fails open** — if Defenso is unreachable, your app keeps serving
- ~0.1 ms in-process latency (rules cached, evaluation is local)
- Attack events queued and flushed asynchronously
- Free tier forever · Pro $29/mo per site
- Requires PHP 8.2+ (works great on 8.4)

## Install

```bash
composer require defenso/sdk-php
```

Get a token at https://app.defen.so/developer, then set `DEFENSO_TOKEN` in `.env`.

## Laravel

Register the client as a singleton in a service provider:

```php
use Defenso\Client;

$this->app->singleton(Client::class, fn () => new Client(config('services.defenso.token')));
```

Append the middleware in `bootstrap/app.php`:

```php
->withMiddleware(function ($middleware) {
    $middleware->append(\Defenso\Middleware\DefensoLaravelMiddleware::class);
})
```

Add to `config/services.php`:

```php
'defenso' => [
    'token' => env('DEFENSO_TOKEN'),
],
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

## Plain PHP

```php
require __DIR__ . '/vendor/autoload.php';

$client = new \Defenso\Client(getenv('DEFENSO_TOKEN'));
$verdict = $client->inspect([
    'method' => $_SERVER['REQUEST_METHOD'],
    'url' => 'https://'.$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'],
    'headers' => getallheaders() ?: [],
    'body' => file_get_contents('php://input') ?: '',
    'ip' => $_SERVER['REMOTE_ADDR'] ?? null,
]);

if ($verdict['action'] === 'block') {
    http_response_code(403);
    echo json_encode(['blocked' => true, 'reason' => $verdict['reason'] ?? null]);
    exit;
}
```

## Options

```php
new Defenso\Client(
    token: 'df_live_...',
    api: 'https://app.defen.so/api',    // override for self-hosted
    policyRefreshSeconds: 300,           // pull rules every 5 min
    logBatchSize: 50,                    // flush at this many events
    policyTimeoutSeconds: 1.0,           // fail-open threshold on policy fetch
);
```

## How it works

- **Policy** (WAF rules) pulled from Defenso every 5 min, cached in memory.
- **Requests** inspected in-process. Latency ~0.1 ms.
- **Attack events** queued in-memory, flushed at batch size or client destruction.
- **If Defenso is down**, requests are allowed. Your app never blocks.

## What Defenso stops

SQL injection, XSS (reflected / stored / DOM), CSRF, SSRF, path traversal, XXE, NoSQL / LDAP / command injection, brute force, credential stuffing, malicious file uploads (polyglots, PHP-in-PNG), bot scrapers, headless browser abuse, TOR exit nodes, exposed secrets, wide-open cloud config. Full list at [defen.so/threats](https://defen.so/threats).

## Companion tools

- **[@defen.so/init](https://www.npmjs.com/package/@defen.so/init)** — one-command bootstrap that detects your framework and adds the SDK correctly.
- **[Playground](https://playground.defen.so)** — fire attacks at a live PHP-SDK-protected origin and see what got blocked.
- **[MCP for Claude Code / Cursor / Windsurf / VS Code](https://mcp.defen.so)** — give your AI IDE real security tools.

## Links

- Marketing site: [defen.so](https://defen.so)
- App: [app.defen.so](https://app.defen.so)
- Source (monorepo): [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so/tree/main/packages/sdk-php)
- Issues: [github.com/1fancy/defen.so/issues](https://github.com/1fancy/defen.so/issues)
- Packagist: [packagist.org/packages/defenso/sdk-php](https://packagist.org/packages/defenso/sdk-php)
- Pricing: [defen.so/pricing](https://defen.so/pricing)
- Contact: info@defen.so

## License

MIT
