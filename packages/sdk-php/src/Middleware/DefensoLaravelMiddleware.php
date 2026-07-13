<?php

declare(strict_types=1);

namespace Defenso\Middleware;

use Closure;
use Defenso\Client;

/**
 * Laravel middleware. Wire it in bootstrap/app.php:
 *
 *   ->withMiddleware(function ($middleware) {
 *       $middleware->append(\Defenso\Middleware\DefensoLaravelMiddleware::class);
 *   })
 *
 * Bind Defenso\Client as a singleton in a service provider so the policy
 * cache and log queue survive across requests within the same process.
 */
final class DefensoLaravelMiddleware
{
    public function __construct(private readonly Client $defenso) {}

    public function handle(mixed $request, Closure $next): mixed
    {
        $verdict = $this->defenso->inspect([
            'method' => $request->method(),
            'url' => $request->fullUrl(),
            'headers' => $request->headers->all(),
            'body' => $request->getContent(),
            'ip' => $request->ip(),
        ]);

        if ($verdict['action'] === 'allow') {
            return $next($request);
        }

        if ($verdict['action'] === 'block') {
            return response()->json([
                'error' => 'blocked_by_defenso',
                'reason' => $verdict['reason'] ?? 'security_policy',
                'rule' => $verdict['rule'] ?? null,
            ], 403, [
                'X-Defenso-Verdict' => 'block',
                'X-Defenso-Rule' => $verdict['rule'] ?? '',
            ]);
        }

        return $next($request)->withHeaders([
            'X-Defenso-Verdict' => 'challenge',
            'X-Defenso-Rule' => $verdict['rule'] ?? '',
        ]);
    }
}
