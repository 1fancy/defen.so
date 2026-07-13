<?php

declare(strict_types=1);

namespace Defenso\Middleware;

use Defenso\Client;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 * Symfony HttpKernel listener. Register in services.yaml:
 *
 *   Defenso\Middleware\DefensoSymfonyListener:
 *       arguments: ['@Defenso\Client']
 *       tags:
 *           - { name: kernel.event_subscriber }
 */
final class DefensoSymfonyListener implements EventSubscriberInterface
{
    public function __construct(private readonly Client $defenso) {}

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => ['onRequest', 32],
        ];
    }

    public function onRequest(RequestEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();

        $verdict = $this->defenso->inspect([
            'method' => $request->getMethod(),
            'url' => $request->getUri(),
            'headers' => $request->headers->all(),
            'body' => $request->getContent(),
            'ip' => $request->getClientIp(),
        ]);

        if ($verdict['action'] === 'block') {
            $event->setResponse(new JsonResponse(
                [
                    'error' => 'blocked_by_defenso',
                    'reason' => $verdict['reason'] ?? 'security_policy',
                    'rule' => $verdict['rule'] ?? null,
                ],
                403,
                [
                    'X-Defenso-Verdict' => 'block',
                    'X-Defenso-Rule' => $verdict['rule'] ?? '',
                ]
            ));
        }
    }
}
