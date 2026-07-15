<?php

declare(strict_types=1);

namespace Defenso;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\GuzzleException;

/**
 * Defenso PHP SDK — core client.
 *
 * Fails open: if Defenso is unreachable, requests are allowed. Attack logs are
 * queued in-memory and best-effort flushed at destruction or on batch size.
 */
final class Client
{
    private const VERSION = '0.1.0';

    /** @var array{version:string, updated_at:int, rules:list<array<string,mixed>>}|null */
    private ?array $policy = null;

    private int $policyLastFetch = 0;

    /** @var list<array<string,mixed>> */
    private array $logQueue = [];

    private GuzzleClient $http;

    public function __construct(
        private readonly string $token,
        private readonly string $api = 'https://app.defen.so/api',
        private readonly int $policyRefreshSeconds = 300,
        private readonly int $logBatchSize = 50,
        private readonly float $policyTimeoutSeconds = 1.0,
    ) {
        if ($token === '') {
            throw new \InvalidArgumentException('[defenso] token is required — get one at https://app.defen.so/developer');
        }

        $this->http = new GuzzleClient([
            'base_uri' => rtrim($this->api, '/').'/',
            'timeout' => $this->policyTimeoutSeconds,
            'headers' => [
                'Authorization' => 'Bearer '.$this->token,
                'User-Agent' => 'defenso/sdk-php/'.self::VERSION,
            ],
        ]);

        $this->refreshPolicy();
    }

    public function __destruct()
    {
        $this->flushLogs();
    }

    /**
     * Inspect a request. Returns a verdict describing the action to take.
     *
     * @param  array<string,mixed>  $request  ['method', 'url', 'headers', 'body'?, 'ip'?]
     * @return array{action: 'allow'|'block'|'challenge'|'deceive', rule?: string, reason?: string, category?: string}
     */
    public function inspect(array $request): array
    {
        if ($this->policy === null) {
            return ['action' => 'allow'];
        }

        foreach ($this->policy['rules'] ?? [] as $rule) {
            $target = $this->extractTarget($request, $rule['target']);
            if ($target === '') {
                continue;
            }

            $flags = $rule['flags'] ?? 'i';
            $delimiter = '#';
            $pattern = $delimiter.str_replace($delimiter, '\\'.$delimiter, $rule['pattern']).$delimiter.$flags;

            if (@preg_match($pattern, $target) === 1) {
                $verdict = [
                    'action' => $rule['action'],
                    'rule' => $rule['id'],
                    'reason' => $rule['category'].': matched '.$rule['target'],
                    'category' => $rule['category'],
                ];

                if ($rule['action'] !== 'allow') {
                    $this->queueLog($request, $verdict);
                }

                return $verdict;
            }
        }

        // Deception: if this site is opted in for API deception and the path
        // looks like an API endpoint, return a 'deceive' verdict so the
        // middleware can serve a plausible fake 200 instead of hitting the
        // real 404 (which would confirm the endpoint doesn't exist).
        $deception = $this->policy['deception'] ?? null;
        if (is_array($deception) && ! empty($deception['api_hosts'])) {
            $host = strtolower((string) parse_url((string) ($request['url'] ?? ''), PHP_URL_HOST));
            $path = (string) parse_url((string) ($request['url'] ?? ''), PHP_URL_PATH);
            if ($host !== '' && in_array($host, array_map('strtolower', (array) $deception['api_hosts']), true)) {
                $pat = '#'.($deception['api_path_pattern'] ?? '^/(api|graphql|rest|v[0-9]+)(/|$)').'#i';
                if (@preg_match($pat, $path) === 1) {
                    $verdict = [
                        'action' => 'deceive',
                        'rule' => 'deception.api',
                        'reason' => 'API deception: unknown endpoint served plausible fake',
                        'category' => 'deception',
                    ];
                    $this->queueLog($request, $verdict);

                    return $verdict;
                }
            }
        }

        return ['action' => 'allow'];
    }

    public function refreshPolicy(): void
    {
        if ($this->policy !== null && (time() - $this->policyLastFetch) < $this->policyRefreshSeconds) {
            return;
        }

        try {
            $response = $this->http->get('policy');
            $body = json_decode((string) $response->getBody(), true);

            if (! is_array($body) || ! isset($body['rules'])) {
                return;
            }

            $this->policy = [
                'version' => (string) ($body['version'] ?? time()),
                'updated_at' => time(),
                'rules' => $body['rules'],
            ];
            $this->policyLastFetch = time();
        } catch (GuzzleException) {
            // fail open — keep last policy
        }
    }

    public function flushLogs(): void
    {
        if (empty($this->logQueue)) {
            return;
        }

        $batch = $this->logQueue;
        $this->logQueue = [];

        try {
            $this->http->post('attacks/ingest', [
                'json' => ['logs' => $batch],
                'timeout' => 1.5,
            ]);
        } catch (GuzzleException) {
            // fail open — drop the batch rather than retry-storm
        }
    }

    /**
     * @param  array<string,mixed>  $request
     */
    private function extractTarget(array $request, string $target): string
    {
        // Decode percent-encoding + `+` for query/url/body targets so
        // rule patterns like `\bunion\s+select\b` match "1+UNION+SELECT"
        // the same as "1 UNION SELECT". Attackers URL-encode payloads
        // to slip past naive regex.
        $decode = static function (string $s): string {
            return $s === '' ? '' : rawurldecode(str_replace('+', ' ', $s));
        };

        return match ($target) {
            'url' => $decode((string) ($request['url'] ?? '')),
            'query' => $decode((string) (parse_url((string) ($request['url'] ?? ''), PHP_URL_QUERY) ?? '')),
            'body' => $decode(is_string($request['body'] ?? null) ? $request['body'] : json_encode($request['body'] ?? '', JSON_UNESCAPED_SLASHES)),
            'headers' => implode(
                "\n",
                array_map(
                    fn ($k, $v) => $k.': '.(is_array($v) ? implode(',', $v) : (string) $v),
                    array_keys($request['headers'] ?? []),
                    array_values($request['headers'] ?? [])
                )
            ),
            default => '',
        };
    }

    /**
     * @param  array<string,mixed>  $request
     * @param  array<string,mixed>  $verdict
     */
    private function queueLog(array $request, array $verdict): void
    {
        $this->logQueue[] = [
            'at' => (int) (microtime(true) * 1000),
            'verdict' => [
                'action' => $verdict['action'],
                'rule' => isset($verdict['rule']) ? ['id' => $verdict['rule']] : null,
                'reason' => $verdict['reason'] ?? null,
            ],
            'request' => [
                'method' => (string) ($request['method'] ?? 'GET'),
                'url' => (string) ($request['url'] ?? ''),
                'ip' => $request['ip'] ?? null,
            ],
        ];

        if (count($this->logQueue) >= $this->logBatchSize) {
            $this->flushLogs();
        }
    }
}
