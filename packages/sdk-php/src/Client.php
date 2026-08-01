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
     * @return array{action: 'allow'|'block'|'challenge', rule?: string, reason?: string, category?: string}
     */
    public function inspect(array $request): array
    {
        if ($this->policy === null || empty($this->policy['rules'])) {
            return ['action' => 'allow'];
        }

        // Endpoint rules — per-IP RPS caps + optional regex per URL pattern.
        // Rules come from /policy under endpoint_rules[]. Rate state is a
        // filesystem token bucket at /tmp/df_rl_<hash>. Cheap + persistent
        // across requests (playground is one long-lived vhost).
        $endpointRules = $this->policy['endpoint_rules'] ?? [];
        if (! empty($endpointRules)) {
            $method = strtoupper((string) ($request['method'] ?? 'GET'));
            $url = (string) ($request['url'] ?? '');
            $host = strtolower((string) parse_url($url, PHP_URL_HOST));
            $path = (string) parse_url($url, PHP_URL_PATH);
            $ip = (string) ($request['ip'] ?? '');
            foreach ($endpointRules as $er) {
                if (! empty($er['host']) && strtolower($er['host']) !== $host) {
                    continue;
                }
                $methods = $er['methods'] ?? '*';
                if ($methods !== '*' && stripos($methods, $method) === false) {
                    continue;
                }
                // Managed rules ship a full regex (path_regex); user rules use
                // literal path patterns with :id placeholders.
                $matched = ! empty($er['path_regex'])
                    ? (@preg_match('#'.str_replace('#', '\\#', (string) $er['path_regex']).'#i', $path) === 1)
                    : $this->patternMatchesPath((string) ($er['pattern'] ?? ''), $path);
                if (! $matched) {
                    continue;
                }
                $rps = (int) ($er['rps_per_ip'] ?? 0);
                // Optional sliding-window limit: max `limit` requests per `window`
                // seconds. Decouples the decay rate from the threshold so a
                // brute-force ("8 tries a minute") actually trips — a plain
                // per-second cap refills as fast as it's checked and never does.
                $window = (float) ($er['window_seconds'] ?? 0);
                $limit = (int) ($er['limit'] ?? 0);
                if (($rps > 0 || ($window > 0 && $limit > 0)) && $ip !== '') {
                    // Effective threshold + decay rate. With a window, decay is
                    // limit/window per second; the trip point is `limit`.
                    $threshold = $window > 0 && $limit > 0 ? $limit : $rps;
                    $decayPerSec = $window > 0 && $limit > 0 ? ($limit / $window) : $rps;

                    $bucketKey = 'df_rl_'.substr(hash('sha256', ((string) $er['id']).'|'.$ip), 0, 16);
                    $bucketFile = sys_get_temp_dir().'/'.$bucketKey;
                    $now = microtime(true);
                    // Atomic read-modify-write under an exclusive lock so a
                    // concurrent burst accumulates instead of racing.
                    $counter = 0.0;
                    $fh = @fopen($bucketFile, 'c+');
                    if ($fh !== false) {
                        @flock($fh, LOCK_EX);
                        $raw = stream_get_contents($fh);
                        $state = ['t' => $now, 'n' => 0.0];
                        $loaded = @json_decode((string) $raw, true);
                        if (is_array($loaded) && isset($loaded['t'], $loaded['n'])) {
                            $state = $loaded;
                        }
                        $elapsed = max(0, $now - (float) $state['t']);
                        $state['n'] = max(0.0, (float) $state['n'] - ($elapsed * $decayPerSec));
                        $state['n'] += 1;
                        $state['t'] = $now;
                        $counter = $state['n'];
                        rewind($fh);
                        ftruncate($fh, 0);
                        fwrite($fh, json_encode($state));
                        fflush($fh);
                        @flock($fh, LOCK_UN);
                        fclose($fh);
                    }
                    if ($counter > $threshold) {
                        $verdict = [
                            'action' => $er['action'] ?? 'block',
                            'rule' => 'rate_limit:'.$er['id'],
                            'reason' => 'endpoint '.$er['pattern'].' exceeded '.$threshold.($window > 0 ? ' req / '.$window.'s' : ' req/s').' from IP',
                            'category' => 'rate_limit',
                        ];
                        if ($verdict['action'] !== 'allow') {
                            $this->queueLog($request, $verdict);
                        }

                        return $verdict;
                    }
                }
            }
        }

        foreach ($this->policy['rules'] as $rule) {
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
                'endpoint_rules' => $body['endpoint_rules'] ?? [],
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
    /**
     * Glob-style path match. ":id", ":uuid", ":slug", ":oid", ":token"
     * become a wildcard "[^/]+" segment so /api/users/:id matches
     * /api/users/42.
     */
    private function patternMatchesPath(string $pattern, string $path): bool
    {
        if ($pattern === '') {
            return false;
        }
        $re = preg_quote($pattern, '#');
        $re = preg_replace('/\\\\:[a-z]+/', '[^/]+', $re);

        return @preg_match('#^'.$re.'$#', $path) === 1;
    }

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
