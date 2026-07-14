<?php

declare(strict_types=1);

namespace Defenso\Tests;

use Defenso\Client;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

final class ClientTest extends TestCase
{
    private function makeClient(array $rules = []): Client
    {
        // Bypass network — inject a fake policy directly.
        $client = new Client('df_live_test', 'http://127.0.0.1:1', 60, 50, 0.1);
        $reflector = new ReflectionClass($client);
        $prop = $reflector->getProperty('policy');
        $prop->setAccessible(true);
        $prop->setValue($client, [
            'version' => 'test-1',
            'updated_at' => time(),
            'rules' => $rules,
        ]);

        return $client;
    }

    public function test_allows_clean_request(): void
    {
        $client = $this->makeClient([
            ['id' => 'sqli.union', 'pattern' => '\\bunion\\s+select\\b', 'flags' => 'i', 'target' => 'query', 'action' => 'block', 'category' => 'sqli'],
        ]);

        $verdict = $client->inspect(['method' => 'GET', 'url' => 'https://example.com/', 'headers' => []]);
        self::assertSame('allow', $verdict['action']);
    }

    public function test_blocks_sqli_in_query(): void
    {
        $client = $this->makeClient([
            ['id' => 'sqli.union', 'pattern' => '\\bunion\\s+select\\b', 'flags' => 'i', 'target' => 'query', 'action' => 'block', 'category' => 'sqli'],
        ]);

        $verdict = $client->inspect([
            'method' => 'GET',
            'url' => 'https://example.com/api?id=1 UNION SELECT password FROM users',
            'headers' => [],
        ]);
        self::assertSame('block', $verdict['action']);
        self::assertSame('sqli.union', $verdict['rule']);
    }

    public function test_blocks_xss_in_body(): void
    {
        $client = $this->makeClient([
            ['id' => 'xss.script', 'pattern' => '<\\s*script[^>]*>', 'flags' => 'i', 'target' => 'body', 'action' => 'block', 'category' => 'xss'],
        ]);

        $verdict = $client->inspect([
            'method' => 'POST',
            'url' => 'https://example.com/api',
            'headers' => [],
            'body' => '<script>alert(1)</script>',
        ]);
        self::assertSame('block', $verdict['action']);
        self::assertSame('xss.script', $verdict['rule']);
    }

    public function test_fails_open_when_no_policy(): void
    {
        $client = new Client('df_live_test', 'http://127.0.0.1:1', 60, 50, 0.1);
        // policy stays null because refresh silently failed
        $verdict = $client->inspect([
            'method' => 'GET',
            'url' => 'https://example.com/api?id=1 UNION SELECT * FROM users',
            'headers' => [],
        ]);
        self::assertSame('allow', $verdict['action']);
    }
}
