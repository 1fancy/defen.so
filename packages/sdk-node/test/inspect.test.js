import { test } from 'node:test';
import assert from 'node:assert/strict';

// Note: tests run against the built dist/. Run `npm run build` first.
const { DefensoClient } = await import('../dist/index.js');

function makeClient() {
    // Inject a fake policy so we don't hit the network.
    const client = new DefensoClient({ token: 'test', policyRefreshMs: 60_000, logFlushMs: 60_000 });
    client['policy'] = {
        version: 'test-1',
        updatedAt: Date.now(),
        rules: [
            { id: 'sqli', pattern: /union\s+select/i, action: 'block', target: 'url', category: 'sqli' },
            { id: 'xss', pattern: /<script>/i, action: 'block', target: 'body', category: 'xss' },
        ],
    };
    return client;
}

test('inspect allows a clean request', () => {
    const client = makeClient();
    const verdict = client.inspect({ method: 'GET', url: '/', headers: {} });
    assert.equal(verdict.action, 'allow');
    client.dispose();
});

test('inspect blocks SQLi in URL', () => {
    const client = makeClient();
    const verdict = client.inspect({ method: 'GET', url: '/api?id=1 UNION SELECT password FROM users', headers: {} });
    assert.equal(verdict.action, 'block');
    assert.equal(verdict.rule?.id, 'sqli');
    client.dispose();
});

test('inspect blocks XSS in body', () => {
    const client = makeClient();
    const verdict = client.inspect({ method: 'POST', url: '/api', headers: {}, body: '<script>alert(1)</script>' });
    assert.equal(verdict.action, 'block');
    assert.equal(verdict.rule?.id, 'xss');
    client.dispose();
});

test('inspect fails open when no policy loaded', () => {
    const client = new DefensoClient({ token: 'test', policyRefreshMs: 60_000, logFlushMs: 60_000 });
    // client.policy stays null because refreshPolicy() failed silently
    const verdict = client.inspect({ method: 'GET', url: '/api?id=1 UNION SELECT * FROM users', headers: {} });
    assert.equal(verdict.action, 'allow');
    client.dispose();
});
