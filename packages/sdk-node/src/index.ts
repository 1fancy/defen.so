/**
 * Defenso Node SDK — core client.
 *
 * Design principles:
 * - **Fails open.** If Defenso is unreachable or slow, the request is allowed.
 *   No user-facing latency, no outage propagation.
 * - **Policy is cached.** WAF rules are pulled every {policyRefreshMs} and
 *   evaluated locally; the request path never blocks on network calls.
 * - **Logs are fire-and-forget.** Attack events are queued and flushed on a
 *   background timer.
 */

export type DefensoAction = 'allow' | 'block' | 'challenge';

export interface DefensoRule {
    id: string;
    pattern: RegExp;
    action: DefensoAction;
    target: 'url' | 'body' | 'headers' | 'query';
    category: string;
}

export interface DefensoPolicy {
    version: string;
    rules: DefensoRule[];
    updatedAt: number;
}

export interface DefensoOptions {
    /** API key from https://app.defen.so/developer. Required. */
    token: string;
    /** Override the API base URL. Default: https://app.defen.so/api. */
    api?: string;
    /** How often to refresh the cached policy from Defenso. Default: 5 min. */
    policyRefreshMs?: number;
    /** Attack log flush interval. Default: 10s. */
    logFlushMs?: number;
    /** Max log batch size before an immediate flush. Default: 50. */
    logBatchSize?: number;
    /** Per-request policy-check timeout. Default: 250ms — everything longer fails open. */
    policyTimeoutMs?: number;
}

export interface DefensoVerdict {
    action: DefensoAction;
    rule?: DefensoRule;
    reason?: string;
}

export interface DefensoRequestShape {
    method: string;
    url: string;
    headers: Record<string, string | string[] | undefined>;
    body?: unknown;
    ip?: string;
}

interface AttackLog {
    at: number;
    verdict: DefensoVerdict;
    request: {
        method: string;
        url: string;
        ip?: string;
    };
}

const DEFAULTS = {
    api: 'https://app.defen.so/api',
    policyRefreshMs: 5 * 60_000,
    logFlushMs: 10_000,
    logBatchSize: 50,
    policyTimeoutMs: 250,
};

export class DefensoClient {
    private readonly token: string;
    private readonly api: string;
    private readonly policyRefreshMs: number;
    private readonly logFlushMs: number;
    private readonly logBatchSize: number;
    private readonly policyTimeoutMs: number;

    private policy: DefensoPolicy | null = null;
    private policyLastFetch = 0;
    private logQueue: AttackLog[] = [];
    private logTimer: ReturnType<typeof setInterval> | null = null;

    constructor(options: DefensoOptions) {
        if (!options.token) {
            throw new Error('[defenso] token is required — get one at https://app.defen.so/developer');
        }
        this.token = options.token;
        this.api = options.api ?? DEFAULTS.api;
        this.policyRefreshMs = options.policyRefreshMs ?? DEFAULTS.policyRefreshMs;
        this.logFlushMs = options.logFlushMs ?? DEFAULTS.logFlushMs;
        this.logBatchSize = options.logBatchSize ?? DEFAULTS.logBatchSize;
        this.policyTimeoutMs = options.policyTimeoutMs ?? DEFAULTS.policyTimeoutMs;

        void this.refreshPolicy();
        this.startLogFlusher();
    }

    /**
     * Evaluate a request against the cached policy. Returns 'allow' unless a
     * rule matches. Never throws; never blocks on network.
     */
    inspect(req: DefensoRequestShape): DefensoVerdict {
        if (!this.policy || this.policy.rules.length === 0) {
            return { action: 'allow' };
        }

        for (const rule of this.policy.rules) {
            const target = this.extractTarget(req, rule.target);
            if (target && rule.pattern.test(target)) {
                const verdict: DefensoVerdict = {
                    action: rule.action,
                    rule,
                    reason: `${rule.category}: matched ${rule.target}`,
                };
                if (rule.action !== 'allow') {
                    this.queueLog({ at: Date.now(), verdict, request: { method: req.method, url: req.url, ip: req.ip } });
                }
                return verdict;
            }
        }

        return { action: 'allow' };
    }

    /**
     * Force a policy refresh. Called automatically on interval + at boot.
     * Fails silently — the last-known policy remains active.
     */
    async refreshPolicy(): Promise<void> {
        if (Date.now() - this.policyLastFetch < this.policyRefreshMs && this.policy) {
            return;
        }

        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), this.policyTimeoutMs * 4);

            const response = await fetch(`${this.api}/policy`, {
                method: 'GET',
                headers: {
                    Authorization: `Bearer ${this.token}`,
                    'User-Agent': `@defenso/sdk-node/${'0.1.0'}`,
                },
                signal: controller.signal,
            });
            clearTimeout(timer);

            if (!response.ok) {
                return;
            }

            const body = (await response.json()) as { version: string; rules: Array<Omit<DefensoRule, 'pattern'> & { pattern: string; flags?: string }> };
            this.policy = {
                version: body.version,
                updatedAt: Date.now(),
                rules: body.rules.map((r) => ({
                    id: r.id,
                    pattern: new RegExp(r.pattern, r.flags ?? 'i'),
                    action: r.action,
                    target: r.target,
                    category: r.category,
                })),
            };
            this.policyLastFetch = Date.now();
        } catch {
            // fail open — keep last policy
        }
    }

    /**
     * Stop the background flusher. Call on process teardown.
     */
    dispose(): void {
        if (this.logTimer) {
            clearInterval(this.logTimer);
            this.logTimer = null;
        }
        void this.flushLogs();
    }

    private extractTarget(req: DefensoRequestShape, target: DefensoRule['target']): string {
        switch (target) {
            case 'url':
                return req.url;
            case 'query':
                return req.url.split('?')[1] ?? '';
            case 'body':
                return typeof req.body === 'string' ? req.body : JSON.stringify(req.body ?? '');
            case 'headers':
                return Object.entries(req.headers)
                    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(',') : v ?? ''}`)
                    .join('\n');
        }
    }

    private queueLog(log: AttackLog): void {
        this.logQueue.push(log);
        if (this.logQueue.length >= this.logBatchSize) {
            void this.flushLogs();
        }
    }

    private startLogFlusher(): void {
        this.logTimer = setInterval(() => {
            void this.flushLogs();
        }, this.logFlushMs);
        // don't hold the event loop open
        (this.logTimer as unknown as { unref?: () => void }).unref?.();
    }

    private async flushLogs(): Promise<void> {
        if (this.logQueue.length === 0) {
            return;
        }
        const batch = this.logQueue.splice(0);
        try {
            await fetch(`${this.api}/attacks/ingest`, {
                method: 'POST',
                headers: {
                    Authorization: `Bearer ${this.token}`,
                    'Content-Type': 'application/json',
                    'User-Agent': `@defenso/sdk-node/${'0.1.0'}`,
                },
                body: JSON.stringify({ logs: batch }),
            });
        } catch {
            // fail open — drop the batch rather than retry-storm
        }
    }
}

let sharedClient: DefensoClient | null = null;

export function initDefenso(options: DefensoOptions): DefensoClient {
    sharedClient = new DefensoClient(options);
    return sharedClient;
}

export function getDefenso(): DefensoClient {
    if (!sharedClient) {
        throw new Error('[defenso] initDefenso() must be called first');
    }
    return sharedClient;
}
