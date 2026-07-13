/**
 * Express middleware:
 *
 *   import express from 'express';
 *   import { defenso } from '@defenso/sdk-node/express';
 *
 *   const app = express();
 *   app.use(defenso({ token: process.env.DEFENSO_TOKEN! }));
 */

import { DefensoClient, initDefenso, type DefensoOptions } from './index.js';

interface ExpressReq {
    method: string;
    originalUrl?: string;
    url: string;
    headers: Record<string, string | string[] | undefined>;
    body?: unknown;
    ip?: string;
}

interface ExpressRes {
    status: (code: number) => ExpressRes;
    json: (body: unknown) => ExpressRes;
    setHeader: (name: string, value: string) => void;
    end: (body?: string) => void;
}

type NextFn = (err?: unknown) => void;

export function defenso(options: DefensoOptions | { client: DefensoClient }) {
    const client = 'client' in options ? options.client : initDefenso(options);

    return (req: ExpressReq, res: ExpressRes, next: NextFn): void => {
        const verdict = client.inspect({
            method: req.method,
            url: req.originalUrl ?? req.url,
            headers: req.headers,
            body: req.body,
            ip: req.ip,
        });

        if (verdict.action === 'allow') {
            next();
            return;
        }

        res.setHeader('X-Defenso-Verdict', verdict.action);
        if (verdict.rule) {
            res.setHeader('X-Defenso-Rule', verdict.rule.id);
        }

        if (verdict.action === 'block') {
            res.status(403).json({ error: 'blocked_by_defenso', reason: verdict.reason ?? 'security_policy' });
            return;
        }

        // challenge → let downstream serve a challenge page or continue
        next();
    };
}
