/**
 * Next.js middleware (Edge or Node runtime):
 *
 *   // middleware.ts
 *   import { NextResponse } from 'next/server';
 *   import { defensoNext } from '@defenso/sdk-node/next';
 *
 *   const inspect = defensoNext({ token: process.env.DEFENSO_TOKEN! });
 *   export function middleware(req: Request) {
 *     const verdict = inspect(req);
 *     if (verdict.blocked) {
 *       return new NextResponse(JSON.stringify({ error: verdict.reason }), { status: 403 });
 *     }
 *     return NextResponse.next();
 *   }
 */

import { DefensoClient, initDefenso, type DefensoOptions } from './index.js';

export interface NextInspectResult {
    blocked: boolean;
    action: 'allow' | 'block' | 'challenge';
    rule?: string;
    reason?: string;
}

export function defensoNext(options: DefensoOptions | { client: DefensoClient }): (req: Request) => NextInspectResult {
    const client = 'client' in options ? options.client : initDefenso(options);

    return (req: Request): NextInspectResult => {
        const headers: Record<string, string> = {};
        req.headers.forEach((v, k) => {
            headers[k] = v;
        });

        const verdict = client.inspect({
            method: req.method,
            url: req.url,
            headers,
            ip: req.headers.get('x-forwarded-for') ?? undefined,
        });

        return {
            blocked: verdict.action === 'block',
            action: verdict.action,
            rule: verdict.rule?.id,
            reason: verdict.reason,
        };
    };
}
