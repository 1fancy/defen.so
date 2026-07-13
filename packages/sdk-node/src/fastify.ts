/**
 * Fastify plugin:
 *
 *   import Fastify from 'fastify';
 *   import { defensoFastify } from '@defenso/sdk-node/fastify';
 *
 *   const app = Fastify();
 *   await app.register(defensoFastify, { token: process.env.DEFENSO_TOKEN! });
 */

import { DefensoClient, initDefenso, type DefensoOptions } from './index.js';

interface FastifyRequest {
    method: string;
    url: string;
    headers: Record<string, string | string[] | undefined>;
    body?: unknown;
    ip?: string;
}

interface FastifyReply {
    header: (name: string, value: string) => FastifyReply;
    code: (status: number) => FastifyReply;
    send: (body: unknown) => void;
}

interface FastifyInstance {
    addHook: (name: string, handler: (req: FastifyRequest, reply: FastifyReply) => Promise<void>) => void;
}

export async function defensoFastify(app: FastifyInstance, options: DefensoOptions | { client: DefensoClient }): Promise<void> {
    const client = 'client' in options ? options.client : initDefenso(options);

    app.addHook('onRequest', async (req, reply) => {
        const verdict = client.inspect({
            method: req.method,
            url: req.url,
            headers: req.headers,
            body: req.body,
            ip: req.ip,
        });

        if (verdict.action === 'allow') {
            return;
        }

        reply.header('X-Defenso-Verdict', verdict.action);
        if (verdict.rule) {
            reply.header('X-Defenso-Rule', verdict.rule.id);
        }

        if (verdict.action === 'block') {
            reply.code(403).send({ error: 'blocked_by_defenso', reason: verdict.reason ?? 'security_policy' });
        }
    });
}
