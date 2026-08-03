/**
 * Defenso SDK for Bun.
 *
 * Bun runs the Node SDK natively — this package re-exports @defen.so/sdk-node
 * so `import { defenso } from '@defen.so/sdk-bun'` works with Bun.serve, Elysia,
 * and Hono. Same fail-open guarantee, same options, same policy contract.
 *
 *   import { defenso } from '@defen.so/sdk-bun';
 *   Bun.serve({
 *     fetch(req) {
 *       const v = defenso({ token: Bun.env.DEFENSO_TOKEN }).inspect(req);
 *       if (v.blocked) return new Response(JSON.stringify({ error: v.reason }), { status: 403 });
 *       return new Response('ok');
 *     },
 *   });
 */
export * from '@defen.so/sdk-node';
export { defenso } from '@defen.so/sdk-node';
