/**
 * Defenso SDK for Deno.
 *
 * Deno runs the Node SDK via the `npm:` specifier — this module re-exports it
 * so `import { defenso } from '@defen.so/sdk-deno'` (or directly from the raw
 * URL / JSR) works with Deno.serve, Fresh, and Oak. Same fail-open guarantee,
 * same options, same policy contract.
 *
 *   import { defenso } from '@defen.so/sdk-deno';
 *   const guard = defenso({ token: Deno.env.get('DEFENSO_TOKEN') });
 *   Deno.serve((req) => {
 *     const v = guard.inspect(req);
 *     if (v.blocked) return new Response(JSON.stringify({ error: v.reason }), { status: 403 });
 *     return new Response('ok');
 *   });
 */
export * from 'npm:@defen.so/sdk-node@^0.2.0';
export { defenso } from 'npm:@defen.so/sdk-node@^0.2.0';
