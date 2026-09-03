/**
 * Offline tests for the CLI deep-check probes added for parity with the hosted
 * scanner: mixed-content (passive, reads ctx.body) and SSTI (active, uses a
 * mocked probeRaw). Run with: node test/deepchecks.test.mjs
 */
import { runMixedContentTemplate, runSstiProbe } from '../src/templates-deepchecks.js';

let failed = 0;
function assert(cond, msg) {
  if (cond) { console.log('  ok   ' + msg); } else { console.error('  FAIL ' + msg); failed++; }
}

// ── mixed content ────────────────────────────────────────────────────────────
const mc = runMixedContentTemplate({ https: true, body: '<script src="http://cdn.evil.com/a.js"></script><link href="http://x.com/s.css">' });
assert(mc.length === 1 && mc[0].id === 'mixed-content', 'flags active http:// resources on an HTTPS page');
assert(mc[0].cwe === 'CWE-311', 'mixed-content carries CWE-311');

const mcClean = runMixedContentTemplate({ https: true, body: '<script src="https://cdn.ok.com/a.js"></script>' });
assert(mcClean.length === 0, 'clean HTTPS page has no mixed-content finding');

const mcHttp = runMixedContentTemplate({ https: false, body: '<script src="http://x/a.js"></script>' });
assert(mcHttp.length === 0, 'a plain-HTTP page is not flagged for mixed content');

// ── SSTI (mock probeRaw) ─────────────────────────────────────────────────────
const vulnerableCtx = {
  probeRaw: async (path) => {
    // Simulate an engine that evaluates {{7*7}} -> 49 (and only that probe).
    if (path.includes('%7B%7B7*7%7D%7D')) return { status: 200, body: '<p>result: 49</p>' };
    return { status: 200, body: '<p>nothing</p>' };
  },
};
const ssti = await runSstiProbe(vulnerableCtx);
assert(ssti.length === 1 && ssti[0].id === 'ssti', 'flags server-side template injection when 7*7 evaluates to 49');
assert(ssti[0].cwe === 'CWE-1336' && ssti[0].severity === 'critical', 'ssti is CWE-1336 / critical');

const safeCtx = {
  // Echoes the raw payload back (that is XSS territory, not SSTI) — must NOT flag.
  probeRaw: async (path) => ({ status: 200, body: decodeURIComponent(path) }),
};
const noSsti = await runSstiProbe(safeCtx);
assert(noSsti.length === 0, 'a literal echo of the payload is not mis-reported as SSTI');

if (failed) { console.error(`\n${failed} assertion(s) failed`); process.exit(1); }
console.log('\nAll deep-check probe assertions passed.');
