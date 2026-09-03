/**
 * Self-contained functional test for the offline repo scanner. No test runner
 * or network. Run with: node test/repo.test.mjs  (exits non-zero on failure).
 */
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { scanRepo } from '../src/repo.js';

let failed = 0;
function assert(cond, msg) {
  if (cond) { console.log('  ok   ' + msg); } else { console.error('  FAIL ' + msg); failed++; }
}
function has(report, id) { return report.findings.some((f) => f.id === id); }

const dir = mkdtempSync(join(tmpdir(), 'defenso-repo-'));
mkdirSync(join(dir, '.github', 'workflows'), { recursive: true });
// Assemble the fake Stripe key at runtime so this source file holds no literal
// key token (GitHub push protection blocks the literal pattern, even a fake).
const fakeStripeKey = ['sk', 'live', 'abcdefghij0123456789abcd'].join('_');
writeFileSync(join(dir, 'app.js'), `const k = "${fakeStripeKey}";\n`);
writeFileSync(join(dir, 'config.env'), 'DATABASE_URL=postgres://admin:s3cr3tp4ss@db:5432/app\n');
writeFileSync(join(dir, 'placeholder.env'), 'API_KEY=your_api_key_here_changeme\n');
writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { 'event-stream': '3.3.6', express: '^4.18.0' } }));
writeFileSync(join(dir, 'Dockerfile'), 'FROM node:latest\nENV API_TOKEN=abc123def456ghi\nCMD ["node","app.js"]\n');
writeFileSync(join(dir, '.github', 'workflows', 'ci.yml'), 'on: pull_request_target\njobs:\n  x:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: some/thing@main\n');

const r = scanRepo(dir);
console.log(`\nrepo scan: ${r.filesScanned} files, grade ${r.grade}, ${r.findings.length} findings`);

assert(has(r, 'stripe-secret'), 'detects Stripe secret key in source');
assert(has(r, 'db-url-with-password'), 'detects database URL with password');
assert(has(r, 'vuln-dependency'), 'detects known-bad dependency (event-stream)');
assert(has(r, 'docker-latest-tag'), 'detects Docker :latest base image');
assert(has(r, 'docker-runs-as-root'), 'detects Docker running as root');
assert(has(r, 'docker-secret-in-env'), 'detects secret baked into Docker ENV');
assert(has(r, 'ci-unpinned-action'), 'detects unpinned third-party GitHub Action');
assert(has(r, 'ci-pr-target-checkout'), 'detects pull_request_target checkout');
assert(r.grade === 'F', 'grades F when a critical secret is present');
assert(!r.findings.some((f) => f.evidence.includes('placeholder.env')), 'skips obvious placeholder secrets');
assert(r.findings.every((f) => f.id && f.name && f.severity && f.evidence), 'every finding has id/name/severity/evidence');

// Clean tree: no findings, grade A.
const clean = mkdtempSync(join(tmpdir(), 'defenso-clean-'));
writeFileSync(join(clean, 'index.js'), 'export const add = (a, b) => a + b;\n');
const rc = scanRepo(clean);
assert(rc.findings.length === 0 && rc.grade === 'A', 'clean tree grades A with zero findings');

rmSync(dir, { recursive: true, force: true });
rmSync(clean, { recursive: true, force: true });

if (failed) { console.error(`\n${failed} assertion(s) failed`); process.exit(1); }
console.log('\nAll repo-scanner assertions passed.');
