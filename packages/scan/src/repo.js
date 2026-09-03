/**
 * Local repository / filesystem scanner for @defen.so/scan.
 *
 *   defenso-scan repo [path]        scan a working tree for committed secrets,
 *                                   risky dependencies and unsafe Docker/CI config.
 *
 * Fully offline — reads files on disk, never makes a network request. Returns
 * the same report shape as the URL scanner so --json / --sarif / --fail-on all
 * work unchanged.
 */
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative, basename, extname } from 'node:path';
import { SECRET_PATTERNS } from './templates.js';
import { VERSION } from './index.js';

const SEV_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'vendor', 'dist', 'build', 'out', '.next', '.nuxt',
  'coverage', '.venv', 'venv', '__pycache__', '.idea', '.vscode', 'bower_components',
  'target', '.gradle', '.cache', 'tmp', '.terraform',
]);

// Binary / generated extensions we never open.
const SKIP_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg', '.woff', '.woff2',
  '.ttf', '.eot', '.pdf', '.zip', '.gz', '.tar', '.mp4', '.mp3', '.mov', '.wasm',
  '.min.js', '.map', '.lock', '.class', '.jar', '.so', '.dll', '.dylib', '.bin',
]);

const MAX_FILE_BYTES = 512 * 1024;

// Repo-only secret patterns (the URL scanner catches these in served pages; on
// disk we also want committed credential lines the browser never sees).
const REPO_SECRETS = [
  { id: 'generic-api-key', name: 'Hardcoded API key/secret', re: /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]/i, sev: 'high', cwe: 'CWE-798' },
  { id: 'db-url-with-password', name: 'Database URL with password', re: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@'"]+:[^\s:@'"]+@[^\s'"]+/i, sev: 'high', cwe: 'CWE-798' },
  { id: 'twilio-key', name: 'Twilio API key', re: /\bSK[0-9a-fA-F]{32}\b/, sev: 'high', cwe: 'CWE-798' },
  { id: 'sendgrid-key', name: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/, sev: 'critical', cwe: 'CWE-798' },
  { id: 'npm-token', name: 'npm access token', re: /\bnpm_[A-Za-z0-9]{36}\b/, sev: 'high', cwe: 'CWE-798' },
  { id: 'openai-key', name: 'OpenAI API key', re: /\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b/, sev: 'high', cwe: 'CWE-798' },
];

// A small offline list of npm packages with well-known malicious/compromised
// versions. Not a substitute for a live OSV feed, but catches the headline
// supply-chain incidents with zero network. Version = affected (<=).
const KNOWN_BAD_NPM = {
  'event-stream': { max: '3.3.6', note: 'v3.3.6 shipped the flatmap-stream bitcoin-stealer backdoor.' },
  'flatmap-stream': { max: '999', note: 'Malicious package; remove entirely.' },
  'ua-parser-js': { max: '0.7.29', note: 'Compromised releases 0.7.29/0.8.0/1.0.0 contained a crypto-miner.' },
  'coa': { max: '2.0.2', note: 'Hijacked 2.0.3+/2.1.x releases were malicious; pin a clean version.' },
  'rc': { max: '1.2.8', note: 'Hijacked 1.2.9/1.3.9/2.3.9 releases were malicious.' },
  'node-ipc': { max: '11.0.0', note: 'Protestware wiper in 10.1.1/11.0.0; avoid affected range.' },
};

function walk(dir, root, out, depth) {
  if (depth > 25) return;
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const full = join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      walk(full, root, out, depth + 1);
    } else if (e.isFile()) {
      const ext = extname(e.name).toLowerCase();
      if (SKIP_EXT.has(ext)) continue;
      if (e.name.endsWith('.min.js')) continue;
      let st;
      try { st = statSync(full); } catch { continue; }
      if (st.size > MAX_FILE_BYTES || st.size === 0) continue;
      out.push(full);
    }
  }
}

function readText(file) {
  try {
    const buf = readFileSync(file);
    // Skip files that look binary (NUL byte in the first 8KB).
    if (buf.subarray(0, 8192).includes(0)) return null;
    return buf.toString('utf8');
  } catch { return null; }
}

function ver(v) {
  return String(v || '').replace(/^[\^~>=<\s]+/, '').split('.').map((n) => parseInt(n, 10) || 0);
}

function lte(a, b) {
  const x = ver(a), y = ver(b);
  for (let i = 0; i < 3; i++) {
    if ((x[i] || 0) < (y[i] || 0)) return true;
    if ((x[i] || 0) > (y[i] || 0)) return false;
  }
  return true;
}

function scanSecrets(files, root, findings) {
  const patterns = [...SECRET_PATTERNS, ...REPO_SECRETS];
  for (const file of files) {
    const rel = relative(root, file);
    const text = readText(file);
    if (text === null) continue;
    const lines = text.split('\n');
    for (const p of patterns) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.length > 4000) continue;
        if (p.re.test(line)) {
          // Skip obvious placeholders/examples.
          if (/(?:example|placeholder|your[_-]?|xxxx|changeme|dummy|<[a-z_]+>|\.\.\.)/i.test(line)) continue;
          findings.push({
            id: p.id,
            name: p.name,
            severity: p.sev,
            cwe: p.cwe,
            tags: ['secret', 'repo'],
            evidence: `${rel}:${i + 1}`,
            remediation: 'Remove the secret from source, rotate it, and load it from an environment variable or a secrets manager. Purge it from git history.',
          });
          break;
        }
      }
    }
  }
}

function scanDependencies(root, findings) {
  const pkgPath = join(root, 'package.json');
  if (!existsSync(pkgPath)) return;
  let pkg;
  try { pkg = JSON.parse(readFileSync(pkgPath, 'utf8')); } catch { return; }
  const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  for (const [name, range] of Object.entries(deps)) {
    const bad = KNOWN_BAD_NPM[name];
    if (bad && lte(range, bad.max)) {
      findings.push({
        id: 'vuln-dependency',
        name: `Known-bad dependency: ${name}`,
        severity: 'high',
        cwe: 'CWE-1104',
        tags: ['dependency', 'supply-chain', 'repo'],
        evidence: `package.json — ${name}@${range}. ${bad.note}`,
        remediation: `Upgrade ${name} past the affected range or remove it, then run npm audit.`,
      });
    }
  }
}

function scanDockerfiles(files, root, findings) {
  for (const file of files) {
    if (basename(file) !== 'Dockerfile' && !basename(file).startsWith('Dockerfile.')) continue;
    const rel = relative(root, file);
    const text = readText(file);
    if (text === null) continue;
    if (/^\s*FROM\s+\S+:latest\b/im.test(text)) {
      findings.push({ id: 'docker-latest-tag', name: 'Docker base image pinned to :latest', severity: 'low', cwe: 'CWE-1104', tags: ['docker', 'repo'], evidence: `${rel} — FROM ...:latest`, remediation: 'Pin the base image to a specific digest or version tag for reproducible, auditable builds.' });
    }
    if (!/^\s*USER\s+(?!root\b)\S+/im.test(text) && /^\s*(?:CMD|ENTRYPOINT)\b/im.test(text)) {
      findings.push({ id: 'docker-runs-as-root', name: 'Docker image runs as root', severity: 'medium', cwe: 'CWE-250', tags: ['docker', 'repo'], evidence: `${rel} — no non-root USER before CMD/ENTRYPOINT`, remediation: 'Add a non-root USER instruction so the container does not run as root.' });
    }
    if (/\b(?:ENV|ARG)\s+\w*(?:PASSWORD|SECRET|TOKEN|KEY)\w*\s*=\s*\S+/i.test(text)) {
      findings.push({ id: 'docker-secret-in-env', name: 'Secret baked into Docker ENV/ARG', severity: 'high', cwe: 'CWE-798', tags: ['docker', 'secret', 'repo'], evidence: `${rel} — credential in ENV/ARG`, remediation: 'Never bake secrets into image layers. Pass them at runtime via a mounted secret or environment variable.' });
    }
  }
}

function scanCiWorkflows(root, findings) {
  const dir = join(root, '.github', 'workflows');
  if (!existsSync(dir)) return;
  let files;
  try { files = readdirSync(dir); } catch { return; }
  for (const name of files) {
    if (!/\.ya?ml$/i.test(name)) continue;
    const rel = join('.github', 'workflows', name);
    const text = readText(join(dir, name));
    if (text === null) continue;
    if (/\buses:\s*[^@\n]+@(?:main|master|v?\d+)\s*$/im.test(text) && /\buses:\s*(?!actions\/)[^@\n]+@[a-z]/im.test(text)) {
      findings.push({ id: 'ci-unpinned-action', name: 'Third-party GitHub Action not pinned to a SHA', severity: 'medium', cwe: 'CWE-829', tags: ['ci', 'supply-chain', 'repo'], evidence: `${rel} — action pinned to a mutable tag/branch`, remediation: 'Pin third-party actions to a full commit SHA so a compromised tag cannot inject code into your pipeline.' });
    }
    if (/\bpull_request_target\b/.test(text) && /\bactions\/checkout\b/.test(text)) {
      findings.push({ id: 'ci-pr-target-checkout', name: 'pull_request_target checks out untrusted PR code', severity: 'high', cwe: 'CWE-94', tags: ['ci', 'repo'], evidence: `${rel} — pull_request_target with checkout`, remediation: 'Do not check out and run untrusted PR code under pull_request_target, which has access to secrets. Use pull_request or split trusted/untrusted steps.' });
    }
  }
}

/**
 * Scan a local directory. Returns the standard report object.
 */
export function scanRepo(dirInput, opts = {}) {
  const root = dirInput || '.';
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    throw new Error(`not a directory: ${root}`);
  }

  const files = [];
  walk(root, root, files, 0);

  const findings = [];
  scanSecrets(files, root, findings);
  scanDependencies(root, findings);
  scanDockerfiles(files, root, findings);
  scanCiWorkflows(root, findings);

  // Dedup + sort (highest severity first), mirroring the URL scanner.
  const seen = new Set();
  const deduped = findings.filter((f) => { const k = f.id + '|' + f.evidence; if (seen.has(k)) return false; seen.add(k); return true; });
  deduped.sort((a, b) => (SEV_ORDER[b.severity] - SEV_ORDER[a.severity]) || a.id.localeCompare(b.id));

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of deduped) counts[f.severity] = (counts[f.severity] || 0) + 1;
  let grade = 'A';
  if (counts.critical) grade = 'F';
  else if (counts.high) grade = 'D';
  else if (counts.medium >= 3) grade = 'C';
  else if (counts.medium) grade = 'B';
  else if (counts.low) grade = 'A-';

  return {
    tool: '@defen.so/scan', version: VERSION,
    mode: 'repo', url: root, host: root, https: true, status: 0,
    filesScanned: files.length,
    templatesRun: SECRET_PATTERNS.length + REPO_SECRETS.length + Object.keys(KNOWN_BAD_NPM).length + 5,
    grade, counts, findings: deduped, hosted: null,
    scannedAt: new Date().toISOString(),
  };
}
