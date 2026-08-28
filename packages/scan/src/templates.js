/**
 * Detection templates — a nuclei-inspired, data-driven check set. Each template
 * is a plain object with metadata (id, name, severity, tags, cwe, references)
 * and a `run(ctx)` matcher that returns a finding when the condition matches.
 *
 * ctx = { url, host, https, status, headers (lowercased map), body, probe(path) }
 * A template returns null (pass) or { matched:true, evidence, remediation }.
 *
 * Severity: info | low | medium | high | critical  (nuclei's taxonomy).
 * Keeping checks as data means new ones are cheap to add and can be served
 * remotely later (same pattern as the browser-extension rules endpoint).
 */

const SECRET_PATTERNS = [
  { id: 'aws-access-key', name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/, sev: 'critical', cwe: 'CWE-798' },
  { id: 'aws-secret-key', name: 'AWS secret key', re: /\baws_secret_access_key\s*[=:]\s*['"]?[A-Za-z0-9/+=]{40}\b/i, sev: 'critical', cwe: 'CWE-798' },
  { id: 'gcp-api-key', name: 'Google API key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/, sev: 'high', cwe: 'CWE-798', note: 'Some Google keys are public by design (Maps) — verify scope.' },
  { id: 'stripe-secret', name: 'Stripe secret key', re: /\bsk_live_[0-9a-zA-Z]{24,}\b/, sev: 'critical', cwe: 'CWE-798' },
  { id: 'github-token', name: 'GitHub token', re: /\bgh[posru]_[0-9A-Za-z]{36,}\b/, sev: 'critical', cwe: 'CWE-798' },
  { id: 'slack-token', name: 'Slack token', re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, sev: 'high', cwe: 'CWE-798' },
  { id: 'private-key-block', name: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/, sev: 'critical', cwe: 'CWE-321' },
  { id: 'supabase-service-role', name: 'Supabase service_role key', re: /"role"\s*:\s*"service_role"/, sev: 'critical', cwe: 'CWE-798', note: 'service_role bypasses RLS — must never reach the browser.' },
  { id: 'jwt-in-page', name: 'JWT in page source', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, sev: 'medium', cwe: 'CWE-522' },
];

const SENSITIVE_PATHS = [
  { id: 'exposed-env', name: 'Exposed .env file', path: '/.env', sev: 'critical', cwe: 'CWE-538', body: /(?:^|\n)\s*[A-Z0-9_]+\s*=/ },
  { id: 'exposed-git-config', name: 'Exposed .git/config', path: '/.git/config', sev: 'high', cwe: 'CWE-538', body: /\[core\]|\[remote/ },
  { id: 'exposed-git-head', name: 'Exposed .git/HEAD', path: '/.git/HEAD', sev: 'high', cwe: 'CWE-538', body: /ref:\s*refs\// },
  { id: 'exposed-env-backup', name: 'Exposed .env backup', path: '/.env.bak', sev: 'high', cwe: 'CWE-538', body: /=/ },
  { id: 'exposed-config-json', name: 'Exposed config.json', path: '/config.json', sev: 'medium', cwe: 'CWE-538', body: /[{]/ },
  { id: 'exposed-ds-store', name: 'Exposed .DS_Store', path: '/.DS_Store', sev: 'low', cwe: 'CWE-538', body: /Bud1/ },
  { id: 'exposed-dockerfile', name: 'Exposed Dockerfile', path: '/Dockerfile', sev: 'low', cwe: 'CWE-538', body: /FROM\s+/ },
  { id: 'exposed-backup-sql', name: 'Exposed SQL backup', path: '/backup.sql', sev: 'high', cwe: 'CWE-538', body: /(?:INSERT INTO|CREATE TABLE)/i },
];

/** Security-header templates: header missing/weak => finding. */
const HEADER_CHECKS = [
  {
    id: 'missing-hsts', name: 'HSTS not set', header: 'strict-transport-security', sev: 'medium', cwe: 'CWE-319',
    ref: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security',
    when: (ctx) => ctx.https && !ctx.headers['strict-transport-security'],
    evidence: 'No Strict-Transport-Security header on an HTTPS response.',
    remediation: 'Add "Strict-Transport-Security: max-age=63072000; includeSubDomains".',
  },
  {
    id: 'missing-csp', name: 'Content-Security-Policy missing', header: 'content-security-policy', sev: 'medium', cwe: 'CWE-1021',
    ref: 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy',
    when: (ctx) => !ctx.headers['content-security-policy'],
    evidence: 'No Content-Security-Policy header — reflected/stored XSS is harder to contain.',
    remediation: 'Add a Content-Security-Policy, starting with "default-src \'self\'".',
  },
  {
    id: 'weak-csp-unsafe-inline', name: 'CSP allows unsafe-inline', header: 'content-security-policy', sev: 'low', cwe: 'CWE-1021',
    when: (ctx) => /unsafe-inline/i.test(ctx.headers['content-security-policy'] || ''),
    evidence: "Content-Security-Policy contains 'unsafe-inline', which weakens XSS protection.",
    remediation: "Remove 'unsafe-inline'; use nonces or hashes for inline scripts.",
  },
  {
    id: 'missing-xcto', name: 'X-Content-Type-Options missing', header: 'x-content-type-options', sev: 'low', cwe: 'CWE-16',
    when: (ctx) => (ctx.headers['x-content-type-options'] || '').toLowerCase() !== 'nosniff',
    evidence: 'Missing "X-Content-Type-Options: nosniff" — browsers may MIME-sniff responses.',
    remediation: 'Add "X-Content-Type-Options: nosniff".',
  },
  {
    id: 'missing-xfo', name: 'Clickjacking protection missing', header: 'x-frame-options', sev: 'low', cwe: 'CWE-1021',
    when: (ctx) => !ctx.headers['x-frame-options'] && !/frame-ancestors/i.test(ctx.headers['content-security-policy'] || ''),
    evidence: 'No X-Frame-Options and no CSP frame-ancestors — the page can be framed (clickjacking).',
    remediation: 'Add "X-Frame-Options: DENY" or a CSP "frame-ancestors \'none\'".',
  },
  {
    id: 'missing-referrer-policy', name: 'Referrer-Policy missing', header: 'referrer-policy', sev: 'info', cwe: 'CWE-200',
    when: (ctx) => !ctx.headers['referrer-policy'],
    evidence: 'No Referrer-Policy header — full URLs may leak to third parties.',
    remediation: 'Add "Referrer-Policy: strict-origin-when-cross-origin".',
  },
  {
    id: 'server-banner-version', name: 'Server version disclosed', header: 'server', sev: 'info', cwe: 'CWE-200',
    when: (ctx) => /\d+\.\d+/.test(ctx.headers['server'] || '') || /\d+\.\d+/.test(ctx.headers['x-powered-by'] || ''),
    evidence: (ctx) => `Server/X-Powered-By leaks a version: "${ctx.headers['server'] || ctx.headers['x-powered-by']}".`,
    remediation: 'Suppress the version in the Server / X-Powered-By header.',
  },
  {
    id: 'cors-wildcard-credentials', name: 'CORS wildcard with credentials', header: 'access-control-allow-origin', sev: 'high', cwe: 'CWE-942',
    when: (ctx) => (ctx.headers['access-control-allow-origin'] || '') === '*' && /true/i.test(ctx.headers['access-control-allow-credentials'] || ''),
    evidence: 'Access-Control-Allow-Origin: * together with Allow-Credentials: true exposes authenticated data cross-origin.',
    remediation: 'Never combine a wildcard origin with credentials; echo a specific allowed origin instead.',
  },
];

/** Cookie-flag templates read Set-Cookie headers. */
function cookieTemplates(ctx) {
  const findings = [];
  const raw = ctx.setCookies || [];
  for (const c of raw) {
    const name = (c.split('=')[0] || '').trim();
    const low = c.toLowerCase();
    const looksSession = /sess|token|auth|sid|jwt/i.test(name);
    if (!looksSession) continue;
    if (!/;\s*secure/i.test(low) && ctx.https) {
      findings.push(mk('cookie-missing-secure', `Session cookie "${name}" missing Secure`, 'medium', 'CWE-614',
        `Set-Cookie "${name}" has no Secure flag on an HTTPS site.`, 'Add the Secure flag so the cookie is only sent over HTTPS.'));
    }
    if (!/;\s*httponly/i.test(low)) {
      findings.push(mk('cookie-missing-httponly', `Session cookie "${name}" missing HttpOnly`, 'medium', 'CWE-1004',
        `Set-Cookie "${name}" has no HttpOnly flag — readable by JavaScript (XSS theft).`, 'Add the HttpOnly flag.'));
    }
    if (!/;\s*samesite/i.test(low)) {
      findings.push(mk('cookie-missing-samesite', `Session cookie "${name}" missing SameSite`, 'low', 'CWE-352',
        `Set-Cookie "${name}" has no SameSite attribute (CSRF exposure).`, 'Add "SameSite=Lax" (or Strict).'));
    }
  }
  return findings;
}

function mk(id, name, severity, cwe, evidence, remediation, extra = {}) {
  return { id, name, severity, cwe, evidence, remediation, ...extra };
}

/**
 * Run every template against the fetched context. Returns an array of findings.
 * Each finding: { id, name, severity, cwe, evidence, remediation, tags, reference }.
 */
export function runTemplates(ctx) {
  const out = [];

  for (const h of HEADER_CHECKS) {
    if (h.when(ctx)) {
      out.push({
        id: h.id, name: h.name, severity: h.sev, cwe: h.cwe,
        tags: ['header', h.header],
        evidence: typeof h.evidence === 'function' ? h.evidence(ctx) : h.evidence,
        remediation: h.remediation,
        reference: h.ref,
      });
    }
  }

  out.push(...cookieTemplates(ctx).map((f) => ({ ...f, tags: ['cookie'] })));

  if (ctx.body) {
    for (const s of SECRET_PATTERNS) {
      const m = ctx.body.match(s.re);
      if (m) {
        out.push({
          id: s.id, name: `Exposed secret: ${s.name}`, severity: s.sev, cwe: s.cwe,
          tags: ['secret', 'exposure'],
          evidence: `Matched ${s.name} pattern in the page source: "${String(m[0]).slice(0, 24)}…".` + (s.note ? ' ' + s.note : ''),
          remediation: 'Rotate the key immediately and remove it from client-delivered code; keep secrets server-side.',
        });
      }
    }
  }

  return out;
}

/**
 * Probe the sensitive-path templates. Each requires an HTTP fetch, so this is
 * async and separated from the synchronous body/header templates.
 */
export async function runPathTemplates(ctx) {
  const out = [];
  for (const p of SENSITIVE_PATHS) {
    try {
      const res = await ctx.probe(p.path);
      if (res && res.status === 200 && (!p.body || p.body.test(res.body || ''))) {
        out.push({
          id: p.id, name: p.name, severity: p.sev, cwe: p.cwe,
          tags: ['exposure', 'file'],
          evidence: `${p.path} returned 200 with content matching a real ${p.name.toLowerCase()} (not an SPA fallback).`,
          remediation: `Block public access to ${p.path} at the web server / CDN.`,
        });
      }
    } catch { /* unreachable path = pass */ }
  }
  return out;
}

export const TEMPLATE_COUNT = HEADER_CHECKS.length + SECRET_PATTERNS.length + SENSITIVE_PATHS.length + 3;
