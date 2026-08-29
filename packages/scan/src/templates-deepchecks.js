/**
 * Deeper, nuclei-inspired checks that go past headers/TLS: version-to-CVE
 * fingerprinting, subdomain-takeover signals, an expanded exposure pack,
 * GraphQL introspection, a deep CORS probe, and safe-active probes for
 * open-redirect and reflected-XSS.
 *
 * Passive checks run always. Anything that sends a crafted parameter (marked
 * ACTIVE below) only runs when opts.active is set — it stays benign: an inert
 * marker, a harmless redirect target, or an already-public path. Nothing here
 * mutates data or tries default credentials.
 */

// ── #1 Version → known-vulnerability fingerprint ────────────────────────────
// Passive: read a disclosed version from headers/body and flag it if the range
// is a known-bad one. This is the "cves/" breadth nuclei has, kept to the
// high-signal, unambiguous cases so we never cry wolf on a patched build.
const VERSION_RULES = [
  {
    id: 'jquery-outdated', name: 'Outdated jQuery with known XSS', sev: 'medium', cwe: 'CWE-1104',
    re: /jquery[/-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js/i,
    bad: (v) => cmp(v, '3.5.0') < 0,
    note: (v) => `jQuery ${v} is below 3.5.0 and carries known XSS (CVE-2020-11022/11023).`,
  },
  {
    id: 'bootstrap-outdated', name: 'Outdated Bootstrap with known XSS', sev: 'low', cwe: 'CWE-1104',
    re: /bootstrap[/-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.(?:js|css)/i,
    bad: (v) => cmp(v, '4.3.1') < 0,
    note: (v) => `Bootstrap ${v} is below 4.3.1 and carries known XSS in data-* attributes.`,
  },
  {
    id: 'server-old-nginx', name: 'Old nginx banner', sev: 'low', cwe: 'CWE-200', header: 'server',
    re: /nginx\/([0-9]+\.[0-9]+\.[0-9]+)/i,
    bad: (v) => cmp(v, '1.20.0') < 0,
    note: (v) => `Server reports nginx ${v}; versions below 1.20 have multiple disclosed CVEs. Hide the banner and update.`,
  },
];

function cmp(a, b) {
  const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
  return 0;
}

export function runVersionCveTemplates(ctx) {
  const out = [];
  const hay = (ctx.body || '') + ' ';
  for (const r of VERSION_RULES) {
    const src = r.header ? (ctx.headers[r.header] || '') : hay;
    const m = src.match(r.re);
    if (m && m[1] && r.bad(m[1])) {
      out.push({
        id: r.id, name: r.name, severity: r.sev, cwe: r.cwe, tags: ['cve', 'version', 'outdated'],
        evidence: r.note(m[1]),
        remediation: 'Upgrade to a patched version, or remove the version from the banner so it cannot be fingerprinted.',
      });
    }
  }
  return out;
}

// ── #2 Subdomain-takeover fingerprints ──────────────────────────────────────
// Safe-active: a plain GET of the root already gives us the body; a dangling
// CNAME shows a provider "not found" page. We match those provider signatures.
const TAKEOVER_SIGNS = [
  { name: 'AWS S3', re: /NoSuchBucket|The specified bucket does not exist/i },
  { name: 'GitHub Pages', re: /There isn't a GitHub Pages site here|For root URLs \(like http:\/\/example\.com\/\) you must provide an index/i },
  { name: 'Heroku', re: /No such app|herokucdn\.com\/error-pages\/no-such-app/i },
  { name: 'Fastly', re: /Fastly error: unknown domain/i },
  { name: 'Shopify', re: /Sorry, this shop is currently unavailable/i },
  { name: 'Netlify', re: /Not Found - Request ID|Site not found · Netlify/i },
  { name: 'Vercel', re: /The deployment could not be found|DEPLOYMENT_NOT_FOUND/i },
];

export function runTakeoverTemplate(ctx) {
  const body = ctx.body || '';
  for (const s of TAKEOVER_SIGNS) {
    if (s.re.test(body)) {
      return [{
        id: 'subdomain-takeover', name: `Possible subdomain takeover (${s.name})`, severity: 'high', cwe: 'CWE-350',
        tags: ['takeover', 'dns', 'exposure'],
        evidence: `The response looks like an unclaimed ${s.name} endpoint. A dangling DNS record pointing here can let an attacker host content on your domain.`,
        remediation: `Remove the dangling DNS record, or reclaim the ${s.name} resource it points to.`,
      }];
    }
  }
  return [];
}

// ── #6 Expanded exposure pack ───────────────────────────────────────────────
// Safe-active: single GET per path. Each has a body signature so a catch-all
// 200 (SPA index) does not false-positive.
const EXPOSURE_PATHS = [
  { path: '/.svn/entries', sig: /^\d+\s*$|dir\n|\bsvn:/, name: '.svn repository metadata', sev: 'high', cwe: 'CWE-538' },
  { path: '/.hg/requires', sig: /revlogv1|dotencode|store/i, name: '.hg (Mercurial) metadata', sev: 'high', cwe: 'CWE-538' },
  { path: '/web.config', sig: /<configuration|<system\.web/i, name: 'web.config exposed', sev: 'high', cwe: 'CWE-538' },
  { path: '/wp-config.php.bak', sig: /DB_PASSWORD|DB_NAME|define\s*\(/i, name: 'WordPress config backup', sev: 'critical', cwe: 'CWE-538' },
  { path: '/.env.production', sig: /=[^\n]+/, name: '.env.production exposed', sev: 'critical', cwe: 'CWE-538' },
  { path: '/.env.local', sig: /=[^\n]+/, name: '.env.local exposed', sev: 'critical', cwe: 'CWE-538' },
  { path: '/phpinfo.php', sig: /phpinfo\(\)|PHP Version|<title>phpinfo/i, name: 'phpinfo() exposed', sev: 'medium', cwe: 'CWE-200' },
  { path: '/actuator/env', sig: /"propertySources"|"activeProfiles"/i, name: 'Spring Actuator env exposed', sev: 'high', cwe: 'CWE-200' },
  { path: '/actuator/health', sig: /"status"\s*:\s*"UP"|"components"/i, name: 'Spring Actuator reachable', sev: 'low', cwe: 'CWE-200' },
  { path: '/swagger.json', sig: /"swagger"|"openapi"|"paths"\s*:/i, name: 'Swagger/OpenAPI spec exposed', sev: 'low', cwe: 'CWE-200' },
  { path: '/openapi.json', sig: /"openapi"\s*:|"paths"\s*:/i, name: 'OpenAPI spec exposed', sev: 'low', cwe: 'CWE-200' },
  { path: '/server-status', sig: /Apache Server Status|Server uptime/i, name: 'Apache server-status exposed', sev: 'medium', cwe: 'CWE-200' },
  { path: '/.aws/credentials', sig: /aws_access_key_id|aws_secret_access_key/i, name: 'AWS credentials file exposed', sev: 'critical', cwe: 'CWE-538' },
  { path: '/id_rsa', sig: /BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY/i, name: 'Private SSH key exposed', sev: 'critical', cwe: 'CWE-538' },
];

export async function runExposurePack(ctx) {
  const out = [];
  for (const e of EXPOSURE_PATHS) {
    const r = await ctx.probe(e.path);
    if (r && r.status === 200 && r.body && e.sig.test(r.body)) {
      out.push({
        id: 'exposure' + e.path.replace(/[^a-z0-9]+/gi, '-'), name: e.name, severity: e.sev, cwe: e.cwe,
        tags: ['exposure'],
        evidence: `${e.path} is publicly reachable and returned matching content.`,
        remediation: 'Block this path at the web server or remove the file. It should never be web-accessible.',
      });
    }
  }
  return out;
}

// ── #8 GraphQL introspection ────────────────────────────────────────────────
// Safe-active: one POST of a benign introspection query. A schema dump back
// means introspection is on in production, which leaks your whole API surface.
export async function runGraphqlTemplate(ctx) {
  const q = { query: '{__schema{queryType{name}}}' };
  for (const path of ['/graphql', '/api/graphql', '/v1/graphql']) {
    let r = null;
    try { r = await ctx.probePost ? await ctx.probePost(path, q) : null; } catch { r = null; }
    if (!r) continue;
    if (r.status === 200 && /"__schema"|"queryType"/.test(r.body || '')) {
      return [{
        id: 'graphql-introspection', name: 'GraphQL introspection enabled', severity: 'medium', cwe: 'CWE-200',
        tags: ['graphql', 'exposure', 'misconfig'],
        evidence: `${path} answered an introspection query, exposing your full GraphQL schema to anyone.`,
        remediation: 'Disable introspection in production so the schema is not public.',
      }];
    }
  }
  return [];
}

// ── #9 Deep CORS probe ──────────────────────────────────────────────────────
// Safe-active: send an evil Origin and see if the app reflects it. A reflected
// ACAO with credentials is exploitable; the wildcard-only check we had before
// misses reflected-origin, which is the common real bug.
export async function runCorsTemplate(ctx) {
  const evil = 'https://evil.example.com';
  let r = null;
  try { r = ctx.probeHeaders ? await ctx.probeHeaders('/', { Origin: evil }) : null; } catch { r = null; }
  if (!r || !r.headers) return [];
  const acao = r.headers['access-control-allow-origin'] || '';
  const acac = (r.headers['access-control-allow-credentials'] || '').toLowerCase();
  if (acao === evil || acao === 'null') {
    return [{
      id: 'cors-reflected-origin', name: 'CORS reflects arbitrary origin', severity: acac === 'true' ? 'high' : 'medium', cwe: 'CWE-942',
      tags: ['cors', 'misconfig'],
      evidence: `The server echoed an untrusted Origin (${acao}) in Access-Control-Allow-Origin` + (acac === 'true' ? ' with credentials allowed, so another site can read authenticated responses.' : '.'),
      remediation: 'Allow only an explicit allowlist of trusted origins; never reflect the request Origin, and never pair a reflected origin with Allow-Credentials.',
    }];
  }
  return [];
}

// ── #4 Open-redirect probe (ACTIVE) ─────────────────────────────────────────
// Safe-active: append a redirect param pointing at a benign external host and
// see if it lands in the Location header. No data touched.
export async function runOpenRedirectProbe(ctx) {
  const target = 'https://defen.so/redirect-canary';
  const params = ['next', 'url', 'redirect', 'return', 'returnTo', 'r', 'dest'];
  const base = ctx.url && ctx.url.origin ? ctx.url.origin : null;
  if (!base) return [];
  for (const p of params) {
    const probe = `/?${p}=${encodeURIComponent(target)}`;
    let r = null;
    try { r = ctx.probeRaw ? await ctx.probeRaw(probe) : null; } catch { r = null; }
    if (!r || !r.headers) continue;
    const loc = r.headers['location'] || '';
    if (r.status >= 300 && r.status < 400 && loc.includes('defen.so/redirect-canary')) {
      return [{
        id: 'open-redirect', name: 'Open redirect', severity: 'medium', cwe: 'CWE-601',
        tags: ['redirect', 'active'],
        evidence: `The "${p}" parameter redirected to an external URL we supplied (${loc}). Attackers use this for convincing phishing links on your domain.`,
        remediation: 'Validate redirect targets against an allowlist of internal paths; never redirect to a raw user-supplied URL.',
      }];
    }
  }
  return [];
}

// ── #5 Reflected-XSS canary (ACTIVE) ────────────────────────────────────────
// Safe-active: inject an inert marker and check it comes back unescaped. The
// marker is a harmless string, not an executing script.
export async function runReflectedXssProbe(ctx) {
  const marker = 'dfns7' + 'zx9q';
  const payload = `${marker}"'><dfns-x>`;
  for (const p of ['q', 's', 'search', 'query', 'name']) {
    const probe = `/?${p}=${encodeURIComponent(payload)}`;
    let r = null;
    try { r = ctx.probeRaw ? await ctx.probeRaw(probe) : null; } catch { r = null; }
    if (!r || !r.body) continue;
    // Unescaped reflection: our raw <dfns-x> tag came back, not entity-encoded.
    if (r.body.includes(`${marker}"'><dfns-x>`)) {
      return [{
        id: 'reflected-xss', name: 'Reflected input without output encoding', severity: 'high', cwe: 'CWE-79',
        tags: ['xss', 'active'],
        evidence: `The "${p}" parameter was reflected into the page without HTML-encoding, so a crafted value can inject markup. This is the pattern behind reflected XSS.`,
        remediation: 'HTML-encode all user input on output, and add a Content-Security-Policy that blocks inline scripts.',
      }];
    }
  }
  return [];
}
