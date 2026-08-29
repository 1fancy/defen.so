/**
 * Deeper templates — surface discovery, tech fingerprint, source-map leaks,
 * an active (safe) error-based SQLi probe, and more secret patterns. These need
 * extra fetches, so they are async and run after the base header/body checks.
 *
 * Everything here is passive or a single benign request — no destructive input,
 * no auth attacks. The SQLi probe only appends a quote and looks for a database
 * error string; it never tries to extract data.
 */

const EXTRA_SECRETS = [
  { id: 'openai-key', name: 'OpenAI API key', re: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/, sev: 'critical', cwe: 'CWE-798' },
  { id: 'anthropic-key', name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/, sev: 'critical', cwe: 'CWE-798' },
  { id: 'sendgrid-key', name: 'SendGrid API key', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/, sev: 'critical', cwe: 'CWE-798' },
  { id: 'twilio-sid', name: 'Twilio Account SID', re: /\bAC[a-f0-9]{32}\b/, sev: 'high', cwe: 'CWE-798' },
  { id: 'mailgun-key', name: 'Mailgun API key', re: /\bkey-[a-f0-9]{32}\b/, sev: 'high', cwe: 'CWE-798' },
  { id: 'firebase-config', name: 'Firebase config in page', re: /apiKey:\s*['"][A-Za-z0-9_-]{30,}['"]/, sev: 'low', cwe: 'CWE-200', note: 'Firebase web apiKey is public by design — verify your Security Rules are locked, not the key.' },
  { id: 'basic-auth-url', name: 'Credentials in URL', re: /https?:\/\/[^\/\s:'"]+:[^@\/\s'"]+@/, sev: 'high', cwe: 'CWE-522' },
];

/** Passive tech/framework fingerprint from headers + body markers. */
const TECH = [
  { name: 'WordPress', test: (ctx) => /wp-content|wp-includes/.test(ctx.body || '') },
  { name: 'Next.js', test: (ctx) => /__NEXT_DATA__|\/_next\//.test(ctx.body || '') },
  { name: 'Laravel', test: (ctx) => /laravel_session|XSRF-TOKEN/.test((ctx.setCookies || []).join(' ')) },
  { name: 'Nuxt', test: (ctx) => /__NUXT__/.test(ctx.body || '') },
  { name: 'React', test: (ctx) => /data-reactroot|react\.production/.test(ctx.body || '') },
  { name: 'PHP', test: (ctx) => /PHPSESSID/.test((ctx.setCookies || []).join(' ')) || /php/i.test(ctx.headers['x-powered-by'] || '') },
];

export function techFingerprint(ctx) {
  const hits = TECH.filter((t) => { try { return t.test(ctx); } catch { return false; } }).map((t) => t.name);
  return hits;
}

// Distinct checks contributed by this file: every extra-secret pattern, plus the
// four single-purpose probes (security.txt, directory-listing, source-map, SQLi).
// Tech fingerprint is metadata, not a finding, so it is not counted.
export const EXTRA_TEMPLATE_COUNT = EXTRA_SECRETS.length + 4;

export function runExtraSecretTemplates(ctx) {
  const out = [];
  if (!ctx.body) return out;
  for (const s of EXTRA_SECRETS) {
    const m = ctx.body.match(s.re);
    if (m) {
      out.push({
        id: s.id, name: `Exposed secret: ${s.name}`, severity: s.sev, cwe: s.cwe, tags: ['secret', 'exposure'],
        evidence: `Matched ${s.name} in the page source.` + (s.note ? ' ' + s.note : ''),
        remediation: 'Rotate the key and keep secrets server-side; never ship them in client-delivered code.',
      });
    }
  }
  return out;
}

/**
 * Surface + config checks that each need one extra fetch. ctx.probe(path)
 * returns { status, body } or null.
 */
export async function runSurfaceTemplates(ctx) {
  const out = [];

  // security.txt (RFC 9116) — its ABSENCE is an info finding.
  const sec = await ctx.probe('/.well-known/security.txt');
  const secRoot = sec && sec.status === 200 ? sec : await ctx.probe('/security.txt');
  if (!(secRoot && secRoot.status === 200 && /contact/i.test(secRoot.body || ''))) {
    out.push({ id: 'missing-security-txt', name: 'No security.txt', severity: 'info', cwe: 'CWE-200', tags: ['disclosure', 'policy'],
      evidence: 'No /.well-known/security.txt — researchers have no clear way to report a vulnerability.',
      remediation: 'Add /.well-known/security.txt (RFC 9116) with a Contact and Expires field.' });
  }

  // Directory listing enabled.
  for (const dir of ['/uploads/', '/assets/', '/files/', '/backup/']) {
    const r = await ctx.probe(dir);
    if (r && r.status === 200 && /Index of |<title>Directory listing/i.test(r.body || '')) {
      out.push({ id: 'directory-listing', name: `Directory listing enabled (${dir})`, severity: 'medium', cwe: 'CWE-548', tags: ['exposure', 'misconfig'],
        evidence: `${dir} returns an auto-generated directory index, exposing the file list.`,
        remediation: `Disable auto-indexing for ${dir} (e.g. "Options -Indexes" / "autoindex off").` });
      break;
    }
  }

  return out;
}

/** Source-map exposure — .map next to a referenced .js leaks original source. */
export async function runSourcemapTemplate(ctx) {
  const out = [];
  const m = (ctx.body || '').match(/src=["']([^"']+\.js)(?:\?[^"']*)?["']/i);
  if (!m) return out;
  let jsPath = m[1];
  if (jsPath.startsWith('//') || /^https?:/i.test(jsPath)) return out; // only same-origin relative
  if (!jsPath.startsWith('/')) jsPath = '/' + jsPath;
  const r = await ctx.probe(jsPath + '.map');
  if (r && r.status === 200 && /"sources"|"mappings"/.test(r.body || '')) {
    out.push({ id: 'sourcemap-exposed', name: 'Source map exposed', severity: 'low', cwe: 'CWE-540', tags: ['exposure', 'sourcemap'],
      evidence: `${jsPath}.map is publicly readable, exposing your original (pre-minified) source.`,
      remediation: 'Do not deploy .map files to production, or block them at the web server.' });
  }
  return out;
}

/**
 * Active but SAFE error-based SQLi probe: append a single quote to the first
 * same-origin link with a query param and look for a database error signature.
 * Never extracts data; a match = the app reflects raw DB errors.
 */
export async function runSqliProbe(ctx) {
  const out = [];
  const linkMatch = (ctx.body || '').match(/href=["']([^"']+\?[^"'#]*=[^"'#]+)["']/i);
  if (!linkMatch) return out;
  let path = linkMatch[1].replace(/&amp;/g, '&');
  if (/^https?:/i.test(path) || path.startsWith('//')) return out;
  if (!path.startsWith('/')) path = '/' + path;
  const r = await ctx.probe(path + "'");
  const sig = /(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite3::|Unclosed quotation mark|You have an error in your SQL)/i;
  if (r && sig.test(r.body || '')) {
    out.push({ id: 'sqli-error-reflected', name: 'Possible SQL injection (DB error reflected)', severity: 'high', cwe: 'CWE-89', tags: ['injection', 'active'],
      evidence: `Appending a single quote to a query parameter surfaced a raw database error — a strong SQL-injection signal.`,
      remediation: 'Use parameterized queries / prepared statements, and never render raw DB errors to users.' });
  }
  return out;
}
