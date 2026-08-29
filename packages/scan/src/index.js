/**
 * @defen.so/scan — programmatic API.
 *
 *   import { scan } from '@defen.so/scan';
 *   const report = await scan('https://example.com', { paths: true });
 *
 * Runs local template checks (headers, cookies, secrets, exposed files) and,
 * when a token or the hosted flag is set, augments with the Defenso hosted
 * grade. Returns a structured report; no process side-effects.
 */
import { runTemplates, runPathTemplates, TEMPLATE_COUNT } from './templates.js';
import { runExtraSecretTemplates, runSurfaceTemplates, runSourcemapTemplate, runSqliProbe, techFingerprint } from './templates-deep.js';
import { runVersionCveTemplates, runTakeoverTemplate, runExposurePack, runGraphqlTemplate, runCorsTemplate, runOpenRedirectProbe, runReflectedXssProbe } from './templates-deepchecks.js';

const VERSION = '0.3.0';
const UA = `@defen.so/scan/${VERSION}`;
const SEV_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function normalizeUrl(input) {
  let u = String(input || '').trim();
  if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
  return new URL(u);
}

function lowerHeaders(h) {
  const out = {};
  if (h && typeof h.forEach === 'function') {
    h.forEach((v, k) => { out[k.toLowerCase()] = v; });
  }
  return out;
}

async function fetchTarget(url, timeoutMs, authHeaders = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url.href, {
      method: 'GET',
      redirect: 'follow',
      headers: { 'User-Agent': UA, Accept: 'text/html,*/*', ...authHeaders },
      signal: ctrl.signal,
    });
    const body = await res.text().catch(() => '');
    // Node's fetch collapses duplicate Set-Cookie into getSetCookie().
    let setCookies = [];
    try { setCookies = res.headers.getSetCookie?.() || []; } catch { /* older node */ }
    if (!setCookies.length && res.headers.get('set-cookie')) setCookies = [res.headers.get('set-cookie')];
    return { status: res.status, headers: lowerHeaders(res.headers), body, setCookies, finalUrl: res.url };
  } finally {
    clearTimeout(t);
  }
}

/**
 * Flexible request for the deeper probes: pick the method, add headers, send a
 * JSON body, and optionally do NOT follow redirects (open-redirect needs the
 * raw Location). Always benign — the deep checks only send inert markers.
 */
async function fetchRaw(url, timeoutMs, { method = 'GET', headers = {}, json = null, follow = true } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url.href, {
      method,
      redirect: follow ? 'follow' : 'manual',
      headers: {
        'User-Agent': UA,
        Accept: json ? 'application/json,*/*' : 'text/html,*/*',
        ...(json ? { 'Content-Type': 'application/json' } : {}),
        ...headers,
      },
      body: json ? JSON.stringify(json) : undefined,
      signal: ctrl.signal,
    });
    const body = await res.text().catch(() => '');
    return { status: res.status, headers: lowerHeaders(res.headers), body: (body || '').slice(0, 8192) };
  } catch { return null; } finally { clearTimeout(t); }
}

/**
 * Ask the hosted Defenso scanner for a graded report (keyless daily teaser, or
 * full report with a token). Best-effort: returns null if unreachable so the
 * local scan still stands on its own.
 */
async function hostedGrade(url, { apiBase, token, timeoutMs }) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${apiBase}/api/mcp/scan_domain`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': UA,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({ url: url.href }),
      signal: ctrl.signal,
    });
    const text = await res.text();
    if (!res.ok) return null;
    try { return JSON.parse(text); } catch { return null; }
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

function grade(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  let g = 'A';
  if (counts.critical) g = 'F';
  else if (counts.high) g = 'D';
  else if (counts.medium >= 3) g = 'C';
  else if (counts.medium) g = 'B';
  else if (counts.low) g = 'A-';
  return { grade: g, counts };
}

/**
 * Scan a target URL. Options:
 *   paths     probe sensitive files (.env/.git/…). Default true.
 *   hosted    also request the Defenso hosted grade. Default true.
 *   token     DEFENSO_TOKEN for the full hosted report.
 *   apiBase   default https://app.defen.so
 *   timeout   ms per request (default 12000).
 * Returns { url, host, https, templatesRun, findings[], grade, counts, hosted }.
 */
export async function scan(input, opts = {}) {
  const url = normalizeUrl(input);
  const timeoutMs = opts.timeout ?? 12000;
  const apiBase = opts.apiBase || process.env.DEFENSO_API || 'https://app.defen.so';
  const token = opts.token || process.env.DEFENSO_TOKEN || null;

  // Authenticated-scan headers: --cookie, --auth-header "K: V", --basic user:pass.
  const authHeaders = buildAuthHeaders(opts);
  const authed = Object.keys(authHeaders).length > 0;

  const fetched = await fetchTarget(url, timeoutMs, authHeaders);
  const mkCtx = (u, f) => ({
    url: u, host: u.host, https: u.protocol === 'https:',
    status: f.status, headers: f.headers, body: f.body, setCookies: f.setCookies,
    probe: async (path) => {
      const p = new URL(path, u.origin);
      try {
        const r = await fetchTarget(p, Math.min(timeoutMs, 6000), authHeaders);
        return { status: r.status, body: (r.body || '').slice(0, 6144) };
      } catch { return null; }
    },
    // Deep-check probes: POST JSON, custom headers, and raw (no-redirect) GET.
    probePost: (path, json) => fetchRaw(new URL(path, u.origin), Math.min(timeoutMs, 6000), { method: 'POST', json, ...(authed ? { headers: authHeaders } : {}) }),
    probeHeaders: (path, headers) => fetchRaw(new URL(path, u.origin), Math.min(timeoutMs, 6000), { headers: { ...authHeaders, ...headers } }),
    probeRaw: (path) => fetchRaw(new URL(path, u.origin), Math.min(timeoutMs, 6000), { follow: false, ...(authed ? { headers: authHeaders } : {}) }),
  });
  const ctx = mkCtx(url, fetched);

  let findings = runTemplates(ctx).concat(runExtraSecretTemplates(ctx))
    .concat(runVersionCveTemplates(ctx), runTakeoverTemplate(ctx));
  const deep = opts.deep !== false;
  if (opts.paths !== false) findings = findings.concat(await runPathTemplates(ctx));
  if (deep) {
    findings = findings.concat(
      await runSurfaceTemplates(ctx),
      await runSourcemapTemplate(ctx),
      await runExposurePack(ctx),
      await runGraphqlTemplate(ctx),
      await runCorsTemplate(ctx),
    );
    if (opts.active) {
      findings = findings.concat(
        await runSqliProbe(ctx),
        await runOpenRedirectProbe(ctx),
        await runReflectedXssProbe(ctx),
      );
    }
  }
  const tech = techFingerprint(ctx);

  // Multi-page crawl: same-origin links, up to opts.crawl pages, run body/secret
  // templates on each (headers/paths only make sense on the root).
  const crawled = [];
  if (opts.crawl && opts.crawl > 1) {
    const links = extractSameOriginLinks(ctx.body, url).slice(0, opts.crawl - 1);
    for (const link of links) {
      try {
        const lf = await fetchTarget(new URL(link), Math.min(timeoutMs, 8000), authHeaders);
        const lctx = mkCtx(new URL(link), lf);
        const lfind = runTemplates(lctx).concat(runExtraSecretTemplates(lctx))
          .filter((f) => f.tags && (f.tags.includes('secret') || f.tags.includes('cookie')));
        for (const f of lfind) f.evidence = `[${link}] ${f.evidence}`;
        findings = findings.concat(lfind);
        crawled.push(link);
      } catch { /* skip unreachable */ }
    }
  }

  // Dedup by id (keep first/highest — already sorted after).
  const seen = new Set();
  findings = findings.filter((f) => { const k = f.id + '|' + (f.evidence || ''); if (seen.has(k)) return false; seen.add(k); return true; });
  findings.sort((a, b) => (SEV_ORDER[b.severity] - SEV_ORDER[a.severity]) || a.id.localeCompare(b.id));

  const g = grade(findings);
  let hosted = null;
  if (opts.hosted !== false) hosted = await hostedGrade(url, { apiBase, token, timeoutMs });

  return {
    tool: '@defen.so/scan', version: VERSION,
    url: url.href, host: url.host, https: ctx.https, status: fetched.status,
    authenticated: authed, tech, crawled,
    templatesRun: TEMPLATE_COUNT + 13,
    grade: g.grade, counts: g.counts, findings, hosted,
    scannedAt: new Date().toISOString(),
  };
}

function buildAuthHeaders(opts) {
  const h = {};
  if (opts.cookie) h['Cookie'] = opts.cookie;
  if (opts.basic) h['Authorization'] = 'Basic ' + Buffer.from(opts.basic).toString('base64');
  if (opts.bearer) h['Authorization'] = 'Bearer ' + opts.bearer;
  for (const raw of opts.authHeaders || []) {
    const i = raw.indexOf(':');
    if (i > 0) h[raw.slice(0, i).trim()] = raw.slice(i + 1).trim();
  }
  return h;
}

function extractSameOriginLinks(body, base) {
  const out = new Set();
  const re = /href=["']([^"'#]+)["']/gi;
  let m;
  while ((m = re.exec(body || '')) && out.size < 30) {
    try {
      const u = new URL(m[1], base);
      if (u.origin === base.origin && /^https?:/.test(u.protocol) && !/\.(png|jpe?g|svg|gif|css|js|woff2?|ico|pdf)$/i.test(u.pathname)) {
        out.add(u.href);
      }
    } catch { /* ignore bad href */ }
  }
  return [...out];
}

export { VERSION };
