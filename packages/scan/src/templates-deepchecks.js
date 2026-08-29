/**
 * Deeper, nuclei-inspired checks that go past headers/TLS: version-to-CVE
 * fingerprinting, subdomain-takeover signals, an expanded exposure pack,
 * GraphQL introspection, a deep CORS probe, and safe-active probes for
 * open-redirect and reflected-XSS.
 *
 * The signature DATA (version rules, takeover fingerprints, exposure paths,
 * probe parameters) lives in ../templates/signatures.json — the single source
 * shared with the hosted PHP scanner, so a new signature is added once. This
 * file holds only the check LOGIC.
 *
 * Passive checks run always. Anything that sends a crafted parameter (marked
 * ACTIVE below) only runs when opts.active is set — it stays benign: an inert
 * marker, a harmless redirect target, or an already-public path. Nothing here
 * mutates data or tries default credentials.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const SIG = JSON.parse(
  readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'templates', 'signatures.json'), 'utf8')
);

function rx(re) { return new RegExp(re, 'i'); }

function cmp(a, b) {
  const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
  for (let i = 0; i < 3; i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d > 0 ? 1 : -1; }
  return 0;
}

// ── #1 Version → known-vulnerability fingerprint ────────────────────────────
// Passive: read a disclosed version from headers/body and flag it if the range
// is a known-bad one. Kept to high-signal, unambiguous cases so we never cry
// wolf on a patched build.
export function runVersionCveTemplates(ctx) {
  const out = [];
  const hay = (ctx.body || '') + ' ';
  for (const r of SIG.version_cves) {
    const src = r.part === 'server' ? (ctx.headers.server || '') : hay;
    const m = src.match(rx(r.re));
    if (m && m[1] && cmp(m[1], r.lt) < 0) {
      out.push({
        id: r.id, name: r.name, severity: r.sev, cwe: r.cwe, tags: ['cve', 'version', 'outdated'],
        evidence: r.note.replace('{v}', m[1]),
        remediation: 'Upgrade to a patched version, or remove the version from the banner so it cannot be fingerprinted.',
      });
    }
  }
  return out;
}

// ── #2 Subdomain-takeover fingerprints ──────────────────────────────────────
// Safe-active: a plain GET of the root already gives us the body; a dangling
// CNAME shows a provider "not found" page. We match those provider signatures.
export function runTakeoverTemplate(ctx) {
  const body = ctx.body || '';
  for (const s of SIG.takeover) {
    if (rx(s.re).test(body)) {
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
export async function runExposurePack(ctx) {
  const out = [];
  for (const e of SIG.exposure_paths) {
    const r = await ctx.probe(e.path);
    if (r && r.status === 200 && r.body && rx(e.re).test(r.body)) {
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
  if (!ctx.probePost) { return []; }
  const q = { query: SIG.graphql.query };
  for (const path of SIG.graphql.paths) {
    let r = null;
    try { r = await ctx.probePost(path, q); } catch { r = null; }
    if (!r) { continue; }
    if (r.status === 200 && rx(SIG.graphql.match).test(r.body || '')) {
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
  const evil = SIG.cors.evil_origin;
  let r = null;
  try { r = ctx.probeHeaders ? await ctx.probeHeaders('/', { Origin: evil }) : null; } catch { r = null; }
  if (!r || !r.headers) { return []; }
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
  const target = SIG.open_redirect.canary;
  const host = target.replace(/^https?:\/\//, '');
  const base = ctx.url && ctx.url.origin ? ctx.url.origin : null;
  if (!base) { return []; }
  for (const p of SIG.open_redirect.params) {
    const probe = `/?${p}=${encodeURIComponent(target)}`;
    let r = null;
    try { r = ctx.probeRaw ? await ctx.probeRaw(probe) : null; } catch { r = null; }
    if (!r || !r.headers) { continue; }
    const loc = r.headers['location'] || '';
    if (r.status >= 300 && r.status < 400 && loc.includes(host)) {
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
  const marker = SIG.xss.marker;
  const payload = `${marker}"'><dfns-x>`;
  for (const p of SIG.xss.params) {
    const probe = `/?${p}=${encodeURIComponent(payload)}`;
    let r = null;
    try { r = ctx.probeRaw ? await ctx.probeRaw(probe) : null; } catch { r = null; }
    if (!r || !r.body) { continue; }
    if (r.body.includes(payload)) {
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
