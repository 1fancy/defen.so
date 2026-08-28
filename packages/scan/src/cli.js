#!/usr/bin/env node
/**
 * defenso-scan — fast, template-based web security scanner for the terminal & CI.
 *
 *   npx @defen.so/scan example.com
 *   npx @defen.so/scan https://example.com --json
 *   npx @defen.so/scan example.com --sarif > results.sarif
 *   npx @defen.so/scan example.com --fail-on high   # non-zero exit for CI
 *
 * Runs local checks (headers, cookies, exposed secrets, .env/.git files) and
 * augments with the Defenso hosted grade. No account needed to start.
 */
import { scan, VERSION } from './index.js';
import { toSarif } from './sarif.js';

const SEV_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const C = process.stdout.isTTY
  ? { r: '\x1b[31m', y: '\x1b[33m', g: '\x1b[32m', b: '\x1b[34m', dim: '\x1b[2m', bold: '\x1b[1m', x: '\x1b[0m', red: '\x1b[41m\x1b[97m', mag: '\x1b[35m' }
  : { r: '', y: '', g: '', b: '', dim: '', bold: '', x: '', red: '', mag: '' };

const SEV_COLOR = { critical: C.red, high: C.r, medium: C.y, low: C.b, info: C.dim };
const SEV_LABEL = { critical: 'CRIT', high: 'HIGH', medium: 'MED ', low: 'LOW ', info: 'INFO' };

function parseArgs(argv) {
  const o = { targets: [], json: false, sarif: false, paths: true, hosted: true, deep: true, active: false, crawl: 1, authHeaders: [], failOn: null, timeout: 12000, quiet: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') o.json = true;
    else if (a === '--sarif') o.sarif = true;
    else if (a === '--no-paths') o.paths = false;
    else if (a === '--no-deep') o.deep = false;
    else if (a === '--active') o.active = true;
    else if (a === '--crawl') o.crawl = Math.max(1, Math.min(20, parseInt(argv[++i], 10) || 5));
    else if (a === '--cookie') o.cookie = argv[++i];
    else if (a === '--basic') o.basic = argv[++i];
    else if (a === '--bearer') o.bearer = argv[++i];
    else if (a === '--auth-header') o.authHeaders.push(argv[++i]);
    else if (a === '--no-hosted' || a === '--offline') o.hosted = false;
    else if (a === '--quiet' || a === '-q') o.quiet = true;
    else if (a === '--fail-on') o.failOn = argv[++i];
    else if (a === '--timeout') o.timeout = parseInt(argv[++i], 10) || 12000;
    else if (a === '--version' || a === '-v') { console.log(VERSION); process.exit(0); }
    else if (a === '--help' || a === '-h') { help(); process.exit(0); }
    else if (a.startsWith('-')) { console.error(`Unknown flag: ${a}`); process.exit(2); }
    else o.targets.push(a);
  }
  return o;
}

function help() {
  console.log(`defenso-scan v${VERSION} — template-based web security scanner

USAGE
  npx @defen.so/scan <url> [url2 ...] [options]

OPTIONS
  --json             Output the full report as JSON
  --sarif            Output SARIF 2.1.0 (for GitHub code scanning / CI)
  --fail-on <sev>    Exit non-zero if a finding at or above <sev> exists
                     (info|low|medium|high|critical)
  --crawl <n>        Also scan up to n same-origin pages (default 1)
  --active           Run the safe active checks (error-based SQLi probe)
  --cookie <str>     Send a Cookie header (authenticated scan)
  --bearer <token>   Send Authorization: Bearer <token>
  --basic <u:p>      Send HTTP Basic auth
  --auth-header <h>  Add a raw request header "Name: value" (repeatable)
  --no-paths         Skip probing sensitive files (.env/.git/…)
  --no-deep          Skip deep surface checks (security.txt, sourcemaps, listing)
  --offline          Local checks only; skip the Defenso hosted grade
  --timeout <ms>     Per-request timeout (default 12000)
  -q, --quiet        Only print findings (no banner/summary)
  -v, --version      Print version
  -h, --help         Show this help

EXAMPLES
  npx @defen.so/scan example.com
  npx @defen.so/scan example.com --crawl 10 --active
  npx @defen.so/scan example.com --cookie "session=abc123"   # behind login
  npx @defen.so/scan example.com --fail-on high
  npx @defen.so/scan example.com --sarif > results.sarif

  Set DEFENSO_TOKEN for the full hosted report (get one at
  https://app.defen.so/developer). Without it you still get local checks plus a
  free daily hosted grade.

Docs: https://defen.so/online-website-security-scanner`);
}

function printReport(report, o) {
  if (!o.quiet) {
    const gcolor = report.grade === 'F' ? C.red : report.grade === 'D' ? C.r : report.grade.startsWith('A') ? C.g : C.y;
    console.log(`\n${C.bold}defenso-scan${C.x} ${C.dim}v${report.version}${C.x}  ${C.bold}${report.url}${C.x}`);
    const extra = [];
    if (report.authenticated) extra.push('authenticated');
    if (report.tech && report.tech.length) extra.push(report.tech.join(', '));
    if (report.crawled && report.crawled.length) extra.push(`${report.crawled.length + 1} pages`);
    console.log(`${C.dim}${report.templatesRun} templates · ${report.status} · ${report.https ? 'https' : C.r + 'http (not encrypted)' + C.x}${extra.length ? ' · ' + extra.join(' · ') : ''}${C.x}`);
    console.log(`Grade ${gcolor}${C.bold} ${report.grade} ${C.x}   ` +
      `${C.red} ${report.counts.critical} crit ${C.x} ${C.r}${report.counts.high} high${C.x} ` +
      `${C.y}${report.counts.medium} med${C.x} ${C.b}${report.counts.low} low${C.x} ${C.dim}${report.counts.info} info${C.x}\n`);
  }

  if (!report.findings.length) {
    if (!o.quiet) console.log(`${C.g}✓ No issues matched. Clean at this depth.${C.x}\n`);
    return;
  }

  for (const f of report.findings) {
    const col = SEV_COLOR[f.severity] || '';
    console.log(`${col} ${SEV_LABEL[f.severity]} ${C.x} ${C.bold}${f.name}${C.x}` + (f.cwe ? ` ${C.dim}${f.cwe}${C.x}` : ''));
    console.log(`      ${f.evidence}`);
    if (f.remediation) console.log(`      ${C.g}fix${C.x} ${f.remediation}`);
    console.log('');
  }

  if (!o.quiet && report.hosted && report.hosted.grade) {
    console.log(`${C.mag}Defenso hosted grade:${C.x} ${report.hosted.grade}` +
      (report.hosted.url ? `  ${C.dim}full report: ${report.hosted.url}${C.x}` : ''));
    console.log('');
  }
}

function worstSeverity(findings) {
  return findings.reduce((w, f) => Math.max(w, SEV_ORDER[f.severity] ?? 0), -1);
}

async function main() {
  const o = parseArgs(process.argv.slice(2));
  if (!o.targets.length) { help(); process.exit(o.json || o.sarif ? 0 : 2); }

  const reports = [];
  for (const target of o.targets) {
    try {
      reports.push(await scan(target, {
        paths: o.paths, hosted: o.hosted, deep: o.deep, active: o.active, crawl: o.crawl,
        cookie: o.cookie, basic: o.basic, bearer: o.bearer, authHeaders: o.authHeaders, timeout: o.timeout,
      }));
    } catch (err) {
      reports.push({ tool: '@defen.so/scan', version: VERSION, url: target, error: err.message, findings: [], grade: '?', counts: {} });
    }
  }

  if (o.sarif) {
    // Merge all runs into one SARIF doc.
    const merged = toSarif({ ...reports[0], findings: reports.flatMap((r) => r.findings || []) });
    process.stdout.write(JSON.stringify(merged, null, 2) + '\n');
  } else if (o.json) {
    process.stdout.write(JSON.stringify(reports.length === 1 ? reports[0] : reports, null, 2) + '\n');
  } else {
    for (const r of reports) {
      if (r.error) { console.error(`${C.r}✗ ${r.url}: ${r.error}${C.x}`); continue; }
      printReport(r, o);
    }
  }

  if (o.failOn) {
    const threshold = SEV_ORDER[o.failOn];
    if (threshold === undefined) { console.error(`--fail-on: unknown severity "${o.failOn}"`); process.exit(2); }
    const worst = Math.max(...reports.map((r) => worstSeverity(r.findings || [])), -1);
    if (worst >= threshold) process.exit(1);
  }
  process.exit(0);
}

main();
