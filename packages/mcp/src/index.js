#!/usr/bin/env node

/**
 * @defen.so/mcp — Defenso MCP server for AI assistants.
 *
 * Exposes Defenso's audit + protect tools to any MCP-speaking assistant
 * (Claude Code, Cursor, Windsurf, VS Code, codex). All tools call the Defenso
 * API at https://mcp.defen.so with an API key from env DEFENSO_TOKEN.
 *
 * Install (per-project):    npx -y @defen.so/mcp
 * Install (global):         npm i -g @defen.so/mcp
 *
 * Wire into ~/.claude/mcp.json:
 *   { "mcpServers": { "defenso": { "command": "npx", "args": ["-y", "@defen.so/mcp"],
 *     "env": { "DEFENSO_TOKEN": "df_live_..." } } } }
 *
 * Don't have a token yet? Run `npx -y @defen.so/mcp link` — opens a browser,
 * approve once, and the token is stored in ~/.defenso/config.json.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const API_BASE = process.env.DEFENSO_API || 'https://mcp.defen.so';
const API_PATH = process.env.DEFENSO_API_PATH || '/api/mcp';

/** Single source of truth for the version — read from package.json so the
 * server metadata and User-Agent never drift from the published package. */
function pkgVersion() {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8'));
    return pkg?.version || '0.0.0';
  } catch { return '0.0.0'; }
}
const VERSION = pkgVersion();

/** Load token from env, then ~/.defenso/config.json fallback. */
function loadToken() {
  if (process.env.DEFENSO_TOKEN) return process.env.DEFENSO_TOKEN;
  try {
    const cfg = JSON.parse(readFileSync(join(homedir(), '.defenso', 'config.json'), 'utf8'));
    return cfg?.token || '';
  } catch { return ''; }
}
const TOKEN = loadToken();

const server = new Server(
  { name: 'defen.so-mcp', version: VERSION },
  { capabilities: { tools: {} } }
);

/**
 * Tool descriptions include explicit `WHEN TO USE` guidance so the assistant
 * calls us only for things that need live data or authenticated writes.
 * For general security reasoning (explain a CVE, write a WAF rule from scratch)
 * the assistant should use its own model — cheaper for the user and for us.
 */
const TOOLS = [
  {
    name: 'scan_domain',
    annotations: { title: 'Scan a domain (pentest)', readOnlyHint: true },
    description: [
      'Run a live surface pentest against a URL: TLS, HSTS, CSP, cookie flags, exposed .env/.git/backup files, leaked Supabase/Firebase/S3 keys, security headers. Returns a graded A-F report.',
      '',
      'WORKS WITHOUT A TOKEN: with no DEFENSO_TOKEN it returns a free once-a-day teaser scan (grade + top findings) for any public URL — great for a first look. With a token + the site onboarded, it returns the full report saved to history.',
      '',
      'WHEN TO USE: user asks to "audit", "pentest", "scan", or "check the security of" a specific URL and needs fresh live data. This tool actually reaches the target.',
      'WHEN NOT TO USE: for general "how do I secure X" advice, answer with your own knowledge. If the user only wants headers, use check_headers (cheaper).',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'Full URL including scheme, e.g. https://example.com' },
      },
      required: ['url'],
    },
  },
  {
    name: 'check_headers',
    annotations: { title: 'Check security headers', readOnlyHint: true },
    description: [
      'Fetch a URL and return the response security-header set (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) plus server banner. Deterministic, ~1 second.',
      'WORKS WITHOUT A TOKEN: this is a public probe (anything curl can do), so it runs keyless — 20 checks/day per IP without a DEFENSO_TOKEN, 200/day with one.',
      '',
      'WHEN TO USE: user asks about the *current* security header state of a specific site. Faster and lighter than scan_domain.',
      'WHEN NOT TO USE: to explain what a header does — answer that from your own knowledge.',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: { url: { type: 'string' } },
      required: ['url'],
    },
  },
  {
    name: 'list_sites',
    annotations: { title: 'List your sites', readOnlyHint: true },
    description: [
      'List every site registered under the authenticated Defenso account, with plan, connection method, and CNAME status.',
      '',
      'WHEN TO USE: user asks "what sites do I have on defenso", "which sites are protected", or wants a summary of coverage. Requires a valid DEFENSO_TOKEN.',
    ].join('\n'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'list_monitors',
    annotations: { title: 'List uptime monitors', readOnlyHint: true },
    description: [
      'List every uptime monitor the calling account owns, with current status (up/down), last checked timestamp, and 24h uptime %.',
      '',
      'WHEN TO USE: user asks "are my sites up", "any monitors down", or wants current uptime state.',
    ].join('\n'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'list_recent_attacks',
    annotations: { title: 'List recent attacks', readOnlyHint: true },
    description: [
      'Return the most recent WAF and honeypot events from the last N hours, with rule, IP, path, action.',
      '',
      'WHEN TO USE: user asks "any attacks recently", "who\'s hitting my site", or is investigating an incident. Live data — the assistant cannot know this without calling us.',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        hours: { type: 'integer', description: 'How far back to look (default 24, max 168)', minimum: 1, maximum: 168 },
        limit: { type: 'integer', description: 'Max rows (default 20, max 100)', minimum: 1, maximum: 100 },
      },
    },
  },
  {
    name: 'list_recent_scans',
    annotations: { title: 'List recent scans', readOnlyHint: true },
    description: [
      'Return the user\'s recent pentest and repo/vibe scans from the last N days, with target, grade, and pass/warn/fail counts.',
      '',
      'WHEN TO USE: user asks "what did I scan recently", "show my last pentest", "history of my scans", or wants to compare a new scan against past results. Live account data.',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        days: { type: 'integer', description: 'How far back to look (default 7, max 90)', minimum: 1, maximum: 90 },
        kind: { type: 'string', description: 'Filter by scan kind', enum: ['pentest', 'vibe', 'all'] },
      },
    },
  },
  {
    name: 'explain_verdict',
    annotations: { title: 'Explain a WAF verdict', readOnlyHint: true },
    description: [
      'Given a Defenso attack-log verdict ID or rule ID, return the pattern, target, action, plan tier, and one-paragraph explanation with reproduction and mitigation.',
      '',
      'WHEN TO USE: user asks "why did rule XSS-1 fire", "explain this block", or references a specific verdict/rule ID. Preferred over guessing.',
      'WHEN NOT TO USE: for generic "what is XSS" answers — use your own knowledge.',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        verdict_id: { type: 'string', description: 'Attack log row ID or WAF rule ID (e.g. XSS-1, SQLi-3, HONEY)' },
      },
      required: ['verdict_id'],
    },
  },
  {
    name: 'scan_repo',
    annotations: { title: 'Scan a public repo', readOnlyHint: true },
    description: [
      'Scan a public GitHub repo for committed secrets, exposed .env / firebase-adminsdk / serviceAccountKey files, and other SAST-style leaks. Reads the default branch via GitHub raw-content endpoints — no clone, no auth needed.',
      '',
      'WHEN TO USE: user asks "is my repo leaking anything", "did we commit an .env", or is pointing at a specific repo URL on github.com, gitlab.com, or bitbucket.org. Also great before a public repo goes public.',
      'WHEN NOT TO USE: for the user\'s running website — use scan_domain instead. For a private repo — this endpoint has no token so it will get a 404.',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        repo_url: { type: 'string', description: 'Public repo URL on github.com, gitlab.com, or bitbucket.org' },
      },
      required: ['repo_url'],
    },
  },
  {
    name: 'run_vibe_scan',
    annotations: { title: 'Run a vibe-coder scan', readOnlyHint: true },
    description: [
      'Run a vibe-coder scan against a LIVE URL: exposed secrets in the served bundle, open S3 buckets, wide-open Supabase RLS / Firebase rules, and other misconfigurations vibe-coded apps ship by default. Pro-tier — plan-gated per site.',
      '',
      'WHEN TO USE: user asks "is my deployed app leaking anything", "scan my live site for exposed keys / open buckets", right after a deploy.',
      'WHEN NOT TO USE: for a GitHub repo (use scan_repo). For a general header/TLS grade (use scan_domain). Requires a token on a plan that includes vibe scans.',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        url: { type: 'string', description: 'The live URL to scan (e.g. https://myapp.com)' },
      },
      required: ['url'],
    },
  },
  {
    name: 'guard_code',
    annotations: { title: 'Guard a code snippet', readOnlyHint: true },
    description: [
      'Run a fast pattern check on a code snippet the user just wrote (or is about to write) and return security findings: server secrets on the client, hardcoded API keys, SQL concatenation, unbounded queries, missing input validation, unrate-limited auth routes, dynamic eval.',
      'WORKS WITHOUT A TOKEN: this is pure static analysis on code the caller already has — nothing leaves as account data — so it runs keyless (30 checks/day per IP without a DEFENSO_TOKEN, 500/day with one). Great for a first-touch security pass with zero signup.',
      '',
      'WHEN TO USE: after writing anything that touches auth, DB, env vars, request bodies, or is in a client-side file. Also whenever the user pastes a chunk of code and asks "is this safe?".',
      'WHEN NOT TO USE: as a substitute for a full pentest — this is heuristic, not exhaustive. Use scan_domain for the running app.',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'The code snippet to check (max 60000 chars)' },
        language: { type: 'string', description: 'Language hint (js, ts, py, php, go, rb, java)' },
        file_path: { type: 'string', description: 'Relative path of the file so we can tell client vs server (e.g. app/api/route.ts, src/pages/index.tsx)' },
      },
      required: ['code'],
    },
  },
  {
    name: 'get_security_preferences',
    annotations: { title: 'Read security preferences', readOnlyHint: true },
    description: [
      'Return the user\'s account-scoped security preferences. These are instructions the user wants YOU (the AI) to remember and honor every session — e.g. "never scan a production site without asking", "always block .env probes".',
      '',
      'WHEN TO USE: at the START of a new coding session, or before doing anything destructive/scan-related on a Defenso-protected site. Read once, apply throughout the session.',
      'WHEN NOT TO USE: for per-file or per-project settings — those live in the user\'s own repo config.',
    ].join('\n'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'set_security_preference',
    annotations: { title: 'Save a security preference', destructiveHint: true },
    description: [
      'Save a single security preference on the user\'s account so it persists across sessions and devices. Use short snake_case keys (e.g. never_scan_production_without_ask). Value is stored verbatim as JSON.',
      '',
      'WHEN TO USE: user says "remember that I never want you to X" or "always do Y before Z" in a security context. Confirm the key and value with the user before saving.',
      'WHEN NOT TO USE: for ephemeral session state — keep that in your own memory.',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        key: { type: 'string', description: 'Snake-case slug, e.g. never_scan_production_without_ask' },
        value: { description: 'Any JSON value (boolean, string, number, object, array, null)' },
      },
      required: ['key'],
    },
  },
  {
    name: 'check_s3_bucket',
    annotations: { title: 'Check an S3 bucket', readOnlyHint: true },
    description: [
      'Probe a public AWS S3 bucket for open ACLs. HEAD + anonymous ListBucket only — no AWS credentials required, no writes. Flags AllUsers / AuthenticatedUsers grants and whether the bucket allows anonymous listing. WORKS WITHOUT A TOKEN: keyless (15 probes/day per IP without a DEFENSO_TOKEN, 60/day with one).',
      '',
      'WHEN TO USE: user says "is my S3 bucket public", "check this bucket", or pastes a bucket URL. Also part of the vibe-audit runbook.',
      'WHEN NOT TO USE: for private buckets that require authentication — this endpoint has no AWS creds so it will just report "not reachable".',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        bucket: { type: 'string', description: 'Bucket name (3-63 chars, lowercase, hyphens allowed)' },
        region: { type: 'string', description: 'AWS region (default us-east-1)' },
      },
      required: ['bucket'],
    },
  },
  {
    name: 'list_cves',
    annotations: { title: 'List CVEs', readOnlyHint: true },
    description: [
      'Look up known CVEs affecting a package via osv.dev (Open Source Vulnerabilities). Returns the 30 most-recent vulnerabilities with severity, affected version ranges, and advisory URLs.',
      '',
      'WHEN TO USE: user asks "any CVEs in X", "is package Y safe", or you spot a dependency in code they just wrote. Also useful before recommending a package.',
      'WHEN NOT TO USE: for private/internal packages — osv.dev only knows about public ecosystems (npm, PyPI, Packagist, Go, RubyGems, crates.io, Maven, NuGet).',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        package: { type: 'string', description: 'Package name, e.g. "lodash" or "django"' },
        ecosystem: { type: 'string', enum: ['npm', 'PyPI', 'Packagist', 'Go', 'RubyGems', 'crates.io', 'Maven', 'NuGet'], description: 'Package ecosystem (default npm)' },
        version: { type: 'string', description: 'Optional exact version to filter to' },
      },
      required: ['package'],
    },
  },
  {
    name: 'add_waf_rule',
    annotations: { title: 'Add a WAF rule', destructiveHint: true },
    description: [
      'PRO TIER + DESTRUCTIVE-ADJACENT: create a custom WAF rule on the user\'s account. The rule joins the policy every Defenso SDK enforces, live within ~5 minutes. ALWAYS show the user the exact pattern, target and action and get an explicit yes before calling.',
      '',
      'WHEN TO USE: the user asks to block a specific attack pattern, path or payload across their sites ("block anything hitting /wp-admin", "block requests containing this payload").',
      'WHEN NOT TO USE: for blocking a single IP — use block_ip. For per-endpoint rate limits — those are endpoint rules in the dashboard.',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        pattern: { type: 'string', description: 'Regular expression the rule matches (case-insensitive), e.g. "/wp-admin" or "union\\\\s+select"' },
        target: { type: 'string', enum: ['url', 'body', 'headers', 'query'], description: 'Which part of the request the pattern runs against' },
        action: { type: 'string', enum: ['block', 'challenge', 'allow'], description: 'What happens on match' },
        category: { type: 'string', description: 'Optional short category slug, e.g. "custom" or "scanner"' },
        description: { type: 'string', description: 'Optional human note stored with the rule' },
      },
      required: ['pattern', 'target', 'action'],
    },
  },
  {
    name: 'block_ip',
    annotations: { title: 'Block an IP or ASN', destructiveHint: true },
    description: [
      'PRO TIER + DESTRUCTIVE-ADJACENT: block an IPv4/IPv6 address or CIDR range across the user\'s sites (or one site via site_id). Enforced by every SDK within ~5 minutes. ALWAYS confirm the exact IP/range with the user before calling — a wrong CIDR can block real users.',
      '',
      'WHEN TO USE: the user says "block this IP", typically after seeing it in list_recent_attacks.',
      'WHEN NOT TO USE: ASN-wide blocks (not supported yet — block the specific ranges), or attack patterns — use add_waf_rule for those.',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        ip_or_asn: { type: 'string', description: 'IPv4/IPv6 address or CIDR, e.g. "203.0.113.9" or "203.0.113.0/24"' },
        note: { type: 'string', description: 'Optional note about why this was blocked' },
        site_id: { type: 'string', description: 'Optional site nano ID to scope the block to one site; omit for all sites' },
      },
      required: ['ip_or_asn'],
    },
  },
  {
    name: 'pentest_status',
    annotations: { title: 'Check pentest status', readOnlyHint: true },
    description: [
      'Look up the status of a pentest run on the user\'s account. Without run_id, returns the most-recent scan across all sites. With run_id, returns that specific scan\'s state — useful for polling while a long scan runs.',
      '',
      'WHEN TO USE: user just kicked off a pentest and wants to know when it\'s done, or wants to see the last pentest verdict for their site.',
      'WHEN NOT TO USE: for the vibe scan history — use list_recent_scans with kind:"vibe" instead.',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        run_id: { type: 'integer', description: 'Optional pentest run ID. If omitted, returns the most recent scan.' },
      },
    },
  },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

/**
 * Turn a structured Defenso API error into a message the assistant can act on.
 * The API returns { error: <code>, message: <text>, fix_url?, sites_url?, onboard_url? }.
 * We flatten that into human-readable text with the actionable URL surfaced.
 */
function friendlyError(status, body) {
  let parsed;
  try { parsed = JSON.parse(body); } catch { parsed = null; }
  if (!parsed || typeof parsed !== 'object') {
    return `Defenso returned HTTP ${status}. Raw response: ${body.slice(0, 400)}`;
  }
  const bits = [];
  if (parsed.message) bits.push(parsed.message);
  else if (parsed.error) bits.push(parsed.error);
  else bits.push(`HTTP ${status}`);
  for (const key of ['fix_url', 'sites_url', 'onboard_url', 'upgrade_url', 'docs']) {
    if (parsed[key]) bits.push(`→ ${parsed[key]}`);
  }
  return bits.join('\n');
}

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;

  // Tools that need a real account (they read the user's sites/monitors/etc.)
  // still require a token. But scan_domain works keyless — the server returns a
  // free once-a-day teaser scan for any public URL — so we let it through even
  // with no token, and surface that value instead of a hard refusal.
  const KEYLESS_OK = new Set(['scan_domain', 'guard_code', 'check_headers', 'check_s3_bucket']);
  if (!TOKEN && !KEYLESS_OK.has(name)) {
    return {
      content: [{
        type: 'text',
        text: [
          `"${name}" needs a Defenso account. To connect:`,
          '  1. Run `npx -y @defen.so/mcp link` to connect this device via the browser (no paste).',
          '  2. Or set DEFENSO_TOKEN in your MCP client config (get one at https://app.defen.so/developer).',
          '',
          'Tip: `scan_domain` works right now with no token — it gives a free daily security preview of any public URL.',
        ].join('\n'),
      }],
      isError: true,
    };
  }

  try {
    const response = await fetch(`${API_BASE}${API_PATH}/${name}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TOKEN}`,
        'User-Agent': `@defen.so/mcp/${VERSION}`,
      },
      body: JSON.stringify(args ?? {}),
    });

    const body = await response.text();

    if (!response.ok) {
      return {
        content: [{ type: 'text', text: friendlyError(response.status, body) }],
        isError: true,
      };
    }

    return { content: [{ type: 'text', text: body }] };
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Could not reach Defenso (${err.message}). If this persists, https://app.defen.so/status shows realtime status.` }],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
