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
import { join } from 'node:path';

const API_BASE = process.env.DEFENSO_API || 'https://mcp.defen.so';
const API_PATH = process.env.DEFENSO_API_PATH || '/api/mcp';

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
  { name: 'defen.so-mcp', version: '0.1.0' },
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
    description: [
      'Run a live surface pentest against a URL — TLS, HSTS, CSP, cookie flags, exposed .env/.git/backup files, security headers. Returns a graded A–F report with per-check evidence.',
      '',
      'WHEN TO USE: user asks to "audit", "pentest", "scan", or "check the security of" a specific URL and needs *fresh live data*. This tool actually reaches the target.',
      'WHEN NOT TO USE: for general "how do I secure X" advice, answer with your own knowledge — don\'t burn a scan quota. Also skip if the user only wants headers (use check_headers instead, it\'s cheaper).',
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
    description: [
      'Fetch a URL and return the response security-header set (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) plus server banner. Deterministic, ~1 second.',
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
    description: [
      'List every site registered under the authenticated Defenso account, with plan, connection method, and CNAME status.',
      '',
      'WHEN TO USE: user asks "what sites do I have on defenso", "which sites are protected", or wants a summary of coverage. Requires a valid DEFENSO_TOKEN.',
    ].join('\n'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'list_monitors',
    description: [
      'List every uptime monitor the calling account owns, with current status (up/down), last checked timestamp, and 24h uptime %.',
      '',
      'WHEN TO USE: user asks "are my sites up", "any monitors down", or wants current uptime state.',
    ].join('\n'),
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'list_recent_attacks',
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
    name: 'explain_verdict',
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
    description: [
      'Scan a public GitHub repo for committed secrets, exposed .env / firebase-adminsdk / serviceAccountKey files, and other SAST-style leaks. Reads the default branch via GitHub raw-content endpoints — no clone, no auth needed.',
      '',
      'WHEN TO USE: user asks "is my repo leaking anything", "did we commit an .env", or is pointing at a specific github.com/{org}/{repo} URL. Also great before a public repo goes public.',
      'WHEN NOT TO USE: for the user\'s running website — use scan_domain instead. For a private repo — this endpoint has no token so it will get a 404.',
    ].join('\n'),
    inputSchema: {
      type: 'object',
      properties: {
        repo_url: { type: 'string', description: 'https://github.com/{org}/{repo} — public repo only' },
      },
      required: ['repo_url'],
    },
  },
  {
    name: 'guard_code',
    description: [
      'Run a fast pattern check on a code snippet the user just wrote (or is about to write) and return security findings: server secrets on the client, hardcoded API keys, SQL concatenation, unbounded queries, missing input validation, unrate-limited auth routes, dynamic eval.',
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
    description: [
      'Probe a public AWS S3 bucket for open ACLs. HEAD + anonymous ListBucket only — no AWS credentials required, no writes. Flags AllUsers / AuthenticatedUsers grants and whether the bucket allows anonymous listing.',
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
    name: 'pentest_status',
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

  if (!TOKEN) {
    return {
      content: [{
        type: 'text',
        text: [
          'No Defenso token found. Two options:',
          '  1. Run `npx -y @defen.so/mcp link` to connect this device via the browser (no paste).',
          '  2. Set DEFENSO_TOKEN in your MCP client config (get one at https://app.defen.so/developer).',
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
        'User-Agent': '@defen.so/mcp/0.2.0',
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
