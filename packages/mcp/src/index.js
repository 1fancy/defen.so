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
