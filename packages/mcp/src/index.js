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
 *     "env": { "DEFENSO_TOKEN": "rk_live_..." } } } }
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

const TOOLS = [
  {
    name: 'scan_domain',
    description: 'Run a Defenso surface pentest on a URL: TLS, HSTS, CSP, cookie flags, exposed .env/.git, headers. Returns a graded report.',
    inputSchema: {
      type: 'object',
      properties: { url: { type: 'string', description: 'Full URL, e.g. https://example.com' } },
      required: ['url'],
    },
  },
  {
    name: 'check_headers',
    description: 'Fetch a URL and inspect security headers (HSTS, CSP, X-Frame-Options, Referrer-Policy). Faster than scan_domain.',
    inputSchema: {
      type: 'object',
      properties: { url: { type: 'string' } },
      required: ['url'],
    },
  },
  {
    name: 'list_monitors',
    description: 'List all uptime monitors for the authenticated Defenso account.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'explain_verdict',
    description: 'Explain a Defenso attack log verdict in plain language, with reproduction steps and mitigation.',
    inputSchema: {
      type: 'object',
      properties: { verdict_id: { type: 'string' } },
      required: ['verdict_id'],
    },
  },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;

  if (!TOKEN) {
    return {
      content: [{ type: 'text', text: 'No Defenso token found. Run `npx -y @defen.so/mcp link` to connect this device, or set DEFENSO_TOKEN.' }],
      isError: true,
    };
  }

  try {
    const response = await fetch(`${API_BASE}/${name}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${TOKEN}`,
        'User-Agent': '@defen.so/mcp/0.1.0',
      },
      body: JSON.stringify(args ?? {}),
    });

    const body = await response.text();

    if (!response.ok) {
      return {
        content: [{ type: 'text', text: `Defenso API error ${response.status}: ${body}` }],
        isError: true,
      };
    }

    return { content: [{ type: 'text', text: body }] };
  } catch (err) {
    return {
      content: [{ type: 'text', text: `Request failed: ${err.message}` }],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
