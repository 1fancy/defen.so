#!/usr/bin/env node
/**
 * defenso — CLI companion to @defen.so/mcp.
 *
 * Subcommands:
 *   link     Device-code sign-in. Opens the browser, saves token.
 *   whoami   Show which Defenso account this token belongs to.
 *   sites    List sites on this account.
 *   status   Ping the Defenso edge (public health).
 *   logout   Delete the local token.
 *   help     Show this list.
 *   (no arg) Run the MCP server (stdio).
 */
import { mkdirSync, writeFileSync, readFileSync, chmodSync, unlinkSync, existsSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';

const API_BASE = process.env.DEFENSO_API || 'https://app.defen.so';
const CONFIG_DIR = join(homedir(), '.defenso');
const CONFIG_PATH = join(CONFIG_DIR, 'config.json');

function openBrowser(url) {
  const cmd = platform() === 'darwin' ? 'open' : platform() === 'win32' ? 'start' : 'xdg-open';
  try {
    spawn(cmd, [url], { detached: true, stdio: 'ignore' }).unref();
    return true;
  } catch {
    return false;
  }
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function saveToken(token) {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_PATH, JSON.stringify({ token, saved_at: new Date().toISOString() }, null, 2));
  chmodSync(CONFIG_PATH, 0o600);
}

function loadToken() {
  if (process.env.DEFENSO_TOKEN) return process.env.DEFENSO_TOKEN;
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'))?.token || '';
  } catch {
    return '';
  }
}

async function link() {
  const client = platform() + '-cli';
  const startRes = await fetch(API_BASE + '/link/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({ client }),
  });
  if (!startRes.ok) {
    console.error(`Could not start link flow: HTTP ${startRes.status}`);
    process.exit(1);
  }
  const { device_code, user_code, verification_uri, interval, expires_in } = await startRes.json();

  console.log('');
  console.log('  Defenso device link');
  console.log('  ───────────────────');
  console.log(`  Verification URL: ${verification_uri}`);
  console.log(`  Code:             ${user_code}`);
  console.log('  Waiting for approval in browser...');
  console.log('');

  const opened = openBrowser(verification_uri);
  if (!opened) {
    console.log(`  (Could not auto-open browser. Copy the URL above.)`);
  }

  const deadline = Date.now() + expires_in * 1000;
  while (Date.now() < deadline) {
    await sleep((interval || 5) * 1000);
    const pollRes = await fetch(API_BASE + '/link/poll', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ device_code }),
    });
    if (!pollRes.ok) continue;
    const data = await pollRes.json();
    if (data.status === 'approved' && data.api_key) {
      saveToken(data.api_key);
      console.log(`  Connected. Token saved to ${CONFIG_PATH}`);
      console.log(`  You can now run: defenso whoami`);
      return;
    }
    if (data.status === 'denied' || data.status === 'expired') {
      console.error(`  Link ${data.status}. Try again: defenso link`);
      process.exit(1);
    }
  }
  console.error('  Link timed out. Try again: defenso link');
  process.exit(1);
}

async function apiCall(path, opts = {}) {
  const token = loadToken();
  if (!token) {
    console.error('Not linked. Run: defenso link');
    process.exit(1);
  }
  return fetch(API_BASE + path, {
    ...opts,
    headers: {
      Accept: 'application/json',
      Authorization: 'Bearer ' + token,
      ...(opts.headers || {}),
    },
  });
}

async function whoami() {
  const r = await apiCall('/api/whoami');
  if (!r.ok) {
    console.error(`whoami failed: HTTP ${r.status}. Token may be invalid — try: defenso link`);
    process.exit(1);
  }
  const body = await r.json();
  console.log('');
  console.log(`  Signed in as ${body.email ?? '(unknown)'}`);
  if (body.name) console.log(`  Name: ${body.name}`);
  if (body.sites_count != null) console.log(`  Sites: ${body.sites_count}`);
  console.log('');
}

async function sites() {
  const r = await apiCall('/api/mcp/list_sites', { method: 'POST', body: JSON.stringify({}) });
  const body = await r.json();
  if (Array.isArray(body.sites) && body.sites.length === 0) {
    console.log('');
    console.log(`  No sites yet. Onboard your first at ${body.onboard_url || API_BASE + '/sites/create'}`);
    console.log('');
    return;
  }
  console.log('');
  for (const s of body.sites) {
    const badge = s.plan?.toUpperCase() || 'FREE';
    const verified = s.verified ? 'verified' : 'unverified';
    console.log(`  ${badge.padEnd(9)} ${s.name.padEnd(20)} ${s.host.padEnd(30)} (${s.connection}, ${verified})`);
  }
  console.log('');
}

async function status() {
  const r = await fetch(API_BASE + '/guard/health');
  console.log(await r.text());
}

async function logout() {
  if (existsSync(CONFIG_PATH)) {
    unlinkSync(CONFIG_PATH);
    console.log(`  Removed ${CONFIG_PATH}`);
  } else {
    console.log('  Not linked. Nothing to remove.');
  }
}

function help() {
  console.log(`
Usage: defenso <command>

Commands:
  link       Sign in via the browser. Saves an API key locally.
  whoami     Show which Defenso account is linked.
  sites      List sites registered on this account.
  status     Ping the public Defenso edge health.
  logout     Remove the local token.
  help       Show this list.

Env:
  DEFENSO_TOKEN   Skip the local config and use this token directly.
  DEFENSO_API     Override the API base (defaults to https://app.defen.so).

Without any command, the CLI starts the MCP stdio server so it can be
launched by an MCP-speaking client like Claude Code, Cursor, or Windsurf.
`);
}

const cmd = process.argv[2];
if (cmd === 'link') { await link(); }
else if (cmd === 'whoami') { await whoami(); }
else if (cmd === 'sites') { await sites(); }
else if (cmd === 'status') { await status(); }
else if (cmd === 'logout') { await logout(); }
else if (cmd === 'help' || cmd === '--help' || cmd === '-h') { help(); }
else { await import('./index.js'); }
