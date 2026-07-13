#!/usr/bin/env node
/**
 * defenso — CLI companion to @defen.so/mcp.
 * Subcommands: link, whoami, status, (no args → MCP server)
 */
import { mkdirSync, writeFileSync, readFileSync, chmodSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";

const API_BASE = process.env.DEFENSO_API || "https://app.defen.so";
const CONFIG_DIR = join(homedir(), ".defenso");
const CONFIG_PATH = join(CONFIG_DIR, "config.json");

function openBrowser(url) {
  const cmd = platform() === "darwin" ? "open" : platform() === "win32" ? "start" : "xdg-open";
  spawn(cmd, [url], { detached: true, stdio: "ignore" }).unref();
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function saveToken(token) {
  mkdirSync(CONFIG_DIR, { recursive: true });
  writeFileSync(CONFIG_PATH, JSON.stringify({ token, saved_at: new Date().toISOString() }, null, 2));
  chmodSync(CONFIG_PATH, 0o600);
}
async function link() {
  const client = platform() + "-cli";
  const startRes = await fetch(API_BASE + "/link/start", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ client }),
  });
  if (!startRes.ok) { console.error("Could not start link flow: HTTP " + startRes.status); process.exit(1); }
  const { device_code, user_code, verification_uri, interval, expires_in } = await startRes.json();
  console.log("
  Defenso device link
  --------------------");
  console.log("  Opening " + verification_uri + " in your browser...");
  console.log("  Code: " + user_code);
  console.log("  Waiting for approval...
");
  openBrowser(verification_uri);
  const deadline = Date.now() + expires_in * 1000;
  while (Date.now() < deadline) {
    await sleep((interval || 5) * 1000);
    const pollRes = await fetch(API_BASE + "/link/poll", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify({ device_code }),
    });
    if (!pollRes.ok) continue;
    const data = await pollRes.json();
    if (data.status === "approved" && data.api_key) {
      saveToken(data.api_key);
      console.log("  Connected. Token saved to " + CONFIG_PATH);
      return;
    }
    if (data.status === "denied" || data.status === "expired") { console.error("  Link " + data.status + ". Try again: defenso link"); process.exit(1); }
  }
  console.error("  Link timed out."); process.exit(1);
}
function loadToken() {
  if (process.env.DEFENSO_TOKEN) return process.env.DEFENSO_TOKEN;
  try { return JSON.parse(readFileSync(CONFIG_PATH, "utf8"))?.token || ""; } catch { return ""; }
}
async function whoami() {
  const token = loadToken();
  if (!token) { console.error("Not linked. Run: defenso link"); process.exit(1); }
  const r = await fetch(API_BASE + "/api/whoami", { headers: { Authorization: "Bearer " + token } });
  console.log(await r.text());
}
async function status() {
  const r = await fetch(API_BASE + "/guard/health");
  console.log(await r.text());
}
const cmd = process.argv[2];
if (cmd === "link") { await link(); }
else if (cmd === "whoami") { await whoami(); }
else if (cmd === "status") { await status(); }
else if (cmd === "help" || cmd === "--help" || cmd === "-h") {
  console.log("Usage: defenso <link|whoami|status|help>");
} else {
  await import("./index.js");
}
