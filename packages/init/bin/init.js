#!/usr/bin/env node
/*
 * @defen.so/init — detect the project framework, install the SDK, wire
 * middleware, write DEFENSO_TOKEN to .env. One shot.
 *
 * Supported today:
 *   - Node: Next.js (app router + pages router), Express, Fastify
 *   - PHP:  Laravel, Symfony
 *   - Python: FastAPI, Django, Flask (stub — prints instructions)
 *
 * Unknown project → prints the manual install snippet and exits.
 * Everything is idempotent: re-running skips already-done steps.
 */

import { readFileSync, existsSync, writeFileSync, appendFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync, spawnSync } from 'node:child_process';

const cwd = process.cwd();
const has = (p) => existsSync(join(cwd, p));
const read = (p) => existsSync(join(cwd, p)) ? readFileSync(join(cwd, p), 'utf8') : '';

function log(msg) { process.stdout.write(msg + '\n'); }
function warn(msg) { process.stderr.write('  ! ' + msg + '\n'); }
function done(msg) { log('  ✓ ' + msg); }

/**
 * Claude-style ASCII hero. Colours only when writing to a real TTY that isn't
 * NO_COLOR — piped/CI output stays plain. Kept dependency-free (raw ANSI).
 */
function banner() {
  const tty = process.stdout.isTTY && !process.env.NO_COLOR;
  const c = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
  const ink = (s) => c('38;5;111', s);   // soft indigo, brand accent
  const bold = (s) => c('1;38;5;111', s);
  const dim = (s) => c('2', s);
  const cols = process.stdout.columns || 80;

  // Letters use ONLY solid full blocks (█) and spaces — every glyph is exactly
  // one monospace cell, so rows can't drift the way thin box-drawing chars do in
  // the user's terminal. Framed top/bottom with a rule, like a proper CLI.
  const wideArt = [
    '█████  ███████ ███████ ███████ ██   ██ ███████  █████ ',
    '██  ██ ██      ██      ██      ███  ██ ██      ██   ██',
    '██  ██ █████   █████   █████   ██ █ ██ ███████ ██   ██',
    '██  ██ ██      ██      ██      ██  ███      ██ ██   ██',
    '█████  ███████ ██      ███████ ██   ██ ███████  █████ ',
  ];
  const inner = 58; // characters between the │ borders
  const rule = '─'.repeat(inner);
  // Pad a plain (uncolored) string to the inner width, then colorize — so ANSI
  // codes never count toward the visible length and the right border stays flush.
  const rowLine = (plain, paint) => {
    const pad = Math.max(0, inner - plain.length);
    return '  ' + dim('│') + paint(plain) + ' '.repeat(pad) + dim('│');
  };

  if (cols >= inner + 4) {
    log('');
    log('  ' + dim('┌' + rule + '┐'));
    log(rowLine('', ink));
    for (const row of wideArt) { log(rowLine(' ' + row, ink)); }
    log(rowLine('', ink));
    log(rowLine('  Your security layer, shipped in 30 seconds.', dim));
    log('  ' + dim('└' + rule + '┘'));
    log('  ' + dim('pentest · repo scan · uptime · alerts') + '   ' + ink('https://defen.so'));
    log('');
  } else {
    const nInner = 24;
    const nRule = '─'.repeat(nInner);
    const nLine = (plain, paint) => '  ' + dim('│') + paint(plain) + ' '.repeat(Math.max(0, nInner - plain.length)) + dim('│');
    log('');
    log('  ' + dim('┌' + nRule + '┐'));
    log(nLine('  DEFEN.SO', bold));
    log(nLine('  security, shipped fast', dim));
    log('  ' + dim('└' + nRule + '┘'));
    log('  ' + dim('pentest · uptime · alerts'));
    log('');
  }
}

/**
 * `npx @defen.so/init skill` — install the Defenso skill into this project so
 * Claude Code / Cursor / Windsurf know what Defenso is (WAF, uptime, pentest,
 * repo-secret scanning, the MCP tools) and stop hesitating on our commands.
 * Writes the bundled SKILL.md into .claude/skills/defenso/ and .cursor/rules/.
 */
function installSkill() {
  const here = dirname(fileURLToPath(import.meta.url));
  const skillSrc = join(here, '..', 'skill', 'SKILL.md');
  if (!existsSync(skillSrc)) {
    warn('Bundled skill not found in this package. Reinstall @defen.so/init or see https://defen.so/mcp');
    process.exit(1);
  }
  const body = readFileSync(skillSrc, 'utf8');
  const targets = [
    join(cwd, '.claude', 'skills', 'defenso', 'SKILL.md'),
    join(cwd, '.cursor', 'rules', 'defenso.md'),
  ];
  log('');
  log('  Installing the Defenso skill');
  log('  ----------------------------');
  let wrote = 0;
  for (const target of targets) {
    try {
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, body);
      done(target.replace(cwd + '/', ''));
      wrote++;
    } catch (e) {
      warn(`Could not write ${target}: ${e.message}`);
    }
  }
  if (wrote > 0) {
    log('');
    log('  Done. Your AI editor now knows Defenso — restart it, then ask it to');
    log('  "add Defenso security to this app" or "scan my repo for leaked secrets".');
    log('');
  }
  process.exit(wrote > 0 ? 0 : 1);
}

banner();

if (process.argv[2] === 'skill') {
  installSkill();
}

function detect() {
  if (has('next.config.js') || has('next.config.mjs') || has('next.config.ts')) return 'next';
  if (has('package.json')) {
    try {
      const pkg = JSON.parse(read('package.json'));
      const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
      if (deps.next) return 'next';
      if (deps.fastify) return 'fastify';
      if (deps.express) return 'express';
    } catch {}
  }
  if (has('artisan') && has('composer.json')) return 'laravel';
  if (has('composer.json')) {
    try {
      const c = JSON.parse(read('composer.json'));
      if ((c.require && c.require['symfony/framework-bundle']) || has('symfony.lock')) return 'symfony';
    } catch {}
  }
  if (has('manage.py')) return 'django';
  if (has('main.py') || has('app.py')) {
    const src = read('main.py') || read('app.py');
    if (src.includes('FastAPI')) return 'fastapi';
    if (src.includes('Flask')) return 'flask';
  }
  return 'unknown';
}

function writeEnv() {
  const path = join(cwd, '.env');
  const cur = read('.env');
  if (cur.includes('DEFENSO_TOKEN=')) {
    done('.env already has DEFENSO_TOKEN — leaving as-is');
    return;
  }
  const line = '\nDEFENSO_TOKEN=df_live_replace_with_your_real_key\n';
  if (!existsSync(path)) writeFileSync(path, line.trimStart());
  else appendFileSync(path, line);
  done('.env stub added — replace df_live_replace_with_your_real_key with a key from https://app.defen.so/developer');
}

function run(cmd, args) {
  // On Windows, npm / composer / git are .cmd/.bat shims, not .exe files, so
  // spawnSync(cmd, ...) without a shell throws ENOENT. Run through a shell on
  // Windows so the PATHEXT resolution finds them.
  const r = spawnSync(cmd, args, {
    cwd,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  if (r.error) {
    warn(`Could not run ${cmd}. Is it installed and on your PATH?`);
    return false;
  }
  if (r.status !== 0) {
    warn(`${cmd} ${args.join(' ')} failed`);
    return false;
  }
  return true;
}

const framework = detect();
log(`  Detected framework: ${framework}`);
log('');

if (framework === 'unknown') {
  log('  Could not auto-detect your framework. Install manually:');
  log('    npm i @defen.so/sdk-node   (Node/Next/Express/Fastify/Bun/Deno)');
  log('    composer require defenso/sdk-php   (Laravel/Symfony)');
  log('    pip install defenso                 (Python)');
  log('');
  log('  Then wire the middleware per docs at https://defen.so/install');
  process.exit(0);
}

switch (framework) {
  case 'next': {
    if (!run('npm', ['i', '@defen.so/sdk-node'])) process.exit(1);
    const middlewarePath = join(cwd, 'middleware.ts');
    if (existsSync(middlewarePath) || existsSync(join(cwd, 'middleware.js'))) {
      warn('middleware file already exists — not overwriting. Add: `export { defensoNext as middleware } from "@defen.so/sdk-node/next"` yourself.');
    } else {
      writeFileSync(middlewarePath, `import { defensoNext } from '@defen.so/sdk-node/next';\nexport default defensoNext({ token: process.env.DEFENSO_TOKEN });\nexport const config = { matcher: '/((?!_next|api/health).*)' };\n`);
      done('middleware.ts written');
    }
    break;
  }
  case 'express':
  case 'fastify': {
    if (!run('npm', ['i', '@defen.so/sdk-node'])) process.exit(1);
    log(`  Add this line to your ${framework} app:`);
    log(framework === 'fastify'
      ? `    import { defensoFastify } from '@defen.so/sdk-node/fastify';\n    await app.register(defensoFastify, { token: process.env.DEFENSO_TOKEN });`
      : `    import { defenso } from '@defen.so/sdk-node';\n    app.use(defenso({ token: process.env.DEFENSO_TOKEN }));`);
    break;
  }
  case 'laravel': {
    if (!run('composer', ['require', 'defenso/sdk-php'])) {
      warn('composer require defenso/sdk-php did not resolve on this machine.');
      log('  Protect a PHP/Laravel app today — no code needed:');
      log('    1. Sign up at https://app.defen.so and add your site.');
      log('    2. Uptime monitoring + surface scans turn on immediately, zero code.');
      log('    3. On the Max plan you can also route traffic through the');
      log('       Defenso edge WAF via CNAME — full WAF with no code.');
      log('  (Laravel/Symfony SDK middleware install: https://defen.so/install)');
    } else {
      log('  Register the middleware in bootstrap/app.php:');
      log('    ->withMiddleware(function ($middleware) {');
      log('        $middleware->append(\\Defenso\\Middleware\\DefensoLaravelMiddleware::class);');
      log('    })');
    }
    break;
  }
  case 'symfony': {
    if (!run('composer', ['require', 'defenso/sdk-php'])) {
      warn('composer require defenso/sdk-php did not resolve on this machine.');
      log('  Protect a PHP/Symfony app today — no code needed:');
      log('    1. Sign up at https://app.defen.so and add your site.');
      log('    2. Uptime monitoring + surface scans turn on immediately, zero code.');
      log('    3. On the Max plan you can also route traffic through the');
      log('       Defenso edge WAF via CNAME — full WAF with no code.');
      log('  (Laravel/Symfony SDK middleware install: https://defen.so/install)');
    } else {
      log('  Register the listener in config/services.yaml:');
      log('    services:');
      log('      Defenso\\Middleware\\DefensoSymfonyListener:');
      log('        tags: [{ name: kernel.event_subscriber }]');
    }
    break;
  }
  case 'django':
  case 'flask':
  case 'fastapi': {
    log('  Install:');
    log('    pip install defenso');
    log('  Then follow https://defen.so/install#python for the framework-specific wiring.');
    break;
  }
}

writeEnv();
log('');
log('  Done. Sign in at https://app.defen.so and paste your API key into .env.');
log('  Docs: https://defen.so/install   Support: info@defen.so');
log('');
