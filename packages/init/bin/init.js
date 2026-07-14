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

import { readFileSync, existsSync, writeFileSync, appendFileSync } from 'node:fs';
import { join } from 'node:path';
import { execSync, spawnSync } from 'node:child_process';

const cwd = process.cwd();
const has = (p) => existsSync(join(cwd, p));
const read = (p) => existsSync(join(cwd, p)) ? readFileSync(join(cwd, p), 'utf8') : '';

function log(msg) { process.stdout.write(msg + '\n'); }
function warn(msg) { process.stderr.write('  ! ' + msg + '\n'); }
function done(msg) { log('  ✓ ' + msg); }

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
  const r = spawnSync(cmd, args, { cwd, stdio: 'inherit' });
  if (r.status !== 0) {
    warn(`${cmd} ${args.join(' ')} failed`);
    return false;
  }
  return true;
}

const framework = detect();
log('');
log('  Defenso init');
log('  ------------');
log(`  Detected: ${framework}`);
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
    if (!run('composer', ['require', 'defenso/sdk-php'])) process.exit(1);
    log('  Register the middleware in bootstrap/app.php:');
    log('    ->withMiddleware(function ($middleware) {');
    log('        $middleware->append(\\Defenso\\Laravel\\DefensoMiddleware::class);');
    log('    })');
    break;
  }
  case 'symfony': {
    if (!run('composer', ['require', 'defenso/sdk-php'])) process.exit(1);
    log('  Register the listener in config/services.yaml:');
    log('    services:');
    log('      Defenso\\Symfony\\DefensoListener:');
    log('        tags: [{ name: kernel.event_subscriber }]');
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
