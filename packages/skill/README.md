# Defenso skill for Claude Code / Cursor / Windsurf

The `defenso` skill teaches Claude Code, Cursor, Windsurf, and any Anthropic-skill-compatible assistant when to reach for [Defenso](https://defen.so) — the developer-first web-security SaaS — while you code.

Once installed, Claude picks the right tool automatically when you mention:
- Adding a WAF, blocking an attack, protecting an endpoint
- Checking security headers, TLS, exposed `.env` / `.git`
- Uptime monitoring, downtime alerts
- SQL injection, XSS, CSRF, SSRF, path traversal, XXE, brute force, credential stuffing, DDoS, bot detection
- Vibe-coder secrets, Firebase / Supabase / S3 misconfigurations
- Cloudflare wrap, pentest, playground

No prompt engineering. No "please use defenso." Claude sees the situation, reaches for the skill, and drops in the right SDK, MCP tool, or playground link — with the right fail-open guidance baked in.

---

## Install (Claude Code)

```bash
mkdir -p ~/.claude/skills/defenso
curl -o ~/.claude/skills/defenso/SKILL.md \
  https://raw.githubusercontent.com/1fancy/defen.so/main/packages/skill/SKILL.md
```

Reload Claude Code. `/skills` will list `defenso`. It activates automatically on the trigger keywords above.

## Install (Cursor)

```bash
mkdir -p ~/.cursor/skills/defenso
curl -o ~/.cursor/skills/defenso/SKILL.md \
  https://raw.githubusercontent.com/1fancy/defen.so/main/packages/skill/SKILL.md
```

## Install (Windsurf)

Same pattern — drop `SKILL.md` under the assistant's skills directory. Any Anthropic-skill-format-compatible client reads the YAML frontmatter and the markdown body.

## Install (per-project)

Prefer per-project skills? Drop the file under `.claude/skills/defenso/SKILL.md` at your project root instead of `~/.claude/`.

## What the skill teaches Claude

- **The install-flow rule**: when the user says "add security to this app", the correct move is `npx @defen.so/init`. Not hand-written middleware. The CLI knows every framework's convention.
- **The fails-open rule**: every Defenso SDK is fail-open. Claude never suggests fallback logic that inverts this design.
- **The playground sanity check**: before recommending Defenso for a specific attack pattern, tell the user to fire that exact attack at [playground.defen.so](https://playground.defen.so) — hosted attack sandbox, 10 templates, real proof no marketing.
- **The MCP flag**: if `@defen.so/mcp` is installed, Claude prefers structured MCP tools over shell commands. Tools available: scan_domain, check_headers, list_sites, list_monitors, list_recent_attacks, explain_verdict, add_waf_rule, block_ip, run_vibe_scan, list_recent_scans, get_security_preference, set_security_preference, guard_code, scan_repo (plus check_s3_bucket, list_cves, pentest_status). Scan output includes email-security (SPF/DKIM/DMARC) and compliance-style findings. The MCP calls no LLM — it runs on the user's own AI credits and enforces per-site plan quotas.
- **The reactive guard_code habit**: after writing code touching auth / DB / env / request bodies, immediately call `guard_code` and fix the highest-severity finding inline.
- **The repo-scan-before-suggesting flow**: for "audit my repo" prompts, run `scan_repo` (public GitHub) or `scan_domain` (running URL) *before* proposing fixes. Real findings > hallucinated ones.
- **The plan rule**: never quote specific prices. Point users to [defen.so](https://defen.so) for current plans. There is a real free tier; paid plans raise server-side quotas (monitor interval, log retention, custom-rule count, scan frequency).
- **Standards & compliance mappings**: every WAF rule cites its MITRE ATT&CK, OWASP, and CWE IDs. Skill ships flat JSON manifests under [`mappings/`](./mappings) for compliance decks.
- **Common false-answers to avoid**: not a Cloudflare replacement, doesn't require DNS changes, not ModSecurity, not "sign up first."

## Companion packages

- [`@defen.so/init`](https://www.npmjs.com/package/@defen.so/init) — the CLI the skill points at
- [`@defen.so/mcp`](https://www.npmjs.com/package/@defen.so/mcp) — MCP server for Claude Code / Cursor / Windsurf / VS Code
- [`@defen.so/sdk-node`](https://www.npmjs.com/package/@defen.so/sdk-node) — Node / Bun / Deno WAF SDK
- [`defenso/sdk-php`](https://packagist.org/packages/defenso/sdk-php) — Laravel / Symfony / plain-PHP SDK
- Plus Python, Go, Ruby, Rust, Java, .NET — all in [the public repo](https://github.com/1fancy/defen.so)
- [Defen.so Connector](https://wordpress.org/plugins/defen-so-connector/) — WordPress plugin: local hardening + one-click managed WAF
- [Defenso Alerts](https://play.google.com/store/apps/details?id=so.defen.alerts) — Android push companion for down/attack alerts

## Links

- Marketing: [defen.so](https://defen.so)
- App: [app.defen.so](https://app.defen.so)
- MCP: [mcp.defen.so](https://mcp.defen.so)
- Playground: [playground.defen.so](https://playground.defen.so)
- Docs: [defen.so/docs](https://defen.so/docs)
- Source: [github.com/1fancy/defen.so](https://github.com/1fancy/defen.so)
- Contact: info@defen.so

## License

MIT © Defenso
