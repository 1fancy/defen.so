# CLAUDE.md

Guidance for Claude Code and other AI assistants working in this repository.

## What this repository is

This is the public, open-source distribution for **Defen.so** — a developer-first security platform (web and app pentest, code and dependency scanning, secret detection, uptime monitoring, and a managed WAF). The hosted service lives at https://defen.so; this repo holds the client-side pieces developers install and run:

- **Language SDKs** — thin, fail-open guard clients for ten runtimes (`packages/sdk-node`, `sdk-python`, `sdk-php`, `sdk-go`, `sdk-ruby`, `sdk-java`, `sdk-rust`, `sdk-dotnet`, `sdk-bun`, `sdk-deno`).
- **CLI scanner** — `packages/scan`, a standalone template-driven scanner (SARIF and JSON output, CI fail-on gates).
- **Project init** — `packages/init`, the `@defen.so/init` one-command onboarding.
- **MCP server** — `packages/mcp`, a Model Context Protocol server exposing Defen.so tools to AI IDEs.
- **WordPress plugin** — `packages/wp-plugin`, the Defen.so Connector.
- **Agent skill** — `packages/skill`, a portable skill definition.
- **WAF rule packs** — `waf-rules/`, versioned rule sets in a portable format.

The hosted application, database, billing, and scan engine are **not** in this repository.

## Core principles

These are hard constraints. Preserve them in any change.

- **Fail open, always.** A client SDK must never take down the app it protects. If Defen.so is unreachable, times out, or errors, the request proceeds. Any code path that could block traffic on our failure is a bug.
- **No real exploitation.** Scanners and probes are passive or use inert, self-identifying markers (our own canary host, a benign marker tag). Never write code that extracts data, sends destructive HTTP methods, or performs an actual attack against a target.
- **Secrets never land in output.** Findings, logs, and reports must not echo back the credential values they detect — report the *kind* of secret and where it was found, not the secret itself. Never print or commit real tokens.
- **No incremental internal IDs.** Anything user-facing uses opaque public IDs, never raw database identifiers.

## Repository layout

```
packages/
  sdk-node/ sdk-python/ sdk-php/ ...   # one directory per language SDK
  scan/                               # CLI scanner (templates + engine)
  init/                               # @defen.so/init onboarding
  mcp/                                # MCP server for AI IDEs
  wp-plugin/                          # WordPress connector
  skill/                              # portable agent skill
waf-rules/                            # versioned WAF rule packs
README.md                             # the developer-facing overview
```

Each package under `packages/` is self-contained and versioned independently. Read that package's own `README.md` and manifest (`package.json`, `composer.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`, `*.csproj`, `*.gemspec`, `pom.xml`) before changing it.

## Development commands

Commands depend on the package you are in. Determine the toolchain from the manifest, then use its conventions:

- **Node / Bun / Deno** (`sdk-node`, `sdk-bun`, `sdk-deno`, `scan`, `init`, `mcp`): `npm install`, `npm test`, `npm run build`.
- **Python** (`sdk-python`): install with the declared build backend, run `pytest`.
- **PHP** (`sdk-php`, `wp-plugin`): `composer install`, `composer test`.
- **Go** (`sdk-go`): `go build ./...`, `go test ./...`.
- **Ruby** (`sdk-ruby`): `bundle install`, `bundle exec rspec`.
- **Java** (`sdk-java`): `mvn verify`.
- **Rust** (`sdk-rust`): `cargo build`, `cargo test`.
- **.NET** (`sdk-dotnet`): `dotnet build`, `dotnet test`.

Run only the affected package's tests. Do not add a dependency or change a published version number unless the task explicitly calls for it.

## Architecture notes

- **SDKs are thin.** An SDK collects request signals, calls the Defen.so decision API, and enforces the verdict, with a short-lived local policy cache so it keeps working during a brief outage. Detection logic lives server-side; the SDK is the enforcement point. Keep added latency minimal.
- **The CLI scanner is template-driven.** Checks are declared as data (paths, regex signatures, severities), not hand-coded per check, so the hosted scanner and the CLI share one canonical signature set. When you touch a signature, keep the shared copy in sync and make sure every regex compiles.
- **The MCP server exposes a fixed tool set.** Some tools are keyless and IP-rate-limited; others require a `df_live_` token. Do not advertise a tool the server does not actually implement.

## Contributing rules for automated changes

- Every behavior change ships with a test in the same package, and that package's tests must pass before you finish.
- Match the surrounding code's style; do not reformat unrelated files.
- Do not add narration comments that explain our internal reasoning in shipped client code — keep comments minimal and technical.
- When in doubt about scope, prefer the smallest correct change.

## Links

- Website: https://defen.so
- App: https://app.defen.so
- MCP: https://mcp.defen.so
- Docs and the site descriptor for crawlers live on the website.
