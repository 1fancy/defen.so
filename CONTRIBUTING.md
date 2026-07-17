# Contributing to Defen.so

Thanks for taking a look. This repo is the open-source half of Defen.so — the WAF rule packs, SDKs, MCP server, Cyber Skill, and WordPress plugin all live here under MIT. Everything you see is usable outside Defen.so's SaaS (see [`waf-rules/`](./waf-rules) for a set of production-tested rules you can drop into nginx / OpenResty / Coraza / your own middleware).

## What to contribute

We happily accept:

- **New WAF rules** — YAML in `waf-rules/{pack}/*.yml`. Each rule needs a `pattern`, `target`, `action`, and ideally `mitre_attack` / `owasp` / `cwe` mappings. See the [schema](./waf-rules/README.md).
- **Bugfixes in the SDKs** (`packages/sdk-node`, `sdk-php`, `sdk-python`, and 7 more).
- **MCP tools** — new safe read-only tools that surface security signal to AI assistants.
- **Skill improvements** — `packages/skill/SKILL.md`.
- **WordPress plugin** patches — `packages/wp-plugin/defen-so-connector/`.

We usually **don't** accept:

- Rebrandings (this is Defen.so — fork if you want to rebrand).
- Rules that duplicate existing ones (search first).
- New SDK languages we don't already ship (they need long-term maintenance we can't guarantee).

## How to contribute a WAF rule (5 steps)

1. **Search.** `git grep 'pattern-you-plan-to-add' waf-rules/` — don't duplicate.
2. **Add a YAML entry** in the right pack under `waf-rules/{pack}/`. Copy an existing rule as the template.
3. **Test the regex** against a real payload. `pcregrep -M -f your-rule.yml sample-request.txt` is a quick check.
4. **Add MITRE / OWASP / CWE mapping** if you know it. Not required but appreciated.
5. **Open a PR** with a one-line justification: "adds detection for `$X`, tested against `$Y`, doesn't false-positive on `$Z`."

CI lints every YAML file on PR — invalid regex or wrong action enum fails the build before a maintainer sees it.

## How to run the tests

```bash
# Node SDK
cd packages/sdk-node && npm test

# PHP SDK
cd packages/sdk-php && composer install && vendor/bin/phpunit

# MCP server
cd packages/mcp && npm test
```

## Development setup

```bash
git clone https://github.com/1fancy/defen.so
cd defen.so
# Every package is independent — install what you plan to touch.
```

The `waf-rules/` directory needs **zero** setup — it's plain YAML.

## Code of conduct

Be respectful, be curious, don't put people down for asking beginner questions. Full policy in [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

## Licence

MIT. By opening a PR you agree that your contribution is submitted under MIT.

## Contact

- Bug reports / feature requests: [GitHub Issues](https://github.com/1fancy/defen.so/issues)
- Security disclosure: **info@defen.so** — please don't open a public issue for a live 0-day.
- General chat: no Discord yet; join the marketing site's contact form on <https://defen.so> if you want to talk to a maintainer.
