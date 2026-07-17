# OWASP Top 10 WAF rules

Patterns covering [OWASP Top 10 (2021)](https://owasp.org/Top10/). Every rule ships with `mitre_attack`, `owasp`, and `cwe` mappings so you can cite them in compliance decks.

## Files

| File | Threat class | OWASP | MITRE ATT&CK | Rules |
|---|---|---|---|---|
| [`injection.yml`](./injection.yml) | SQL / NoSQL / command / template injection | A03:2021 | T1190, T1059 | 6 |
| [`xss.yml`](./xss.yml) | Reflected + stored + DOM XSS | A03:2021 | T1059.007 | 4 |
| [`traversal.yml`](./traversal.yml) | Path traversal + file probes (`.env`, `.git`, `wp-admin`) | A01:2021, A05:2021 | T1083, T1552.001, T1595.002 | 6 |

## Importing outside Defen.so

Every rule is a plain YAML entry with fields the [schema doc](../README.md) describes. Drop-in helpers:

- **nginx / OpenResty** — see [example-nginx.md](../../docs/example-nginx.md) for a Lua map that iterates rules.
- **Coraza (Go WAF)** — YAML converts to `.conf` via `waf-rules-to-coraza.js` (planned).
- **Envoy / ModSecurity** — the `pattern` field is PCRE and drops into ModSec `SecRule` blocks directly.
- **Cloudflare Workers / Deno** — `endpoint_rules` schema (`packages/sdk-node`) shows the runtime shape.

## Contributing a rule

See [../CONTRIBUTING.md](../../CONTRIBUTING.md). Short version: copy an existing rule as your template, add the MITRE mapping, open a PR.
