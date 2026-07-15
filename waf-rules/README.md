# Defen.so WAF rule packs

Community-maintainable YAML rules for the Defen.so managed WAF. Every pack
here is imported into production by the `defenso:sync-waf-rules` command
on the Defen.so backend. Users on Pro+ can also import individual packs
into their own account.

## Structure

```
waf-rules/
├── owasp-top10/     # OWASP Top 10 canonical patterns
├── vibe-coder/      # Mistakes vibe-coded projects tend to ship
├── api-abuse/       # API-specific abuse patterns (mass assignment, rate abuse)
└── bot-scanners/    # Known scanner UAs, TOR fingerprints, etc.
```

Each pack directory contains one or more `.yml` files. One file may
contain multiple rules (a YAML list at the top level).

## Rule schema

```yaml
- id: sqli.union
  category: sqli
  description: SQL UNION SELECT
  pattern: '\bunion\s+select\b'
  flags: i               # PCRE flags (default: empty)
  target: query          # url | query | body | headers
  action: block          # allow | block | challenge | deceive
  min_plan: scout        # scout | pro | business | agency (min plan to enable)
  priority: 100          # higher = evaluated earlier
  false_positive_notes: |
    Fires on any query string containing "UNION SELECT" — legitimate
    admin panels that expose raw SQL may need an allowlist.
```

## Contributing

Open a PR against `main`. CI runs `regex-lint` + a false-positive corpus
on every rule. Merged rules are synced to production within 24 h.

## Licensing

MIT. Rules are patterns, not code — free to fork and adapt. Attribution
appreciated but not required.

## Related

- Managed WAF docs: https://defen.so/features
- SDK repo: https://github.com/1fancy/defen.so
- Full site: https://defen.so
