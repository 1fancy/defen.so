# Vibe-coder WAF rules

Rules that catch the specific mistakes AI-generated web apps ship to production. Every rule here fired at least once against a real Defen.so-monitored site in the past 90 days.

## What it catches

| Rule | Threat | MITRE ATT&CK |
|---|---|---|
| `probe.supabase.serviceroleleak` | Someone probing your JS bundle for `SUPABASE_SERVICE_KEY` | T1552.001, T1526 |
| `probe.firebase.rules` | Attackers checking `/database.rules.json` for wide-open Firebase | T1526 |
| `probe.aws.metadata` | SSRF payloads targeting `169.254.169.254` (AWS IMDS) | T1580 |
| `probe.gcp.metadata` | SSRF targeting GCP's `metadata.google.internal` | T1580 |

## Why "vibe-coder"?

Vibe-coded projects tend to ship the same small set of mistakes because AI assistants generate boilerplate that skips security defaults. This pack focuses on those exact patterns rather than trying to be a comprehensive OWASP replacement.

## Related

- [OWASP Top 10 pack](../owasp-top10/) — the standard classes of injection and misconfig.
- [Bot scanners pack](../bot-scanners/) — user-agent-based blocks for sqlmap, nikto, etc.
- [API abuse pack](../api-abuse/) — mass-assignment, GraphQL introspection.
