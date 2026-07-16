=== Defen.so Connector — WAF, uptime, upload scanning ===
Contributors: defenso
Tags: security, waf, firewall, brute force, malware, uptime monitor
Requires at least: 5.8
Tested up to: 6.5
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Official Defen.so connector. One-click connect: managed WAF, upload scan, uptime monitor, brute-force signal, attack log. No config file.

== Description ==

Defen.so is a developer-first web application security SaaS. This plugin connects your WordPress site to Defen.so in one click — no API key to paste, no config file.

**What it does at runtime**

* **Managed WAF** — blocks SQL injection, XSS, path traversal, bot scanners, mass assignment. 25 signatures + your custom rules from the Defen.so dashboard.
* **Upload scan** — polyglot detection, dangerous extension blocklist, MIME + magic-byte disagreement on every uploaded file.
* **Brute-force signal** — every failed `wp-login.php` attempt is queued to Defen.so so the dashboard shows what's hitting you.
* **Attack log** — every blocked / challenged / deceived event is shipped to your dashboard with full context (IP, ASN, matched rule, verdict).
* **Uptime monitor** — Defen.so checks this site's public URL from its edge on your plan's interval (15 min free / 1 min Pro / 30 sec Business).

**One-click connect**

Click "Connect to Defen.so". A popup opens at `app.defen.so`, you sign in (or sign up), authorize the connection, and the popup postMessages a scoped API key back — origin-locked to `app.defen.so` so no third party can intercept.

Fails-open: if Defen.so is unreachable at request time, the plugin allows the request and ships the log later.

Free forever tier available. Pro is $29/mo per site.

== Installation ==

1. Upload `defen-so-connector` to `/wp-content/plugins/`.
2. Activate through the "Plugins" menu.
3. You'll be redirected to the Defen.so setup page. Click "Connect to Defen.so" and follow the popup.

== Frequently Asked Questions ==

= Does the plugin slow down my site? =

No. The WAF check on `init` reads a locally-cached policy (10-min TTL, stale-while-revalidate) — no external HTTP call on the hot path. Attack logs ship in a batched, non-blocking `wp_remote_post` on `shutdown`.

= What happens if Defen.so is down? =

Fails open. The cached policy stays live for 24 h so protection continues even during an outage. If the cache is also gone, requests are allowed.

= Is my data safe? =

Only attack-log metadata leaves your site: method, URL path, IP, User-Agent, matched rule ID, action. No request bodies, no cookies, no PII.

= Can I self-host? =

Not today. The plugin is the SDK; the classifier, rule store, and dashboard live on Defen.so infra.

== Screenshots ==

1. One-click connect popup.
2. Connected dashboard with WAF rule count and event queue.
3. Live attack log on the Defen.so dashboard.

== Changelog ==

= 1.0.0 =
* Initial release. WAF, upload scan, brute-force signal, uptime monitor, attack log.
