=== Defen.so Connector ===
Contributors: defenso
Tags: security, waf, firewall, malware scan, brute force, uptime monitor
Requires at least: 5.8
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.2.4
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Modern security kit for WordPress: malware scan, managed WAF & firewall, brute-force protection, uptime & SSL monitoring, and instant alerts — one-click connect.

== Description ==

**Modern security kit for developers &amp; vibe coders.** Scan your website, apps &amp; GitHub for vulnerabilities. Block attacks &amp; bad bots, rate-limit your APIs, monitor uptime, domain &amp; SSL expiry — all in one security platform. Scan &amp; pentest · Monitoring &amp; uptime · Instant alerts · API rate limits · 360° protection · MCP &amp; SDKs.

Defen.so is a developer-first web application security SaaS. This plugin gives your WordPress site real, local protection out of the box, and connects to Defen.so in one click for a managed cloud layer on top — no API key to paste, no config file.

**Works standalone — no account required**

You do not need a Defen.so account to use the plugin. These features run entirely on your own server, for free, with no sign-up and no limits:

* **Upload scanning** — every uploaded file is checked for dangerous extensions and polyglots (magic bytes that disagree with the declared type). Runs on every upload for everyone.
* **Login hardening** — per-IP brute-force rate limiting with adjustable attempt count + window, optional reCAPTCHA v3, optional TOTP 2FA.
* **Firewall-lite** — blocks known-bad scanner user-agents (sqlmap, nikto, wpscan, nuclei…) and common exploit request patterns (path traversal, LFI/RFI wrappers, code-in-querystring, wp-config &amp; dotfile probes).
* **WordPress hardening** — one-click toggles: block username enumeration (?author= and REST /users), hide the WP version, disable the theme/plugin file editor (DISALLOW_FILE_EDIT), disable XML-RPC, comment/pingback hardening, and security response headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, optional HSTS).
* **Geo-block** — reject requests from any list of countries.
* **Local malware scan** — heuristic sweep of your PHP/JS files for common webshell / obfuscation patterns.
* **File-integrity baseline** — snapshot your files and compare for changes.
* **Core-file checksum verification** — verifies WordPress core files against the official WordPress.org checksum manifest and flags any modified or missing core file.
* **Exposed-file check** — probes for publicly-reachable secrets (.env, .git, wp-config backups, database dumps, debug logs).
* **Activity log** — records the last 100 high-value admin actions locally.

**Better when connected (optional)**

Connecting a free Defen.so account adds the managed cloud layer — none of it takes anything away from the standalone features above:

* **Managed WAF** — blocks SQL injection, XSS, path traversal, bot scanners, mass assignment, using the rule set + custom rules from your Defen.so dashboard.
* **Attack log + uptime monitor** — blocked events (including upload blocks) streamed to your dashboard; edge uptime checks.
* **CVE vulnerability lookup** — checks your installed plugins/themes against the live CVE feed.

Paid plans (Pro $29/mo, Business $69/mo per site) increase the server-side quotas — monitor interval, log retention, custom-rule count, scan frequency — all of which run on Defen.so infrastructure, not by unlocking code in this plugin.

**One-click connect**

Click "Connect to Defen.so". A popup opens at `app.defen.so`, you sign in (or sign up), authorize the connection, and the popup postMessages a scoped API key back — origin-locked to `app.defen.so` so no third party can intercept.

Fails-open: if Defen.so is unreachable at request time, the plugin allows the request and ships the log later.

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

== External services ==

This plugin connects to external services. Here is exactly what is sent, when, and to whom.

**1. Defen.so API (app.defen.so)** — the plugin's core service.

* What it is: the managed WAF, uptime monitoring, and attack-log backend the plugin connects your site to.
* When data is sent: when you connect your site (one-time OAuth handshake), when the plugin refreshes its cached rule policy, and when a request is blocked/challenged/deceived (attack-log events are batched and sent on `shutdown`).
* What is sent: your scoped API token, your site URL, and per-event metadata — HTTP method, URL path, visitor IP, User-Agent, matched rule ID, and the action taken. No request bodies, no cookies, no personal content.
* Terms: https://defen.so/tos — Privacy: https://defen.so/privacy

**2. Google reCAPTCHA (google.com/recaptcha)** — optional, only if you enable login hardening with a reCAPTCHA site key.

* What it is: Google's bot-detection service, used to score login attempts on `wp-login.php`.
* When data is sent: only on the login page, and only if you have entered a reCAPTCHA site key in the plugin settings. If you leave it blank, no request is ever made to Google.
* What is sent: the reCAPTCHA token and the data Google's script collects from the login page (per Google's terms).
* Terms: https://policies.google.com/terms — Privacy: https://policies.google.com/privacy

**3. ip-api.com** — optional, only if you enable the geo-block feature.

* What it is: a free IP-to-country geolocation lookup, used to find the country of a visitor so the geo-block rule can allow or deny it.
* When data is sent: only when geo-block is enabled and a visitor's country is not already supplied by your host (e.g. Cloudflare's country header). The visitor's IP address is sent for the lookup.
* What is sent: the visitor's IP address only.
* Terms: https://ip-api.com/docs/legal — Privacy: https://ip-api.com/docs/legal

**4. api.wordpress.org** — only when you run the "Verify core files" check.

* What it is: the official WordPress.org checksums API, the same one WP-CLI uses to verify core-file integrity.
* When data is sent: only when you click "Verify core files" in the plugin. Nothing is sent automatically.
* What is sent: your WordPress version number and locale only — no site content, no personal data.
* Terms &amp; Privacy: https://wordpress.org/about/privacy/

== Screenshots ==

1. One-click connect popup.
2. Connected dashboard with WAF rule count and event queue.
3. Live attack log on the Defen.so dashboard.

== Changelog ==

= 1.2.4 =
* New: the admin screen is now organised into tabs — Overview, Firewall & hardening, Scans, Rate limits, Uptime & alerts, and Activity log — so every tool is one click away instead of one long scroll. The tab you were on is remembered across reloads.
* New **Rate limits** tab: the login brute-force limiter (attempts + window + optional reCAPTCHA) gets its own clear home, alongside a note about the managed per-endpoint / per-IP edge limits available when connected.
* New **Uptime & alerts** tab: everything the Defen.so cloud adds — multi-region uptime monitoring, SSL & domain-expiry checks, Slack / Discord / Telegram / email / webhook alerts, and the call-style Defenso Alerts mobile app — in one place.
* Improved: the Scans tab shows a small count badge when a scan has flagged something, so you can see at a glance whether anything needs attention.
* Housekeeping: aligned the internal version constant with the plugin header. No changes to any security module behaviour.

= 1.2.3 =
* Improved: the admin screen now uses clean in-page modals and toasts instead of the browser's blocking alert()/confirm() dialogs — disconnect and take-baseline confirmations, scan errors and save errors all look native.
* SEO: refreshed the plugin description and tags (malware scan, WAF & firewall, brute-force protection, uptime & SSL monitoring, instant alerts).
* No changes to any security module behaviour.

= 1.2.2 =
* Improved: **Upgrade** and **Open dashboard** buttons now deep-link straight to *this* site's page in your Defen.so dashboard (and its checkout), instead of the generic app home.
* Polish: unified the admin UI typeface with the WordPress admin (dropped the bundled monospace face).
* No changes to any security module behaviour.

= 1.2.1 =
* Compatibility: tested up to WordPress 6.8.
* Hardening: declare `Update URI: false` so a same-slug plugin can never hijack updates.
* Housekeeping: version + metadata alignment; no functional changes to security modules.

= 1.2.0 =
* New **Firewall-lite** (free, local): blocks known-bad scanner user-agents and common exploit request patterns (path traversal, LFI/RFI wrappers, code-in-querystring, wp-config &amp; dotfile probes) before they reach WordPress. Blocked hits show in your Defen.so dashboard when connected.
* New **WordPress hardening** panel (free, local): one-click toggles for username-enumeration blocking (?author= + REST /users), hide WP version, disable the theme/plugin file editor, disable XML-RPC, comment/pingback hardening, and security response headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, optional HSTS). Safe defaults on for new installs.
* New **Core-file checksum verification** (free, local): checks WordPress core files against the official WordPress.org checksum manifest and flags any modified or missing core file.
* New **Exposed-file check** (free, local): probes for publicly-reachable secrets (.env, .git, wp-config backups, DB dumps, debug logs).
* Added tasteful, dismissible admin promos for the optional Defen.so cloud upgrades — uptime monitoring, multi-channel alerts (Slack/Discord/Telegram/email/webhook), and the Defenso Alerts mobile app (call-style alarm). No local feature is gated behind them.
* Documented the api.wordpress.org checksum service in the External services section.

= 1.1.8 =
* Plugin URI updated to the plugin's page (previous URL now redirects).
* No functional changes from 1.1.7.


= 1.1.7 =
* All local tools (malware scan, file integrity, vulnerability listing UI, geo-block, login hardening, activity log) now render and work without connecting an account, per directory Guideline 5. Connection only adds the external Defen.so service (WAF policy, uptime, attack log, CVE lookups), documented per Guideline 6.
* Admin menu slug renamed from defen-so to defenso for a consistent unique prefix.

= 1.1.6 =
* Sanitize REQUEST_URI and QUERY_STRING with sanitize_text_field() on receipt; raw copies are used only for in-memory WAF pattern matching, never stored.

= 1.1.5 =
* Upload scanning (dangerous extensions + polyglot detection) now runs for everyone, always — it no longer required a connected account, since it's fully local.
* Sanitized the request path before it's stored in the local attack-log queue.
* Fixed the Plugin URI and readme Terms link; documented the optional ip-api.com geo-lookup service.

= 1.1.4 =
* Plugin Check: set an explicit version arg on the reCAPTCHA script enqueue (false, since Google hosts it) to silence the MissingVersion warning.

= 1.1.3 =
* Plugin Check cleanup: reCAPTCHA now loads via wp_enqueue_script; prefixed admin-view variables; trimmed tags to 5; documented the WAF's raw-input reads.

= 1.1.2 =
* Compatibility: tested up to WordPress 7.0.
* Housekeeping: shortened the plugin name so the text domain matches the slug.

= 1.1.1 =
* All in-plugin features (login hardening, geo-block, local malware scan, file-integrity, activity log) now work fully for everyone, with no account and no plan limits. Plan tiers only affect the optional server-side cloud services.
* Every AJAX handler now verifies a nonce; sanitized all request/server inputs.
* Documented external services (Defen.so API, optional Google reCAPTCHA) in the readme.

= 1.1.0 =
* Added login hardening, geo-block, file-integrity, activity log, and vulnerability + malware scanning modules.
* Cleaner admin page and connect flow.

= 1.0.0 =
* Initial release. WAF, upload scan, brute-force signal, uptime monitor, attack log.
