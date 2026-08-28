=== Security, Malware Scan, Firewall, Rate-limiting & Uptime Monitor with Alerts by Defen.so ===
Contributors: defenso
Tags: security, firewall, malware, uptime, waf
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.4.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Firewall, malware & file-change scanner, brute-force protection, rate limiting, plus free uptime + SSL monitoring — one-click connect, no API key.

== Description ==

**Everything you need to keep a WordPress site safe — in one plugin, most of it running locally for free.** Defen.so blocks attacks, scans for malware, watches your files for tampering, hardens the common holes hackers walk through, and — once you connect a free account — pings your site from outside so you know the second it goes down or your SSL is about to expire.

No API key to paste. No config file. Click **Connect to Defen.so**, sign in, and you're protected.

**▶ Get the free mobile app — Defenso Alerts:** https://play.google.com/store/apps/details?id=so.defen.alerts — a phone app that *rings you like a phone call*, an alarm that cuts through silent mode and Do Not Disturb, the moment your site goes down, gets attacked, or your SSL/domain is about to expire. Also on iOS. This is the feature people install the plugin for and then tell their friends about.

**Works standalone — no account required**

You do not need a Defen.so account to use the plugin. These run entirely on your own server, for free, with no sign-up and no limits:

* **Upload scanning** — every uploaded file is checked for dangerous extensions and polyglots (magic bytes that disagree with the declared type). Runs on every upload, for everyone.
* **Malware scan** — heuristic sweep of your PHP/JS files for common webshell and obfuscation patterns.
* **File-modification detection (new in 1.4.0)** — snapshots a trusted sha256 baseline of your files, then flags anything **added, changed, or removed** since. This is how you catch a hacked or injected file that a signature scanner would miss — a backdoor dropped into your theme, a modified `wp-config.php`, a plugin file that isn't the one you installed.
* **Continuous database scanning (new in 1.4.0)** — a weekly background sweep keeps your malware and vulnerability findings fresh automatically. No manual clicking; your results are never stale.
* **Background scan with a live progress bar (new in 1.4.0)** — the heavy scan runs on WP-Cron, not inside your admin request, so the dashboard never hangs. A progress bar tracks it and can't get stuck.
* **Path rate limiting** — throttle any URL slug or wildcard pattern on your own site (e.g. `/wp-login.php`, `/wp-json/*`, `/checkout*`) per client IP; excess requests get a `429` with a `Retry-After` header. Up to 3 rules run locally for free; connect a free account to add more.
* **Login / brute-force hardening** — per-IP login rate limiting with an adjustable attempt count and window, optional reCAPTCHA v3, optional TOTP 2FA.
* **Firewall-lite** — blocks known-bad scanner user-agents (sqlmap, nikto, wpscan, nuclei…) and common exploit request patterns (path traversal, LFI/RFI wrappers, code-in-querystring, wp-config and dotfile probes).
* **Core-file integrity check** — verifies WordPress core files against the official WordPress.org checksum manifest and flags any modified or missing core file.
* **Exposed-file check** — probes for publicly-reachable secrets (.env, .git, wp-config backups, database dumps, debug logs).
* **Activity log** — records the last 100 high-value admin actions locally.

**Common WordPress security holes we close**

Most WordPress compromises come through the same handful of doors. Defen.so shuts them with one-click toggles (safe defaults on for new installs):

* **Brute-force logins** — per-IP throttling and lockout on `wp-login.php` so credential-stuffing bots can't grind your passwords.
* **User enumeration** — blocks `?author=` scans and the REST `/users` endpoint that leak your usernames to attackers before they even try a password.
* **XML-RPC abuse** — disable `xmlrpc.php`, a favourite amplifier for brute-force and pingback DDoS.
* **Version fingerprinting** — hides your WordPress version so attackers can't cheaply match you to a known exploit.
* **The built-in file editor** — disables the theme/plugin editor (`DISALLOW_FILE_EDIT`) so a single stolen admin session can't paste a backdoor into your code.
* **Missing security headers** — sends X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and optional HSTS.
* **Geo-block** — reject requests from any list of countries.

**A green "Security active" badge in your toolbar (new in 1.4.0)**

A shield icon sits in the WordPress admin bar and turns green when your site is protected, with a one-click menu to **Scan**, **Reports & findings**, **File changes**, **Uptime**, and **Upgrade**. Security status is visible on every page, not buried in a settings screen.

**Uptime, SSL & domain-expiry monitoring — free once connected**

Uptime, SSL-expiry and domain-expiry checks have to run from *outside* your server — a plugin inside WordPress can't reliably tell whether your own site is reachable. So the moment you connect a free Defen.so account, external checks start running from Defen.so's servers, and you can route alerts to email, Slack, Telegram, Discord, a webhook, or the Defenso Alerts app. **This is free.** A paid subscription is how you support development — and it unlocks more: faster check intervals, more monitors, longer log retention, more scans, and custom WAF rules. Soft ask, honest deal: you never need to pay to stay protected.

**Better when connected (optional)**

Connecting a free Defen.so account adds a managed cloud layer on top — nothing above is taken away:

* **Managed WAF** — blocks SQL injection, XSS, path traversal, bot scanners and mass-assignment using the live rule set plus custom rules from your dashboard.
* **Attack log** — blocked events (including upload and rate-limit blocks) streamed to your dashboard in real time.
* **CVE vulnerability lookup** — checks your installed plugins and themes against the live CVE feed.

**For AI coding assistants — MCP server + Claude skill**

The Defen.so ecosystem goes past the browser. There's an **MCP server** (`@defen.so/mcp`) and a **Claude Code skill** so AI coding assistants — Claude Code, Cursor, Windsurf — can scan a site or repo, guard the code they're writing, and add WAF rules without leaving the editor. If you build with an AI pair-programmer, your security tooling lives where your code does.

**One-click connect**

Click "Connect to Defen.so". A popup opens at `app.defen.so`; you sign in (or sign up) and authorize. The popup postMessages a scoped API key back — origin-locked to `app.defen.so` so no third party can intercept it.

Fails open: if Defen.so is unreachable at request time, the plugin allows the request and ships the log later.

== Installation ==

1. Upload `defen-so-connector` to `/wp-content/plugins/`.
2. Activate through the "Plugins" menu.
3. You'll be redirected to the Defen.so setup page. Click "Connect to Defen.so" and follow the popup.
4. (Recommended) Install **Defenso Alerts** on your phone from Google Play (https://play.google.com/store/apps/details?id=so.defen.alerts) or the App Store and sign in with the same account to get alarm-style down alerts.

== Frequently Asked Questions ==

= Does the plugin slow down my site? =

No. The WAF check on `init` reads a locally-cached policy (10-min TTL, stale-while-revalidate) — no external HTTP call on the hot path. The heavy malware and file-integrity scan runs on WP-Cron in the background, not inside your admin request, so the dashboard never hangs. Attack logs ship in a batched, non-blocking request on `shutdown`.

= What is file-modification detection? =

Take a baseline once, and the plugin records a sha256 hash of every PHP/JS file in your site. From then on it can tell you exactly which files were **added, changed, or removed** since — the fastest way to spot a hacked or injected file, a modified core file, or a backdoor dropped into your theme. The weekly background scan re-checks this automatically.

= What happens if Defen.so is down? =

Fails open. The cached policy stays live for 24 h so protection continues even during an outage. If the cache is also gone, requests are allowed.

= Is my data safe? =

Only attack-log metadata leaves your site: method, URL path, IP, User-Agent, matched rule ID, action. No request bodies, no cookies, no PII.

= Do I need a Defen.so account? =

No — the firewall (WAF), WordPress hardening, brute-force protection, path rate limiting, malware scan, file-modification detection and core-file verification all run locally with no account. Connecting a free Defen.so account (one click, no API key to paste) adds the cloud layer: uptime & SSL monitoring, the live attack log, alert channels, CVE lookups, and the managed rule feed.

= Does the uptime monitor work without connecting an account? =

Uptime, SSL-expiry and domain-expiry monitoring must run from outside your server — a plugin inside WordPress can't reliably check whether your own site is reachable. So they become active once you connect the site to a Defen.so account, and the checks run from Defen.so's external servers. The local security features work with or without an account.

= How do I get alerted when my site goes down? =

Connect the site, then choose your channels: email, Slack, Telegram, Discord, webhook, or the free **Defenso Alerts** mobile app (iOS & Android), which rings a full-screen alarm — through silent mode and Do Not Disturb — the moment a site goes down, gets attacked, or an SSL/domain is near expiry. Get it on Google Play: https://play.google.com/store/apps/details?id=so.defen.alerts

= Can AI coding assistants use Defen.so? =

Yes. There's an MCP server (`@defen.so/mcp`) and a Claude Code skill, so Claude Code, Cursor and Windsurf can scan, guard code, and add WAF rules directly from the editor.

= Is this plugin free? =

Yes. The plugin and its local protection are free forever, and a free Defen.so account covers a connected site with uptime monitoring and a managed WAF. Paid plans support development and unlock more — more sites, longer retention, custom WAF rules, faster intervals — but you never need them to stay protected.

= Does it protect against SQL injection, XSS, and bad bots? =

Yes. The firewall inspects each request on `init` against a managed rule set and blocks common attacks — SQL injection, cross-site scripting (XSS), path traversal, and known bot/scanner signatures — before they reach your theme or plugins.

= Can I self-host? =

Not today. The plugin is the SDK; the classifier, rule store, and dashboard live on Defen.so infra.

= Will it conflict with Wordfence, Cloudflare, or another security plugin? =

No. Defen.so complements them — many sites run it alongside Cloudflare or another WAF for a second layer. It doesn't require DNS changes, doesn't take over `wp-login.php` or the REST API, and its checks are additive and fail open.

= Does it work with WooCommerce and multisite? =

Yes. It runs at the request level, so it protects WooCommerce stores and other plugins the same way. It activates per-site on multisite.

== External services ==

This plugin connects to external services. Here is exactly what is sent, when, and to whom.

**1. Defen.so API (app.defen.so)** — the plugin's core service.

* What it is: the managed WAF, uptime monitoring, and attack-log backend the plugin connects your site to.
* When data is sent: when you connect your site (one-time OAuth handshake), when the plugin refreshes its cached rule policy, when scan findings (including file-change diffs) are reported, and when a request is blocked/challenged/deceived (attack-log events are batched and sent on `shutdown`).
* What is sent: your scoped API token, your site URL, per-event metadata — HTTP method, URL path, visitor IP, User-Agent, matched rule ID, and the action taken — and scan finding summaries. No request bodies, no cookies, no personal content.
* Terms: https://defen.so/tos — Privacy: https://defen.so/privacy

**2. Google reCAPTCHA (google.com/recaptcha)** — optional, only if you enable login hardening with a reCAPTCHA site key.

* What it is: Google's bot-detection service, used to score login attempts on `wp-login.php`.
* When data is sent: only on the login page, and only if you have entered a reCAPTCHA site key. If you leave it blank, no request is ever made to Google.
* What is sent: the reCAPTCHA token and the data Google's script collects from the login page (per Google's terms).
* Terms: https://policies.google.com/terms — Privacy: https://policies.google.com/privacy

**3. ip-api.com** — optional, only if you enable the geo-block feature.

* What it is: a free IP-to-country geolocation lookup, used to find a visitor's country so the geo-block rule can allow or deny it.
* When data is sent: only when geo-block is enabled and a visitor's country is not already supplied by your host (e.g. Cloudflare's country header). The visitor's IP is sent for the lookup.
* What is sent: the visitor's IP address only.
* Terms: https://ip-api.com/docs/legal — Privacy: https://ip-api.com/docs/legal

**4. api.wordpress.org** — only when you run the "Verify core files" check.

* What it is: the official WordPress.org checksums API, the same one WP-CLI uses to verify core-file integrity.
* When data is sent: only when you click "Verify core files". Nothing is sent automatically.
* What is sent: your WordPress version number and locale only — no site content, no personal data.
* Terms & Privacy: https://wordpress.org/about/privacy/

== Screenshots ==

1. Defenso Alerts mobile app — when a connected site goes down, your phone rings with a full-screen alarm, through silent mode and Do Not Disturb, so you never miss an outage.
2. One-click connect popup.
3. Connected dashboard with WAF rule count and event queue.
4. Live attack log on the Defen.so dashboard.

== Changelog ==

= 1.4.1 =
* Clearer plugin name so the security features are easier to find. No functional changes.

= 1.4.0 =
* New: **file-modification detection** — take a trusted baseline, then flag any file that was added, changed, or removed since. Catches hacked, injected or tampered files (backdoors in a theme, a modified wp-config) that signature scanning alone misses. Findings sync to your Pentest tab when connected.
* New: **continuous database scanning** — a weekly background sweep keeps malware and vulnerability findings fresh automatically, with no manual clicking.
* New: **background scan with a live progress bar** — the heavy scan runs on WP-Cron, so the admin never hangs, and the progress bar can't get stuck.
* New: **green "Security active" toolbar badge** — a shield in the WordPress admin bar with quick access to Scan, Reports, File changes, Uptime and Upgrade.
* Improved: clearer messaging that uptime, SSL and domain-expiry monitoring is free once you connect an account, and that a paid subscription supports development and unlocks faster checks, more monitors and more scans.
* Docs: reordered screenshots to lead with the Defenso Alerts mobile app; documented the MCP server (@defen.so/mcp) and Claude Code skill for AI coding assistants.

= 1.3.3 =
* New: local Path rate limiting — throttle any slug or wildcard pattern on your own site by IP, entirely in the plugin. Up to 3 rules free; connect a free account to add more.
* i18n: added German (de_DE), Brazilian Portuguese (pt_BR) and Russian (ru_RU) translations; refreshed French and Spanish.

= 1.3.2 =
* Listing: clearer plugin name (Firewall, Malware Scan & Uptime Monitor) for search.
* Docs: expanded the FAQ (account requirement, how uptime monitoring works, down alerts, WooCommerce/multisite, coexisting with Cloudflare/Wordfence) and added a mobile-app screenshot showing the full-screen down alarm.

= 1.3.1 =
* Fix: removed the "Update URI" header, which is not permitted for plugins hosted on WordPress.org, so the release imports correctly.

= 1.3.0 =
* Compatibility: confirmed tested with WordPress 7.0. Maintenance release to refresh the WordPress.org listing.

= 1.2.9 =
* Listing: refreshed the plugin tags and short description so people searching WordPress.org for "security scanner", "malware scanner", "firewall" and "uptime monitor" can find it. No functional changes.

= 1.2.8 =
* Maintenance release: republish to WordPress.org (registry was serving an older build). No functional changes since 1.2.7.

= 1.2.7 =
* New: Spanish (es_ES) and French (fr_FR) translations — the admin screen is now fully localised, with the plugin loading its text domain from /languages.
* Every user-facing admin string is now translatable (translators can add more languages via the bundled .pot template).

= 1.2.6 =
* New: three screenshots on the plugin listing (Overview, Firewall & hardening, Uptime & alerts) so you can see the admin before installing.
* Fixed: stray HTML entities in the readme description and changelog now render as plain text.
* Cleaner links: the admin footer and rate-limit panel link straight to defen.so instead of a pricing page.
* Housekeeping: version constant aligned with the plugin header. No changes to any security module behaviour.

= 1.2.5 =
* SEO: refreshed the plugin description with the full feature list (managed WAF, upload scanning, login hardening, malware & file-integrity scans, core-file verification, live attack log).
* Housekeeping: aligned the internal version constant with the plugin header. No changes to any security module behaviour.

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
* New **Firewall-lite** (free, local): blocks known-bad scanner user-agents and common exploit request patterns (path traversal, LFI/RFI wrappers, code-in-querystring, wp-config & dotfile probes) before they reach WordPress. Blocked hits show in your Defen.so dashboard when connected.
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
