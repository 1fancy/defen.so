# Defen.so Connector for WordPress

Official Defen.so connector. One-click connect to Defen.so, managed WAF, upload scan, uptime monitor, brute-force signal, attack log — installed in about 30 seconds.

## Quick install (developers)

```bash
cd /wp-content/plugins/
git clone --depth 1 https://github.com/1fancy/defen.so.git tmp
mv tmp/packages/wp-plugin/defen-so-connector .
rm -rf tmp
```

Activate from the WP admin. You'll be redirected to the setup wizard automatically.

## What connecting does

1. Opens a popup at `https://app.defen.so/oauth/wp-connect`.
2. You sign in (or sign up).
3. Defen.so mints a scoped API key just for this site, adds the site to your account (Free plan), and postMessages the key back to the plugin popup — origin-locked to `app.defen.so`.
4. The plugin persists the key, pulls the WAF policy in the background, and starts inspecting every request.

No key paste, no config file, no CLI.

## What the plugin does at runtime

| Hook | What runs |
|---|---|
| `init` (priority 1) | Pull cached WAF policy, evaluate rules against URL / query / body / headers. Block / challenge / deceive on match. Fails-open on any error. |
| `wp_handle_upload_prefilter` | Extension blocklist + MIME/magic-byte polyglot detection on every upload. |
| `wp_login_failed` | Queue a signal for the attack log so the dashboard shows brute-force patterns. |
| `shutdown` | Ship queued attack logs to Defen.so in a fire-and-forget POST (max 50/request). |

Admin dashboard widget shows active rules count + queued events. Full attack log + WAF rule management lives at [app.defen.so](https://app.defen.so).

## Files

```
defen-so-connector/
├── defen-so-connector.php   # Main plugin class
├── uninstall.php            # Options cleanup on delete
├── views/admin-page.php     # Setup + connected admin view
├── assets/css/admin.css
├── assets/js/admin.js       # Popup + postMessage handler
├── readme.txt               # WP plugin repo readme
└── README.md                # This file
```

## Distribution

Ships from the public `1fancy/defen.so` monorepo under `packages/wp-plugin/`. WP.org submission uses the same tree with `readme.txt` at the plugin root.

## License

GPLv2 or later.
