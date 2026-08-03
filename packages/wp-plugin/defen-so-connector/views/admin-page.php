<?php
if (! defined('ABSPATH')) {
    exit;
}

$defenso_connected = (bool) get_option('defenso_api_token');
$defenso_connected_at = get_option('defenso_connected_at');
$defenso_plan_label = (string) get_option('defenso_plan_label', 'Free');
$defenso_verified = get_option('defenso_verified', '1') === '1';
$defenso_rules_count = is_array(get_option('defenso_policy_cache')) ? count(get_option('defenso_policy_cache')['rules'] ?? []) : 0;
$defenso_queue_count = is_array(get_option('defenso_attack_log_queue')) ? count(get_option('defenso_attack_log_queue')) : 0;
$defenso_refreshed_at = (int) get_option('defenso_policy_refreshed_at', 0);
$defenso_refreshed_ago = $defenso_refreshed_at ? human_time_diff($defenso_refreshed_at, time()).' ago' : '—';
$defenso_manage_url = (string) get_option('defenso_manage_url', '');
if ($defenso_manage_url === '' || strpos($defenso_manage_url, DEFENSO_APP_URL.'/sites/') !== 0) {
    $defenso_manage_url = DEFENSO_APP_URL.'/sites';
}

// Local tool state (used for the section bodies + the tab issue-count badges).
$defenso_malware_stats = get_option('defenso_malware_stats');
$defenso_integrity_baseline_at = (int) get_option('defenso_integrity_baseline_at', 0);
$defenso_integrity_last_diff = get_option('defenso_integrity_last_diff');
$defenso_core_result = get_option('defenso_core_checksum_result');
$defenso_exposed_result = get_option('defenso_exposed_files_result');
$defenso_geo_blocklist = (array) get_option('defenso_geo_blocklist', []);
$defenso_login_max = (int) get_option('defenso_login_max', 5);
$defenso_login_window = (int) get_option('defenso_login_window', 900);
$defenso_recaptcha_site = (string) get_option('defenso_recaptcha_site_key', '');
$defenso_recaptcha_secret = (string) get_option('defenso_recaptcha_secret_key', '');
$defenso_activity = array_slice((array) get_option('defenso_activity_log', []), 0, 10);

// Count of outstanding findings, used to badge the "Scans" tab so the owner
// sees at a glance whether anything needs attention.
$defenso_scan_issues = 0;
if (is_array($defenso_malware_stats)) {
    $defenso_scan_issues += (int) ($defenso_malware_stats['files_flagged'] ?? 0);
}
if (is_array($defenso_core_result) && isset($defenso_core_result['counts'])) {
    $defenso_scan_issues += (int) ($defenso_core_result['counts']['modified'] ?? 0) + (int) ($defenso_core_result['counts']['missing'] ?? 0);
}
if (is_array($defenso_exposed_result) && isset($defenso_exposed_result['exposed'])) {
    $defenso_scan_issues += count((array) $defenso_exposed_result['exposed']);
}

// Resolve the active tab from the URL (?page=defenso&tab=…). Client-side JS
// also restores the last tab from localStorage on a plain reload. Whitelist the
// slug so nothing user-supplied reaches an attribute unescaped.
$defenso_tabs = ['overview', 'firewall', 'scans', 'ratelimits', 'uptime', 'activity'];
// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only tab selector, no state change
$defenso_active_tab = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'overview';
if (! in_array($defenso_active_tab, $defenso_tabs, true)) {
    $defenso_active_tab = 'overview';
}

/**
 * Small helper: build the ?page=defenso&tab=X admin URL for a nav tab.
 */
$defenso_tab_url = static function (string $tab): string {
    return esc_url(admin_url('admin.php?page=defenso&tab='.$tab));
};
?>
<div class="wrap defenso-wrap">
    <div class="defenso-header">
        <div class="defenso-brand">
            <div class="defenso-logo"></div>
            <div>
                <h1 style="margin:0;font-size:22px;">Defen.so</h1>
                <p style="margin:2px 0 0;color:#6b7280;font-size:13px;">Firewall &middot; hardening &middot; malware &amp; core-file scan &middot; login hardening &middot; WAF &middot; uptime</p>
            </div>
        </div>
        <div class="defenso-status">
            <?php if ($defenso_connected) { ?>
                <span class="defenso-pill defenso-pill-ok">&#9679; Connected</span>
                <span id="defenso-verified-chip" class="defenso-pill <?php echo $defenso_verified ? 'defenso-pill-ok' : 'defenso-pill-warn'; ?>" style="margin-left:6px;">
                    <?php echo $defenso_verified ? '&#9679; Verified' : '&#9680; Not verified'; ?>
                </span>
                <span id="defenso-plan-badge" class="defenso-pill defenso-pill-ok" style="margin-left:6px;"><?php echo esc_html($defenso_plan_label); ?></span>
            <?php } else { ?>
                <span class="defenso-pill defenso-pill-warn">&#9680; Not connected</span>
            <?php } ?>
        </div>
    </div>

    <?php if (isset($_GET['connected']) && $_GET['connected'] === '1') { // phpcs:ignore WordPress.Security.NonceVerification.Recommended?>
        <div class="notice notice-success is-dismissible"><p><strong>Connected!</strong> Your site is now protected. WAF policy is being pulled in the background.</p></div>
    <?php } ?>

    <h2 class="nav-tab-wrapper defenso-tabs" id="defenso-tabs">
        <a href="<?php echo $defenso_tab_url('overview'); ?>" class="nav-tab defenso-tab<?php echo $defenso_active_tab === 'overview' ? ' nav-tab-active' : ''; ?>" data-tab="overview">Overview</a>
        <a href="<?php echo $defenso_tab_url('firewall'); ?>" class="nav-tab defenso-tab<?php echo $defenso_active_tab === 'firewall' ? ' nav-tab-active' : ''; ?>" data-tab="firewall">Firewall &amp; hardening</a>
        <a href="<?php echo $defenso_tab_url('scans'); ?>" class="nav-tab defenso-tab<?php echo $defenso_active_tab === 'scans' ? ' nav-tab-active' : ''; ?>" data-tab="scans">Scans<?php if ($defenso_scan_issues > 0) { ?><span class="defenso-tab-badge"><?php echo esc_html($defenso_scan_issues); ?></span><?php } ?></a>
        <a href="<?php echo $defenso_tab_url('ratelimits'); ?>" class="nav-tab defenso-tab<?php echo $defenso_active_tab === 'ratelimits' ? ' nav-tab-active' : ''; ?>" data-tab="ratelimits">Rate limits</a>
        <a href="<?php echo $defenso_tab_url('uptime'); ?>" class="nav-tab defenso-tab<?php echo $defenso_active_tab === 'uptime' ? ' nav-tab-active' : ''; ?>" data-tab="uptime">Uptime &amp; alerts</a>
        <a href="<?php echo $defenso_tab_url('activity'); ?>" class="nav-tab defenso-tab<?php echo $defenso_active_tab === 'activity' ? ' nav-tab-active' : ''; ?>" data-tab="activity">Activity log</a>
    </h2>

    <?php /* ============================ OVERVIEW ============================ */ ?>
    <div class="defenso-panel" data-panel="overview"<?php echo $defenso_active_tab === 'overview' ? '' : ' style="display:none;"'; ?>>
        <?php if (! $defenso_connected) { ?>
            <div class="defenso-card">
                <h2>Optional: connect the Defen.so service</h2>
                <p>Every security tool in the tabs above works locally, no account needed. Connecting adds the cloud service on top: the managed WAF policy, uptime monitoring from our edge, upload scanning, the attack-log dashboard and CVE lookups.</p>
                <p>
                    <button id="defenso-connect" class="button button-primary button-hero">Connect to Defen.so</button>
                    <a href="https://defen.so" target="_blank" class="button">What's Defen.so?</a>
                </p>
                <p class="description">The connector talks to the external Defen.so service (<a href="https://defen.so/tos" target="_blank">Terms</a> &middot; <a href="https://defen.so/privacy" target="_blank">Privacy</a>).</p>
            </div>
        <?php } else { ?>
            <div class="defenso-grid">
                <div class="defenso-card">
                    <p class="defenso-eyebrow">Live plan</p>
                    <p class="defenso-metric-small" id="defenso-plan-name"><?php echo esc_html($defenso_plan_label); ?></p>
                    <p class="description">
                        <a id="defenso-upgrade-link" href="<?php echo esc_url($defenso_manage_url.'/billing/checkout'); ?>" target="_blank">Upgrade &rarr;</a>
                    </p>
                </div>
                <div class="defenso-card">
                    <p class="defenso-eyebrow">WAF rules active</p>
                    <p class="defenso-metric"><?php echo esc_html($defenso_rules_count); ?></p>
                    <p class="description">refreshed <?php echo esc_html($defenso_refreshed_ago); ?></p>
                </div>
                <div class="defenso-card">
                    <p class="defenso-eyebrow">Queued events</p>
                    <p class="defenso-metric"><?php echo esc_html($defenso_queue_count); ?></p>
                    <p class="description">shipping in the next request</p>
                </div>
                <div class="defenso-card">
                    <p class="defenso-eyebrow">Connected</p>
                    <p class="defenso-metric-small"><?php echo esc_html($defenso_connected_at ? human_time_diff(strtotime($defenso_connected_at), time()).' ago' : '—'); ?></p>
                    <p class="description">key scoped to this site</p>
                </div>
            </div>
        <?php } ?>

        <?php // Vulnerability scan (service-backed CVE lookups) lives on Overview.?>
        <div class="defenso-card">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                <div>
                    <h3 style="margin:0;">Vulnerability scan <span style="font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:#a3a3a3;">&middot; Defen.so service</span></h3>
                    <p class="description" style="margin:4px 0 0;">Enumerates installed plugins &amp; themes with versions and checks them against known CVEs via the external Defen.so service (<a href="https://defen.so/tos" target="_blank">Terms</a> &middot; <a href="https://defen.so/privacy" target="_blank">Privacy</a>).</p>
                </div>
                <?php if ($defenso_connected) { ?>
                    <button id="defenso-vuln-scan" class="button button-primary">Scan now</button>
                <?php } else { ?>
                    <button type="button" class="button button-primary defenso-connect-alt">Connect to run</button>
                <?php } ?>
            </div>
            <div id="defenso-vuln-result"></div>
        </div>

        <?php if ($defenso_connected) { ?>
            <div class="defenso-card">
                <h3>Manage this site</h3>
                <p>The cloud side — attack log, WAF rules, alerts, monitors, plan — is managed from your Defen.so dashboard.</p>
                <p>
                    <a class="button button-primary" href="<?php echo esc_url($defenso_manage_url); ?>" target="_blank">Open Defen.so dashboard</a>
                    <a class="button" href="<?php echo esc_url(DEFENSO_APP_URL.'/developer'); ?>" target="_blank">Manage API keys</a>
                    <button id="defenso-disconnect" class="button-link" style="color:#b32d2e;margin-left:12px;">Disconnect this site</button>
                </p>
            </div>
        <?php } ?>
    </div>

    <?php /* ======================= FIREWALL & HARDENING ===================== */ ?>
    <div class="defenso-panel" data-panel="firewall"<?php echo $defenso_active_tab === 'firewall' ? '' : ' style="display:none;"'; ?>>
        <?php
        $defenso_hardening = class_exists('Defenso_Hardening') ? Defenso_Hardening::settings() : [];
$defenso_toggles = [
    'block_bad_bots' => ['Block bad bots &amp; scanners', 'Rejects sqlmap, nikto, wpscan, nuclei and other known scanner user-agents.'],
    'block_exploit_patterns' => ['Block exploit request patterns', 'Blocks path traversal, LFI/RFI wrappers, code-in-querystring, wp-config &amp; dotfile probes.'],
    'block_user_enum' => ['Block username enumeration', 'Stops ?author=N scans and the anonymous REST /users endpoint from leaking usernames.'],
    'security_headers' => ['Security response headers', 'Adds X-Frame-Options, X-Content-Type-Options and Referrer-Policy to every page.'],
    'hsts' => ['Strict-Transport-Security (HSTS)', 'Forces HTTPS for a year. Only enable once your whole site is on HTTPS.'],
    'remove_version' => ['Hide WordPress version', 'Removes the generator meta tag that advertises your exact WP version.'],
    'disable_file_edit' => ['Disable theme/plugin file editor', 'Sets DISALLOW_FILE_EDIT so a compromised admin can\'t edit code from wp-admin.'],
    'disable_xmlrpc' => ['Disable XML-RPC', 'Turns off xmlrpc.php entirely (blocks pingback DDoS &amp; brute-force amplification).'],
    'comment_hardening' => ['Comment / pingback hardening', 'Drops pingback methods and the X-Pingback header.'],
];
?>
        <div class="defenso-card">
            <h3 style="margin-top:0;">Firewall &amp; hardening <span style="font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:#a3a3a3;">&middot; runs locally, free</span></h3>
            <p class="description" style="margin:4px 0 14px;">Cheap, self-contained WordPress protections. Everything here runs in the plugin — no account needed.</p>
            <div class="defenso-toggle-grid">
                <?php foreach ($defenso_toggles as $defenso_key => $defenso_meta) { ?>
                    <label class="defenso-toggle">
                        <input type="checkbox" class="defenso-harden-cb" data-key="<?php echo esc_attr($defenso_key); ?>" <?php echo ! empty($defenso_hardening[$defenso_key]) ? 'checked' : ''; ?>>
                        <span>
                            <strong><?php echo wp_kses($defenso_meta[0], ['br' => []]); ?></strong>
                            <span class="description" style="display:block; margin-top:2px;"><?php echo wp_kses($defenso_meta[1], ['br' => []]); ?></span>
                        </span>
                    </label>
                <?php } ?>
            </div>
            <p style="margin-top:14px;">
                <button id="defenso-hardening-save" class="button button-primary">Save hardening settings</button>
                <span id="defenso-hardening-status" style="font-size:12px; color:#525252; margin-left:10px;"></span>
            </p>
        </div>

        <div class="defenso-card">
            <div>
                <h3 style="margin:0;">Geo-block</h3>
                <p class="description" style="margin:4px 0 12px;">Reject requests from selected countries (ISO 3166-1 alpha-2, comma-separated). Works locally for everyone.</p>
            </div>
            <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                <input id="defenso-geo-input" type="text" placeholder="e.g. RU, KP, IR" value="<?php echo esc_attr(implode(', ', $defenso_geo_blocklist)); ?>" style="min-width:260px; padding:8px 12px; font-family:Consolas, Monaco, monospace;">
                <button id="defenso-geo-save" class="button button-primary">Save blocklist</button>
                <span id="defenso-geo-status" style="font-size:12px; color:#525252;"></span>
            </div>
        </div>
    </div>

    <?php /* ============================== SCANS ============================= */ ?>
    <div class="defenso-panel" data-panel="scans"<?php echo $defenso_active_tab === 'scans' ? '' : ' style="display:none;"'; ?>>
        <div class="defenso-card">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                <div>
                    <h3 style="margin:0;">Malware scan</h3>
                    <p class="description" style="margin:4px 0 0;">
                        <?php if ($defenso_malware_stats) { ?>
                            Last scan: <?php echo esc_html(human_time_diff((int) $defenso_malware_stats['ran_at'], time()).' ago'); ?> &middot; <?php echo (int) $defenso_malware_stats['files_seen']; ?> files inspected &middot; <strong><?php echo (int) $defenso_malware_stats['files_flagged']; ?> flagged</strong>
                        <?php } else { ?>
                            Not run yet. Click Scan to run a local malware sweep.
                        <?php } ?>
                    </p>
                </div>
                <button id="defenso-malware-scan" class="button button-primary">Scan now</button>
            </div>
            <div id="defenso-malware-findings"></div>
        </div>

        <div class="defenso-card">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                <div>
                    <h3 style="margin:0;">File integrity</h3>
                    <p class="description" style="margin:4px 0 0;">
                        <?php if ($defenso_integrity_baseline_at) { ?>
                            Baseline: <?php echo esc_html(human_time_diff($defenso_integrity_baseline_at, time()).' ago'); ?>
                            <?php if (is_array($defenso_integrity_last_diff) && isset($defenso_integrity_last_diff['counts'])) { ?>
                                &middot; Last check flagged
                                <strong><?php echo (int) $defenso_integrity_last_diff['counts']['added']; ?></strong> new,
                                <strong><?php echo (int) $defenso_integrity_last_diff['counts']['changed']; ?></strong> changed,
                                <strong><?php echo (int) $defenso_integrity_last_diff['counts']['removed']; ?></strong> removed.
                            <?php } ?>
                        <?php } else { ?>
                            No baseline taken yet. Take one after a clean install / update.
                        <?php } ?>
                    </p>
                </div>
                <div>
                    <button id="defenso-integrity-baseline" class="button">Take baseline</button>
                    <button id="defenso-integrity-diff" class="button button-primary" <?php echo $defenso_integrity_baseline_at ? '' : 'disabled'; ?>>Check for changes</button>
                </div>
            </div>
            <div id="defenso-integrity-result"></div>
        </div>

        <div class="defenso-card">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                <div>
                    <h3 style="margin:0;">Core file &amp; exposure check <span style="font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:#a3a3a3;">&middot; free</span></h3>
                    <p class="description" style="margin:4px 0 0;">
                        Verifies WordPress core files against the official WordPress.org checksums, and probes for publicly-reachable secrets (.env, .git, config backups, DB dumps).
                        <?php if (is_array($defenso_core_result) && isset($defenso_core_result['counts'])) { ?>
                            <br>Last core check: <strong><?php echo (int) $defenso_core_result['counts']['modified']; ?></strong> modified, <strong><?php echo (int) $defenso_core_result['counts']['missing']; ?></strong> missing.
                        <?php } ?>
                        <?php if (is_array($defenso_exposed_result) && isset($defenso_exposed_result['exposed'])) { ?>
                            <br>Last exposure check: <strong><?php echo count((array) $defenso_exposed_result['exposed']); ?></strong> exposed.
                        <?php } ?>
                    </p>
                </div>
                <div>
                    <button id="defenso-core-checksum" class="button button-primary">Verify core files</button>
                    <button id="defenso-exposed-files" class="button">Check exposed files</button>
                </div>
            </div>
            <div id="defenso-core-result"></div>
        </div>
    </div>

    <?php /* =========================== RATE LIMITS ========================== */ ?>
    <div class="defenso-panel" data-panel="ratelimits"<?php echo $defenso_active_tab === 'ratelimits' ? '' : ' style="display:none;"'; ?>>
        <div class="defenso-card">
            <h3 style="margin-top:0;">Login rate limiting <span style="font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:#a3a3a3;">&middot; runs locally, free</span></h3>
            <p class="description" style="margin:4px 0 14px;">Per-IP brute-force protection on <code>wp-login.php</code>. Too many failed attempts inside the window locks that IP out until it cools down. Fully adjustable and runs entirely in the plugin.</p>
            <div style="display:grid; grid-template-columns:repeat(2, 1fr); gap:14px; margin-top:4px;">
                <div>
                    <p class="defenso-eyebrow">Max failed attempts</p>
                    <input id="defenso-login-max" type="number" min="1" max="50" value="<?php echo esc_attr($defenso_login_max); ?>" style="width:120px; padding:6px 10px;">
                </div>
                <div>
                    <p class="defenso-eyebrow">Window (seconds)</p>
                    <input id="defenso-login-window" type="number" min="60" max="86400" value="<?php echo esc_attr($defenso_login_window); ?>" style="width:120px; padding:6px 10px;">
                </div>
                <div>
                    <p class="defenso-eyebrow">reCAPTCHA v3 site key <span style="color:#a3a3a3;">(optional)</span></p>
                    <input id="defenso-recaptcha-site" type="text" value="<?php echo esc_attr($defenso_recaptcha_site); ?>" placeholder="6L…" style="width:100%; padding:6px 10px; font-family:Consolas, Monaco, monospace; font-size:11.5px;">
                </div>
                <div>
                    <p class="defenso-eyebrow">reCAPTCHA v3 secret key</p>
                    <input id="defenso-recaptcha-secret" type="password" value="<?php echo esc_attr($defenso_recaptcha_secret); ?>" placeholder="6L…" style="width:100%; padding:6px 10px; font-family:Consolas, Monaco, monospace; font-size:11.5px;">
                </div>
            </div>
            <p style="margin-top:14px;">
                <button id="defenso-login-save" class="button button-primary">Save rate-limit settings</button>
                <span id="defenso-login-status" style="font-size:12px; color:#525252; margin-left:10px;"></span>
            </p>
        </div>

        <div class="defenso-card">
            <h3 style="margin-top:0;">Managed edge rate limits <span style="font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:#a3a3a3;">&middot; Defen.so service</span></h3>
            <?php if ($defenso_connected) { ?>
                <p class="description" style="margin:4px 0 0;">Per-endpoint, per-IP and per-account velocity limits run on the Defen.so edge, ahead of WordPress. Configure them, and see what they blocked, from your dashboard.</p>
                <p style="margin-top:14px;"><a class="button button-primary" href="<?php echo esc_url($defenso_manage_url); ?>" target="_blank">Open rate-limit rules &rarr;</a></p>
            <?php } else { ?>
                <p class="description" style="margin:4px 0 0;">Connect a free Defen.so account to add per-endpoint, per-IP and per-account velocity limits at the edge, ahead of WordPress. Higher plans raise the limits and custom-rule count.</p>
                <p style="margin-top:14px;">
                    <button type="button" class="button button-primary defenso-connect-alt">Connect to enable</button>
                    <a class="button" href="https://defen.so/pricing" target="_blank" rel="noopener">See plans</a>
                </p>
            <?php } ?>
        </div>
    </div>

    <?php /* ========================= UPTIME & ALERTS ======================== */ ?>
    <div class="defenso-panel" data-panel="uptime"<?php echo $defenso_active_tab === 'uptime' ? '' : ' style="display:none;"'; ?>>
        <div class="defenso-card defenso-promo-card">
            <p class="defenso-eyebrow">Defen.so cloud &middot; optional</p>
            <h3 style="margin:0 0 6px;">Know the instant this site is in trouble</h3>
            <p class="description" style="margin:0 0 4px;">Uptime monitoring, SSL &amp; domain-expiry checks, and multi-channel alerts all run on the Defen.so edge — not in this plugin — so they keep working even if WordPress itself is down.</p>

            <div class="defenso-promo-item">
                <span class="defenso-promo-ico">&#9201;&#65039;</span>
                <div>
                    <strong>Uptime monitoring</strong>
                    <p class="description" style="margin:2px 0 0;">Checks from multiple regions; SSL &amp; domain-expiry alerts.
                        <a href="https://defen.so/website-apps-uptime-monitoring" target="_blank" rel="noopener">Learn more &rarr;</a></p>
                </div>
            </div>
            <div class="defenso-promo-item">
                <span class="defenso-promo-ico">&#128276;</span>
                <div>
                    <strong>Alerts everywhere</strong>
                    <p class="description" style="margin:2px 0 0;">Slack, Discord, Telegram, email &amp; webhooks the moment something breaks.</p>
                </div>
            </div>
            <div class="defenso-promo-item">
                <span class="defenso-promo-ico">&#128241;</span>
                <div>
                    <strong>Defenso Alerts app</strong>
                    <p class="description" style="margin:2px 0 0;">A call-style alarm on your phone for downtime &amp; attacks — it rings even on silent.
                        <a href="https://play.google.com/store/apps/details?id=so.defen.alerts" target="_blank" rel="noopener">Get it on Google Play &rarr;</a></p>
                </div>
            </div>

            <p style="margin:16px 0 0;">
                <?php if ($defenso_connected) { ?>
                    <a class="button button-primary" href="<?php echo esc_url($defenso_manage_url); ?>" target="_blank" rel="noopener">Set up monitoring &amp; alerts</a>
                <?php } else { ?>
                    <button type="button" class="button button-primary defenso-connect-alt">Connect a free account</button>
                <?php } ?>
                <a class="button" href="https://defen.so/website-monitor-app" target="_blank" rel="noopener">Explore the app</a>
            </p>
        </div>
    </div>

    <?php /* =========================== ACTIVITY LOG ========================= */ ?>
    <div class="defenso-panel" data-panel="activity"<?php echo $defenso_active_tab === 'activity' ? '' : ' style="display:none;"'; ?>>
        <div class="defenso-card">
            <h3 style="margin-top:0;">Recent activity</h3>
            <?php if (empty($defenso_activity)) { ?>
                <p class="description">No admin events yet. Login, plugin activate/deactivate, and role changes show up here.</p>
            <?php } else { ?>
                <table style="width:100%; margin-top:8px; border-collapse:separate; border-spacing:0 4px;">
                    <thead><tr>
                        <th style="text-align:left; font-size:10px; letter-spacing:.14em; text-transform:uppercase; color:#737373; padding:0 10px;">When</th>
                        <th style="text-align:left; font-size:10px; padding:0 10px;">Actor</th>
                        <th style="text-align:left; font-size:10px; padding:0 10px;">Event</th>
                    </tr></thead>
                    <tbody>
                        <?php foreach ($defenso_activity as $defenso_ev) { ?>
                            <tr>
                                <td style="padding:6px 10px; font-size:11.5px; color:#737373;"><?php echo esc_html(human_time_diff((int) $defenso_ev['at'], time()).' ago'); ?></td>
                                <td style="padding:6px 10px; font-size:11.5px; font-family:Consolas, Monaco, monospace;"><?php echo esc_html($defenso_ev['actor'] ?? '—'); ?></td>
                                <td style="padding:6px 10px; font-size:12px;"><?php echo esc_html($defenso_ev['summary'] ?? $defenso_ev['kind']); ?></td>
                            </tr>
                        <?php } ?>
                    </tbody>
                </table>
            <?php } ?>
        </div>
    </div>

    <?php
    // The Defen.so cloud upgrade content (uptime / alerts / mobile app) now
    // lives in the "Uptime & alerts" tab above. The dismissible promo notice
    // registered by Defenso_Promo still renders independently via admin_notices.
?>

    <p class="defenso-footer">
        <a href="https://defen.so/docs" target="_blank">Docs</a> &middot;
        <a href="https://defen.so/pricing" target="_blank">Pricing</a> &middot;
        <a href="mailto:info@defen.so">Support</a> &middot;
        v<?php echo esc_html(DEFENSO_VERSION); ?>
    </p>
</div>
