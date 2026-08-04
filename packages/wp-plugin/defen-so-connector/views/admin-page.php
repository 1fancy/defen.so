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
                <p style="margin:2px 0 0;color:#6b7280;font-size:13px;"><?php echo esc_html__('Firewall &middot; hardening &middot; malware &amp; core-file scan &middot; login hardening &middot; WAF &middot; uptime', 'defen-so-connector'); ?></p>
            </div>
        </div>
        <div class="defenso-status">
            <?php if ($defenso_connected) { ?>
                <span class="defenso-pill defenso-pill-ok">&#9679; <?php echo esc_html__('Connected', 'defen-so-connector'); ?></span>
                <span id="defenso-verified-chip" class="defenso-pill <?php echo $defenso_verified ? 'defenso-pill-ok' : 'defenso-pill-warn'; ?>" style="margin-left:6px;">
                    <?php echo $defenso_verified ? '&#9679; '.esc_html__('Verified', 'defen-so-connector') : '&#9680; '.esc_html__('Not verified', 'defen-so-connector'); ?>
                </span>
                <span id="defenso-plan-badge" class="defenso-pill defenso-pill-ok" style="margin-left:6px;"><?php echo esc_html($defenso_plan_label); ?></span>
            <?php } else { ?>
                <span class="defenso-pill defenso-pill-warn">&#9680; <?php echo esc_html__('Not connected', 'defen-so-connector'); ?></span>
            <?php } ?>
        </div>
    </div>

    <?php if (isset($_GET['connected']) && $_GET['connected'] === '1') { // phpcs:ignore WordPress.Security.NonceVerification.Recommended?>
        <div class="notice notice-success is-dismissible"><p><strong><?php echo esc_html__('Connected!', 'defen-so-connector'); ?></strong> <?php echo esc_html__('Your site is now protected. WAF policy is being pulled in the background.', 'defen-so-connector'); ?></p></div>
    <?php } ?>

    <h2 class="nav-tab-wrapper defenso-tabs" id="defenso-tabs">
        <a href="<?php echo $defenso_tab_url('overview'); ?>" class="nav-tab defenso-tab<?php echo $defenso_active_tab === 'overview' ? ' nav-tab-active' : ''; ?>" data-tab="overview"><?php echo esc_html__('Overview', 'defen-so-connector'); ?></a>
        <a href="<?php echo $defenso_tab_url('firewall'); ?>" class="nav-tab defenso-tab<?php echo $defenso_active_tab === 'firewall' ? ' nav-tab-active' : ''; ?>" data-tab="firewall"><?php echo esc_html__('Firewall &amp; hardening', 'defen-so-connector'); ?></a>
        <a href="<?php echo $defenso_tab_url('scans'); ?>" class="nav-tab defenso-tab<?php echo $defenso_active_tab === 'scans' ? ' nav-tab-active' : ''; ?>" data-tab="scans"><?php echo esc_html__('Scans', 'defen-so-connector'); ?><?php if ($defenso_scan_issues > 0) { ?><span class="defenso-tab-badge"><?php echo esc_html($defenso_scan_issues); ?></span><?php } ?></a>
        <a href="<?php echo $defenso_tab_url('ratelimits'); ?>" class="nav-tab defenso-tab<?php echo $defenso_active_tab === 'ratelimits' ? ' nav-tab-active' : ''; ?>" data-tab="ratelimits"><?php echo esc_html__('Rate limits', 'defen-so-connector'); ?></a>
        <a href="<?php echo $defenso_tab_url('uptime'); ?>" class="nav-tab defenso-tab<?php echo $defenso_active_tab === 'uptime' ? ' nav-tab-active' : ''; ?>" data-tab="uptime"><?php echo esc_html__('Uptime &amp; alerts', 'defen-so-connector'); ?></a>
        <a href="<?php echo $defenso_tab_url('activity'); ?>" class="nav-tab defenso-tab<?php echo $defenso_active_tab === 'activity' ? ' nav-tab-active' : ''; ?>" data-tab="activity"><?php echo esc_html__('Activity log', 'defen-so-connector'); ?></a>
    </h2>

    <?php /* ============================ OVERVIEW ============================ */ ?>
    <div class="defenso-panel" data-panel="overview"<?php echo $defenso_active_tab === 'overview' ? '' : ' style="display:none;"'; ?>>
        <?php if (! $defenso_connected) { ?>
            <div class="defenso-card">
                <h2><?php echo esc_html__('Optional: connect the Defen.so service', 'defen-so-connector'); ?></h2>
                <p><?php echo esc_html__('Every security tool in the tabs above works locally, no account needed. Connecting adds the cloud service on top: the managed WAF policy, uptime monitoring from our edge, upload scanning, the attack-log dashboard and CVE lookups.', 'defen-so-connector'); ?></p>
                <p>
                    <button id="defenso-connect" class="button button-primary button-hero"><?php echo esc_html__('Connect to Defen.so', 'defen-so-connector'); ?></button>
                    <a href="https://defen.so" target="_blank" class="button"><?php echo esc_html__("What's Defen.so?", 'defen-so-connector'); ?></a>
                </p>
                <p class="description"><?php echo esc_html__('The connector talks to the external Defen.so service', 'defen-so-connector'); ?> (<a href="https://defen.so/tos" target="_blank"><?php echo esc_html__('Terms', 'defen-so-connector'); ?></a> &middot; <a href="https://defen.so/privacy" target="_blank"><?php echo esc_html__('Privacy', 'defen-so-connector'); ?></a>).</p>
            </div>
        <?php } else { ?>
            <div class="defenso-grid">
                <div class="defenso-card">
                    <p class="defenso-eyebrow"><?php echo esc_html__('Live plan', 'defen-so-connector'); ?></p>
                    <p class="defenso-metric-small" id="defenso-plan-name"><?php echo esc_html($defenso_plan_label); ?></p>
                    <p class="description">
                        <a id="defenso-upgrade-link" href="<?php echo esc_url($defenso_manage_url.'/billing/checkout'); ?>" target="_blank"><?php echo esc_html__('Upgrade', 'defen-so-connector'); ?> &rarr;</a>
                    </p>
                </div>
                <div class="defenso-card">
                    <p class="defenso-eyebrow"><?php echo esc_html__('WAF rules active', 'defen-so-connector'); ?></p>
                    <p class="defenso-metric"><?php echo esc_html($defenso_rules_count); ?></p>
                    <p class="description"><?php
                        /* translators: %s = relative time */
                        echo esc_html(sprintf(__('refreshed %s', 'defen-so-connector'), $defenso_refreshed_ago)); ?></p>
                </div>
                <div class="defenso-card">
                    <p class="defenso-eyebrow"><?php echo esc_html__('Queued events', 'defen-so-connector'); ?></p>
                    <p class="defenso-metric"><?php echo esc_html($defenso_queue_count); ?></p>
                    <p class="description"><?php echo esc_html__('shipping in the next request', 'defen-so-connector'); ?></p>
                </div>
                <div class="defenso-card">
                    <p class="defenso-eyebrow"><?php echo esc_html__('Connected', 'defen-so-connector'); ?></p>
                    <p class="defenso-metric-small"><?php echo esc_html($defenso_connected_at ? human_time_diff(strtotime($defenso_connected_at), time()).' ago' : '—'); ?></p>
                    <p class="description"><?php echo esc_html__('key scoped to this site', 'defen-so-connector'); ?></p>
                </div>
            </div>
        <?php } ?>

        <?php // Vulnerability scan (service-backed CVE lookups) lives on Overview.?>
        <div class="defenso-card">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                <div>
                    <h3 style="margin:0;"><?php echo esc_html__('Vulnerability scan', 'defen-so-connector'); ?> <span style="font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:#a3a3a3;">&middot; Defen.so service</span></h3>
                    <p class="description" style="margin:4px 0 0;"><?php echo esc_html__('Enumerates installed plugins and themes with versions and checks them against known CVEs via the external Defen.so service', 'defen-so-connector'); ?> (<a href="https://defen.so/tos" target="_blank"><?php echo esc_html__('Terms', 'defen-so-connector'); ?></a> &middot; <a href="https://defen.so/privacy" target="_blank"><?php echo esc_html__('Privacy', 'defen-so-connector'); ?></a>).</p>
                </div>
                <?php if ($defenso_connected) { ?>
                    <button id="defenso-vuln-scan" class="button button-primary"><?php echo esc_html__('Scan now', 'defen-so-connector'); ?></button>
                <?php } else { ?>
                    <button type="button" class="button button-primary defenso-connect-alt"><?php echo esc_html__('Connect to run', 'defen-so-connector'); ?></button>
                <?php } ?>
            </div>
            <div id="defenso-vuln-result"></div>
        </div>

        <?php if ($defenso_connected) { ?>
            <div class="defenso-card">
                <h3><?php echo esc_html__('Manage this site', 'defen-so-connector'); ?></h3>
                <p><?php echo esc_html__('The cloud side (attack log, WAF rules, alerts, monitors, plan) is managed from your Defen.so dashboard.', 'defen-so-connector'); ?></p>
                <p>
                    <a class="button button-primary" href="<?php echo esc_url($defenso_manage_url); ?>" target="_blank"><?php echo esc_html__('Open Defen.so dashboard', 'defen-so-connector'); ?></a>
                    <a class="button" href="<?php echo esc_url(DEFENSO_APP_URL.'/developer'); ?>" target="_blank"><?php echo esc_html__('Manage API keys', 'defen-so-connector'); ?></a>
                    <button id="defenso-disconnect" class="button-link" style="color:#b32d2e;margin-left:12px;"><?php echo esc_html__('Disconnect this site', 'defen-so-connector'); ?></button>
                </p>
            </div>
        <?php } ?>
    </div>

    <?php /* ======================= FIREWALL & HARDENING ===================== */ ?>
    <div class="defenso-panel" data-panel="firewall"<?php echo $defenso_active_tab === 'firewall' ? '' : ' style="display:none;"'; ?>>
        <?php
        $defenso_hardening = class_exists('Defenso_Hardening') ? Defenso_Hardening::settings() : [];
$defenso_toggles = [
    'block_bad_bots' => [__('Block bad bots &amp; scanners', 'defen-so-connector'), __('Rejects sqlmap, nikto, wpscan, nuclei and other known scanner user-agents.', 'defen-so-connector')],
    'block_exploit_patterns' => [__('Block exploit request patterns', 'defen-so-connector'), __('Blocks path traversal, LFI/RFI wrappers, code-in-querystring, wp-config &amp; dotfile probes.', 'defen-so-connector')],
    'block_user_enum' => [__('Block username enumeration', 'defen-so-connector'), __('Stops ?author=N scans and the anonymous REST /users endpoint from leaking usernames.', 'defen-so-connector')],
    'security_headers' => [__('Security response headers', 'defen-so-connector'), __('Adds X-Frame-Options, X-Content-Type-Options and Referrer-Policy to every page.', 'defen-so-connector')],
    'hsts' => [__('Strict-Transport-Security (HSTS)', 'defen-so-connector'), __('Forces HTTPS for a year. Only enable once your whole site is on HTTPS.', 'defen-so-connector')],
    'remove_version' => [__('Hide WordPress version', 'defen-so-connector'), __('Removes the generator meta tag that advertises your exact WP version.', 'defen-so-connector')],
    'disable_file_edit' => [__('Disable theme/plugin file editor', 'defen-so-connector'), __('Sets DISALLOW_FILE_EDIT so a compromised admin can\'t edit code from wp-admin.', 'defen-so-connector')],
    'disable_xmlrpc' => [__('Disable XML-RPC', 'defen-so-connector'), __('Turns off xmlrpc.php entirely (blocks pingback DDoS &amp; brute-force amplification).', 'defen-so-connector')],
    'comment_hardening' => [__('Comment / pingback hardening', 'defen-so-connector'), __('Drops pingback methods and the X-Pingback header.', 'defen-so-connector')],
];
?>
        <div class="defenso-card">
            <h3 style="margin-top:0;"><?php echo esc_html__('Firewall &amp; hardening', 'defen-so-connector'); ?> <span style="font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:#a3a3a3;">&middot; <?php echo esc_html__('runs locally, free', 'defen-so-connector'); ?></span></h3>
            <p class="description" style="margin:4px 0 14px;"><?php echo esc_html__('Cheap, self-contained WordPress protections. Everything here runs in the plugin, no account needed.', 'defen-so-connector'); ?></p>
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
                <button id="defenso-hardening-save" class="button button-primary"><?php echo esc_html__('Save hardening settings', 'defen-so-connector'); ?></button>
                <span id="defenso-hardening-status" style="font-size:12px; color:#525252; margin-left:10px;"></span>
            </p>
        </div>

        <div class="defenso-card">
            <div>
                <h3 style="margin:0;"><?php echo esc_html__('Geo-block', 'defen-so-connector'); ?></h3>
                <p class="description" style="margin:4px 0 12px;"><?php echo esc_html__('Reject requests from selected countries (ISO 3166-1 alpha-2, comma-separated). Works locally for everyone.', 'defen-so-connector'); ?></p>
            </div>
            <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                <input id="defenso-geo-input" type="text" placeholder="<?php echo esc_attr__('e.g. RU, KP, IR', 'defen-so-connector'); ?>" value="<?php echo esc_attr(implode(', ', $defenso_geo_blocklist)); ?>" style="min-width:260px; padding:8px 12px; font-family:Consolas, Monaco, monospace;">
                <button id="defenso-geo-save" class="button button-primary"><?php echo esc_html__('Save blocklist', 'defen-so-connector'); ?></button>
                <span id="defenso-geo-status" style="font-size:12px; color:#525252;"></span>
            </div>
        </div>
    </div>

    <?php /* ============================== SCANS ============================= */ ?>
    <div class="defenso-panel" data-panel="scans"<?php echo $defenso_active_tab === 'scans' ? '' : ' style="display:none;"'; ?>>
        <div class="defenso-card">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                <div>
                    <h3 style="margin:0;"><?php echo esc_html__('Malware scan', 'defen-so-connector'); ?></h3>
                    <p class="description" style="margin:4px 0 0;">
                        <?php if ($defenso_malware_stats) { ?>
                            <?php
                                /* translators: %1$s = relative time, %2$d = files inspected, %3$d = files flagged */
                                echo esc_html(sprintf(__('Last scan: %1$s ago', 'defen-so-connector'), human_time_diff((int) $defenso_malware_stats['ran_at'], time()))); ?> &middot; <?php echo (int) $defenso_malware_stats['files_seen']; ?> <?php echo esc_html__('files inspected', 'defen-so-connector'); ?> &middot; <strong><?php echo (int) $defenso_malware_stats['files_flagged']; ?> <?php echo esc_html__('flagged', 'defen-so-connector'); ?></strong>
                        <?php } else { ?>
                            <?php echo esc_html__('Not run yet. Click Scan to run a local malware sweep.', 'defen-so-connector'); ?>
                        <?php } ?>
                    </p>
                </div>
                <button id="defenso-malware-scan" class="button button-primary"><?php echo esc_html__('Scan now', 'defen-so-connector'); ?></button>
            </div>
            <div id="defenso-malware-findings"></div>
        </div>

        <div class="defenso-card">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                <div>
                    <h3 style="margin:0;"><?php echo esc_html__('File integrity', 'defen-so-connector'); ?></h3>
                    <p class="description" style="margin:4px 0 0;">
                        <?php if ($defenso_integrity_baseline_at) { ?>
                            <?php
                                /* translators: %s = relative time */
                                echo esc_html(sprintf(__('Baseline: %s ago', 'defen-so-connector'), human_time_diff($defenso_integrity_baseline_at, time()))); ?>
                            <?php if (is_array($defenso_integrity_last_diff) && isset($defenso_integrity_last_diff['counts'])) { ?>
                                &middot; <?php echo esc_html__('Last check flagged', 'defen-so-connector'); ?>
                                <strong><?php echo (int) $defenso_integrity_last_diff['counts']['added']; ?></strong> <?php echo esc_html__('new', 'defen-so-connector'); ?>,
                                <strong><?php echo (int) $defenso_integrity_last_diff['counts']['changed']; ?></strong> <?php echo esc_html__('changed', 'defen-so-connector'); ?>,
                                <strong><?php echo (int) $defenso_integrity_last_diff['counts']['removed']; ?></strong> <?php echo esc_html__('removed', 'defen-so-connector'); ?>.
                            <?php } ?>
                        <?php } else { ?>
                            <?php echo esc_html__('No baseline taken yet. Take one after a clean install / update.', 'defen-so-connector'); ?>
                        <?php } ?>
                    </p>
                </div>
                <div>
                    <button id="defenso-integrity-baseline" class="button"><?php echo esc_html__('Take baseline', 'defen-so-connector'); ?></button>
                    <button id="defenso-integrity-diff" class="button button-primary" <?php echo $defenso_integrity_baseline_at ? '' : 'disabled'; ?>><?php echo esc_html__('Check for changes', 'defen-so-connector'); ?></button>
                </div>
            </div>
            <div id="defenso-integrity-result"></div>
        </div>

        <div class="defenso-card">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                <div>
                    <h3 style="margin:0;"><?php echo esc_html__('Core file &amp; exposure check', 'defen-so-connector'); ?> <span style="font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:#a3a3a3;">&middot; <?php echo esc_html__('free', 'defen-so-connector'); ?></span></h3>
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
                    <button id="defenso-core-checksum" class="button button-primary"><?php echo esc_html__('Verify core files', 'defen-so-connector'); ?></button>
                    <button id="defenso-exposed-files" class="button"><?php echo esc_html__('Check exposed files', 'defen-so-connector'); ?></button>
                </div>
            </div>
            <div id="defenso-core-result"></div>
        </div>
    </div>

    <?php /* =========================== RATE LIMITS ========================== */ ?>
    <div class="defenso-panel" data-panel="ratelimits"<?php echo $defenso_active_tab === 'ratelimits' ? '' : ' style="display:none;"'; ?>>
        <div class="defenso-card">
            <h3 style="margin-top:0;"><?php echo esc_html__('Login rate limiting', 'defen-so-connector'); ?> <span style="font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:#a3a3a3;">&middot; <?php echo esc_html__('runs locally, free', 'defen-so-connector'); ?></span></h3>
            <p class="description" style="margin:4px 0 14px;"><?php echo wp_kses(__('Per-IP brute-force protection on <code>wp-login.php</code>. Too many failed attempts inside the window locks that IP out until it cools down. Fully adjustable and runs entirely in the plugin.', 'defen-so-connector'), ['code' => []]); ?></p>
            <div style="display:grid; grid-template-columns:repeat(2, 1fr); gap:14px; margin-top:4px;">
                <div>
                    <p class="defenso-eyebrow"><?php echo esc_html__('Max failed attempts', 'defen-so-connector'); ?></p>
                    <input id="defenso-login-max" type="number" min="1" max="50" value="<?php echo esc_attr($defenso_login_max); ?>" style="width:120px; padding:6px 10px;">
                </div>
                <div>
                    <p class="defenso-eyebrow"><?php echo esc_html__('Window (seconds)', 'defen-so-connector'); ?></p>
                    <input id="defenso-login-window" type="number" min="60" max="86400" value="<?php echo esc_attr($defenso_login_window); ?>" style="width:120px; padding:6px 10px;">
                </div>
                <div>
                    <p class="defenso-eyebrow"><?php echo esc_html__('reCAPTCHA v3 site key', 'defen-so-connector'); ?> <span style="color:#a3a3a3;"><?php echo esc_html__('(optional)', 'defen-so-connector'); ?></span></p>
                    <input id="defenso-recaptcha-site" type="text" value="<?php echo esc_attr($defenso_recaptcha_site); ?>" placeholder="6L…" style="width:100%; padding:6px 10px; font-family:Consolas, Monaco, monospace; font-size:11.5px;">
                </div>
                <div>
                    <p class="defenso-eyebrow"><?php echo esc_html__('reCAPTCHA v3 secret key', 'defen-so-connector'); ?></p>
                    <input id="defenso-recaptcha-secret" type="password" value="<?php echo esc_attr($defenso_recaptcha_secret); ?>" placeholder="6L…" style="width:100%; padding:6px 10px; font-family:Consolas, Monaco, monospace; font-size:11.5px;">
                </div>
            </div>
            <p style="margin-top:14px;">
                <button id="defenso-login-save" class="button button-primary"><?php echo esc_html__('Save rate-limit settings', 'defen-so-connector'); ?></button>
                <span id="defenso-login-status" style="font-size:12px; color:#525252; margin-left:10px;"></span>
            </p>
        </div>

        <div class="defenso-card">
            <h3 style="margin-top:0;"><?php echo esc_html__('Managed edge rate limits', 'defen-so-connector'); ?> <span style="font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:#a3a3a3;">&middot; Defen.so service</span></h3>
            <?php if ($defenso_connected) { ?>
                <p class="description" style="margin:4px 0 0;"><?php echo esc_html__('Per-endpoint, per-IP and per-account velocity limits run on the Defen.so edge, ahead of WordPress. Configure them, and see what they blocked, from your dashboard.', 'defen-so-connector'); ?></p>
                <p style="margin-top:14px;"><a class="button button-primary" href="<?php echo esc_url($defenso_manage_url); ?>" target="_blank"><?php echo esc_html__('Open rate-limit rules', 'defen-so-connector'); ?> &rarr;</a></p>
            <?php } else { ?>
                <p class="description" style="margin:4px 0 0;"><?php echo esc_html__('Connect a free Defen.so account to add per-endpoint, per-IP and per-account velocity limits at the edge, ahead of WordPress. Higher plans raise the limits and custom-rule count.', 'defen-so-connector'); ?></p>
                <p style="margin-top:14px;">
                    <button type="button" class="button button-primary defenso-connect-alt"><?php echo esc_html__('Connect to enable', 'defen-so-connector'); ?></button>
                    <a class="button" href="https://defen.so" target="_blank" rel="noopener"><?php echo esc_html__('Learn more', 'defen-so-connector'); ?></a>
                </p>
            <?php } ?>
        </div>
    </div>

    <?php /* ========================= UPTIME & ALERTS ======================== */ ?>
    <div class="defenso-panel" data-panel="uptime"<?php echo $defenso_active_tab === 'uptime' ? '' : ' style="display:none;"'; ?>>
        <div class="defenso-card defenso-promo-card">
            <p class="defenso-eyebrow">Defen.so cloud &middot; <?php echo esc_html__('optional', 'defen-so-connector'); ?></p>
            <h3 style="margin:0 0 6px;"><?php echo esc_html__('Know the instant this site is in trouble', 'defen-so-connector'); ?></h3>
            <p class="description" style="margin:0 0 4px;"><?php echo esc_html__('Uptime monitoring, SSL and domain-expiry checks, and multi-channel alerts all run on the Defen.so edge, not in this plugin, so they keep working even if WordPress itself is down.', 'defen-so-connector'); ?></p>

            <div class="defenso-promo-item">
                <span class="defenso-promo-ico">&#9201;&#65039;</span>
                <div>
                    <strong><?php echo esc_html__('Uptime monitoring', 'defen-so-connector'); ?></strong>
                    <p class="description" style="margin:2px 0 0;"><?php echo esc_html__('Checks from multiple regions; SSL and domain-expiry alerts.', 'defen-so-connector'); ?>
                        <a href="https://defen.so/website-apps-uptime-monitoring" target="_blank" rel="noopener"><?php echo esc_html__('Learn more', 'defen-so-connector'); ?> &rarr;</a></p>
                </div>
            </div>
            <div class="defenso-promo-item">
                <span class="defenso-promo-ico">&#128276;</span>
                <div>
                    <strong><?php echo esc_html__('Alerts everywhere', 'defen-so-connector'); ?></strong>
                    <p class="description" style="margin:2px 0 0;"><?php echo esc_html__('Slack, Discord, Telegram, email and webhooks the moment something breaks.', 'defen-so-connector'); ?></p>
                </div>
            </div>
            <div class="defenso-promo-item">
                <span class="defenso-promo-ico">&#128241;</span>
                <div>
                    <strong><?php echo esc_html__('Defenso Alerts app', 'defen-so-connector'); ?></strong>
                    <p class="description" style="margin:2px 0 0;"><?php echo esc_html__('A call-style alarm on your phone for downtime and attacks. It rings even on silent.', 'defen-so-connector'); ?>
                        <a href="https://play.google.com/store/apps/details?id=so.defen.alerts" target="_blank" rel="noopener"><?php echo esc_html__('Get it on Google Play', 'defen-so-connector'); ?> &rarr;</a></p>
                </div>
            </div>

            <p style="margin:16px 0 0;">
                <?php if ($defenso_connected) { ?>
                    <a class="button button-primary" href="<?php echo esc_url($defenso_manage_url); ?>" target="_blank" rel="noopener"><?php echo esc_html__('Set up monitoring &amp; alerts', 'defen-so-connector'); ?></a>
                <?php } else { ?>
                    <button type="button" class="button button-primary defenso-connect-alt"><?php echo esc_html__('Connect a free account', 'defen-so-connector'); ?></button>
                <?php } ?>
                <a class="button" href="https://defen.so/website-monitor-app" target="_blank" rel="noopener"><?php echo esc_html__('Explore the app', 'defen-so-connector'); ?></a>
            </p>
        </div>
    </div>

    <?php /* =========================== ACTIVITY LOG ========================= */ ?>
    <div class="defenso-panel" data-panel="activity"<?php echo $defenso_active_tab === 'activity' ? '' : ' style="display:none;"'; ?>>
        <div class="defenso-card">
            <h3 style="margin-top:0;"><?php echo esc_html__('Recent activity', 'defen-so-connector'); ?></h3>
            <?php if (empty($defenso_activity)) { ?>
                <p class="description"><?php echo esc_html__('No admin events yet. Login, plugin activate/deactivate, and role changes show up here.', 'defen-so-connector'); ?></p>
            <?php } else { ?>
                <table style="width:100%; margin-top:8px; border-collapse:separate; border-spacing:0 4px;">
                    <thead><tr>
                        <th style="text-align:left; font-size:10px; letter-spacing:.14em; text-transform:uppercase; color:#737373; padding:0 10px;"><?php echo esc_html__('When', 'defen-so-connector'); ?></th>
                        <th style="text-align:left; font-size:10px; padding:0 10px;"><?php echo esc_html__('Actor', 'defen-so-connector'); ?></th>
                        <th style="text-align:left; font-size:10px; padding:0 10px;"><?php echo esc_html__('Event', 'defen-so-connector'); ?></th>
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
        <a href="https://defen.so/docs" target="_blank"><?php echo esc_html__('Docs', 'defen-so-connector'); ?></a> &middot;
        <a href="https://defen.so" target="_blank">defen.so</a> &middot;
        <a href="mailto:info@defen.so"><?php echo esc_html__('Support', 'defen-so-connector'); ?></a> &middot;
        v<?php echo esc_html(DEFENSO_VERSION); ?>
    </p>
</div>
