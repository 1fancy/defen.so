<?php
if (! defined('ABSPATH')) {
    exit;
}

$connected = (bool) get_option('defenso_api_token');
$connected_at = get_option('defenso_connected_at');
$rules_count = is_array(get_option('defenso_policy_cache')) ? count(get_option('defenso_policy_cache')['rules'] ?? []) : 0;
$queue_count = is_array(get_option('defenso_attack_log_queue')) ? count(get_option('defenso_attack_log_queue')) : 0;
$refreshed_at = (int) get_option('defenso_policy_refreshed_at', 0);
$refreshed_ago = $refreshed_at ? human_time_diff($refreshed_at, time()).' ago' : '—';
?>
<div class="wrap defenso-wrap">
    <div class="defenso-header">
        <div class="defenso-brand">
            <div class="defenso-logo"></div>
            <div>
                <h1 style="margin:0;font-size:22px;">Defen.so</h1>
                <p style="margin:2px 0 0;color:#6b7280;font-size:13px;">WAF · uptime · upload scanning · attack log</p>
            </div>
        </div>
        <div class="defenso-status">
            <?php if ($connected) { ?>
                <span class="defenso-pill defenso-pill-ok">● Connected</span>
            <?php } else { ?>
                <span class="defenso-pill defenso-pill-warn">◐ Not connected</span>
            <?php } ?>
        </div>
    </div>

    <?php if (isset($_GET['connected']) && $_GET['connected'] === '1') { // phpcs:ignore WordPress.Security.NonceVerification.Recommended?>
        <div class="notice notice-success is-dismissible"><p><strong>Connected!</strong> Your site is now protected. WAF policy is being pulled in the background.</p></div>
    <?php } ?>

    <?php if (! $connected) { ?>
        <div class="defenso-card">
            <h2>Connect this site to Defen.so</h2>
            <p>One click, one popup. No API key to paste. Signs into your Defen.so account, adds this WordPress site as a Site, and mints a scoped key just for this install.</p>
            <p>
                <button id="defenso-connect" class="button button-primary button-hero">Connect to Defen.so</button>
                <a href="https://defen.so" target="_blank" class="button">What's Defen.so?</a>
            </p>
            <p class="description">No account yet? The popup will let you sign up first. Free forever tier includes: 1 site, WAF, upload scan, uptime monitor.</p>
        </div>

        <div class="defenso-card defenso-card-quiet">
            <h3>What connecting unlocks</h3>
            <ul>
                <li><strong>Managed WAF</strong> — SQL injection, XSS, path traversal, bot scanners, mass-assignment. 25 signatures + your custom rules.</li>
                <li><strong>Upload scan</strong> — polyglot detection, dangerous extensions blocked, MIME/magic-byte disagreement flagged.</li>
                <li><strong>Uptime monitor</strong> — checks every 15 min on Free (1 min on Pro). Email + Slack + webhook on down/up.</li>
                <li><strong>Attack log</strong> — every blocked / challenged / deceived request appears on your Defen.so dashboard with full context.</li>
                <li><strong>Login brute-force signal</strong> — failed WP logins ship to Defen.so so the dashboard shows what's hitting <code>/wp-login.php</code>.</li>
            </ul>
        </div>
    <?php } else { ?>
        <div class="defenso-grid">
            <div class="defenso-card">
                <p class="defenso-eyebrow">Status</p>
                <p class="defenso-metric"><?php echo esc_html($rules_count); ?></p>
                <p class="description">WAF rules active</p>
            </div>
            <div class="defenso-card">
                <p class="defenso-eyebrow">Queued events</p>
                <p class="defenso-metric"><?php echo esc_html($queue_count); ?></p>
                <p class="description">shipping in the next request</p>
            </div>
            <div class="defenso-card">
                <p class="defenso-eyebrow">Policy refreshed</p>
                <p class="defenso-metric-small"><?php echo esc_html($refreshed_ago); ?></p>
                <p class="description">cached 10 min, stale-while-revalidate</p>
            </div>
            <div class="defenso-card">
                <p class="defenso-eyebrow">Connected</p>
                <p class="defenso-metric-small"><?php echo esc_html($connected_at ? human_time_diff(strtotime($connected_at), time()).' ago' : '—'); ?></p>
                <p class="description">key scoped to this site</p>
            </div>
        </div>

        <div class="defenso-card">
            <h3>Manage this site</h3>
            <p>Everything except this on/off switch is managed from your Defen.so dashboard — attack log, WAF rules, alerts, monitors, plan.</p>
            <p>
                <a class="button button-primary" href="<?php echo esc_url(DEFENSO_APP_URL); ?>" target="_blank">Open Defen.so dashboard</a>
                <a class="button" href="<?php echo esc_url(DEFENSO_APP_URL.'/developer'); ?>" target="_blank">Manage API keys</a>
                <button id="defenso-disconnect" class="button-link" style="color:#b32d2e;margin-left:12px;">Disconnect this site</button>
            </p>
        </div>
    <?php } ?>

    <p class="defenso-footer">
        <a href="https://defen.so/docs" target="_blank">Docs</a> ·
        <a href="https://defen.so/pricing" target="_blank">Pricing</a> ·
        <a href="mailto:info@defen.so">Support</a> ·
        v<?php echo esc_html(DEFENSO_VERSION); ?>
    </p>
</div>
