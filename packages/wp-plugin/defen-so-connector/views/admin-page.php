<?php
if (! defined('ABSPATH')) {
    exit;
}

$connected = (bool) get_option('defenso_api_token');
$connected_at = get_option('defenso_connected_at');
$plan_label = (string) get_option('defenso_plan_label', 'Free');
$verified = get_option('defenso_verified', '1') === '1';
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
                <span id="defenso-verified-chip" class="defenso-pill <?php echo $verified ? 'defenso-pill-ok' : 'defenso-pill-warn'; ?>" style="margin-left:6px;">
                    <?php echo $verified ? '● Verified' : '◐ Not verified'; ?>
                </span>
                <span id="defenso-plan-badge" class="defenso-pill defenso-pill-ok" style="margin-left:6px;"><?php echo esc_html($plan_label); ?></span>
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
                <p class="defenso-eyebrow">Live plan</p>
                <p class="defenso-metric-small" id="defenso-plan-name"><?php echo esc_html($plan_label); ?></p>
                <p class="description">
                    <a id="defenso-upgrade-link" href="<?php echo esc_url(DEFENSO_APP_URL); ?>" target="_blank">Upgrade →</a>
                </p>
            </div>
            <div class="defenso-card">
                <p class="defenso-eyebrow">WAF rules active</p>
                <p class="defenso-metric"><?php echo esc_html($rules_count); ?></p>
                <p class="description">refreshed <?php echo esc_html($refreshed_ago); ?></p>
            </div>
            <div class="defenso-card">
                <p class="defenso-eyebrow">Queued events</p>
                <p class="defenso-metric"><?php echo esc_html($queue_count); ?></p>
                <p class="description">shipping in the next request</p>
            </div>
            <div class="defenso-card">
                <p class="defenso-eyebrow">Connected</p>
                <p class="defenso-metric-small"><?php echo esc_html($connected_at ? human_time_diff(strtotime($connected_at), time()).' ago' : '—'); ?></p>
                <p class="description">key scoped to this site</p>
            </div>
        </div>

        <?php
        $malware_stats = get_option('defenso_malware_stats');
        $integrity_baseline_at = (int) get_option('defenso_integrity_baseline_at', 0);
        $integrity_last_diff = get_option('defenso_integrity_last_diff');
        ?>
        <div class="defenso-card">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                <div>
                    <h3 style="margin:0;">Malware scan</h3>
                    <p class="description" style="margin:4px 0 0;">
                        <?php if ($malware_stats) : ?>
                            Last scan: <?php echo esc_html(human_time_diff((int) $malware_stats['ran_at'], time()).' ago'); ?> · <?php echo (int) $malware_stats['files_seen']; ?> files inspected · <strong><?php echo (int) $malware_stats['files_flagged']; ?> flagged</strong>
                        <?php else : ?>
                            Not run yet. Free tier: 1 scan / 7 days.
                        <?php endif; ?>
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
                        <?php if ($integrity_baseline_at) : ?>
                            Baseline: <?php echo esc_html(human_time_diff($integrity_baseline_at, time()).' ago'); ?>
                            <?php if (is_array($integrity_last_diff) && isset($integrity_last_diff['counts'])) : ?>
                                · Last check flagged
                                <strong><?php echo (int) $integrity_last_diff['counts']['added']; ?></strong> new,
                                <strong><?php echo (int) $integrity_last_diff['counts']['changed']; ?></strong> changed,
                                <strong><?php echo (int) $integrity_last_diff['counts']['removed']; ?></strong> removed.
                            <?php endif; ?>
                        <?php else : ?>
                            No baseline taken yet. Take one after a clean install / update.
                        <?php endif; ?>
                    </p>
                </div>
                <div>
                    <button id="defenso-integrity-baseline" class="button">Take baseline</button>
                    <button id="defenso-integrity-diff" class="button button-primary" <?php echo $integrity_baseline_at ? '' : 'disabled'; ?>>Check for changes</button>
                </div>
            </div>
            <div id="defenso-integrity-result"></div>
        </div>

        <?php $geo_blocklist = (array) get_option('defenso_geo_blocklist', []); ?>
        <div class="defenso-card">
            <div style="display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;">
                <div>
                    <h3 style="margin:0;">Vulnerability scan</h3>
                    <p class="description" style="margin:4px 0 0;">Enumerates installed plugins &amp; themes with versions, checks against known CVEs.</p>
                </div>
                <button id="defenso-vuln-scan" class="button button-primary">Scan now</button>
            </div>
            <div id="defenso-vuln-result"></div>
        </div>

        <div class="defenso-card">
            <div>
                <h3 style="margin:0;">Geo-block</h3>
                <p class="description" style="margin:4px 0 12px;">Reject requests from selected countries (ISO 3166-1 alpha-2, comma-separated). Free tier: 1 country max.</p>
            </div>
            <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
                <input id="defenso-geo-input" type="text" placeholder="e.g. RU, KP, IR" value="<?php echo esc_attr(implode(', ', $geo_blocklist)); ?>" style="min-width:260px; padding:8px 12px; font-family:JetBrains Mono, monospace;">
                <button id="defenso-geo-save" class="button button-primary">Save blocklist</button>
                <span id="defenso-geo-status" style="font-size:12px; color:#525252;"></span>
            </div>
        </div>

        <?php
        $login_max = (int) get_option('defenso_login_max', 5);
        $login_window = (int) get_option('defenso_login_window', 900);
        $recaptcha_site = (string) get_option('defenso_recaptcha_site_key', '');
        $recaptcha_secret = (string) get_option('defenso_recaptcha_secret_key', '');
        $activity = array_slice((array) get_option('defenso_activity_log', []), 0, 10);
        $plan_lower = strtolower((string) get_option('defenso_plan_label', 'Free'));
        ?>
        <div class="defenso-card">
            <h3 style="margin-top:0;">Login hardening</h3>
            <div style="display:grid; grid-template-columns:repeat(2, 1fr); gap:14px; margin-top:14px;">
                <div>
                    <p class="defenso-eyebrow">Max failed attempts</p>
                    <input id="defenso-login-max" type="number" min="1" max="50" value="<?php echo esc_attr($login_max); ?>" <?php echo $plan_lower === 'free' ? 'disabled' : ''; ?> style="width:120px; padding:6px 10px;">
                </div>
                <div>
                    <p class="defenso-eyebrow">Window (seconds)</p>
                    <input id="defenso-login-window" type="number" min="60" max="86400" value="<?php echo esc_attr($login_window); ?>" <?php echo $plan_lower === 'free' ? 'disabled' : ''; ?> style="width:120px; padding:6px 10px;">
                </div>
                <div>
                    <p class="defenso-eyebrow">reCAPTCHA v3 site key <span style="color:#a3a3a3;">(optional)</span></p>
                    <input id="defenso-recaptcha-site" type="text" value="<?php echo esc_attr($recaptcha_site); ?>" placeholder="6L…" style="width:100%; padding:6px 10px; font-family:JetBrains Mono,monospace; font-size:11.5px;">
                </div>
                <div>
                    <p class="defenso-eyebrow">reCAPTCHA v3 secret key</p>
                    <input id="defenso-recaptcha-secret" type="password" value="<?php echo esc_attr($recaptcha_secret); ?>" placeholder="6L…" style="width:100%; padding:6px 10px; font-family:JetBrains Mono,monospace; font-size:11.5px;">
                </div>
            </div>
            <p style="margin-top:14px;">
                <button id="defenso-login-save" class="button button-primary">Save login settings</button>
                <span id="defenso-login-status" style="font-size:12px; color:#525252; margin-left:10px;"></span>
            </p>
            <?php if ($plan_lower === 'free') : ?>
                <p class="description" style="color:#a3a3a3;">Free tier is locked to 5 attempts / 15 min. Upgrade to edit.</p>
            <?php endif; ?>
        </div>

        <div class="defenso-card">
            <h3 style="margin-top:0;">Recent activity</h3>
            <?php if (empty($activity)) : ?>
                <p class="description">No admin events yet. Login, plugin activate/deactivate, and role changes show up here.</p>
            <?php else : ?>
                <table style="width:100%; margin-top:8px; border-collapse:separate; border-spacing:0 4px;">
                    <thead><tr>
                        <th style="text-align:left; font-size:10px; letter-spacing:.14em; text-transform:uppercase; color:#737373; padding:0 10px;">When</th>
                        <th style="text-align:left; font-size:10px; padding:0 10px;">Actor</th>
                        <th style="text-align:left; font-size:10px; padding:0 10px;">Event</th>
                    </tr></thead>
                    <tbody>
                        <?php foreach ($activity as $ev) : ?>
                            <tr>
                                <td style="padding:6px 10px; font-size:11.5px; color:#737373;"><?php echo esc_html(human_time_diff((int) $ev['at'], time()).' ago'); ?></td>
                                <td style="padding:6px 10px; font-size:11.5px; font-family:JetBrains Mono, monospace;"><?php echo esc_html($ev['actor'] ?? '—'); ?></td>
                                <td style="padding:6px 10px; font-size:12px;"><?php echo esc_html($ev['summary'] ?? $ev['kind']); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
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
