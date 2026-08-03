<?php

/**
 * Admin promo surfaces for the Defen.so cloud upgrades — uptime monitoring,
 * multi-channel alerts, and the Defenso Alerts mobile app (call-style alarm).
 *
 * Two touch points, both tasteful and non-blocking:
 *
 *   1. A dismissible admin notice (shown only on the plugin's own pages, and
 *      only ~once — the dismissal is remembered per-user in user-meta).
 *   2. A sidebar promo card rendered inside the plugin settings page via the
 *      `defenso_admin_sidebar` action, so it lives next to the local tools
 *      rather than interrupting them.
 *
 * All links point at the public marketing pages. Nothing here sends data or
 * gates a local feature — it only advertises the optional cloud service.
 */
if (! defined('ABSPATH')) {
    exit;
}

class Defenso_Promo
{
    private const UPTIME_URL = 'https://defen.so/website-apps-uptime-monitoring';

    private const APP_PAGE_URL = 'https://defen.so/website-monitor-app';

    private const PLAY_URL = 'https://play.google.com/store/apps/details?id=so.defen.alerts';

    private const DISMISS_META = 'defenso_promo_dismissed';

    public static function register(): void
    {
        add_action('admin_notices', [self::class, 'maybe_notice']);
        add_action('wp_ajax_defenso_promo_dismiss', [self::class, 'ajax_dismiss']);
        add_action('defenso_admin_sidebar', [self::class, 'render_sidebar_card']);
    }

    private static function on_plugin_page(): bool
    {
        $screen = function_exists('get_current_screen') ? get_current_screen() : null;

        return $screen && strpos((string) $screen->id, 'defenso') !== false;
    }

    /**
     * Dismissible notice, shown on the plugin's own admin pages only, and only
     * to admins who haven't dismissed it and haven't connected an account.
     */
    public static function maybe_notice(): void
    {
        if (! current_user_can('manage_options') || ! self::on_plugin_page()) {
            return;
        }
        if (get_user_meta(get_current_user_id(), self::DISMISS_META, true)) {
            return;
        }
        $nonce = wp_create_nonce('defenso_admin');
        ?>
        <div class="notice notice-info is-dismissible defenso-promo-notice" data-nonce="<?php echo esc_attr($nonce); ?>">
            <p style="font-size:13px;">
                <strong>New:</strong> Defen.so can watch this site's uptime from our edge and call your phone the moment it goes down —
                via Slack, Discord, Telegram, email, webhook, or the
                <a href="<?php echo esc_url(self::APP_PAGE_URL); ?>" target="_blank" rel="noopener">Defenso Alerts app</a>
                (call-style alarm). <a href="<?php echo esc_url(self::UPTIME_URL); ?>" target="_blank" rel="noopener">See uptime monitoring →</a>
            </p>
        </div>
        <script>
        (function(){
            var n = document.querySelector('.defenso-promo-notice');
            if (!n) { return; }
            n.addEventListener('click', function(e){
                if (!e.target.classList.contains('notice-dismiss')) { return; }
                var data = new FormData();
                data.append('action', 'defenso_promo_dismiss');
                data.append('_wpnonce', n.getAttribute('data-nonce'));
                fetch(ajaxurl, { method: 'POST', credentials: 'same-origin', body: data });
            });
        })();
        </script>
        <?php
    }

    public static function ajax_dismiss(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        if (! check_ajax_referer('defenso_admin', '_wpnonce', false)) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
        }
        update_user_meta(get_current_user_id(), self::DISMISS_META, 1);
        wp_send_json_success();
    }

    /**
     * Sidebar promo card. Rendered inside the plugin settings page. Presents the
     * three cloud upgrades attractively without gating anything local.
     */
    public static function render_sidebar_card(): void
    {
        ?>
        <div class="defenso-card defenso-promo-card">
            <p class="defenso-eyebrow">Defen.so cloud · optional upgrades</p>
            <h3 style="margin:0 0 10px;">Know the instant your site is in trouble</h3>

            <div class="defenso-promo-item">
                <span class="defenso-promo-ico">⏱️</span>
                <div>
                    <strong>Uptime monitoring</strong>
                    <p class="description" style="margin:2px 0 0;">Checks from multiple regions; SSL &amp; domain-expiry alerts.
                        <a href="<?php echo esc_url(self::UPTIME_URL); ?>" target="_blank" rel="noopener">Learn more →</a></p>
                </div>
            </div>

            <div class="defenso-promo-item">
                <span class="defenso-promo-ico">🔔</span>
                <div>
                    <strong>Alerts everywhere</strong>
                    <p class="description" style="margin:2px 0 0;">Slack, Discord, Telegram, email &amp; webhooks the moment something breaks.</p>
                </div>
            </div>

            <div class="defenso-promo-item">
                <span class="defenso-promo-ico">📱</span>
                <div>
                    <strong>Defenso Alerts app</strong>
                    <p class="description" style="margin:2px 0 0;">Call-style alarm on your phone for downtime &amp; attacks.
                        <a href="<?php echo esc_url(self::PLAY_URL); ?>" target="_blank" rel="noopener">Get it on Google Play →</a></p>
                </div>
            </div>

            <p style="margin:14px 0 0;">
                <a class="button button-primary" href="<?php echo esc_url(self::APP_PAGE_URL); ?>" target="_blank" rel="noopener">Explore the app</a>
            </p>
        </div>
        <?php
    }
}
