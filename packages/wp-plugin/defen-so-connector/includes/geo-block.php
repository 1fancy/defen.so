<?php
/**
 * Geo-block. Rejects requests from country codes the site owner listed.
 * Runs on `init` (priority 1), before the WAF, so blocked countries never
 * consume policy match cycles.
 *
 * Country is resolved from (in order):
 *   1. CF-IPCountry header if the site sits behind Cloudflare.
 *   2. Free ip-api.com lookup (cached 24h per /24) — falls back to allow on
 *      network failure so we never block due to our own outage.
 *
 * Free tier: 1 country in the blocklist. Pro tier: unlimited.
 *
 * Blocklist stored in wp_options['defenso_geo_blocklist'] as an array of
 * 2-letter uppercase country codes.
 *
 * @package DefensoConnector
 */

if (! defined('ABSPATH')) {
    exit;
}

class Defenso_Geo_Block
{
    public static function register(): void
    {
        add_action('wp_ajax_defenso_geo_save', [self::class, 'ajax_save']);
        add_action('init', [self::class, 'maybe_block'], 1);
    }

    public static function ajax_save(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        if (! check_ajax_referer('defenso_admin', '_wpnonce', false)) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
        }
        $raw = isset($_POST['countries']) ? sanitize_text_field(wp_unslash($_POST['countries'])) : '';
        $parts = array_map('trim', explode(',', strtoupper($raw)));
        $codes = [];
        foreach ($parts as $c) {
            if (preg_match('/^[A-Z]{2}$/', $c)) {
                $codes[] = $c;
            }
        }
        $codes = array_values(array_unique($codes));

        $plan = strtolower((string) get_option('defenso_plan_label', 'Free'));
        if ($plan === 'free' && count($codes) > 1) {
            wp_send_json_error([
                'message' => 'Free tier: 1 country max. Upgrade for unlimited geo-block.',
                'upgrade_url' => 'https://app.defen.so',
            ], 429);
        }
        update_option('defenso_geo_blocklist', $codes, false);
        wp_send_json_success(['blocklist' => $codes]);
    }

    public static function maybe_block(): void
    {
        if (is_admin() || wp_doing_cron() || wp_doing_ajax()) {
            return;
        }
        $blocklist = (array) get_option('defenso_geo_blocklist', []);
        if (empty($blocklist)) {
            return;
        }
        $country = self::resolve_country();
        if ($country && in_array($country, $blocklist, true)) {
            status_header(403);
            nocache_headers();
            header('Content-Type: application/json');
            echo wp_json_encode([
                'error' => 'blocked_by_defen_so',
                'reason' => 'geo_block',
                'country' => $country,
            ]);
            exit;
        }
    }

    /** @return string|null 2-letter uppercase country code, or null on any failure. */
    private static function resolve_country(): ?string
    {
        if (isset($_SERVER['HTTP_CF_IPCOUNTRY'])) {
            $c = strtoupper((string) $_SERVER['HTTP_CF_IPCOUNTRY']);
            if (preg_match('/^[A-Z]{2}$/', $c)) {
                return $c;
            }
        }
        $ip = isset($_SERVER['REMOTE_ADDR']) ? (string) $_SERVER['REMOTE_ADDR'] : '';
        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return null;
        }
        // Cache by /24 so nearby requests don't refetch. Keeps geoip cheap.
        $key = 'defenso_geo_'.md5(preg_replace('/\.\d+$/', '.0', $ip));
        $cached = get_transient($key);
        if ($cached !== false) {
            return $cached === '__null__' ? null : (string) $cached;
        }
        $response = wp_remote_get('http://ip-api.com/line/'.rawurlencode($ip).'?fields=countryCode', [
            'timeout' => 2,
            'blocking' => true,
        ]);
        if (is_wp_error($response)) {
            set_transient($key, '__null__', 3600);
            return null;
        }
        $body = trim((string) wp_remote_retrieve_body($response));
        if (preg_match('/^[A-Z]{2}$/', $body)) {
            set_transient($key, $body, 86400);
            return $body;
        }
        set_transient($key, '__null__', 3600);
        return null;
    }
}
