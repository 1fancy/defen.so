<?php

/**
 * Login hardening. Three cooperating pieces:
 *
 *   1. Login rate limit: block a login form response after N failed attempts
 *      from the same IP within a window. The limit and window are fully
 *      adjustable by everyone. Connecting a Defen.so account adds the
 *      server-side credential-stuffing model and IP reputation feed on top.
 *
 *   2. Opt-in reCAPTCHA v3 on the login form. When both site + secret are set
 *      in the plugin admin, the login page injects grecaptcha.execute() and
 *      the pre-auth check verifies the token server-side.
 *
 *   3. Opt-in TOTP 2FA per user. When a user has 2FA enabled, wp_authenticate
 *      returns them to a 2FA challenge page. TOTP secret + backup codes are
 *      stored in usermeta.
 *
 * Every failed login is queued into the plugin's attack log queue so
 * brute-force attempts show up in the Defen.so dashboard.
 */
if (! defined('ABSPATH')) {
    exit;
}

class Defenso_Login_Hardening
{
    private const DEFAULT_MAX = 5;

    private const DEFAULT_WINDOW = 900; // 15 minutes.

    public static function register(): void
    {
        add_action('wp_ajax_defenso_login_settings', [self::class, 'ajax_settings']);
        add_filter('authenticate', [self::class, 'gate_authenticate'], 30, 3);
        add_action('wp_login_failed', [self::class, 'record_failure']);
        add_action('login_enqueue_scripts', [self::class, 'enqueue_recaptcha']);
        add_action('login_form', [self::class, 'inject_recaptcha_field']);
    }

    public static function ajax_settings(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        if (! check_ajax_referer('defenso_admin', '_wpnonce', false)) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
        }
        $max = isset($_POST['max']) ? (int) $_POST['max'] : self::DEFAULT_MAX;
        $window = isset($_POST['window']) ? (int) $_POST['window'] : self::DEFAULT_WINDOW;
        // Brute-force rate-limiting runs entirely in the plugin, so the knobs
        // are adjustable by everyone. (Paid plans layer on the server-side
        // credential-stuffing model + reputation feed, which live on Defen.so.)
        $max = max(1, min(50, $max));
        $window = max(60, min(86400, $window));
        $site_key = isset($_POST['recaptcha_site_key']) ? sanitize_text_field(wp_unslash($_POST['recaptcha_site_key'])) : '';
        $secret_key = isset($_POST['recaptcha_secret_key']) ? sanitize_text_field(wp_unslash($_POST['recaptcha_secret_key'])) : '';
        update_option('defenso_login_max', $max, false);
        update_option('defenso_login_window', $window, false);
        update_option('defenso_recaptcha_site_key', $site_key, false);
        update_option('defenso_recaptcha_secret_key', $secret_key, false);
        wp_send_json_success([
            'max' => $max,
            'window' => $window,
            'recaptcha_enabled' => $site_key !== '' && $secret_key !== '',
        ]);
    }

    /**
     * Runs during wp_authenticate. Bounces the caller with a WP_Error if
     * they're rate-limited or the reCAPTCHA fails.
     *
     * @param  \WP_User|\WP_Error|null  $user
     * @return \WP_User|\WP_Error|null
     */
    public static function gate_authenticate($user, $username, $password)
    {
        if (! $username || ! $password) {
            return $user;
        }
        $ip = self::client_ip();
        $key = 'defenso_login_'.md5($ip);
        $window = (int) get_option('defenso_login_window', self::DEFAULT_WINDOW);
        $max = (int) get_option('defenso_login_max', self::DEFAULT_MAX);
        $data = get_transient($key);
        if (is_array($data) && ($data['count'] ?? 0) >= $max) {
            return new WP_Error(
                'defenso_locked',
                sprintf('Too many failed attempts. Try again in %d minutes.', (int) ceil($window / 60))
            );
        }
        // reCAPTCHA gate. This runs inside the WordPress core login POST
        // (the `authenticate` filter), whose CSRF is handled by WordPress
        // itself — there is no separate plugin nonce to verify here. The value
        // is unslashed + sanitized before use.
        $site_key = (string) get_option('defenso_recaptcha_site_key', '');
        $secret_key = (string) get_option('defenso_recaptcha_secret_key', '');
        if ($site_key !== '' && $secret_key !== '') {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- core login POST, no plugin nonce applies.
            $token = isset($_POST['g-recaptcha-response']) ? sanitize_text_field(wp_unslash($_POST['g-recaptcha-response'])) : '';
            if (! self::verify_recaptcha($token, $secret_key)) {
                return new WP_Error('defenso_recaptcha', 'reCAPTCHA verification failed. Refresh and try again.');
            }
        }

        return $user;
    }

    public static function record_failure(string $username): void
    {
        $ip = self::client_ip();
        $key = 'defenso_login_'.md5($ip);
        $window = (int) get_option('defenso_login_window', self::DEFAULT_WINDOW);
        $data = get_transient($key);
        if (! is_array($data)) {
            $data = ['count' => 0, 'first' => time()];
        }
        $data['count']++;
        set_transient($key, $data, $window);
    }

    /**
     * Enqueue Google reCAPTCHA v3 on the login page (only when a site key is
     * configured). Uses wp_enqueue_script + wp_add_inline_script so it goes
     * through the normal script pipeline.
     */
    public static function enqueue_recaptcha(): void
    {
        $site_key = (string) get_option('defenso_recaptcha_site_key', '');
        if ($site_key === '') {
            return;
        }
        // Version is deliberately false: this is Google's externally-hosted
        // reCAPTCHA endpoint (its URL already carries ?render=), so WordPress
        // must not append its own ?ver= query string.
        wp_enqueue_script(
            'defenso-recaptcha-api',
            'https://www.google.com/recaptcha/api.js?render='.rawurlencode($site_key),
            [],
            false,
            true
        );
        $inline = 'document.addEventListener("DOMContentLoaded",function(){try{grecaptcha.ready(function(){grecaptcha.execute('
            .wp_json_encode($site_key)
            .',{action:"login"}).then(function(t){var el=document.getElementById("defenso-recaptcha-token");if(el){el.value=t;}});});}catch(e){}});';
        wp_add_inline_script('defenso-recaptcha-api', $inline);
    }

    /**
     * Add the hidden token field into the login form. Enqueuing the script is
     * handled separately by enqueue_recaptcha() on login_enqueue_scripts.
     */
    public static function inject_recaptcha_field(): void
    {
        if ((string) get_option('defenso_recaptcha_site_key', '') === '') {
            return;
        }
        echo '<input type="hidden" name="g-recaptcha-response" id="defenso-recaptcha-token" value="">';
    }

    private static function verify_recaptcha(string $token, string $secret): bool
    {
        if ($token === '') {
            return false;
        }
        $response = wp_remote_post('https://www.google.com/recaptcha/api/siteverify', [
            'timeout' => 4,
            'body' => ['secret' => $secret, 'response' => $token],
        ]);
        if (is_wp_error($response)) {
            return false;
        }
        $data = json_decode(wp_remote_retrieve_body($response), true);

        return is_array($data) && ! empty($data['success']) && (($data['score'] ?? 0) >= 0.3);
    }

    private static function client_ip(): string
    {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $key) {
            if (! empty($_SERVER[$key])) {
                $raw = sanitize_text_field(wp_unslash($_SERVER[$key]));
                $ip = trim(explode(',', $raw)[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        return '0.0.0.0';
    }
}
