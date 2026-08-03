<?php

/**
 * Firewall-lite + WordPress hardening. A single settings-driven module that
 * bundles the cheap, self-contained WordPress protections every site should
 * have. Everything here runs entirely in the plugin — no account, no plan, no
 * external call. Each switch is individually toggleable from the admin page and
 * defaults to a safe value.
 *
 * Firewall-lite (runs on `init`, priority 2 — after geo-block, before the WAF):
 *   - Block known-bad / scanner user-agents (sqlmap, nikto, masscan, …).
 *   - Block common exploit request patterns in the URL / query string
 *     (../ traversal, eval() in querystring, wp-config probes, …).
 *   - Optionally disable XML-RPC entirely.
 *
 * Hardening:
 *   - Block user enumeration (?author=N redirect + REST /wp/v2/users for anon).
 *   - Remove the WordPress version generator meta tag.
 *   - Disable the theme/plugin file editor (DISALLOW_FILE_EDIT).
 *   - Send security response headers (X-Frame-Options, X-Content-Type-Options,
 *     Referrer-Policy, and an opt-in Strict-Transport-Security over HTTPS).
 *   - Comment/pingback spam hardening (drop pingbacks, X-Pingback header).
 *
 * Settings live in wp_options['defenso_hardening'] as a flat array of bools.
 * Blocked firewall hits are pushed into the plugin's attack-log queue via the
 * main connector so they surface in the Defen.so dashboard when connected.
 */
if (! defined('ABSPATH')) {
    exit;
}

class Defenso_Hardening
{
    private const OPT = 'defenso_hardening';

    /**
     * Default state for every switch. New installs get sane, non-breaking
     * defaults on: the firewall and header protections that never lock anyone
     * out. wp-login rename and HSTS stay off (they need a deliberate choice).
     *
     * @return array<string, bool>
     */
    public static function defaults(): array
    {
        return [
            'block_bad_bots' => true,
            'block_exploit_patterns' => true,
            'disable_xmlrpc' => false,
            'block_user_enum' => true,
            'remove_version' => true,
            'disable_file_edit' => true,
            'security_headers' => true,
            'hsts' => false,
            'comment_hardening' => true,
        ];
    }

    /**
     * @return array<string, bool>
     */
    public static function settings(): array
    {
        $saved = get_option(self::OPT, null);
        if (! is_array($saved)) {
            return self::defaults();
        }

        return array_merge(self::defaults(), array_map('boolval', $saved));
    }

    public static function is_on(string $key): bool
    {
        $s = self::settings();

        return ! empty($s[$key]);
    }

    public static function register(): void
    {
        add_action('wp_ajax_defenso_hardening_save', [self::class, 'ajax_save']);

        $s = self::settings();

        // ── Firewall-lite (front-of-request) ──
        add_action('init', [self::class, 'firewall'], 2);

        // ── XML-RPC ──
        if (! empty($s['disable_xmlrpc'])) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('xmlrpc_methods', [self::class, 'strip_xmlrpc_methods']);
        }

        // ── User-enumeration blocking ──
        if (! empty($s['block_user_enum'])) {
            add_action('template_redirect', [self::class, 'block_author_scan']);
            add_filter('rest_endpoints', [self::class, 'restrict_users_endpoint']);
        }

        // ── Version disclosure ──
        if (! empty($s['remove_version'])) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
        }

        // ── Disable the built-in file editor ──
        if (! empty($s['disable_file_edit']) && ! defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }

        // ── Security response headers ──
        if (! empty($s['security_headers'])) {
            add_action('send_headers', [self::class, 'send_security_headers']);
        }

        // ── Comment / pingback hardening ──
        if (! empty($s['comment_hardening'])) {
            add_filter('xmlrpc_methods', [self::class, 'drop_pingback_method']);
            add_filter('wp_headers', [self::class, 'strip_pingback_header']);
            add_filter('bloginfo_url', [self::class, 'strip_pingback_url'], 10, 2);
        }
    }

    public static function ajax_save(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        if (! check_ajax_referer('defenso_admin', '_wpnonce', false)) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
        }
        $out = [];
        foreach (array_keys(self::defaults()) as $key) {
            // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce checked above.
            $out[$key] = isset($_POST[$key]) && in_array((string) wp_unslash($_POST[$key]), ['1', 'true', 'on', 'yes'], true);
        }
        update_option(self::OPT, $out, false);
        wp_send_json_success(['settings' => $out]);
    }

    /* ---------------------------------------------------------------------
     * Firewall-lite
     * -------------------------------------------------------------------*/

    /**
     * Bad-bot + exploit-pattern gate. Runs before the cloud WAF so obvious
     * scanner traffic never reaches it. Skips admin, cron, and ajax so it can
     * never lock the site owner out.
     */
    public static function firewall(): void
    {
        if (is_admin() || wp_doing_cron() || wp_doing_ajax()) {
            return;
        }
        $s = self::settings();

        if (! empty($s['block_bad_bots'])) {
            $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) wp_unslash($_SERVER['HTTP_USER_AGENT']) : '';
            if ($ua !== '' && self::is_bad_bot($ua)) {
                self::deny('firewall.bad_bot', 'Blocked scanner user-agent');
            }
        }

        if (! empty($s['block_exploit_patterns'])) {
            // Raw request line — deliberately unsanitized so attack payloads
            // stay detectable. Only regex-matched below, never stored/echoed.
            // phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
            $uri = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '';
            $qs = isset($_SERVER['QUERY_STRING']) ? (string) wp_unslash($_SERVER['QUERY_STRING']) : '';
            // phpcs:enable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
            $hay = $uri.' '.rawurldecode($qs);
            if (self::matches_exploit($hay)) {
                self::deny('firewall.exploit_pattern', 'Blocked exploit request pattern');
            }
        }
    }

    private static function is_bad_bot(string $ua): bool
    {
        $patterns = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'nessus', 'openvas', 'acunetix',
            'nuclei', 'wpscan', 'dirbuster', 'gobuster', 'feroxbuster', 'zgrab',
            'zmeu', 'havij', 'arachni', 'metasploit', 'python-requests/0',
            'go-http-client', 'libwww-perl', 'muieblackcat', 'xrumer',
        ];
        $ua_l = strtolower($ua);
        foreach ($patterns as $p) {
            if (strpos($ua_l, $p) !== false) {
                return true;
            }
        }

        return false;
    }

    private static function matches_exploit(string $hay): bool
    {
        $patterns = [
            '~\.\./\.\./~',                       // directory traversal
            '~/etc/passwd~i',                     // LFI classic
            '~(?:php|data|file|expect)://~i',     // wrapper SSRF/LFI
            '~\b(?:eval|base64_decode|system|passthru|shell_exec)\s*\(~i', // code in querystring
            '~<script\b[^>]*>~i',                 // reflected XSS marker
            '~(?:union\s+select|select\s+.*\s+from\s+information_schema)~i', // SQLi
            '~wp-config\.php~i',                  // wp-config probe
            '~/\.(?:git|svn|env|htaccess|htpasswd)\b~i', // dotfile probe
            '~%00~',                              // null byte
        ];
        foreach ($patterns as $p) {
            if (@preg_match($p, $hay)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Emit a 403, queue the block into the connector's attack log, and stop.
     */
    private static function deny(string $rule, string $reason): void
    {
        if (class_exists('Defenso_Connector') && method_exists('Defenso_Connector', 'instance')) {
            $path = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
            Defenso_Connector::instance()->log_local_block($path, $rule, $reason);
        }
        status_header(403);
        nocache_headers();
        header('Content-Type: application/json');
        echo wp_json_encode(['error' => 'Blocked by Defen.so', 'rule' => $rule]);
        exit;
    }

    /* ---------------------------------------------------------------------
     * User-enumeration blocking
     * -------------------------------------------------------------------*/

    /**
     * Bounce ?author=N scans (which leak usernames via the redirect) to the
     * home page with a 403 for non-logged-in visitors.
     */
    public static function block_author_scan(): void
    {
        if (is_admin() || is_user_logged_in()) {
            return;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only enumeration guard on a public request.
        if (isset($_GET['author']) && preg_match('/^\d+$/', (string) wp_unslash($_GET['author']))) {
            status_header(403);
            nocache_headers();
            wp_die('Author enumeration is disabled.', 'Forbidden', ['response' => 403]);
        }
    }

    /**
     * Remove the REST users collection endpoints for unauthenticated callers so
     * /wp-json/wp/v2/users can't be scraped for usernames.
     *
     * @param  array<string, mixed>  $endpoints
     * @return array<string, mixed>
     */
    public static function restrict_users_endpoint(array $endpoints): array
    {
        if (is_user_logged_in()) {
            return $endpoints;
        }
        foreach (['/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)'] as $route) {
            if (isset($endpoints[$route])) {
                unset($endpoints[$route]);
            }
        }

        return $endpoints;
    }

    /* ---------------------------------------------------------------------
     * XML-RPC
     * -------------------------------------------------------------------*/

    /**
     * @param  array<string, mixed>  $methods
     * @return array<string, mixed>
     */
    public static function strip_xmlrpc_methods($methods): array
    {
        return [];
    }

    /* ---------------------------------------------------------------------
     * Security headers
     * -------------------------------------------------------------------*/

    public static function send_security_headers(): void
    {
        if (headers_sent()) {
            return;
        }
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('X-XSS-Protection: 0');
        if (self::is_on('hsts') && is_ssl()) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
    }

    /* ---------------------------------------------------------------------
     * Comment / pingback hardening
     * -------------------------------------------------------------------*/

    /**
     * @param  array<string, mixed>  $methods
     * @return array<string, mixed>
     */
    public static function drop_pingback_method($methods): array
    {
        unset($methods['pingback.ping'], $methods['pingback.extensions.getPingbacks']);

        return $methods;
    }

    /**
     * @param  array<string, string>  $headers
     * @return array<string, string>
     */
    public static function strip_pingback_header($headers): array
    {
        unset($headers['X-Pingback']);

        return $headers;
    }

    public static function strip_pingback_url($output, $show)
    {
        if ($show === 'pingback_url') {
            return '';
        }

        return $output;
    }
}
