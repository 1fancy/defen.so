<?php

/**
 * Local path rate-limiting. The site owner defines slug rules — an exact path
 * or a wildcard pattern (e.g. `/wp-login.php`, `/wp-json/*`, `/checkout*`) — and
 * a per-IP budget (N requests per window). Excess requests get a 429 with a
 * Retry-After header.
 *
 * Runs entirely locally on `init` (priority 2, after geo-block, before the WAF).
 * No account needed — it's the owner's own WordPress. Counters live in short
 * transients keyed by rule + client IP, so the cost is one object-cache read
 * per matching rule.
 *
 * Free tier: up to DEFENSO_RL_FREE_RULES active rules run locally. Adding more
 * prompts a free Defen.so sign-up (which lifts the cap and adds the managed
 * edge rate-limiter + attack log on top). Rules already saved keep working even
 * past the cap — we never disable protection someone already configured.
 *
 * Rules stored in wp_options['defenso_rate_limits'] as a list of:
 *   ['pattern' => string, 'limit' => int, 'window' => int, 'enabled' => bool]
 */
if (! defined('ABSPATH')) {
    exit;
}

if (! defined('DEFENSO_RL_FREE_RULES')) {
    define('DEFENSO_RL_FREE_RULES', 3);
}

class Defenso_Rate_Limit
{
    const OPTION = 'defenso_rate_limits';

    public static function register(): void
    {
        add_action('wp_ajax_defenso_rl_save', [self::class, 'ajax_save']);
        add_action('init', [self::class, 'maybe_limit'], 2);
    }

    /** @return array<int,array{pattern:string,limit:int,window:int,enabled:bool}> */
    public static function get_rules(): array
    {
        $rules = get_option(self::OPTION, []);
        if (! is_array($rules)) {
            return [];
        }
        $clean = [];
        foreach ($rules as $r) {
            if (! is_array($r) || empty($r['pattern'])) {
                continue;
            }
            $clean[] = [
                'pattern' => (string) $r['pattern'],
                'limit' => max(1, (int) ($r['limit'] ?? 60)),
                'window' => max(1, (int) ($r['window'] ?? 60)),
                'enabled' => ! empty($r['enabled']),
            ];
        }

        return $clean;
    }

    /**
     * Whether the free local cap has been reached. Connecting an account lifts
     * it. We compare against the count of ENABLED rules so a user can keep a few
     * drafts disabled without burning their free slots.
     */
    public static function is_capped(): bool
    {
        if (get_option('defenso_api_token')) {
            return false;
        }
        $enabled = 0;
        foreach (self::get_rules() as $r) {
            if ($r['enabled']) {
                $enabled++;
            }
        }

        return $enabled >= DEFENSO_RL_FREE_RULES;
    }

    public static function ajax_save(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => __('Permission denied', 'defen-so-connector')], 403);
        }
        if (! check_ajax_referer('defenso_admin', '_wpnonce', false)) {
            wp_send_json_error(['message' => __('Invalid nonce', 'defen-so-connector')], 403);
        }

        // The UI posts the full rule list as JSON so add/edit/delete/reorder all
        // go through one endpoint.
        $raw = isset($_POST['rules']) ? wp_unslash($_POST['rules']) : '[]';
        $decoded = json_decode((string) $raw, true);
        if (! is_array($decoded)) {
            $decoded = [];
        }

        $rules = [];
        $enabled_count = 0;
        $connected = (bool) get_option('defenso_api_token');
        foreach ($decoded as $r) {
            if (! is_array($r)) {
                continue;
            }
            $pattern = isset($r['pattern']) ? self::sanitize_pattern((string) $r['pattern']) : '';
            if ($pattern === '') {
                continue;
            }
            $enabled = ! empty($r['enabled']);
            // Enforce the free cap on the number of ENABLED rules. Extra rules are
            // still saved, just forced disabled, so the owner keeps their config
            // and can flip them on after connecting.
            if ($enabled && ! $connected && $enabled_count >= DEFENSO_RL_FREE_RULES) {
                $enabled = false;
            }
            if ($enabled) {
                $enabled_count++;
            }
            $rules[] = [
                'pattern' => $pattern,
                'limit' => min(100000, max(1, (int) ($r['limit'] ?? 60))),
                'window' => min(3600, max(1, (int) ($r['window'] ?? 60))),
                'enabled' => $enabled,
            ];
            // Hard ceiling on stored rules to keep the option row small.
            if (count($rules) >= 50) {
                break;
            }
        }

        update_option(self::OPTION, $rules, false);
        wp_send_json_success([
            'rules' => $rules,
            'capped' => self::is_capped(),
            'free_rules' => DEFENSO_RL_FREE_RULES,
        ]);
    }

    /**
     * Normalise a user-entered slug/pattern to a leading-slash path with at most
     * one trailing `*` wildcard. Strips scheme/host if the user pasted a full URL.
     */
    public static function sanitize_pattern(string $raw): string
    {
        $raw = trim($raw);
        if ($raw === '') {
            return '';
        }
        // If a full URL was pasted, keep only the path.
        if (preg_match('~^https?://~i', $raw)) {
            $path = wp_parse_url($raw, PHP_URL_PATH);
            $raw = is_string($path) ? $path : '';
        }
        // Keep a trailing wildcard marker, sanitize the rest as a URL path.
        $wild = false;
        if (substr($raw, -1) === '*') {
            $wild = true;
            $raw = rtrim($raw, '*');
        }
        $raw = '/'.ltrim($raw, '/');
        // Allow typical path characters only.
        $raw = preg_replace('~[^A-Za-z0-9/._\-]~', '', $raw);
        if ($raw === '' || $raw === false) {
            return '';
        }

        return $wild ? $raw.'*' : $raw;
    }

    public static function maybe_limit(): void
    {
        if (is_admin() || wp_doing_cron() || wp_doing_ajax()) {
            return;
        }
        $rules = self::get_rules();
        if (empty($rules)) {
            return;
        }
        $path = self::current_path();
        if ($path === '') {
            return;
        }
        $ip = self::client_ip();
        if ($ip === '') {
            return;
        }

        foreach ($rules as $i => $rule) {
            if (! $rule['enabled'] || ! self::path_matches($path, $rule['pattern'])) {
                continue;
            }
            $key = 'defenso_rl_'.$i.'_'.md5($rule['pattern'].'|'.$ip);
            $hits = (int) get_transient($key);
            if ($hits >= $rule['limit']) {
                self::reject($rule['window']);
            }
            // First hit in the window seeds the counter with the window TTL;
            // subsequent hits just increment without extending it (fixed window).
            if ($hits === 0) {
                set_transient($key, 1, $rule['window']);
            } else {
                set_transient($key, $hits + 1, $rule['window']);
            }

            return; // one matching rule is enough
        }
    }

    private static function reject(int $window): void
    {
        status_header(429);
        nocache_headers();
        header('Retry-After: '.max(1, $window));
        header('Content-Type: application/json');
        echo wp_json_encode([
            'error' => 'rate_limited_by_defen_so',
            'reason' => 'rate_limit',
            'retry_after' => max(1, $window),
        ]);
        exit;
    }

    /** Match a request path against a rule pattern (exact, or trailing `*`). */
    private static function path_matches(string $path, string $pattern): bool
    {
        if (substr($pattern, -1) === '*') {
            $prefix = rtrim($pattern, '*');

            return strpos($path, $prefix) === 0;
        }

        return $path === $pattern;
    }

    private static function current_path(): string
    {
        $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
        $path = wp_parse_url($uri, PHP_URL_PATH);

        return is_string($path) ? $path : '';
    }

    /** Best-effort client IP; prefers a Cloudflare / proxy header, then REMOTE_ADDR. */
    private static function client_ip(): string
    {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $h) {
            if (empty($_SERVER[$h])) {
                continue;
            }
            $val = sanitize_text_field(wp_unslash($_SERVER[$h]));
            // X-Forwarded-For can be a list; take the first.
            $val = trim(explode(',', $val)[0]);
            if (filter_var($val, FILTER_VALIDATE_IP)) {
                return $val;
            }
        }

        return '';
    }
}
