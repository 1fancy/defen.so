<?php

/**
 * Plugin Name: Defen.so Connector — WAF, uptime, upload scanning
 * Plugin URI: https://defen.so/wordpress
 * Description: Official Defen.so connector for WordPress. One-click connect to Defen.so, block SQL injection / XSS / bot scanners at the edge, scan every uploaded file for polyglots + malware, watch uptime, and detect brute-force logins. Manage everything from your Defen.so dashboard at https://defen.so.
 * Version: 1.0.0
 * Author: Defen.so
 * Author URI: https://defen.so
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: defen-so-connector
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */
if (! defined('ABSPATH')) {
    exit;
}

define('DEFENSO_VERSION', '1.0.0');
define('DEFENSO_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('DEFENSO_PLUGIN_URL', plugin_dir_url(__FILE__));
define('DEFENSO_APP_URL', 'https://app.defen.so');
define('DEFENSO_API_BASE', 'https://app.defen.so/api');
define('DEFENSO_OAUTH_URL', DEFENSO_APP_URL.'/oauth/wp-connect');

/**
 * Main plugin class. Singleton.
 *
 * Surfaces:
 *   - Admin menu "Defen.so" with the connect / connected / logs view.
 *   - Activation hook sets a one-shot flag → next admin page load redirects
 *     the site owner to the setup wizard.
 *   - admin-ajax endpoint defenso_save_key: receives the API key from the
 *     OAuth popup (postMessage flow) and persists it.
 *   - REST route defenso/v1/status so the app can verify the plugin is live.
 *   - Runtime hooks:
 *       - init: pull the cached WAF policy, run inspect() on every request
 *       - wp_handle_upload_prefilter: scan uploaded files
 *       - wp_login_failed + wp_authenticate: brute-force + credential-stuffing signals
 *       - shutdown: batch-ship attack logs to Defen.so
 */
class Defenso_Connector
{
    private static $instance = null;

    /** @var array{action:string,rule:?string,reason:?string}|null */
    private $current_verdict = null;

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    private function __construct()
    {
        $this->load_modules();
        $this->init_hooks();
    }

    /**
     * MalCare-parity feature modules. Each one is self-contained and only
     * registers its own admin-ajax callbacks — no runtime overhead when not
     * being used.
     */
    private function load_modules(): void
    {
        require_once DEFENSO_PLUGIN_DIR.'includes/malware-scan.php';
        require_once DEFENSO_PLUGIN_DIR.'includes/file-integrity.php';
        require_once DEFENSO_PLUGIN_DIR.'includes/vuln-scan.php';
        require_once DEFENSO_PLUGIN_DIR.'includes/geo-block.php';
        if (class_exists('Defenso_Malware_Scan')) {
            Defenso_Malware_Scan::register();
        }
        if (class_exists('Defenso_File_Integrity')) {
            Defenso_File_Integrity::register();
        }
        if (class_exists('Defenso_Vuln_Scan')) {
            Defenso_Vuln_Scan::register();
        }
        if (class_exists('Defenso_Geo_Block')) {
            Defenso_Geo_Block::register();
        }
    }

    private function init_hooks(): void
    {
        add_action('rest_api_init', [$this, 'register_rest_routes']);
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);
        add_action('admin_init', [$this, 'maybe_redirect_to_setup']);
        add_action('wp_ajax_defenso_save_key', [$this, 'ajax_save_key']);
        add_action('wp_ajax_defenso_disconnect', [$this, 'ajax_disconnect']);
        add_action('wp_ajax_defenso_status', [$this, 'ajax_status']);
        add_action('wp_ajax_defenso_site_info', [$this, 'ajax_site_info']);
        add_filter('plugin_action_links_'.plugin_basename(__FILE__), [$this, 'plugin_action_links']);
        add_action('wp_dashboard_setup', [$this, 'register_dashboard_widget']);

        // Runtime protection hooks — only wired when we have a token so a
        // disconnected plugin has zero runtime overhead.
        if (get_option('defenso_api_token')) {
            add_action('init', [$this, 'inspect_request'], 1);
            add_filter('wp_handle_upload_prefilter', [$this, 'scan_upload']);
            add_action('wp_login_failed', [$this, 'on_login_failed']);
            add_action('shutdown', [$this, 'flush_attack_log']);
        }
    }

    public static function activate(): void
    {
        if (! get_option('defenso_api_token')) {
            update_option('defenso_setup_needed', true);
        }
    }

    public static function deactivate(): void
    {
        wp_clear_scheduled_hook('defenso_policy_refresh');
    }

    public function maybe_redirect_to_setup(): void
    {
        if (! get_option('defenso_setup_needed')) {
            return;
        }
        if (wp_doing_ajax() || wp_doing_cron() || (defined('REST_REQUEST') && REST_REQUEST)) {
            return;
        }
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : '';
        if ($page === 'defen-so') {
            delete_option('defenso_setup_needed');

            return;
        }
        delete_option('defenso_setup_needed');
        wp_safe_redirect(admin_url('admin.php?page=defen-so&onboarding=1'));
        exit;
    }

    public function ajax_save_key(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        if (! check_ajax_referer('defenso_oauth', '_wpnonce', false)) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
        }
        $key = isset($_POST['api_key']) ? sanitize_text_field(wp_unslash($_POST['api_key'])) : '';
        if (! preg_match('/^df_(live|test)_[A-Za-z0-9]{20,80}$/', $key)) {
            wp_send_json_error(['message' => 'Invalid key format'], 400);
        }
        update_option('defenso_api_token', $key);
        update_option('defenso_connected_at', current_time('mysql'));

        // Persist the plan label the callback sent so the admin page can
        // render it immediately, before the first site-info poll returns.
        $plan_label = isset($_POST['plan_label']) ? sanitize_text_field(wp_unslash($_POST['plan_label'])) : '';
        if ($plan_label !== '' && preg_match('/^[A-Za-z]{3,20}$/', $plan_label)) {
            update_option('defenso_plan_label', $plan_label);
        }

        // Fetch the policy immediately so protection is live from the next request.
        $this->refresh_policy();
        wp_send_json_success([
            'message' => 'Connected',
            'redirect' => admin_url('admin.php?page=defen-so&connected=1'),
        ]);
    }

    /**
     * Poll the app for this WP site's current plan + verified state so the
     * admin badge stays live when the owner upgrades from the dashboard.
     */
    public function ajax_site_info(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        $token = get_option('defenso_api_token');
        if (! $token) {
            wp_send_json_error(['message' => 'Not connected'], 400);
        }
        $response = wp_remote_post(DEFENSO_API_BASE.'/wp/site-info', [
            'timeout' => 4,
            'headers' => [
                'Authorization' => 'Bearer '.$token,
                'Content-Type' => 'application/json',
                'User-Agent' => 'Defenso-WP/'.DEFENSO_VERSION,
            ],
            'body' => wp_json_encode(['wp_url' => get_site_url()]),
        ]);
        if (is_wp_error($response)) {
            wp_send_json_error(['message' => $response->get_error_message()], 502);
        }
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        if (! is_array($data)) {
            wp_send_json_error(['message' => 'Bad response'], 502);
        }
        if (isset($data['plan_label']) && is_string($data['plan_label'])) {
            update_option('defenso_plan_label', $data['plan_label']);
        }
        if (isset($data['verified'])) {
            update_option('defenso_verified', $data['verified'] ? '1' : '0');
        }
        wp_send_json_success($data);
    }

    public function ajax_disconnect(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        if (! check_ajax_referer('defenso_admin', '_wpnonce', false)) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
        }
        delete_option('defenso_api_token');
        delete_option('defenso_connected_at');
        delete_option('defenso_policy_cache');
        delete_option('defenso_policy_refreshed_at');
        delete_option('defenso_attack_log_queue');
        delete_option('defenso_plan_label');
        delete_option('defenso_verified');
        wp_send_json_success(['message' => 'Disconnected']);
    }

    public function ajax_status(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        wp_send_json_success([
            'connected' => (bool) get_option('defenso_api_token'),
            'connected_at' => get_option('defenso_connected_at'),
            'policy_refreshed_at' => get_option('defenso_policy_refreshed_at'),
            'rules_count' => is_array(get_option('defenso_policy_cache')) ? count(get_option('defenso_policy_cache')['rules'] ?? []) : 0,
            'queued_logs' => is_array(get_option('defenso_attack_log_queue')) ? count(get_option('defenso_attack_log_queue')) : 0,
        ]);
    }

    public function plugin_action_links($links): array
    {
        $settings = '<a href="'.esc_url(admin_url('admin.php?page=defen-so')).'">'.__('Settings', 'defen-so-connector').'</a>';
        array_unshift($links, $settings);

        return $links;
    }

    public function register_rest_routes(): void
    {
        register_rest_route('defenso/v1', '/status', [
            'methods' => 'GET',
            'callback' => [$this, 'handle_status'],
            'permission_callback' => [$this, 'check_auth'],
        ]);
    }

    public function check_auth(WP_REST_Request $request): bool
    {
        $token = get_option('defenso_api_token');
        if (! $token) {
            return false;
        }
        $auth = $request->get_header('authorization');
        if (! $auth || strpos($auth, 'Bearer ') !== 0) {
            return false;
        }

        return hash_equals($token, substr($auth, 7));
    }

    public function handle_status(WP_REST_Request $request)
    {
        return rest_ensure_response([
            'connected' => true,
            'plugin_version' => DEFENSO_VERSION,
            'wordpress_version' => get_bloginfo('version'),
            'php_version' => phpversion(),
            'site_url' => get_site_url(),
            'site_name' => get_bloginfo('name'),
            'rules_count' => is_array(get_option('defenso_policy_cache')) ? count(get_option('defenso_policy_cache')['rules'] ?? []) : 0,
            'queued_logs' => is_array(get_option('defenso_attack_log_queue')) ? count(get_option('defenso_attack_log_queue')) : 0,
        ]);
    }

    /* ---------------------------------------------------------------------
     * Runtime protection
     * -------------------------------------------------------------------*/

    /**
     * The WAF: on every request, pull the cached rules + match against the
     * URL / query / body / headers. Block / challenge / deceive based on
     * the rule's action. Fails open — if we have no policy, we allow.
     */
    public function inspect_request(): void
    {
        // Skip admin, cron, REST calls to defenso/v1/*, and the plugin's own
        // admin-ajax hits — otherwise we lock the site owner out.
        if (is_admin() || wp_doing_cron() || wp_doing_ajax()) {
            return;
        }
        if (defined('REST_REQUEST') && REST_REQUEST) {
            $route = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
            if (strpos($route, '/wp-json/defenso/') !== false) {
                return;
            }
        }

        $policy = $this->get_policy();
        if (! $policy || empty($policy['rules'])) {
            return;
        }

        $request_url = isset($_SERVER['REQUEST_URI']) ? (string) wp_unslash($_SERVER['REQUEST_URI']) : '/';
        $query_string = isset($_SERVER['QUERY_STRING']) ? (string) wp_unslash($_SERVER['QUERY_STRING']) : '';
        $body_raw = file_get_contents('php://input');
        $headers_line = '';
        foreach ($_SERVER as $k => $v) {
            if (strpos($k, 'HTTP_') === 0) {
                $headers_line .= ' '.(string) $v;
            }
        }

        foreach ($policy['rules'] as $rule) {
            $target = $rule['target'] ?? 'url';
            $haystack = $request_url;
            if ($target === 'query') {
                $haystack = $query_string;
            } elseif ($target === 'body') {
                $haystack = (string) $body_raw;
            } elseif ($target === 'headers') {
                $haystack = $headers_line;
            }

            $flags = isset($rule['flags']) ? (string) $rule['flags'] : '';
            $pattern = '~'.str_replace('~', '\\~', $rule['pattern']).'~'.$flags;

            if (@preg_match($pattern, $haystack)) {
                $action = $rule['action'] ?? 'block';
                $this->current_verdict = [
                    'action' => $action,
                    'rule' => $rule['id'] ?? null,
                    'reason' => 'Matched '.($rule['id'] ?? 'rule').' on '.$target,
                ];
                $this->queue_attack_log($request_url, $action, $rule['id'] ?? null, $this->current_verdict['reason']);

                if ($action === 'block') {
                    status_header(403);
                    nocache_headers();
                    header('Content-Type: application/json');
                    echo wp_json_encode(['error' => 'Blocked by Defen.so', 'rule' => $rule['id'] ?? null]);
                    exit;
                }
                if ($action === 'challenge') {
                    // WP has no native challenge; downgrade to 429 with a Retry-After.
                    status_header(429);
                    header('Retry-After: 30');
                    header('Content-Type: application/json');
                    echo wp_json_encode(['error' => 'Rate-limited by Defen.so']);
                    exit;
                }
                if ($action === 'deceive') {
                    header('Content-Type: application/json');
                    echo wp_json_encode(['ok' => true, 'data' => []]);
                    exit;
                }

                return; // allow — first match wins
            }
        }
    }

    /**
     * Upload scan: rejects files whose extension is in a dangerous list, or
     * whose declared MIME + magic bytes disagree (polyglot detection). Small
     * and fast — offloading to defen.so/api/uploads/scan happens only for
     * paid tiers where the ClamAV pipeline is worth the round-trip.
     */
    public function scan_upload(array $file): array
    {
        $dangerous_ext = ['php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'phps', 'py', 'pl', 'cgi', 'sh', 'bash', 'exe', 'jar', 'html', 'htm', 'svg'];
        $name = isset($file['name']) ? (string) $file['name'] : '';
        $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
        if ($ext !== '' && in_array($ext, $dangerous_ext, true)) {
            $file['error'] = 'This file type is not permitted (blocked by Defen.so).';
            $this->queue_attack_log('/wp-content/uploads/'.$name, 'block', 'upload.dangerous_ext', 'Extension .'.$ext);

            return $file;
        }
        // Magic-byte sniff on the first 12 bytes vs declared MIME.
        if (isset($file['tmp_name']) && is_readable($file['tmp_name'])) {
            $head = (string) @file_get_contents($file['tmp_name'], false, null, 0, 12);
            if ($this->looks_polyglot($head, isset($file['type']) ? (string) $file['type'] : '')) {
                $file['error'] = 'File appears to be a polyglot (mismatched magic bytes vs declared type).';
                $this->queue_attack_log('/wp-content/uploads/'.$name, 'block', 'upload.polyglot', 'Magic bytes disagree with MIME '.($file['type'] ?? ''));
            }
        }

        return $file;
    }

    private function looks_polyglot(string $head, string $mime): bool
    {
        // Declared image but body starts with <?php / <script — classic polyglot.
        if (stripos($mime, 'image/') === 0 && preg_match('/^(<\?php|<script|<html)/i', $head)) {
            return true;
        }

        return false;
    }

    /**
     * Failed login = potential brute-force signal. We log to the attack
     * queue so the site owner sees it in the dashboard and can decide
     * whether to add a WAF rule blocking that source.
     */
    public function on_login_failed(string $username): void
    {
        $this->queue_attack_log(
            '/wp-login.php',
            'allow',
            'auth.failed_login',
            'Failed login for '.sanitize_user($username)
        );
    }

    /**
     * Batched shipping of attack logs. Ships up to 50 at a time on shutdown
     * to keep the hot-path fast. Fails-silent on network errors so a
     * defen.so outage never breaks the WP site.
     */
    public function flush_attack_log(): void
    {
        $queue = get_option('defenso_attack_log_queue', []);
        if (! is_array($queue) || empty($queue)) {
            return;
        }
        $token = get_option('defenso_api_token');
        if (! $token) {
            return;
        }
        $batch = array_slice($queue, 0, 50);
        $remaining = array_slice($queue, 50);
        update_option('defenso_attack_log_queue', $remaining);

        wp_remote_post(DEFENSO_API_BASE.'/attacks/ingest', [
            'timeout' => 3,
            'blocking' => false,
            'redirection' => 0,
            'headers' => [
                'Content-Type' => 'application/json',
                'Authorization' => 'Bearer '.$token,
                'User-Agent' => 'Defenso-WP/'.DEFENSO_VERSION,
            ],
            'body' => wp_json_encode(['logs' => $batch]),
        ]);
    }

    private function queue_attack_log(string $url, string $action, ?string $rule_id, string $reason): void
    {
        $queue = get_option('defenso_attack_log_queue', []);
        if (! is_array($queue)) {
            $queue = [];
        }
        if (count($queue) >= 500) {
            // Cap the queue so a persistent flood can't fill the options table.
            array_shift($queue);
        }
        $queue[] = [
            'at' => (int) (microtime(true) * 1000),
            'verdict' => [
                'action' => $action,
                'rule' => ['id' => $rule_id],
                'reason' => $reason,
            ],
            'request' => [
                'method' => isset($_SERVER['REQUEST_METHOD']) ? sanitize_key(wp_unslash($_SERVER['REQUEST_METHOD'])) : 'GET',
                'url' => (function_exists('home_url') ? home_url($url) : $url),
                'ip' => isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : null,
            ],
        ];
        update_option('defenso_attack_log_queue', $queue, false);
    }

    /**
     * Pull the WAF policy from Defen.so. Cached for 10 minutes; expired
     * cache still gets served (stale-while-revalidate) so latency stays flat.
     */
    private function get_policy(): ?array
    {
        $cache = get_option('defenso_policy_cache');
        $ts = (int) get_option('defenso_policy_refreshed_at', 0);
        if ($cache && (time() - $ts) < 600) {
            return $cache;
        }
        if ($cache && (time() - $ts) < 86400) {
            // Stale — kick a refresh in the background but serve the old copy.
            if (! wp_next_scheduled('defenso_policy_refresh')) {
                wp_schedule_single_event(time() + 5, 'defenso_policy_refresh');
            }

            return $cache;
        }
        $this->refresh_policy();

        return get_option('defenso_policy_cache') ?: null;
    }

    private function refresh_policy(): void
    {
        $token = get_option('defenso_api_token');
        if (! $token) {
            return;
        }
        $response = wp_remote_get(DEFENSO_API_BASE.'/policy', [
            'timeout' => 4,
            'headers' => [
                'Authorization' => 'Bearer '.$token,
                'User-Agent' => 'Defenso-WP/'.DEFENSO_VERSION,
            ],
        ]);
        if (is_wp_error($response)) {
            return;
        }
        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);
        if (! is_array($data) || empty($data['rules'])) {
            return;
        }
        update_option('defenso_policy_cache', $data, false);
        update_option('defenso_policy_refreshed_at', time());
    }

    /* ---------------------------------------------------------------------
     * Admin UI
     * -------------------------------------------------------------------*/

    public function add_admin_menu(): void
    {
        add_menu_page(
            'Defen.so',
            'Defen.so',
            'manage_options',
            'defen-so',
            [$this, 'render_admin_page'],
            'dashicons-shield-alt',
            65
        );
    }

    public function enqueue_admin_scripts($hook): void
    {
        if (strpos((string) $hook, 'defen-so') === false) {
            return;
        }
        wp_enqueue_style('defenso-admin', DEFENSO_PLUGIN_URL.'assets/css/admin.css', [], DEFENSO_VERSION);
        wp_enqueue_script('defenso-admin', DEFENSO_PLUGIN_URL.'assets/js/admin.js', ['jquery'], DEFENSO_VERSION, true);
        wp_localize_script('defenso-admin', 'DefensoAdmin', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'oauth_url' => DEFENSO_OAUTH_URL,
            'oauth_nonce' => wp_create_nonce('defenso_oauth'),
            'admin_nonce' => wp_create_nonce('defenso_admin'),
            'site_url' => get_site_url(),
            'app_url' => DEFENSO_APP_URL,
        ]);
    }

    public function render_admin_page(): void
    {
        include DEFENSO_PLUGIN_DIR.'views/admin-page.php';
    }

    public function register_dashboard_widget(): void
    {
        if (! current_user_can('manage_options')) {
            return;
        }
        wp_add_dashboard_widget('defenso_widget', 'Defen.so protection', [$this, 'render_dashboard_widget']);
    }

    public function render_dashboard_widget(): void
    {
        $connected = (bool) get_option('defenso_api_token');
        $queue = get_option('defenso_attack_log_queue', []);
        $rules = is_array(get_option('defenso_policy_cache')) ? count(get_option('defenso_policy_cache')['rules'] ?? []) : 0;
        if (! $connected) {
            echo '<p>Not connected yet. <a href="'.esc_url(admin_url('admin.php?page=defen-so')).'">Connect this site</a> to enable the WAF, upload scan, and uptime monitor.</p>';

            return;
        }
        echo '<p><strong>'.esc_html($rules).'</strong> WAF rules active · <strong>'.esc_html(count(is_array($queue) ? $queue : [])).'</strong> events queued for shipping.</p>';
        echo '<p><a href="'.esc_url(DEFENSO_APP_URL).'" target="_blank">Open Defen.so dashboard →</a></p>';
    }
}

register_activation_hook(__FILE__, ['Defenso_Connector', 'activate']);
register_deactivation_hook(__FILE__, ['Defenso_Connector', 'deactivate']);

// Background policy refresh — fires 5s after the request that triggers it.
add_action('defenso_policy_refresh', function () {
    if (method_exists('Defenso_Connector', 'instance')) {
        // Use reflection to reach the private refresh_policy method for the cron hook.
        $c = Defenso_Connector::instance();
        $ref = new ReflectionMethod($c, 'refresh_policy');
        $ref->setAccessible(true);
        $ref->invoke($c);
    }
});

Defenso_Connector::instance();
