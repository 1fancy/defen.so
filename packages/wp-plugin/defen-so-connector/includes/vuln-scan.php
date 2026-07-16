<?php
/**
 * Vulnerability scanner. Enumerates installed plugins + themes with their
 * versions, hits the app's /api/mcp/list_cves endpoint for each, and marks
 * anything that resolves to a CVE list as vulnerable.
 *
 * Free tier: manual scan, 1 per day. Pro tier: daily cron.
 *
 * @package DefensoConnector
 */

if (! defined('ABSPATH')) {
    exit;
}

class Defenso_Vuln_Scan
{
    private const FREE_COOLDOWN = 86400;

    public static function register(): void
    {
        add_action('wp_ajax_defenso_vuln_scan', [self::class, 'ajax_scan']);
    }

    public static function ajax_scan(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        if (! check_ajax_referer('defenso_admin', '_wpnonce', false)) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
        }
        $plan = strtolower((string) get_option('defenso_plan_label', 'Free'));
        $last = (int) get_option('defenso_vuln_last_run', 0);
        if ($plan === 'free' && $last && (time() - $last) < self::FREE_COOLDOWN) {
            $wait = (int) ceil((self::FREE_COOLDOWN - (time() - $last)) / 3600);
            wp_send_json_error([
                'message' => "Free tier: 1 vuln scan / day. Next in {$wait}h.",
                'upgrade_url' => 'https://app.defen.so',
            ], 429);
        }

        $token = get_option('defenso_api_token');
        if (! $token) {
            wp_send_json_error(['message' => 'Not connected.'], 400);
        }

        $inventory = self::inventory();
        $results = self::check_all($inventory, (string) $token);
        update_option('defenso_vuln_last_run', time(), false);
        update_option('defenso_vuln_findings', $results, false);

        $vuln_count = 0;
        foreach ($results as $r) {
            if (! empty($r['vulnerabilities'])) {
                $vuln_count++;
            }
        }
        wp_send_json_success([
            'checked' => count($results),
            'vulnerable' => $vuln_count,
            'findings' => $results,
        ]);
    }

    /**
     * @return array<int, array{name:string,slug:string,version:string,kind:string,ecosystem:string}>
     */
    private static function inventory(): array
    {
        $out = [];
        if (! function_exists('get_plugins')) {
            require_once ABSPATH.'wp-admin/includes/plugin.php';
        }
        foreach (get_plugins() as $file => $data) {
            $slug = current(explode('/', $file));
            $out[] = [
                'name' => (string) ($data['Name'] ?? $slug),
                'slug' => (string) $slug,
                'version' => (string) ($data['Version'] ?? ''),
                'kind' => 'plugin',
                'ecosystem' => 'wp-plugin',
            ];
        }
        foreach (wp_get_themes() as $slug => $theme) {
            $out[] = [
                'name' => $theme->get('Name'),
                'slug' => (string) $slug,
                'version' => (string) $theme->get('Version'),
                'kind' => 'theme',
                'ecosystem' => 'wp-theme',
            ];
        }
        return $out;
    }

    /**
     * @param array<int, array{name:string,slug:string,version:string,kind:string,ecosystem:string}> $inventory
     */
    private static function check_all(array $inventory, string $token): array
    {
        $api = defined('DEFENSO_API_BASE') ? DEFENSO_API_BASE : 'https://app.defen.so/api';
        $results = [];
        foreach ($inventory as $item) {
            $response = wp_remote_post($api.'/mcp/list_cves', [
                'timeout' => 4,
                'headers' => [
                    'Authorization' => 'Bearer '.$token,
                    'Content-Type' => 'application/json',
                    'User-Agent' => 'Defenso-WP/'.DEFENSO_VERSION,
                ],
                'body' => wp_json_encode([
                    'package' => $item['slug'],
                    'ecosystem' => $item['ecosystem'],
                    'version' => $item['version'],
                ]),
            ]);
            $vulns = [];
            if (! is_wp_error($response)) {
                $body = wp_remote_retrieve_body($response);
                $data = json_decode($body, true);
                if (is_array($data) && ! empty($data['vulnerabilities'])) {
                    foreach ($data['vulnerabilities'] as $v) {
                        $vulns[] = [
                            'id' => (string) ($v['id'] ?? ''),
                            'summary' => (string) ($v['summary'] ?? ''),
                            'severity' => (string) ($v['severity'] ?? ''),
                        ];
                    }
                }
            }
            $results[] = array_merge($item, ['vulnerabilities' => $vulns]);
        }
        return $results;
    }
}
