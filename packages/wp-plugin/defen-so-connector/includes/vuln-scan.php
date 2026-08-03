<?php

/**
 * Vulnerability scanner. Enumerates installed plugins + themes with their
 * versions, hits the app's /api/mcp/list_cves endpoint for each, and marks
 * anything that resolves to a CVE list as vulnerable.
 *
 * Manual scan for everyone (server-side CVE data is rate-limited per plan on Defen.so).
 */
if (! defined('ABSPATH')) {
    exit;
}

class Defenso_Vuln_Scan
{
    private const SCAN_THROTTLE = 300;

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
        // Short anti-abuse throttle, same for everyone. The CVE data comes from
        // the Defen.so API, which applies its own per-plan quota server-side —
        // so tier differentiation lives on the server, not as a local paywall.
        $last = (int) get_option('defenso_vuln_last_run', 0);
        if ($last && (time() - $last) < self::SCAN_THROTTLE) {
            $wait_m = (int) ceil((self::SCAN_THROTTLE - (time() - $last)) / 60);
            wp_send_json_error([
                'message' => "A scan just ran. Try again in {$wait_m} minute(s).",
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

        self::report_findings($results, (string) $token);
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
     * @param  array<int, array{name:string,slug:string,version:string,kind:string,ecosystem:string}>  $inventory
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

    /**
     * Push the vuln results to Defen.so's /wp/findings endpoint so they surface
     * on the site's Pentest tab. One finding per checked plugin/theme: a package
     * with CVEs → fail (CVE ids in the note); clean → pass. Fails silently on any
     * network error so it never breaks the admin scan.
     *
     * @param  array<int, array{name:string,slug:string,version:string,kind:string,ecosystem:string,vulnerabilities:array}>  $results
     */
    private static function report_findings(array $results, string $token): void
    {
        if (empty($results)) {
            return;
        }
        $api = defined('DEFENSO_API_BASE') ? DEFENSO_API_BASE : 'https://app.defen.so/api';
        $findings = [];
        foreach ($results as $r) {
            $label = ucfirst((string) ($r['kind'] ?? 'package')).' '.(string) ($r['name'] ?? $r['slug'] ?? '');
            $version = (string) ($r['version'] ?? '');
            if (! empty($r['vulnerabilities'])) {
                $ids = [];
                foreach ($r['vulnerabilities'] as $v) {
                    if (! empty($v['id'])) {
                        $ids[] = (string) $v['id'];
                    }
                }
                $note = count($ids) > 0
                    ? 'Version '.$version.' — '.count($ids).' known CVE(s): '.implode(', ', array_slice($ids, 0, 8))
                    : 'Version '.$version.' has known vulnerabilities.';
                $findings[] = [
                    'title' => substr($label.' ('.$version.') is vulnerable', 0, 200),
                    'level' => 'fail',
                    'note' => substr($note, 0, 500),
                ];
            } else {
                $findings[] = [
                    'title' => substr($label.' ('.$version.') has no known CVEs', 0, 200),
                    'level' => 'pass',
                    'note' => '',
                ];
            }
        }

        wp_remote_post($api.'/wp/findings', [
            'timeout' => 5,
            'blocking' => false,
            'headers' => [
                'Authorization' => 'Bearer '.$token,
                'Content-Type' => 'application/json',
                'User-Agent' => 'Defenso-WP/'.DEFENSO_VERSION,
            ],
            'body' => wp_json_encode([
                'wp_url' => get_site_url(),
                'findings' => array_slice($findings, 0, 200),
            ]),
        ]);
    }
}
