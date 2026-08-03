<?php

/**
 * Core-file integrity + exposed-file check. Two on-demand, fully-local scans
 * that need no account:
 *
 *   1. Core checksum: pulls the official WordPress.org checksum manifest for
 *      the exact installed version + locale, then hashes every core file and
 *      reports any that don't match (modified core = a classic infection sign)
 *      or are missing. Uses the public, unauthenticated api.wordpress.org
 *      endpoint — the same one WP-CLI's `checksums` command uses.
 *
 *   2. Exposed files: probes a short list of files that must never be publicly
 *      reachable (.env, .git/config, wp-config backups, database dumps) by
 *      making a loopback HTTP request to each and flagging any that return 200.
 *
 * Findings are cached in wp_options for the admin page, and streamed to the
 * Defen.so /wp/findings endpoint when an account is connected so they land on
 * the site's Pentest tab.
 */
if (! defined('ABSPATH')) {
    exit;
}

class Defenso_Core_Checksum
{
    private const SIZE_CAP = 8_388_608; // 8 MB per core file.

    private const THROTTLE = 120;

    public static function register(): void
    {
        add_action('wp_ajax_defenso_core_checksum', [self::class, 'ajax_checksum']);
        add_action('wp_ajax_defenso_exposed_files', [self::class, 'ajax_exposed_files']);
    }

    /* ---------------------------------------------------------------------
     * Core checksum
     * -------------------------------------------------------------------*/

    public static function ajax_checksum(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        if (! check_ajax_referer('defenso_admin', '_wpnonce', false)) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
        }
        $last = (int) get_option('defenso_core_checksum_last', 0);
        if ($last && (time() - $last) < self::THROTTLE) {
            $wait = (int) ceil((self::THROTTLE - (time() - $last)) / 60);
            wp_send_json_error(['message' => "A check just ran. Try again in {$wait} minute(s)."], 429);
        }
        update_option('defenso_core_checksum_last', time(), false);

        $version = get_bloginfo('version');
        $locale = function_exists('get_locale') ? get_locale() : 'en_US';
        $checksums = self::fetch_checksums($version, $locale);
        if ($checksums === null) {
            wp_send_json_error(['message' => 'Could not fetch official checksums from WordPress.org. Try again shortly.'], 502);
        }

        $modified = [];
        $missing = [];
        $checked = 0;
        foreach ($checksums as $rel => $expected) {
            // Only verify core: skip wp-content (themes/plugins/uploads live there).
            if (strpos($rel, 'wp-content/') === 0) {
                continue;
            }
            $abs = ABSPATH.$rel;
            $checked++;
            if (! file_exists($abs)) {
                $missing[] = $rel;

                continue;
            }
            if (! is_readable($abs) || filesize($abs) > self::SIZE_CAP) {
                continue;
            }
            if (hash_file('md5', $abs) !== $expected) {
                $modified[] = $rel;
            }
        }

        $result = [
            'version' => $version,
            'checked' => $checked,
            'modified' => array_slice($modified, 0, 100),
            'missing' => array_slice($missing, 0, 100),
            'counts' => [
                'modified' => count($modified),
                'missing' => count($missing),
            ],
            'ran_at' => time(),
        ];
        update_option('defenso_core_checksum_result', $result, false);

        $token = get_option('defenso_api_token');
        if ($token) {
            self::report_core_findings($result, (string) $token);
        }

        wp_send_json_success($result);
    }

    /**
     * @return array<string, string>|null path => md5, or null on failure
     */
    private static function fetch_checksums(string $version, string $locale): ?array
    {
        $url = add_query_arg(
            [
                'version' => $version,
                'locale' => $locale,
            ],
            'https://api.wordpress.org/core/checksums/1.0/'
        );
        $response = wp_remote_get($url, [
            'timeout' => 12,
            'user-agent' => 'Defenso-WP/'.(defined('DEFENSO_VERSION') ? DEFENSO_VERSION : '0'),
        ]);
        if (is_wp_error($response)) {
            return null;
        }
        $data = json_decode((string) wp_remote_retrieve_body($response), true);
        if (! is_array($data) || empty($data['checksums']) || ! is_array($data['checksums'])) {
            // Some locales nest under the version key; retry with en_US.
            if ($locale !== 'en_US') {
                return self::fetch_checksums($version, 'en_US');
            }

            return null;
        }
        $out = [];
        foreach ($data['checksums'] as $rel => $hash) {
            if (is_string($rel) && is_string($hash) && preg_match('/^[a-f0-9]{32}$/i', $hash)) {
                $out[ltrim($rel, '/')] = strtolower($hash);
            }
        }

        return $out ?: null;
    }

    /* ---------------------------------------------------------------------
     * Exposed-file probe
     * -------------------------------------------------------------------*/

    public static function ajax_exposed_files(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        if (! check_ajax_referer('defenso_admin', '_wpnonce', false)) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
        }
        $candidates = [
            '.env',
            '.git/config',
            '.git/HEAD',
            'wp-config.php.bak',
            'wp-config.php~',
            'wp-config.php.save',
            'wp-config.bak',
            '.wp-config.php.swp',
            'backup.sql',
            'database.sql',
            'dump.sql',
            'backup.zip',
            'debug.log',
            'error_log',
            '.htpasswd',
            'phpinfo.php',
        ];
        $base = trailingslashit(home_url());
        $exposed = [];
        $checked = 0;
        foreach ($candidates as $rel) {
            $checked++;
            $url = $base.$rel;
            $response = wp_remote_get($url, [
                'timeout' => 4,
                'redirection' => 0,
                'sslverify' => false,
                'user-agent' => 'Defenso-WP/'.(defined('DEFENSO_VERSION') ? DEFENSO_VERSION : '0'),
            ]);
            if (is_wp_error($response)) {
                continue;
            }
            $code = (int) wp_remote_retrieve_response_code($response);
            if ($code === 200) {
                $body = (string) wp_remote_retrieve_body($response);
                // Guard against catch-all 200 pages: only flag if the body
                // actually looks like the sensitive file, not a themed 404.
                if (self::looks_sensitive($rel, $body)) {
                    $exposed[] = ['file' => $rel, 'url' => $url];
                }
            }
        }
        $result = [
            'checked' => $checked,
            'exposed' => $exposed,
            'ran_at' => time(),
        ];
        update_option('defenso_exposed_files_result', $result, false);

        $token = get_option('defenso_api_token');
        if ($token) {
            self::report_exposed_findings($result, (string) $token);
        }

        wp_send_json_success($result);
    }

    private static function looks_sensitive(string $rel, string $body): bool
    {
        if ($body === '') {
            return false;
        }
        // A real themed 404 page usually contains a full HTML document; the raw
        // sensitive files do not. Reject obvious HTML error pages.
        if (stripos($body, '<!doctype html') !== false || stripos($body, '<html') !== false) {
            return false;
        }
        if (strpos($rel, '.env') !== false) {
            return (bool) preg_match('/^[A-Z0-9_]+\s*=/m', $body);
        }
        if (strpos($rel, '.git/') !== false) {
            return stripos($body, 'ref:') !== false || stripos($body, '[core]') !== false;
        }
        if (substr($rel, -4) === '.sql') {
            return stripos($body, 'INSERT INTO') !== false || stripos($body, 'CREATE TABLE') !== false || stripos($body, 'DROP TABLE') !== false;
        }
        if (strpos($rel, 'wp-config') !== false) {
            return stripos($body, 'DB_PASSWORD') !== false || stripos($body, '<?php') !== false;
        }
        if (substr($rel, -9) === '.htpasswd') {
            return (bool) preg_match('/^[^:]+:\S+/m', $body);
        }

        // For logs / zips / phpinfo we accept a non-HTML 200 as suspicious.
        return true;
    }

    /* ---------------------------------------------------------------------
     * Reporting to Defen.so (only when connected)
     * -------------------------------------------------------------------*/

    /**
     * @param  array{version:string,checked:int,modified:array<int,string>,missing:array<int,string>,counts:array{modified:int,missing:int}}  $result
     */
    private static function report_core_findings(array $result, string $token): void
    {
        $findings = [];
        if ($result['counts']['modified'] === 0 && $result['counts']['missing'] === 0) {
            $findings[] = [
                'title' => 'WordPress core files match the official '.$result['version'].' checksums',
                'level' => 'pass',
                'note' => '',
            ];
        } else {
            foreach (array_slice($result['modified'], 0, 100) as $path) {
                $findings[] = [
                    'title' => substr('Modified core file: '.$path, 0, 200),
                    'level' => 'fail',
                    'note' => 'Contents differ from the official WordPress.org checksum — possible infection.',
                ];
            }
            foreach (array_slice($result['missing'], 0, 50) as $path) {
                $findings[] = [
                    'title' => substr('Missing core file: '.$path, 0, 200),
                    'level' => 'warn',
                    'note' => 'Core file expected by WordPress.org is absent.',
                ];
            }
        }
        self::ship($findings, $token);
    }

    /**
     * @param  array{checked:int,exposed:array<int,array{file:string,url:string}>}  $result
     */
    private static function report_exposed_findings(array $result, string $token): void
    {
        $findings = [];
        if (empty($result['exposed'])) {
            $findings[] = [
                'title' => 'No exposed sensitive files found',
                'level' => 'pass',
                'note' => 'Checked '.$result['checked'].' common paths (.env, .git, config backups, DB dumps).',
            ];
        } else {
            foreach ($result['exposed'] as $row) {
                $findings[] = [
                    'title' => substr('Publicly reachable sensitive file: '.$row['file'], 0, 200),
                    'level' => 'fail',
                    'note' => 'Reachable at '.$row['url'].' — block or remove it immediately.',
                ];
            }
        }
        self::ship($findings, $token);
    }

    /**
     * @param  array<int, array{title:string,level:string,note:string}>  $findings
     */
    private static function ship(array $findings, string $token): void
    {
        $api = defined('DEFENSO_API_BASE') ? DEFENSO_API_BASE : 'https://app.defen.so/api';
        wp_remote_post($api.'/wp/findings', [
            'timeout' => 5,
            'blocking' => false,
            'headers' => [
                'Authorization' => 'Bearer '.$token,
                'Content-Type' => 'application/json',
                'User-Agent' => 'Defenso-WP/'.(defined('DEFENSO_VERSION') ? DEFENSO_VERSION : '0'),
            ],
            'body' => wp_json_encode([
                'wp_url' => get_site_url(),
                'findings' => array_slice($findings, 0, 200),
            ]),
        ]);
    }
}
