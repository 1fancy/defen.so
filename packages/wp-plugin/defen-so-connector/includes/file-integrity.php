<?php
/**
 * File-integrity monitor. Records a sha256 baseline of every PHP file in the
 * WP tree (excluding wp-content/cache, wp-content/uploads, and node_modules).
 *
 * Free tier: baseline is stored; user can trigger a compare manually. Pro tier
 * runs a daily cron. Business runs on every request (not implemented here —
 * would need a persistent watcher, out of scope for a wp-cron plugin).
 *
 * Stored in wp_options:
 *   defenso_integrity_baseline  → { path => sha256 } (max 5000 entries)
 *   defenso_integrity_last_diff → { added:[], changed:[], removed:[], ran_at }
 *
 * @package DefensoConnector
 */

if (! defined('ABSPATH')) {
    exit;
}

class Defenso_File_Integrity
{
    private const FILE_CAP = 5000;
    private const SIZE_CAP = 2_097_152; // 2 MB

    public static function register(): void
    {
        add_action('wp_ajax_defenso_integrity_baseline', [self::class, 'ajax_baseline']);
        add_action('wp_ajax_defenso_integrity_diff', [self::class, 'ajax_diff']);
    }

    public static function ajax_baseline(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        if (! check_ajax_referer('defenso_admin', '_wpnonce', false)) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
        }
        $baseline = self::snapshot();
        update_option('defenso_integrity_baseline', $baseline, false);
        update_option('defenso_integrity_baseline_at', time(), false);
        wp_send_json_success([
            'files' => count($baseline),
            'taken_at' => time(),
        ]);
    }

    public static function ajax_diff(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        if (! check_ajax_referer('defenso_admin', '_wpnonce', false)) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
        }
        $baseline = (array) get_option('defenso_integrity_baseline', []);
        if (empty($baseline)) {
            wp_send_json_error(['message' => 'No baseline taken yet. Take a baseline first.'], 400);
        }
        $current = self::snapshot();
        $added = array_diff_key($current, $baseline);
        $removed = array_diff_key($baseline, $current);
        $changed = [];
        foreach ($current as $path => $hash) {
            if (isset($baseline[$path]) && $baseline[$path] !== $hash) {
                $changed[$path] = ['from' => $baseline[$path], 'to' => $hash];
            }
        }
        $diff = [
            'added' => array_slice(array_keys($added), 0, 100),
            'changed' => array_slice(array_keys($changed), 0, 100),
            'removed' => array_slice(array_keys($removed), 0, 100),
            'counts' => [
                'added' => count($added),
                'changed' => count($changed),
                'removed' => count($removed),
            ],
            'ran_at' => time(),
        ];
        update_option('defenso_integrity_last_diff', $diff, false);
        wp_send_json_success($diff);
    }

    /**
     * @return array<string, string> path (relative to ABSPATH) => sha256
     */
    private static function snapshot(): array
    {
        $root = defined('ABSPATH') ? ABSPATH : '';
        $out = [];
        if (! is_dir($root)) {
            return $out;
        }
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );
        } catch (Throwable $e) {
            return $out;
        }
        $seen = 0;
        foreach ($it as $f) {
            if ($seen >= self::FILE_CAP) {
                break;
            }
            $path = (string) $f;
            if (! $f->isFile()) {
                continue;
            }
            // Skip ephemeral / user-content directories.
            if (
                strpos($path, '/wp-content/cache/') !== false
                || strpos($path, '/wp-content/uploads/') !== false
                || strpos($path, '/node_modules/') !== false
                || strpos($path, '/vendor/') !== false
            ) {
                continue;
            }
            $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
            if (! in_array($ext, ['php', 'phtml', 'js', 'htaccess'], true) && basename($path) !== '.htaccess') {
                continue;
            }
            if ($f->getSize() > self::SIZE_CAP) {
                continue;
            }
            $seen++;
            $body = @file_get_contents($path, false, null, 0, self::SIZE_CAP);
            if (! is_string($body) || $body === '') {
                continue;
            }
            $rel = str_replace($root, '', $path);
            $out[$rel] = hash('sha256', $body);
        }
        return $out;
    }
}
