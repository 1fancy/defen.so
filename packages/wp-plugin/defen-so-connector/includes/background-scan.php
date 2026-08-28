<?php
/**
 * Background scan orchestrator. Runs the (CPU-heavy) malware + file-integrity
 * sweep on WP-Cron instead of inside the admin request, so the UI never hangs.
 * The browser kicks a scan, then polls a status option to drive a progress bar,
 * and gets a "done" push when it finishes. A weekly cron keeps the database of
 * findings continuously fresh even if the admin never clicks Scan.
 *
 * Status option shape (defenso_bgscan_status):
 *   { state: idle|queued|running|done|error, pct:int, phase:string,
 *     started_at:int, finished_at:int, files_seen:int, flagged:int }
 */

if (! defined('ABSPATH')) {
    exit;
}

class Defenso_Background_Scan
{
    private const HOOK = 'defenso_bgscan_run';
    private const WEEKLY_HOOK = 'defenso_bgscan_weekly';
    private const STATUS = 'defenso_bgscan_status';

    public static function register(): void
    {
        add_action('wp_ajax_defenso_bgscan_start', [self::class, 'ajax_start']);
        add_action('wp_ajax_defenso_bgscan_status', [self::class, 'ajax_status']);

        add_action(self::HOOK, [self::class, 'run']);
        add_action(self::WEEKLY_HOOK, [self::class, 'run']);

        // Keep the findings database continuously fresh: a weekly sweep, even
        // with no manual click. Scheduled on first load if not already set.
        if (! wp_next_scheduled(self::WEEKLY_HOOK)) {
            wp_schedule_event(time() + 3600, 'weekly', self::WEEKLY_HOOK);
        }
    }

    /** Kick a background scan (returns immediately; cron runs it). */
    public static function ajax_start(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        if (! check_ajax_referer('defenso_admin', '_wpnonce', false)) {
            wp_send_json_error(['message' => 'Invalid nonce'], 403);
        }

        $status = self::status();
        if (in_array($status['state'], ['queued', 'running'], true)) {
            // Already running — just report it so the bar picks up.
            wp_send_json_success($status);
        }

        self::set_status(['state' => 'queued', 'pct' => 2, 'phase' => 'Queued…', 'started_at' => time(), 'finished_at' => 0, 'files_seen' => 0, 'flagged' => 0]);

        // Fire an out-of-band cron tick so it starts within seconds without a
        // real system cron. Non-blocking.
        if (! wp_next_scheduled(self::HOOK)) {
            wp_schedule_single_event(time(), self::HOOK);
        }
        self::spawn_cron();

        wp_send_json_success(self::status());
    }

    public static function ajax_status(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        wp_send_json_success(self::status());
    }

    /** The actual sweep (runs in cron context). Updates progress as it goes. */
    public static function run(): void
    {
        // Guard: if two ticks race, only one runs.
        $status = self::status();
        if ($status['state'] === 'running' && (time() - (int) $status['started_at']) < 600) {
            return;
        }

        @set_time_limit(0);
        self::set_status(['state' => 'running', 'pct' => 8, 'phase' => 'Scanning files for malware…']);

        $files_seen = 0;
        $flagged = 0;

        // Malware sweep — reuse the existing engine, with a progress callback.
        if (class_exists('Defenso_Malware_Scan') && method_exists('Defenso_Malware_Scan', 'run_scan')) {
            $res = Defenso_Malware_Scan::run_scan(static function (int $pct, int $seen) {
                self::set_status(['pct' => min(70, 8 + (int) ($pct * 0.62)), 'files_seen' => $seen]);
            });
            $files_seen = (int) ($res['files_seen'] ?? 0);
            $flagged = (int) count($res['findings'] ?? []);
        }

        self::set_status(['pct' => 78, 'phase' => 'Checking file integrity…']);

        // File-integrity diff (which files changed vs the baseline).
        $changed = 0;
        if (class_exists('Defenso_File_Integrity') && method_exists('Defenso_File_Integrity', 'run_diff')) {
            $diff = Defenso_File_Integrity::run_diff();
            $changed = (int) (count($diff['added'] ?? []) + count($diff['changed'] ?? []) + count($diff['removed'] ?? []));
        }

        self::set_status([
            'state' => 'done',
            'pct' => 100,
            'phase' => 'Complete',
            'finished_at' => time(),
            'files_seen' => $files_seen,
            'flagged' => $flagged,
            'changed' => $changed,
        ]);
    }

    /** @return array<string,mixed> */
    private static function status(): array
    {
        $s = get_option(self::STATUS, []);
        if (! is_array($s) || empty($s['state'])) {
            $s = ['state' => 'idle', 'pct' => 0, 'phase' => '', 'started_at' => 0, 'finished_at' => 0, 'files_seen' => 0, 'flagged' => 0];
        }

        return $s;
    }

    /** @param array<string,mixed> $patch */
    private static function set_status(array $patch): void
    {
        update_option(self::STATUS, array_merge(self::status(), $patch), false);
    }

    /** Nudge WP-Cron to run now (non-blocking spawn). */
    private static function spawn_cron(): void
    {
        if (defined('DISABLE_WP_CRON') && DISABLE_WP_CRON) {
            return;
        }
        $url = site_url('wp-cron.php?doing_wp_cron');
        wp_remote_post($url, [
            'timeout' => 0.01,
            'blocking' => false,
            'sslverify' => apply_filters('https_local_ssl_verify', false),
        ]);
    }

    public static function clear_schedule(): void
    {
        wp_clear_scheduled_hook(self::WEEKLY_HOOK);
        wp_clear_scheduled_hook(self::HOOK);
    }
}
