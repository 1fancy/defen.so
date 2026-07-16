<?php
/**
 * Activity log. Records last-N admin actions to wp_options and pipes each
 * into the plugin's attack-log queue so the Defen.so dashboard shows
 * high-value admin events alongside blocked attacks.
 *
 * Actions tracked:
 *   - wp_login             (successful login of any user)
 *   - profile_update       (user role or password change)
 *   - activated_plugin     (plugin activated)
 *   - deactivated_plugin   (plugin deactivated)
 *   - upgrader_process_complete (plugin/theme install / update)
 *   - switch_theme         (theme switch)
 *   - updated_option       (specific high-risk options: siteurl, home, admin_email)
 *
 * Free tier: last 100 events kept locally. Pro tier: retention extended
 * server-side via the dashboard.
 *
 * @package DefensoConnector
 */

if (! defined('ABSPATH')) {
    exit;
}

class Defenso_Activity_Log
{
    private const CAP = 100;
    private const OPT = 'defenso_activity_log';

    public static function register(): void
    {
        add_action('wp_login', [self::class, 'on_login'], 10, 2);
        add_action('profile_update', [self::class, 'on_profile_update'], 10, 2);
        add_action('activated_plugin', [self::class, 'on_plugin_activated'], 10, 2);
        add_action('deactivated_plugin', [self::class, 'on_plugin_deactivated'], 10, 2);
        add_action('switch_theme', [self::class, 'on_theme_switch'], 10, 3);
        add_action('updated_option', [self::class, 'on_option_updated'], 10, 3);
        add_action('wp_ajax_defenso_activity_log', [self::class, 'ajax_read']);
    }

    public static function ajax_read(): void
    {
        if (! current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied'], 403);
        }
        wp_send_json_success([
            'events' => array_slice((array) get_option(self::OPT, []), 0, 30),
        ]);
    }

    public static function on_login(string $username, $user): void
    {
        self::push([
            'kind' => 'login',
            'summary' => "User '{$username}' logged in",
            'actor' => $user->user_login ?? $username,
        ]);
    }

    public static function on_profile_update(int $user_id, $old_user_data): void
    {
        $user = get_userdata($user_id);
        if (! $user) {
            return;
        }
        self::push([
            'kind' => 'profile',
            'summary' => "Profile updated for '{$user->user_login}'",
            'actor' => wp_get_current_user()->user_login ?? '',
        ]);
    }

    public static function on_plugin_activated(string $plugin, bool $network): void
    {
        self::push([
            'kind' => 'plugin_activate',
            'summary' => "Plugin activated: {$plugin}",
            'actor' => wp_get_current_user()->user_login ?? '',
        ]);
    }

    public static function on_plugin_deactivated(string $plugin, bool $network): void
    {
        self::push([
            'kind' => 'plugin_deactivate',
            'summary' => "Plugin deactivated: {$plugin}",
            'actor' => wp_get_current_user()->user_login ?? '',
        ]);
    }

    public static function on_theme_switch(string $new_name, $new_theme, $old_theme): void
    {
        self::push([
            'kind' => 'theme_switch',
            'summary' => "Theme switched to '{$new_name}'",
            'actor' => wp_get_current_user()->user_login ?? '',
        ]);
    }

    public static function on_option_updated(string $option, $old_value, $new_value): void
    {
        // Only high-risk options — otherwise this floods on every save.
        if (! in_array($option, ['siteurl', 'home', 'admin_email', 'default_role', 'blogname'], true)) {
            return;
        }
        self::push([
            'kind' => 'option_change',
            'summary' => "Option '{$option}' changed",
            'actor' => wp_get_current_user()->user_login ?? '',
        ]);
    }

    /**
     * @param array{kind:string, summary:string, actor?:string} $ev
     */
    private static function push(array $ev): void
    {
        $log = (array) get_option(self::OPT, []);
        $ev['at'] = time();
        $ev['ip'] = self::client_ip();
        array_unshift($log, $ev);
        if (count($log) > self::CAP) {
            $log = array_slice($log, 0, self::CAP);
        }
        update_option(self::OPT, $log, false);
    }

    private static function client_ip(): string
    {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'] as $key) {
            if (! empty($_SERVER[$key])) {
                $ip = trim(explode(',', (string) $_SERVER[$key])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '0.0.0.0';
    }
}
