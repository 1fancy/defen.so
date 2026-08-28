<?php
/**
 * Defenso admin-bar node. Adds a green "shield" icon to the WordPress toolbar
 * that reads "Security active" when connected, with a submenu for Scan, Reports,
 * Uptime, and Upgrade. When not connected it nudges the user to connect a (free)
 * account to unlock uptime / SSL / domain monitoring.
 *
 * WP 7.1 note: the toolbar is now persistently shown in the Post + Site editors.
 * We register on the standard `admin_bar_menu` hook at a late priority and use
 * only core node APIs (add_node) + an inline dashicon, so the item renders
 * consistently across wp-admin, the front end, and both editors.
 */

if (! defined('ABSPATH')) {
    exit;
}

class Defenso_Admin_Bar
{
    public static function register(): void
    {
        add_action('admin_bar_menu', [self::class, 'add_nodes'], 90);
        add_action('admin_head', [self::class, 'inline_css']);
        add_action('wp_head', [self::class, 'inline_css']);
    }

    private static function connected(): bool
    {
        return (bool) get_option('defenso_api_token');
    }

    public static function add_nodes(\WP_Admin_Bar $bar): void
    {
        if (! current_user_can('manage_options')) {
            return;
        }

        $connected = self::connected();
        $admin = admin_url('admin.php?page=defenso');

        // Root node: green shield + "Security active" (or a connect nudge).
        $title = self::icon($connected)
            .'<span class="ab-label">'
            .($connected ? esc_html__('Security active', 'defen-so-connector') : esc_html__('Secure this site', 'defen-so-connector'))
            .'</span>';

        $bar->add_node([
            'id' => 'defenso',
            'title' => $title,
            'href' => $admin,
            'meta' => ['class' => $connected ? 'defenso-ab defenso-ab-on' : 'defenso-ab defenso-ab-off'],
        ]);

        if ($connected) {
            $bar->add_node(['parent' => 'defenso', 'id' => 'defenso-scan', 'title' => esc_html__('Run a scan', 'defen-so-connector'), 'href' => $admin.'#scans']);
            $bar->add_node(['parent' => 'defenso', 'id' => 'defenso-reports', 'title' => esc_html__('Reports &amp; findings', 'defen-so-connector'), 'href' => $admin.'#scans']);
            $bar->add_node(['parent' => 'defenso', 'id' => 'defenso-changes', 'title' => esc_html__('File changes', 'defen-so-connector'), 'href' => $admin.'#filechanges']);
            $bar->add_node(['parent' => 'defenso', 'id' => 'defenso-uptime', 'title' => esc_html__('Uptime, SSL &amp; domain', 'defen-so-connector'), 'href' => DEFENSO_APP_URL.'/sites']);
            $bar->add_node(['parent' => 'defenso', 'id' => 'defenso-upgrade', 'title' => esc_html__('Upgrade / support us ★', 'defen-so-connector'), 'href' => DEFENSO_APP_URL.'/billing']);
        } else {
            $bar->add_node([
                'parent' => 'defenso',
                'id' => 'defenso-connect',
                'title' => esc_html__('Connect a free account →', 'defen-so-connector'),
                'href' => $admin,
            ]);
            $bar->add_node([
                'parent' => 'defenso',
                'id' => 'defenso-why',
                'title' => esc_html__('Free uptime, SSL & domain-expiry watch once connected', 'defen-so-connector'),
                'href' => $admin,
                'meta' => ['class' => 'defenso-ab-hint'],
            ]);
        }
    }

    /** Inline SVG shield — green when protected, muted when not. */
    private static function icon(bool $on): string
    {
        $color = $on ? '#1FA855' : '#9ca3af';

        return '<span class="ab-icon" aria-hidden="true" style="display:inline-block;width:17px;height:17px;vertical-align:-3px;margin-right:6px;">'
            .'<svg width="17" height="17" viewBox="0 0 24 24" fill="'.$color.'"><path d="M12 2l7 3v6c0 4.4-3 8.3-7 9-4-0.7-7-4.6-7-9V5l7-3z"/>'
            .($on ? '<path d="M10.4 14.6l-2.2-2.2 1.1-1.1 1.1 1.1 3.4-3.4 1.1 1.1-4.5 4.5z" fill="#fff"/>' : '')
            .'</svg></span>';
    }

    public static function inline_css(): void
    {
        echo '<style id="defenso-ab-css">'
            .'#wpadminbar .defenso-ab-on > .ab-item .ab-label{color:#5fd39a!important;font-weight:600;}'
            .'#wpadminbar .defenso-ab-off > .ab-item .ab-label{color:#e2e4e7!important;}'
            .'#wpadminbar #wp-admin-bar-defenso-upgrade .ab-item{color:#ffd66b!important;font-weight:600;}'
            .'#wpadminbar #wp-admin-bar-defenso-why .ab-item{white-space:normal!important;line-height:1.4;font-size:11px;opacity:.75;max-width:220px;}'
            .'#wpadminbar .defenso-ab .ab-icon svg{display:block;}'
            .'</style>';
    }
}
