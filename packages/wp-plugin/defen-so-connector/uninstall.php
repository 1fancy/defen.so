<?php

/**
 * Cleanup on plugin delete. Called by WordPress when the user hits Delete
 * (not Deactivate — deactivate is handled inline in the main file).
 */
if (! defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

delete_option('defenso_api_token');
delete_option('defenso_connected_at');
delete_option('defenso_setup_needed');
delete_option('defenso_policy_cache');
delete_option('defenso_policy_refreshed_at');
delete_option('defenso_attack_log_queue');
delete_option('defenso_plan_label');
delete_option('defenso_verified');
delete_option('defenso_malware_last_run');
delete_option('defenso_malware_findings');
delete_option('defenso_malware_stats');
delete_option('defenso_integrity_baseline');
delete_option('defenso_integrity_baseline_at');
delete_option('defenso_integrity_last_diff');
delete_option('defenso_vuln_last_run');
delete_option('defenso_vuln_findings');
delete_option('defenso_geo_blocklist');
delete_option('defenso_login_max');
delete_option('defenso_login_window');
delete_option('defenso_recaptcha_site_key');
delete_option('defenso_recaptcha_secret_key');
delete_option('defenso_activity_log');
wp_clear_scheduled_hook('defenso_policy_refresh');
