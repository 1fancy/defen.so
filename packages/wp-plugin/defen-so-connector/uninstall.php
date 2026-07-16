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
wp_clear_scheduled_hook('defenso_policy_refresh');
