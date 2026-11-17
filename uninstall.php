<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * @package WP_Secure_Guard
 */

// If uninstall not called from WordPress, exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// Check if user specified to delete all plugin data on uninstall.
$settings = get_option( 'wpsg_settings', array() );
$delete_data = ! empty( $settings['delete_data_on_uninstall'] );

if ( $delete_data ) {
	// 1. Delete custom database table for activity logs.
	$table_name = $wpdb->prefix . 'wpsg_activity_logs';
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpdb->query( "DROP TABLE IF EXISTS {$table_name}" );

	// 2. Delete plugin options.
	delete_option( 'wpsg_settings' );
	delete_option( 'wpsg_db_version' );
	delete_option( 'wpsg_activation_timestamp' );

	// 3. Delete transients.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_wpsg_%' OR option_name LIKE '_transient_timeout_wpsg_%'" );

	// 4. Delete user meta associated with 2FA and security.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
	$wpdb->query( "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'wpsg_%'" );
}
