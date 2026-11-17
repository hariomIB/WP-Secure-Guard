<?php
/**
 * Fired during plugin deactivation.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Deactivator
 */
class WPSG_Deactivator {

	/**
	 * Plugin deactivation routine.
	 */
	public static function deactivate() {
		// 1. Clear scheduled cron jobs.
		$timestamp = wp_next_scheduled( 'wpsg_daily_maintenance' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'wpsg_daily_maintenance' );
		}

		// 2. Clear transients created by plugin.
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_wpsg_%' OR option_name LIKE '_transient_timeout_wpsg_%'" );

		// 3. Log deactivation event.
		WPSG_Logger::log(
			'plugin_lifecycle',
			__( 'WP Secure Guard was deactivated.', 'wp-secure-guard' ),
			'warning'
		);
	}
}
