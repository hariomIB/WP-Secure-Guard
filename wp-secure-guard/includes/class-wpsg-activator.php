<?php
/**
 * Fired during plugin activation.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Activator
 */
class WPSG_Activator {

	/**
	 * Plugin activation routine.
	 */
	public static function activate() {
		// 1. Create database tables.
		WPSG_Logger::create_table();

		// 2. Initialize default settings if they do not exist.
		$existing = get_option( WPSG_Settings::OPTION_NAME, null );
		if ( null === $existing ) {
			add_option( WPSG_Settings::OPTION_NAME, WPSG_Settings::get_defaults() );
		}

		// 3. Store activation timestamp & db version.
		update_option( 'wpsg_activation_timestamp', time() );
		update_option( 'wpsg_db_version', WPSG_VERSION );

		// 4. Schedule daily maintenance cron for log pruning.
		if ( ! wp_next_scheduled( 'wpsg_daily_maintenance' ) ) {
			wp_schedule_event( time(), 'daily', 'wpsg_daily_maintenance' );
		}

		// 5. Log activation event.
		WPSG_Logger::log(
			'plugin_lifecycle',
			__( 'WP Secure Guard was successfully activated.', 'wp-secure-guard' ),
			'success'
		);
	}
}
