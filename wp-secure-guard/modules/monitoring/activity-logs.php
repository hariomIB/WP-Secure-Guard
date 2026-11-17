<?php
/**
 * Module: Security Activity Logs & Audit Trail.
 *
 * Captures user role changes, profile updates, plugin lifecycle, and firewall alerts.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Activity_Logs
 */
class WPSG_Activity_Logs {

	/**
	 * Initialize activity log watchers.
	 */
	public static function init() {
		if ( ! WPSG_Settings::get( 'activity_logs_enable', true ) ) {
			return;
		}

		// Watch plugin lifecycle events.
		add_action( 'activated_plugin', array( __CLASS__, 'log_plugin_activation' ) );
		add_action( 'deactivated_plugin', array( __CLASS__, 'log_plugin_deactivation' ) );

		// Watch user role & profile changes.
		add_action( 'set_user_role', array( __CLASS__, 'log_role_change' ), 10, 3 );
		add_action( 'delete_user', array( __CLASS__, 'log_user_deletion' ), 10, 2 );
		add_action( 'password_reset', array( __CLASS__, 'log_password_reset' ), 10, 2 );

		// Scheduled log maintenance.
		add_action( 'wpsg_daily_maintenance', array( __CLASS__, 'run_scheduled_prune' ) );
	}

	/**
	 * Log plugin activation.
	 *
	 * @param string $plugin Plugin basename.
	 */
	public static function log_plugin_activation( $plugin ) {
		WPSG_Logger::log(
			'plugin_activated',
			sprintf(
				/* translators: %s: plugin name */
				__( 'Plugin "%s" was activated.', 'wp-secure-guard' ),
				$plugin
			),
			'info'
		);
	}

	/**
	 * Log plugin deactivation.
	 *
	 * @param string $plugin Plugin basename.
	 */
	public static function log_plugin_deactivation( $plugin ) {
		WPSG_Logger::log(
			'plugin_deactivated',
			sprintf(
				/* translators: %s: plugin name */
				__( 'Plugin "%s" was deactivated.', 'wp-secure-guard' ),
				$plugin
			),
			'warning'
		);
	}

	/**
	 * Log changes in user role.
	 *
	 * @param int    $user_id   User ID.
	 * @param string $role      New role.
	 * @param array  $old_roles Old roles.
	 */
	public static function log_role_change( $user_id, $role, $old_roles ) {
		$user = get_userdata( $user_id );
		$username = $user ? $user->user_login : (string) $user_id;

		WPSG_Logger::log(
			'user_role_changed',
			sprintf(
				/* translators: 1: username, 2: new role, 3: old role */
				__( 'Role for user "%1$s" changed to "%2$s" (previous: %3$s).', 'wp-secure-guard' ),
				$username,
				$role,
				implode( ', ', (array) $old_roles )
			),
			'administrator' === $role ? 'danger' : 'warning',
			array( 'user_id' => $user_id, 'username' => $username )
		);
	}

	/**
	 * Log user deletion.
	 *
	 * @param int      $user_id      User ID.
	 * @param int|null $reassign_id  Reassigned ID.
	 */
	public static function log_user_deletion( $user_id, $reassign_id = null ) {
		$user = get_userdata( $user_id );
		$username = $user ? $user->user_login : (string) $user_id;

		WPSG_Logger::log(
			'user_deleted',
			sprintf(
				/* translators: %s: username */
				__( 'User account "%s" was permanently deleted.', 'wp-secure-guard' ),
				$username
			),
			'warning',
			array( 'user_id' => $user_id, 'username' => $username )
		);
	}

	/**
	 * Log password reset.
	 *
	 * @param WP_User $user     User object.
	 * @param string  $new_pass New password string.
	 */
	public static function log_password_reset( $user, $new_pass ) {
		WPSG_Logger::log(
			'password_reset',
			sprintf(
				/* translators: %s: username */
				__( 'Password was reset for user "%s".', 'wp-secure-guard' ),
				$user->user_login
			),
			'info',
			array( 'user_id' => $user->ID, 'username' => $user->user_login )
		);
	}

	/**
	 * Prune old logs based on retention days.
	 */
	public static function run_scheduled_prune() {
		$days = absint( WPSG_Settings::get( 'activity_logs_retention_days', 30 ) );
		WPSG_Logger::prune_logs( $days );
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled     = (bool) WPSG_Settings::get( 'activity_logs_enable', true );
		$total_count = $enabled ? WPSG_Logger::count_logs() : 0;
		$retention   = absint( WPSG_Settings::get( 'activity_logs_retention_days', 30 ) );

		return array(
			'id'          => 'activity_logs',
			'title'       => __( 'Security Activity Log', 'wp-secure-guard' ),
			'category'    => 'monitoring',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? sprintf( __( 'Active (%1$d events logged, %2$dd retention)', 'wp-secure-guard' ), $total_count, $retention ) : __( 'Disabled', 'wp-secure-guard' ),
			'description' => __( 'Real-time tamper-evident event logging tracking authentication, admin role escalations, and WAF events.', 'wp-secure-guard' ),
		);
	}
}
