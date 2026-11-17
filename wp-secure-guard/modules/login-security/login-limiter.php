<?php
/**
 * Module: Login Rate Limiter & Brute-Force Protection.
 *
 * Tracks failed login attempts per IP address and enforces temporary lockouts.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Login_Limiter
 */
class WPSG_Login_Limiter {

	/**
	 * Initialize hooks if enabled.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'login_limiter_enable', true ) ) {
			add_filter( 'authenticate', array( __CLASS__, 'check_lockout_before_auth' ), 30, 3 );
			add_action( 'wp_login_failed', array( __CLASS__, 'handle_failed_login' ), 10, 1 );
			add_action( 'wp_login', array( __CLASS__, 'handle_successful_login' ), 10, 2 );
			add_filter( 'login_message', array( __CLASS__, 'render_lockout_message' ) );
		}
	}

	/**
	 * Check if current client IP is in the lockout state before evaluating credentials.
	 *
	 * @param WP_User|WP_Error|null $user     User object or error.
	 * @param string                $username Username or email.
	 * @param string                $password Password string.
	 * @return WP_User|WP_Error|null
	 */
	public static function check_lockout_before_auth( $user, $username, $password ) {
		// Only check when login is being attempted.
		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}

		$ip = WPSG_Logger::get_client_ip();

		if ( self::is_ip_whitelisted( $ip ) ) {
			return $user;
		}

		$lockout_until = get_transient( self::get_lockout_transient_key( $ip ) );

		if ( false !== $lockout_until ) {
			$remaining_seconds = $lockout_until - time();
			$remaining_minutes = max( 1, (int) ceil( $remaining_seconds / 60 ) );

			return new WP_Error(
				'wpsg_ip_locked_out',
				sprintf(
					/* translators: %d: number of minutes remaining */
					__( '<strong>ERROR</strong>: Too many failed login attempts. Your IP has been temporarily locked out. Please try again in %d minute(s).', 'wp-secure-guard' ),
					$remaining_minutes
				)
			);
		}

		return $user;
	}

	/**
	 * Record a failed login attempt and trigger lockout if threshold is exceeded.
	 *
	 * @param string $username Username attempted.
	 */
	public static function handle_failed_login( $username ) {
		$ip = WPSG_Logger::get_client_ip();

		if ( self::is_ip_whitelisted( $ip ) ) {
			return;
		}

		$max_retries      = absint( WPSG_Settings::get( 'login_max_retries', 5 ) );
		$lockout_duration = absint( WPSG_Settings::get( 'login_lockout_duration', 15 ) ); // in minutes
		$fail_key         = self::get_fail_transient_key( $ip );

		$attempts = absint( get_transient( $fail_key ) );
		$attempts++;

		// Save attempts for the duration window.
		set_transient( $fail_key, $attempts, $lockout_duration * MINUTE_IN_SECONDS );

		if ( $attempts >= $max_retries ) {
			$lockout_time = time() + ( $lockout_duration * MINUTE_IN_SECONDS );
			set_transient( self::get_lockout_transient_key( $ip ), $lockout_time, $lockout_duration * MINUTE_IN_SECONDS );

			// Clear the attempt counter now that lockout is active.
			delete_transient( $fail_key );

			WPSG_Logger::log(
				'login_lockout',
				sprintf(
					/* translators: 1: IP address, 2: duration in minutes, 3: attempts count, 4: username */
					__( 'IP %1$s locked out for %2$d minutes after %3$d consecutive failed login attempts on username "%4$s".', 'wp-secure-guard' ),
					$ip,
					$lockout_duration,
					$attempts,
					$username
				),
				'danger',
				array(
					'ip_address' => $ip,
					'username'   => $username,
				)
			);
		} else {
			WPSG_Logger::log(
				'login_failed',
				sprintf(
					/* translators: 1: attempt count, 2: max retries, 3: username, 4: IP address */
					__( 'Failed login attempt (%1$d/%2$d) for user "%3$s" from IP %4$s.', 'wp-secure-guard' ),
					$attempts,
					$max_retries,
					$username,
					$ip
				),
				'warning',
				array(
					'ip_address' => $ip,
					'username'   => $username,
				)
			);
		}
	}

	/**
	 * Clear failed attempt count on successful authentication and log event.
	 *
	 * @param string  $user_login User login.
	 * @param WP_User $user       WP_User object.
	 */
	public static function handle_successful_login( $user_login, $user ) {
		$ip = WPSG_Logger::get_client_ip();

		delete_transient( self::get_fail_transient_key( $ip ) );
		delete_transient( self::get_lockout_transient_key( $ip ) );

		WPSG_Logger::log(
			'login_success',
			sprintf(
				/* translators: 1: user login, 2: client IP address */
				__( 'User "%1$s" logged in successfully from IP %2$s.', 'wp-secure-guard' ),
				$user_login,
				$ip
			),
			'info',
			array(
				'ip_address' => $ip,
				'user_id'    => $user->ID,
				'username'   => $user_login,
			)
		);
	}

	/**
	 * Display lockout banner on wp-login.php.
	 *
	 * @param string $message Existing message.
	 * @return string
	 */
	public static function render_lockout_message( $message ) {
		$ip = WPSG_Logger::get_client_ip();
		$lockout_until = get_transient( self::get_lockout_transient_key( $ip ) );

		if ( false !== $lockout_until ) {
			$remaining_seconds = $lockout_until - time();
			$remaining_minutes = max( 1, (int) ceil( $remaining_seconds / 60 ) );

			$notice = sprintf(
				'<div id="login_error" class="notice notice-error" style="border-left-color:#dc3232;">' .
				'<p>%s</p></div>',
				sprintf(
					/* translators: %d: minutes remaining */
					esc_html__( 'Too many failed login attempts from your IP. Lockout active for %d more minute(s).', 'wp-secure-guard' ),
					$remaining_minutes
				)
			);
			return $notice . $message;
		}

		return $message;
	}

	/**
	 * Check if an IP address is in the administrator whitelist.
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 */
	public static function is_ip_whitelisted( $ip ) {
		$whitelist = WPSG_Settings::get( 'login_whitelist_ips', '' );
		if ( empty( $whitelist ) ) {
			return false;
		}

		$lines = explode( "\n", str_replace( array( "\r\n", "\r" ), "\n", $whitelist ) );
		foreach ( $lines as $line ) {
			$whitelisted_ip = trim( $line );
			if ( ! empty( $whitelisted_ip ) && $whitelisted_ip === $ip ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Helper to get transient key for failed attempts.
	 *
	 * @param string $ip Client IP.
	 * @return string
	 */
	private static function get_fail_transient_key( $ip ) {
		return 'wpsg_fail_' . md5( $ip );
	}

	/**
	 * Helper to get transient key for lockout.
	 *
	 * @param string $ip Client IP.
	 * @return string
	 */
	private static function get_lockout_transient_key( $ip ) {
		return 'wpsg_lock_' . md5( $ip );
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled     = (bool) WPSG_Settings::get( 'login_limiter_enable', true );
		$max_retries = absint( WPSG_Settings::get( 'login_max_retries', 5 ) );
		$lockout_min = absint( WPSG_Settings::get( 'login_lockout_duration', 15 ) );

		return array(
			'id'          => 'login_limiter',
			'title'       => __( 'Brute-Force Rate Limiting', 'wp-secure-guard' ),
			'category'    => 'login_security',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? sprintf( __( 'Active (%1$d tries / %2$dm)', 'wp-secure-guard' ), $max_retries, $lockout_min ) : __( 'Disabled', 'wp-secure-guard' ),
			'description' => __( 'Protects against brute-force password cracking by locking out abusive IP addresses.', 'wp-secure-guard' ),
		);
	}
}
