<?php
/**
 * Module: User Registration Restriction & Spam Account Protection.
 *
 * Controls whether public user registration is enabled or disabled, blocks registration endpoints,
 * and restricts REST API user creation to prevent spam and fake account creation.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_User_Registration
 */
class WPSG_User_Registration {

	/**
	 * Initialize registration restriction hooks.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'disable_user_registration', false ) ) {
			// 1. Force users_can_register option to 0 (false).
			add_filter( 'pre_option_users_can_register', '__return_zero' );
			add_filter( 'option_users_can_register', '__return_zero' );

			// 2. Intercept direct registration actions on init and login_init.
			add_action( 'init', array( __CLASS__, 'block_registration_screen' ), 1 );
			add_action( 'login_init', array( __CLASS__, 'block_registration_screen' ), 1 );

			// 3. Block REST API user creation for non-admins.
			add_filter( 'rest_pre_dispatch', array( __CLASS__, 'block_rest_user_creation' ), 10, 3 );
		}
	}

	/**
	 * Block access to wp-login.php?action=register and wp-signup.php.
	 */
	public static function block_registration_screen() {
		$raw_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : '';

		$is_register_action = ( 'register' === $action );
		$is_signup_page     = ( false !== stripos( $raw_uri, 'wp-signup.php' ) );

		if ( $is_register_action || $is_signup_page ) {
			$ip = WPSG_Logger::get_client_ip();

			WPSG_Logger::log(
				'registration_attempt_blocked',
				sprintf(
					/* translators: %s: client IP address */
					__( 'Blocked user registration attempt from IP %s (Public registration is disabled).', 'wp-secure-guard' ),
					$ip
				),
				'warning',
				array( 'ip_address' => $ip, 'request_uri' => $raw_uri )
			);

			status_header( 403 );
			nocache_headers();

			wp_die(
				'<h1>' . esc_html__( 'Registration Disabled', 'wp-secure-guard' ) . '</h1>' .
				'<p>' . esc_html__( 'User registration is currently disabled on this site.', 'wp-secure-guard' ) . '</p>',
				esc_html__( 'Registration Disabled', 'wp-secure-guard' ),
				array( 'response' => 403 )
			);
			exit;
		}
	}

	/**
	 * Block REST API user creation requests for unauthenticated visitors.
	 *
	 * @param mixed           $result  Response result.
	 * @param WP_REST_Server  $server  Server instance.
	 * @param WP_REST_Request $request Request instance.
	 * @return mixed
	 */
	public static function block_rest_user_creation( $result, $server, $request ) {
		if ( 'POST' === $request->get_method() && preg_match( '#^/wp/v2/users(\b|/|\?)#i', $request->get_route() ) ) {
			if ( ! is_user_logged_in() || ! current_user_can( 'create_users' ) ) {
				return new WP_Error(
					'rest_registration_disabled',
					__( 'Public user registration is disabled.', 'wp-secure-guard' ),
					array( 'status' => 403 )
				);
			}
		}

		return $result;
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$plugin_disabled = (bool) WPSG_Settings::get( 'disable_user_registration', false );
		$core_can_reg    = (bool) get_option( 'users_can_register', false );

		$is_disabled = $plugin_disabled || ! $core_can_reg;

		return array(
			'id'          => 'user_registration',
			'title'       => __( 'User Registration Control', 'wp-secure-guard' ),
			'category'    => 'login_security',
			'enabled'     => $plugin_disabled,
			'status'      => $is_disabled ? 'passed' : 'warning',
			'label'       => $is_disabled ? __( 'Registration Disabled (Secure)', 'wp-secure-guard' ) : __( 'Open Registration (Public)', 'wp-secure-guard' ),
			'description' => __( 'Disables public membership registration to prevent malicious bots from creating unauthorized subscriber or spam accounts.', 'wp-secure-guard' ),
		);
	}
}
