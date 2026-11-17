<?php
/**
 * Module: REST API User Enumeration Protection.
 *
 * Restricts unauthenticated access to /wp-json/wp/v2/users endpoints.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_REST_API_Protection
 */
class WPSG_REST_API_Protection {

	/**
	 * Initialize hooks if enabled.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'rest_api_user_protect', true ) ) {
			add_filter( 'rest_authentication_errors', array( __CLASS__, 'restrict_user_endpoint' ), 20 );
			add_filter( 'rest_endpoints', array( __CLASS__, 'filter_endpoints' ), 20 );
		}
	}

	/**
	 * Restrict access to /wp/v2/users for unauthorized requests.
	 *
	 * @param WP_Error|null|bool $result Error object or null.
	 * @return WP_Error|null|bool
	 */
	public static function restrict_user_endpoint( $result ) {
		if ( ! empty( $result ) ) {
			return $result;
		}

		if ( is_user_logged_in() && current_user_can( 'list_users' ) ) {
			return $result;
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		if ( preg_match( '#/wp/v2/users(\b|/|\?)#i', $request_uri ) ) {
			$ip = WPSG_Logger::get_client_ip();

			WPSG_Logger::log(
				'rest_user_enumeration',
				sprintf(
					/* translators: %s: client IP address */
					__( 'Unauthenticated REST API user enumeration blocked from IP %s.', 'wp-secure-guard' ),
					$ip
				),
				'warning',
				array( 'ip_address' => $ip )
			);

			return new WP_Error(
				'rest_forbidden_context',
				__( 'Access to the user directory via REST API is restricted.', 'wp-secure-guard' ),
				array( 'status' => rest_authorization_required_code() )
			);
		}

		return $result;
	}

	/**
	 * Remove public user endpoints for non-logged-in visitors.
	 *
	 * @param array $endpoints Registered REST endpoints.
	 * @return array
	 */
	public static function filter_endpoints( $endpoints ) {
		if ( is_user_logged_in() && current_user_can( 'list_users' ) ) {
			return $endpoints;
		}

		if ( isset( $endpoints['/wp/v2/users'] ) ) {
			unset( $endpoints['/wp/v2/users'] );
		}
		if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
			unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		}

		return $endpoints;
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'rest_api_user_protect', true );
		return array(
			'id'          => 'rest_api_user_protect',
			'title'       => __( 'REST API User Enumeration', 'wp-secure-guard' ),
			'category'    => 'user_protection',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? __( 'Protected', 'wp-secure-guard' ) : __( 'Vulnerable', 'wp-secure-guard' ),
			'description' => __( 'Stops unauthenticated visitors from harvesting usernames via /wp-json/wp/v2/users.', 'wp-secure-guard' ),
		);
	}
}
