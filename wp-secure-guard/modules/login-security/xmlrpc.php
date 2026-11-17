<?php
/**
 * Module: XML-RPC Protection.
 *
 * Disables XML-RPC endpoints and pingbacks to prevent brute-force attacks and DDoS amplification.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_XMLRPC_Protection
 */
class WPSG_XMLRPC_Protection {

	/**
	 * Initialize hooks if enabled.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'xmlrpc_disable', true ) ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', array( __CLASS__, 'disable_xmlrpc_methods' ) );
			add_filter( 'wp_headers', array( __CLASS__, 'remove_pingback_header' ) );
			add_action( 'init', array( __CLASS__, 'block_direct_xmlrpc_requests' ) );
		}
	}

	/**
	 * Empty the list of available XML-RPC methods.
	 *
	 * @param array $methods Method names array.
	 * @return array
	 */
	public static function disable_xmlrpc_methods( $methods ) {
		return array();
	}

	/**
	 * Remove X-Pingback from HTTP response headers.
	 *
	 * @param array $headers Response headers.
	 * @return array
	 */
	public static function remove_pingback_header( $headers ) {
		if ( isset( $headers['X-Pingback'] ) ) {
			unset( $headers['X-Pingback'] );
		}
		return $headers;
	}

	/**
	 * Block direct requests hitting xmlrpc.php.
	 */
	public static function block_direct_xmlrpc_requests() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		if ( preg_match( '/xmlrpc\.php/i', $request_uri ) ) {
			$ip = WPSG_Logger::get_client_ip();

			WPSG_Logger::log(
				'xmlrpc_blocked',
				sprintf(
					/* translators: %s: client IP address */
					__( 'XML-RPC request blocked from IP %s.', 'wp-secure-guard' ),
					$ip
				),
				'warning',
				array( 'ip_address' => $ip )
			);

			status_header( 403 );
			nocache_headers();
			wp_die(
				esc_html__( 'XML-RPC services are disabled on this site for security reasons.', 'wp-secure-guard' ),
				esc_html__( '403 Forbidden', 'wp-secure-guard' ),
				array( 'response' => 403 )
			);
		}
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'xmlrpc_disable', true );
		return array(
			'id'          => 'xmlrpc_disable',
			'title'       => __( 'XML-RPC Protection', 'wp-secure-guard' ),
			'category'    => 'login_security',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? __( 'Disabled & Blocked', 'wp-secure-guard' ) : __( 'Enabled', 'wp-secure-guard' ),
			'description' => __( 'Disables XML-RPC API and pingback header to prevent DDoS amplification and automated credential stuffing.', 'wp-secure-guard' ),
		);
	}
}
