<?php
/**
 * Module: Server Information & Header Shield.
 *
 * Removes X-Powered-By and Server response headers and disables Apache ServerSignature
 * to obscure underlying server operating system and server software daemon details.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Server_Info_Hider
 */
class WPSG_Server_Info_Hider {

	/**
	 * Marker comment for .htaccess rules.
	 */
	const HTACCESS_MARKER = 'WP Secure Guard - Hide Server Info';

	/**
	 * Initialize server info shield hooks.
	 */
	public static function init() {
		if ( ! WPSG_Settings::get( 'hide_server_info', true ) ) {
			return;
		}

		// 1. Strip HTTP headers via PHP runtime.
		add_action( 'send_headers', array( __CLASS__, 'remove_server_headers' ), 9999 );
		add_action( 'init', array( __CLASS__, 'remove_server_headers' ), 1 );

		// 2. Ensure Apache .htaccess rules exist.
		add_action( 'admin_init', array( __CLASS__, 'ensure_htaccess_rules' ) );
	}

	/**
	 * Remove identifying server headers from PHP response.
	 */
	public static function remove_server_headers() {
		if ( function_exists( 'header_remove' ) && ! headers_sent() ) {
			@header_remove( 'X-Powered-By' );
			@header_remove( 'Server' );
		}
	}

	/**
	 * Ensure root .htaccess contains ServerSignature Off and header unsetting.
	 */
	public static function ensure_htaccess_rules() {
		$server = WPSG_Uploads_Protection::get_server_type();
		if ( ! in_array( $server, array( 'apache', 'litespeed' ), true ) ) {
			return;
		}

		$root_htaccess = get_home_path() . '.htaccess';
		if ( ! file_exists( $root_htaccess ) || ! is_writable( $root_htaccess ) ) {
			return;
		}

		$content = file_get_contents( $root_htaccess );
		if ( false === strpos( $content, self::HTACCESS_MARKER ) ) {
			self::install_htaccess_rules();
		}
	}

	/**
	 * Install header unsetting rules to root .htaccess.
	 *
	 * @return bool
	 */
	public static function install_htaccess_rules() {
		$root_htaccess = get_home_path() . '.htaccess';

		$rules = array(
			'ServerSignature Off',
			'<IfModule mod_headers.c>',
			'    Header unset Server',
			'    Header unset X-Powered-By',
			'    Header always unset X-Powered-By',
			'</IfModule>',
		);

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';

		return insert_with_markers( $root_htaccess, self::HTACCESS_MARKER, $rules );
	}

	/**
	 * Remove server info rules from root .htaccess.
	 *
	 * @return bool
	 */
	public static function remove_htaccess_rules() {
		$root_htaccess = get_home_path() . '.htaccess';
		if ( ! file_exists( $root_htaccess ) ) {
			return true;
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';

		return insert_with_markers( $root_htaccess, self::HTACCESS_MARKER, array() );
	}

	/**
	 * Get Nginx configuration snippet for hiding server info.
	 *
	 * @return string
	 */
	public static function get_nginx_snippet() {
		return "# WP Secure Guard - Hide Server Information\n" .
			"server_tokens off;\n" .
			"more_clear_headers 'Server' 'X-Powered-By';";
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'hide_server_info', true );

		return array(
			'id'          => 'hide_server_info',
			'title'       => __( 'Hide Server Information', 'wp-secure-guard' ),
			'category'    => 'monitoring',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? __( 'Hidden (Headers & Signatures Stripped)', 'wp-secure-guard' ) : __( 'Exposed in HTTP Headers', 'wp-secure-guard' ),
			'description' => __( 'Suppresses Server and X-Powered-By HTTP response headers and disables Apache ServerSignature banners.', 'wp-secure-guard' ),
		);
	}
}
