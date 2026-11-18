<?php
/**
 * Module: Cookie Security & HTTP Header Hardening.
 *
 * Automatically enforces Secure, HttpOnly, and SameSite (Lax/Strict) attributes
 * on all outgoing HTTP cookies (including third-party security plugin cookies like
 * icwp-wpsf-notbot, session cookies, and auth tokens) to eliminate Netsparker,
 * Acunetix, and OWASP ZAP cookie security vulnerability findings.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Cookie_Security
 */
class WPSG_Cookie_Security {

	/**
	 * Cookie names / prefixes that intentionally require client-side JavaScript access.
	 *
	 * @var array
	 */
	private static $js_cookie_exceptions = array(
		'_ga',
		'_gid',
		'_gat',
		'wp-settings-',
		'wp-settings-time-',
	);

	/**
	 * Initialize module.
	 */
	public static function init() {
		if ( ! WPSG_Settings::get( 'cookie_security_enable', true ) ) {
			return;
		}

		// 1. Enforce PHP session cookie parameters at runtime.
		@ini_set( 'session.cookie_httponly', '1' );
		@ini_set( 'session.cookie_samesite', 'Lax' );
		if ( is_ssl() ) {
			@ini_set( 'session.cookie_secure', '1' );
		}

		// 2. Intercept outgoing HTTP headers before they are transmitted to the client.
		if ( function_exists( 'header_register_callback' ) ) {
			header_register_callback( array( __CLASS__, 'process_outgoing_cookies' ) );
		}
	}

	/**
	 * Process all queued Set-Cookie headers and ensure required security attributes exist.
	 */
	public static function process_outgoing_cookies() {
		if ( headers_sent() ) {
			return;
		}

		$headers = headers_list();
		if ( empty( $headers ) ) {
			return;
		}

		$cookie_headers = array();
		foreach ( $headers as $header ) {
			if ( stripos( $header, 'Set-Cookie:' ) === 0 ) {
				$cookie_headers[] = trim( substr( $header, 11 ) );
			}
		}

		if ( empty( $cookie_headers ) ) {
			return;
		}

		header_remove( 'Set-Cookie' );

		$is_ssl          = is_ssl();
		$samesite_policy = WPSG_Settings::get( 'cookie_samesite_policy', 'Lax' );
		if ( ! in_array( $samesite_policy, array( 'Lax', 'Strict', 'None' ), true ) ) {
			$samesite_policy = 'Lax';
		}
		$enforce_httponly = (bool) WPSG_Settings::get( 'cookie_httponly_enable', true );
		$enforce_secure   = (bool) WPSG_Settings::get( 'cookie_secure_enable', true );

		foreach ( $cookie_headers as $cookie_string ) {
			$secured_cookie = self::secure_cookie_string(
				$cookie_string,
				$is_ssl,
				$samesite_policy,
				$enforce_httponly,
				$enforce_secure
			);

			header( 'Set-Cookie: ' . $secured_cookie, false );
		}
	}

	/**
	 * Hardens a single raw cookie string by injecting missing security directives.
	 *
	 * @param string $cookie_string   Raw cookie string (name=value; path=/; ...).
	 * @param bool   $is_ssl          Whether the current request is over SSL/HTTPS.
	 * @param string $samesite_policy SameSite policy (Lax/Strict).
	 * @param bool   $enforce_httponly Whether to append HttpOnly.
	 * @param bool   $enforce_secure   Whether to append Secure.
	 * @return string Hardened cookie string.
	 */
	public static function secure_cookie_string(
		$cookie_string,
		$is_ssl = true,
		$samesite_policy = 'Lax',
		$enforce_httponly = true,
		$enforce_secure = true
	) {
		$cookie_val = trim( $cookie_string );

		// Extract cookie name
		$cookie_name = '';
		if ( preg_match( '/^([^=;]+)=/i', $cookie_val, $matches ) ) {
			$cookie_name = trim( $matches[1] );
		}

		// 1. SameSite directive
		if ( ! preg_match( '/;\s*samesite=/i', $cookie_val ) ) {
			$cookie_val .= '; SameSite=' . $samesite_policy;
		}

		// 2. Secure directive (required when over HTTPS)
		if ( $enforce_secure && $is_ssl && ! preg_match( '/;\s*secure/i', $cookie_val ) ) {
			$cookie_val .= '; Secure';
		}

		// 3. HttpOnly directive (protects against XSS cookie-theft)
		if ( $enforce_httponly && ! preg_match( '/;\s*httponly/i', $cookie_val ) ) {
			$allow_js = false;
			foreach ( self::$js_cookie_exceptions as $prefix ) {
				if ( 0 === strpos( $cookie_name, $prefix ) ) {
					$allow_js = true;
					break;
				}
			}

			if ( ! $allow_js ) {
				$cookie_val .= '; HttpOnly';
			}
		}

		return $cookie_val;
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'cookie_security_enable', true );
		return array(
			'id'          => 'cookie_security',
			'title'       => __( 'Cookie Security Hardening (HttpOnly & SameSite)', 'wp-secure-guard' ),
			'category'    => 'login_security',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? __( 'Active & Hardened', 'wp-secure-guard' ) : __( 'Disabled', 'wp-secure-guard' ),
			'description' => __( 'Enforces Secure, HttpOnly, and SameSite flags on all outgoing cookies to defeat scanner vulnerabilities (Netsparker/Invicti).', 'wp-secure-guard' ),
		);
	}
}
