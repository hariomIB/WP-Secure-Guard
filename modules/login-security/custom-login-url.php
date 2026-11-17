<?php
/**
 * Module: Custom Login URL & wp-login.php / wp-admin Cloaking.
 *
 * Changes the default login URL from wp-login.php / wp-admin to a custom slug (e.g. login-controller)
 * and blocks direct access to default login endpoints.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Custom_Login_URL
 */
class WPSG_Custom_Login_URL {

	/**
	 * Initialize custom login hooks.
	 */
	public static function init() {
		// Emergency bypass check via wp-config.php constant.
		if ( defined( 'WPSG_DISABLE_CUSTOM_LOGIN' ) && WPSG_DISABLE_CUSTOM_LOGIN ) {
			return;
		}

		if ( ! WPSG_Settings::get( 'custom_login_enable', false ) ) {
			return;
		}

		// Intercept requests on wp_loaded after WordPress core bootstrap has fully initialized.
		add_action( 'wp_loaded', array( __CLASS__, 'handle_login_routing' ), 1 );

		// Filter URLs across WordPress so forms and links route through custom slug.
		add_filter( 'site_url', array( __CLASS__, 'filter_site_url' ), 10, 4 );
		add_filter( 'network_site_url', array( __CLASS__, 'filter_site_url' ), 10, 4 );
		add_filter( 'login_url', array( __CLASS__, 'filter_login_url' ), 10, 3 );
		add_filter( 'logout_url', array( __CLASS__, 'filter_logout_url' ), 10, 2 );
		add_filter( 'lostpassword_url', array( __CLASS__, 'filter_lostpassword_url' ), 10, 2 );
		add_filter( 'register_url', array( __CLASS__, 'filter_register_url' ), 10, 1 );

		// Intercept /wp-admin for logged-out visitors.
		add_action( 'init', array( __CLASS__, 'block_unauthenticated_wp_admin' ), 1 );
	}

	/**
	 * Get the configured custom login slug.
	 *
	 * @return string
	 */
	public static function get_slug() {
		$slug = WPSG_Settings::get( 'custom_login_slug', 'login-controller' );
		$slug = sanitize_title_with_dashes( trim( (string) $slug ) );
		return ! empty( $slug ) ? $slug : 'login-controller';
	}

	/**
	 * Get the full custom login URL.
	 *
	 * @return string
	 */
	public static function get_custom_login_url() {
		return home_url( '/' . self::get_slug() . '/' );
	}

	/**
	 * Extract normalized request path relative to WordPress home directory.
	 *
	 * @return string
	 */
	public static function get_request_path() {
		if ( empty( $_SERVER['REQUEST_URI'] ) ) {
			return '';
		}

		$req_uri  = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) );
		$req_path = trim( (string) wp_parse_url( $req_uri, PHP_URL_PATH ), '/' );

		// Normalize subdirectory path if WordPress is in a subfolder (e.g. /virajrevamp/)
		$home_path = trim( (string) wp_parse_url( home_url(), PHP_URL_PATH ), '/' );
		if ( ! empty( $home_path ) && 0 === strpos( $req_path, $home_path ) ) {
			$req_path = trim( substr( $req_path, strlen( $home_path ) ), '/' );
		}

		return $req_path;
	}

	/**
	 * Coordinate login routing on wp_loaded:
	 * 1. If custom slug is accessed -> load wp-login.php.
	 * 2. If default wp-login.php is accessed directly -> block with 404.
	 */
	public static function handle_login_routing() {
		$req_path = self::get_request_path();
		$slug     = self::get_slug();

		// Case A: Visitor accessed the secret custom login slug
		if ( $req_path === $slug ) {
			if ( ! defined( 'WPSG_AUTHORIZED_LOGIN_ACCESS' ) ) {
				define( 'WPSG_AUTHORIZED_LOGIN_ACCESS', true );
			}

			global $pagenow, $error, $interim_login, $action, $user_login;
			$pagenow = 'wp-login.php';

			status_header( 200 );
			require_once ABSPATH . 'wp-login.php';
			exit;
		}

		// Case B: Direct visit to wp-login.php without authorization
		if ( ! defined( 'WPSG_AUTHORIZED_LOGIN_ACCESS' ) || ! WPSG_AUTHORIZED_LOGIN_ACCESS ) {
			$raw_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

			if ( false !== stripos( $raw_uri, 'wp-login.php' ) ) {
				// Allow internal password-protected post action
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$action = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : '';
				if ( 'postpass' === $action ) {
					return;
				}

				self::block_access_404();
			}
		}
	}

	/**
	 * Prevent logged-out visitors from seeing wp-admin or being redirected to custom slug.
	 */
	public static function block_unauthenticated_wp_admin() {
		// Logged in users are permitted
		if ( is_user_logged_in() ) {
			return;
		}

		// Skip AJAX, Cron, and REST API
		if ( ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return;
		}

		$raw_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		if ( false !== stripos( $raw_uri, 'wp-admin' ) ) {
			// Exclude admin-ajax.php and admin-post.php
			if ( false !== stripos( $raw_uri, 'admin-ajax.php' ) || false !== stripos( $raw_uri, 'admin-post.php' ) ) {
				return;
			}

			self::block_access_404();
		}
	}

	/**
	 * Serve a robust, crash-proof HTTP 404 response to unauthorized visitors.
	 */
	public static function block_access_404() {
		$ip = WPSG_Logger::get_client_ip();

		WPSG_Logger::log(
			'direct_login_blocked',
			sprintf(
				/* translators: %s: client IP address */
				__( 'Direct access to protected login endpoint blocked from IP %s. Served HTTP 404.', 'wp-secure-guard' ),
				$ip
			),
			'warning',
			array( 'ip_address' => $ip )
		);

		status_header( 404 );
		nocache_headers();

		wp_die(
			'<h1>' . esc_html__( '404 Not Found', 'wp-secure-guard' ) . '</h1>' .
			'<p>' . esc_html__( 'The requested URL was not found on this server.', 'wp-secure-guard' ) . '</p>',
			esc_html__( '404 Not Found', 'wp-secure-guard' ),
			array( 'response' => 404 )
		);
		exit;
	}

	/**
	 * Filter site_url calls targeting wp-login.php to ensure form actions route through custom slug.
	 *
	 * @param string      $url     The complete site URL.
	 * @param string      $path    Path relative to the site URL.
	 * @param string|null $scheme  Scheme to give the site URL.
	 * @param int|null    $blog_id Site ID, or null for the current site.
	 * @return string
	 */
	public static function filter_site_url( $url, $path, $scheme = null, $blog_id = null ) {
		if ( is_string( $path ) && false !== strpos( $path, 'wp-login.php' ) ) {
			$slug  = self::get_slug();
			$query = wp_parse_url( $url, PHP_URL_QUERY );

			$custom_url = home_url( '/' . $slug . '/' );
			if ( ! empty( $query ) ) {
				$custom_url .= '?' . $query;
			}

			return $custom_url;
		}

		return $url;
	}

	/**
	 * Filter the standard login URL to use the custom slug.
	 *
	 * @param string $login_url    The login URL.
	 * @param string $redirect     The path to redirect to on login.
	 * @param bool   $force_reauth Whether to force reauthorization.
	 * @return string
	 */
	public static function filter_login_url( $login_url, $redirect = '', $force_reauth = false ) {
		$custom_url = self::get_custom_login_url();

		if ( ! empty( $redirect ) ) {
			$custom_url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $custom_url );
		}

		if ( $force_reauth ) {
			$custom_url = add_query_arg( 'reauth', '1', $custom_url );
		}

		return $custom_url;
	}

	/**
	 * Filter logout URL to append custom login redirect.
	 *
	 * @param string $logout_url The logout URL.
	 * @param string $redirect   The path to redirect to on logout.
	 * @return string
	 */
	public static function filter_logout_url( $logout_url, $redirect = '' ) {
		return $logout_url;
	}

	/**
	 * Filter lost password URL to route through custom slug.
	 *
	 * @param string $lostpassword_url The lost password URL.
	 * @param string $redirect         The path to redirect to on reset.
	 * @return string
	 */
	public static function filter_lostpassword_url( $lostpassword_url, $redirect = '' ) {
		$custom_url = add_query_arg( 'action', 'lostpassword', self::get_custom_login_url() );
		if ( ! empty( $redirect ) ) {
			$custom_url = add_query_arg( 'redirect_to', rawurlencode( $redirect ), $custom_url );
		}
		return $custom_url;
	}

	/**
	 * Filter registration URL to route through custom slug.
	 *
	 * @param string $register_url The registration URL.
	 * @return string
	 */
	public static function filter_register_url( $register_url ) {
		return add_query_arg( 'action', 'register', self::get_custom_login_url() );
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'custom_login_enable', false );
		$slug    = self::get_slug();

		return array(
			'id'          => 'custom_login_url',
			'title'       => __( 'Custom Login URL', 'wp-secure-guard' ),
			'category'    => 'login_security',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? sprintf( __( 'Active (/%s/)', 'wp-secure-guard' ), $slug ) : __( 'Default wp-login.php Exposed', 'wp-secure-guard' ),
			'slug'        => $slug,
			'url'         => self::get_custom_login_url(),
			'description' => __( 'Hides wp-login.php and wp-admin, routing authentication through a custom secret URL to prevent automated bot brute-force.', 'wp-secure-guard' ),
		);
	}
}
