<?php
/**
 * Module: Author ID Enumeration Protection.
 *
 * Prevents attackers from discovering usernames via /?author=N query string redirects.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Author_Enumeration
 */
class WPSG_Author_Enumeration {

	/**
	 * Initialize hooks if enabled.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'user_enum_block', true ) ) {
			add_action( 'template_redirect', array( __CLASS__, 'block_author_enumeration' ), 1 );
		}
	}

	/**
	 * Inspect request and block ?author=N scanning attempts.
	 */
	public static function block_author_enumeration() {
		if ( is_admin() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['author'] ) || isset( $_REQUEST['author'] ) ) {
			// Check if author query parameter contains an integer / ID.
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$raw_author = isset( $_GET['author'] ) ? sanitize_text_field( wp_unslash( $_GET['author'] ) ) : '';

			if ( '' !== $raw_author && is_numeric( $raw_author ) ) {
				$ip = WPSG_Logger::get_client_ip();

				WPSG_Logger::log(
					'user_enumeration',
					sprintf(
						/* translators: 1: author ID, 2: client IP address */
						__( 'Author ID enumeration probe (author=%1$s) blocked from IP %2$s.', 'wp-secure-guard' ),
						$raw_author,
						$ip
					),
					'warning',
					array( 'ip_address' => $ip )
				);

				// Block enumeration by rendering 404.
				global $wp_query;
				if ( is_object( $wp_query ) ) {
					$wp_query->set_404();
				}
				status_header( 404 );
				nocache_headers();

				$template = get_query_template( '404' );
				if ( $template && file_exists( $template ) ) {
					include $template;
				} else {
					wp_die(
						esc_html__( 'Resource not found.', 'wp-secure-guard' ),
						esc_html__( '404 Not Found', 'wp-secure-guard' ),
						array( 'response' => 404 )
					);
				}
				exit;
			}
		}
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'user_enum_block', true );
		return array(
			'id'          => 'author_enumeration',
			'title'       => __( 'Author ID Enumeration', 'wp-secure-guard' ),
			'category'    => 'user_protection',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? __( 'Protected', 'wp-secure-guard' ) : __( 'Vulnerable', 'wp-secure-guard' ),
			'description' => __( 'Blocks /?author=N scans that expose WordPress usernames to automated bots.', 'wp-secure-guard' ),
		);
	}
}
