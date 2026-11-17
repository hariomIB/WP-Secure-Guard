<?php
/**
 * Module: Public Author Archives Protection.
 *
 * Controls exposure of public /author/{username} profile pages.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Author_Archives
 */
class WPSG_Author_Archives {

	/**
	 * Initialize hooks if enabled.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'author_archive_disable', false ) ) {
			add_action( 'template_redirect', array( __CLASS__, 'disable_author_archives' ) );
			add_filter( 'author_link', array( __CLASS__, 'filter_author_link' ), 10, 3 );
		}
	}

	/**
	 * Redirect public author archive requests to homepage.
	 */
	public static function disable_author_archives() {
		if ( is_author() && ! is_admin() ) {
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	/**
	 * Replace public author links with the site home URL or clean anchor.
	 *
	 * @param string $link            Author profile link.
	 * @param int    $author_id       Author ID.
	 * @param string $author_nicename Author slug.
	 * @return string
	 */
	public static function filter_author_link( $link, $author_id, $author_nicename ) {
		return home_url( '/' );
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'author_archive_disable', false );
		return array(
			'id'          => 'author_archive_disable',
			'title'       => __( 'Public Author Archives', 'wp-secure-guard' ),
			'category'    => 'user_protection',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? __( 'Disabled', 'wp-secure-guard' ) : __( 'Active', 'wp-secure-guard' ),
			'description' => __( 'Redirects /author/{username} pages to home to hide author login names.', 'wp-secure-guard' ),
		);
	}
}
