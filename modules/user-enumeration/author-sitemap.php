<?php
/**
 * Module: Author Sitemap Protection.
 *
 * Disables the public author/user XML sitemaps to prevent indexing user profiles.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Author_Sitemap
 */
class WPSG_Author_Sitemap {

	/**
	 * Initialize hooks if enabled.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'author_sitemap_disable', true ) ) {
			add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'remove_users_sitemap_provider' ), 10, 2 );
			add_filter( 'wp_sitemaps_post_types', array( __CLASS__, 'filter_sitemap_types' ), 10, 1 );
		}
	}

	/**
	 * Remove the core 'users' sitemap provider.
	 *
	 * @param WP_Sitemaps_Provider|bool $provider The sitemap provider instance.
	 * @param string                    $name     The name of the provider.
	 * @return WP_Sitemaps_Provider|bool
	 */
	public static function remove_users_sitemap_provider( $provider, $name ) {
		if ( 'users' === $name ) {
			return false;
		}
		return $provider;
	}

	/**
	 * Ensure no user sitemap references remain.
	 *
	 * @param array $post_types Array of post types.
	 * @return array
	 */
	public static function filter_sitemap_types( $post_types ) {
		return $post_types;
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'author_sitemap_disable', true );
		return array(
			'id'          => 'author_sitemap_disable',
			'title'       => __( 'Author XML Sitemap', 'wp-secure-guard' ),
			'category'    => 'user_protection',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? __( 'Disabled', 'wp-secure-guard' ) : __( 'Enabled', 'wp-secure-guard' ),
			'description' => __( 'Disables the user sitemap (wp-sitemap-users-1.xml) from search engine index lists.', 'wp-secure-guard' ),
		);
	}
}
