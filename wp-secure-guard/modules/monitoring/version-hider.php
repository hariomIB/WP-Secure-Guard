<?php
/**
 * Module: WordPress Version Cloaking & Generator Obfuscation.
 *
 * Removes WordPress version information from HTML meta tags, asset query strings, RSS feeds, and headers
 * to prevent vulnerability scanners (WPScan, Wappalyzer, BuiltWith) from profiling the exact core version.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Version_Hider
 */
class WPSG_Version_Hider {

	/**
	 * Initialize version cloaking hooks.
	 */
	public static function init() {
		if ( ! WPSG_Settings::get( 'hide_wp_version', true ) ) {
			return;
		}

		// 1. Remove generator meta tags from HTML head.
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );

		// 2. Remove generator signatures from RSS, Atom, RDF, and Comments feeds.
		add_filter( 'get_the_generator_html', '__return_empty_string' );
		add_filter( 'get_the_generator_xhtml', '__return_empty_string' );
		add_filter( 'get_the_generator_atom', '__return_empty_string' );
		add_filter( 'get_the_generator_rss2', '__return_empty_string' );
		add_filter( 'get_the_generator_comment', '__return_empty_string' );
		add_filter( 'get_the_generator_export', '__return_empty_string' );

		// 3. Remove ?ver=X.X.X query parameters from styles and scripts on frontend.
		if ( ! is_admin() ) {
			add_filter( 'style_loader_src', array( __CLASS__, 'remove_version_query_strings' ), 9999 );
			add_filter( 'script_loader_src', array( __CLASS__, 'remove_version_query_strings' ), 9999 );
		}

		// 4. Remove Windows Live Writer and RSD links if present in head.
		remove_action( 'wp_head', 'wlwmanifest_link' );
		remove_action( 'wp_head', 'rsd_link' );
	}

	/**
	 * Strip WordPress core version from enqueued scripts and stylesheets.
	 *
	 * @param string $src Asset URL.
	 * @return string Cleaned asset URL.
	 */
	public static function remove_version_query_strings( $src ) {
		if ( empty( $src ) ) {
			return $src;
		}

		$wp_version = get_bloginfo( 'version' );

		// Only strip version if it matches the current WordPress core version.
		if ( strpos( $src, 'ver=' . $wp_version ) !== false ) {
			$src = remove_query_arg( 'ver', $src );
		}

		return $src;
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'hide_wp_version', true );

		return array(
			'id'          => 'hide_wp_version',
			'title'       => __( 'Hide WordPress Version', 'wp-secure-guard' ),
			'category'    => 'monitoring',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? __( 'Hidden / Cloaked', 'wp-secure-guard' ) : __( 'Exposed in HTML & Feeds', 'wp-secure-guard' ),
			'description' => __( 'Removes generator meta tags, script/style ?ver= parameters, and feed signatures so automated scanners cannot profile your core version.', 'wp-secure-guard' ),
		);
	}
}
