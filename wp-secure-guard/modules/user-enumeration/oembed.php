<?php
/**
 * Module: oEmbed Author Information Filter.
 *
 * Strips author names and author archive URLs from oEmbed responses.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_oEmbed_Protection
 */
class WPSG_oEmbed_Protection {

	/**
	 * Initialize hooks if enabled.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'oembed_strip_author', true ) ) {
			add_filter( 'oembed_response_data', array( __CLASS__, 'filter_oembed_data' ), 10, 1 );
		}
	}

	/**
	 * Strip author name and author URL from oEmbed response.
	 *
	 * @param array $data The oEmbed response data.
	 * @return array
	 */
	public static function filter_oembed_data( $data ) {
		if ( ! is_array( $data ) ) {
			return $data;
		}

		if ( isset( $data['author_name'] ) ) {
			unset( $data['author_name'] );
		}

		if ( isset( $data['author_url'] ) ) {
			unset( $data['author_url'] );
		}

		return $data;
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'oembed_strip_author', true );
		return array(
			'id'          => 'oembed_strip_author',
			'title'       => __( 'oEmbed Author Data', 'wp-secure-guard' ),
			'category'    => 'user_protection',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? __( 'Filtered', 'wp-secure-guard' ) : __( 'Exposed', 'wp-secure-guard' ),
			'description' => __( 'Removes author usernames and profile links from WordPress oEmbed responses.', 'wp-secure-guard' ),
		);
	}
}
