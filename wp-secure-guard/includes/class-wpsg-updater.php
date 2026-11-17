<?php
/**
 * Remote Auto-Updater for WP Secure Guard.
 *
 * Checks GitHub repository or custom update endpoint for new releases,
 * integrates with WordPress's native Update Core and Plugins page,
 * and enables seamless 1-click updates on all client sites.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Updater
 */
class WPSG_Updater {

	/**
	 * Remote version info URL (GitHub raw version metadata).
	 */
	const REMOTE_JSON_URL = 'https://raw.githubusercontent.com/hariomIB/WP-Secure-Guard/main/version.json';

	/**
	 * Fallback GitHub Releases API endpoint.
	 */
	const GITHUB_API_URL = 'https://api.github.com/repos/hariomIB/WP-Secure-Guard/releases/latest';

	/**
	 * Transient key for caching remote version check.
	 */
	const CACHE_KEY = 'wpsg_remote_version_info';

	/**
	 * Cache duration in seconds (12 hours).
	 */
	const CACHE_DURATION = 43200;

	/**
	 * Initialize updater hooks.
	 */
	public static function init() {
		// 1. Inject update information into WordPress plugins update transient.
		add_filter( 'pre_set_site_transient_update_plugins', array( __CLASS__, 'check_for_update' ) );

		// 2. Supply plugin information popup details (View version details modal).
		add_filter( 'plugins_api', array( __CLASS__, 'plugin_info' ), 20, 3 );

		// 3. Ensure post-install directory naming is always 'wp-secure-guard'.
		add_filter( 'upgrader_post_install', array( __CLASS__, 'post_install' ), 10, 3 );

		// 4. Listen for manual "Check for Updates" trigger in WP Secure Guard.
		add_action( 'admin_init', array( __CLASS__, 'handle_manual_update_check' ) );
	}

	/**
	 * Check remote source for available plugin updates.
	 *
	 * @param object $transient Update plugins site transient.
	 * @return object
	 */
	public static function check_for_update( $transient ) {
		if ( empty( $transient->checked ) ) {
			return $transient;
		}

		$remote = self::get_remote_version_info();
		if ( ! $remote || empty( $remote['version'] ) ) {
			return $transient;
		}

		$plugin_file = plugin_basename( WPSG_PLUGIN_FILE );

		if ( version_compare( $remote['version'], WPSG_VERSION, '>' ) ) {
			$update_data = (object) array(
				'id'            => $plugin_file,
				'slug'          => 'wp-secure-guard',
				'plugin'        => $plugin_file,
				'new_version'   => $remote['version'],
				'url'           => ! empty( $remote['homepage'] ) ? $remote['homepage'] : 'https://github.com/hariomIB/WP-Secure-Guard',
				'package'       => ! empty( $remote['download_url'] ) ? $remote['download_url'] : '',
				'icons'         => ! empty( $remote['icons'] ) ? (array) $remote['icons'] : array(),
				'banners'       => ! empty( $remote['banners'] ) ? (array) $remote['banners'] : array(),
				'tested'        => ! empty( $remote['tested'] ) ? $remote['tested'] : '',
				'requires_php'  => ! empty( $remote['requires_php'] ) ? $remote['requires_php'] : '7.4',
				'compatibility' => new stdClass(),
			);

			$transient->response[ $plugin_file ] = $update_data;
		} else {
			$no_update_data = (object) array(
				'id'            => $plugin_file,
				'slug'          => 'wp-secure-guard',
				'plugin'        => $plugin_file,
				'new_version'   => $remote['version'],
				'url'           => ! empty( $remote['homepage'] ) ? $remote['homepage'] : 'https://github.com/hariomIB/WP-Secure-Guard',
				'package'       => '',
			);

			$transient->no_update[ $plugin_file ] = $no_update_data;
		}

		return $transient;
	}

	/**
	 * Intercept WordPress plugin information popup.
	 *
	 * @param false|object|array $res    The result object.
	 * @param string             $action The API action being performed.
	 * @param object             $args   Plugin API arguments.
	 * @return object|false
	 */
	public static function plugin_info( $res, $action, $args ) {
		if ( 'plugin_information' !== $action || ! isset( $args->slug ) || 'wp-secure-guard' !== $args->slug ) {
			return $res;
		}

		$remote = self::get_remote_version_info();
		if ( ! $remote ) {
			return $res;
		}

		$plugin_info = (object) array(
			'name'              => ! empty( $remote['name'] ) ? $remote['name'] : 'WP Secure Guard',
			'slug'              => 'wp-secure-guard',
			'version'           => $remote['version'],
			'author'            => ! empty( $remote['author'] ) ? $remote['author'] : 'WP Secure Guard Team',
			'author_profile'    => ! empty( $remote['author_homepage'] ) ? $remote['author_homepage'] : 'https://github.com/hariomIB/WP-Secure-Guard',
			'homepage'          => ! empty( $remote['homepage'] ) ? $remote['homepage'] : 'https://github.com/hariomIB/WP-Secure-Guard',
			'requires'          => ! empty( $remote['requires'] ) ? $remote['requires'] : '5.8',
			'tested'            => ! empty( $remote['tested'] ) ? $remote['tested'] : '6.5',
			'requires_php'      => ! empty( $remote['requires_php'] ) ? $remote['requires_php'] : '7.4',
			'last_updated'      => ! empty( $remote['last_updated'] ) ? $remote['last_updated'] : current_time( 'Y-m-d' ),
			'download_link'     => ! empty( $remote['download_url'] ) ? $remote['download_url'] : '',
			'sections'          => ! empty( $remote['sections'] ) ? (array) $remote['sections'] : array(
				'description' => 'Advanced modular WordPress security suite featuring User Enumeration Protection, Brute-Force Rate Limiting, Custom Login URL, Native TOTP 2FA, XML-RPC Shield, WAF Firewall, Sensitive File Protection, and Activity Logs.',
			),
			'banners'           => ! empty( $remote['banners'] ) ? (array) $remote['banners'] : array(),
		);

		return $plugin_info;
	}

	/**
	 * Guarantee the destination directory stays 'wp-secure-guard' after unzipping an update.
	 *
	 * @param bool  $response   Installation response.
	 * @param array $hook_extra Extra hook parameters.
	 * @param array $result     Installation results.
	 * @return array
	 */
	public static function post_install( $response, $hook_extra, $result ) {
		global $wp_filesystem;

		$plugin_file = plugin_basename( WPSG_PLUGIN_FILE );

		if ( ! isset( $hook_extra['plugin'] ) || $hook_extra['plugin'] !== $plugin_file ) {
			return $result;
		}

		$proper_destination = trailingslashit( WP_PLUGIN_DIR ) . 'wp-secure-guard';

		// If unpacked directory has a different name (e.g. branch suffix from git archive), normalize it.
		if ( isset( $result['destination'] ) && $result['destination'] !== $proper_destination ) {
			if ( $wp_filesystem->exists( $proper_destination ) ) {
				$wp_filesystem->delete( $proper_destination, true );
			}
			$wp_filesystem->move( $result['destination'], $proper_destination );
			$result['destination'] = $proper_destination;
		}

		// Re-activate plugin if it was active prior to update.
		if ( ! is_plugin_active( $plugin_file ) ) {
			activate_plugin( $plugin_file );
		}

		return $result;
	}

	/**
	 * Fetch remote version details with caching.
	 *
	 * @param bool $force_refresh Whether to bypass cache.
	 * @return array|false
	 */
	public static function get_remote_version_info( $force_refresh = false ) {
		if ( ! $force_refresh ) {
			$cached = get_transient( self::CACHE_KEY );
			if ( false !== $cached && is_array( $cached ) ) {
				return $cached;
			}
		}

		// 1. Primary: Fetch static version.json from raw GitHub (No API rate limits).
		$response = wp_remote_get(
			self::REMOTE_JSON_URL,
			array(
				'timeout' => 10,
				'headers' => array(
					'Accept' => 'application/json',
				),
			)
		);

		if ( ! is_wp_error( $response ) && 200 === (int) wp_remote_retrieve_response_code( $response ) ) {
			$body = wp_remote_retrieve_body( $response );
			$data = json_decode( $body, true );
			if ( ! empty( $data ) && is_array( $data ) && ! empty( $data['version'] ) ) {
				set_transient( self::CACHE_KEY, $data, self::CACHE_DURATION );
				return $data;
			}
		}

		// 2. Fallback: Query GitHub Releases API.
		$api_response = wp_remote_get(
			self::GITHUB_API_URL,
			array(
				'timeout' => 10,
				'headers' => array(
					'User-Agent' => 'WP-Secure-Guard-Updater',
					'Accept'     => 'application/vnd.github.v3+json',
				),
			)
		);

		if ( ! is_wp_error( $api_response ) && 200 === (int) wp_remote_retrieve_response_code( $api_response ) ) {
			$release = json_decode( wp_remote_retrieve_body( $api_response ), true );
			if ( ! empty( $release['tag_name'] ) ) {
				$version = ltrim( $release['tag_name'], 'vV' );
				$download_url = '';

				// Look for uploaded wp-secure-guard.zip asset in release.
				if ( ! empty( $release['assets'] ) && is_array( $release['assets'] ) ) {
					foreach ( $release['assets'] as $asset ) {
						if ( 'wp-secure-guard.zip' === $asset['name'] && ! empty( $asset['browser_download_url'] ) ) {
							$download_url = $asset['browser_download_url'];
							break;
						}
					}
				}

				if ( empty( $download_url ) && ! empty( $release['zipball_url'] ) ) {
					$download_url = $release['zipball_url'];
				}

				$data = array(
					'name'         => 'WP Secure Guard',
					'slug'         => 'wp-secure-guard',
					'version'      => $version,
					'download_url' => $download_url,
					'homepage'     => ! empty( $release['html_url'] ) ? $release['html_url'] : 'https://github.com/hariomIB/WP-Secure-Guard',
					'author'       => 'WP Secure Guard Team',
					'last_updated' => ! empty( $release['published_at'] ) ? substr( $release['published_at'], 0, 10 ) : current_time( 'Y-m-d' ),
					'sections'     => array(
						'description' => 'WP Secure Guard Security Suite.',
						'changelog'   => ! empty( $release['body'] ) ? wp_kses_post( wpautop( $release['body'] ) ) : 'Maintenance and security updates.',
					),
				);

				set_transient( self::CACHE_KEY, $data, self::CACHE_DURATION );
				return $data;
			}
		}

		return false;
	}

	/**
	 * Handle manual "Check for Updates" button click.
	 */
	public static function handle_manual_update_check() {
		if ( ! isset( $_GET['wpsg_action'] ) || 'check_updates' !== $_GET['wpsg_action'] ) {
			return;
		}

		if ( ! current_user_can( 'update_plugins' ) ) {
			return;
		}

		check_admin_referer( 'wpsg_manual_update_check' );

		// Clear cache and re-fetch.
		delete_transient( self::CACHE_KEY );
		delete_site_transient( 'update_plugins' );
		self::get_remote_version_info( true );

		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : 'wpsg-dashboard';
		wp_safe_redirect( add_query_arg( array( 'page' => $page, 'wpsg_updated_checked' => '1' ), admin_url( 'admin.php' ) ) );
		exit;
	}
}
