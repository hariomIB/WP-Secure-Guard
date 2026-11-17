<?php
/**
 * Module: Directory Listing & Indexing Prevention.
 *
 * Prevents web servers from displaying directory listings when index files are absent.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Directory_Listing
 */
class WPSG_Directory_Listing {

	/**
	 * Marker comment for directory indexing .htaccess rules.
	 */
	const HTACCESS_MARKER = 'WP Secure Guard - Directory Browsing Protection';

	/**
	 * Initialize module.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'directory_listing_protect', true ) ) {
			add_action( 'admin_init', array( __CLASS__, 'protect_directories' ) );
		}
	}

	/**
	 * Place blank index.php files and .htaccess Options -Indexes rules.
	 */
	public static function protect_directories() {
		// 1. Place blank index.php in uploads if missing.
		$upload_dir = wp_upload_dir();
		$uploads_base = trailingslashit( $upload_dir['basedir'] );

		if ( is_dir( $uploads_base ) && is_writable( $uploads_base ) ) {
			$index_file = $uploads_base . 'index.php';
			if ( ! file_exists( $index_file ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFileSystem.file_system_read_file_put_contents
				file_put_contents( $index_file, "<?php\n// Silence is golden.\n" );
			}
		}

		// 2. Add Options -Indexes to root .htaccess on Apache.
		$server = WPSG_Uploads_Protection::get_server_type();
		if ( in_array( $server, array( 'apache', 'litespeed' ), true ) ) {
			$root_htaccess = get_home_path() . '.htaccess';
			if ( file_exists( $root_htaccess ) && is_writable( $root_htaccess ) ) {
				$content = file_get_contents( $root_htaccess );
				if ( false === strpos( $content, self::HTACCESS_MARKER ) ) {
					require_once ABSPATH . 'wp-admin/includes/file.php';
					require_once ABSPATH . 'wp-admin/includes/misc.php';
					insert_with_markers( $root_htaccess, self::HTACCESS_MARKER, array( 'Options -Indexes' ) );
				}
			}
		}
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'directory_listing_protect', true );
		return array(
			'id'          => 'directory_listing',
			'title'       => __( 'Directory Indexing Prevention', 'wp-secure-guard' ),
			'category'    => 'file_security',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? __( 'Disabled (Protected)', 'wp-secure-guard' ) : __( 'Exposed', 'wp-secure-guard' ),
			'description' => __( 'Disables directory browsing so visitors cannot view files inside folders lacking an index.php.', 'wp-secure-guard' ),
		);
	}
}
