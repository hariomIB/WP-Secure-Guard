<?php
/**
 * Module: File Permissions Audit.
 *
 * Inspects filesystem permissions on critical WordPress directories and configuration files.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Permissions_Audit
 */
class WPSG_Permissions_Audit {

	/**
	 * Run full filesystem permissions audit.
	 *
	 * @return array List of audited items with status and permissions.
	 */
	public static function run_audit() {
		$items = array();

		$wp_config = self::find_wp_config_file();
		$upload_dir = wp_upload_dir();

		$targets = array(
			array(
				'name'        => 'wp-config.php',
				'path'        => $wp_config,
				'type'        => 'file',
				'recommended' => '0644 / 0440',
				'safe_octals' => array( '0644', '0640', '0600', '0440', '0400' ),
			),
			array(
				'name'        => '.htaccess',
				'path'        => get_home_path() . '.htaccess',
				'type'        => 'file',
				'recommended' => '0644',
				'safe_octals' => array( '0644', '0640', '0600', '0444' ),
			),
			array(
				'name'        => 'wp-content',
				'path'        => WP_CONTENT_DIR,
				'type'        => 'dir',
				'recommended' => '0755',
				'safe_octals' => array( '0755', '0750' ),
			),
			array(
				'name'        => 'wp-content/uploads',
				'path'        => $upload_dir['basedir'],
				'type'        => 'dir',
				'recommended' => '0755',
				'safe_octals' => array( '0755', '0750' ),
			),
			array(
				'name'        => 'wp-content/plugins',
				'path'        => WP_PLUGIN_DIR,
				'type'        => 'dir',
				'recommended' => '0755',
				'safe_octals' => array( '0755', '0750' ),
			),
			array(
				'name'        => 'wp-content/themes',
				'path'        => get_theme_root(),
				'type'        => 'dir',
				'recommended' => '0755',
				'safe_octals' => array( '0755', '0750' ),
			),
			array(
				'name'        => 'wp-includes',
				'path'        => ABSPATH . WPINC,
				'type'        => 'dir',
				'recommended' => '0755',
				'safe_octals' => array( '0755', '0750' ),
			),
		);

		$is_windows = strtoupper( substr( PHP_OS, 0, 3 ) ) === 'WIN';

		foreach ( $targets as $target ) {
			$path = $target['path'];

			if ( ! file_exists( $path ) ) {
				$items[] = array(
					'name'        => $target['name'],
					'path'        => $path,
					'status'      => 'info',
					'current'     => __( 'Not Found', 'wp-secure-guard' ),
					'recommended' => $target['recommended'],
					'message'     => __( 'File or directory does not exist.', 'wp-secure-guard' ),
				);
				continue;
			}

			if ( $is_windows ) {
				$writable = is_writable( $path );
				$status   = ( 'wp-config.php' === $target['name'] && $writable ) ? 'warning' : 'passed';
				$current  = $writable ? __( 'Writable (Windows)', 'wp-secure-guard' ) : __( 'Read-Only (Windows)', 'wp-secure-guard' );

				$items[] = array(
					'name'        => $target['name'],
					'path'        => $path,
					'status'      => $status,
					'current'     => $current,
					'recommended' => $target['recommended'],
					'message'     => $status === 'passed' ? __( 'Standard permissions', 'wp-secure-guard' ) : __( 'Consider restricting write permissions.', 'wp-secure-guard' ),
				);
			} else {
				$perms  = fileperms( $path );
				$octal  = substr( sprintf( '%o', $perms ), -4 );
				$status = in_array( $octal, $target['safe_octals'], true ) ? 'passed' : 'warning';

				// Critical warning if world-writable.
				if ( ( $perms & 0x0002 ) ) {
					$status = 'critical';
				}

				$items[] = array(
					'name'        => $target['name'],
					'path'        => $path,
					'status'      => $status,
					'current'     => $octal,
					'recommended' => $target['recommended'],
					'message'     => 'critical' === $status ? __( 'World-writable! High security vulnerability.', 'wp-secure-guard' ) : ( 'warning' === $status ? __( 'Permissions differ from recommendation.', 'wp-secure-guard' ) : __( 'Secure permissions', 'wp-secure-guard' ) ),
				);
			}
		}

		return $items;
	}

	/**
	 * Locate wp-config.php whether in root or one level above root.
	 *
	 * @return string
	 */
	public static function find_wp_config_file() {
		if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
			return ABSPATH . 'wp-config.php';
		} elseif ( @file_exists( dirname( ABSPATH ) . '/wp-config.php' ) && ! @file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
			return dirname( ABSPATH ) . '/wp-config.php';
		}
		return ABSPATH . 'wp-config.php';
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'permissions_audit_enable', true );
		$audit   = self::run_audit();

		$has_critical = false;
		$has_warning  = false;

		foreach ( $audit as $row ) {
			if ( 'critical' === $row['status'] ) {
				$has_critical = true;
			} elseif ( 'warning' === $row['status'] ) {
				$has_warning = true;
			}
		}

		if ( $has_critical ) {
			$status = 'critical';
			$label  = __( 'Critical Insecure Permissions Found', 'wp-secure-guard' );
		} elseif ( $has_warning ) {
			$status = 'warning';
			$label  = __( 'Permissions Review Recommended', 'wp-secure-guard' );
		} else {
			$status = 'passed';
			$label  = __( 'All Permissions Secure', 'wp-secure-guard' );
		}

		return array(
			'id'          => 'permissions_audit',
			'title'       => __( 'File Permissions Audit', 'wp-secure-guard' ),
			'category'    => 'file_security',
			'enabled'     => $enabled,
			'status'      => $status,
			'label'       => $label,
			'details'     => $audit,
			'description' => __( 'Audits file and directory permission levels across core paths to ensure least-privilege access.', 'wp-secure-guard' ),
		);
	}
}
