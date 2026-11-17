<?php
/**
 * Module: WordPress Core, Plugin & Theme Update Monitor.
 *
 * Checks for outdated software components that may contain known security vulnerabilities.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Update_Checker
 */
class WPSG_Update_Checker {

	/**
	 * Run checks across WordPress core, plugins, and themes.
	 *
	 * @return array
	 */
	public static function check_updates() {
		$results = array(
			'core_outdated'    => false,
			'core_version'     => get_bloginfo( 'version' ),
			'core_latest'      => get_bloginfo( 'version' ),
			'outdated_plugins' => array(),
			'outdated_themes'  => array(),
			'total_pending'    => 0,
		);

		// 1. Check Core Updates.
		$core_updates = get_site_transient( 'update_core' );
		if ( ! empty( $core_updates->updates ) && is_array( $core_updates->updates ) ) {
			foreach ( $core_updates->updates as $update ) {
				if ( isset( $update->response ) && 'upgrade' === $update->response ) {
					$results['core_outdated'] = true;
					$results['core_latest']   = $update->current;
					$results['total_pending']++;
					break;
				}
			}
		}

		// 2. Check Plugin Updates.
		$plugin_updates = get_site_transient( 'update_plugins' );
		if ( ! empty( $plugin_updates->response ) && is_array( $plugin_updates->response ) ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$all_plugins = get_plugins();

			foreach ( $plugin_updates->response as $file => $plugin_data ) {
				$name = isset( $all_plugins[ $file ]['Name'] ) ? $all_plugins[ $file ]['Name'] : $file;
				$current = isset( $all_plugins[ $file ]['Version'] ) ? $all_plugins[ $file ]['Version'] : '?';
				$new     = isset( $plugin_data->new_version ) ? $plugin_data->new_version : '?';

				$results['outdated_plugins'][] = array(
					'file'            => $file,
					'name'            => $name,
					'current_version' => $current,
					'new_version'     => $new,
				);
				$results['total_pending']++;
			}
		}

		// 3. Check Theme Updates.
		$theme_updates = get_site_transient( 'update_themes' );
		if ( ! empty( $theme_updates->response ) && is_array( $theme_updates->response ) ) {
			foreach ( $theme_updates->response as $stylesheet => $theme_data ) {
				$theme   = wp_get_theme( $stylesheet );
				$name    = $theme->exists() ? $theme->get( 'Name' ) : $stylesheet;
				$current = $theme->exists() ? $theme->get( 'Version' ) : '?';
				$new     = isset( $theme_data['new_version'] ) ? $theme_data['new_version'] : '?';

				$results['outdated_themes'][] = array(
					'stylesheet'      => $stylesheet,
					'name'            => $name,
					'current_version' => $current,
					'new_version'     => $new,
				);
				$results['total_pending']++;
			}
		}

		return $results;
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'update_checker_enable', true );
		$data    = self::check_updates();

		if ( ! $enabled ) {
			$status = 'warning';
			$label  = __( 'Monitoring Disabled', 'wp-secure-guard' );
		} elseif ( $data['total_pending'] > 0 ) {
			$status = 'critical';
			/* translators: %d: count of updates available */
			$label  = sprintf( _n( '%d Vulnerable Update Available', '%d Vulnerable Updates Available', $data['total_pending'], 'wp-secure-guard' ), $data['total_pending'] );
		} else {
			$status = 'passed';
			$label  = __( 'Up to Date (No pending updates)', 'wp-secure-guard' );
		}

		return array(
			'id'          => 'update_checker',
			'title'       => __( 'Security Update Status', 'wp-secure-guard' ),
			'category'    => 'monitoring',
			'enabled'     => $enabled,
			'status'      => $status,
			'label'       => $label,
			'details'     => $data,
			'description' => __( 'Identifies outdated core, plugins, or themes that may be vulnerable to known public exploits.', 'wp-secure-guard' ),
		);
	}
}
