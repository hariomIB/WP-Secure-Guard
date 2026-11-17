<?php
/**
 * Module: File Editor Hardening.
 *
 * Disables the built-in WordPress theme and plugin code editor to prevent arbitrary PHP execution.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_File_Editor
 */
class WPSG_File_Editor {

	/**
	 * Initialize hooks if enabled.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'disallow_file_edit_enforce', true ) ) {
			if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
				define( 'DISALLOW_FILE_EDIT', true );
			}
			add_filter( 'map_meta_cap', array( __CLASS__, 'prevent_file_editing_caps' ), 10, 2 );
		}
	}

	/**
	 * Filter user capabilities to disallow file editing even if requested.
	 *
	 * @param array  $caps Array of capabilities.
	 * @param string $cap  Capability name.
	 * @return array
	 */
	public static function prevent_file_editing_caps( $caps, $cap ) {
		if ( in_array( $cap, array( 'edit_themes', 'edit_plugins', 'edit_files' ), true ) ) {
			$caps[] = 'do_not_allow';
		}
		return $caps;
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enforced_in_config = defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT;
		$plugin_enabled     = (bool) WPSG_Settings::get( 'disallow_file_edit_enforce', true );

		$status = ( $enforced_in_config || $plugin_enabled ) ? 'passed' : 'warning';
		$label  = ( $enforced_in_config || $plugin_enabled ) ? __( 'File Editor Disabled', 'wp-secure-guard' ) : __( 'File Editor Enabled', 'wp-secure-guard' );

		return array(
			'id'                 => 'file_editor',
			'title'              => __( 'Theme & Plugin File Editor', 'wp-secure-guard' ),
			'category'           => 'file_security',
			'enabled'            => $plugin_enabled,
			'status'             => $status,
			'label'              => $label,
			'enforced_in_config' => $enforced_in_config,
			'description'        => __( 'Prevents administrators or compromised accounts from editing executable PHP files from the WP admin.', 'wp-secure-guard' ),
		);
	}
}
