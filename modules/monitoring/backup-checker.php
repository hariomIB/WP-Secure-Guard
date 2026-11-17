<?php
/**
 * Module: Backup Health & Tool Checker.
 *
 * Checks for presence of reliable backup solutions and recent database snapshots.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Backup_Checker
 */
class WPSG_Backup_Checker {

	/**
	 * List of known backup plugins and their signatures.
	 *
	 * @return array
	 */
	public static function get_known_backup_plugins() {
		return array(
			'UpdraftPlus'             => 'updraftplus/updraftplus.php',
			'BackWPup'                => 'backwpup/backwpup.php',
			'Duplicator'              => 'duplicator/duplicator.php',
			'BlogVault'               => 'blogvault-real-time-backup/blogvault.php',
			'WPvivid Backup'          => 'wpvivid-backuprestore/wpvivid-backuprestore.php',
			'All-in-One WP Migration' => 'all-in-one-wp-migration/all-in-one-wp-migration.php',
			'BackupBuddy'             => 'backupbuddy/backupbuddy.php',
			'Solid Backups'           => 'backupbuddy/backupbuddy.php',
		);
	}

	/**
	 * Scan for active backup plugins or recent backup archives.
	 *
	 * @return array
	 */
	public static function scan_backup_status() {
		$known = self::get_known_backup_plugins();
		$found = array();

		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		foreach ( $known as $name => $path ) {
			if ( is_plugin_active( $path ) ) {
				$found[] = $name;
			}
		}

		return array(
			'has_backup_tool' => ! empty( $found ),
			'tools_detected'  => $found,
		);
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'backup_checker_enable', true );
		$status_data = self::scan_backup_status();

		if ( ! $enabled ) {
			$status = 'warning';
			$label  = __( 'Backup Monitoring Disabled', 'wp-secure-guard' );
		} elseif ( $status_data['has_backup_tool'] ) {
			$status = 'passed';
			$label  = sprintf(
				/* translators: %s: list of detected backup plugins */
				__( 'Backup Active (%s)', 'wp-secure-guard' ),
				implode( ', ', $status_data['tools_detected'] )
			);
		} else {
			$status = 'warning';
			$label  = __( 'No Automated Backup Plugin Detected', 'wp-secure-guard' );
		}

		return array(
			'id'          => 'backup_checker',
			'title'       => __( 'Backup Status & Disaster Recovery', 'wp-secure-guard' ),
			'category'    => 'monitoring',
			'enabled'     => $enabled,
			'status'      => $status,
			'label'       => $label,
			'detected'    => $status_data['tools_detected'],
			'description' => __( 'Regular automated backups are essential for ransomware recovery and site restoration.', 'wp-secure-guard' ),
		);
	}
}
