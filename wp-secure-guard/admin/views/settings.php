<?php
/**
 * View: Settings, Tools & System Information.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;

$sys_info = array(
	'WordPress Version' => get_bloginfo( 'version' ),
	'Site URL'          => site_url(),
	'Home URL'          => home_url(),
	'Plugin Version'    => WPSG_VERSION,
	'PHP Version'       => phpversion(),
	'Web Server'        => isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : 'Unknown',
	'Database Engine'   => $wpdb->is_mysql ? 'MySQL / MariaDB' : 'Other',
	'Database Version'  => $wpdb->db_version(),
	'PHP Memory Limit'  => ini_get( 'memory_limit' ),
	'Max Execution Time'=> ini_get( 'max_execution_time' ) . 's',
	'HTTPS Active'      => is_ssl() ? 'Yes' : 'No',
	'DISALLOW_FILE_EDIT'=> defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ? 'Yes' : 'No',
);

$sys_info_text = '';
foreach ( $sys_info as $key => $val ) {
	$sys_info_text .= "{$key}: {$val}\n";
}
?>

<div class="wpsg-grid-2col">
	<div class="wpsg-col">
		<!-- Maintenance & Uninstall Settings -->
		<form method="post" action="" class="wpsg-form">
			<?php wp_nonce_field( 'wpsg_save_settings_action', 'wpsg_save_nonce' ); ?>
			<input type="hidden" name="wpsg_save_settings" value="1" />
			<input type="hidden" name="wpsg_tab" value="settings" />

			<div class="wpsg-card">
				<div class="wpsg-card-header">
					<h2>
						<span class="dashicons dashicons-admin-settings"></span>
						<?php esc_html_e( 'Plugin Maintenance & Uninstall Options', 'wp-secure-guard' ); ?>
					</h2>
					<p class="description">
						<?php esc_html_e( 'Configure data retention and cleanup policies.', 'wp-secure-guard' ); ?>
					</p>
				</div>

				<div class="wpsg-setting-row">
					<div class="wpsg-setting-toggle">
						<label class="wpsg-switch">
							<input type="hidden" name="wpsg[delete_data_on_uninstall]" value="0" />
							<input type="checkbox" name="wpsg[delete_data_on_uninstall]" value="1" <?php checked( $settings['delete_data_on_uninstall'] ); ?> />
							<span class="wpsg-slider"></span>
						</label>
					</div>
					<div class="wpsg-setting-info">
						<h3 class="wpsg-setting-title"><?php esc_html_e( 'Complete Data Cleanup on Uninstall', 'wp-secure-guard' ); ?></h3>
						<p class="wpsg-setting-text">
							<?php esc_html_e( 'If enabled, deleting the plugin will permanently drop all activity log database tables, delete user 2FA keys, and remove all stored preferences.', 'wp-secure-guard' ); ?>
						</p>
					</div>
				</div>

				<div class="wpsg-form-actions">
					<button type="submit" class="button button-primary">
						<?php esc_html_e( 'Save Maintenance Preferences', 'wp-secure-guard' ); ?>
					</button>
				</div>
			</div>
		</form>

		<!-- One-Click Rollback / Reset Card -->
		<div class="wpsg-card">
			<div class="wpsg-card-header">
				<h2>
					<span class="dashicons dashicons-backup"></span>
					<?php esc_html_e( 'One-Click Rollback to Safe Defaults', 'wp-secure-guard' ); ?>
				</h2>
				<p class="description">
					<?php esc_html_e( 'Safely reset all 20 security modules to recommended baseline defaults to avoid admin lockouts or conflicts.', 'wp-secure-guard' ); ?>
				</p>
			</div>

			<div class="wpsg-sub-settings">
				<p>
					<?php esc_html_e( 'Reverting to default settings does not delete your activity logs or 2FA secret keys. It restores the recommended protection toggles.', 'wp-secure-guard' ); ?>
				</p>
				<form method="post" action="" onsubmit="return confirm('<?php esc_attr_e( 'Are you sure you want to reset all security configurations back to safe defaults?', 'wp-secure-guard' ); ?>');">
					<?php wp_nonce_field( 'wpsg_reset_defaults_action', 'wpsg_reset_nonce' ); ?>
					<input type="hidden" name="wpsg_reset_defaults" value="1" />
					<button type="submit" class="button button-secondary">
						<span class="dashicons dashicons-undo" style="vertical-align:text-bottom;margin-right:4px;"></span>
						<?php esc_html_e( 'Reset All Settings to Safe Defaults', 'wp-secure-guard' ); ?>
					</button>
				</form>
			</div>
		</div>
	</div>

	<div class="wpsg-col">
		<!-- System Information Report -->
		<div class="wpsg-card">
			<div class="wpsg-card-header wpsg-flex-between">
				<div>
					<h2>
						<span class="dashicons dashicons-info"></span>
						<?php esc_html_e( 'System & Environment Report', 'wp-secure-guard' ); ?>
					</h2>
					<p class="description"><?php esc_html_e( 'Server and WordPress runtime diagnostic specs.', 'wp-secure-guard' ); ?></p>
				</div>
				<button type="button" class="button button-secondary wpsg-copy-sysinfo-btn" data-info="<?php echo esc_attr( $sys_info_text ); ?>">
					<span class="dashicons dashicons-clipboard" style="vertical-align:text-bottom;margin-right:2px;"></span>
					<?php esc_html_e( 'Copy Report', 'wp-secure-guard' ); ?>
				</button>
			</div>

			<table class="wp-list-table widefat fixed striped">
				<tbody>
					<?php foreach ( $sys_info as $label => $val ) : ?>
						<tr>
							<td style="width: 45%;"><strong><?php echo esc_html( $label ); ?></strong></td>
							<td><code><?php echo esc_html( $val ); ?></code></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	</div>
</div>
