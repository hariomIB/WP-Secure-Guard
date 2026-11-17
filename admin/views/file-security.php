<?php
/**
 * View: File & Server Security Settings (Features 11-15).
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$server_type     = WPSG_Uploads_Protection::get_server_type();
$htaccess_active = WPSG_Uploads_Protection::is_htaccess_installed();
$perms_audit     = WPSG_Permissions_Audit::run_audit();
$file_edit_stat  = WPSG_File_Editor::get_status();
$sensitive_audit = WPSG_Sensitive_Files::audit_sensitive_files();
?>

<form method="post" action="" class="wpsg-form">
	<?php wp_nonce_field( 'wpsg_save_settings_action', 'wpsg_save_nonce' ); ?>
	<input type="hidden" name="wpsg_save_settings" value="1" />
	<input type="hidden" name="wpsg_tab" value="file_security" />

	<!-- Feature 11: Disable File Editor -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-edit"></span>
				<?php esc_html_e( '11. Theme & Plugin File Editor', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'The built-in file editor allows administrators to edit theme and plugin code directly. If an admin account is compromised, attackers use this editor to upload PHP web shells.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[disallow_file_edit_enforce]" value="0" />
					<input type="checkbox" name="wpsg[disallow_file_edit_enforce]" value="1" <?php checked( $settings['disallow_file_edit_enforce'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Disable Built-in Theme and Plugin Code Editor', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Enforces DISALLOW_FILE_EDIT at runtime and strips file editing capabilities from all roles.', 'wp-secure-guard' ); ?>
				</p>
				<?php if ( $file_edit_stat['enforced_in_config'] ) : ?>
					<span class="wpsg-pill wpsg-pill-recommended"><?php esc_html_e( 'Defined in wp-config.php (Optimal)', 'wp-secure-guard' ); ?></span>
				<?php else : ?>
					<span class="wpsg-pill wpsg-pill-optional"><?php esc_html_e( 'Enforced via Plugin Filter', 'wp-secure-guard' ); ?></span>
				<?php endif; ?>
			</div>
		</div>
	</div>

	<!-- Feature 12: Uploads PHP Protection & Malicious File Upload Shield -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-upload"></span>
				<?php esc_html_e( '12. Prevent PHP Execution & Malicious Uploads', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Media uploads should only ever contain images, documents, and videos—never executable PHP scripts. This prevents backdoor web shells from being uploaded and executed.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[uploads_php_protect]" value="0" />
					<input type="checkbox" name="wpsg[uploads_php_protect]" value="1" <?php checked( $settings['uploads_php_protect'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Block PHP Execution inside /wp-content/uploads/', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Writes server-level deny rules into uploads/.htaccess for Apache and LiteSpeed web servers, and screens all uploads in real-time.', 'wp-secure-guard' ); ?>
				</p>
				<p>
					<strong><?php esc_html_e( 'Detected Web Server:', 'wp-secure-guard' ); ?></strong>
					<code style="text-transform: uppercase;"><?php echo esc_html( $server_type ); ?></code>
					<?php if ( in_array( $server_type, array( 'apache', 'litespeed' ), true ) ) : ?>
						<?php if ( $htaccess_active ) : ?>
							<span class="wpsg-badge wpsg-badge-success" style="margin-left: 8px;"><?php esc_html_e( '.htaccess Execution Shield Active', 'wp-secure-guard' ); ?></span>
						<?php else : ?>
							<span class="wpsg-badge wpsg-badge-warning" style="margin-left: 8px;"><?php esc_html_e( '.htaccess Needs Installation', 'wp-secure-guard' ); ?></span>
						<?php endif; ?>
					<?php endif; ?>
				</p>
			</div>
		</div>

		<div class="wpsg-sub-settings">
			<div class="wpsg-alert wpsg-alert-info">
				<span class="dashicons dashicons-shield"></span>
				<strong><?php esc_html_e( 'Active Multi-Layer Upload Defenses:', 'wp-secure-guard' ); ?></strong>
				<ul style="margin: 6px 0 0 18px; list-style-type: disc;">
					<li><strong><?php esc_html_e( 'Server Deny Rules:', 'wp-secure-guard' ); ?></strong> <?php esc_html_e( 'Blocks direct execution of .php, .phtml, .php5, .phar, and script files inside /uploads/.', 'wp-secure-guard' ); ?></li>
					<li><strong><?php esc_html_e( 'Extension Blacklist:', 'wp-secure-guard' ); ?></strong> <?php esc_html_e( 'Rejects 26+ dangerous extensions (php, phtml, phar, sh, exe, bat, cgi, pl, py, vbs, etc.).', 'wp-secure-guard' ); ?></li>
					<li><strong><?php esc_html_e( 'Double-Extension Masking:', 'wp-secure-guard' ); ?></strong> <?php esc_html_e( 'Blocks disguise attempts such as image.jpg.php or shell.php.png.', 'wp-secure-guard' ); ?></li>
					<li><strong><?php esc_html_e( 'Deep File Byte Scanning:', 'wp-secure-guard' ); ?></strong> <?php esc_html_e( 'Inspects binary chunks of uploaded media for hidden <?php or <?= opening tags.', 'wp-secure-guard' ); ?></li>
				</ul>
			</div>

			<?php if ( 'nginx' === $server_type ) : ?>
				<div class="wpsg-alert wpsg-alert-warning" style="margin-top: 10px;">
					<span class="dashicons dashicons-info"></span>
					<strong><?php esc_html_e( 'Nginx Configuration Required:', 'wp-secure-guard' ); ?></strong>
					<?php esc_html_e( 'Nginx does not read .htaccess files. Add the following rule inside your Nginx server block configuration:', 'wp-secure-guard' ); ?>
				</div>
				<pre class="wpsg-code-box"><code><?php echo esc_html( WPSG_Uploads_Protection::get_nginx_snippet() ); ?></code></pre>
				<button type="button" class="button button-small wpsg-copy-btn" data-target="code"><?php esc_html_e( 'Copy Nginx Snippet', 'wp-secure-guard' ); ?></button>
			<?php endif; ?>
		</div>
	</div>

	<!-- Feature 13: Sensitive Files Protection -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-hidden"></span>
				<?php esc_html_e( '13. Sensitive Files Shield & Information Disclosure Audit', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Blocks unauthorized web access to readme.html, license.txt, composer.json, package manifests, database backup files (.sql), .env files, debug.log, and wp-config backups.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[sensitive_files_protect]" value="0" />
					<input type="checkbox" name="wpsg[sensitive_files_protect]" value="1" <?php checked( $settings['sensitive_files_protect'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Protect Sensitive Files & Information Disclosure Endpoints', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Installs Apache/LiteSpeed .htaccess FilesMatch protection (returning HTTP 403 Forbidden) and intercepts requests via PHP.', 'wp-secure-guard' ); ?>
				</p>
				<?php if ( WPSG_Sensitive_Files::is_htaccess_installed() ) : ?>
					<span class="wpsg-pill wpsg-pill-recommended"><?php esc_html_e( '.htaccess 403 Shield Active', 'wp-secure-guard' ); ?></span>
				<?php else : ?>
					<span class="wpsg-pill wpsg-pill-optional"><?php esc_html_e( 'PHP Interception Fallback', 'wp-secure-guard' ); ?></span>
				<?php endif; ?>
			</div>
		</div>

		<div class="wpsg-sub-settings" style="padding: 0;">
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th style="width: 220px;"><?php esc_html_e( 'Target File', 'wp-secure-guard' ); ?></th>
						<th style="width: 140px;"><?php esc_html_e( 'Disk State', 'wp-secure-guard' ); ?></th>
						<th style="width: 260px;"><?php esc_html_e( 'Access Protection Status', 'wp-secure-guard' ); ?></th>
						<th><?php esc_html_e( 'Security Threat / Risk', 'wp-secure-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $sensitive_audit as $file_item ) : ?>
						<?php
						$status_badge = ( 'passed' === $file_item['status'] ) ? 'wpsg-badge-success' : 'wpsg-badge-danger';
						?>
						<tr>
							<td><strong><code><?php echo esc_html( $file_item['file'] ); ?></code></strong></td>
							<td>
								<?php if ( $file_item['exists'] ) : ?>
									<span class="wpsg-badge wpsg-badge-warning"><?php esc_html_e( 'Present on Disk', 'wp-secure-guard' ); ?></span>
								<?php else : ?>
									<span class="wpsg-badge wpsg-badge-info"><?php esc_html_e( 'Not Present (404)', 'wp-secure-guard' ); ?></span>
								<?php endif; ?>
							</td>
							<td>
								<span class="wpsg-badge <?php echo esc_attr( $status_badge ); ?>">
									<?php echo esc_html( $file_item['badge'] ); ?>
								</span>
							</td>
							<td><?php echo esc_html( $file_item['risk'] ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>

		<?php if ( 'nginx' === $server_type ) : ?>
			<div class="wpsg-sub-settings" style="margin-top: 15px;">
				<div class="wpsg-alert wpsg-alert-warning">
					<span class="dashicons dashicons-info"></span>
					<strong><?php esc_html_e( 'Nginx Sensitive Files Block:', 'wp-secure-guard' ); ?></strong>
					<?php esc_html_e( 'For Nginx servers, paste this snippet into your server configuration:', 'wp-secure-guard' ); ?>
				</div>
				<pre class="wpsg-code-box"><code><?php echo esc_html( WPSG_Sensitive_Files::get_nginx_snippet() ); ?></code></pre>
			</div>
		<?php endif; ?>
	</div>

	<!-- Feature 14: Directory Listing Prevention -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-category"></span>
				<?php esc_html_e( '14. Directory Indexing Prevention', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'When directory indexing is enabled on a web server, visitors can view all files in folders that lack an index file, exposing sensitive assets.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[directory_listing_protect]" value="0" />
					<input type="checkbox" name="wpsg[directory_listing_protect]" value="1" <?php checked( $settings['directory_listing_protect'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Disable Directory Indexing & Place Guard Files', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Enforces Options -Indexes in .htaccess and automatically ensures blank index.php files are present in uploads folders.', 'wp-secure-guard' ); ?>
				</p>
				<span class="wpsg-pill wpsg-pill-recommended"><?php esc_html_e( 'Recommended', 'wp-secure-guard' ); ?></span>
			</div>
		</div>
	</div>

	<!-- Feature 15: File Permissions Audit -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-yes"></span>
				<?php esc_html_e( '15. File Permissions Audit', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Audits POSIX permissions on key WordPress files and directories to ensure least-privilege security.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-sub-settings" style="padding: 0;">
			<table class="wp-list-table widefat fixed striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'File / Directory', 'wp-secure-guard' ); ?></th>
						<th style="width: 150px;"><?php esc_html_e( 'Current Perms', 'wp-secure-guard' ); ?></th>
						<th style="width: 150px;"><?php esc_html_e( 'Recommended', 'wp-secure-guard' ); ?></th>
						<th style="width: 120px;"><?php esc_html_e( 'Status', 'wp-secure-guard' ); ?></th>
						<th><?php esc_html_e( 'Analysis', 'wp-secure-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $perms_audit as $item ) : ?>
						<?php
						$status_class = 'wpsg-badge-info';
						if ( 'passed' === $item['status'] ) {
							$status_class = 'wpsg-badge-success';
						} elseif ( 'warning' === $item['status'] ) {
							$status_class = 'wpsg-badge-warning';
						} elseif ( 'critical' === $item['status'] ) {
							$status_class = 'wpsg-badge-danger';
						}
						?>
						<tr>
							<td><strong><code><?php echo esc_html( $item['name'] ); ?></code></strong></td>
							<td><code><?php echo esc_html( $item['current'] ); ?></code></td>
							<td><code><?php echo esc_html( $item['recommended'] ); ?></code></td>
							<td><span class="wpsg-badge <?php echo esc_attr( $status_class ); ?>"><?php echo esc_html( ucfirst( $item['status'] ) ); ?></span></td>
							<td><?php echo esc_html( $item['message'] ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	</div>

	<div class="wpsg-form-actions">
		<button type="submit" class="button button-primary button-large">
			<span class="dashicons dashicons-saved" style="vertical-align:text-bottom;margin-right:4px;"></span>
			<?php esc_html_e( 'Save File Security Settings', 'wp-secure-guard' ); ?>
		</button>
	</div>
</form>
