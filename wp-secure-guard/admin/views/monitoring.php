<?php
/**
 * View: Threat Monitoring & WAF (Features 16-20).
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$update_data = WPSG_Update_Checker::check_updates();
$php_audit   = WPSG_PHP_Hardening::audit();
$backup_data = WPSG_Backup_Checker::scan_backup_status();
$loaded_ini  = WPSG_PHP_Hardening::get_loaded_php_ini();
?>

<form method="post" action="" class="wpsg-form">
	<?php wp_nonce_field( 'wpsg_save_settings_action', 'wpsg_save_nonce' ); ?>
	<input type="hidden" name="wpsg_save_settings" value="1" />
	<input type="hidden" name="wpsg_tab" value="monitoring" />

	<!-- Feature 16: Application Firewall (WAF) -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-shield-alt"></span>
				<?php esc_html_e( '16. Web Application Firewall (WAF)', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Inspects incoming GET, POST, Cookie, and User-Agent payloads for malicious exploitation patterns without adding server overhead.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[waf_enable]" value="0" />
					<input type="checkbox" name="wpsg[waf_enable]" value="1" <?php checked( $settings['waf_enable'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Enable Web Application Firewall', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Activates real-time packet inspection to defend against common OWASP Top 10 web application vulnerabilities.', 'wp-secure-guard' ); ?>
				</p>
			</div>
		</div>

		<div class="wpsg-sub-settings">
			<div class="wpsg-field-group" style="margin-bottom: 15px;">
				<label for="wpsg_waf_mode"><strong><?php esc_html_e( 'Firewall Operating Mode:', 'wp-secure-guard' ); ?></strong></label>
				<select id="wpsg_waf_mode" name="wpsg[waf_mode]">
					<option value="block" <?php selected( $settings['waf_mode'], 'block' ); ?>><?php esc_html_e( 'Block Attacks (403 Forbidden + Log Event) - Recommended', 'wp-secure-guard' ); ?></option>
					<option value="monitor" <?php selected( $settings['waf_mode'], 'monitor' ); ?>><?php esc_html_e( 'Monitor Only (Log to Activity Trail without blocking)', 'wp-secure-guard' ); ?></option>
				</select>
			</div>

			<div class="wpsg-checkbox-group">
				<label>
					<input type="hidden" name="wpsg[waf_block_sqli]" value="0" />
					<input type="checkbox" name="wpsg[waf_block_sqli]" value="1" <?php checked( $settings['waf_block_sqli'] ); ?> />
					<strong><?php esc_html_e( 'Block SQL Injection (SQLi)', 'wp-secure-guard' ); ?></strong>
					<span class="description" style="display:block;margin-left:22px;"><?php esc_html_e( 'Detects UNION SELECT, benchmark(), concat(), and SQL truncation comments.', 'wp-secure-guard' ); ?></span>
				</label>
				<br />
				<label>
					<input type="hidden" name="wpsg[waf_block_xss]" value="0" />
					<input type="checkbox" name="wpsg[waf_block_xss]" value="1" <?php checked( $settings['waf_block_xss'] ); ?> />
					<strong><?php esc_html_e( 'Block Cross-Site Scripting (XSS)', 'wp-secure-guard' ); ?></strong>
					<span class="description" style="display:block;margin-left:22px;"><?php esc_html_e( 'Detects inline JavaScript injection, <script> tags, and DOM event attributes (onerror=, onload=).', 'wp-secure-guard' ); ?></span>
				</label>
				<br />
				<label>
					<input type="hidden" name="wpsg[waf_block_traversal]" value="0" />
					<input type="checkbox" name="wpsg[waf_block_traversal]" value="1" <?php checked( $settings['waf_block_traversal'] ); ?> />
					<strong><?php esc_html_e( 'Block Directory / Path Traversal', 'wp-secure-guard' ); ?></strong>
					<span class="description" style="display:block;margin-left:22px;"><?php esc_html_e( 'Blocks "../" patterns targeting /etc/passwd or system configuration files.', 'wp-secure-guard' ); ?></span>
				</label>
				<br />
				<label>
					<input type="hidden" name="wpsg[waf_block_bad_bots]" value="0" />
					<input type="checkbox" name="wpsg[waf_block_bad_bots]" value="1" <?php checked( $settings['waf_block_bad_bots'] ); ?> />
					<strong><?php esc_html_e( 'Block Malicious Vulnerability Scanners & Bots', 'wp-secure-guard' ); ?></strong>
					<span class="description" style="display:block;margin-left:22px;"><?php esc_html_e( 'Detects automated attack crawlers like sqlmap, Nikto, Acunetix, Masscan, and Havij.', 'wp-secure-guard' ); ?></span>
				</label>
			</div>
		</div>
	</div>

	<!-- Feature 17: Core, Plugin & Theme Update Checker -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-update"></span>
				<?php esc_html_e( '17. Software Vulnerability & Update Monitor', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Over 90% of WordPress compromises originate from known vulnerabilities in outdated plugins and themes.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[update_checker_enable]" value="0" />
					<input type="checkbox" name="wpsg[update_checker_enable]" value="1" <?php checked( $settings['update_checker_enable'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Enable Update Security Monitoring', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Monitors pending WordPress core, plugin, and theme updates that expose security weaknesses.', 'wp-secure-guard' ); ?>
				</p>
			</div>
		</div>

		<div class="wpsg-sub-settings">
			<?php if ( 0 === $update_data['total_pending'] ) : ?>
				<div class="wpsg-alert wpsg-alert-success">
					<span class="dashicons dashicons-yes-alt"></span>
					<strong><?php esc_html_e( 'All Software Up to Date:', 'wp-secure-guard' ); ?></strong>
					<?php esc_html_e( 'WordPress core, active plugins, and themes are running the latest versions.', 'wp-secure-guard' ); ?>
				</div>
			<?php else : ?>
				<div class="wpsg-alert wpsg-alert-danger">
					<span class="dashicons dashicons-warning"></span>
					<strong><?php printf( esc_html__( '%d Pending Updates Require Attention!', 'wp-secure-guard' ), esc_html( $update_data['total_pending'] ) ); ?></strong>
					<a href="<?php echo esc_url( admin_url( 'update-core.php' ) ); ?>" class="button button-small" style="margin-left: 10px;">
						<?php esc_html_e( 'Go to WordPress Updates', 'wp-secure-guard' ); ?> &rarr;
					</a>
				</div>

				<?php if ( ! empty( $update_data['outdated_plugins'] ) ) : ?>
					<h4 style="margin: 10px 0 5px;"><?php esc_html_e( 'Outdated Plugins:', 'wp-secure-guard' ); ?></h4>
					<ul>
						<?php foreach ( $update_data['outdated_plugins'] as $p ) : ?>
							<li>
								<strong><?php echo esc_html( $p['name'] ); ?></strong> —
								<span style="color:#d63638;"><?php echo esc_html( $p['current_version'] ); ?></span> &rarr;
								<span style="color:#00a32a;font-weight:bold;"><?php echo esc_html( $p['new_version'] ); ?></span>
							</li>
						<?php endforeach; ?>
					</ul>
				<?php endif; ?>
			<?php endif; ?>
		</div>
	</div>

	<!-- Feature 18: PHP Hardening Audit & Remediation Solutions -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-admin-generic"></span>
				<?php esc_html_e( '18. PHP Environment Hardening Audit & Fix Guide', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Audits server-level PHP configuration directives and provides instant, step-by-step remediation snippets for php.ini, .htaccess, and wp-config.php.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[php_hardening_audit]" value="0" />
					<input type="checkbox" name="wpsg[php_hardening_audit]" value="1" <?php checked( $settings['php_hardening_audit'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Enable PHP Hardening Audit & Runtime Shield', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Checks security flags and actively suppresses frontend error disclosure on production.', 'wp-secure-guard' ); ?>
				</p>
			</div>
		</div>

		<div class="wpsg-sub-settings" style="margin-top: 10px; margin-bottom: 16px;">
			<div class="wpsg-php-ini-banner">
				<span class="dashicons dashicons-media-code" style="font-size:24px;width:24px;height:24px;color:#2271b1;"></span>
				<div style="flex-grow:1;">
					<strong style="display:block;"><?php esc_html_e( 'Active Loaded php.ini File:', 'wp-secure-guard' ); ?></strong>
					<code class="wpsg-ini-path"><?php echo esc_html( $loaded_ini ); ?></code>
				</div>
				<button type="button" class="button button-small wpsg-copy-btn" data-target=".wpsg-ini-path">
					<?php esc_html_e( 'Copy php.ini Path', 'wp-secure-guard' ); ?>
				</button>
			</div>
		</div>

		<div class="wpsg-sub-settings" style="padding: 0;">
			<table class="wp-list-table widefat fixed striped wpsg-audit-table">
				<thead>
					<tr>
						<th style="width: 170px;"><?php esc_html_e( 'PHP Directive', 'wp-secure-guard' ); ?></th>
						<th style="width: 110px;"><?php esc_html_e( 'Current', 'wp-secure-guard' ); ?></th>
						<th style="width: 120px;"><?php esc_html_e( 'Recommended', 'wp-secure-guard' ); ?></th>
						<th style="width: 90px;"><?php esc_html_e( 'Status', 'wp-secure-guard' ); ?></th>
						<th><?php esc_html_e( 'Security Impact', 'wp-secure-guard' ); ?></th>
						<th style="width: 150px; text-align: center;"><?php esc_html_e( 'Action / Fix', 'wp-secure-guard' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $php_audit as $key => $check ) : ?>
						<?php
						$status_class = ( 'passed' === $check['status'] ) ? 'wpsg-badge-success' : ( ( 'critical' === $check['status'] ) ? 'wpsg-badge-danger' : 'wpsg-badge-warning' );
						$row_id = 'wpsg-sol-' . esc_attr( $check['id'] );
						?>
						<tr>
							<td><strong><code><?php echo esc_html( $check['directive'] ); ?></code></strong></td>
							<td><code><?php echo esc_html( $check['current'] ); ?></code></td>
							<td><code><?php echo esc_html( $check['recommended'] ); ?></code></td>
							<td><span class="wpsg-badge <?php echo esc_attr( $status_class ); ?>"><?php echo esc_html( ucfirst( $check['status'] ) ); ?></span></td>
							<td><?php echo esc_html( $check['description'] ); ?></td>
							<td style="text-align: center;">
								<button type="button" class="button button-small wpsg-toggle-solution-btn <?php echo ( 'passed' !== $check['status'] ) ? 'button-secondary' : ''; ?>" data-target="#<?php echo esc_attr( $row_id ); ?>">
									<span class="dashicons dashicons-admin-tools" style="vertical-align:text-bottom;font-size:14px;width:14px;height:14px;margin-right:2px;"></span>
									<span class="wpsg-btn-text"><?php esc_html_e( 'How to Fix ▼', 'wp-secure-guard' ); ?></span>
								</button>
							</td>
						</tr>

						<!-- Collapsible Solution Drawer Row -->
						<tr id="<?php echo esc_attr( $row_id ); ?>" class="wpsg-solution-row" style="display:none; background: #fdfdfd;">
							<td colspan="6" style="padding: 16px 20px;">
								<div class="wpsg-solution-card">
									<h4 style="margin: 0 0 10px; color: #1d2327; font-size: 14px; display:flex; align-items:center; gap:6px;">
										<span class="dashicons dashicons-info" style="color:#2271b1;"></span>
										<?php echo esc_html( $check['solution_title'] ); ?>
									</h4>

									<?php if ( ! empty( $check['steps'] ) ) : ?>
										<ol style="margin: 0 0 14px 20px; padding: 0; line-height: 1.6; font-size: 13px;">
											<?php foreach ( $check['steps'] as $step ) : ?>
												<li><?php echo esc_html( $step ); ?></li>
											<?php endforeach; ?>
										</ol>
									<?php endif; ?>

									<?php if ( ! empty( $check['code_snippets'] ) ) : ?>
										<div class="wpsg-snippets-grid">
											<?php foreach ( $check['code_snippets'] as $snippet ) : ?>
												<div class="wpsg-snippet-box">
													<div class="wpsg-snippet-header">
														<span class="wpsg-snippet-label"><?php echo esc_html( $snippet['label'] ); ?></span>
														<button type="button" class="button button-small wpsg-copy-btn" data-target="code">
															<?php esc_html_e( 'Copy Snippet', 'wp-secure-guard' ); ?>
														</button>
													</div>
													<pre class="wpsg-code-box" style="margin: 0;"><code><?php echo esc_html( $snippet['code'] ); ?></code></pre>
												</div>
											<?php endforeach; ?>
										</div>
									<?php endif; ?>
								</div>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
	</div>

	<!-- Feature 19: Security Activity Logs Configuration -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-list-view"></span>
				<?php esc_html_e( '19. Security Activity Trail & Logging', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Tamper-resistant audit log capturing logins, lockouts, firewall blocks, role elevations, and account deletions.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[activity_logs_enable]" value="0" />
					<input type="checkbox" name="wpsg[activity_logs_enable]" value="1" <?php checked( $settings['activity_logs_enable'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Enable Activity Logging Table', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Records security events directly into a dedicated, indexed database table.', 'wp-secure-guard' ); ?>
				</p>
			</div>
		</div>

		<div class="wpsg-sub-settings">
			<div class="wpsg-field-group">
				<label for="wpsg_activity_logs_retention_days"><strong><?php esc_html_e( 'Log Retention Period:', 'wp-secure-guard' ); ?></strong></label>
				<input type="number" id="wpsg_activity_logs_retention_days" name="wpsg[activity_logs_retention_days]" value="<?php echo esc_attr( $settings['activity_logs_retention_days'] ); ?>" min="7" max="365" class="small-text" />
				<span class="description"><?php esc_html_e( 'days (Older events are automatically pruned via daily maintenance cron)', 'wp-secure-guard' ); ?></span>
			</div>
		</div>
	</div>

	<!-- Feature 20: Backup Checker -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-backup"></span>
				<?php esc_html_e( '20. Backup Status & Disaster Recovery', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'In the event of ransomware, server failure, or persistent compromise, off-site backups are your ultimate guarantee of recovery.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-sub-settings">
			<?php if ( $backup_data['has_backup_tool'] ) : ?>
				<div class="wpsg-alert wpsg-alert-success">
					<span class="dashicons dashicons-yes-alt"></span>
					<strong><?php esc_html_e( 'Automated Backup Solution Detected:', 'wp-secure-guard' ); ?></strong>
					<?php echo esc_html( implode( ', ', $backup_data['tools_detected'] ) ); ?>
				</div>
			<?php else : ?>
				<div class="wpsg-alert wpsg-alert-warning">
					<span class="dashicons dashicons-info"></span>
					<strong><?php esc_html_e( 'No Automated Backup Plugin Detected!', 'wp-secure-guard' ); ?></strong>
					<?php esc_html_e( 'We strongly recommend installing an automated backup tool (such as UpdraftPlus, Duplicator, or host-managed snapshots) and scheduling daily off-site backups.', 'wp-secure-guard' ); ?>
				</div>
			<?php endif; ?>
		</div>
	</div>

	<!-- Feature: Hide WordPress Version -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-wordpress"></span>
				<?php esc_html_e( 'Hide WordPress Core Version', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Prevents automated vulnerability scanners (such as WPScan, Wappalyzer, and BuiltWith) from fingerprinting your exact WordPress core version.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[hide_wp_version]" value="0" />
					<input type="checkbox" name="wpsg[hide_wp_version]" value="1" <?php checked( $settings['hide_wp_version'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Cloak WordPress Core Version Indicators', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Removes generator meta tags, strips version numbers (?ver=X.X.X) from frontend scripts and stylesheets, and filters RSS/Atom feed headers.', 'wp-secure-guard' ); ?>
				</p>
				<span class="wpsg-pill wpsg-pill-recommended"><?php esc_html_e( 'Recommended', 'wp-secure-guard' ); ?></span>
			</div>
		</div>

		<div class="wpsg-sub-settings">
			<ul style="margin: 0; padding-left: 20px; line-height: 1.6; font-size: 13px;">
				<li><strong><?php esc_html_e( 'HTML Meta Tag:', 'wp-secure-guard' ); ?></strong> <?php esc_html_e( 'Removes <meta name="generator" content="WordPress X.X" /> from header.', 'wp-secure-guard' ); ?></li>
				<li><strong><?php esc_html_e( 'Asset Query Strings:', 'wp-secure-guard' ); ?></strong> <?php esc_html_e( 'Removes version query strings from script and style tags matching current core version.', 'wp-secure-guard' ); ?></li>
				<li><strong><?php esc_html_e( 'Feeds & Manifests:', 'wp-secure-guard' ); ?></strong> <?php esc_html_e( 'Removes version generators from RSS2, Atom, RDF, Comments feeds, WLW manifest, and RSD links.', 'wp-secure-guard' ); ?></li>
			</ul>
		</div>
	</div>

	<!-- Feature: Hide Server Information -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-networking"></span>
				<?php esc_html_e( 'Hide Server Information & Headers', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Removes HTTP headers and server signature banners that advertise your web server daemon (Apache/Nginx/LiteSpeed) and PHP version.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[hide_server_info]" value="0" />
					<input type="checkbox" name="wpsg[hide_server_info]" value="1" <?php checked( $settings['hide_server_info'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Suppress Server & X-Powered-By Headers', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Strips X-Powered-By via PHP runtime and writes ServerSignature Off rules to root .htaccess for Apache.', 'wp-secure-guard' ); ?>
				</p>
				<span class="wpsg-pill wpsg-pill-recommended"><?php esc_html_e( 'Recommended', 'wp-secure-guard' ); ?></span>
			</div>
		</div>

		<div class="wpsg-sub-settings">
			<div class="wpsg-alert wpsg-alert-info">
				<span class="dashicons dashicons-info"></span>
				<strong><?php esc_html_e( 'Protected Headers:', 'wp-secure-guard' ); ?></strong>
				<?php esc_html_e( 'Strips "X-Powered-By: PHP/8.x", disables Apache ServerSignature banner, and unsets Server identification headers.', 'wp-secure-guard' ); ?>
			</div>

			<div style="margin-top: 10px;">
				<strong><?php esc_html_e( 'Nginx Server Snippet (Optional for Nginx hosts):', 'wp-secure-guard' ); ?></strong>
				<pre class="wpsg-code-box" style="margin-top: 6px;"><code><?php echo esc_html( WPSG_Server_Info_Hider::get_nginx_snippet() ); ?></code></pre>
			</div>
		</div>
	</div>

	<div class="wpsg-form-actions">
		<button type="submit" class="button button-primary button-large">
			<span class="dashicons dashicons-saved" style="vertical-align:text-bottom;margin-right:4px;"></span>
			<?php esc_html_e( 'Save Monitoring Settings', 'wp-secure-guard' ); ?>
		</button>
	</div>
</form>
