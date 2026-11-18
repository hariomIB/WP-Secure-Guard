<?php
/**
 * View: Login Security Settings (Features 6-10).
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Run live common usernames scan
$vulnerable_users = WPSG_Common_Usernames::scan_existing_users();
$client_ip = WPSG_Logger::get_client_ip();
?>

<form method="post" action="" class="wpsg-form">
	<?php wp_nonce_field( 'wpsg_save_settings_action', 'wpsg_save_nonce' ); ?>
	<input type="hidden" name="wpsg_save_settings" value="1" />
	<input type="hidden" name="wpsg_tab" value="login_security" />

	<!-- Feature 6: Brute-Force Rate Limiting -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-lock"></span>
				<?php esc_html_e( '6. Brute-Force Rate Limiting', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Thwart automated password guessing by temporarily locking out abusive IP addresses after consecutive failed attempts.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[login_limiter_enable]" value="0" />
					<input type="checkbox" name="wpsg[login_limiter_enable]" value="1" <?php checked( $settings['login_limiter_enable'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Enable Brute-Force Rate Limiting', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Monitors failed authentications and blocks subsequent attempts from that IP for a specified lockout duration.', 'wp-secure-guard' ); ?>
				</p>
			</div>
		</div>

		<div class="wpsg-sub-settings">
			<div class="wpsg-field-grid">
				<div class="wpsg-field-group">
					<label for="wpsg_login_max_retries"><strong><?php esc_html_e( 'Max Failed Attempts Before Lockout:', 'wp-secure-guard' ); ?></strong></label>
					<input type="number" id="wpsg_login_max_retries" name="wpsg[login_max_retries]" value="<?php echo esc_attr( $settings['login_max_retries'] ); ?>" min="1" max="20" class="small-text" />
					<span class="description"><?php esc_html_e( 'attempts (Default: 5)', 'wp-secure-guard' ); ?></span>
				</div>

				<div class="wpsg-field-group">
					<label for="wpsg_login_lockout_duration"><strong><?php esc_html_e( 'Lockout Duration:', 'wp-secure-guard' ); ?></strong></label>
					<input type="number" id="wpsg_login_lockout_duration" name="wpsg[login_lockout_duration]" value="<?php echo esc_attr( $settings['login_lockout_duration'] ); ?>" min="1" max="1440" class="small-text" />
					<span class="description"><?php esc_html_e( 'minutes (Default: 15)', 'wp-secure-guard' ); ?></span>
				</div>
			</div>

			<div class="wpsg-field-group" style="margin-top: 15px;">
				<label for="wpsg_login_whitelist_ips"><strong><?php esc_html_e( 'IP Whitelist (Never Locked Out):', 'wp-secure-guard' ); ?></strong></label>
				<textarea id="wpsg_login_whitelist_ips" name="wpsg[login_whitelist_ips]" rows="3" class="large-text code" placeholder="192.168.1.100&#10;203.0.113.1"><?php echo esc_textarea( $settings['login_whitelist_ips'] ); ?></textarea>
				<p class="description">
					<?php
					printf(
						/* translators: %s: client's current IP */
						esc_html__( 'Enter one IPv4 or IPv6 address per line. Your current detected IP is: %s', 'wp-secure-guard' ),
						'<code>' . esc_html( $client_ip ) . '</code>'
					);
					?>
					<button type="button" class="button button-small wpsg-add-ip-btn" data-ip="<?php echo esc_attr( $client_ip ); ?>" style="margin-left: 8px;">
						<?php esc_html_e( '+ Add My Current IP', 'wp-secure-guard' ); ?>
					</button>
				</p>
			</div>
		</div>
	</div>

	<!-- Feature 7: Two-Factor Authentication (2FA) -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-smartphone"></span>
				<?php esc_html_e( '7. Two-Factor Authentication (TOTP 2FA)', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Vendor-independent RFC 6238 time-based one-time passwords compatible with Google Authenticator, Authy, Microsoft Authenticator, and 1Password.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[two_factor_enable]" value="0" />
					<input type="checkbox" name="wpsg[two_factor_enable]" value="1" <?php checked( $settings['two_factor_enable'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Enable Two-Factor Authentication Module', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Allows users to configure 2FA on their User Profile with one-time emergency recovery codes.', 'wp-secure-guard' ); ?>
				</p>
			</div>
		</div>

		<div class="wpsg-sub-settings">
			<p>
				<a href="<?php echo esc_url( admin_url( 'profile.php#wpsg_2fa_nonce' ) ); ?>" class="button button-secondary">
					<span class="dashicons dashicons-admin-users" style="vertical-align:text-bottom;margin-right:4px;"></span>
					<?php esc_html_e( 'Configure 2FA on Your Account Profile', 'wp-secure-guard' ); ?> &rarr;
				</a>
			</p>
		</div>
	</div>

	<!-- Feature 8: XML-RPC Protection -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-rest-api"></span>
				<?php esc_html_e( '8. XML-RPC Protection', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'XML-RPC was originally built for remote blog posting, but today it is overwhelmingly used for DDoS reflection attacks and mass brute-force attacks via multicall.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[xmlrpc_disable]" value="0" />
					<input type="checkbox" name="wpsg[xmlrpc_disable]" value="1" <?php checked( $settings['xmlrpc_disable'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Disable XML-RPC & Remove Pingback Header', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Disables all XML-RPC methods and blocks direct HTTP POST requests to xmlrpc.php.', 'wp-secure-guard' ); ?>
				</p>
				<span class="wpsg-pill wpsg-pill-recommended"><?php esc_html_e( 'Recommended', 'wp-secure-guard' ); ?></span>
			</div>
		</div>
	</div>

	<!-- Feature 9: Common Usernames Audit -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-id-alt"></span>
				<?php esc_html_e( '9. Common Administrator Usernames Audit', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Default usernames like "admin" or "root" are the first targets tested by credential brute-force bots.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[common_usernames_audit]" value="0" />
					<input type="checkbox" name="wpsg[common_usernames_audit]" value="1" <?php checked( $settings['common_usernames_audit'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Audit & Block Weak Default Usernames', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Disallows new registrations with common usernames and audits existing accounts.', 'wp-secure-guard' ); ?>
				</p>
			</div>
		</div>

		<div class="wpsg-sub-settings">
			<?php if ( empty( $vulnerable_users ) ) : ?>
				<div class="wpsg-alert wpsg-alert-success">
					<span class="dashicons dashicons-yes-alt"></span>
					<strong><?php esc_html_e( 'Audit Passed:', 'wp-secure-guard' ); ?></strong>
					<?php esc_html_e( 'No administrative accounts found with insecure default usernames ("admin", "root", "test", etc.).', 'wp-secure-guard' ); ?>
				</div>
			<?php else : ?>
				<div class="wpsg-alert wpsg-alert-danger">
					<span class="dashicons dashicons-warning"></span>
					<strong><?php esc_html_e( 'High Risk Accounts Detected!', 'wp-secure-guard' ); ?></strong>
					<?php esc_html_e( 'The following accounts use predictable usernames. Create a new administrative account with a unique username, transfer content, and delete these accounts:', 'wp-secure-guard' ); ?>
				</div>
				<table class="wp-list-table widefat fixed striped" style="margin-top: 10px;">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Username', 'wp-secure-guard' ); ?></th>
							<th><?php esc_html_e( 'Email', 'wp-secure-guard' ); ?></th>
							<th><?php esc_html_e( 'Role', 'wp-secure-guard' ); ?></th>
							<th><?php esc_html_e( 'Action', 'wp-secure-guard' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $vulnerable_users as $vuln ) : ?>
							<tr>
								<td><strong><?php echo esc_html( $vuln['username'] ); ?></strong></td>
								<td><?php echo esc_html( $vuln['email'] ); ?></td>
								<td><code><?php echo esc_html( implode( ', ', (array) $vuln['roles'] ) ); ?></code></td>
								<td>
									<a href="<?php echo esc_url( admin_url( 'user-edit.php?user_id=' . $vuln['id'] ) ); ?>" class="button button-small">
										<?php esc_html_e( 'Edit Account', 'wp-secure-guard' ); ?>
									</a>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
	</div>

	<!-- Feature 10: Password Security Policy -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-admin-network"></span>
				<?php esc_html_e( '10. Password Strength Policy', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Enforce strong password rules for all users during account registration, password resets, and profile updates.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[password_policy_enable]" value="0" />
					<input type="checkbox" name="wpsg[password_policy_enable]" value="1" <?php checked( $settings['password_policy_enable'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Enforce Password Security Policy', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Rejects weak passwords and requires compliance with character length and complexity rules.', 'wp-secure-guard' ); ?>
				</p>
			</div>
		</div>

		<div class="wpsg-sub-settings">
			<div class="wpsg-field-group" style="margin-bottom: 12px;">
				<label for="wpsg_password_min_length"><strong><?php esc_html_e( 'Minimum Password Length:', 'wp-secure-guard' ); ?></strong></label>
				<input type="number" id="wpsg_password_min_length" name="wpsg[password_min_length]" value="<?php echo esc_attr( $settings['password_min_length'] ); ?>" min="8" max="64" class="small-text" />
				<span class="description"><?php esc_html_e( 'characters (Recommended: 12 or more)', 'wp-secure-guard' ); ?></span>
			</div>

			<div class="wpsg-checkbox-group">
				<label>
					<input type="hidden" name="wpsg[password_require_mixed_case]" value="0" />
					<input type="checkbox" name="wpsg[password_require_mixed_case]" value="1" <?php checked( $settings['password_require_mixed_case'] ); ?> />
					<?php esc_html_e( 'Require both uppercase (A-Z) and lowercase (a-z) letters', 'wp-secure-guard' ); ?>
				</label>
				<br />
				<label>
					<input type="hidden" name="wpsg[password_require_numbers]" value="0" />
					<input type="checkbox" name="wpsg[password_require_numbers]" value="1" <?php checked( $settings['password_require_numbers'] ); ?> />
					<?php esc_html_e( 'Require at least one numeric digit (0-9)', 'wp-secure-guard' ); ?>
				</label>
				<br />
				<label>
					<input type="hidden" name="wpsg[password_require_symbols]" value="0" />
					<input type="checkbox" name="wpsg[password_require_symbols]" value="1" <?php checked( $settings['password_require_symbols'] ); ?> />
					<?php esc_html_e( 'Require at least one special character or symbol (!@#$%^&*)', 'wp-secure-guard' ); ?>
				</label>
			</div>
		</div>
	</div>

	<!-- Feature: Custom Login URL (Cloak wp-login.php & wp-admin) -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-admin-links"></span>
				<?php esc_html_e( 'Custom Login URL (Cloak wp-admin & wp-login.php)', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Changes the default WordPress login address to a secret custom URL (e.g., /login-controller/). Anyone attempting to access wp-login.php or wp-admin directly receives a 404 Not Found error.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[custom_login_enable]" value="0" />
					<input type="checkbox" name="wpsg[custom_login_enable]" value="1" <?php checked( $settings['custom_login_enable'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Enable Custom Login URL', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Blocks direct visits to wp-login.php and wp-admin, serving an HTTP 404 response to bots and unauthorized visitors.', 'wp-secure-guard' ); ?>
				</p>
			</div>
		</div>

		<div class="wpsg-sub-settings">
			<div class="wpsg-field-group">
				<label for="wpsg_custom_login_slug"><strong><?php esc_html_e( 'Custom Login Slug:', 'wp-secure-guard' ); ?></strong></label>
				<div style="display:flex; align-items:center; gap:6px; margin-top:4px;">
					<code><?php echo esc_html( home_url( '/' ) ); ?></code>
					<input type="text" id="wpsg_custom_login_slug" name="wpsg[custom_login_slug]" value="<?php echo esc_attr( $settings['custom_login_slug'] ); ?>" class="regular-text code" placeholder="login-controller" />
					<code>/</code>
				</div>
				<p class="description">
					<?php esc_html_e( 'Example: enter "login-controller" or your preferred secret slug. Avoid spaces and special characters.', 'wp-secure-guard' ); ?>
				</p>
			</div>

			<?php if ( ! empty( $settings['custom_login_enable'] ) ) : ?>
				<div class="wpsg-alert wpsg-alert-success" style="margin-top: 15px;">
					<span class="dashicons dashicons-admin-links"></span>
					<strong><?php esc_html_e( 'Your Active Secret Login URL:', 'wp-secure-guard' ); ?></strong>
					<a href="<?php echo esc_url( WPSG_Custom_Login_URL::get_custom_login_url() ); ?>" target="_blank" rel="noopener noreferrer" style="font-weight: bold; margin-left: 5px;">
						<?php echo esc_html( WPSG_Custom_Login_URL::get_custom_login_url() ); ?>
					</a>
				</div>
			<?php endif; ?>

			<div class="wpsg-alert wpsg-alert-warning" style="margin-top: 10px;">
				<span class="dashicons dashicons-shield"></span>
				<strong><?php esc_html_e( 'Emergency Access / Failsafe:', 'wp-secure-guard' ); ?></strong>
				<?php esc_html_e( 'If you ever forget your custom slug, you can instantly restore default wp-login.php by adding this line to your wp-config.php file:', 'wp-secure-guard' ); ?>
				<pre class="wpsg-code-box" style="margin: 8px 0 0;"><code>define( 'WPSG_DISABLE_CUSTOM_LOGIN', true );</code></pre>
			</div>
		</div>
	</div>

	<!-- Feature: User Registration Control -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-admin-users"></span>
				<?php esc_html_e( 'User Registration & Spam Account Protection', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Disallow public membership registration to prevent malicious bots from creating unauthorized subscriber or spam accounts.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[disable_user_registration]" value="0" />
					<input type="checkbox" name="wpsg[disable_user_registration]" value="1" <?php checked( $settings['disable_user_registration'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Disable Public User Registration', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Overrides the "Anyone can register" setting, blocks wp-login.php?action=register, and denies unauthenticated REST API user creation.', 'wp-secure-guard' ); ?>
				</p>
				<?php
				$reg_status = WPSG_User_Registration::get_status();
				if ( 'passed' === $reg_status['status'] ) : ?>
					<span class="wpsg-pill wpsg-pill-recommended"><?php echo esc_html( $reg_status['label'] ); ?></span>
				<?php else : ?>
					<span class="wpsg-pill wpsg-pill-optional" style="background:#fcf0f0;color:#d63638;border-color:#f5c6cb;"><?php echo esc_html( $reg_status['label'] ); ?></span>
				<?php endif; ?>
			</div>
		</div>
	</div>

	<!-- Feature: Cookie Security Hardening (HttpOnly & SameSite) -->
	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-shield"></span>
				<?php esc_html_e( 'Cookie Security & Scanner Hardening (HttpOnly, SameSite & Secure)', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Enforces HttpOnly, SameSite, and Secure flags on all outgoing cookies (including third-party security plugin cookies like icwp-wpsf-notbot). Resolves Netsparker, Invicti, Acunetix, and OWASP ZAP cookie vulnerability findings (CWE-1004 & CWE-1275).', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[cookie_security_enable]" value="0" />
					<input type="checkbox" name="wpsg[cookie_security_enable]" value="1" <?php checked( $settings['cookie_security_enable'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( 'Enable Cookie Security Hardening', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Automatically inspects all HTTP Set-Cookie headers and injects missing SameSite, HttpOnly, and Secure flags before output.', 'wp-secure-guard' ); ?>
				</p>
				<span class="wpsg-pill wpsg-pill-recommended"><?php esc_html_e( 'Netsparker & OWASP Compliant', 'wp-secure-guard' ); ?></span>
			</div>
		</div>

		<div class="wpsg-sub-settings">
			<div class="wpsg-field-group">
				<label for="wpsg_cookie_samesite_policy"><strong><?php esc_html_e( 'SameSite Policy:', 'wp-secure-guard' ); ?></strong></label>
				<select id="wpsg_cookie_samesite_policy" name="wpsg[cookie_samesite_policy]">
					<option value="Lax" <?php selected( $settings['cookie_samesite_policy'], 'Lax' ); ?>><?php esc_html_e( 'Lax (Recommended - Balanced security & seamless user experience)', 'wp-secure-guard' ); ?></option>
					<option value="Strict" <?php selected( $settings['cookie_samesite_policy'], 'Strict' ); ?>><?php esc_html_e( 'Strict (Highest security - cookies restricted strictly to first-party requests)', 'wp-secure-guard' ); ?></option>
				</select>
			</div>

			<div class="wpsg-field-group" style="margin-top:10px;">
				<label>
					<input type="hidden" name="wpsg[cookie_httponly_enable]" value="0" />
					<input type="checkbox" name="wpsg[cookie_httponly_enable]" value="1" <?php checked( $settings['cookie_httponly_enable'] ); ?> />
					<strong><?php esc_html_e( 'Enforce HttpOnly flag', 'wp-secure-guard' ); ?></strong>
				</label>
				<p class="description">
					<?php esc_html_e( 'Prevents client-side scripts from reading sensitive cookies, eliminating XSS session-hijacking risks.', 'wp-secure-guard' ); ?>
				</p>
			</div>

			<div class="wpsg-field-group" style="margin-top:10px;">
				<label>
					<input type="hidden" name="wpsg[cookie_secure_enable]" value="0" />
					<input type="checkbox" name="wpsg[cookie_secure_enable]" value="1" <?php checked( $settings['cookie_secure_enable'] ); ?> />
					<strong><?php esc_html_e( 'Enforce Secure flag on HTTPS', 'wp-secure-guard' ); ?></strong>
				</label>
				<p class="description">
					<?php esc_html_e( 'Ensures cookies are only transmitted over encrypted SSL/TLS connections.', 'wp-secure-guard' ); ?>
				</p>
			</div>
		</div>
	</div>

	<div class="wpsg-form-actions">
		<button type="submit" class="button button-primary button-large">
			<span class="dashicons dashicons-saved" style="vertical-align:text-bottom;margin-right:4px;"></span>
			<?php esc_html_e( 'Save Login Security Settings', 'wp-secure-guard' ); ?>
		</button>
	</div>
</form>
