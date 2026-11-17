<?php
/**
 * Module: Two-Factor Authentication (RFC 6238 TOTP).
 *
 * Implements native, vendor-independent TOTP 2FA with emergency backup codes.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Two_Factor
 */
class WPSG_Two_Factor {

	/**
	 * Meta keys for storing 2FA configuration in wp_usermeta.
	 */
	const META_SECRET       = 'wpsg_2fa_secret';
	const META_ENABLED      = 'wpsg_2fa_enabled';
	const META_BACKUP_CODES = 'wpsg_2fa_backup_codes';

	/**
	 * Initialize 2FA hooks.
	 */
	public static function init() {
		if ( ! WPSG_Settings::get( 'two_factor_enable', true ) ) {
			return;
		}

		// Login form hooks.
		add_action( 'login_form', array( __CLASS__, 'render_login_2fa_field' ) );
		add_filter( 'wp_authenticate_user', array( __CLASS__, 'verify_login_2fa' ), 20, 2 );

		// User profile setup hooks.
		add_action( 'show_user_profile', array( __CLASS__, 'render_profile_fields' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'render_profile_fields' ) );
		add_action( 'personal_options_update', array( __CLASS__, 'save_profile_fields' ) );
		add_action( 'edit_user_profile_update', array( __CLASS__, 'save_profile_fields' ) );
	}

	/**
	 * Render the 2FA code input field on the wp-login.php screen.
	 */
	public static function render_login_2fa_field() {
		?>
		<p class="wpsg-2fa-login-wrap" style="margin-top: 12px; margin-bottom: 16px;">
			<label for="wpsg_2fa_code" style="font-weight: 600; display: block; margin-bottom: 4px;">
				<?php esc_html_e( 'Security Code / 2FA (if enabled)', 'wp-secure-guard' ); ?>
			</label>
			<input type="text" name="wpsg_2fa_code" id="wpsg_2fa_code" class="input" value="" size="20" autocomplete="one-time-code" placeholder="<?php esc_attr_e( '6-digit code or backup code', 'wp-secure-guard' ); ?>" style="letter-spacing: 2px; font-family: monospace; font-size: 16px;" />
			<span class="description" style="font-size: 12px; color: #646970; display: block; margin-top: 3px;">
				<?php esc_html_e( 'Enter your Authenticator app code or emergency backup code.', 'wp-secure-guard' ); ?>
			</span>
		</p>
		<?php
	}

	/**
	 * Intercept authentication to verify TOTP or backup code if 2FA is enabled for this user.
	 *
	 * @param WP_User|WP_Error $user     User object or authentication error.
	 * @param string           $password Submitted password.
	 * @return WP_User|WP_Error
	 */
	public static function verify_login_2fa( $user, $password ) {
		if ( is_wp_error( $user ) ) {
			return $user;
		}

		$user_id = $user->ID;

		// Check if 2FA is active for this user.
		if ( ! self::is_user_2fa_enabled( $user_id ) ) {
			return $user;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$code = isset( $_POST['wpsg_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['wpsg_2fa_code'] ) ) : '';
		$code = trim( str_replace( ' ', '', $code ) );

		if ( empty( $code ) ) {
			return new WP_Error(
				'wpsg_2fa_code_required',
				__( '<strong>ERROR</strong>: Two-Factor Authentication is required for your account. Please enter your 6-digit authenticator code or emergency backup code.', 'wp-secure-guard' )
			);
		}

		$secret = get_user_meta( $user_id, self::META_SECRET, true );

		// 1. Verify TOTP 6-digit code.
		if ( self::verify_totp( $secret, $code ) ) {
			WPSG_Logger::log(
				'2fa_success',
				sprintf(
					/* translators: 1: username, 2: client IP */
					__( '2FA verification succeeded for user "%1$s" from IP %2$s.', 'wp-secure-guard' ),
					$user->user_login,
					WPSG_Logger::get_client_ip()
				),
				'info',
				array( 'user_id' => $user_id, 'username' => $user->user_login )
			);
			return $user;
		}

		// 2. Check emergency backup codes.
		if ( self::verify_and_consume_backup_code( $user_id, $code ) ) {
			WPSG_Logger::log(
				'2fa_backup_used',
				sprintf(
					/* translators: 1: username, 2: client IP */
					__( 'Emergency 2FA backup code used for login by user "%1$s" from IP %2$s.', 'wp-secure-guard' ),
					$user->user_login,
					WPSG_Logger::get_client_ip()
				),
				'warning',
				array( 'user_id' => $user_id, 'username' => $user->user_login )
			);
			return $user;
		}

		// Invalid 2FA code.
		WPSG_Logger::log(
			'2fa_failed',
			sprintf(
				/* translators: 1: username, 2: client IP */
				__( 'Invalid 2FA code attempt for user "%1$s" from IP %2$s.', 'wp-secure-guard' ),
				$user->user_login,
				WPSG_Logger::get_client_ip()
			),
			'warning',
			array( 'user_id' => $user_id, 'username' => $user->user_login )
		);

		return new WP_Error(
			'wpsg_2fa_code_invalid',
			__( '<strong>ERROR</strong>: The Two-Factor Authentication code you entered is invalid or has expired. Please try again.', 'wp-secure-guard' )
		);
	}

	/**
	 * Check if 2FA is active on an individual user account.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	public static function is_user_2fa_enabled( $user_id ) {
		$enabled = get_user_meta( $user_id, self::META_ENABLED, true );
		$secret  = get_user_meta( $user_id, self::META_SECRET, true );
		return ! empty( $enabled ) && ! empty( $secret );
	}

	/**
	 * Render profile settings for Two-Factor Authentication.
	 *
	 * @param WP_User $user User object.
	 */
	public static function render_profile_fields( $user ) {
		if ( ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}

		$is_enabled   = self::is_user_2fa_enabled( $user->ID );
		$secret       = get_user_meta( $user->ID, self::META_SECRET, true );
		$backup_codes = get_user_meta( $user->ID, self::META_BACKUP_CODES, true );

		if ( empty( $secret ) ) {
			$secret = self::generate_secret();
			// Store preliminary secret for configuration.
			update_user_meta( $user->ID, self::META_SECRET, $secret );
		}

		$site_title = get_bloginfo( 'name' );
		$otpauth_url = sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
			rawurlencode( $site_title ),
			rawurlencode( $user->user_login ),
			$secret,
			rawurlencode( $site_title )
		);

		wp_nonce_field( 'wpsg_save_2fa_' . $user->ID, 'wpsg_2fa_nonce' );
		?>
		<h2><?php esc_html_e( 'WP Secure Guard — Two-Factor Authentication (2FA)', 'wp-secure-guard' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><?php esc_html_e( '2FA Status', 'wp-secure-guard' ); ?></th>
				<td>
					<?php if ( $is_enabled ) : ?>
						<span class="wpsg-badge wpsg-badge-success" style="background:#00a32a;color:#fff;padding:4px 8px;border-radius:3px;font-weight:600;">
							<?php esc_html_e( 'Enabled & Active', 'wp-secure-guard' ); ?>
						</span>
						<label style="margin-left: 15px;">
							<input type="checkbox" name="wpsg_disable_2fa" value="1" />
							<?php esc_html_e( 'Disable Two-Factor Authentication for this account', 'wp-secure-guard' ); ?>
						</label>
					<?php else : ?>
						<span class="wpsg-badge wpsg-badge-warning" style="background:#dba617;color:#fff;padding:4px 8px;border-radius:3px;font-weight:600;">
							<?php esc_html_e( 'Not Enabled', 'wp-secure-guard' ); ?>
						</span>
					<?php endif; ?>
				</td>
			</tr>

			<?php if ( ! $is_enabled ) : ?>
			<tr>
				<th scope="row"><?php esc_html_e( 'Setup 2FA', 'wp-secure-guard' ); ?></th>
				<td>
					<p><?php esc_html_e( 'Scan the QR key link or enter the secret key below into your authenticator app (Google Authenticator, Microsoft Authenticator, Authy, or 1Password):', 'wp-secure-guard' ); ?></p>
					
					<div style="background:#f0f0f1;padding:12px;display:inline-block;border-radius:4px;margin:8px 0;">
						<strong style="font-size:16px;font-family:monospace;letter-spacing:2px;"><?php echo esc_html( chunk_split( $secret, 4, ' ' ) ); ?></strong>
					</div>
					<p>
						<a href="<?php echo esc_url( $otpauth_url ); ?>" class="button button-secondary">
							<?php esc_html_e( 'Open in Authenticator App (One-Click)', 'wp-secure-guard' ); ?>
						</a>
					</p>

					<p style="margin-top:15px;">
						<label for="wpsg_verify_code"><strong><?php esc_html_e( 'Verification Code:', 'wp-secure-guard' ); ?></strong></label><br />
						<input type="text" name="wpsg_verify_code" id="wpsg_verify_code" class="regular-text" placeholder="123456" autocomplete="off" style="width:140px;letter-spacing:3px;font-family:monospace;" />
						<span class="description"><?php esc_html_e( 'Enter the 6-digit code shown in your app and click "Update Profile" to activate 2FA.', 'wp-secure-guard' ); ?></span>
					</p>
				</td>
			</tr>
			<?php endif; ?>

			<?php if ( $is_enabled ) : ?>
			<tr>
				<th scope="row"><?php esc_html_e( 'Emergency Backup Codes', 'wp-secure-guard' ); ?></th>
				<td>
					<?php
					$remaining_codes = is_array( $backup_codes ) ? count( $backup_codes ) : 0;
					?>
					<p>
						<?php
						printf(
							/* translators: %d: remaining backup codes */
							esc_html__( 'You have %d remaining emergency backup codes.', 'wp-secure-guard' ),
							$remaining_codes
						);
						?>
					</p>
					<label>
						<input type="checkbox" name="wpsg_regenerate_backup_codes" value="1" />
						<?php esc_html_e( 'Generate 8 new emergency backup codes (invalidates old ones)', 'wp-secure-guard' ); ?>
					</label>
				</td>
			</tr>
			<?php endif; ?>
		</table>
		<?php
	}

	/**
	 * Save 2FA settings from profile update.
	 *
	 * @param int $user_id User ID.
	 */
	public static function save_profile_fields( $user_id ) {
		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! isset( $_POST['wpsg_2fa_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['wpsg_2fa_nonce'] ) ), 'wpsg_save_2fa_' . $user_id ) ) {
			return;
		}

		// Disable 2FA if requested.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['wpsg_disable_2fa'] ) ) {
			delete_user_meta( $user_id, self::META_ENABLED );
			delete_user_meta( $user_id, self::META_SECRET );
			delete_user_meta( $user_id, self::META_BACKUP_CODES );

			WPSG_Logger::log(
				'2fa_disabled',
				sprintf(
					/* translators: %d: user id */
					__( 'Two-Factor Authentication was disabled for user ID %d.', 'wp-secure-guard' ),
					$user_id
				),
				'warning',
				array( 'user_id' => $user_id )
			);
			return;
		}

		// Verify and activate 2FA if verification code submitted.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['wpsg_verify_code'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$code   = sanitize_text_field( wp_unslash( $_POST['wpsg_verify_code'] ) );
			$secret = get_user_meta( $user_id, self::META_SECRET, true );

			if ( self::verify_totp( $secret, $code ) ) {
				update_user_meta( $user_id, self::META_ENABLED, 1 );

				// Automatically generate first set of backup codes.
				$codes = self::generate_backup_codes( $user_id );

				// Store transient to show codes on next page load.
				set_transient( 'wpsg_new_backup_codes_' . $user_id, $codes, 120 );

				WPSG_Logger::log(
					'2fa_enabled',
					sprintf(
						/* translators: %d: user id */
						__( 'Two-Factor Authentication was successfully activated for user ID %d.', 'wp-secure-guard' ),
						$user_id
					),
					'success',
					array( 'user_id' => $user_id )
				);
			}
		}

		// Regenerate backup codes if requested.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['wpsg_regenerate_backup_codes'] ) && self::is_user_2fa_enabled( $user_id ) ) {
			$codes = self::generate_backup_codes( $user_id );
			set_transient( 'wpsg_new_backup_codes_' . $user_id, $codes, 120 );
		}
	}

	/**
	 * Generate 8 emergency single-use backup recovery codes.
	 *
	 * @param int $user_id User ID.
	 * @return array Plaintext codes for initial display.
	 */
	public static function generate_backup_codes( $user_id ) {
		$plain_codes  = array();
		$hashed_codes = array();

		for ( $i = 0; $i < 8; $i++ ) {
			$code = wp_generate_password( 10, false, false );
			$plain_codes[]  = $code;
			$hashed_codes[] = wp_hash_password( $code );
		}

		update_user_meta( $user_id, self::META_BACKUP_CODES, $hashed_codes );
		return $plain_codes;
	}

	/**
	 * Verify an emergency backup code and remove it upon consumption.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Entered code.
	 * @return bool
	 */
	public static function verify_and_consume_backup_code( $user_id, $code ) {
		$hashed_codes = get_user_meta( $user_id, self::META_BACKUP_CODES, true );
		if ( ! is_array( $hashed_codes ) || empty( $hashed_codes ) ) {
			return false;
		}

		foreach ( $hashed_codes as $index => $hash ) {
			if ( wp_check_password( $code, $hash ) ) {
				// Remove consumed code.
				unset( $hashed_codes[ $index ] );
				update_user_meta( $user_id, self::META_BACKUP_CODES, array_values( $hashed_codes ) );
				return true;
			}
		}

		return false;
	}

	/**
	 * Generate a random 16-character Base32 secret string.
	 *
	 * @return string
	 */
	public static function generate_secret() {
		$chars  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$secret = '';
		for ( $i = 0; $i < 16; $i++ ) {
			$secret .= $chars[ wp_rand( 0, 31 ) ];
		}
		return $secret;
	}

	/**
	 * Verify an RFC 6238 TOTP code against a Base32 secret with +/- 1 time step tolerance.
	 *
	 * @param string $secret Base32 secret.
	 * @param string $code   6-digit code.
	 * @return bool
	 */
	public static function verify_totp( $secret, $code ) {
		if ( empty( $secret ) || empty( $code ) || strlen( $code ) !== 6 || ! ctype_digit( $code ) ) {
			return false;
		}

		$time_step = 30;
		$current_time_slice = (int) floor( time() / $time_step );

		// Check current, previous, and next time slices (tolerance for clock drift).
		for ( $offset = -1; $offset <= 1; $offset++ ) {
			$calculated = self::calculate_totp( $secret, $current_time_slice + $offset );
			if ( hash_equals( $calculated, $code ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Calculate TOTP code for a specific time slice.
	 *
	 * @param string $secret Base32 secret.
	 * @param int    $time_slice Time slice number.
	 * @return string 6-digit code.
	 */
	public static function calculate_totp( $secret, $time_slice ) {
		$key = self::base32_decode( $secret );

		// Pack counter into 8 bytes big-endian.
		$time_bytes = pack( 'N*', 0 ) . pack( 'N*', $time_slice );

		// Calculate HMAC-SHA1.
		$hash = hash_hmac( 'sha1', $time_bytes, $key, true );

		// Dynamic truncation.
		$offset = ord( substr( $hash, -1 ) ) & 0x0F;
		$truncated = unpack( 'N', substr( $hash, $offset, 4 ) );
		$binary = $truncated[1] & 0x7FFFFFFF;

		$otp = $binary % 1000000;
		return str_pad( (string) $otp, 6, '0', STR_PAD_LEFT );
	}

	/**
	 * Decode Base32 string to binary key.
	 *
	 * @param string $str Base32 encoded string.
	 * @return string Binary output.
	 */
	public static function base32_decode( $str ) {
		$str   = strtoupper( trim( $str ) );
		$chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$map   = array_flip( str_split( $chars ) );

		$binary = '';
		$len    = strlen( $str );
		for ( $i = 0; $i < $len; $i++ ) {
			$char = $str[ $i ];
			if ( ! isset( $map[ $char ] ) ) {
				continue;
			}
			$binary .= str_pad( decbin( $map[ $char ] ), 5, '0', STR_PAD_LEFT );
		}

		$bytes = '';
		$binary_len = strlen( $binary );
		for ( $i = 0; $i + 8 <= $binary_len; $i += 8 ) {
			$bytes .= chr( bindec( substr( $binary, $i, 8 ) ) );
		}

		return $bytes;
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'two_factor_enable', true );
		return array(
			'id'          => 'two_factor',
			'title'       => __( 'Two-Factor Authentication (2FA)', 'wp-secure-guard' ),
			'category'    => 'login_security',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? __( 'Active (TOTP)', 'wp-secure-guard' ) : __( 'Disabled', 'wp-secure-guard' ),
			'description' => __( 'Adds an additional layer of security using Google/Microsoft Authenticator or 1Password.', 'wp-secure-guard' ),
		);
	}
}
