<?php
/**
 * Module: Password Security Policy.
 *
 * Enforces strong password requirements for user registrations, resets, and profile updates.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Password_Policy
 */
class WPSG_Password_Policy {

	/**
	 * Initialize hooks if enabled.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'password_policy_enable', true ) ) {
			add_action( 'user_profile_update_errors', array( __CLASS__, 'validate_user_password' ), 10, 3 );
			add_action( 'validate_password_reset', array( __CLASS__, 'validate_reset_password' ), 10, 2 );
		}
	}

	/**
	 * Validate password when a user updates their profile.
	 *
	 * @param WP_Error $errors WP_Error object.
	 * @param bool     $update Whether this is an update.
	 * @param WP_User  $user   User object.
	 */
	public static function validate_user_password( $errors, $update, $user ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['pass1'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$password = sanitize_text_field( wp_unslash( $_POST['pass1'] ) );
			self::validate_password_rules( $password, $errors, $user );
		}
	}

	/**
	 * Validate password during password reset request.
	 *
	 * @param WP_Error $errors WP_Error object.
	 * @param WP_User  $user   User object.
	 */
	public static function validate_reset_password( $errors, $user ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST['pass1'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$password = sanitize_text_field( wp_unslash( $_POST['pass1'] ) );
			self::validate_password_rules( $password, $errors, $user );
		}
	}

	/**
	 * Verify password string against configured security rules.
	 *
	 * @param string   $password Raw password.
	 * @param WP_Error $errors   WP_Error object to append to.
	 * @param WP_User  $user     User object.
	 */
	public static function validate_password_rules( $password, $errors, $user ) {
		$min_length   = absint( WPSG_Settings::get( 'password_min_length', 12 ) );
		$require_case = (bool) WPSG_Settings::get( 'password_require_mixed_case', true );
		$require_num  = (bool) WPSG_Settings::get( 'password_require_numbers', true );
		$require_sym  = (bool) WPSG_Settings::get( 'password_require_symbols', true );

		if ( strlen( $password ) < $min_length ) {
			$errors->add(
				'wpsg_password_too_short',
				sprintf(
					/* translators: %d: minimum character length */
					__( '<strong>ERROR</strong>: Password must be at least %d characters in length.', 'wp-secure-guard' ),
					$min_length
				)
			);
		}

		if ( $require_case && ( ! preg_match( '/[a-z]/', $password ) || ! preg_match( '/[A-Z]/', $password ) ) ) {
			$errors->add(
				'wpsg_password_case_missing',
				__( '<strong>ERROR</strong>: Password must contain both uppercase and lowercase letters.', 'wp-secure-guard' )
			);
		}

		if ( $require_num && ! preg_match( '/[0-9]/', $password ) ) {
			$errors->add(
				'wpsg_password_num_missing',
				__( '<strong>ERROR</strong>: Password must contain at least one numeric digit (0-9).', 'wp-secure-guard' )
			);
		}

		if ( $require_sym && ! preg_match( '/[^a-zA-Z0-9]/', $password ) ) {
			$errors->add(
				'wpsg_password_sym_missing',
				__( '<strong>ERROR</strong>: Password must contain at least one special character or symbol.', 'wp-secure-guard' )
			);
		}

		// Prevent username inside password.
		if ( ! empty( $user->user_login ) && false !== stripos( $password, $user->user_login ) ) {
			$errors->add(
				'wpsg_password_contains_username',
				__( '<strong>ERROR</strong>: Password cannot contain your username.', 'wp-secure-guard' )
			);
		}
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled    = (bool) WPSG_Settings::get( 'password_policy_enable', true );
		$min_length = absint( WPSG_Settings::get( 'password_min_length', 12 ) );

		return array(
			'id'          => 'password_policy',
			'title'       => __( 'Password Strength Policy', 'wp-secure-guard' ),
			'category'    => 'login_security',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? sprintf( __( 'Enforced (%d+ chars)', 'wp-secure-guard' ), $min_length ) : __( 'Disabled', 'wp-secure-guard' ),
			'description' => __( 'Mandates strong passwords (length, numbers, case, symbols) to stop credential dictionary attacks.', 'wp-secure-guard' ),
		);
	}
}
