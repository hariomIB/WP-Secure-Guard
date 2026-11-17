<?php
/**
 * Module: Common Usernames Audit & Protection.
 *
 * Scans for high-risk default administrative usernames and prevents registration of weak names.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Common_Usernames
 */
class WPSG_Common_Usernames {

	/**
	 * List of vulnerable usernames to audit against.
	 *
	 * @return array
	 */
	public static function get_insecure_usernames() {
		return array(
			'admin',
			'administrator',
			'root',
			'test',
			'user',
			'demo',
			'webmaster',
			'master',
			'support',
			'guest',
			'system',
			'superuser',
		);
	}

	/**
	 * Initialize registration hooks if enabled.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'common_usernames_audit', true ) ) {
			add_filter( 'validate_username', array( __CLASS__, 'prevent_insecure_username_registration' ), 10, 2 );
		}
	}

	/**
	 * Disallow new user registration with blacklisted weak usernames.
	 *
	 * @param bool   $valid    Whether username is valid.
	 * @param string $username Username string.
	 * @return bool
	 */
	public static function prevent_insecure_username_registration( $valid, $username ) {
		if ( ! $valid ) {
			return $valid;
		}

		$insecure = self::get_insecure_usernames();
		if ( in_array( strtolower( trim( $username ) ), $insecure, true ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Scan existing users for insecure administrative usernames.
	 *
	 * @return array List of user details with insecure usernames.
	 */
	public static function scan_existing_users() {
		$insecure_names = self::get_insecure_usernames();
		$vulnerable     = array();

		// Add site domain name without extension as a potential insecure username.
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( $host ) {
			$host_parts = explode( '.', $host );
			if ( ! empty( $host_parts[0] ) ) {
				$insecure_names[] = strtolower( $host_parts[0] );
			}
		}

		$insecure_names = array_unique( $insecure_names );

		foreach ( $insecure_names as $name ) {
			$user = get_user_by( 'login', $name );
			if ( $user ) {
				$vulnerable[] = array(
					'id'           => $user->ID,
					'username'     => $user->user_login,
					'email'        => $user->user_email,
					'roles'        => $user->roles,
					'is_admin'     => in_array( 'administrator', (array) $user->roles, true ),
				);
			}
		}

		return $vulnerable;
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled    = (bool) WPSG_Settings::get( 'common_usernames_audit', true );
		$vulnerable = self::scan_existing_users();
		$count      = count( $vulnerable );

		if ( ! $enabled ) {
			$status = 'warning';
			$label  = __( 'Audit Disabled', 'wp-secure-guard' );
		} elseif ( $count > 0 ) {
			$status = 'critical';
			/* translators: %d: count of vulnerable accounts */
			$label  = sprintf( _n( '%d Insecure Account Found', '%d Insecure Accounts Found', $count, 'wp-secure-guard' ), $count );
		} else {
			$status = 'passed';
			$label  = __( 'Clean (No common usernames)', 'wp-secure-guard' );
		}

		return array(
			'id'          => 'common_usernames',
			'title'       => __( 'Common Usernames Audit', 'wp-secure-guard' ),
			'category'    => 'login_security',
			'enabled'     => $enabled,
			'status'      => $status,
			'label'       => $label,
			'vulnerable'  => $vulnerable,
			'description' => __( 'Identifies accounts using predictable names like "admin", "administrator", or "root".', 'wp-secure-guard' ),
		);
	}
}
