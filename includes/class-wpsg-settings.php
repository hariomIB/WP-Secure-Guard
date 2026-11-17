<?php
/**
 * Settings and options manager.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Settings
 */
class WPSG_Settings {

	/**
	 * Option name in wp_options.
	 */
	const OPTION_NAME = 'wpsg_settings';

	/**
	 * Cached settings array.
	 *
	 * @var array|null
	 */
	private static $cached_settings = null;

	/**
	 * Retrieve default plugin settings.
	 *
	 * @return array Default settings map.
	 */
	public static function get_defaults() {
		return array(
			// 1. User Protection
			'user_enum_block'              => true,
			'rest_api_user_protect'        => true,
			'oembed_strip_author'          => true,
			'author_sitemap_disable'       => true,
			'author_archive_disable'       => false,

			// 2. Login Security
			'login_limiter_enable'         => true,
			'login_max_retries'            => 5,
			'login_lockout_duration'       => 15, // in minutes
			'login_whitelist_ips'          => '',
			'two_factor_enable'            => true,
			'two_factor_roles'             => array( 'administrator' ),
			'xmlrpc_disable'               => true,
			'common_usernames_audit'       => true,
			'password_policy_enable'       => true,
			'password_min_length'          => 12,
			'password_require_mixed_case'  => true,
			'password_require_numbers'     => true,
			'password_require_symbols'     => true,
			'custom_login_enable'          => false,
			'custom_login_slug'            => 'login-controller',
			'disable_user_registration'    => false,

			// 3. File Security
			'disallow_file_edit_enforce'   => true,
			'uploads_php_protect'          => true,
			'sensitive_files_protect'      => true,
			'directory_listing_protect'    => true,
			'permissions_audit_enable'     => true,

			// 4. Monitoring & Threat Defense
			'waf_enable'                   => true,
			'waf_mode'                     => 'block', // 'block' or 'monitor'
			'waf_block_sqli'               => true,
			'waf_block_xss'                => true,
			'waf_block_traversal'          => true,
			'waf_block_bad_bots'           => true,
			'update_checker_enable'        => true,
			'php_hardening_audit'          => true,
			'activity_logs_enable'         => true,
			'activity_logs_retention_days' => 30,
			'backup_checker_enable'        => true,
			'hide_wp_version'              => true,
			'hide_server_info'             => true,

			// Plugin Maintenance
			'delete_data_on_uninstall'     => false,
		);
	}

	/**
	 * Get all settings merged with defaults.
	 *
	 * @param bool $refresh Whether to bypass static cache.
	 * @return array
	 */
	public static function get_settings( $refresh = false ) {
		if ( null !== self::$cached_settings && ! $refresh ) {
			return self::$cached_settings;
		}

		$saved    = get_option( self::OPTION_NAME, array() );
		$defaults = self::get_defaults();

		if ( ! is_array( $saved ) ) {
			$saved = array();
		}

		self::$cached_settings = wp_parse_args( $saved, $defaults );
		return self::$cached_settings;
	}

	/**
	 * Retrieve a specific setting value.
	 *
	 * @param string $key     Setting key name.
	 * @param mixed  $default Fallback value if setting not found.
	 * @return mixed
	 */
	public static function get( $key, $default = null ) {
		$settings = self::get_settings();
		if ( isset( $settings[ $key ] ) ) {
			return $settings[ $key ];
		}
		$defaults = self::get_defaults();
		return isset( $defaults[ $key ] ) ? $defaults[ $key ] : $default;
	}

	/**
	 * Map of settings keys belonging to each admin tab.
	 *
	 * @return array
	 */
	public static function get_tab_map() {
		return array(
			'user_security' => array(
				'user_enum_block',
				'rest_api_user_protect',
				'oembed_strip_author',
				'author_sitemap_disable',
				'author_archive_disable',
			),
			'login_security' => array(
				'login_limiter_enable',
				'login_max_retries',
				'login_lockout_duration',
				'login_whitelist_ips',
				'two_factor_enable',
				'two_factor_roles',
				'xmlrpc_disable',
				'common_usernames_audit',
				'password_policy_enable',
				'password_min_length',
				'password_require_mixed_case',
				'password_require_numbers',
				'password_require_symbols',
				'custom_login_enable',
				'custom_login_slug',
				'disable_user_registration',
			),
			'file_security' => array(
				'disallow_file_edit_enforce',
				'uploads_php_protect',
				'sensitive_files_protect',
				'directory_listing_protect',
				'permissions_audit_enable',
			),
			'monitoring' => array(
				'waf_enable',
				'waf_mode',
				'waf_block_sqli',
				'waf_block_xss',
				'waf_block_traversal',
				'waf_block_bad_bots',
				'update_checker_enable',
				'php_hardening_audit',
				'activity_logs_enable',
				'activity_logs_retention_days',
				'backup_checker_enable',
				'hide_wp_version',
				'hide_server_info',
			),
			'settings' => array(
				'delete_data_on_uninstall',
			),
		);
	}

	/**
	 * Update settings.
	 *
	 * @param array  $new_settings Settings to update.
	 * @param string $tab          Optional tab slug being updated.
	 * @return bool True if updated.
	 */
	public static function update_settings( $new_settings, $tab = '' ) {
		$current  = self::get_settings( true );
		$defaults = self::get_defaults();
		$tab_map  = self::get_tab_map();

		$target = $current;

		if ( ! empty( $tab ) && isset( $tab_map[ $tab ] ) ) {
			// Tab-scoped update: update ONLY the keys belonging to this tab.
			$tab_keys = $tab_map[ $tab ];

			foreach ( $tab_keys as $key ) {
				if ( is_bool( $defaults[ $key ] ) ) {
					// Boolean toggle: if present and truthy, true; otherwise false.
					$target[ $key ] = ! empty( $new_settings[ $key ] );
				} elseif ( isset( $new_settings[ $key ] ) ) {
					$target[ $key ] = $new_settings[ $key ];
				}
			}
		} else {
			// Full update or un-tabbed update.
			foreach ( $defaults as $key => $default_val ) {
				if ( is_bool( $default_val ) ) {
					if ( isset( $new_settings[ $key ] ) ) {
						$target[ $key ] = ! empty( $new_settings[ $key ] );
					}
				} elseif ( isset( $new_settings[ $key ] ) ) {
					$target[ $key ] = $new_settings[ $key ];
				}
			}
		}

		$sanitized = self::sanitize_settings( $target );
		$updated   = update_option( self::OPTION_NAME, $sanitized );
		self::$cached_settings = $sanitized;
		return $updated;
	}

	/**
	 * Reset all settings to safe defaults.
	 *
	 * @return bool
	 */
	public static function reset_to_defaults() {
		$defaults              = self::get_defaults();
		$updated               = update_option( self::OPTION_NAME, $defaults );
		self::$cached_settings = $defaults;
		return $updated;
	}

	/**
	 * Sanitize raw settings input from forms or API.
	 *
	 * @param array $input Raw input.
	 * @return array Sanitized settings.
	 */
	public static function sanitize_settings( $input ) {
		$defaults = self::get_defaults();
		$clean    = array();

		// Boolean flags
		$bool_keys = array(
			'user_enum_block',
			'rest_api_user_protect',
			'oembed_strip_author',
			'author_sitemap_disable',
			'author_archive_disable',
			'login_limiter_enable',
			'two_factor_enable',
			'xmlrpc_disable',
			'common_usernames_audit',
			'password_policy_enable',
			'password_require_mixed_case',
			'password_require_numbers',
			'password_require_symbols',
			'custom_login_enable',
			'disable_user_registration',
			'disallow_file_edit_enforce',
			'uploads_php_protect',
			'sensitive_files_protect',
			'directory_listing_protect',
			'permissions_audit_enable',
			'waf_enable',
			'waf_block_sqli',
			'waf_block_xss',
			'waf_block_traversal',
			'waf_block_bad_bots',
			'update_checker_enable',
			'php_hardening_audit',
			'activity_logs_enable',
			'backup_checker_enable',
			'hide_wp_version',
			'hide_server_info',
			'delete_data_on_uninstall',
		);

		foreach ( $bool_keys as $key ) {
			$clean[ $key ] = ! empty( $input[ $key ] );
		}

		// Numeric values
		$clean['login_max_retries']            = isset( $input['login_max_retries'] ) ? max( 1, min( 20, absint( $input['login_max_retries'] ) ) ) : 5;
		$clean['login_lockout_duration']       = isset( $input['login_lockout_duration'] ) ? max( 1, min( 1440, absint( $input['login_lockout_duration'] ) ) ) : 15;
		$clean['password_min_length']          = isset( $input['password_min_length'] ) ? max( 8, min( 64, absint( $input['password_min_length'] ) ) ) : 12;
		$clean['activity_logs_retention_days'] = isset( $input['activity_logs_retention_days'] ) ? max( 7, min( 365, absint( $input['activity_logs_retention_days'] ) ) ) : 30;

		// Strings
		$clean['waf_mode'] = isset( $input['waf_mode'] ) && in_array( $input['waf_mode'], array( 'block', 'monitor' ), true )
			? sanitize_key( $input['waf_mode'] )
			: 'block';

		// Custom login slug
		if ( isset( $input['custom_login_slug'] ) ) {
			$slug = sanitize_title_with_dashes( trim( (string) $input['custom_login_slug'] ) );
			$clean['custom_login_slug'] = ! empty( $slug ) ? $slug : 'login-controller';
		} else {
			$clean['custom_login_slug'] = 'login-controller';
		}

		// IP Whitelist (textarea or comma-delimited)
		if ( isset( $input['login_whitelist_ips'] ) ) {
			$raw_ips = explode( "\n", str_replace( array( "\r\n", "\r", ',' ), "\n", $input['login_whitelist_ips'] ) );
			$valid_ips = array();
			foreach ( $raw_ips as $ip ) {
				$ip = trim( sanitize_text_field( $ip ) );
				if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
					$valid_ips[] = $ip;
				}
			}
			$clean['login_whitelist_ips'] = implode( "\n", array_unique( $valid_ips ) );
		} else {
			$clean['login_whitelist_ips'] = '';
		}

		// 2FA Roles
		if ( isset( $input['two_factor_roles'] ) && is_array( $input['two_factor_roles'] ) ) {
			$clean['two_factor_roles'] = array_map( 'sanitize_key', $input['two_factor_roles'] );
		} else {
			$clean['two_factor_roles'] = array( 'administrator' );
		}

		return $clean;
	}
}
