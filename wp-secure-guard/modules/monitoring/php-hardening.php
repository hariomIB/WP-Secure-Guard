<?php
/**
 * Module: PHP Environment Hardening Audit.
 *
 * Inspects PHP runtime directives for security best practices and configurations,
 * and provides actionable remediation solutions.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_PHP_Hardening
 */
class WPSG_PHP_Hardening {

	/**
	 * Initialize runtime hardening hooks if enabled.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'php_hardening_audit', true ) ) {
			// Suppress frontend display_errors on production if WP_DEBUG is not actively enabled.
			if ( ( ! defined( 'WP_DEBUG' ) || ! WP_DEBUG ) && ! is_admin() ) {
				@ini_set( 'display_errors', '0' );
			}
		}
	}

	/**
	 * Get the active loaded php.ini file path.
	 *
	 * @return string
	 */
	public static function get_loaded_php_ini() {
		$ini = php_ini_loaded_file();
		return $ini ? $ini : __( 'Not detected (or managed by web server / Cloud hosting)', 'wp-secure-guard' );
	}

	/**
	 * Run full PHP configuration audit with actionable solutions.
	 *
	 * @return array
	 */
	public static function audit() {
		$checks = array();
		$loaded_ini = self::get_loaded_php_ini();

		// 1. expose_php
		$expose_php    = ini_get( 'expose_php' );
		$expose_is_off = empty( $expose_php ) || '0' === $expose_php || 'off' === strtolower( $expose_php );

		$checks['expose_php'] = array(
			'id'             => 'expose_php',
			'directive'      => 'expose_php',
			'current'        => $expose_is_off ? 'Off' : 'On',
			'recommended'    => 'Off',
			'status'         => $expose_is_off ? 'passed' : 'warning',
			'description'    => __( 'When "On", PHP sends "X-Powered-By: PHP/x.x" in every HTTP response header, revealing your exact PHP version to attackers.', 'wp-secure-guard' ),
			'solution_title' => __( 'How to Disable expose_php', 'wp-secure-guard' ),
			'loaded_ini'     => $loaded_ini,
			'steps'          => array(
				__( 'Option A (php.ini - Recommended for WAMP / VPS / Dedicated): Open your php.ini file, search for "expose_php = On", change it to "expose_php = Off", and restart your web server (in WAMP: Left-click WAMP icon > Restart All Services).', 'wp-secure-guard' ),
				__( 'Option B (.user.ini - For cPanel / FastCGI / PHP-FPM): Place "expose_php = Off" in a .user.ini file in your WordPress root directory.', 'wp-secure-guard' ),
				__( 'Option C (.htaccess - For Apache with mod_php): Add the snippet below to your root .htaccess file.', 'wp-secure-guard' ),
			),
			'code_snippets'  => array(
				array(
					'label' => 'php.ini',
					'code'  => "expose_php = Off",
				),
				array(
					'label' => '.htaccess (Apache)',
					'code'  => "<IfModule mod_php.c>\n    php_flag expose_php Off\n</IfModule>",
				),
				array(
					'label' => '.user.ini',
					'code'  => "expose_php = Off",
				),
			),
		);

		// 2. display_errors
		$display_errors = ini_get( 'display_errors' );
		$display_is_off = empty( $display_errors ) || '0' === $display_errors || 'off' === strtolower( $display_errors );

		$checks['display_errors'] = array(
			'id'             => 'display_errors',
			'directive'      => 'display_errors',
			'current'        => $display_is_off ? 'Off' : 'On',
			'recommended'    => 'Off',
			'status'         => $display_is_off ? 'passed' : 'warning',
			'description'    => __( 'When "On", raw PHP errors, fatal warnings, and database stack traces are printed on public web pages, exposing filesystem paths and sensitive information.', 'wp-secure-guard' ),
			'solution_title' => __( 'How to Disable display_errors', 'wp-secure-guard' ),
			'loaded_ini'     => $loaded_ini,
			'steps'          => array(
				__( 'Option A (wp-config.php - Fastest for WordPress): Add the debugging suppression code to your wp-config.php file before the "/* That\'s all, stop editing! */" line.', 'wp-secure-guard' ),
				__( 'Option B (php.ini): Search for "display_errors = On" in your php.ini, change to "display_errors = Off", and restart Apache/web server.', 'wp-secure-guard' ),
				__( 'Option C (.htaccess): Add the php_flag directive into your root .htaccess file.', 'wp-secure-guard' ),
			),
			'code_snippets'  => array(
				array(
					'label' => 'wp-config.php',
					'code'  => "define( 'WP_DEBUG', false );\ndefine( 'WP_DEBUG_DISPLAY', false );\n@ini_set( 'display_errors', '0' );",
				),
				array(
					'label' => 'php.ini',
					'code'  => "display_errors = Off\ndisplay_startup_errors = Off\nlog_errors = On",
				),
				array(
					'label' => '.htaccess',
					'code'  => "<IfModule mod_php.c>\n    php_flag display_errors Off\n</IfModule>",
				),
			),
		);

		// 3. disable_functions
		$disabled_functions = array_map( 'trim', explode( ',', (string) ini_get( 'disable_functions' ) ) );
		$dangerous = array( 'exec', 'shell_exec', 'system', 'passthru', 'proc_open' );
		$disabled_count = 0;
		foreach ( $dangerous as $fn ) {
			if ( in_array( $fn, $disabled_functions, true ) ) {
				$disabled_count++;
			}
		}

		$checks['disable_functions'] = array(
			'id'             => 'disable_functions',
			'directive'      => 'disable_functions',
			'current'        => sprintf( __( '%d/%d dangerous shell functions disabled', 'wp-secure-guard' ), $disabled_count, count( $dangerous ) ),
			'recommended'    => __( 'Shell execution disabled in shared environments', 'wp-secure-guard' ),
			'status'         => $disabled_count > 0 ? 'passed' : 'info',
			'description'    => __( 'Allowing functions like exec, shell_exec, and system enables attackers with compromised accounts or malicious plugins to execute arbitrary server shell commands.', 'wp-secure-guard' ),
			'solution_title' => __( 'How to Restrict Dangerous Shell Functions', 'wp-secure-guard' ),
			'loaded_ini'     => $loaded_ini,
			'steps'          => array(
				__( 'Open your php.ini file and find the "disable_functions =" directive.', 'wp-secure-guard' ),
				__( 'Append the recommended list of dangerous functions, save the file, and restart your web server / WAMP services.', 'wp-secure-guard' ),
				__( 'Note: If a specific plugin on your site requires shell execution (e.g. video transcoders or WP-CLI), omit that specific function from the list.', 'wp-secure-guard' ),
			),
			'code_snippets'  => array(
				array(
					'label' => 'php.ini',
					'code'  => "disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec,parse_ini_file,show_source",
				),
			),
		);

		// 4. allow_url_include
		$allow_url_include = ini_get( 'allow_url_include' );
		$url_inc_is_off    = empty( $allow_url_include ) || '0' === $allow_url_include || 'off' === strtolower( $allow_url_include );

		$checks['allow_url_include'] = array(
			'id'             => 'allow_url_include',
			'directive'      => 'allow_url_include',
			'current'        => $url_inc_is_off ? 'Off' : 'On',
			'recommended'    => 'Off',
			'status'         => $url_inc_is_off ? 'passed' : 'critical',
			'description'    => __( 'When "On", PHP allows remote URLs to be loaded inside include/require statements, making Remote File Inclusion (RFI) attacks possible.', 'wp-secure-guard' ),
			'solution_title' => __( 'How to Disable allow_url_include', 'wp-secure-guard' ),
			'loaded_ini'     => $loaded_ini,
			'steps'          => array(
				__( 'Open your php.ini file, search for "allow_url_include = On", and change it to "allow_url_include = Off".', 'wp-secure-guard' ),
				__( 'In cPanel: Navigate to "MultiPHP INI Editor" > Select your domain > Switch allow_url_include to Disabled.', 'wp-secure-guard' ),
			),
			'code_snippets'  => array(
				array(
					'label' => 'php.ini',
					'code'  => "allow_url_include = Off",
				),
			),
		);

		// 5. PHP Version Check
		$php_version   = phpversion();
		$version_is_ok = version_compare( $php_version, '8.0.0', '>=' );

		$checks['php_version'] = array(
			'id'             => 'php_version',
			'directive'      => 'PHP Version',
			'current'        => $php_version,
			'recommended'    => '>= 8.0 (8.1 or 8.2 Recommended)',
			'status'         => $version_is_ok ? 'passed' : 'warning',
			'description'    => $version_is_ok ? __( 'Running modern, supported PHP version with active security patches.', 'wp-secure-guard' ) : __( 'PHP version is end-of-life and lacks official security patches.', 'wp-secure-guard' ),
			'solution_title' => __( 'How to Upgrade PHP Version', 'wp-secure-guard' ),
			'loaded_ini'     => $loaded_ini,
			'steps'          => array(
				__( 'In WAMP: Left-click WAMP icon > PHP > Version > Select PHP 8.1 or 8.2.', 'wp-secure-guard' ),
				__( 'In cPanel / Cloud Hosting: Open "MultiPHP Manager" or "PHP Selector", select your domain, and switch to PHP 8.1 or 8.2.', 'wp-secure-guard' ),
			),
			'code_snippets'  => array(),
		);

		return $checks;
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'php_hardening_audit', true );
		$audit   = self::audit();

		$has_critical = false;
		$has_warning  = false;

		foreach ( $audit as $row ) {
			if ( 'critical' === $row['status'] ) {
				$has_critical = true;
			} elseif ( 'warning' === $row['status'] ) {
				$has_warning = true;
			}
		}

		if ( ! $enabled ) {
			$status = 'warning';
			$label  = __( 'Audit Disabled', 'wp-secure-guard' );
		} elseif ( $has_critical ) {
			$status = 'critical';
			$label  = __( 'Critical PHP Directives Exposed', 'wp-secure-guard' );
		} elseif ( $has_warning ) {
			$status = 'warning';
			$label  = __( 'PHP Hardening Recommended', 'wp-secure-guard' );
		} else {
			$status = 'passed';
			$label  = __( 'PHP Configuration Hardened', 'wp-secure-guard' );
		}

		return array(
			'id'          => 'php_hardening',
			'title'       => __( 'PHP Runtime Hardening', 'wp-secure-guard' ),
			'category'    => 'monitoring',
			'enabled'     => $enabled,
			'status'      => $status,
			'label'       => $label,
			'details'     => $audit,
			'description' => __( 'Evaluates PHP security directives including expose_php, display_errors, and allow_url_include with step-by-step remediation.', 'wp-secure-guard' ),
		);
	}
}
