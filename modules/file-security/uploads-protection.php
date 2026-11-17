<?php
/**
 * Module: Uploads Directory PHP Execution Protection & Malicious File Upload Shield.
 *
 * Prevents execution of PHP and script files inside /wp-content/uploads/
 * and inspects incoming uploads to block malicious PHP/executable scripts from being uploaded.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Uploads_Protection
 */
class WPSG_Uploads_Protection {

	/**
	 * Marker comment for .htaccess rules.
	 */
	const HTACCESS_MARKER = 'WP Secure Guard - Uploads PHP Shield';

	/**
	 * Initialize module.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'uploads_php_protect', true ) ) {
			add_action( 'admin_init', array( __CLASS__, 'ensure_htaccess_exists' ) );
			add_filter( 'wp_handle_upload_prefilter', array( __CLASS__, 'inspect_uploaded_file' ) );
			add_filter( 'upload_mimes', array( __CLASS__, 'filter_upload_mimes' ) );
		}
	}

	/**
	 * Inspect uploaded files before they are saved to disk.
	 * Blocks dangerous extensions, double extensions, and hidden PHP opening tags.
	 *
	 * @param array $file Upload file data array.
	 * @return array
	 */
	public static function inspect_uploaded_file( $file ) {
		if ( ! empty( $file['error'] ) ) {
			return $file;
		}

		$filename = isset( $file['name'] ) ? strtolower( sanitize_file_name( $file['name'] ) ) : '';
		$tmp_name = isset( $file['tmp_name'] ) ? $file['tmp_name'] : '';

		// 1. Blacklisted dangerous extensions.
		$dangerous_extensions = array(
			'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phps',
			'phar', 'inc', 'sh', 'bash', 'cgi', 'pl', 'py', 'exe', 'bat',
			'cmd', 'vbs', 'msi', 'bin', 'dll', 'com', 'scr', 'hta', 'csh',
		);

		$ext = strtolower( pathinfo( $filename, PATHINFO_EXTENSION ) );

		if ( in_array( $ext, $dangerous_extensions, true ) ) {
			return self::reject_upload(
				$file,
				sprintf(
					/* translators: %s: file extension */
					__( 'Security Alert: Uploading .%s executable files is strictly forbidden.', 'wp-secure-guard' ),
					$ext
				),
				$filename
			);
		}

		// 2. Double-extension attack check (e.g. avatar.jpg.php or shell.php.png).
		$parts = explode( '.', $filename );
		if ( count( $parts ) > 2 ) {
			foreach ( $parts as $part ) {
				if ( in_array( strtolower( $part ), $dangerous_extensions, true ) ) {
					return self::reject_upload(
						$file,
						__( 'Security Alert: Double-extension executable mask detected.', 'wp-secure-guard' ),
						$filename
					);
				}
			}
		}

		// 3. Deep content inspection for embedded PHP opening tags (e.g. polyglot web shells in images).
		if ( ! empty( $tmp_name ) && file_exists( $tmp_name ) && is_readable( $tmp_name ) ) {
			// Read first 8KB of file.
			$handle = fopen( $tmp_name, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFileSystem.file_system_read_fopen
			if ( $handle ) {
				$chunk = fread( $handle, 8192 ); // phpcs:ignore WordPress.WP.AlternativeFileSystem.file_system_read_fread
				fclose( $handle ); // phpcs:ignore WordPress.WP.AlternativeFileSystem.file_system_read_fclose

				if ( false !== $chunk ) {
					$suspicious_patterns = array(
						'<\?php\b',
						'<\?=',
						'<script\s+language\s*=\s*["\']?php["\']?',
						'__halt_compiler\s*\(',
					);

					foreach ( $suspicious_patterns as $pattern ) {
						if ( preg_match( '/' . $pattern . '/i', $chunk ) ) {
							return self::reject_upload(
								$file,
								__( 'Security Alert: Embedded PHP script tags detected inside uploaded media file.', 'wp-secure-guard' ),
								$filename
							);
						}
					}
				}
			}
		}

		return $file;
	}

	/**
	 * Log malicious upload attempt and populate file error message.
	 *
	 * @param array  $file     File data array.
	 * @param string $reason   Reason for rejection.
	 * @param string $filename Name of attempted file.
	 * @return array
	 */
	private static function reject_upload( $file, $reason, $filename ) {
		$ip = WPSG_Logger::get_client_ip();

		WPSG_Logger::log(
			'malicious_upload_blocked',
			sprintf(
				/* translators: 1: filename, 2: reason, 3: IP address */
				__( 'Malicious file upload blocked: "%1$s" [%2$s] from IP %3$s.', 'wp-secure-guard' ),
				$filename,
				$reason,
				$ip
			),
			'danger',
			array( 'ip_address' => $ip )
		);

		$file['error'] = $reason;
		return $file;
	}

	/**
	 * Filter allowed MIME types to prevent executable or unsafe types.
	 *
	 * @param array $mimes Array of allowed MIME types.
	 * @return array
	 */
	public static function filter_upload_mimes( $mimes ) {
		unset( $mimes['exe'] );
		unset( $mimes['sh'] );
		unset( $mimes['bin'] );
		return $mimes;
	}

	/**
	 * Detect active web server environment.
	 *
	 * @return string 'apache', 'litespeed', 'nginx', 'iis', or 'other'.
	 */
	public static function get_server_type() {
		$server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';

		if ( strpos( $server, 'nginx' ) !== false ) {
			return 'nginx';
		} elseif ( strpos( $server, 'litespeed' ) !== false ) {
			return 'litespeed';
		} elseif ( strpos( $server, 'apache' ) !== false ) {
			return 'apache';
		} elseif ( strpos( $server, 'microsoft-iis' ) !== false ) {
			return 'iis';
		}

		return 'other';
	}

	/**
	 * Get the uploads directory path.
	 *
	 * @return string
	 */
	public static function get_uploads_path() {
		$upload_dir = wp_upload_dir();
		return trailingslashit( $upload_dir['basedir'] );
	}

	/**
	 * Get the path to .htaccess inside uploads folder.
	 *
	 * @return string
	 */
	public static function get_htaccess_file() {
		return self::get_uploads_path() . '.htaccess';
	}

	/**
	 * Check if .htaccess rules are present.
	 *
	 * @return bool
	 */
	public static function is_htaccess_installed() {
		$file = self::get_htaccess_file();
		if ( ! file_exists( $file ) || ! is_readable( $file ) ) {
			return false;
		}

		$content = file_get_contents( $file );
		return false !== strpos( $content, self::HTACCESS_MARKER );
	}

	/**
	 * Write protection rules into uploads/.htaccess for Apache / LiteSpeed servers.
	 *
	 * @return bool
	 */
	public static function install_htaccess() {
		$file = self::get_htaccess_file();

		$rules = array(
			'<FilesMatch "(?i)\.(php|phtml|php3|php4|php5|php7|phps|pl|py|cgi|sh|phar|inc)$">',
			'    <IfModule mod_authz_core.c>',
			'        Require all denied',
			'    </IfModule>',
			'    <IfModule !mod_authz_core.c>',
			'        Order deny,allow',
			'        Deny from all',
			'    </IfModule>',
			'</FilesMatch>',
		);

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';

		return insert_with_markers( $file, self::HTACCESS_MARKER, $rules );
	}

	/**
	 * Remove protection rules from uploads/.htaccess.
	 *
	 * @return bool
	 */
	public static function remove_htaccess() {
		$file = self::get_htaccess_file();
		if ( ! file_exists( $file ) ) {
			return true;
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';

		return insert_with_markers( $file, self::HTACCESS_MARKER, array() );
	}

	/**
	 * Check and ensure .htaccess rules are installed during admin sessions.
	 */
	public static function ensure_htaccess_exists() {
		$server = self::get_server_type();
		if ( in_array( $server, array( 'apache', 'litespeed' ), true ) ) {
			if ( ! self::is_htaccess_installed() && is_writable( self::get_uploads_path() ) ) {
				self::install_htaccess();
			}
		}
	}

	/**
	 * Get Nginx configuration snippet.
	 *
	 * @return string
	 */
	public static function get_nginx_snippet() {
		return "# WP Secure Guard - Block PHP Execution in Uploads\n" .
			"location ~* /wp-content/uploads/.*\\.(php|phtml|php3|php4|php5|php7|phps|phar|inc|sh|cgi|py)$ {\n" .
			"    deny all;\n" .
			"    return 403;\n" .
			"}";
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled     = (bool) WPSG_Settings::get( 'uploads_php_protect', true );
		$server      = self::get_server_type();
		$is_htaccess = self::is_htaccess_installed();

		if ( ! $enabled ) {
			$status = 'warning';
			$label  = __( 'Protection Disabled', 'wp-secure-guard' );
		} elseif ( in_array( $server, array( 'apache', 'litespeed' ), true ) ) {
			$status = $is_htaccess ? 'passed' : 'warning';
			$label  = $is_htaccess ? __( 'Execution & Uploads Shield Active', 'wp-secure-guard' ) : __( '.htaccess Needs Installation', 'wp-secure-guard' );
		} elseif ( 'nginx' === $server ) {
			$status = 'warning';
			$label  = __( 'Nginx Rule Required (Upload Filter Active)', 'wp-secure-guard' );
		} else {
			$status = 'passed';
			$label  = __( 'Uploads Shield Active', 'wp-secure-guard' );
		}

		return array(
			'id'          => 'uploads_php_protect',
			'title'       => __( 'Uploads PHP & Malicious File Shield', 'wp-secure-guard' ),
			'category'    => 'file_security',
			'enabled'     => $enabled,
			'status'      => $status,
			'label'       => $label,
			'server_type' => $server,
			'description' => __( 'Blocks execution of PHP scripts in uploads and actively inspects uploads to reject executable scripts and embedded web shells.', 'wp-secure-guard' ),
		);
	}
}
