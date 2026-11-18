<?php
/**
 * Module: Sensitive Files Protection & Information Disclosure Shield.
 *
 * Prevents unauthorized web access to wp-config.php, readme.html, license.txt,
 * composer.json, composer.lock, package.json, .env, .git, debug.log, database dumps, and backups.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Sensitive_Files
 */
class WPSG_Sensitive_Files {

	/**
	 * Marker comment for root .htaccess rules.
	 */
	const HTACCESS_MARKER = 'WP Secure Guard - Sensitive Files Shield';

	/**
	 * Initialize hooks.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'sensitive_files_protect', true ) ) {
			add_action( 'init', array( __CLASS__, 'block_sensitive_file_requests' ), 1 );
			add_action( 'admin_init', array( __CLASS__, 'ensure_htaccess_rules' ) );
		}
	}

	/**
	 * Inspect request URI and abort if requesting known sensitive files.
	 */
	public static function block_sensitive_file_requests() {
		if ( ! isset( $_SERVER['REQUEST_URI'] ) ) {
			return;
		}

		$uri  = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) );
		$path = trim( (string) wp_parse_url( $uri, PHP_URL_PATH ), '/' );
		$file = strtolower( basename( $path ) );

		$blocked_patterns = array(
			// Git and VCS repositories
			'#(^|/)\.(git|svn|hg|bzr)($|/)#i',
			// Environment and local configs
			'#(^|/)\.env(\..+)?$#i',
			'#(^|/)\.(user\.ini|htaccess|htpasswd)$#i',
			'#(^|/)php\.ini$#i',
			// Readme, license, changelog information disclosure files
			'#^(readme|license|licence|changelog|changes)(\.(html|txt|md))?$#i',
			// Dependency manifests & package managers
			'#^(composer\.(json|lock)|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|bower\.json)$#i',
			// Docker configs
			'#^(dockerfile|docker-compose(\.override)?\.(yml|yaml))$#i',
			// WordPress configuration and backup variants
			'#^wp-config(-sample)?(\.php)?(\.(bak|backup|old|save|txt|orig|temp|tmp|swp|swo))?$#i',
			// Logs, SQL dumps, shell scripts, archive backups
			'#\.(sql|sql\.gz|bak|backup|old|save|log|ini|conf|sh|bash|ps1|swp|swo|tar|gz|zip|7z|rar)$#i',
			// Direct access to theme directories or direct PHP file execution in themes/plugins (prevents 500 fatal errors)
			'#^wp-content/themes/[^/]+/?$#i',
			'#^wp-content/(themes|plugins)/.*\.php$#i',
		);

		foreach ( $blocked_patterns as $pattern ) {
			if ( preg_match( $pattern, $path ) || preg_match( $pattern, $file ) ) {
				$ip = WPSG_Logger::get_client_ip();

				WPSG_Logger::log(
					'sensitive_file_blocked',
					sprintf(
						/* translators: 1: requested uri, 2: IP address */
						__( 'Sensitive file request "%1$s" blocked from IP %2$s (403 Forbidden).', 'wp-secure-guard' ),
						$uri,
						$ip
					),
					'danger',
					array( 'ip_address' => $ip, 'request_uri' => $uri )
				);

				status_header( 403 );
				nocache_headers();
				wp_die(
					esc_html__( 'Access to this file is restricted for security reasons.', 'wp-secure-guard' ),
					esc_html__( '403 Forbidden', 'wp-secure-guard' ),
					array( 'response' => 403 )
				);
			}
		}
	}

	/**
	 * Ensure root .htaccess contains sensitive file blocks on Apache/LiteSpeed.
	 */
	public static function ensure_htaccess_rules() {
		$server = WPSG_Uploads_Protection::get_server_type();
		if ( ! in_array( $server, array( 'apache', 'litespeed' ), true ) ) {
			return;
		}

		$root_htaccess = get_home_path() . '.htaccess';
		if ( ! file_exists( $root_htaccess ) || ! is_writable( $root_htaccess ) ) {
			return;
		}

		$content = file_get_contents( $root_htaccess );
		// If marker missing or old rules don't contain themes block rule, reinstall rules.
		if ( false === strpos( $content, self::HTACCESS_MARKER ) || false === strpos( $content, 'themes' ) ) {
			self::install_htaccess_rules();
		}
	}

	/**
	 * Install rules to root .htaccess.
	 *
	 * @return bool
	 */
	public static function install_htaccess_rules() {
		$root_htaccess = get_home_path() . '.htaccess';

		$rules = array(
			'# 1. Protect wp-config.php and wp-config backups/samples',
			'<FilesMatch "(?i)^wp-config(-sample)?(\.php)?(\.(bak|backup|old|save|txt|orig|temp|tmp|swp|swo))?$">',
			'    <IfModule mod_authz_core.c>',
			'        Require all denied',
			'    </IfModule>',
			'    <IfModule !mod_authz_core.c>',
			'        Order deny,allow',
			'        Deny from all',
			'    </IfModule>',
			'</FilesMatch>',
			'',
			'# 2. Block information disclosure files: readme, license, changelog',
			'<FilesMatch "(?i)^(readme|license|licence|changelog|changes)(\.(html|txt|md))?$">',
			'    <IfModule mod_authz_core.c>',
			'        Require all denied',
			'    </IfModule>',
			'    <IfModule !mod_authz_core.c>',
			'        Order deny,allow',
			'        Deny from all',
			'    </IfModule>',
			'</FilesMatch>',
			'',
			'# 3. Block developer manifests, dependency files, lockfiles, and container configs',
			'<FilesMatch "(?i)^(composer\.(json|lock)|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|bower\.json|Dockerfile|docker-compose(\.override)?\.(yml|yaml))$">',
			'    <IfModule mod_authz_core.c>',
			'        Require all denied',
			'    </IfModule>',
			'    <IfModule !mod_authz_core.c>',
			'        Order deny,allow',
			'        Deny from all',
			'    </IfModule>',
			'</FilesMatch>',
			'',
			'# 4. Block dotfiles (.env, .git), server configs (php.ini, .user.ini), logs, and database dumps',
			'<FilesMatch "(?i)(^\.env(\..+)?|^\.user\.ini|^php\.ini|\.(bak|backup|old|save|conf|dist|fla|in[ci]|log|psd|sh|sql|sw[op]|yml|yaml|tar|gz|zip|7z|rar))$">',
			'    <IfModule mod_authz_core.c>',
			'        Require all denied',
			'    </IfModule>',
			'    <IfModule !mod_authz_core.c>',
			'        Order deny,allow',
			'        Deny from all',
			'    </IfModule>',
			'</FilesMatch>',
			'',
			'# 5. Block direct HTTP execution of PHP files in themes & plugins (prevents 500 fatal errors)',
			'<IfModule mod_rewrite.c>',
			'    RewriteEngine On',
			'    RewriteCond %{REQUEST_URI} !/wp-admin/admin-ajax\.php [NC]',
			'    RewriteCond %{REQUEST_URI} !/wp-admin/ [NC]',
			'    RewriteCond %{REQUEST_URI} ^.*/wp-content/(themes|plugins)/.*\.php$ [NC]',
			'    RewriteRule .* - [F,L]',
			'</IfModule>',
		);

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';

		return insert_with_markers( $root_htaccess, self::HTACCESS_MARKER, $rules );
	}

	/**
	 * Remove sensitive file rules from root .htaccess.
	 *
	 * @return bool
	 */
	public static function remove_htaccess_rules() {
		$root_htaccess = get_home_path() . '.htaccess';
		if ( ! file_exists( $root_htaccess ) ) {
			return true;
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';

		return insert_with_markers( $root_htaccess, self::HTACCESS_MARKER, array() );
	}

	/**
	 * Check whether .htaccess rules are actively present in root .htaccess.
	 *
	 * @return bool
	 */
	public static function is_htaccess_installed() {
		$root_htaccess = get_home_path() . '.htaccess';
		if ( ! file_exists( $root_htaccess ) ) {
			return false;
		}
		$content = file_get_contents( $root_htaccess );
		return ( false !== strpos( $content, self::HTACCESS_MARKER ) );
	}

	/**
	 * Run a live audit check on common sensitive files in the root folder.
	 *
	 * @return array
	 */
	public static function audit_sensitive_files() {
		$home_path = get_home_path();
		$htaccess_active = self::is_htaccess_installed();

		$targets = array(
			array(
				'file'        => 'readme.html',
				'label'       => 'WordPress Readme (readme.html)',
				'risk'        => __( 'Reveals exact WordPress core version and installation guide.', 'wp-secure-guard' ),
				'threat'      => 'info_disclosure',
			),
			array(
				'file'        => 'license.txt',
				'label'       => 'License File (license.txt)',
				'risk'        => __( 'Used by automated fingerprinters to verify WordPress CMS presence.', 'wp-secure-guard' ),
				'threat'      => 'info_disclosure',
			),
			array(
				'file'        => 'composer.json',
				'label'       => 'Composer Manifest (composer.json)',
				'risk'        => __( 'Exposes PHP dependencies, internal packages, and exact version numbers.', 'wp-secure-guard' ),
				'threat'      => 'dependency_exposure',
			),
			array(
				'file'        => 'composer.lock',
				'label'       => 'Composer Lockfile (composer.lock)',
				'risk'        => __( 'Exposes locked hashes and dependencies with known CVEs.', 'wp-secure-guard' ),
				'threat'      => 'dependency_exposure',
			),
			array(
				'file'        => 'package.json',
				'label'       => 'Node/NPM Manifest (package.json)',
				'risk'        => __( 'Exposes frontend build libraries, dev tools, and script names.', 'wp-secure-guard' ),
				'threat'      => 'dependency_exposure',
			),
			array(
				'file'        => '.env',
				'label'       => 'Environment File (.env)',
				'risk'        => __( 'CRITICAL: May contain database passwords, API keys, and secret tokens.', 'wp-secure-guard' ),
				'threat'      => 'secret_leak',
			),
			array(
				'file'        => 'wp-config.php.bak',
				'label'       => 'Config Backup (wp-config.php.bak)',
				'risk'        => __( 'CRITICAL: May serve database credentials as plain text if accessed.', 'wp-secure-guard' ),
				'threat'      => 'credential_leak',
			),
			array(
				'file'        => 'wp-config.php.old',
				'label'       => 'Old Config (wp-config.php.old)',
				'risk'        => __( 'CRITICAL: Plain text backup of WordPress database credentials.', 'wp-secure-guard' ),
				'threat'      => 'credential_leak',
			),
			array(
				'file'        => 'debug.log',
				'label'       => 'WordPress Debug Log (debug.log)',
				'risk'        => __( 'Exposes PHP fatal errors, database queries, and sensitive system stack traces.', 'wp-secure-guard' ),
				'threat'      => 'info_disclosure',
			),
			array(
				'file'        => '.htaccess',
				'label'       => 'Server Rules (.htaccess)',
				'risk'        => __( 'Server routing and security directives.', 'wp-secure-guard' ),
				'threat'      => 'server_config',
			),
		);

		$results = array();

		foreach ( $targets as $item ) {
			$file_path    = $home_path . $item['file'];
			$exists       = file_exists( $file_path );
			$is_protected = $htaccess_active || ! $exists;

			if ( ! $exists ) {
				$status = 'passed';
				$badge  = __( 'Not Present on Disk (Safe)', 'wp-secure-guard' );
			} elseif ( $htaccess_active ) {
				$status = 'passed';
				$badge  = __( 'Protected by .htaccess (HTTP 403 Forbidden)', 'wp-secure-guard' );
			} else {
				$status = 'warning';
				$badge  = __( 'Exposed (HTTP 200) - Needs Protection', 'wp-secure-guard' );
			}

			$results[] = array(
				'file'         => $item['file'],
				'label'        => $item['label'],
				'exists'       => $exists,
				'is_protected' => $is_protected,
				'status'       => $status,
				'badge'        => $badge,
				'risk'         => $item['risk'],
			);
		}

		return $results;
	}

	/**
	 * Get Nginx configuration snippet for sensitive files.
	 *
	 * @return string
	 */
	public static function get_nginx_snippet() {
		return "# WP Secure Guard - Protect Sensitive Files & Information Disclosure\n" .
			"location ~* /(wp-config.*|readme.*|license.*|licence.*|composer\\.(json|lock)|package.*\\.json|yarn\\.lock|\\.env.*|\\.git.*|.*\\.sql|.*\\.log|php\\.ini|\\.user\\.ini)$ {\n" .
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
		$enabled         = (bool) WPSG_Settings::get( 'sensitive_files_protect', true );
		$htaccess_active = self::is_htaccess_installed();

		return array(
			'id'          => 'sensitive_files',
			'title'       => __( 'Sensitive Files Shield', 'wp-secure-guard' ),
			'category'    => 'file_security',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $enabled ? ( $htaccess_active ? __( 'Protected (403 Shield Active)', 'wp-secure-guard' ) : __( 'Protected (PHP Filter Active)', 'wp-secure-guard' ) ) : __( 'Unprotected', 'wp-secure-guard' ),
			'description' => __( 'Shields readme.html, license.txt, composer.json, wp-config backups, .env files, debug.log, and database dumps (.sql) from public exposure.', 'wp-secure-guard' ),
		);
	}
}
