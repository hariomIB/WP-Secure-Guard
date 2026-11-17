<?php
/**
 * Plugin Name:       WP Secure Guard
 * Plugin URI:        https://wordpress.org/plugins/wp-secure-guard/
 * Description:       Advanced modular WordPress security suite featuring User Enumeration Protection, Brute-Force Rate Limiting, Custom Login URL, Native TOTP 2FA, XML-RPC Shield, WAF Firewall, Sensitive File Protection, and Activity Logs.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            WP Secure Guard Team
 * Author URI:        https://wordpress.org/plugins/wp-secure-guard/
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-secure-guard
 * Domain Path:       /languages
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Plugin constants.
$wpsg_main_file = defined( 'WPSG_ROOT_FILE' ) ? WPSG_ROOT_FILE : __FILE__;

if ( ! defined( 'WPSG_VERSION' ) ) {
	define( 'WPSG_VERSION', '1.0.0' );
}
if ( ! defined( 'WPSG_PLUGIN_FILE' ) ) {
	define( 'WPSG_PLUGIN_FILE', $wpsg_main_file );
}
if ( ! defined( 'WPSG_PLUGIN_DIR' ) ) {
	define( 'WPSG_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
}
if ( ! defined( 'WPSG_PLUGIN_URL' ) ) {
	define( 'WPSG_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
}
if ( ! defined( 'WPSG_PLUGIN_BASENAME' ) ) {
	define( 'WPSG_PLUGIN_BASENAME', plugin_basename( $wpsg_main_file ) );
}

// 1. Core Framework Includes.
require_once WPSG_PLUGIN_DIR . 'includes/class-wpsg-loader.php';
require_once WPSG_PLUGIN_DIR . 'includes/class-wpsg-activator.php';
require_once WPSG_PLUGIN_DIR . 'includes/class-wpsg-deactivator.php';
require_once WPSG_PLUGIN_DIR . 'includes/class-wpsg-settings.php';
require_once WPSG_PLUGIN_DIR . 'includes/class-wpsg-logger.php';
require_once WPSG_PLUGIN_DIR . 'includes/class-wpsg-dashboard.php';
require_once WPSG_PLUGIN_DIR . 'includes/class-wpsg-updater.php';

// 2. User Protection Modules (Features 1-5).
require_once WPSG_PLUGIN_DIR . 'modules/user-enumeration/author-enumeration.php';
require_once WPSG_PLUGIN_DIR . 'modules/user-enumeration/rest-api.php';
require_once WPSG_PLUGIN_DIR . 'modules/user-enumeration/oembed.php';
require_once WPSG_PLUGIN_DIR . 'modules/user-enumeration/author-sitemap.php';
require_once WPSG_PLUGIN_DIR . 'modules/user-enumeration/author-archives.php';

// 3. Login Security Modules (Features 6-10 + Custom Login URL & Registration Control).
require_once WPSG_PLUGIN_DIR . 'modules/login-security/login-limiter.php';
require_once WPSG_PLUGIN_DIR . 'modules/login-security/two-factor.php';
require_once WPSG_PLUGIN_DIR . 'modules/login-security/xmlrpc.php';
require_once WPSG_PLUGIN_DIR . 'modules/login-security/common-usernames.php';
require_once WPSG_PLUGIN_DIR . 'modules/login-security/password-policy.php';
require_once WPSG_PLUGIN_DIR . 'modules/login-security/custom-login-url.php';
require_once WPSG_PLUGIN_DIR . 'modules/login-security/user-registration.php';

// 4. File & Server Security Modules (Features 11-15).
require_once WPSG_PLUGIN_DIR . 'modules/file-security/file-editor.php';
require_once WPSG_PLUGIN_DIR . 'modules/file-security/uploads-protection.php';
require_once WPSG_PLUGIN_DIR . 'modules/file-security/sensitive-files.php';
require_once WPSG_PLUGIN_DIR . 'modules/file-security/directory-listing.php';
require_once WPSG_PLUGIN_DIR . 'modules/file-security/permissions-audit.php';

// 5. Threat Monitoring Modules (Features 16-20 + Version & Server Info Hiding).
require_once WPSG_PLUGIN_DIR . 'modules/monitoring/waf-integration.php';
require_once WPSG_PLUGIN_DIR . 'modules/monitoring/update-checker.php';
require_once WPSG_PLUGIN_DIR . 'modules/monitoring/php-hardening.php';
require_once WPSG_PLUGIN_DIR . 'modules/monitoring/activity-logs.php';
require_once WPSG_PLUGIN_DIR . 'modules/monitoring/backup-checker.php';
require_once WPSG_PLUGIN_DIR . 'modules/monitoring/version-hider.php';
require_once WPSG_PLUGIN_DIR . 'modules/monitoring/server-info-hider.php';

/**
 * Register activation and deactivation hooks.
 */
register_activation_hook( $wpsg_main_file, array( 'WPSG_Activator', 'activate' ) );
register_deactivation_hook( $wpsg_main_file, array( 'WPSG_Deactivator', 'deactivate' ) );

/**
 * Class WP_Secure_Guard
 *
 * Core coordinator singleton.
 */
final class WP_Secure_Guard {

	/**
	 * Singleton instance.
	 *
	 * @var WP_Secure_Guard|null
	 */
	private static $instance = null;

	/**
	 * Hook loader instance.
	 *
	 * @var WPSG_Loader
	 */
	protected $loader;

	/**
	 * Get singleton instance.
	 *
	 * @return WP_Secure_Guard
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Constructor.
	 */
	private function __construct() {
		$this->loader = new WPSG_Loader();
		$this->load_dependencies();
		$this->init_modules();
	}

	/**
	 * Load translation files and base filters.
	 */
	private function load_dependencies() {
		add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );
		add_filter( 'plugin_action_links_' . WPSG_PLUGIN_BASENAME, array( $this, 'add_plugin_action_links' ) );
	}

	/**
	 * Load text domain for internationalization (i18n).
	 */
	public function load_textdomain() {
		load_plugin_textdomain(
			'wp-secure-guard',
			false,
			dirname( WPSG_PLUGIN_BASENAME ) . '/languages/'
		);
	}

	/**
	 * Initialize all modular security features.
	 */
	private function init_modules() {
		// Category 1: User Protection
		WPSG_Author_Enumeration::init();
		WPSG_REST_API_Protection::init();
		WPSG_oEmbed_Protection::init();
		WPSG_Author_Sitemap::init();
		WPSG_Author_Archives::init();

		// Category 2: Login Security
		WPSG_Login_Limiter::init();
		WPSG_Two_Factor::init();
		WPSG_XMLRPC_Protection::init();
		WPSG_Common_Usernames::init();
		WPSG_Password_Policy::init();
		WPSG_Custom_Login_URL::init();
		WPSG_User_Registration::init();

		// Category 3: File Security
		WPSG_File_Editor::init();
		WPSG_Uploads_Protection::init();
		WPSG_Sensitive_Files::init();
		WPSG_Directory_Listing::init();

		// Category 4: Threat Monitoring & Hardening
		WPSG_WAF::init();
		WPSG_Activity_Logs::init();
		WPSG_PHP_Hardening::init();
		WPSG_Version_Hider::init();
		WPSG_Server_Info_Hider::init();

		// Remote Auto-Updater
		WPSG_Updater::init();

		// Admin UI coordinator
		if ( is_admin() ) {
			WPSG_Dashboard::init();
		}

		$this->loader->run();
	}

	/**
	 * Add quick settings links directly in the WordPress Plugins table.
	 *
	 * @param array $links Array of action links.
	 * @return array
	 */
	public function add_plugin_action_links( $links ) {
		$custom_links = array(
			'<a href="' . esc_url( admin_url( 'admin.php?page=wpsg-dashboard' ) ) . '">' . esc_html__( 'Security Dashboard', 'wp-secure-guard' ) . '</a>',
			'<a href="' . esc_url( admin_url( 'admin.php?page=wpsg-login-security' ) ) . '">' . esc_html__( 'Login Security', 'wp-secure-guard' ) . '</a>',
		);
		return array_merge( $custom_links, $links );
	}
}

/**
 * Bootstrap the plugin.
 */
function wpsg() {
	return WP_Secure_Guard::instance();
}

// Launch plugin.
wpsg();
