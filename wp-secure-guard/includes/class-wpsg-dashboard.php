<?php
/**
 * Admin Dashboard and UI coordinator.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Dashboard
 */
class WPSG_Dashboard {

	/**
	 * Register hooks for admin UI and actions.
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'register_admin_menus' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_admin_assets' ) );
		add_action( 'admin_init', array( __CLASS__, 'handle_admin_actions' ) );
	}

	/**
	 * Register top-level and submenu pages.
	 */
	public static function register_admin_menus() {
		$cap = 'manage_options';

		// Top level
		add_menu_page(
			__( 'WP Secure Guard', 'wp-secure-guard' ),
			__( 'WP Secure Guard', 'wp-secure-guard' ),
			$cap,
			'wpsg-dashboard',
			array( __CLASS__, 'render_page' ),
			'dashicons-shield',
			80
		);

		// Submenus
		add_submenu_page(
			'wpsg-dashboard',
			__( 'Security Overview', 'wp-secure-guard' ),
			__( 'Dashboard', 'wp-secure-guard' ),
			$cap,
			'wpsg-dashboard',
			array( __CLASS__, 'render_page' )
		);

		add_submenu_page(
			'wpsg-dashboard',
			__( 'User Protection', 'wp-secure-guard' ),
			__( 'User Protection', 'wp-secure-guard' ),
			$cap,
			'wpsg-user-security',
			array( __CLASS__, 'render_page' )
		);

		add_submenu_page(
			'wpsg-dashboard',
			__( 'Login Security', 'wp-secure-guard' ),
			__( 'Login Security', 'wp-secure-guard' ),
			$cap,
			'wpsg-login-security',
			array( __CLASS__, 'render_page' )
		);

		add_submenu_page(
			'wpsg-dashboard',
			__( 'File & Server Security', 'wp-secure-guard' ),
			__( 'File Security', 'wp-secure-guard' ),
			$cap,
			'wpsg-file-security',
			array( __CLASS__, 'render_page' )
		);

		add_submenu_page(
			'wpsg-dashboard',
			__( 'Threat Monitoring & WAF', 'wp-secure-guard' ),
			__( 'Threat Monitoring', 'wp-secure-guard' ),
			$cap,
			'wpsg-monitoring',
			array( __CLASS__, 'render_page' )
		);

		add_submenu_page(
			'wpsg-dashboard',
			__( 'Activity Logs', 'wp-secure-guard' ),
			__( 'Activity Logs', 'wp-secure-guard' ),
			$cap,
			'wpsg-activity-logs',
			array( __CLASS__, 'render_page' )
		);

		add_submenu_page(
			'wpsg-dashboard',
			__( 'Settings & Tools', 'wp-secure-guard' ),
			__( 'Settings & Tools', 'wp-secure-guard' ),
			$cap,
			'wpsg-settings',
			array( __CLASS__, 'render_page' )
		);
	}

	/**
	 * Enqueue admin styles and scripts on plugin pages.
	 *
	 * @param string $hook Page hook suffix.
	 */
	public static function enqueue_admin_assets( $hook ) {
		if ( false === strpos( $hook, 'wpsg' ) ) {
			return;
		}

		wp_enqueue_style(
			'wpsg-admin-css',
			WPSG_PLUGIN_URL . 'admin/css/wpsg-admin.css',
			array(),
			WPSG_VERSION
		);

		wp_enqueue_script(
			'wpsg-admin-js',
			WPSG_PLUGIN_URL . 'admin/js/wpsg-admin.js',
			array( 'jquery' ),
			WPSG_VERSION,
			true
		);

		wp_localize_script(
			'wpsg-admin-js',
			'wpsgAdmin',
			array(
				'ajaxUrl'   => admin_url( 'admin-ajax.php' ),
				'nonce'     => wp_create_nonce( 'wpsg_admin_ajax_nonce' ),
				'copiedMsg' => __( 'Copied to clipboard!', 'wp-secure-guard' ),
			)
		);
	}

	/**
	 * Handle admin form submissions (save, reset, clear logs, export logs).
	 */
	public static function handle_admin_actions() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		// 1. Save Settings
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['wpsg_save_settings'] ) ) {
			check_admin_referer( 'wpsg_save_settings_action', 'wpsg_save_nonce' );

			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$raw_input = isset( $_POST['wpsg'] ) ? (array) wp_unslash( $_POST['wpsg'] ) : array();
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$tab       = isset( $_POST['wpsg_tab'] ) ? sanitize_key( wp_unslash( $_POST['wpsg_tab'] ) ) : '';
			WPSG_Settings::update_settings( $raw_input, $tab );

			WPSG_Logger::log(
				'settings_updated',
				__( 'WP Secure Guard settings were updated by administrator.', 'wp-secure-guard' ),
				'info'
			);

			$redirect = add_query_arg( array( 'wpsg_notice' => 'saved' ), wp_get_referer() );
			wp_safe_redirect( $redirect );
			exit;
		}

		// 2. Reset Settings to Safe Defaults
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['wpsg_reset_defaults'] ) ) {
			check_admin_referer( 'wpsg_reset_defaults_action', 'wpsg_reset_nonce' );

			WPSG_Settings::reset_to_defaults();

			WPSG_Logger::log(
				'settings_reset',
				__( 'WP Secure Guard settings were rolled back to safe defaults.', 'wp-secure-guard' ),
				'warning'
			);

			$redirect = add_query_arg( array( 'wpsg_notice' => 'reset' ), wp_get_referer() );
			wp_safe_redirect( $redirect );
			exit;
		}

		// 3. Clear Activity Logs
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST['wpsg_clear_logs'] ) ) {
			check_admin_referer( 'wpsg_clear_logs_action', 'wpsg_clear_logs_nonce' );

			WPSG_Logger::clear_logs();

			$redirect = add_query_arg( array( 'wpsg_notice' => 'logs_cleared' ), wp_get_referer() );
			wp_safe_redirect( $redirect );
			exit;
		}

		// 4. Export Activity Logs CSV
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['action'] ) && 'wpsg_export_logs_csv' === $_GET['action'] ) {
			check_admin_referer( 'wpsg_export_logs_csv_nonce' );

			self::stream_logs_csv();
			exit;
		}
	}

	/**
	 * Stream logs as downloadable CSV file.
	 */
	public static function stream_logs_csv() {
		$filename = 'wpsg-activity-logs-' . gmdate( 'Y-m-d-His' ) . '.csv';

		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename=' . $filename );
		header( 'Pragma: no-cache' );
		header( 'Expires: 0' );

		$output = fopen( 'php://output', 'w' );
		fputcsv( $output, array( 'ID', 'Date/Time (UTC)', 'Event Type', 'Severity', 'Message', 'IP Address', 'User ID', 'Username', 'Request URI' ) );

		$logs = WPSG_Logger::get_logs( array( 'per_page' => 5000, 'offset' => 0 ) );
		foreach ( $logs as $row ) {
			fputcsv(
				$output,
				array(
					$row->id,
					$row->created_at,
					$row->event_type,
					$row->severity,
					$row->message,
					$row->ip_address,
					$row->user_id,
					$row->username,
					$row->request_uri,
				)
			);
		}

		fclose( $output ); // phpcs:ignore WordPress.WP.AlternativeFileSystem.file_system_read_fclose
	}

	/**
	 * Gather comprehensive audit status across all 20 security features.
	 *
	 * @return array
	 */
	public static function get_security_audit_summary() {
		$modules = array(
			// Category 1: User Protection
			WPSG_Author_Enumeration::get_status(),
			WPSG_REST_API_Protection::get_status(),
			WPSG_oEmbed_Protection::get_status(),
			WPSG_Author_Sitemap::get_status(),
			WPSG_Author_Archives::get_status(),

			// Category 2: Login Security
			WPSG_Login_Limiter::get_status(),
			WPSG_Two_Factor::get_status(),
			WPSG_XMLRPC_Protection::get_status(),
			WPSG_Common_Usernames::get_status(),
			WPSG_Password_Policy::get_status(),
			WPSG_Custom_Login_URL::get_status(),
			WPSG_User_Registration::get_status(),

			// Category 3: File Security
			WPSG_File_Editor::get_status(),
			WPSG_Uploads_Protection::get_status(),
			WPSG_Sensitive_Files::get_status(),
			WPSG_Directory_Listing::get_status(),
			WPSG_Permissions_Audit::get_status(),

			// Category 4: Monitoring & Hardening
			WPSG_WAF::get_status(),
			WPSG_Update_Checker::get_status(),
			WPSG_PHP_Hardening::get_status(),
			WPSG_Activity_Logs::get_status(),
			WPSG_Backup_Checker::get_status(),
			WPSG_Version_Hider::get_status(),
			WPSG_Server_Info_Hider::get_status(),
		);

		$total    = count( $modules );
		$passed   = 0;
		$warning  = 0;
		$critical = 0;
		$disabled = 0;

		foreach ( $modules as $item ) {
			if ( empty( $item['enabled'] ) && 'passed' !== $item['status'] ) {
				$disabled++;
			} elseif ( 'critical' === $item['status'] ) {
				$critical++;
			} elseif ( 'warning' === $item['status'] ) {
				$warning++;
			} elseif ( 'passed' === $item['status'] ) {
				$passed++;
			}
		}

		// Calculate health score (0 - 100%)
		$score = ( $total > 0 ) ? (int) round( ( $passed / $total ) * 100 ) : 0;

		return array(
			'total'    => $total,
			'passed'   => $passed,
			'warning'  => $warning,
			'critical' => $critical,
			'disabled' => $disabled,
			'score'    => $score,
			'modules'  => $modules,
		);
	}

	/**
	 * Route and render requested admin page.
	 */
	public static function render_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : 'wpsg-dashboard';
		$settings = WPSG_Settings::get_settings();

		// Render admin header with tabs
		include WPSG_PLUGIN_DIR . 'admin/views/header.php';

		switch ( $page ) {
			case 'wpsg-user-security':
				include WPSG_PLUGIN_DIR . 'admin/views/user-security.php';
				break;
			case 'wpsg-login-security':
				include WPSG_PLUGIN_DIR . 'admin/views/login-security.php';
				break;
			case 'wpsg-file-security':
				include WPSG_PLUGIN_DIR . 'admin/views/file-security.php';
				break;
			case 'wpsg-monitoring':
				include WPSG_PLUGIN_DIR . 'admin/views/monitoring.php';
				break;
			case 'wpsg-activity-logs':
				include WPSG_PLUGIN_DIR . 'admin/views/activity-logs.php';
				break;
			case 'wpsg-settings':
				include WPSG_PLUGIN_DIR . 'admin/views/settings.php';
				break;
			case 'wpsg-dashboard':
			default:
				$audit = self::get_security_audit_summary();
				include WPSG_PLUGIN_DIR . 'admin/views/dashboard.php';
				break;
		}

		include WPSG_PLUGIN_DIR . 'admin/views/footer.php';
	}
}
