<?php
/**
 * Admin Header and Navigation Tabs.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$current_page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : 'wpsg-dashboard';
// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$notice = isset( $_GET['wpsg_notice'] ) ? sanitize_key( wp_unslash( $_GET['wpsg_notice'] ) ) : '';

$nav_tabs = array(
	'wpsg-dashboard'      => array( 'title' => __( 'Security Dashboard', 'wp-secure-guard' ), 'icon' => 'dashicons-dashboard' ),
	'wpsg-user-security'  => array( 'title' => __( 'User Protection', 'wp-secure-guard' ), 'icon' => 'dashicons-admin-users' ),
	'wpsg-login-security' => array( 'title' => __( 'Login Security', 'wp-secure-guard' ), 'icon' => 'dashicons-lock' ),
	'wpsg-file-security'  => array( 'title' => __( 'File Security', 'wp-secure-guard' ), 'icon' => 'dashicons-media-document' ),
	'wpsg-monitoring'     => array( 'title' => __( 'Threat Monitoring & WAF', 'wp-secure-guard' ), 'icon' => 'dashicons-shield-alt' ),
	'wpsg-activity-logs'  => array( 'title' => __( 'Activity Logs', 'wp-secure-guard' ), 'icon' => 'dashicons-list-view' ),
	'wpsg-settings'       => array( 'title' => __( 'Settings & Tools', 'wp-secure-guard' ), 'icon' => 'dashicons-admin-settings' ),
);
?>

<div class="wrap wpsg-wrap">
	<div class="wpsg-top-banner">
		<div class="wpsg-brand">
			<span class="dashicons dashicons-shield wpsg-brand-icon"></span>
			<div>
				<h1 class="wpsg-brand-title"><?php esc_html_e( 'WP Secure Guard', 'wp-secure-guard' ); ?></h1>
				<span class="wpsg-version-badge">v<?php echo esc_html( WPSG_VERSION ); ?></span>
				<span class="wpsg-brand-tagline"><?php esc_html_e( 'Modular WordPress Security & Firewall Suite', 'wp-secure-guard' ); ?></span>
			</div>
		</div>
		<div class="wpsg-top-actions">
			<?php
			$check_updates_url = wp_nonce_url(
				add_query_arg( array( 'page' => $current_page, 'wpsg_action' => 'check_updates' ), admin_url( 'admin.php' ) ),
				'wpsg_manual_update_check'
			);
			?>
			<a href="<?php echo esc_url( $check_updates_url ); ?>" class="button button-secondary" title="<?php esc_attr_e( 'Check GitHub for WP Secure Guard Updates', 'wp-secure-guard' ); ?>">
				<span class="dashicons dashicons-update" style="vertical-align:text-bottom;margin-right:3px;"></span>
				<?php esc_html_e( 'Check for Updates', 'wp-secure-guard' ); ?>
			</a>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wpsg-activity-logs' ) ); ?>" class="button button-secondary">
				<span class="dashicons dashicons-visibility" style="vertical-align:text-bottom;margin-right:3px;"></span>
				<?php esc_html_e( 'View Activity Log', 'wp-secure-guard' ); ?>
			</a>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=wpsg-settings' ) ); ?>" class="button button-secondary">
				<span class="dashicons dashicons-admin-tools" style="vertical-align:text-bottom;margin-right:3px;"></span>
				<?php esc_html_e( 'Tools & Rollback', 'wp-secure-guard' ); ?>
			</a>
		</div>
	</div>

	<?php
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended
	if ( isset( $_GET['wpsg_updated_checked'] ) ) :
	?>
		<div class="notice notice-info is-dismissible wpsg-notice">
			<p><strong><?php esc_html_e( 'Update Check Complete:', 'wp-secure-guard' ); ?></strong> <?php esc_html_e( 'Checked GitHub repository for releases. You are on the latest version or any new release is listed below.', 'wp-secure-guard' ); ?></p>
		</div>
	<?php endif; ?>

	<?php
	$remote_info = WPSG_Updater::get_remote_version_info();
	if ( ! empty( $remote_info['version'] ) && version_compare( $remote_info['version'], WPSG_VERSION, '>' ) ) :
	?>
		<div class="notice notice-warning is-dismissible wpsg-notice" style="border-left-color: #d63638; background: #fff8f8; padding: 12px 16px;">
			<p style="margin: 0; font-size: 14px;">
				<span class="dashicons dashicons-warning" style="color: #d63638; vertical-align: text-bottom; margin-right: 6px;"></span>
				<strong><?php esc_html_e( 'New Version Available for WP Secure Guard!', 'wp-secure-guard' ); ?></strong>
				<?php
				printf(
					/* translators: 1: Current version, 2: New version */
					esc_html__( 'Installed: v%1$s &rarr; Latest: v%2$s.', 'wp-secure-guard' ),
					esc_html( WPSG_VERSION ),
					'<strong>' . esc_html( $remote_info['version'] ) . '</strong>'
				);
				?>
				<a href="<?php echo esc_url( admin_url( 'plugins.php' ) ); ?>" class="button button-primary" style="margin-left: 12px;">
					<?php esc_html_e( 'Update Now (Plugins Page)', 'wp-secure-guard' ); ?>
				</a>
			</p>
		</div>
	<?php endif; ?>

	<?php if ( ! empty( $notice ) ) : ?>
		<?php if ( 'saved' === $notice ) : ?>
			<div class="notice notice-success is-dismissible wpsg-notice">
				<p><strong><?php esc_html_e( 'Success:', 'wp-secure-guard' ); ?></strong> <?php esc_html_e( 'Security settings were successfully updated.', 'wp-secure-guard' ); ?></p>
			</div>
		<?php elseif ( 'reset' === $notice ) : ?>
			<div class="notice notice-warning is-dismissible wpsg-notice">
				<p><strong><?php esc_html_e( 'Reset Complete:', 'wp-secure-guard' ); ?></strong> <?php esc_html_e( 'All configuration settings have been safely reverted to defaults.', 'wp-secure-guard' ); ?></p>
			</div>
		<?php elseif ( 'logs_cleared' === $notice ) : ?>
			<div class="notice notice-info is-dismissible wpsg-notice">
				<p><strong><?php esc_html_e( 'Cleared:', 'wp-secure-guard' ); ?></strong> <?php esc_html_e( 'Security activity log table was emptied successfully.', 'wp-secure-guard' ); ?></p>
			</div>
		<?php endif; ?>
	<?php endif; ?>

	<nav class="nav-tab-wrapper wpsg-nav-tab-wrapper">
		<?php foreach ( $nav_tabs as $slug => $tab ) : ?>
			<?php $active_class = ( $current_page === $slug ) ? 'nav-tab-active' : ''; ?>
			<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $slug ) ); ?>" class="nav-tab <?php echo esc_attr( $active_class ); ?>">
				<span class="dashicons <?php echo esc_attr( $tab['icon'] ); ?>"></span>
				<?php echo esc_html( $tab['title'] ); ?>
			</a>
		<?php endforeach; ?>
	</nav>

	<div class="wpsg-tab-content">
