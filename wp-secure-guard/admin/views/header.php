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
