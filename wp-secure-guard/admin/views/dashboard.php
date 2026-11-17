<?php
/**
 * View: Security Dashboard & Health Score.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$score = $audit['score'];
$score_color = ( $score >= 80 ) ? '#00a32a' : ( ( $score >= 55 ) ? '#dba617' : '#d63638' );
$score_label = ( $score >= 80 ) ? __( 'Strong Security Posture', 'wp-secure-guard' ) : ( ( $score >= 55 ) ? __( 'Moderate Risks Present', 'wp-secure-guard' ) : __( 'Critical Attention Required', 'wp-secure-guard' ) );

// Fetch recent 5 logs
$recent_logs = WPSG_Logger::get_logs( array( 'per_page' => 5, 'offset' => 0 ) );
?>

<div class="wpsg-dashboard-grid">
	<!-- Left: Health Score Card -->
	<div class="wpsg-card wpsg-score-card">
		<div class="wpsg-score-inner">
			<div class="wpsg-score-circle" style="border-color: <?php echo esc_attr( $score_color ); ?>;">
				<span class="wpsg-score-number" style="color: <?php echo esc_attr( $score_color ); ?>;"><?php echo esc_html( $score ); ?>%</span>
				<span class="wpsg-score-sub"><?php esc_html_e( 'HEALTH SCORE', 'wp-secure-guard' ); ?></span>
			</div>
			<div class="wpsg-score-meta">
				<h2 class="wpsg-score-headline" style="color: <?php echo esc_attr( $score_color ); ?>;"><?php echo esc_html( $score_label ); ?></h2>
				<p class="wpsg-score-desc">
					<?php
					printf(
						/* translators: 1: passed count, 2: total count */
						esc_html__( '%1$d of %2$d modular security safeguards are currently active and hardened.', 'wp-secure-guard' ),
						esc_html( $audit['passed'] ),
						esc_html( $audit['total'] )
					);
					?>
				</p>
				<div class="wpsg-score-bar-wrap">
					<div class="wpsg-score-bar" style="width: <?php echo esc_attr( $score ); ?>%; background-color: <?php echo esc_attr( $score_color ); ?>;"></div>
				</div>
			</div>
		</div>
	</div>

	<!-- Right: Stats Counter Tiles -->
	<div class="wpsg-stats-tiles">
		<div class="wpsg-stat-tile wpsg-stat-passed">
			<span class="dashicons dashicons-yes-alt wpsg-stat-icon"></span>
			<div class="wpsg-stat-content">
				<span class="wpsg-stat-val"><?php echo esc_html( $audit['passed'] ); ?></span>
				<span class="wpsg-stat-label"><?php esc_html_e( 'Passed Safeguards', 'wp-secure-guard' ); ?></span>
			</div>
		</div>

		<div class="wpsg-stat-tile wpsg-stat-warning">
			<span class="dashicons dashicons-warning wpsg-stat-icon"></span>
			<div class="wpsg-stat-content">
				<span class="wpsg-stat-val"><?php echo esc_html( $audit['warning'] ); ?></span>
				<span class="wpsg-stat-label"><?php esc_html_e( 'Warnings / Notices', 'wp-secure-guard' ); ?></span>
			</div>
		</div>

		<div class="wpsg-stat-tile wpsg-stat-critical">
			<span class="dashicons dashicons-dismiss wpsg-stat-icon"></span>
			<div class="wpsg-stat-content">
				<span class="wpsg-stat-val"><?php echo esc_html( $audit['critical'] ); ?></span>
				<span class="wpsg-stat-label"><?php esc_html_e( 'Critical Vulnerabilities', 'wp-secure-guard' ); ?></span>
			</div>
		</div>

		<div class="wpsg-stat-tile wpsg-stat-disabled">
			<span class="dashicons dashicons-minus wpsg-stat-icon"></span>
			<div class="wpsg-stat-content">
				<span class="wpsg-stat-val"><?php echo esc_html( $audit['disabled'] ); ?></span>
				<span class="wpsg-stat-label"><?php esc_html_e( 'Disabled Modules', 'wp-secure-guard' ); ?></span>
			</div>
		</div>
	</div>
</div>

<!-- 20-Feature Security Status Grid -->
<div class="wpsg-card wpsg-features-summary-card">
	<div class="wpsg-card-header">
		<h2>
			<span class="dashicons dashicons-shield"></span>
			<?php esc_html_e( 'Modular Safeguards Audit (20 Features)', 'wp-secure-guard' ); ?>
		</h2>
		<p class="description">
			<?php esc_html_e( 'Every security feature functions independently. Configure each safeguard to suit your hosting and architecture needs.', 'wp-secure-guard' ); ?>
		</p>
	</div>

	<div class="wpsg-feature-matrix">
		<?php foreach ( $audit['modules'] as $mod ) : ?>
			<?php
			$badge_class = 'wpsg-badge-info';
			if ( 'passed' === $mod['status'] ) {
				$badge_class = 'wpsg-badge-success';
			} elseif ( 'warning' === $mod['status'] ) {
				$badge_class = 'wpsg-badge-warning';
			} elseif ( 'critical' === $mod['status'] ) {
				$badge_class = 'wpsg-badge-danger';
			}

			$target_tab = 'wpsg-user-security';
			if ( 'login_security' === $mod['category'] ) {
				$target_tab = 'wpsg-login-security';
			} elseif ( 'file_security' === $mod['category'] ) {
				$target_tab = 'wpsg-file-security';
			} elseif ( 'monitoring' === $mod['category'] ) {
				$target_tab = 'wpsg-monitoring';
			}
			?>
			<div class="wpsg-matrix-item">
				<div class="wpsg-matrix-top">
					<h3 class="wpsg-matrix-title"><?php echo esc_html( $mod['title'] ); ?></h3>
					<span class="wpsg-badge <?php echo esc_attr( $badge_class ); ?>">
						<?php echo esc_html( $mod['label'] ); ?>
					</span>
				</div>
				<p class="wpsg-matrix-desc"><?php echo esc_html( $mod['description'] ); ?></p>
				<div class="wpsg-matrix-footer">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $target_tab ) ); ?>" class="button button-small">
						<?php esc_html_e( 'Configure', 'wp-secure-guard' ); ?> &rarr;
					</a>
				</div>
			</div>
		<?php endforeach; ?>
	</div>
</div>

<!-- Recent Security Activity Log Preview -->
<div class="wpsg-card wpsg-recent-logs-card">
	<div class="wpsg-card-header wpsg-flex-between">
		<div>
			<h2>
				<span class="dashicons dashicons-visibility"></span>
				<?php esc_html_e( 'Recent Security Events', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description"><?php esc_html_e( 'Latest authentication events, blocked intrusions, and administrative changes.', 'wp-secure-guard' ); ?></p>
		</div>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=wpsg-activity-logs' ) ); ?>" class="button button-secondary">
			<?php esc_html_e( 'View All Activity Logs', 'wp-secure-guard' ); ?> &rarr;
		</a>
	</div>

	<?php if ( empty( $recent_logs ) ) : ?>
		<div class="wpsg-empty-state">
			<p><?php esc_html_e( 'No security events recorded yet.', 'wp-secure-guard' ); ?></p>
		</div>
	<?php else : ?>
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th style="width: 170px;"><?php esc_html_e( 'Time (Local)', 'wp-secure-guard' ); ?></th>
					<th style="width: 110px;"><?php esc_html_e( 'Severity', 'wp-secure-guard' ); ?></th>
					<th style="width: 140px;"><?php esc_html_e( 'Event Type', 'wp-secure-guard' ); ?></th>
					<th><?php esc_html_e( 'Description', 'wp-secure-guard' ); ?></th>
					<th style="width: 140px;"><?php esc_html_e( 'IP Address', 'wp-secure-guard' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $recent_logs as $log ) : ?>
					<?php
					$sev_class = 'wpsg-badge-info';
					if ( 'success' === $log->severity ) {
						$sev_class = 'wpsg-badge-success';
					} elseif ( 'warning' === $log->severity ) {
						$sev_class = 'wpsg-badge-warning';
					} elseif ( 'danger' === $log->severity ) {
						$sev_class = 'wpsg-badge-danger';
					}
					?>
					<tr>
						<td><?php echo esc_html( get_date_from_gmt( $log->created_at, 'Y-m-d H:i:s' ) ); ?></td>
						<td><span class="wpsg-badge <?php echo esc_attr( $sev_class ); ?>"><?php echo esc_html( strtoupper( $log->severity ) ); ?></span></td>
						<td><code><?php echo esc_html( $log->event_type ); ?></code></td>
						<td><?php echo esc_html( $log->message ); ?></td>
						<td><code><?php echo esc_html( $log->ip_address ); ?></code></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
	<?php endif; ?>
</div>
