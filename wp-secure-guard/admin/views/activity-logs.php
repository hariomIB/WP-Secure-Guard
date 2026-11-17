<?php
/**
 * View: Full Security Activity Logs & Audit Trail.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$current_paged = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$filter_type   = isset( $_GET['event_type'] ) ? sanitize_key( wp_unslash( $_GET['event_type'] ) ) : '';
// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$filter_sev    = isset( $_GET['severity'] ) ? sanitize_key( wp_unslash( $_GET['severity'] ) ) : '';
// phpcs:ignore WordPress.Security.NonceVerification.Recommended
$search_term   = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';

$per_page = 25;
$offset   = ( $current_paged - 1 ) * $per_page;

$log_args = array(
	'per_page'   => $per_page,
	'offset'     => $offset,
	'event_type' => $filter_type,
	'severity'   => $filter_sev,
	'search'     => $search_term,
);

$logs  = WPSG_Logger::get_logs( $log_args );
$total = WPSG_Logger::count_logs( $log_args );
$pages = ceil( $total / $per_page );
?>

<div class="wpsg-card">
	<div class="wpsg-card-header wpsg-flex-between">
		<div>
			<h2>
				<span class="dashicons dashicons-list-view"></span>
				<?php esc_html_e( 'Security Activity Audit Trail', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php
				printf(
					/* translators: %d: total logs count */
					esc_html__( 'Total recorded security events: %d', 'wp-secure-guard' ),
					absint( $total )
				);
				?>
			</p>
		</div>

		<div class="wpsg-log-actions">
			<a href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin.php?page=wpsg-activity-logs&action=wpsg_export_logs_csv' ), 'wpsg_export_logs_csv_nonce' ) ); ?>" class="button button-secondary">
				<span class="dashicons dashicons-download" style="vertical-align:text-bottom;margin-right:4px;"></span>
				<?php esc_html_e( 'Export CSV', 'wp-secure-guard' ); ?>
			</a>

			<form method="post" action="" style="display:inline-block; margin-left:8px;" onsubmit="return confirm('<?php esc_attr_e( 'Are you sure you want to permanently clear all activity logs?', 'wp-secure-guard' ); ?>');">
				<?php wp_nonce_field( 'wpsg_clear_logs_action', 'wpsg_clear_logs_nonce' ); ?>
				<input type="hidden" name="wpsg_clear_logs" value="1" />
				<button type="submit" class="button button-link-delete">
					<span class="dashicons dashicons-trash" style="vertical-align:text-bottom;margin-right:2px;"></span>
					<?php esc_html_e( 'Clear All Logs', 'wp-secure-guard' ); ?>
				</button>
			</form>
		</div>
	</div>

	<!-- Filters Bar -->
	<form method="get" action="" class="wpsg-filter-bar">
		<input type="hidden" name="page" value="wpsg-activity-logs" />

		<div class="wpsg-filter-group">
			<label for="wpsg_filter_type"><?php esc_html_e( 'Event Type:', 'wp-secure-guard' ); ?></label>
			<select name="event_type" id="wpsg_filter_type">
				<option value=""><?php esc_html_e( 'All Event Types', 'wp-secure-guard' ); ?></option>
				<option value="login_failed" <?php selected( $filter_type, 'login_failed' ); ?>><?php esc_html_e( 'Failed Login', 'wp-secure-guard' ); ?></option>
				<option value="login_lockout" <?php selected( $filter_type, 'login_lockout' ); ?>><?php esc_html_e( 'Login Lockout', 'wp-secure-guard' ); ?></option>
				<option value="login_success" <?php selected( $filter_type, 'login_success' ); ?>><?php esc_html_e( 'Successful Login', 'wp-secure-guard' ); ?></option>
				<option value="waf_blocked" <?php selected( $filter_type, 'waf_blocked' ); ?>><?php esc_html_e( 'WAF Blocked', 'wp-secure-guard' ); ?></option>
				<option value="waf_monitored" <?php selected( $filter_type, 'waf_monitored' ); ?>><?php esc_html_e( 'WAF Monitored', 'wp-secure-guard' ); ?></option>
				<option value="user_enumeration" <?php selected( $filter_type, 'user_enumeration' ); ?>><?php esc_html_e( 'User Enumeration', 'wp-secure-guard' ); ?></option>
				<option value="rest_user_enumeration" <?php selected( $filter_type, 'rest_user_enumeration' ); ?>><?php esc_html_e( 'REST User Enumeration', 'wp-secure-guard' ); ?></option>
				<option value="xmlrpc_blocked" <?php selected( $filter_type, 'xmlrpc_blocked' ); ?>><?php esc_html_e( 'XML-RPC Blocked', 'wp-secure-guard' ); ?></option>
				<option value="sensitive_file_blocked" <?php selected( $filter_type, 'sensitive_file_blocked' ); ?>><?php esc_html_e( 'Sensitive File Blocked', 'wp-secure-guard' ); ?></option>
				<option value="user_role_changed" <?php selected( $filter_type, 'user_role_changed' ); ?>><?php esc_html_e( 'User Role Changed', 'wp-secure-guard' ); ?></option>
				<option value="settings_updated" <?php selected( $filter_type, 'settings_updated' ); ?>><?php esc_html_e( 'Settings Updated', 'wp-secure-guard' ); ?></option>
			</select>
		</div>

		<div class="wpsg-filter-group">
			<label for="wpsg_filter_sev"><?php esc_html_e( 'Severity:', 'wp-secure-guard' ); ?></label>
			<select name="severity" id="wpsg_filter_sev">
				<option value=""><?php esc_html_e( 'All Severities', 'wp-secure-guard' ); ?></option>
				<option value="danger" <?php selected( $filter_sev, 'danger' ); ?>><?php esc_html_e( 'Danger / Blocked', 'wp-secure-guard' ); ?></option>
				<option value="warning" <?php selected( $filter_sev, 'warning' ); ?>><?php esc_html_e( 'Warning', 'wp-secure-guard' ); ?></option>
				<option value="info" <?php selected( $filter_sev, 'info' ); ?>><?php esc_html_e( 'Info', 'wp-secure-guard' ); ?></option>
				<option value="success" <?php selected( $filter_sev, 'success' ); ?>><?php esc_html_e( 'Success', 'wp-secure-guard' ); ?></option>
			</select>
		</div>

		<div class="wpsg-filter-group">
			<label for="wpsg_search_box"><?php esc_html_e( 'Search:', 'wp-secure-guard' ); ?></label>
			<input type="search" id="wpsg_search_box" name="s" value="<?php echo esc_attr( $search_term ); ?>" placeholder="<?php esc_attr_e( 'IP, username, or message', 'wp-secure-guard' ); ?>" />
		</div>

		<div class="wpsg-filter-group">
			<button type="submit" class="button button-secondary"><?php esc_html_e( 'Filter Logs', 'wp-secure-guard' ); ?></button>
			<?php if ( ! empty( $filter_type ) || ! empty( $filter_sev ) || ! empty( $search_term ) ) : ?>
				<a href="<?php echo esc_url( admin_url( 'admin.php?page=wpsg-activity-logs' ) ); ?>" class="button button-link" style="margin-left: 8px;">
					<?php esc_html_e( 'Reset Filters', 'wp-secure-guard' ); ?>
				</a>
			<?php endif; ?>
		</div>
	</form>

	<!-- Logs Table -->
	<?php if ( empty( $logs ) ) : ?>
		<div class="wpsg-empty-state" style="padding: 40px; text-align: center;">
			<span class="dashicons dashicons-yes-alt" style="font-size: 48px; width:48px; height:48px; color: #00a32a;"></span>
			<p style="font-size: 16px; margin-top: 10px;"><?php esc_html_e( 'No log entries found matching current criteria.', 'wp-secure-guard' ); ?></p>
		</div>
	<?php else : ?>
		<table class="wp-list-table widefat fixed striped">
			<thead>
				<tr>
					<th style="width: 60px;"><?php esc_html_e( 'ID', 'wp-secure-guard' ); ?></th>
					<th style="width: 170px;"><?php esc_html_e( 'Time (Local)', 'wp-secure-guard' ); ?></th>
					<th style="width: 110px;"><?php esc_html_e( 'Severity', 'wp-secure-guard' ); ?></th>
					<th style="width: 160px;"><?php esc_html_e( 'Event Type', 'wp-secure-guard' ); ?></th>
					<th><?php esc_html_e( 'Details', 'wp-secure-guard' ); ?></th>
					<th style="width: 140px;"><?php esc_html_e( 'IP Address', 'wp-secure-guard' ); ?></th>
					<th style="width: 120px;"><?php esc_html_e( 'User', 'wp-secure-guard' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $logs as $row ) : ?>
					<?php
					$sev_class = 'wpsg-badge-info';
					if ( 'success' === $row->severity ) {
						$sev_class = 'wpsg-badge-success';
					} elseif ( 'warning' === $row->severity ) {
						$sev_class = 'wpsg-badge-warning';
					} elseif ( 'danger' === $row->severity ) {
						$sev_class = 'wpsg-badge-danger';
					}
					?>
					<tr>
						<td>#<?php echo esc_html( $row->id ); ?></td>
						<td><?php echo esc_html( get_date_from_gmt( $row->created_at, 'Y-m-d H:i:s' ) ); ?></td>
						<td><span class="wpsg-badge <?php echo esc_attr( $sev_class ); ?>"><?php echo esc_html( strtoupper( $row->severity ) ); ?></span></td>
						<td><code><?php echo esc_html( $row->event_type ); ?></code></td>
						<td>
							<?php echo esc_html( $row->message ); ?>
							<?php if ( ! empty( $row->request_uri ) ) : ?>
								<br /><small style="color: #646970;">URI: <code><?php echo esc_html( $row->request_uri ); ?></code></small>
							<?php endif; ?>
						</td>
						<td><code><?php echo esc_html( $row->ip_address ); ?></code></td>
						<td><?php echo ! empty( $row->username ) ? esc_html( $row->username ) : '—'; ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>

		<!-- Pagination -->
		<?php if ( $pages > 1 ) : ?>
			<div class="wpsg-pagination-wrap" style="margin-top: 15px; text-align: right;">
				<?php
				$base_url = add_query_arg(
					array(
						'page'       => 'wpsg-activity-logs',
						'event_type' => $filter_type,
						'severity'   => $filter_sev,
						's'          => $search_term,
					),
					admin_url( 'admin.php' )
				);

				echo wp_kses_post(
					paginate_links(
						array(
							'base'      => $base_url . '%_%',
							'format'    => '&paged=%#%',
							'current'   => $current_paged,
							'total'     => $pages,
							'prev_text' => '&laquo; ' . __( 'Previous', 'wp-secure-guard' ),
							'next_text' => __( 'Next', 'wp-secure-guard' ) . ' &raquo;',
						)
					)
				);
				?>
			</div>
		<?php endif; ?>
	<?php endif; ?>
</div>
