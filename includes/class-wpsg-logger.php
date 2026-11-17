<?php
/**
 * Security Activity Logger.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_Logger
 */
class WPSG_Logger {

	/**
	 * Log table name suffix.
	 */
	const TABLE_NAME = 'wpsg_activity_logs';

	/**
	 * Get full table name with WordPress prefix.
	 *
	 * @return string
	 */
	public static function get_table_name() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE_NAME;
	}

	/**
	 * Create database table on plugin activation.
	 */
	public static function create_table() {
		global $wpdb;

		$table_name      = self::get_table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			event_type varchar(50) NOT NULL,
			severity varchar(20) NOT NULL DEFAULT 'info',
			message text NOT NULL,
			ip_address varchar(45) NOT NULL DEFAULT '',
			user_id bigint(20) unsigned NOT NULL DEFAULT 0,
			username varchar(100) NOT NULL DEFAULT '',
			request_uri varchar(255) NOT NULL DEFAULT '',
			created_at datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY event_type (event_type),
			KEY ip_address (ip_address),
			KEY created_at (created_at)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Record a security activity log entry.
	 *
	 * @param string $event_type e.g., 'login_failed', 'waf_blocked', 'user_enum'.
	 * @param string $message    Descriptive message.
	 * @param string $severity   'info', 'warning', 'danger', 'success'.
	 * @param array  $extra      Optional extra data: ip_address, user_id, username, request_uri.
	 * @return int|false Inserted ID or false on failure.
	 */
	public static function log( $event_type, $message, $severity = 'info', $extra = array() ) {
		if ( ! WPSG_Settings::get( 'activity_logs_enable', true ) ) {
			return false;
		}

		global $wpdb;

		$ip = isset( $extra['ip_address'] ) ? $extra['ip_address'] : self::get_client_ip();
		$user_id = isset( $extra['user_id'] ) ? absint( $extra['user_id'] ) : get_current_user_id();
		$username = isset( $extra['username'] ) ? sanitize_user( $extra['username'] ) : '';

		if ( ! $username && $user_id > 0 ) {
			$user = get_userdata( $user_id );
			if ( $user ) {
				$username = $user->user_login;
			}
		}

		$request_uri = isset( $extra['request_uri'] )
			? sanitize_text_field( $extra['request_uri'] )
			: ( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '' );

		$data = array(
			'event_type'  => sanitize_key( $event_type ),
			'severity'    => in_array( $severity, array( 'info', 'warning', 'danger', 'success' ), true ) ? $severity : 'info',
			'message'     => sanitize_textarea_field( $message ),
			'ip_address'  => sanitize_text_field( $ip ),
			'user_id'     => $user_id,
			'username'    => $username,
			'request_uri' => substr( $request_uri, 0, 255 ),
			'created_at'  => current_time( 'mysql' ),
		);

		$format = array( '%s', '%s', '%s', '%s', '%d', '%s', '%s', '%s' );

		if ( ! is_object( $wpdb ) ) {
			return false;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$inserted = $wpdb->insert( self::get_table_name(), $data, $format );

		return $inserted ? $wpdb->insert_id : false;
	}

	/**
	 * Retrieve log entries with pagination and filters.
	 *
	 * @param array $args Filter and pagination arguments.
	 * @return array Array of log objects.
	 */
	public static function get_logs( $args = array() ) {
		global $wpdb;

		$table = self::get_table_name();

		$defaults = array(
			'per_page'   => 20,
			'offset'     => 0,
			'event_type' => '',
			'severity'   => '',
			'search'     => '',
			'orderby'    => 'created_at',
			'order'      => 'DESC',
		);

		$params = wp_parse_args( $args, $defaults );

		$where = array( '1=1' );
		$values = array();

		if ( ! empty( $params['event_type'] ) ) {
			$where[]  = 'event_type = %s';
			$values[] = sanitize_key( $params['event_type'] );
		}

		if ( ! empty( $params['severity'] ) ) {
			$where[]  = 'severity = %s';
			$values[] = sanitize_key( $params['severity'] );
		}

		if ( ! empty( $params['search'] ) ) {
			$search   = '%' . $wpdb->esc_like( $params['search'] ) . '%';
			$where[]  = '(message LIKE %s OR ip_address LIKE %s OR username LIKE %s)';
			$values[] = $search;
			$values[] = $search;
			$values[] = $search;
		}

		$where_clause = implode( ' AND ', $where );
		$orderby = in_array( $params['orderby'], array( 'id', 'created_at', 'event_type', 'severity' ), true ) ? $params['orderby'] : 'created_at';
		$order   = strtoupper( $params['order'] ) === 'ASC' ? 'ASC' : 'DESC';

		$limit = absint( $params['per_page'] );
		$offset = absint( $params['offset'] );

		$query = "SELECT * FROM {$table} WHERE {$where_clause} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d";
		$values[] = $limit;
		$values[] = $offset;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
		return $wpdb->get_results( $wpdb->prepare( $query, $values ) );
	}

	/**
	 * Count total log entries matching filters.
	 *
	 * @param array $args Filter arguments.
	 * @return int Total rows.
	 */
	public static function count_logs( $args = array() ) {
		global $wpdb;

		$table = self::get_table_name();
		$where = array( '1=1' );
		$values = array();

		if ( ! empty( $args['event_type'] ) ) {
			$where[]  = 'event_type = %s';
			$values[] = sanitize_key( $args['event_type'] );
		}

		if ( ! empty( $args['severity'] ) ) {
			$where[]  = 'severity = %s';
			$values[] = sanitize_key( $args['severity'] );
		}

		if ( ! empty( $args['search'] ) ) {
			$search   = '%' . $wpdb->esc_like( $args['search'] ) . '%';
			$where[]  = '(message LIKE %s OR ip_address LIKE %s OR username LIKE %s)';
			$values[] = $search;
			$values[] = $search;
			$values[] = $search;
		}

		$where_clause = implode( ' AND ', $where );
		$query = "SELECT COUNT(*) FROM {$table} WHERE {$where_clause}";

		if ( ! empty( $values ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
			return absint( $wpdb->get_var( $wpdb->prepare( $query, $values ) ) );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
		return absint( $wpdb->get_var( $query ) );
	}

	/**
	 * Clear all log entries.
	 *
	 * @return bool
	 */
	public static function clear_logs() {
		global $wpdb;
		$table = self::get_table_name();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return false !== $wpdb->query( "TRUNCATE TABLE {$table}" );
	}

	/**
	 * Prune old logs based on retention days setting.
	 *
	 * @param int $days Number of days to retain.
	 * @return int Deleted rows.
	 */
	public static function prune_logs( $days = 30 ) {
		global $wpdb;
		$table = self::get_table_name();
		$cutoff_date = gmdate( 'Y-m-d H:i:s', time() - ( absint( $days ) * DAY_IN_SECONDS ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->query(
			$wpdb->prepare(
				"DELETE FROM {$table} WHERE created_at < %s",
				$cutoff_date
			)
		);
	}

	/**
	 * Safely determine the client's IP address.
	 *
	 * @return string
	 */
	public static function get_client_ip() {
		$ip = '';

		$headers = array(
			'HTTP_CF_CONNECTING_IP', // Cloudflare
			'HTTP_X_FORWARDED_FOR',  // Proxies
			'HTTP_CLIENT_IP',
			'REMOTE_ADDR',
		);

		foreach ( $headers as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$val = sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) );
				// In case of X-Forwarded-For with multiple IPs, take the first one.
				if ( strpos( $val, ',' ) !== false ) {
					$ips = explode( ',', $val );
					$val = trim( $ips[0] );
				}
				if ( filter_var( $val, FILTER_VALIDATE_IP ) ) {
					$ip = $val;
					break;
				}
			}
		}

		return $ip ? $ip : '127.0.0.1';
	}
}
