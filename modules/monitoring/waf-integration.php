<?php
/**
 * Module: Web Application Firewall (WAF) & Request Inspection.
 *
 * Inspects incoming requests for SQL injection, XSS, directory traversal, and malicious crawlers.
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class WPSG_WAF
 */
class WPSG_WAF {

	/**
	 * Initialize firewall hooks early.
	 */
	public static function init() {
		if ( WPSG_Settings::get( 'waf_enable', true ) ) {
			add_action( 'plugins_loaded', array( __CLASS__, 'inspect_incoming_request' ), 1 );
		}
	}

	/**
	 * Run firewall inspection against incoming payload and headers.
	 */
	public static function inspect_incoming_request() {
		$ip = WPSG_Logger::get_client_ip();

		// Bypass whitelisted IPs.
		if ( WPSG_Login_Limiter::is_ip_whitelisted( $ip ) ) {
			return;
		}

		// Bypass logged-in administrators in admin area.
		if ( is_admin() && is_user_logged_in() && current_user_can( 'manage_options' ) ) {
			return;
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$user_agent  = isset( $_SERVER['HTTP_USER_AGENT'] ) ? wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		$payloads_to_check = array(
			'URI' => $request_uri,
			'GET' => ! empty( $_GET ) ? wp_json_encode( wp_unslash( $_GET ) ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			'POST' => ! empty( $_POST ) ? wp_json_encode( wp_unslash( $_POST ) ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Missing
			'COOKIE' => ! empty( $_COOKIE ) ? wp_json_encode( wp_unslash( $_COOKIE ) ) : '',
		);

		// 1. Check Bad Bots / Malicious Scanners.
		if ( WPSG_Settings::get( 'waf_block_bad_bots', true ) && ! empty( $user_agent ) ) {
			$bad_bot_patterns = array(
				'sqlmap',
				'nikto',
				'acunetix',
				'masscan',
				'wpscan',
				'havij',
				'morfeus',
				'zmeu',
				'dirbuster',
			);

			foreach ( $bad_bot_patterns as $bot ) {
				if ( false !== stripos( $user_agent, $bot ) ) {
					self::trigger_waf_action( 'Malicious Scanner / Bot: ' . $bot, $ip, $request_uri );
					return;
				}
			}
		}

		// 2. Inspect Payloads for SQLi, XSS, and Path Traversal.
		foreach ( $payloads_to_check as $source => $payload ) {
			if ( empty( $payload ) ) {
				continue;
			}

			// SQL Injection Check
			if ( WPSG_Settings::get( 'waf_block_sqli', true ) ) {
				$sqli_patterns = array(
					'/(union\s+all\s+select|union\s+select)/i',
					'/(\b(concat|char|sleep|benchmark)\s*\(.*?\))/i',
					'/(exec\s*\(|execute\s*immediate)/i',
					'/(into\s+outfile|into\s+dumpfile)/i',
					'/(\bwhere\b.+=\bwhere\b|1=1\s*--|1=1\s*#)/i',
				);

				foreach ( $sqli_patterns as $pattern ) {
					if ( preg_match( $pattern, $payload ) ) {
						self::trigger_waf_action( 'SQL Injection pattern detected in ' . $source, $ip, $request_uri );
						return;
					}
				}
			}

			// Cross-Site Scripting (XSS) Check
			if ( WPSG_Settings::get( 'waf_block_xss', true ) ) {
				$xss_patterns = array(
					'/<script\b[^>]*>/i',
					'/javascript\s*:/i',
					'/vbscript\s*:/i',
					'/(onerror|onload|onclick|onmouseover|onfocus)\s*=/i',
					'/document\.(cookie|location|write)/i',
				);

				foreach ( $xss_patterns as $pattern ) {
					if ( preg_match( $pattern, $payload ) ) {
						self::trigger_waf_action( 'Cross-Site Scripting (XSS) pattern detected in ' . $source, $ip, $request_uri );
						return;
					}
				}
			}

			// Path / Directory Traversal Check
			if ( WPSG_Settings::get( 'waf_block_traversal', true ) ) {
				$traversal_patterns = array(
					'#(\.\./|\.\.\\\\){2,}#',
					'#etc/(passwd|shadow|hosts)#i',
					'#(boot\.ini|win\.ini)#i',
				);

				foreach ( $traversal_patterns as $pattern ) {
					if ( preg_match( $pattern, $payload ) ) {
						self::trigger_waf_action( 'Path Traversal pattern detected in ' . $source, $ip, $request_uri );
						return;
					}
				}
			}
		}
	}

	/**
	 * Handle firewall alert according to configured mode (block vs monitor).
	 *
	 * @param string $threat_reason Descriptive threat explanation.
	 * @param string $ip            Client IP address.
	 * @param string $request_uri   Requested URI.
	 */
	private static function trigger_waf_action( $threat_reason, $ip, $request_uri ) {
		$mode = WPSG_Settings::get( 'waf_mode', 'block' );

		if ( 'block' === $mode ) {
			WPSG_Logger::log(
				'waf_blocked',
				sprintf(
					/* translators: 1: reason, 2: client IP, 3: request URI */
					__( 'WAF Blocked Request [%1$s] from IP %2$s (URI: %3$s)', 'wp-secure-guard' ),
					$threat_reason,
					$ip,
					$request_uri
				),
				'danger',
				array( 'ip_address' => $ip, 'request_uri' => $request_uri )
			);

			status_header( 403 );
			nocache_headers();
			wp_die(
				sprintf(
					'<h2>%1$s</h2><p>%2$s</p><p><small>%3$s %4$s | %5$s</small></p>',
					esc_html__( '403 Forbidden - Request Blocked', 'wp-secure-guard' ),
					esc_html__( 'This request was blocked by the WP Secure Guard Application Firewall due to detected malicious signatures.', 'wp-secure-guard' ),
					esc_html__( 'Client IP:', 'wp-secure-guard' ),
					esc_html( $ip ),
					esc_html( gmdate( 'Y-m-d H:i:s \U\T\C' ) )
				),
				esc_html__( 'Security Firewall Block', 'wp-secure-guard' ),
				array( 'response' => 403 )
			);
			exit;
		} else {
			// Monitor Mode
			WPSG_Logger::log(
				'waf_monitored',
				sprintf(
					/* translators: 1: reason, 2: client IP, 3: request URI */
					__( 'WAF Monitored Request [%1$s] from IP %2$s (URI: %3$s)', 'wp-secure-guard' ),
					$threat_reason,
					$ip,
					$request_uri
				),
				'warning',
				array( 'ip_address' => $ip, 'request_uri' => $request_uri )
			);
		}
	}

	/**
	 * Retrieve feature audit status.
	 *
	 * @return array
	 */
	public static function get_status() {
		$enabled = (bool) WPSG_Settings::get( 'waf_enable', true );
		$mode    = WPSG_Settings::get( 'waf_mode', 'block' );

		$label = ! $enabled ? __( 'Disabled', 'wp-secure-guard' ) : ( 'block' === $mode ? __( 'Active (Block Mode)', 'wp-secure-guard' ) : __( 'Active (Monitor Mode)', 'wp-secure-guard' ) );

		return array(
			'id'          => 'waf_firewall',
			'title'       => __( 'Application Firewall (WAF)', 'wp-secure-guard' ),
			'category'    => 'monitoring',
			'enabled'     => $enabled,
			'status'      => $enabled ? 'passed' : 'warning',
			'label'       => $label,
			'mode'        => $mode,
			'description' => __( 'Zero-latency web application firewall filtering SQLi, XSS, and directory traversal attempts.', 'wp-secure-guard' ),
		);
	}
}
