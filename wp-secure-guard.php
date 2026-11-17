<?php
/**
 * Plugin Name:       WP Secure Guard
 * Plugin URI:        https://github.com/hariomIB/WP-Secure-Guard
 * Description:       Advanced modular WordPress security suite featuring User Enumeration Protection, Brute-Force Rate Limiting, Custom Login URL, Native TOTP 2FA, XML-RPC Shield, WAF Firewall, Sensitive File Protection, and Activity Logs.
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            WP Secure Guard Team
 * Author URI:        https://github.com/hariomIB/WP-Secure-Guard
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

// Support for GitHub repository "Download ZIP" archives (e.g. WP-Secure-Guard-main.zip)
if ( ! defined( 'WPSG_ROOT_FILE' ) ) {
	define( 'WPSG_ROOT_FILE', __FILE__ );
}

if ( file_exists( __DIR__ . '/wp-secure-guard/wp-secure-guard.php' ) ) {
	require_once __DIR__ . '/wp-secure-guard/wp-secure-guard.php';
}
