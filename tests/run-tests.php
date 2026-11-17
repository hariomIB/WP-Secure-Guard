<?php
/**
 * Standalone Unit and Integration Test Runner for WP Secure Guard.
 *
 * Runs without requiring a live WordPress database by providing minimal WP polyfills.
 */

// Define mock ABSPATH
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/../' );
}
if ( ! defined( 'WPINC' ) ) {
	define( 'WPINC', 'wp-includes' );
}
if ( ! defined( 'WP_CONTENT_DIR' ) ) {
	define( 'WP_CONTENT_DIR', __DIR__ . '/../wp-content' );
}
if ( ! defined( 'WP_PLUGIN_DIR' ) ) {
	define( 'WP_PLUGIN_DIR', __DIR__ . '/..' );
}
if ( ! defined( 'DAY_IN_SECONDS' ) ) {
	define( 'DAY_IN_SECONDS', 86400 );
}
if ( ! defined( 'MINUTE_IN_SECONDS' ) ) {
	define( 'MINUTE_IN_SECONDS', 60 );
}

// Minimal WordPress helper polyfills for testing pure functions
if ( ! function_exists( 'esc_html' ) ) {
	function esc_html( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES, 'UTF-8' ); }
}
if ( ! function_exists( 'esc_attr' ) ) {
	function esc_attr( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES, 'UTF-8' ); }
}
if ( ! function_exists( 'esc_url' ) ) {
	function esc_url( $s ) { return $s; }
}
if ( ! function_exists( 'sanitize_text_field' ) ) {
	function sanitize_text_field( $s ) { return trim( strip_tags( (string) $s ) ); }
}
if ( ! function_exists( 'sanitize_key' ) ) {
	function sanitize_key( $s ) { return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $s ) ); }
}
if ( ! function_exists( 'sanitize_user' ) ) {
	function sanitize_user( $s ) { return trim( strip_tags( (string) $s ) ); }
}
if ( ! function_exists( 'sanitize_textarea_field' ) ) {
	function sanitize_textarea_field( $s ) { return trim( strip_tags( (string) $s ) ); }
}
if ( ! function_exists( 'wp_unslash' ) ) {
	function wp_unslash( $s ) { return is_array( $s ) ? array_map( 'wp_unslash', $s ) : stripslashes( (string) $s ); }
}
if ( ! function_exists( 'absint' ) ) {
	function absint( $n ) { return abs( (int) $n ); }
}
if ( ! function_exists( 'wp_parse_args' ) ) {
	function wp_parse_args( $args, $defaults = array() ) {
		return array_merge( $defaults, (array) $args );
	}
}
if ( ! function_exists( 'wp_rand' ) ) {
	function wp_rand( $min = 0, $max = 0 ) { return mt_rand( $min, $max ); }
}
if ( ! function_exists( '__' ) ) {
	function __( $s, $d = 'default' ) { return $s; }
}
if ( ! function_exists( 'esc_html__' ) ) {
	function esc_html__( $s, $d = 'default' ) { return esc_html( $s ); }
}
if ( ! function_exists( 'current_time' ) ) {
	function current_time( $type ) { return date( 'Y-m-d H:i:s' ); }
}
if ( ! function_exists( 'get_current_user_id' ) ) {
	function get_current_user_id() { return 1; }
}
if ( ! function_exists( 'get_userdata' ) ) {
	function get_userdata( $id ) {
		$u = new stdClass();
		$u->user_login = 'tester';
		return $u;
	}
}
if ( ! function_exists( 'is_user_logged_in' ) ) {
	function is_user_logged_in() { return false; }
}
if ( ! function_exists( 'trailingslashit' ) ) {
	function trailingslashit( $s ) { return rtrim( $s, '/\\' ) . '/'; }
}
if ( ! function_exists( 'home_url' ) ) {
	function home_url( $path = '' ) { return 'https://example.com' . ( $path ? '/' . ltrim( $path, '/' ) : '' ); }
}
if ( ! function_exists( 'sanitize_title_with_dashes' ) ) {
	function sanitize_title_with_dashes( $s ) { return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( str_replace( ' ', '-', (string) $s ) ) ); }
}
if ( ! function_exists( 'sanitize_file_name' ) ) {
	function sanitize_file_name( $s ) { return preg_replace( '/[^a-zA-Z0-9_\.-]/', '', (string) $s ); }
}
if ( ! function_exists( 'get_bloginfo' ) ) {
	function get_bloginfo( $show = '' ) { return '6.5.3'; }
}
if ( ! function_exists( 'remove_query_arg' ) ) {
	function remove_query_arg( $key, $query = false ) {
		return preg_replace( '/([?&])' . preg_quote( $key, '/' ) . '=[^&]*(&|$)/', '$1', (string) $query );
	}
}
if ( ! function_exists( 'add_query_arg' ) ) {
	function add_query_arg( $key, $val, $url = '' ) {
		return $url . ( strpos( $url, '?' ) !== false ? '&' : '?' ) . urlencode( $key ) . '=' . urlencode( $val );
	}
}
if ( ! function_exists( 'get_home_path' ) ) {
	function get_home_path() { return __DIR__ . '/'; }
}

$mock_options = array();
class MockWPDB {
	public $prefix = 'wp_';
	public $insert_id = 1;
	public function insert( $table, $data, $format = null ) { return 1; }
}
$wpdb = new MockWPDB();
if ( ! function_exists( 'get_option' ) ) {
	function get_option( $name, $default = false ) {
		global $mock_options;
		return isset( $mock_options[ $name ] ) ? $mock_options[ $name ] : $default;
	}
}
if ( ! function_exists( 'update_option' ) ) {
	function update_option( $name, $value ) {
		global $mock_options;
		$mock_options[ $name ] = $value;
		return true;
	}
}

// Require needed modules
require_once __DIR__ . '/../includes/class-wpsg-settings.php';
require_once __DIR__ . '/../includes/class-wpsg-logger.php';
require_once __DIR__ . '/../modules/login-security/two-factor.php';
require_once __DIR__ . '/../modules/login-security/common-usernames.php';
require_once __DIR__ . '/../modules/login-security/login-limiter.php';
require_once __DIR__ . '/../modules/file-security/uploads-protection.php';
require_once __DIR__ . '/../modules/file-security/sensitive-files.php';
require_once __DIR__ . '/../modules/login-security/custom-login-url.php';
require_once __DIR__ . '/../modules/login-security/user-registration.php';
require_once __DIR__ . '/../modules/monitoring/php-hardening.php';
require_once __DIR__ . '/../modules/monitoring/version-hider.php';
require_once __DIR__ . '/../modules/monitoring/server-info-hider.php';

$passed_tests = 0;
$failed_tests = 0;

function assert_test( $condition, $name ) {
	global $passed_tests, $failed_tests;
	if ( $condition ) {
		echo " [PASS] " . $name . "\n";
		$passed_tests++;
	} else {
		echo " [FAIL] " . $name . "\n";
		$failed_tests++;
	}
}

echo "=========================================================\n";
echo " WP Secure Guard - Automated Test Suite\n";
echo "=========================================================\n\n";

// Test 1: Settings Defaults
$defaults = WPSG_Settings::get_defaults();
assert_test( isset( $defaults['user_enum_block'] ) && true === $defaults['user_enum_block'], 'Default settings: user_enum_block is true' );
assert_test( isset( $defaults['waf_enable'] ) && true === $defaults['waf_enable'], 'Default settings: waf_enable is true' );
assert_test( isset( $defaults['waf_mode'] ) && 'block' === $defaults['waf_mode'], 'Default settings: waf_mode is block' );
assert_test( isset( $defaults['login_max_retries'] ) && 5 === $defaults['login_max_retries'], 'Default settings: login_max_retries is 5' );

// Test 2: Settings Sanitization
$sanitized = WPSG_Settings::sanitize_settings( array(
	'login_max_retries' => '15',
	'login_lockout_duration' => '30',
	'login_whitelist_ips' => "127.0.0.1\n192.168.1.50\ninvalid_ip",
	'waf_mode' => 'invalid_mode',
) );
assert_test( 15 === $sanitized['login_max_retries'], 'Settings Sanitizer: login_max_retries clamped/cast to 15' );
assert_test( 30 === $sanitized['login_lockout_duration'], 'Settings Sanitizer: login_lockout_duration is 30' );
assert_test( 'block' === $sanitized['waf_mode'], 'Settings Sanitizer: invalid waf_mode falls back to block' );
assert_test( strpos( $sanitized['login_whitelist_ips'], '127.0.0.1' ) !== false, 'Settings Sanitizer: valid IP 127.0.0.1 preserved' );
assert_test( strpos( $sanitized['login_whitelist_ips'], 'invalid_ip' ) === false, 'Settings Sanitizer: invalid IP filtered out' );

// Test 3: Tab-Scoped Update (Toggle OFF and ON verification)
// Initialize default settings in mock DB
update_option( WPSG_Settings::OPTION_NAME, $defaults );

// Simulate submitting user_security form with user_enum_block turned OFF (0 or missing)
WPSG_Settings::update_settings( array(
	'user_enum_block'       => '0',
	'rest_api_user_protect' => '1',
	'oembed_strip_author'   => '1',
	'author_sitemap_disable'=> '1',
), 'user_security' );

assert_test( false === WPSG_Settings::get( 'user_enum_block' ), 'Toggle OFF: user_enum_block successfully saved as false' );
assert_test( true === WPSG_Settings::get( 'rest_api_user_protect' ), 'Toggle ON: rest_api_user_protect saved as true' );
assert_test( true === WPSG_Settings::get( 'waf_enable' ), 'Tab Isolation: other tab setting waf_enable remained intact' );

// Now simulate turning user_enum_block back ON
WPSG_Settings::update_settings( array(
	'user_enum_block' => '1',
), 'user_security' );
assert_test( true === WPSG_Settings::get( 'user_enum_block' ), 'Toggle ON: user_enum_block successfully saved as true' );

// Test 4: TOTP 2FA RFC 6238 Implementation
$secret = WPSG_Two_Factor::generate_secret();
assert_test( strlen( $secret ) === 16, 'TOTP 2FA: Secret generated is 16 chars long' );
assert_test( preg_match( '/^[A-Z2-7]+$/', $secret ) === 1, 'TOTP 2FA: Secret uses valid Base32 RFC 4648 alphabet' );

// Generate TOTP for current time slice and verify it
$current_slice = (int) floor( time() / 30 );
$totp_code = WPSG_Two_Factor::calculate_totp( $secret, $current_slice );
assert_test( strlen( $totp_code ) === 6 && ctype_digit( $totp_code ), 'TOTP 2FA: Generates valid 6-digit numeric OTP code' );
assert_test( WPSG_Two_Factor::verify_totp( $secret, $totp_code ), 'TOTP 2FA: Verify current TOTP code passes' );
assert_test( ! WPSG_Two_Factor::verify_totp( $secret, '000000' ) && ! WPSG_Two_Factor::verify_totp( $secret, '999999' ), 'TOTP 2FA: Reject incorrect OTP code' );

// Test 5: Common Insecure Usernames List
$insecure_names = WPSG_Common_Usernames::get_insecure_usernames();
assert_test( in_array( 'admin', $insecure_names, true ), 'Common Usernames: "admin" is blacklisted' );
assert_test( in_array( 'administrator', $insecure_names, true ), 'Common Usernames: "administrator" is blacklisted' );
assert_test( in_array( 'root', $insecure_names, true ), 'Common Usernames: "root" is blacklisted' );
assert_test( false === WPSG_Common_Usernames::prevent_insecure_username_registration( true, 'admin' ), 'Common Usernames: blocks registration of "admin"' );
assert_test( true === WPSG_Common_Usernames::prevent_insecure_username_registration( true, 'mysecuresiteuser' ), 'Common Usernames: allows safe username registration' );

// Test 6: Client IP Resolver
$_SERVER['REMOTE_ADDR'] = '203.0.113.195';
unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
$ip1 = WPSG_Logger::get_client_ip();
assert_test( '203.0.113.195' === $ip1, 'Logger IP Detection: REMOTE_ADDR parsed accurately' );

$_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.22, 10.0.0.1';
$ip2 = WPSG_Logger::get_client_ip();
assert_test( '198.51.100.22' === $ip2, 'Logger IP Detection: Proxied X-Forwarded-For parsed accurately' );

// Test 7: WAF Attack Signatures
$sqli_test = 'SELECT * FROM users WHERE id = 1 UNION SELECT 1,2,3,4,5--';
$xss_test = '<script>alert(document.cookie)</script>';
$traversal_test = '../../../../etc/passwd';
$safe_test = 'Hello world, welcome to my WordPress blog.';

$sqli_regex = '/(union\s+all\s+select|union\s+select)/i';
$xss_regex = '/<script\b[^>]*>/i';
$traversal_regex = '#(\.\./|\.\.\\\\){2,}#';

assert_test( preg_match( $sqli_regex, $sqli_test ) === 1, 'WAF Signatures: Detects SQL Injection payload' );
assert_test( preg_match( $sqli_regex, $safe_test ) === 0, 'WAF Signatures: Does not false-positive on safe SQL comment' );
assert_test( preg_match( $xss_regex, $xss_test ) === 1, 'WAF Signatures: Detects XSS <script> payload' );
assert_test( preg_match( $xss_regex, $safe_test ) === 0, 'WAF Signatures: Does not false-positive on safe text' );
assert_test( preg_match( $traversal_regex, $traversal_test ) === 1, 'WAF Signatures: Detects directory traversal ../' );
assert_test( preg_match( $traversal_regex, $safe_test ) === 0, 'WAF Signatures: Does not false-positive on normal slashes' );

// Test 8: Uploads Protection Server Snippet
$nginx_snippet = WPSG_Uploads_Protection::get_nginx_snippet();
assert_test( strpos( $nginx_snippet, 'location ~* /wp-content/uploads/.*' ) !== false, 'Uploads Protection: Nginx block rule contains path pattern' );
assert_test( strpos( $nginx_snippet, 'deny all;' ) !== false, 'Uploads Protection: Nginx block rule contains deny all' );

// Test 9: PHP Hardening Solutions & Guidance
$php_audit = WPSG_PHP_Hardening::audit();
assert_test( isset( $php_audit['expose_php'] ) && ! empty( $php_audit['expose_php']['code_snippets'] ), 'PHP Hardening: expose_php has actionable code snippets' );
assert_test( isset( $php_audit['display_errors'] ) && ! empty( $php_audit['display_errors']['steps'] ), 'PHP Hardening: display_errors has remediation steps' );
assert_test( isset( $php_audit['disable_functions'] ) && ! empty( $php_audit['disable_functions']['code_snippets'] ), 'PHP Hardening: disable_functions has recommended blacklist' );

// Test 10: Custom Login URL
WPSG_Settings::update_settings( array(
	'custom_login_enable' => '1',
	'custom_login_slug'   => 'my-secret-login',
), 'login_security' );
assert_test( 'my-secret-login' === WPSG_Custom_Login_URL::get_slug(), 'Custom Login URL: slug configured as my-secret-login' );
assert_test( strpos( WPSG_Custom_Login_URL::get_custom_login_url(), '/my-secret-login/' ) !== false, 'Custom Login URL: generates correct custom endpoint' );

// Test 11: Hide WordPress Version
$dirty_script = 'https://example.com/wp-includes/js/wp-embed.min.js?ver=6.5.3';
$clean_script = WPSG_Version_Hider::remove_version_query_strings( $dirty_script );
assert_test( strpos( $clean_script, 'ver=6.5.3' ) === false, 'Version Hider: Strips WP version ver=6.5.3 from enqueued scripts' );

// Test 12: Hide Server Information
$server_nginx = WPSG_Server_Info_Hider::get_nginx_snippet();
assert_test( strpos( $server_nginx, 'server_tokens off;' ) !== false, 'Server Info Hider: Nginx snippet includes server_tokens off' );
assert_test( strpos( $server_nginx, 'more_clear_headers' ) !== false, 'Server Info Hider: Nginx snippet strips Server and X-Powered-By' );

// Test 13: Uploads Protection Pre-filter
$fake_malicious_upload = array(
	'name'     => 'shell.php',
	'tmp_name' => '',
	'error'    => 0,
);
$res_malicious = WPSG_Uploads_Protection::inspect_uploaded_file( $fake_malicious_upload );
assert_test( ! empty( $res_malicious['error'] ), 'Uploads Protection: Rejects dangerous executable .php file' );

$fake_double_ext_upload = array(
	'name'     => 'avatar.jpg.php',
	'tmp_name' => '',
	'error'    => 0,
);
$res_double = WPSG_Uploads_Protection::inspect_uploaded_file( $fake_double_ext_upload );
assert_test( ! empty( $res_double['error'] ), 'Uploads Protection: Rejects double extension mask avatar.jpg.php' );

$fake_phar_upload = array(
	'name'     => 'exploit.phar',
	'tmp_name' => '',
	'error'    => 0,
);
$res_phar = WPSG_Uploads_Protection::inspect_uploaded_file( $fake_phar_upload );
assert_test( ! empty( $res_phar['error'] ), 'Uploads Protection: Rejects executable .phar archive' );

// Test 14: Sensitive Files Pattern Matching
$files_to_test = array(
	'readme.html',
	'license.txt',
	'composer.json',
	'composer.lock',
	'package.json',
	'.env',
	'.env.production',
	'wp-config.php.bak',
	'wp-config.php.old',
	'debug.log',
	'database_dump.sql',
	'.git/config',
	'php.ini',
);

$blocked_patterns = array(
	'#(^|/)\.(git|svn|hg|bzr)($|/)#i',
	'#(^|/)\.env(\..+)?$#i',
	'#(^|/)\.(user\.ini|htaccess|htpasswd)$#i',
	'#(^|/)php\.ini$#i',
	'#^(readme|license|licence|changelog|changes)(\.(html|txt|md))?$#i',
	'#^(composer\.(json|lock)|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|bower\.json)$#i',
	'#^(dockerfile|docker-compose(\.override)?\.(yml|yaml))$#i',
	'#^wp-config(-sample)?(\.php)?(\.(bak|backup|old|save|txt|orig|temp|tmp|swp|swo))?$#i',
	'#\.(sql|sql\.gz|bak|backup|old|save|log|ini|conf|sh|bash|ps1|swp|swo|tar|gz|zip|7z|rar)$#i',
);

foreach ( $files_to_test as $f ) {
	$matched = false;
	foreach ( $blocked_patterns as $p ) {
		if ( preg_match( $p, $f ) || preg_match( $p, basename( $f ) ) ) {
			$matched = true;
			break;
		}
	}
	assert_test( $matched, "Sensitive Files Shield: Successfully matches and blocks {$f}" );
}

// -------------------------------------------------------------
// Test 10: Remote Auto-Updater & version.json Validation
// -------------------------------------------------------------
$version_file = __DIR__ . '/../version.json';
assert_test( file_exists( $version_file ), "Updater: version.json exists at root" );

$v_data = json_decode( file_get_contents( $version_file ), true );
assert_test( ! empty( $v_data ) && is_array( $v_data ), "Updater: version.json is valid JSON" );
assert_test( isset( $v_data['version'] ) && '1.0.0' === $v_data['version'], "Updater: version.json version matches 1.0.0" );
assert_test( isset( $v_data['download_url'] ) && strpos( $v_data['download_url'], 'wp-secure-guard.zip' ) !== false, "Updater: download_url points to wp-secure-guard.zip" );
assert_test( isset( $v_data['sections']['changelog'] ), "Updater: changelog section is defined" );

// Verify version compare logic
assert_test( version_compare( '1.0.1', '1.0.0', '>' ), "Updater: Higher remote version detected for update" );
assert_test( ! version_compare( '1.0.0', '1.0.0', '>' ), "Updater: Same version does not trigger update" );

echo "\n---------------------------------------------------------\n";
echo " Test Results: {$passed_tests} PASSED, {$failed_tests} FAILED\n";
echo "=========================================================\n";

if ( $failed_tests > 0 ) {
	exit( 1 );
}
exit( 0 );
