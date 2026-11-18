=== WP Secure Guard - Advanced Modular Security & Firewall ===
Contributors: wpsecureguard
Donate link: https://example.com/donate
Tags: security, firewall, 2fa, login security, user enumeration, waf, activity log
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protect your WordPress website against user enumeration, brute-force attacks, malicious requests, sensitive file leaks, and unauthorized access.

== Description ==

**WP Secure Guard** is an advanced, lightweight, and modular security plugin designed to safeguard your WordPress website without bloat or mandatory cloud dependencies.

Unlike monolithic security plugins that slow down your website or lock essential security features behind expensive subscriptions, WP Secure Guard provides **20 dedicated, modular security features** that you can independently enable, configure, or disable.

### Key Security Modules

#### 1. User & Author Protection
* **Author ID Enumeration Block**: Blocks automated bot scans exploiting `/?author=N` redirects to harvest usernames.
* **REST API User Endpoint Protection**: Restricts public `/wp/v2/users` endpoints to authenticated users only.
* **oEmbed Author Strip**: Filters author details and profile links from oEmbed responses.
* **Author Sitemap Restriction**: Disables the WordPress 5.5+ user sitemap (`wp-sitemap-users-1.xml`).
* **Public Author Archive Control**: Optionally disables author archive pages (`/author/{user}`) and redirects visitors safely.

#### 2. Login & Authentication Security
* **Brute-Force Rate Limiting**: Enforces strict attempt thresholds with customizable lockout durations and IP whitelisting.
* **Two-Factor Authentication (TOTP 2FA)**: Native RFC 6238 TOTP authentication compatible with Google Authenticator, Authy, Microsoft Authenticator, and 1Password with emergency recovery codes.
* **XML-RPC Protection**: Disable or restrict XML-RPC pingbacks and methods to eliminate DDoS amplification vectors.
* **Common Username Audit**: Identifies vulnerable administrative accounts using default usernames such as `admin`, `administrator`, or `root`.
* **Password Strength Policy**: Enforces strict password requirements (length, uppercase, lowercase, numbers, symbols) for all user roles.

#### 3. File & Server Hardening
* **Disable File Editor**: Verifies and enforces `DISALLOW_FILE_EDIT` to prevent code execution via the theme/plugin editor.
* **Uploads Directory PHP Execution Protection**: Prevents malicious execution of `.php`, `.phtml`, and script files uploaded to `/wp-content/uploads/`.
* **Sensitive Files Shield**: Blocks public web access to `wp-config.php`, `readme.html`, `license.txt`, `.git`, `.env`, and backup files.
* **Directory Listing Prevention**: Blocks directory browsing (`Options -Indexes`) across sensitive folders.
* **File Permissions Audit**: Inspects and audits filesystem permissions on vital WordPress core files and directories.

#### 4. Threat Monitoring & Audit
* **Application Firewall (WAF)**: Lightweight, zero-latency detection of SQL Injection (SQLi), Cross-Site Scripting (XSS), Directory Traversal, and suspicious user-agents. Offers "Monitor Only" and "Block" modes.
* **Core, Plugin & Theme Update Monitor**: Continuously highlights outdated components that pose severe security vulnerabilities.
* **PHP Environment Hardening Audit**: Audits PHP configuration directives (`expose_php`, `display_errors`, `allow_url_include`, dangerous functions).
* **Comprehensive Activity Log**: Records successful & failed logins, role modifications, profile updates, and firewall events with CSV export and automatic log retention.
* **Backup Status Health Check**: Confirms active backup routines and alerts administrators if backups are absent or outdated.

### Zero Tracking & Maximum Privacy
WP Secure Guard respects your privacy and website performance:
* No external tracking, telemetry, or third-party phone-home calls.
* Pure PHP & native WordPress APIs for fast execution.
* Clean uninstall option that removes all plugin tables and settings.

== Installation ==

1. Upload the `wp-secure-guard` folder to your `/wp-content/plugins/` directory, or install the plugin directly through the WordPress Plugins dashboard.
2. Activate the plugin through the **Plugins** menu in WordPress.
3. Navigate to **WP Secure Guard** in the WordPress admin menu to configure your modules.
4. Review the **Security Dashboard** to view your real-time security score and recommended actions.

== Frequently Asked Questions ==

= Does WP Secure Guard slow down my website? =
No. WP Secure Guard is built with performance as a top priority. Features only execute on relevant hooks, queries are optimized, and no external API calls or heavyweight scans run during frontend page requests.

= Will this plugin lock me out of my admin dashboard? =
We have implemented safe defaults:
1. You can whitelist your current IP address in the Login Security settings.
2. Two-Factor Authentication (2FA) includes one-time emergency backup codes.
3. Lockouts automatically expire after the configured duration.

= Does Upload PHP Protection work on Nginx? =
Writing `.htaccess` rules protects Apache and LiteSpeed servers out of the box. For Nginx servers, WP Secure Guard provides an exact server block snippet in the File Security tab that you can copy into your Nginx configuration.

= Can I use 2FA without an external paid service? =
Yes! WP Secure Guard implements the RFC 6238 standard TOTP natively. You can use standard free authenticator apps such as Google Authenticator, Microsoft Authenticator, Authy, or 1Password.

= What happens if I deactivate or uninstall the plugin? =
When deactivated, all security hooks stop immediately. When uninstalled, you can choose in Settings whether to preserve logs and options or execute a complete cleanup of all database tables and options.

== Screenshots ==

1. Security Overview Dashboard with real-time health score, active protections, and status matrix.
2. User Enumeration Protection module settings.
3. Login Security and Rate Limiting controls.
4. Two-Factor Authentication (TOTP) configuration with QR Code generator.
5. File and Server Security auditing tools.
6. Threat Monitoring, Application Firewall (WAF) logs, and PHP hardening audit.

== Changelog ==

= 1.0.1 =
* New: Added Cookie Security & Scanner Hardening module (WPSG_Cookie_Security) enforcing HttpOnly, SameSite (Lax/Strict), and Secure attributes across all outgoing HTTP cookies (resolving Netsparker, Invicti, Acunetix, and OWASP ZAP CWE-1004 / CWE-1275 findings on third-party cookies like icwp-wpsf-notbot).
* Fix: Added Direct Theme and Plugin Directory Execution Protection in .htaccess and PHP filter, completely eliminating HTTP 500 Internal Server Errors when vulnerability scanners or bots probe theme directories (e.g. /wp-content/themes/{theme}/) or raw template files.
* Fix: Streamlined and flattened repository architecture so that GitHub repository ZIP archives (WP-Secure-Guard-main.zip) install and activate seamlessly without "No valid plugins were found" or "invalid header" errors.
* New: Integrated native Remote Auto-Updater (WPSG_Updater) enabling 1-click update notifications directly in the WordPress admin dashboard across all client websites.

= 1.0.0 =
* Initial public release.
* Added 20 modular security features.
* Added native RFC 6238 TOTP Two-Factor Authentication.
* Added Brute-Force Rate Limiting with customizable thresholds and IP whitelisting.
* Added Application Firewall (WAF) with Monitor and Block modes.
* Added detailed Security Activity Log with CSV export.
* Added File Permissions and PHP hardening security audits.
* Added Custom Login URL cloaking (wp-admin / wp-login.php replacement) with emergency bypass failsafe.
* Added WordPress Version Cloaking across HTML head, asset query strings, and feeds.
* Added Server Information and Header Suppression (ServerSignature, Server, X-Powered-By).
* Added Malicious File Upload Pre-filter (blocking dangerous & double extensions, scanning for embedded PHP tags).
* Added Public User Registration controls and REST API user creation block.
* Added Sensitive Files Shield blocking readme.html, license.txt, composer.json, composer.lock, package.json, debug.log, and wp-config backups with HTTP 403 Forbidden.
* Fully compliant with WordPress.org coding and security standards.

== Upgrade Notice ==

= 1.0.0 =
Initial release of WP Secure Guard.
