# WP Secure Guard 🛡️

[![License: GPL-2.0-or-later](https://img.shields.io/badge/License-GPL%20v2%2B-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![WordPress](https://img.shields.io/badge/WordPress-%3E%3D%205.8-blue.svg)](https://wordpress.org/)
[![PHP Version](https://img.shields.io/badge/PHP-%3E%3D%207.4-8892BF.svg)](https://php.net/)
[![Tests](https://img.shields.io/badge/Tests-72%2F72%20Passing-brightgreen.svg)](tests/)

**WP Secure Guard** is an advanced, lightweight, modular WordPress security suite designed to protect websites against brute-force attacks, unauthorized user enumeration, malicious file uploads, information disclosure, and web exploits—without cloud lock-in, bloat, or third-party telemetry.

Every security feature is **independently configurable**, allowing site owners to enable only the protections they need.

---

## 🚀 Key Security Modules & Features

### 1. 👤 User & Author Protection
* **Author ID Enumeration Shield:** Blocks bot scans attempting `/?author=N` redirects to harvest WordPress usernames.
* **REST API User Protection:** Restricts public `/wp/v2/users` endpoints to authenticated users only.
* **oEmbed Author Stripping:** Removes author metadata and profile links from oEmbed responses.
* **Author Sitemap Restriction:** Disables public user sitemaps (`wp-sitemap-users-1.xml`).
* **Author Archives Control:** Disables author archive pages (`/author/{user}`) and redirects visitors safely.

### 2. 🔐 Login & Authentication Security
* **Custom Login URL (Cloak wp-login.php & wp-admin):** Changes the default login URL to a custom slug (e.g. `/login-controller/`), returning HTTP 404 to bots attempting direct access. Includes failsafe constant `WPSG_DISABLE_CUSTOM_LOGIN`.
* **Brute-Force Rate Limiting:** Enforces strict login attempt thresholds with customizable lockout durations and IP whitelisting.
* **Two-Factor Authentication (Native TOTP 2FA):** Vendor-independent RFC 6238 time-based one-time passwords compatible with Google Authenticator, Authy, Microsoft Authenticator, and 1Password, plus 8 emergency single-use backup recovery codes.
* **XML-RPC Shield:** Completely disables XML-RPC methods and removes pingback headers to eliminate DDoS reflection and multicall brute-force attacks.
* **Common Usernames Audit:** Scans for default administrator usernames (`admin`, `administrator`, `root`, etc.) and blocks registration of common usernames.
* **Password Strength Policy:** Enforces configurable password rules (minimum length, mixed case, numbers, symbols) across all user roles.
* **Public User Registration Control:** Disables public membership registration, blocks `action=register` endpoints with HTTP 403, and denies unauthenticated REST API user creation.

### 3. 📁 File & Server Hardening
* **Uploads Directory PHP Execution Protection:** Writes server-level deny rules into `/wp-content/uploads/.htaccess` for Apache/LiteSpeed, preventing `.php`, `.phtml`, and script execution.
* **Malicious File Upload Pre-Filter:** Real-time inspection before uploads are saved:
  * Rejects 26+ dangerous executable extensions (`php`, `phar`, `sh`, `exe`, `bat`, `cgi`, `py`, etc.).
  * Blocks double-extension masquerades (e.g. `avatar.jpg.php`, `shell.php.png`).
  * Scans binary chunks of media files for embedded PHP opening tags (`<?php`, `<?=`).
* **Sensitive Files Shield (HTTP 403 Forbidden):** Server-level `<FilesMatch>` protection and PHP-level interception blocking:
  * Information disclosure files: `readme.html`, `license.txt`, `changelog.txt`.
  * Developer & dependency manifests: `composer.json`, `composer.lock`, `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bower.json`.
  * Secrets & configurations: `.env`, `.env.*`, `wp-config*.bak`, `wp-config*.old`, `php.ini`, `.user.ini`.
  * System logs & backups: `debug.log`, `error_log`, `*.sql`, `*.sql.gz`, `*.tar`, `*.zip`.
* **Theme & Plugin File Editor Lockout:** Enforces `DISALLOW_FILE_EDIT` to prevent code execution via compromised admin accounts.
* **Directory Indexing Prevention:** Enforces `Options -Indexes` and places fallback `index.php` guard files.
* **File Permissions Audit:** Audits POSIX filesystem permissions against WordPress security benchmarks.

### 4. 🛡️ Threat Monitoring & System Hardening
* **Application Firewall (WAF):** Zero-latency real-time packet inspection defending against:
  * SQL Injection (SQLi)
  * Cross-Site Scripting (XSS)
  * Directory / Path Traversal (`../`)
  * Vulnerability scanners & malicious user-agents (`sqlmap`, `Nikto`, `Acunetix`, etc.)
  * Supports both **Block** (HTTP 403) and **Monitor Only** operating modes.
* **WordPress Core Version Cloaking:** Removes HTML generator meta tags, strips `?ver=` parameters from frontend assets matching WP core version, and filters RSS/Atom feed headers.
* **Server Info & Header Suppression:** Strips `Server` and `X-Powered-By` headers and enforces `ServerSignature Off`.
* **PHP Environment Hardening Audit:** Audits key directives (`expose_php`, `display_errors`, `disable_functions`) with interactive, one-click copyable remediation guides for `php.ini`, `.htaccess`, and `wp-config.php`.
* **Security Activity Audit Trail:** Tamper-resistant database logging of authentications, lockouts, firewall events, and role modifications with CSV export and configurable retention pruning.
* **Backup Solution Health Check:** Detects active backup plugins and warns if automated disaster recovery is missing.

---

## 📂 Project Structure

```text
WP-Secure-Guard/
├── build-zip.php                 # Cross-platform forward-slash ZIP packager
├── build-zip.ps1                 # PowerShell helper script
├── tests/
│   └── run-tests.php             # Standalone test runner (57 automated tests)
└── wp-secure-guard/              # Core plugin directory
    ├── wp-secure-guard.php       # Main plugin loader & metadata
    ├── uninstall.php             # GDPR & clean database uninstaller
    ├── readme.txt                # WordPress.org standard documentation
    ├── license.txt               # GNU General Public License v2
    ├── includes/
    │   ├── class-wpsg-loader.php
    │   ├── class-wpsg-activator.php
    │   ├── class-wpsg-deactivator.php
    │   ├── class-wpsg-settings.php
    │   ├── class-wpsg-logger.php
    │   └── class-wpsg-dashboard.php
    ├── modules/
    │   ├── user-enumeration/     # User protection modules (5 features)
    │   ├── login-security/       # Login security, 2FA & custom URL (7 features)
    │   ├── file-security/        # Uploads, sensitive files & permissions (5 features)
    │   └── monitoring/           # WAF, cloaking, logs & PHP audit (7 features)
    └── admin/
        ├── css/wpsg-admin.css    # Responsive admin dashboard styles
        ├── js/wpsg-admin.js      # AJAX toggles & UI interactions
        └── views/                # Modular tabbed admin views
```

---

## 💻 Installation

### Method 1: WordPress Dashboard (Recommended)
1. Download **`wp-secure-guard.zip`** from the latest release.
2. In your WordPress Admin, navigate to **Plugins &rarr; Add New Plugin &rarr; Upload Plugin**.
3. Select `wp-secure-guard.zip` and click **Install Now**.
4. Click **Activate Plugin**.
5. Go to **WP Secure Guard** in the sidebar menu to configure your settings.

### Method 2: Manual Directory Upload
1. Clone or download this repository.
2. Copy the `wp-secure-guard` folder into your site's `/wp-content/plugins/` directory.
3. Activate the plugin via **Plugins &rarr; Installed Plugins** in the WordPress admin.

---

## 🧪 Automated Testing

WP Secure Guard includes a standalone unit and integration test suite with minimal WordPress polyfills, enabling local CLI verification without requiring an active MySQL database:

```bash
php tests/run-tests.php
```

All 57 test suites test:
* Default settings verification
* Input sanitization & type casting
* Tab-scoped option updates & toggle state isolation
* RFC 6238 Base32 TOTP generation & verification
* Insecure username blacklists
* IP detection & proxy header resolution
* WAF attack signature regex patterns (SQLi, XSS, Path Traversal)
* Custom Login URL slug routing & link rewriting
* Upload inspection (extension blacklist, double extensions, embedded PHP bytecode)
* Sensitive file detection (`readme.html`, `license.txt`, `composer.json`, `.env`, `debug.log`)
* PHP hardening remediation data structures

---

## 📦 Building the Plugin ZIP

To create a 100% compliant ZIP package enforcing standard UNIX forward-slashes (`/`) for cross-platform WordPress compatibility:

```bash
php build-zip.php
```

---

## 🔄 Automatic Remote Updates Across All Client Websites

WP Secure Guard includes a built-in **Remote Auto-Updater** (`WPSG_Updater`) that connects to your GitHub repository or custom update server.

Whenever you install WP Secure Guard on any website, that site will automatically check for new releases and display native WordPress update notifications (`There is a new version of WP Secure Guard available`). Site administrators can update with a single click from their WordPress dashboard!

### How to Release an Update:
1. **Update Version:** Bump the version string in `wp-secure-guard/wp-secure-guard.php` (e.g. `1.0.1`) and in `version.json`.
2. **Build the ZIP:** Run `php build-zip.php`.
3. **Commit & Push:** Commit your changes to git and push to GitHub `main`.
4. **Create a GitHub Release:**
   * Go to your repository &rarr; **Releases** &rarr; **Draft a new release**.
   * Tag version: `v1.0.1`.
   * Attach `wp-secure-guard.zip` as a Release binary asset.
   * Click **Publish release**.
5. **Instant Distribution:** All connected WordPress sites will automatically detect the new version (or admins can click "Check for Updates" in their WP Secure Guard dashboard), display the WordPress update notice, and update in 1-click!

---

## 🔒 WordPress.org Standards Compliance

* **GPL-Compatible License:** Licensed under GPLv2 or later.
* **Zero External Telemetry:** Strictly no cloud tracking, phone-home APIs, or external script dependencies.
* **Security & Nonce Verification:** Every form submission verified via `check_admin_referer` and capability checks (`manage_options`).
* **Input Sanitization & Escaping:** Strict usage of `sanitize_text_field`, `sanitize_key`, `absint`, `esc_html`, `esc_attr`, and `esc_url`.
* **Safe Uninstallation:** Clean `uninstall.php` respecting the administrator's choice to retain or purge database tables.

---

## 📄 License

This project is licensed under the GNU General Public License v2.0 or later - see the [LICENSE](wp-secure-guard/license.txt) file for details.
