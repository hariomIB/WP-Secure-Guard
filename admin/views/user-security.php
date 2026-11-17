<?php
/**
 * View: User Protection Settings (Features 1-5).
 *
 * @package WP_Secure_Guard
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>

<form method="post" action="" class="wpsg-form">
	<?php wp_nonce_field( 'wpsg_save_settings_action', 'wpsg_save_nonce' ); ?>
	<input type="hidden" name="wpsg_save_settings" value="1" />
	<input type="hidden" name="wpsg_tab" value="user_security" />

	<div class="wpsg-card">
		<div class="wpsg-card-header">
			<h2>
				<span class="dashicons dashicons-admin-users"></span>
				<?php esc_html_e( 'User Protection & Anti-Enumeration', 'wp-secure-guard' ); ?>
			</h2>
			<p class="description">
				<?php esc_html_e( 'Prevent automated reconnaissance bots from harvesting WordPress login usernames before launching brute-force attacks.', 'wp-secure-guard' ); ?>
			</p>
		</div>

		<!-- Feature 1: Author ID Enumeration -->
		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[user_enum_block]" value="0" />
					<input type="checkbox" name="wpsg[user_enum_block]" value="1" <?php checked( $settings['user_enum_block'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( '1. Block Author ID Enumeration', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Blocks /?author=1, /?author=2 query scans. In default WordPress, visiting these URLs redirects to /author/username/, leaking login usernames to attackers.', 'wp-secure-guard' ); ?>
				</p>
				<span class="wpsg-pill wpsg-pill-recommended"><?php esc_html_e( 'Recommended', 'wp-secure-guard' ); ?></span>
			</div>
		</div>

		<!-- Feature 2: REST API User Protection -->
		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[rest_api_user_protect]" value="0" />
					<input type="checkbox" name="wpsg[rest_api_user_protect]" value="1" <?php checked( $settings['rest_api_user_protect'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( '2. Restrict REST API User Endpoint', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Restricts access to /wp-json/wp/v2/users so unauthenticated visitors cannot query the user list via REST API.', 'wp-secure-guard' ); ?>
				</p>
				<span class="wpsg-pill wpsg-pill-recommended"><?php esc_html_e( 'Recommended', 'wp-secure-guard' ); ?></span>
			</div>
		</div>

		<!-- Feature 3: oEmbed Information Filtering -->
		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[oembed_strip_author]" value="0" />
					<input type="checkbox" name="wpsg[oembed_strip_author]" value="1" <?php checked( $settings['oembed_strip_author'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( '3. Filter oEmbed Author Information', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Strips author_name and author_url from WordPress oEmbed responses, preventing third-party scrapers from linking content to author logins.', 'wp-secure-guard' ); ?>
				</p>
				<span class="wpsg-pill wpsg-pill-recommended"><?php esc_html_e( 'Recommended', 'wp-secure-guard' ); ?></span>
			</div>
		</div>

		<!-- Feature 4: Author Sitemap -->
		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[author_sitemap_disable]" value="0" />
					<input type="checkbox" name="wpsg[author_sitemap_disable]" value="1" <?php checked( $settings['author_sitemap_disable'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( '4. Disable Author XML Sitemap', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Removes the users sitemap provider (wp-sitemap-users-1.xml) from core XML sitemaps to prevent indexing user profile pages in Google and Bing.', 'wp-secure-guard' ); ?>
				</p>
				<span class="wpsg-pill wpsg-pill-recommended"><?php esc_html_e( 'Recommended', 'wp-secure-guard' ); ?></span>
			</div>
		</div>

		<!-- Feature 5: Public Author Profiles -->
		<div class="wpsg-setting-row">
			<div class="wpsg-setting-toggle">
				<label class="wpsg-switch">
					<input type="hidden" name="wpsg[author_archive_disable]" value="0" />
					<input type="checkbox" name="wpsg[author_archive_disable]" value="1" <?php checked( $settings['author_archive_disable'] ); ?> />
					<span class="wpsg-slider"></span>
				</label>
			</div>
			<div class="wpsg-setting-info">
				<h3 class="wpsg-setting-title"><?php esc_html_e( '5. Disable Public Author Archives', 'wp-secure-guard' ); ?></h3>
				<p class="wpsg-setting-text">
					<?php esc_html_e( 'Redirects all /author/{username} frontend pages to the homepage. Recommended for single-author blogs or business sites where author archives are unnecessary.', 'wp-secure-guard' ); ?>
				</p>
				<span class="wpsg-pill wpsg-pill-optional"><?php esc_html_e( 'Optional', 'wp-secure-guard' ); ?></span>
			</div>
		</div>

		<div class="wpsg-form-actions">
			<button type="submit" class="button button-primary button-large">
				<span class="dashicons dashicons-saved" style="vertical-align:text-bottom;margin-right:4px;"></span>
				<?php esc_html_e( 'Save User Protection Settings', 'wp-secure-guard' ); ?>
			</button>
		</div>
	</div>
</form>
