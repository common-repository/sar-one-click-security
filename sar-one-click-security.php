<?php
/**
 *
 * Plugin Name: SAR One Click Security
 * Plugin URI: http://www.samuelaguilera.com/archivo/protege-wordpress-facilmente.xhtml
 * Description: Adds some extra security to your WordPress with only one click.
 * Author: Samuel Aguilera
 * Version: 1.3
 * Author URI: http://www.samuelaguilera.com
 * Text Domain: sar-one-click-security
 * License: GPL3
 *
 * @package SAR One Click Security
 */

/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License version 3 as published by
the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

if ( ! defined( 'ABSPATH' ) ) {
	exit;
} // Not needed in this case, but maybe in the future...

// Current plugin version.
define( 'SAR_OCS_VER', '1.3' );

/**
 * Check if Apache 2.4.x is available.
 */
function sar_ocs_check_apache24() {

	$is_apache_24 = false;

	if ( isset( $_SERVER['SERVER_SOFTWARE'] ) ) {
		$is_apache_24 = strpos( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ), 'Apache/2.4' ) !== false ? true : false;
	}

	return $is_apache_24;
}

/**
 * Tasks to be done on init.
 */
function sar_ocs_init() {

	global $is_apache;

	// Load language file first.
	load_plugin_textdomain( 'sar-one-click-security', false, dirname( plugin_basename( __FILE__ ) ) . '/languages/' );

	// Notice was shown?
	$apache24_notice = get_option( 'sar_ocs_apache24_notice' );

	// Show Apache 2.4 notice only for Apache server users where notice was not shown previously.
	if ( $is_apache && false === $apache24_notice ) {
		/**
		 * Output message for non Apache users.
		 */
		function sar_apache24_notice() {
			// translators: %1$ and %2$ are <strong> and </strong> tags. %3$ and %4$ are <p> and </p> tags.
			$message = sprintf( esc_html__( '%3$s%1$sPlease note this version of SAR One Click Security drops support for Apache 2.2.x branch, only Apache 2.4.x servers are supported.%2$s%4$s %3$sThis is %1$sonly a notice%2$s, Apache 2.2.x EOL was reached on 2018-01-01, so if you are using any up to date hosting there is nothing to worry about. But if you are not sure of which Apache version are you using, please ask to your host support.%4$s', 'sar-one-click-security' ), '<strong>', '</strong>', '<p>', '</p>' );
			?>
			<div class="notice notice-warning is-dismissible">
			<p>
			<?php
			echo wp_kses(
				$message,
				array(
					'strong' => array(),
					'p'      => array(),
				)
			);
			?>
			</p>
			</div>
			<?php
		}

		add_action( 'admin_notices', 'sar_apache24_notice' );

		// Add option to prevent notice being show again.
		update_option( 'sar_ocs_apache24_notice', true );

	}

	// In a perfect world I would check for Apache/2.4 but the server could be configured to not disclose the version and therefore cause a false positive.
	if ( ! $is_apache ) {
		/**
		 * Output message for non Apache users.
		 */
		function sar_not_supported_server() {
				// translators: SAR One Click Security only supports Apache2 servers sounrounded by <strong> tags.
				$message = sprintf( esc_html__( '%1$sSAR One Click Security only supports Apache 2.4 servers%2$s. Your server is not supported, you should deactivate and delete this plugin.', 'sar-one-click-security' ), '<strong>', '</strong>' );
			?>
				<div class="notice notice-error">
				<p><?php echo wp_kses( $message, array( 'strong' => array() ) ); ?></p>
				</div>
				<?php
		}

		add_action( 'admin_notices', 'sar_not_supported_server' );

		return;

	}

	// Needs upgrade?
	$current_ver = get_option( 'sar_ocs_ver' );

	if ( false === $current_ver /* For older releases where SAR_OCS_VER was not introduced yet */ || version_compare( $current_ver, SAR_OCS_VER, '<' ) || '111' === $current_ver ) {

		/**
		 * Automatic update of rules removed for this release to give a chance to Apache 2.2.x users to uninstall the plugin.
		 */

		// Update current ver to DB.
		update_option( 'sar_ocs_ver', SAR_OCS_VER );

	}

}

add_action( 'admin_init', 'sar_ocs_init' );

/**
 * Tasks to be done on activation.
 */
function sar_ocs_activation() {

	global $is_apache;

	// In a perfect world I would check for Apache/2.4 but the server could be configured to not disclose the version and therefore cause a false positive.
	if ( $is_apache ) {
		// Adds current ver to DB.
		add_option( 'sar_ocs_ver', SAR_OCS_VER );

		// Install security rules.
		sar_add_security_rules();
	}

}

/**
 * Tasks to be done on deactivation.
 */
function sar_ocs_deactivation() {

	// Remove security rules.
	sar_remove_security_rules();

	// Remove options stored.
	delete_option( 'sar_ocs_ver' );
	delete_option( 'sar_ocs_wpc_htaccess' );
	delete_option( 'sar_ocs_apache24_notice' );
}

register_activation_hook( __FILE__, 'sar_ocs_activation' );
register_deactivation_hook( __FILE__, 'sar_ocs_deactivation' );

/**
 * Adds plugin rules to .htaccess file.
 */
function sar_add_security_rules() {

	// Path to .htaccess.
	$htaccess            = get_home_path() . '.htaccess';
	$wp_content_htaccess = WP_CONTENT_DIR . '/.htaccess';

	// WordPress domain.
	$wp_url    = get_bloginfo( 'wpurl' );
	$wp_url    = wp_parse_url( $wp_url );
	$wp_domain = preg_replace( '#^www\.(.+\.)#i', '$1', $wp_url['host'] ); // Only removes www from beginning, allowing domains that contains www on it.
	$wp_domain = explode( '.', $wp_domain );

	// Support for multisite subdomains.
	$domain_parts = count( $wp_domain );

	// Assumming domain is supported by default.
	$wp_domain_not_supported = false;

	if ( 2 === $domain_parts ) {
		$wp_domain_exploded = $wp_domain[0] . '\.' . $wp_domain[1];
	} elseif ( 3 === $domain_parts ) {
		$wp_domain_exploded = $wp_domain[0] . '\.' . $wp_domain[1] . '\.' . $wp_domain[2];
	} else {
		$wp_domain_not_supported = true; // for IP based URLs.
	}

	// Security rules.
	$sec_rules   = array();
	$sec_rules[] = "# Any decent hosting should have this set, but many don't have";
	$sec_rules[] = 'ServerSignature Off';
	$sec_rules[] = '<IfModule mod_autoindex.c>';
	$sec_rules[] = 'IndexIgnore *'; // Options -Indexes maybe is better, but some hostings doesn't allow the use of Options directives from .htaccess.
	$sec_rules[] = '</IfModule>';

	$sec_rules[] = '# Block access to sensitive files';
	// Use Apache 2.4 syntax. Apache 2.2 is no longer supported. https://httpd.apache.org/#apache-httpd-22-end-of-life-2018-01-01 .
	$sec_rules[] = '<Files .htaccess>';
	$sec_rules[] = 'Require all denied';
	$sec_rules[] = '</Files>';
	$sec_rules[] = '<FilesMatch "^(license\.txt|readme\.html|wp-config\.php|wp-config-sample\.php|install\.php)$">';
	$sec_rules[] = 'Require all denied';
	$sec_rules[] = '</FilesMatch>';

	$sec_rules[] = '# Stops dummy bots trying to register in WordPress sites that have registration disabled';
	$sec_rules[] = '<IfModule mod_rewrite.c>';
	$sec_rules[] = 'RewriteEngine On';
	$sec_rules[] = 'RewriteCond %{QUERY_STRING} ^action=register$ [NC,OR]';
	$sec_rules[] = 'RewriteCond %{HTTP_REFERER} ^.*registration=disabled$ [NC]';
	$sec_rules[] = 'RewriteRule (.*) - [F]';
	$sec_rules[] = '</IfModule>';

	if ( ! defined( 'SAR_ALLOW_TIMTHUMB' ) ) {
		$sec_rules[] = '# Block requests looking for timthumb.php';
		$sec_rules[] = '<IfModule mod_rewrite.c>';
		$sec_rules[] = 'RewriteEngine On';
		$sec_rules[] = 'RewriteRule ^(.*)/?timthumb\.php$ - [F]';
		$sec_rules[] = '</IfModule>';
	}

	$sec_rules[] = '# Block TRACE and TRACK request methods'; // TRACK is not availabe in Apache (without plugins) is a IIS method, but bots will try it anyway.
	$sec_rules[] = '<IfModule mod_rewrite.c>';
	$sec_rules[] = 'RewriteEngine On';
	$sec_rules[] = 'RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)$';
	$sec_rules[] = 'RewriteRule (.*) - [F]';
	$sec_rules[] = '</IfModule>';

	if ( ! $wp_domain_not_supported ) { // We don't want to add this if the domain is not supported...
		$sec_rules[] = '# Blocks direct posting to wp-comments-post.php/wp-login.php and black User Agent';
		$sec_rules[] = '<IfModule mod_rewrite.c>';
		$sec_rules[] = 'RewriteEngine On';
		$sec_rules[] = 'RewriteCond %{REQUEST_METHOD} ^(PUT|POST)$ [NC]';
		$sec_rules[] = 'RewriteCond %{REQUEST_URI} ^.(wp-comments-post|wp-login)\.php$ [NC]';
		$sec_rules[] = 'RewriteCond %{HTTP_REFERER} !^.*' . $wp_domain_exploded . '.*$ [OR]';
		$sec_rules[] = 'RewriteCond %{HTTP_USER_AGENT} ^$';
		$sec_rules[] = 'RewriteRule (.*) - [F]';
		$sec_rules[] = '</IfModule>';
	}

	// This may look like duplicated based on the above rule but it's not.
	$sec_rules[] = '# Block any query string trying to get a copy of wp-config.php file and gf_page=upload (deprecated on May 2015, update your copy of GF!).';
	$sec_rules[] = '<IfModule mod_rewrite.c>';
	$sec_rules[] = 'RewriteEngine On';
	$sec_rules[] = 'RewriteCond %{QUERY_STRING} ^.*=(.*wp-config\.php)|gf_page=upload$ [NC]';
	$sec_rules[] = 'RewriteRule (.*) - [F]';
	$sec_rules[] = '</IfModule>';

	// Block WPscan when using default user-agent.
	$sec_rules[] = '# Block WPscan by user-agent';
	$sec_rules[] = '<IfModule mod_rewrite.c>';
	$sec_rules[] = 'RewriteEngine On';
	$sec_rules[] = 'RewriteCond %{HTTP_USER_AGENT} WPScan';
	$sec_rules[] = 'RewriteRule (.*) http://127.0.0.1 [L,R=301]';
	$sec_rules[] = '</IfModule>';

	// Insert rules to existing .htaccess or create new file if no .htaccess is present.
	insert_with_markers( $htaccess, 'SAR One Click Security', $sec_rules );

	// Create .htacces for blocking direct access to PHP files in wp-content/ only if file .htaccess does not exists.
	$wpc_htaccess_exists = file_exists( $wp_content_htaccess );

	$wp_content_sec_rules   = array();
	$wp_content_sec_rules[] = '<FilesMatch "\.(php|php3|php5|php4|phtml)$">';
	$wp_content_sec_rules[] = 'Require all denied';
	$wp_content_sec_rules[] = '</FilesMatch>';

	// Block access to .txt files under any plugin/theme directory to prevent scans for installed plugins/themes.
	$wp_content_sec_rules[] = '<IfModule mod_rewrite.c>';
	$wp_content_sec_rules[] = 'RewriteEngine On';
	$wp_content_sec_rules[] = 'RewriteRule ^(themes|plugins)/(.*)/(.*)\.txt$ - [F]';
	$wp_content_sec_rules[] = '</IfModule>';

	if ( defined( 'SAR_ALLOW_TIMTHUMB' ) ) {
		$wp_content_sec_rules[] = '# Allow requests looking for TimThumb';
		$wp_content_sec_rules[] = '<FilesMatch "^(timthumb|thumb)\.php$">';
		$wp_content_sec_rules[] = 'Require all granted';
		$wp_content_sec_rules[] = '</FilesMatch>';
	}

	// Stores an option to be sure that if we delete the file on deactivation, it was created by the plugin.
	if ( ! $wpc_htaccess_exists ) {
		add_option( 'sar_ocs_wpc_htaccess', 'yes' );
	}

	// Insert rules to existing .htaccess or create new file if no .htaccess is present.
	insert_with_markers( $wp_content_htaccess, 'SAR One Click Security', $wp_content_sec_rules );

}

/**
 * Removes rules added by the plugin.
 */
function sar_remove_security_rules() {

	global $is_apache;

	if ( $is_apache ) {

		// Path to .htaccess.
		$htaccess            = get_home_path() . '.htaccess';
		$wp_content_htaccess = WP_CONTENT_DIR . '/.htaccess';

		$wp_content_htaccess_owned = get_option( 'sar_ocs_wpc_htaccess' );

		// Empty rules.
		$empty_sec_rules = array();
		// Remove rules. Markers will remain, but are only comments. TODO: Maybe create a new function to remove markers too.
		insert_with_markers( $htaccess, 'SAR One Click Security', $empty_sec_rules );

		if ( 'yes' === $wp_content_htaccess_owned ) {

			// Remove .htacces from wp-content that we have created.
			unlink( $wp_content_htaccess );
			delete_option( 'sar_ocs_wpc_htaccess' );

		} else { // If the file was there before the plugin.

			// Remove rules. Markers will remain, but are only comments. TODO: Maybe create a new function to remove markers too.
			insert_with_markers( $wp_content_htaccess, 'SAR One Click Security', $empty_sec_rules );

		}
	}

}

/**
 * Removes version information from being disclosed in page and syndication headers.
 *
 * @param string $type The type of generator to return.
 */
function sar_remove_wp_version( $type ) {

	switch ( $type ) {
		case 'html':
			$generator = '<meta name="generator" content="WordPress">';
			break;
		case 'xhtml':
			$generator = '<meta name="generator" content="WordPress" />';
			break;
		case 'atom':
			$generator = '<generator uri="https://wordpress.org/">WordPress</generator>';
			break;
		case 'rss2':
			$generator = '<generator>https://wordpress.org/</generator>';
			break;
		case 'rdf':
			$generator = '<admin:generatorAgent rdf:resource="https://wordpress.org/" />';
			break;
		case 'comment':
			$generator = '<!-- generator="WordPress" -->';
			break;
		// We don't need to remove the generator from exported files.
	}

	return $generator;
}

add_filter( 'get_the_generator', 'sar_remove_wp_version', 10, 2 );
