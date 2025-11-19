<?php
/**
 * Plugin Name: WordPress Password
 * Plugin URI: https://loopdash.com/
 * Description: Lightweight password protection plugin for staging WordPress sites. Returns 501 HTTP errors to prevent search engine indexing while allowing authorized access with a configurable password. Enhanced for WPEngine and managed hosting compatibility.
 * Version: 1.2.0
 * Author: Gery Brkospy
 * Author URI: mailto:gary@loopdash.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: loopdash-staging-protection
 * Domain Path: /languages
 * 
 * @package LoopdashStagingProtection
 * @author Gery Brkospy <gery@loopdash.com>
 * @copyright 2025 Loopdash
 * @license GPL v2 or later
 * 
 * This plugin is designed specifically for staging WordPress sites to:
 * - Prevent search engine indexing with 501 HTTP status codes
 * - Provide simple password-based access control
 * - Maintain a lightweight footprint
 * - Allow easy configuration through WordPress admin
 * 
 * Version 1.2.0 Enhancements:
 * - Added external CSS support for centralized style management
 * - Configurable CSS source (local file, external URL, or inline fallback)
 * - Support for Git repository or CDN hosted stylesheets
 * - Enhanced admin interface for CSS management
 * - Automatic fallback to inline styles if external CSS fails
 * 
 * Version 1.1.0 Enhancements:
 * - Fixed session handling for WPEngine and managed hosting providers
 * - Added transient-based authentication fallback for session reliability
 * - Improved redirect logic to prevent loops between frontend and admin
 * - Enhanced cache bypass headers for managed hosting environments
 * - Better IP detection for proxy environments (Cloudflare, etc.)
 * - Configurable session cookies with proper domain/path settings
 */

// Prevent direct access to this file
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('LSP_VERSION', '1.2.0');
define('LSP_PLUGIN_URL', plugin_dir_url(__FILE__));
define('LSP_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('LSP_PLUGIN_BASENAME', plugin_basename(__FILE__));

/**
 * Main plugin class for Loopdash Staging Protection
 * 
 * This class handles the core functionality including:
 * - Plugin activation/deactivation
 * - Session management
 * - Password verification
 * - Admin interface
 * - Frontend protection
 */
class LoopdashStagingProtection {
    
    /**
     * Plugin instance
     * @var LoopdashStagingProtection
     */
    private static $instance = null;
    
    /**
     * Session key for storing authentication status
     * @var string
     */
    private $session_key = 'lsp_authenticated';
    
    /**
     * Transient key for fallback authentication storage
     * @var string
     */
    private $transient_key = 'lsp_auth_';
    
    /**
     * Authentication timeout in seconds (2 hours)
     * @var int
     */
    private $auth_timeout = 7200;
    
    /**
     * Get plugin instance (Singleton pattern)
     * 
     * @return LoopdashStagingProtection
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor - Initialize the plugin
     */
    private function __construct() {
        $this->init();
    }
    
    /**
     * Initialize plugin hooks and functionality
     */
    private function init() {
        // Start session earlier for better hosting compatibility (especially WPEngine)
        add_action('plugins_loaded', array($this, 'start_session'), 1);
        
        // Add cache busting for all non-authenticated requests
        add_action('template_redirect', array($this, 'add_cache_busting'), 1);
        
        // Main protection hook - runs early to catch all requests
        add_action('init', array($this, 'check_protection'), 1);
        
        // Admin interface hooks
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        
        // Add admin bar indicator
        add_action('admin_bar_menu', array($this, 'add_admin_bar_indicator'), 999);
        add_action('admin_head', array($this, 'admin_bar_styles'));
        add_action('wp_head', array($this, 'admin_bar_styles'));
        
        // Handle login form submission
        add_action('wp_ajax_nopriv_lsp_login', array($this, 'handle_login'));
        add_action('wp_ajax_lsp_login', array($this, 'handle_login'));
        
        // Enqueue styles for login page
        add_action('wp_enqueue_scripts', array($this, 'enqueue_login_styles'), 1);
        add_action('login_enqueue_scripts', array($this, 'enqueue_login_styles'), 1);
        add_action('admin_enqueue_scripts', array($this, 'enqueue_login_styles'), 1);
    }
    
    /**
     * Add cache busting for non-authenticated requests
     * Forces fresh page loads to prevent cache issues
     */
    public function add_cache_busting() {
        // Skip if user is authenticated
        if ($this->is_user_authenticated()) {
            return;
        }
        
        // Skip for admin pages (they usually aren't cached)
        if (is_admin()) {
            return;
        }
        
        // Add cache busting headers immediately
        $this->set_cache_bypass_headers();
        
        // If this is a frontend request without cache busting parameter, redirect with one
        if (!isset($_GET['lsp_nocache']) && !isset($_POST['lsp_login_submit'])) {
            $current_url = home_url($_SERVER['REQUEST_URI'] ?? '');
            $separator = strpos($current_url, '?') !== false ? '&' : '?';
            $cache_bust_url = $current_url . $separator . 'lsp_nocache=' . time();
            
            wp_redirect($cache_bust_url);
            exit;
        }
    }
    
    /**
     * Start PHP session if not already started
     * Required for tracking authentication status across requests
     * Includes hosting-specific configurations for WPEngine compatibility
     */
    public function start_session() {
        if (!session_id()) {
            // Configure session for better hosting compatibility
            $this->configure_session_settings();
            session_start();
        }
    }
    
    /**
     * Configure session settings for managed hosting compatibility
     * Addresses WPEngine and similar hosting provider session issues
     */
    private function configure_session_settings() {
        // Only configure if session hasn't started yet
        if (session_status() === PHP_SESSION_NONE) {
            // Set session cookie parameters for cross-domain compatibility
            $domain = $this->get_session_domain();
            $secure = is_ssl();
            $httponly = true;
            $samesite = 'Lax'; // Better compatibility than 'Strict'
            
            // Set session cookie parameters
            session_set_cookie_params([
                'lifetime' => 0, // Session cookie (expires when browser closes)
                'path' => '/',
                'domain' => $domain,
                'secure' => $secure,
                'httponly' => $httponly,
                'samesite' => $samesite
            ]);
            
            // Set session name to avoid conflicts
            session_name('lsp_session');
            
            // Configure session for managed hosting
            ini_set('session.cookie_httponly', 1);
            ini_set('session.use_only_cookies', 1);
            ini_set('session.cookie_samesite', $samesite);
        }
    }
    
    /**
     * Get appropriate session domain for current site
     * Handles subdomain and main domain scenarios
     */
    private function get_session_domain() {
        $host = $_SERVER['HTTP_HOST'] ?? '';
        
        // For localhost development
        if (strpos($host, 'localhost') !== false || strpos($host, '127.0.0.1') !== false) {
            return '';
        }
        
        // For managed hosting, use the full domain
        // This ensures sessions work across frontend and admin
        return $host;
    }
    
    /**
     * Check if user is authenticated using session or fallback method
     * Provides redundancy for hosting environments where sessions are unreliable
     */
    private function is_user_authenticated() {
        // First, try session-based authentication
        if (isset($_SESSION[$this->session_key]) && $_SESSION[$this->session_key] === true) {
            return true;
        }
        
        // Fallback: Check transient-based authentication
        $auth_key = $this->get_auth_transient_key();
        $is_authenticated = get_transient($auth_key);
        
        if ($is_authenticated === 'authenticated') {
            // If transient exists but session doesn't, sync them
            $_SESSION[$this->session_key] = true;
            return true;
        }
        
        return false;
    }
    
    /**
     * Set user as authenticated using both session and transient
     * Provides redundancy for hosting environments where sessions are unreliable
     */
    private function set_user_authenticated() {
        // Set session authentication
        $_SESSION[$this->session_key] = true;
        
        // Set transient fallback authentication
        $auth_key = $this->get_auth_transient_key();
        set_transient($auth_key, 'authenticated', $this->auth_timeout);
    }
    
    /**
     * Clear user authentication from both session and transient
     */
    private function clear_user_authentication() {
        // Clear session
        if (isset($_SESSION[$this->session_key])) {
            unset($_SESSION[$this->session_key]);
        }
        
        // Clear transient
        $auth_key = $this->get_auth_transient_key();
        delete_transient($auth_key);
    }
    
    /**
     * Generate unique transient key based on user's IP and user agent
     * Provides reasonable security while maintaining functionality
     */
    private function get_auth_transient_key() {
        $ip = $this->get_client_ip();
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        // Use AUTH_SALT if available, fallback to ABSPATH for early execution compatibility
        $salt = defined('NONCE_SALT') ? NONCE_SALT : (defined('AUTH_SALT') ? AUTH_SALT : ABSPATH);
        $unique_id = md5($ip . $user_agent . $salt);
        return $this->transient_key . substr($unique_id, 0, 12);
    }
    
    /**
     * Get client IP address with proxy support
     * Handles various proxy headers used by managed hosting providers
     */
    private function get_client_ip() {
        // Check for various proxy headers
        $headers = [
            'HTTP_CF_CONNECTING_IP',     // Cloudflare
            'HTTP_X_FORWARDED_FOR',      // General proxy
            'HTTP_X_FORWARDED',          // General proxy
            'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster
            'HTTP_FORWARDED_FOR',        // General proxy
            'HTTP_FORWARDED',            // General proxy
            'REMOTE_ADDR'                // Standard
        ];
        
        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                // Handle comma-separated IPs (take first one)
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                // Validate IP
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        // Fallback to REMOTE_ADDR even if it's a private IP
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }
    
    /**
     * Set cache bypass headers for managed hosting providers
     * Prevents caching of login page on WPEngine and similar hosts
     */
    private function set_cache_bypass_headers() {
        // Only set headers if they haven't been sent yet
        if (headers_sent()) {
            return;
        }
        
        // Aggressive cache control headers
        header('Cache-Control: no-cache, no-store, must-revalidate, max-age=0, private');
        header('Pragma: no-cache');
        header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
        
        // WPEngine specific headers
        header('X-Cache-Control: no-cache');
        header('X-WPE-Debug: staging-protection-no-cache');
        header('X-WPE-Cache-Status: BYPASS');
        
        // Cloudflare bypass (often used with WPEngine)
        header('CF-Cache-Status: BYPASS');
        header('CF-Cache-Control: no-cache');
        
        // Varnish cache bypass
        header('X-Cacheable: NO');
        header('X-Cache-Status: BYPASS');
        
        // General proxy cache bypass
        header('Surrogate-Control: no-store');
        
        // Vary header to prevent shared caching
        header('Vary: Cookie, Authorization, X-Forwarded-Proto');
        
        // Additional cache busting headers
        header('X-Accel-Expires: 0');
        header('X-Frame-Options: SAMEORIGIN');
        
        // Force revalidation
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s') . ' GMT');
        header('ETag: "' . md5(microtime()) . '"');
    }
    
    /**
     * Main protection logic - checks if user is authenticated
     * Returns 501 HTTP status for unauthorized access to prevent indexing
     * PROTECTS EVERYTHING: Frontend, admin, login pages - everything requires the password
     */
    public function check_protection() {
        // Check if protection is enabled
        $options = $this->get_options();
        if (!$options['protection_enabled']) {
            return; // Protection is disabled - allow normal access
        }
        
        // FORCE CACHE BYPASS: Add aggressive cache bypass headers immediately
        $this->set_cache_bypass_headers();
        
        // Force no-cache for this request to prevent caching issues
        if (!headers_sent()) {
            header('Cache-Control: no-cache, no-store, must-revalidate, max-age=0, private');
            header('Pragma: no-cache');
            header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
            header('X-WPE-Debug: staging-protection-active');
            header('Vary: Cookie, Authorization');
        }
        
        // Allow administrators to bypass protection (optional - uncomment to enable)
        // if (current_user_can('administrator')) {
        //     return;
        // }
        
        // TEMPORARY: Allow bypassing protection with special URL parameter
        // Remove this in production or add IP restrictions
        if (isset($_GET['lsp_disable']) && $_GET['lsp_disable'] === 'temp_admin_access') {
            return;
        }
        
        // ONLY skip protection for AJAX requests to avoid breaking functionality
        if (defined('DOING_AJAX') && DOING_AJAX) {
            return;
        }
        
        // Handle logout parameter (for testing purposes - only if already authenticated)
        if (isset($_GET['lsp_logout'])) {
            $this->clear_user_authentication();
            wp_redirect(remove_query_arg('lsp_logout'));
            exit;
        }
        
        // Skip protection for login form submission (handle it in show_login_page)
        if (isset($_POST['lsp_login_submit'])) {
            $this->show_login_page();
            return;
        }
        
        // Check if user is authenticated via our session or fallback method
        if ($this->is_user_authenticated()) {
            return; // User is authenticated - allow access to everything
        }
        
        // User not authenticated - show login page with 501 status
        // This blocks EVERYTHING: frontend, admin, wp-login.php, everything
        $this->show_login_page();
    }
    
    /**
     * Display the custom login page
     * Sets 501 HTTP status to prevent search engine indexing
     * Includes cache bypass headers for managed hosting
     */
    private function show_login_page() {
        // Set 501 HTTP status code (Not Implemented)
        // This prevents search engines from indexing the staging site
        http_response_code(501);
        
        // Add cache bypass headers for managed hosting providers
        $this->set_cache_bypass_headers();
        
        // Get configuration options
        $options = $this->get_options();
        $site_title = get_bloginfo('name');
        
        // Handle login form submission
        $error_message = '';
        if (isset($_POST['lsp_login_submit'])) {
            $error_message = $this->process_login($_POST['lsp_password'] ?? '');
        }
        
        // Output the login page HTML
        $this->render_login_page($site_title, $options, $error_message);
        exit;
    }
    
    /**
     * Process login form submission
     * 
     * @param string $submitted_password The password submitted by user
     * @return string Error message if login fails, empty string if success
     */
    private function process_login($submitted_password) {
        $options = $this->get_options();
        $correct_password = $options['password'];
        
        if ($submitted_password === $correct_password) {
            // Password correct - set authentication and redirect
            $this->set_user_authenticated();
            
            // Improved redirect logic to prevent loops
            $redirect_url = $this->get_safe_redirect_url();
            wp_redirect($redirect_url);
            exit;
        } else {
            // Password incorrect - return error message
            return $options['error_message'];
        }
    }
    
    /**
     * Get safe redirect URL to prevent loops and handle different contexts
     * Addresses issues with frontend/admin redirect loops on managed hosting
     */
    private function get_safe_redirect_url() {
        // If we have a specific return URL from the form, use it (but validate it's safe)
        if (isset($_POST['return_to']) && !empty($_POST['return_to'])) {
            $return_url = sanitize_url($_POST['return_to']);
            if ($this->is_safe_redirect_url($return_url)) {
                return home_url($return_url);
            }
        }
        
        // If we have a specific return URL from GET, use it (but validate it's safe)
        if (isset($_GET['return_to']) && !empty($_GET['return_to'])) {
            $return_url = sanitize_url($_GET['return_to']);
            if ($this->is_safe_redirect_url($return_url)) {
                return $return_url;
            }
        }
        
        // If we came from admin area, return to admin
        $referer = wp_get_referer();
        if ($referer && strpos($referer, '/wp-admin/') !== false) {
            return admin_url();
        }
        
        // If current request is for admin, return to admin
        if (is_admin() || strpos($_SERVER['REQUEST_URI'] ?? '', '/wp-admin/') !== false) {
            return admin_url();
        }
        
        // Default to home URL for frontend requests
        return home_url();
    }
    
    /**
     * Check if a redirect URL is safe (same domain)
     */
    private function is_safe_redirect_url($url) {
        $parsed_url = parse_url($url);
        $current_host = $_SERVER['HTTP_HOST'] ?? '';
        
        // Only allow redirects to same domain
        return isset($parsed_url['host']) && $parsed_url['host'] === $current_host;
    }
    
    /**
     * Render the login page HTML
     * 
     * @param string $site_title WordPress site title
     * @param array $options Plugin configuration options
     * @param string $error_message Error message to display (if any)
     */
    private function render_login_page($site_title, $options, $error_message = '') {
        ?>
        <!DOCTYPE html>
        <html <?php language_attributes(); ?>>
        <head>
            <meta charset="<?php bloginfo('charset'); ?>">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta name="robots" content="noindex, nofollow">
            <title><?php echo esc_html($site_title); ?> - Staging Access</title>
            <?php $this->output_login_styles(); ?>
        </head>
        <body class="lsp-login-body">
            <div class="lsp-login-container">
                <div class="lsp-login-form">
                    <h1 class="lsp-site-title">View <?php echo esc_html($site_title); ?></h1>
                    
                    <div class="lsp-login-message">
                        <?php echo wp_kses_post($options['login_message']); ?>
                    </div>
                    
                    <?php if (!empty($error_message)): ?>
                        <div class="lsp-error-message">
                            <?php echo esc_html($error_message); ?>
                        </div>
                    <?php endif; ?>
                    
                    <form method="post" class="lsp-login-form-inner">
                        <!-- Hidden field to preserve current URL for redirect -->
                        <input type="hidden" name="return_to" value="<?php echo esc_attr($_SERVER['REQUEST_URI'] ?? ''); ?>">
                        
                        <!-- Cache busting field to prevent caching issues -->
                        <input type="hidden" name="lsp_cache_bust" value="<?php echo time(); ?>">
                        
                        <div class="lsp-input-group">
                            <input 
                                type="password" 
                                id="lsp_password" 
                                name="lsp_password" 
                                class="lsp-input" 
                                placeholder="Enter password"
                                required 
                                autocomplete="current-password"
                                autofocus
                                style="text-align: center;"
                            >
                        </div>
                        
                        <button type="submit" name="lsp_login_submit" class="lsp-submit-btn">
                            View Site
                        </button>
                    </form>
                    
                    <div class="lsp-footer">
                        <p>Made by <a href="https://loopdash.com/" target="_blank" rel="noopener">Loopdash</a></p>
                    </div>
                </div>
            </div>
        </body>
        </html>
        <?php
    }
    
    /**
     * Output CSS styles for the login page
     * Loads appropriate CSS based on configuration
     */
    private function output_login_styles() {
        $options = $this->get_options();
        $css_source = $options['css_source'] ?? 'local';
        
        echo '<style type="text/css">' . "\n";
        
        if ($css_source === 'external' && !empty($options['external_css_url'])) {
            // For external CSS, we need to output a link tag since we're not in normal WP context
            echo '</style>' . "\n";
            echo '<link rel="stylesheet" href="' . esc_url($options['external_css_url']) . '?v=' . esc_attr($options['css_version'] ?? LSP_VERSION) . '" type="text/css" media="all" />' . "\n";
            
            // Debug info when WP_DEBUG is enabled
            if (defined('WP_DEBUG') && WP_DEBUG) {
                echo '<!-- LSP External CSS Debug: Loading from ' . esc_html($options['external_css_url']) . ' -->' . "\n";
            }
        } else {
            // For local CSS, read the file and output inline styles
            $css_file_path = LSP_PLUGIN_PATH . 'assets/css/login-styles.css';
            
            if (file_exists($css_file_path)) {
                $css_content = file_get_contents($css_file_path);
                echo $css_content;
                
                // Debug info when WP_DEBUG is enabled
                if (defined('WP_DEBUG') && WP_DEBUG) {
                    echo "\n" . '/* LSP Local CSS Debug: Loaded from ' . $css_file_path . ' */' . "\n";
                }
            } else {
                // Fallback: basic styling if CSS file is missing
                echo $this->get_basic_fallback_css();
                
                // Debug info when WP_DEBUG is enabled
                if (defined('WP_DEBUG') && WP_DEBUG) {
                    echo "\n" . '/* LSP Local CSS Debug: File not found at ' . $css_file_path . ', using fallback CSS */' . "\n";
                }
            }
            
            echo '</style>' . "\n";
        }
    }
    
    /**
     * Add admin menu page for plugin settings
     */
    public function add_admin_menu() {
        add_management_page(
            'Staging Protection Settings',
            'Staging Protection',
            'manage_options',
            'loopdash-staging-protection',
            array($this, 'admin_page')
        );
    }
    
    /**
     * Add staging protection indicator to admin bar
     */
    public function add_admin_bar_indicator($wp_admin_bar) {
        if (!is_admin_bar_showing()) {
            return;
        }
        
        $options = $this->get_options();
        $protection_enabled = $options['protection_enabled'];
        
        if ($protection_enabled) {
            $title = 'STAGING PROTECTED';
            $css_class = 'lsp-protected';
        } else {
            $title = 'STAGING NOT PROTECTED';
            $css_class = 'lsp-not-protected';
        }
        
        $wp_admin_bar->add_node(array(
            'id' => 'lsp-staging-protection',
            'title' => $title,
            'href' => admin_url('tools.php?page=loopdash-staging-protection'),
            'meta' => array(
                'title' => 'Staging Protection Status - Click to manage settings',
                'class' => $css_class
            )
        ));
    }
    
    /**
     * Add styles for admin bar indicator
     */
    public function admin_bar_styles() {
        if (!is_admin_bar_showing()) {
            return;
        }
        ?>
        <style>
        /* Protected status - Green background */
        #wp-admin-bar-lsp-staging-protection.lsp-protected > .ab-item {
            background: #27ae60 !important;
            color: #ffffff !important;
            font-weight: bold !important;
        }
        
        #wp-admin-bar-lsp-staging-protection.lsp-protected > .ab-item:hover {
            background: #219a52 !important;
            color: #ffffff !important;
        }
        
        /* Not protected status - Red background */
        #wp-admin-bar-lsp-staging-protection.lsp-not-protected > .ab-item {
            background: #e74c3c !important;
            color: #ffffff !important;
            font-weight: bold !important;
        }
        
        #wp-admin-bar-lsp-staging-protection.lsp-not-protected > .ab-item:hover {
            background: #c0392b !important;
            color: #ffffff !important;
        }
        </style>
        <?php
    }
    
    /**
     * Register plugin settings with WordPress
     */
    public function register_settings() {
        register_setting('lsp_settings', 'lsp_options', array($this, 'sanitize_options'));
        
        add_settings_section(
            'lsp_main_section',
            'Staging Protection Configuration',
            array($this, 'section_callback'),
            'lsp_settings'
        );
        
        add_settings_field(
            'password',
            'Access Password',
            array($this, 'password_field_callback'),
            'lsp_settings',
            'lsp_main_section'
        );
        
        add_settings_field(
            'protection_enabled',
            'Protection Status',
            array($this, 'protection_enabled_field_callback'),
            'lsp_settings',
            'lsp_main_section'
        );
        
        add_settings_field(
            'login_message',
            'Login Page Message',
            array($this, 'login_message_field_callback'),
            'lsp_settings',
            'lsp_main_section'
        );
        
        add_settings_field(
            'error_message',
            'Failed Login Message',
            array($this, 'error_message_field_callback'),
            'lsp_settings',
            'lsp_main_section'
        );
        
        add_settings_field(
            'css_source',
            'CSS Source',
            array($this, 'css_source_field_callback'),
            'lsp_settings',
            'lsp_main_section'
        );
        
        add_settings_field(
            'external_css_url',
            'External CSS URL',
            array($this, 'external_css_url_field_callback'),
            'lsp_settings',
            'lsp_main_section'
        );
        
        add_settings_field(
            'css_version',
            'CSS Version',
            array($this, 'css_version_field_callback'),
            'lsp_settings',
            'lsp_main_section'
        );
    }
    
    /**
     * Sanitize and validate plugin options
     * 
     * @param array $input Raw input from settings form
     * @return array Sanitized options
     */
    public function sanitize_options($input) {
        $sanitized = array();
        
        // Sanitize password (allow any characters but trim whitespace)
        $sanitized['password'] = isset($input['password']) ? trim($input['password']) : 'ShapeTomorrow';
        
        // Sanitize messages (allow HTML but escape dangerous content)
        $sanitized['login_message'] = isset($input['login_message']) ? wp_kses_post($input['login_message']) : '';
        $sanitized['error_message'] = isset($input['error_message']) ? sanitize_text_field($input['error_message']) : '';
        
        // Sanitize CSS source
        $valid_css_sources = array('local', 'external');
        $sanitized['css_source'] = isset($input['css_source']) && in_array($input['css_source'], $valid_css_sources) 
            ? $input['css_source'] 
            : 'local';
        
        // Sanitize external CSS URL
        $sanitized['external_css_url'] = isset($input['external_css_url']) ? esc_url_raw($input['external_css_url']) : '';
        
        // Sanitize CSS version
        $sanitized['css_version'] = isset($input['css_version']) ? sanitize_text_field($input['css_version']) : LSP_VERSION;
        
        // Sanitize protection enabled
        $sanitized['protection_enabled'] = isset($input['protection_enabled']) ? (bool) $input['protection_enabled'] : false;
        
        // Ensure password is not empty
        if (empty($sanitized['password'])) {
            $sanitized['password'] = 'ShapeTomorrow';
            add_settings_error('lsp_options', 'empty_password', 'Password cannot be empty. Reset to default.');
        }
        
        // Validate external CSS URL if external source is selected
        if ($sanitized['css_source'] === 'external' && empty($sanitized['external_css_url'])) {
            add_settings_error('lsp_options', 'empty_css_url', 'External CSS URL is required when using external CSS source.');
            $sanitized['css_source'] = 'local'; // Fallback to local
        }
        
        return $sanitized;
    }
    
    /**
     * Get plugin options with defaults
     * 
     * @return array Plugin options
     */
    private function get_options() {
        $defaults = array(
            'password' => 'ShapeTomorrow',
            'login_message' => 'This is a staging environment. Please enter the access password to continue.',
            'error_message' => 'Incorrect password. Please try again.',
            'css_source' => 'external',
            'external_css_url' => 'https://cdn.jsdelivr.net/gh/loopdash/wp-password@main/assets/css/login-styles.css',
            'css_version' => LSP_VERSION,
            'protection_enabled' => false
        );
        
        $options = get_option('lsp_options', array());
        return wp_parse_args($options, $defaults);
    }
    
    /**
     * Display admin settings page
     */
    public function admin_page() {
        $session_status = isset($_SESSION[$this->session_key]) ? 'Authenticated' : 'Not authenticated';
        $options = $this->get_options();
        ?>
        <div class="wrap">
            <h1>Loopdash Staging Protection</h1>
            
            <!-- Two Column Layout: Settings and Info -->
            <div class="lsp-two-column-layout">
                <!-- Left Column: Settings Form -->
                <div class="lsp-settings-section lsp-left-column">
                    <form method="post" action="options.php" class="lsp-settings-form">
                        <?php
                        settings_fields('lsp_settings');
                        do_settings_sections('lsp_settings');
                        ?>
                        <div class="lsp-form-actions">
                            <?php submit_button('Save Settings', 'primary', 'submit', false); ?>
                        </div>
                    </form>
                </div>
                
                <!-- Right Column: Plugin Information -->
                <div class="lsp-info-section lsp-right-column">
                    <h2>Plugin Information</h2>
                    <!-- Emergency Access Card -->
                    <div class="lsp-status-card">
                        <div class="lsp-card-header">
                            <span class="lsp-card-icon">🆘</span>
                            <h3>Emergency Access</h3>
                        </div>
                        <div class="lsp-card-content">
                            <p>If locked out, add this to any URL:</p>
                            <code class="lsp-emergency-code">?lsp_disable=temp_admin_access</code>
                        </div>
                    </div>
                    
                    <!-- How it works -->
                    <div class="lsp-features-list">
                        <h3>How it works:</h3>
                        <ul>
                            <li><strong>Total Protection:</strong> Blocks access to frontend, admin, and all WordPress pages</li>
                            <li><strong>SEO Blocking:</strong> Returns 501 HTTP status codes to prevent search engine indexing</li>
                            <li><strong>Password Authentication:</strong> Requires password to access ANY part of the site</li>
                            <li><strong>Session-Based:</strong> Users stay logged in until browser closes</li>
                            <li><strong>Full Access:</strong> Once authenticated, complete WordPress functionality</li>
                        </ul>
                    </div>

                    <!-- Plugin Details Group -->
                    <div class="lsp-plugin-details">
                        <div class="lsp-info-item">
                            <h3>Protection Status</h3>
                            <?php $options = $this->get_options(); ?>
                            <?php if ($options['protection_enabled']): ?>
                                <p style="color: #27ae60; font-weight: bold;">✅ STAGING PROTECTION ENABLED</p>
                                <p>Site is protected with password authentication.</p>
                            <?php else: ?>
                                <p style="color: #e74c3c; font-weight: bold;">❌ STAGING PROTECTION DISABLED</p>
                                <p>Site is accessible without password (normal WordPress behavior).</p>
                            <?php endif; ?>
                        </div>
                        
                        <div class="lsp-info-item">
                            <h3>CSS Configuration</h3>
                            <p><strong>Current CSS Source:</strong> <?php echo ucfirst($options['css_source']); ?></p>
                            <?php if ($options['css_source'] === 'external' && !empty($options['external_css_url'])): ?>
                                <p><strong>External CSS URL:</strong><br>
                                <code style="word-break: break-all;"><?php echo esc_html($options['external_css_url']); ?></code></p>
                            <?php endif; ?>
                            <p><strong>CSS Version:</strong> <?php echo esc_html($options['css_version']); ?></p>
                        </div>
                        
                        <div class="lsp-info-item">
                            <div class="lsp-logo-container">
                                <svg class="logo" width="164" height="21" viewBox="0 0 205 28" fill="none" xmlns="http://www.w3.org/2000/svg"><path class="logo-path logo-mark" d="M0.285889 1.28564H6.51599C6.51599 5.43904 6.51599 9.17711 6.51599 12.4998C6.51599 13.5556 6.51599 15.217 6.51599 17.4839H11.5001H22.7143V23.714C20.2222 23.714 16.4841 23.714 11.5001 23.714C8.91562 23.714 5.17756 23.714 0.285889 23.714C0.285889 18.502 0.285889 14.764 0.285889 12.4998C0.285889 7.51575 0.285889 3.77768 0.285889 1.28564Z" fill="#000000"></path><path class="logo-path logo-mark" d="M22.7144 15.6147H16.4843C16.4843 15.6147 16.4843 14.5764 16.4843 12.4997C16.4843 11.7104 16.4843 10.049 16.4843 7.51561L11.5002 7.51561H8.38529V1.28551C8.38529 1.28551 9.42358 1.28551 11.5002 1.28551C14.0459 1.28551 17.784 1.28551 22.7144 1.28551C22.7144 6.32335 22.7144 10.0614 22.7144 12.4997C22.7144 14.5764 22.7144 15.6147 22.7144 15.6147Z" fill="#000000"></path><path class="logo-path logo-text" d="M200.417 23.7955V0.880371H205V23.7955H200.417ZM185.98 23.7955V0.880371H190.563V23.7955H185.98ZM189.974 13.942V10.2428H201.17V13.942H189.974Z" fill="#000000"></path><path class="logo-path logo-text" d="M174.083 24.1885C172.424 24.1885 170.94 23.9048 169.631 23.3374C168.343 22.77 167.317 21.9407 166.553 20.8495C165.79 19.7583 165.397 18.4379 165.375 16.8885H170.22C170.242 17.5432 170.405 18.1324 170.711 18.6562C171.038 19.18 171.486 19.5946 172.053 19.9001C172.621 20.2057 173.286 20.3585 174.05 20.3585C174.727 20.3585 175.305 20.2493 175.785 20.0311C176.287 19.8129 176.669 19.5073 176.931 19.1145C177.214 18.7217 177.356 18.2415 177.356 17.6741C177.356 17.063 177.193 16.5393 176.865 16.1028C176.56 15.6663 176.134 15.2953 175.589 14.9898C175.043 14.6842 174.41 14.4114 173.69 14.1714C172.992 13.9095 172.239 13.6476 171.431 13.3857C169.62 12.7965 168.234 12.0108 167.274 11.0287C166.335 10.0467 165.866 8.73722 165.866 7.10043C165.866 5.7037 166.193 4.5143 166.848 3.53223C167.525 2.55015 168.452 1.79723 169.631 1.27345C170.831 0.749679 172.184 0.487793 173.69 0.487793C175.239 0.487793 176.603 0.760591 177.782 1.30619C178.96 1.82996 179.888 2.5938 180.564 3.5977C181.263 4.6016 181.634 5.791 181.677 7.1659H176.767C176.745 6.66396 176.603 6.20565 176.342 5.791C176.08 5.35452 175.72 5.00534 175.261 4.74345C174.803 4.48156 174.257 4.35062 173.624 4.35062C173.079 4.3288 172.577 4.41609 172.119 4.61251C171.682 4.7871 171.333 5.0599 171.071 5.4309C170.809 5.78009 170.678 6.22748 170.678 6.77307C170.678 7.31867 170.809 7.77697 171.071 8.14798C171.333 8.49716 171.693 8.8027 172.151 9.06458C172.631 9.32647 173.188 9.57744 173.821 9.81751C174.454 10.0357 175.141 10.2649 175.883 10.505C177.04 10.8978 178.098 11.367 179.059 11.9126C180.019 12.4364 180.783 13.1238 181.35 13.975C181.939 14.8261 182.234 15.95 182.234 17.3468C182.234 18.5689 181.918 19.7037 181.285 20.7513C180.652 21.777 179.735 22.6063 178.535 23.2392C177.335 23.8721 175.85 24.1885 174.083 24.1885Z" fill="#000000"></path><path class="logo-path logo-text" d="M141.285 23.7955L149.633 0.880371H154.838L163.185 23.7955H158.341L152.219 6.08537L146.065 23.7955H141.285ZM144.952 18.6559L146.163 15.0877H157.948L159.126 18.6559H144.952Z" fill="#000000"></path><path class="logo-path logo-text" d="M121.02 23.7955V0.880371H128.811C131.452 0.880371 133.645 1.3605 135.391 2.32075C137.137 3.25918 138.425 4.59043 139.254 6.31452C140.105 8.01679 140.531 10.0246 140.531 12.3379C140.531 14.6294 140.105 16.6372 139.254 18.3613C138.425 20.0854 137.137 21.4276 135.391 22.3878C133.667 23.3262 131.463 23.7955 128.779 23.7955H121.02ZM125.603 19.8672H128.55C130.383 19.8672 131.823 19.5725 132.871 18.9833C133.94 18.3722 134.704 17.5102 135.162 16.3972C135.62 15.2623 135.85 13.9092 135.85 12.3379C135.85 10.7666 135.62 9.42443 135.162 8.31141C134.704 7.17656 133.940 6.30361 132.871 5.69254C131.823 5.08147 130.383 4.77594 128.55 4.77594H125.603V19.8672Z" fill="#000000"></path><path class="logo-path logo-text" d="M100.784 23.7955V0.880371H109.492C111.347 0.880371 112.886 1.19682 114.108 1.82971C115.33 2.46261 116.235 3.32465 116.825 4.41584C117.436 5.48521 117.741 6.70735 117.741 8.08226C117.741 9.34804 117.447 10.5265 116.857 11.6177C116.29 12.6871 115.395 13.5601 114.173 14.2366C112.951 14.9131 111.391 15.2514 109.492 15.2514H105.367V23.7955H100.784ZM105.367 11.5523H109.197C110.572 11.5523 111.554 11.2358 112.144 10.6029C112.755 9.97002 113.06 9.1298 113.06 8.08226C113.06 6.99106 112.755 6.13993 112.144 5.52886C111.554 4.91779 110.572 4.61226 109.197 4.61226H105.367V11.5523Z" fill="#000000"></path><path class="logo-path logo-text" d="M85.6877 24.1885C83.4617 24.1885 81.4975 23.6866 79.7953 22.6827C78.093 21.6788 76.7508 20.293 75.7687 18.5252C74.8085 16.7357 74.3284 14.6733 74.3284 12.3382C74.3284 10.003 74.8085 7.95156 75.7687 6.18383C76.7508 4.39427 78.093 2.99754 79.7953 1.99364C81.4975 0.989742 83.4617 0.487793 85.6877 0.487793C87.9356 0.487793 89.9106 0.989742 91.6129 1.99364C93.337 2.99754 94.6682 4.39427 95.6067 6.18383C96.5669 7.95156 97.047 10.003 97.047 12.3382C97.047 14.6733 96.5669 16.7357 95.6067 18.5252C94.6682 20.293 93.337 21.6788 91.6129 22.6827C89.9106 23.6866 87.9356 24.1885 85.6877 24.1885ZM85.6877 20.0638C87.0626 20.0638 88.252 19.7474 89.2559 19.1145C90.2598 18.4816 91.0346 17.5977 91.5802 16.4629C92.1258 15.3062 92.3986 13.9313 92.3986 12.3382C92.3986 10.745 92.1258 9.38103 91.5802 8.24619C91.0346 7.08952 90.2598 6.19474 89.2559 5.56185C88.252 4.92895 87.0626 4.61251 85.6877 4.61251C84.3346 4.61251 83.1561 4.92895 82.1522 5.56185C81.1702 6.19474 80.3954 7.08952 79.828 8.24619C79.2824 9.38103 79.0096 10.745 79.0096 12.3382C79.0096 13.9313 79.2824 15.3062 79.828 16.4629C80.3954 17.5977 81.1702 18.4816 82.1522 19.1145C83.1561 19.7474 84.3346 20.0638 85.6877 20.0638Z" fill="#000000"></path><path class="logo-path logo-text" d="M59.9851 24.1885C57.759 24.1885 55.7949 23.6866 54.0926 22.6827C52.3904 21.6788 51.0482 20.293 50.0661 18.5252C49.1059 16.7357 48.6257 14.6733 48.6257 12.3382C48.6257 10.003 49.1059 7.95156 50.0661 6.18383C51.0482 4.39427 52.3904 2.99754 54.0926 1.99364C55.7949 0.989742 57.759 0.487793 59.9851 0.487793C62.2329 0.487793 64.208 0.989742 65.9103 1.99364C67.6343 2.99754 68.9656 4.39427 69.904 6.18383C70.8643 7.95156 71.3444 10.003 71.3444 12.3382C71.3444 14.6733 70.8643 16.7357 69.904 18.5252C68.9656 20.293 67.6343 21.6788 65.9103 22.6827C64.208 23.6866 62.2329 24.1885 59.9851 24.1885ZM59.9851 20.0638C61.36 20.0638 62.5494 19.7474 63.5533 19.1145C64.5572 18.4816 65.3319 17.5977 65.8775 16.4629C66.4231 15.3062 66.6959 13.9313 66.6959 12.3382C66.6959 10.745 66.4231 9.38103 65.8775 8.24619C65.3319 7.08952 64.5572 6.19474 63.5533 5.56185C62.5494 4.92895 61.36 4.61251 59.9851 4.61251C58.632 4.61251 57.4535 4.92895 56.4496 5.56185C55.4675 6.19474 54.6928 7.08952 54.1254 8.24619C53.5798 9.38103 53.307 10.745 53.307 12.3382C53.307 13.9313 53.5798 15.3062 54.1254 16.4629C54.6928 17.5977 55.4675 18.4816 56.4496 19.1145C57.4535 19.7474 58.632 20.0638 59.9851 20.0638Z" fill="#000000"></path><path class="logo-path logo-text" d="M33.0107 23.7955V0.880371H37.5938V20.2273H47.6109V23.7955H33.0107Z" fill="#000000"></path></svg>
                                <p>Loopdash brings simplicity and sophistication to web development, combining seamless design, development, and SEO into a personal, partnership-driven experience.</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Custom Admin Styles -->
        <style>
        .lsp-status-card {
            overflow: hidden;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
        }
        
        .lsp-card-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }
        
        .lsp-card-icon {
            font-size: 20px;
        }
        
        .lsp-card-header h3 {
            margin: 0;
            flex: 1;
            font-size: 16px;
            color: #2c3e50;
        }
        
        .lsp-card-content {
            padding: 0;
            color: #555;
            line-height: 1.6;
        }
        
        .lsp-card-content p {
            margin: 0 0 8px 0;
            font-size: 14px;
        }
        
        .lsp-card-content p:last-child {
            margin-bottom: 0;
        }
        
        .lsp-emergency-code {
            background: #f8f9fa;
            padding: 6px 10px;
            border-radius: 4px;
            border: 1px solid #e9ecef;
            display: block;
            margin: 0;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 12px;
        }
        
        .lsp-test-btn {
            display: inline-block;
            padding: 8px 16px;
            background: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 6px;
            font-size: 14px;
            margin-top: 10px;
            transition: background 0.2s ease;
        }
        
        .lsp-test-btn:hover {
            background: #2980b9;
            color: white;
        }
        
        /* Two Column Layout */
        .lsp-two-column-layout {
            display: flex;
            gap: 30px;
            align-items: flex-start;
            margin-top: 20px;
        }
        
        .lsp-left-column {
            flex: 1;
            min-width: 0; /* Allows the column to shrink */
        }
        
        .lsp-right-column {
            width: 300px;
            flex-shrink: 0; /* Prevents the column from shrinking */
        }
        
        .lsp-settings-section {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
            margin-bottom: 0; /* Remove bottom margin in two-column layout */
        }
        
        .lsp-settings-section h2 {
            margin-top: 0;
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 15px;
        }
        
        .lsp-form-actions {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
        }
        
        .lsp-info-section {
            background: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.07);
        }
        
        .lsp-info-section h2 {
            margin-top: 0;
            color: #2c3e50;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 15px;
        }
        
        .lsp-info-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 15px;
            margin-bottom: 30px;
        }

        .lsp-plugin-details {
            padding: 20px;
            border: 1px solid #e9ecef;
            border-radius: 8px;
        }

        .lsp-plugin-details .lsp-info-item {
            padding: 0;
            background: transparent;
            border: none;
            border-radius: 0;
            border-bottom: 1px solid #e9ecef;
        }
        
        .lsp-plugin-details .lsp-info-item:last-child {
            border-bottom: none;
        }
        
        .lsp-info-item {
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            border-left: 3px solid #3498db;
        }
        .lsp-features-list {
            margin-bottom: 30px;
        }
        .lsp-features-list h3 {
            color: #2c3e50;
            margin-bottom: 10px;
        }
        
        .lsp-features-list ul {
            list-style: disc;
            padding-left: 20px;
        }
        
        .lsp-features-list li {
            border-bottom: none;
            font-size: 14px;
            line-height: 1.4;
        }
        
        /* Logo styling */
        .lsp-logo-container p {
            margin: 0;
        }
        
        .lsp-logo-container .logo {
            max-width: 200px;
            height: auto;
        }
        
        /* Responsive adjustments */
        @media (max-width: 1024px) {
            .lsp-two-column-layout {
                flex-direction: column;
            }
            
            .lsp-right-column {
                width: 100%;
                margin-top: 30px;
            }
            
            .lsp-info-grid {
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            }
        }
        
        @media (max-width: 768px) {
            .lsp-two-column-layout {
                gap: 20px;
            }
            
            .lsp-settings-section,
            .lsp-info-section {
                padding: 20px;
            }
        }
        </style>
        <?php
    }
    
    /**
     * Settings section description callback
     */
    public function section_callback() {
        // No description text needed - removed as requested
    }
    
    /**
     * Password field callback
     */
    public function password_field_callback() {
        $options = $this->get_options();
        echo '<input type="text" name="lsp_options[password]" value="' . esc_attr($options['password']) . '" class="regular-text" />';
        echo '<p class="description">The password required to access the staging site. Default: ShapeTomorrow</p>';
    }
    
    /**
     * Protection enabled field callback
     */
    public function protection_enabled_field_callback() {
        $options = $this->get_options();
        $enabled = $options['protection_enabled'];
        ?>
        <label>
            <input type="checkbox" name="lsp_options[protection_enabled]" value="1" <?php checked($enabled, true); ?> />
            Enable staging protection
        </label>
        <p class="description">
            <strong>When enabled:</strong> Site is protected with password login<br>
            <strong>When disabled:</strong> Site is accessible without password (normal WordPress site)
        </p>
        <?php
    }
    
    /**
     * Login message field callback
     */
    public function login_message_field_callback() {
        $options = $this->get_options();
        echo '<textarea name="lsp_options[login_message]" rows="3" class="large-text">' . esc_textarea($options['login_message']) . '</textarea>';
        echo '<p class="description">Message displayed above the password field on the login page. HTML allowed.</p>';
    }
    
    /**
     * Error message field callback
     */
    public function error_message_field_callback() {
        $options = $this->get_options();
        echo '<input type="text" name="lsp_options[error_message]" value="' . esc_attr($options['error_message']) . '" class="large-text" />';
        echo '<p class="description">Message displayed when login fails.</p>';
    }
    
    /**
     * CSS source field callback
     */
    public function css_source_field_callback() {
        $options = $this->get_options();
        $current_source = $options['css_source'];
        ?>
        <select name="lsp_options[css_source]" id="lsp_css_source">
            <option value="local" <?php selected($current_source, 'local'); ?>>Local CSS File</option>
            <option value="external" <?php selected($current_source, 'external'); ?>>External CSS URL</option>
        </select>
        <p class="description">
            <strong>Local:</strong> Load CSS from plugin's assets/css/login-styles.css<br>
            <strong>External:</strong> Load CSS from external URL (Git repository, CDN, etc.)
        </p>
        <?php
    }
    
    /**
     * External CSS URL field callback
     */
    public function external_css_url_field_callback() {
        $options = $this->get_options();
        echo '<input type="url" name="lsp_options[external_css_url]" value="' . esc_attr($options['external_css_url']) . '" class="large-text" placeholder="https://example.com/path/to/styles.css" />';
        echo '<p class="description">URL to external CSS file. <strong>No inline CSS fallback</strong> - ensure the URL is always accessible. Examples:<br>';
        echo '<code>https://cdn.jsdelivr.net/gh/loopdash/wp-password@main/assets/css/login-styles.css</code><br>';
        echo '<code>https://loopdash.com/assets/staging-protection/css/login-styles.css</code><br>';
        echo 'Only required when CSS Source is set to "External CSS URL".</p>';
        
        // Add test button for external CSS
        if (!empty($options['external_css_url'])) {
            echo '<button type="button" id="test-css-url" class="button button-secondary" style="margin-top: 10px;">Test CSS URL</button>';
            echo '<div id="css-test-result" style="margin-top: 10px;"></div>';
            
            // Add JavaScript for testing
            ?>
            <script type="text/javascript">
            document.addEventListener('DOMContentLoaded', function() {
                const testBtn = document.getElementById('test-css-url');
                const resultDiv = document.getElementById('css-test-result');
                
                if (testBtn) {
                    testBtn.addEventListener('click', function() {
                        const cssUrl = document.querySelector('input[name="lsp_options[external_css_url]"]').value;
                        
                        if (!cssUrl) {
                            resultDiv.innerHTML = '<p style="color: red;">Please enter a CSS URL first.</p>';
                            return;
                        }
                        
                        testBtn.disabled = true;
                        testBtn.textContent = 'Testing...';
                        resultDiv.innerHTML = '<p style="color: blue;">Testing CSS URL...</p>';
                        
                        // Test the URL by trying to load it
                        const testLink = document.createElement('link');
                        testLink.rel = 'stylesheet';
                        testLink.href = cssUrl;
                        
                        testLink.onload = function() {
                            resultDiv.innerHTML = '<p style="color: green;">✅ CSS URL is accessible and loads successfully!</p>';
                            testBtn.disabled = false;
                            testBtn.textContent = 'Test CSS URL';
                            document.head.removeChild(testLink);
                        };
                        
                        testLink.onerror = function() {
                            resultDiv.innerHTML = '<p style="color: red;">❌ CSS URL failed to load. Check the URL and try again.</p>';
                            testBtn.disabled = false;
                            testBtn.textContent = 'Test CSS URL';
                            document.head.removeChild(testLink);
                        };
                        
                        document.head.appendChild(testLink);
                    });
                }
            });
            </script>
            <?php
        }
    }
    
    /**
     * CSS version field callback
     */
    public function css_version_field_callback() {
        $options = $this->get_options();
        echo '<input type="text" name="lsp_options[css_version]" value="' . esc_attr($options['css_version']) . '" class="regular-text" placeholder="' . LSP_VERSION . '" />';
        echo '<p class="description">Version string for cache busting. Change this when you update external CSS. Defaults to plugin version.</p>';
    }
    
    /**
     * Handle AJAX login (for future enhancement)
     */
    public function handle_login() {
        // This method is reserved for future AJAX login implementation
        wp_die();
    }
    
    /**
     * Enqueue login page styles
     */
    public function enqueue_login_styles() {
        // Only enqueue styles on the login page (when protection is active)
        if (!$this->is_user_authenticated() && !is_admin() && !wp_doing_ajax()) {
            $options = $this->get_options();
            $css_source = $options['css_source'] ?? 'local';
            $external_css_url = $options['external_css_url'] ?? '';
            
            switch ($css_source) {
                case 'external':
                    if (!empty($external_css_url)) {
                        // Enqueue external CSS with version for cache busting
                        wp_enqueue_style(
                            'lsp-login-styles',
                            $external_css_url,
                            array(),
                            $options['css_version'] ?? LSP_VERSION,
                            'all'
                        );
                        
                        // No fallback script needed - external CSS only
                    }
                    break;
                    
                case 'local':
                default:
                    $this->enqueue_local_css();
                    break;
            }
        }
    }
    
    /**
     * Enqueue local CSS file
     */
    private function enqueue_local_css() {
        $css_file_path = LSP_PLUGIN_PATH . 'assets/css/login-styles.css';
        $css_file_url = LSP_PLUGIN_URL . 'assets/css/login-styles.css';
        
        // Check if local CSS file exists
        if (file_exists($css_file_path)) {
            wp_enqueue_style(
                'lsp-login-styles',
                $css_file_url,
                array(),
                filemtime($css_file_path), // Use file modification time for cache busting
                'all'
            );
            
            // Debug info when WP_DEBUG is enabled
            if (defined('WP_DEBUG') && WP_DEBUG) {
                echo '<!-- LSP Local CSS Debug: File exists and enqueued from ' . $css_file_url . ' -->';
            }
        } else {
            // Debug info when file doesn't exist
            if (defined('WP_DEBUG') && WP_DEBUG) {
                echo '<!-- LSP Local CSS Debug: File not found at ' . $css_file_path . ' -->';
            }
        }
    }
    
    /**
     * Add CSS fallback script to page
     */
    public function add_css_fallback_script() {
        if (!$this->is_user_authenticated() && !is_admin() && !wp_doing_ajax()) {
            // Add debugging info when WP_DEBUG is enabled
            if (defined('WP_DEBUG') && WP_DEBUG) {
                $options = $this->get_options();
                echo '<!-- LSP Debug Info:' . "\n";
                echo 'CSS Source: ' . $options['css_source'] . "\n";
                
                if ($options['css_source'] === 'external') {
                    echo 'External CSS URL: ' . $options['external_css_url'] . "\n";
                    echo 'No inline CSS fallback - external CSS only' . "\n";
                } else {
                    echo 'Local CSS Path: ' . LSP_PLUGIN_PATH . 'assets/css/login-styles.css' . "\n";
                    echo 'Local CSS URL: ' . LSP_PLUGIN_URL . 'assets/css/login-styles.css' . "\n";
                    echo 'Local CSS File Exists: ' . (file_exists(LSP_PLUGIN_PATH . 'assets/css/login-styles.css') ? 'Yes' : 'No') . "\n";
                }
                
                echo 'CSS Version: ' . $options['css_version'] . "\n";
                echo '-->';
            }
        }
    }
    
    /**
     * Get basic fallback CSS when local file is missing
     * Provides minimal styling to ensure the login page is functional
     */
    private function get_basic_fallback_css() {
        return '
        body.lsp-login-body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .lsp-login-container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            padding: 40px;
            max-width: 400px;
            width: 90%;
        }
        
        .lsp-site-title {
            text-align: center;
            color: #333;
            margin-bottom: 20px;
            font-size: 24px;
        }
        
        .lsp-login-message {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            line-height: 1.5;
        }
        
        .lsp-input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            margin-bottom: 20px;
            box-sizing: border-box;
        }
        
        .lsp-submit-btn {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
        }
        
        .lsp-submit-btn:hover {
            background: #5a6fd8;
        }
        
        .lsp-footer {
            text-align: center;
            margin-top: 30px;
            font-size: 14px;
            color: #999;
        }
        
        .lsp-footer a {
            color: #667eea;
            text-decoration: none;
        }
        
        .lsp-error-message {
            background: #f8d7da;
            color: #721c24;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            text-align: center;
        }
        ';
    }
    
    /**
     * Get inline CSS styles as a string
     * This method is kept for local CSS file reference only
     */
    private function get_inline_css() {
        // This method is preserved for reference but not used for inline output
        // CSS should come from external URL or local file only
        return '';
    }
}

/**
 * Plugin activation hook
 * Sets up default options when plugin is first activated
 */
function lsp_activate() {
    // Set default options if they don't exist
    $default_options = array(
        'password' => 'ShapeTomorrow',
        'login_message' => 'This is a staging environment. Please enter the access password to continue.',
        'error_message' => 'Incorrect password. Please try again.',
        'css_source' => 'external',
        'external_css_url' => 'https://cdn.jsdelivr.net/gh/loopdash/wp-password@main/assets/css/login-styles.css',
        'css_version' => LSP_VERSION,
        'protection_enabled' => false // Protection disabled by default
    );
    
    if (!get_option('lsp_options')) {
        add_option('lsp_options', $default_options);
    } else {
        // Update existing options with new defaults
        $existing_options = get_option('lsp_options');
        $updated_options = wp_parse_args($existing_options, $default_options);
        update_option('lsp_options', $updated_options);
    }
}

/**
 * Plugin deactivation hook
 * Cleans up any temporary data but preserves settings
 */
function lsp_deactivate() {
    // Clear any existing sessions
    if (session_id()) {
        session_destroy();
    }
    
    // Clear any authentication transients
    global $wpdb;
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_lsp_auth_%' OR option_name LIKE '_transient_timeout_lsp_auth_%'");
}

/**
 * Plugin uninstall hook
 * Removes all plugin data when plugin is deleted
 */
function lsp_uninstall() {
    // Remove plugin options
    delete_option('lsp_options');
    
    // Clear any existing sessions
    if (session_id()) {
        session_destroy();
    }
    
    // Clear any authentication transients
    global $wpdb;
    $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_lsp_auth_%' OR option_name LIKE '_transient_timeout_lsp_auth_%'");
}

// Register activation and deactivation hooks
register_activation_hook(__FILE__, 'lsp_activate');
register_deactivation_hook(__FILE__, 'lsp_deactivate');

// Initialize the plugin
add_action('plugins_loaded', function() {
    LoopdashStagingProtection::get_instance();
});
