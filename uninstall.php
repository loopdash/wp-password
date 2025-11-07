<?php
/**
 * Uninstall script for Loopdash Staging Protection Plugin
 * 
 * This file is executed when the plugin is deleted (not just deactivated).
 * It removes all data created by the plugin to keep the WordPress database clean.
 * 
 * @package LoopdashStagingProtection
 * @author Gery Brkospy <gery@loopdash.com>
 * @copyright 2025 Loopdash
 */

// Prevent direct access to this file
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

/**
 * Clean up all plugin data when uninstalled
 * 
 * This includes:
 * - Plugin options/settings
 * - Any cached data
 * - Session data (if any exists)
 */

// Remove plugin options from WordPress database
delete_option('lsp_options');

// Clear any existing sessions (though they should be browser-based)
// This is just a safety measure
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Clear the specific session key used by our plugin
if (isset($_SESSION['lsp_authenticated'])) {
    unset($_SESSION['lsp_authenticated']);
}