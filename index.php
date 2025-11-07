<?php
/**
 * Index file for Loopdash Staging Protection Plugin
 * 
 * This file prevents direct access to the plugin directory
 * and provides basic information about the plugin structure.
 * 
 * @package LoopdashStagingProtection
 * @author Gery Brkospy <gery@loopdash.com>
 * @copyright 2025 Loopdash
 */

// Prevent direct access to this directory
if (!defined('ABSPATH')) {
    exit;
}

// Redirect to WordPress admin if someone tries to access this directory directly
wp_redirect(admin_url());
exit;