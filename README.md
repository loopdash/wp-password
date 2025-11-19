# WP Password - WordPress Staging Protection Plugin

![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)
![WordPress](https://img.shields.io/badge/wordpress-5.0%2B-brightgreen.svg)
![License](https://img.shields.io/badge/license-GPL--2.0%2B-red.svg)

A lightweight password protection plugin for staging WordPress sites. Returns 501 HTTP errors to prevent search engine indexing while allowing authorized access with a configurable password.

## 🎯 Purpose

**WP Password** is specifically designed for staging and development WordPress sites to:

- **Prevent Search Engine Indexing** - Returns 501 HTTP status codes to block crawlers
- **Simple Password Protection** - Single password protects the entire site
- **Lightweight & Fast** - Minimal footprint with no bloat
- **Managed Hosting Compatible** - Enhanced for WPEngine, Cloudflare, and similar providers
- **Centralized Style Management** - External CSS support via CDN for consistent branding

## ✨ Features

- 🔒 **Total Site Protection** - Blocks frontend, admin, and all WordPress pages
- 🚫 **SEO Blocking** - 501 HTTP status prevents search engine indexing
- 🔑 **Session-Based Authentication** - Users stay logged in until browser closes
- 🎨 **External CSS Support** - Load styles from GitHub/CDN for centralized management
- ⚡ **Cache Busting** - Automatic cache bypass for WPEngine and managed hosting
- 🔄 **Transient Fallback** - Dual authentication system for session reliability
- 📱 **Responsive Design** - Mobile-friendly login page
- 🛡️ **Emergency Access** - Built-in bypass for lockout situations

## 📦 Installation

### Method 1: WordPress Admin (Recommended)

1. Download the latest release ZIP file
2. Go to **WordPress Admin → Plugins → Add New**
3. Click **Upload Plugin** and select the ZIP file
4. Click **Install Now**
5. Activate the plugin

### Method 2: Manual Installation

1. Download and extract the plugin files
2. Upload the `wp-password` folder to `/wp-content/plugins/`
3. Go to **WordPress Admin → Plugins**
4. Activate **WordPress Password**

### Method 3: Git Clone

```bash
cd wp-content/plugins/
git clone https://github.com/loopdash/wp-password.git
```

## 🚀 Quick Start

1. **Activate the plugin** from WordPress Admin
2. Go to **Tools → Staging Protection**
3. **Set your password** (default is `ShapeTomorrow`)
4. **Enable protection** by checking "Enable staging protection"
5. Click **Save Settings**

Your site is now protected! Try accessing it in an incognito window.

## ⚙️ Configuration

### Basic Settings

| Setting | Description | Default |
|---------|-------------|---------|
| **Protection Status** | Enable/disable site protection | Disabled |
| **Access Password** | Password required to access the site | `ShapeTomorrow` |
| **Login Page Message** | Message displayed on login page | "This is a staging environment..." |
| **Failed Login Message** | Message shown for incorrect password | "Incorrect password..." |

### CSS Configuration

| Setting | Description | Default |
|---------|-------------|---------|
| **CSS Source** | Local file or external URL | External |
| **External CSS URL** | CDN/GitHub URL for stylesheet | jsDelivr CDN |
| **CSS Version** | Cache busting version string | Plugin version |

### Default External CSS URL
```
https://cdn.jsdelivr.net/gh/loopdash/wp-password@main/assets/css/login-styles.css
```

## 📖 How to Use

### Enabling Protection

1. Navigate to **Tools → Staging Protection**
2. Check **"Enable staging protection"**
3. Set your desired password
4. Click **Save Settings**

### Accessing Protected Site

1. Visit your site URL
2. Enter the password on the login page
3. Click **"View Site"**
4. Access remains active until browser closes

### Disabling Protection

1. Go to **Tools → Staging Protection**
2. Uncheck **"Enable staging protection"**
3. Click **Save Settings**

### Emergency Access

If locked out, add this parameter to any URL:
```
?lsp_disable=temp_admin_access
```

Example:
```
https://yoursite.com/?lsp_disable=temp_admin_access
```

### Logout (Testing)

To test the login page while authenticated, add:
```
?lsp_logout=1
```

## 🎨 Custom CSS

### Using External CSS (Recommended)

**Benefits:**
- Centralized style management across multiple sites
- Update styles once, apply everywhere
- No plugin updates required for style changes
- CDN performance benefits

**Setup:**
1. Host your CSS file on GitHub, CDN, or your server
2. Go to **Tools → Staging Protection**
3. Select **"External CSS URL"** as CSS Source
4. Enter your CSS URL
5. Set a version number for cache busting
6. Click **Save Settings**

**Example URLs:**
```
# jsDelivr CDN (Recommended)
https://cdn.jsdelivr.net/gh/yourusername/repo@main/path/to/styles.css

# Statically CDN
https://cdn.statically.io/gh/yourusername/repo/main/path/to/styles.css

# Your own server
https://yourdomain.com/assets/css/login-styles.css
```

### Using Local CSS

1. Go to **Tools → Staging Protection**
2. Select **"Local CSS File"** as CSS Source
3. Edit `/wp-content/plugins/wp-password/assets/css/login-styles.css`
4. Click **Save Settings**

### CSS Classes Reference

```css
.lsp-login-body          /* Body wrapper */
.lsp-login-container     /* Main container */
.lsp-login-form          /* Form wrapper */
.lsp-site-title          /* Site title heading */
.lsp-login-message       /* Login instruction text */
.lsp-error-message       /* Error message box */
.lsp-input-group         /* Input field wrapper */
.lsp-input               /* Password input field */
.lsp-submit-btn          /* Submit button */
.lsp-footer              /* Footer section */
```

## 🔧 Technical Details

### System Requirements

- **WordPress:** 5.0 or higher
- **PHP:** 7.0 or higher
- **Sessions:** PHP sessions enabled

### How It Works

1. **Early Hook** - Runs on `init` action (priority 1)
2. **Session Check** - Validates authentication via session or transient
3. **Cache Bypass** - Sends cache-busting headers for managed hosting
4. **501 Response** - Returns HTTP 501 for unauthenticated requests
5. **Login Form** - Displays custom login page with external CSS
6. **Authentication** - Stores auth in both session and transient (fallback)

### Authentication Flow

```
User Request
    ↓
Check Session/Transient
    ↓
Authenticated? → Yes → Allow Access
    ↓
   No
    ↓
Send 501 Headers
    ↓
Show Login Page
    ↓
Password Correct? → Yes → Set Session & Transient → Redirect
    ↓
   No
    ↓
Show Error Message
```

### Session Management

- **Primary:** PHP sessions with managed hosting compatibility
- **Fallback:** WordPress transients (2-hour timeout)
- **Key:** `lsp_authenticated` (session) / `lsp_auth_{hash}` (transient)
- **Timeout:** Browser session (primary) / 2 hours (transient)

### Cache Busting

The plugin sends aggressive cache-bypass headers for:
- WPEngine
- Cloudflare
- Varnish
- Nginx FastCGI Cache
- Generic reverse proxies

### Security Features

- **HTTP 501 Status** - Discourages search engine indexing
- **Session-Based Auth** - Secure, server-side authentication
- **IP + User Agent Hash** - Transient key includes client fingerprint
- **No Cookie Exposure** - Password never stored in cookies
- **CSRF Protection** - WordPress nonce validation (future enhancement)

## 🌐 Managed Hosting Compatibility

### WPEngine
✅ Fully compatible with session handling
✅ Cache bypass headers included
✅ Transient fallback for session issues

### Cloudflare
✅ Cache bypass headers included
✅ IP detection for proxied requests
✅ Proper redirect handling

### Kinsta / Flywheel / Pressable
✅ Standard compatibility
✅ Session configuration optimized
✅ Cache-busting URLs

## 🎨 Admin Interface

### Admin Bar Indicator

A colored indicator appears in the WordPress admin bar:

- 🟢 **Green "STAGING PROTECTED"** - Protection is active
- 🔴 **Red "STAGING NOT PROTECTED"** - Protection is disabled

Click the indicator to access settings.

### Settings Page

Located at **Tools → Staging Protection**

**Left Column:** Settings form with all configuration options
**Right Column:** Plugin information, emergency access, and documentation

## 📝 Use Cases

### 1. Staging Sites
Prevent clients from sharing staging URLs publicly while blocking search engines.

### 2. Development Sites
Protect work-in-progress sites from premature exposure.

### 3. Demo Sites
Control access to demonstration sites with simple password.

### 4. Client Previews
Share a single password with clients for preview access.

### 5. Multi-Site Networks
Deploy across multiple staging sites with centralized CSS management.

## 🔌 Hooks & Filters

### Available Hooks (Future Extensions)

```php
// Customize authentication timeout (2 hours default)
add_filter('lsp_auth_timeout', function($timeout) {
    return 3600; // 1 hour
});

// Customize session key
add_filter('lsp_session_key', function($key) {
    return 'my_custom_auth_key';
});

// Bypass protection for specific IPs
add_filter('lsp_bypass_ips', function($ips) {
    return ['123.456.789.000'];
});
```

## 🐛 Troubleshooting

### Issue: Can't Login / Locked Out

**Solution:** Add emergency access parameter to URL:
```
?lsp_disable=temp_admin_access
```

### Issue: Styles Not Loading

**Cause:** Using raw GitHub URLs instead of CDN
**Solution:** Use jsDelivr CDN URL:
```
https://cdn.jsdelivr.net/gh/loopdash/wp-password@main/assets/css/login-styles.css
```

### Issue: Cache Not Clearing

**Solution:** 
1. Add `?lsp_nocache=1` to URL
2. Clear browser cache
3. Check WPEngine cache settings

### Issue: Session Not Persisting

**Solution:** The plugin uses transient fallback automatically. If issues persist:
1. Check PHP session configuration
2. Verify `/tmp` directory is writable
3. Contact hosting provider about session handling

## 📋 Changelog

### Version 1.2.0
- ✨ Added external CSS support for centralized style management
- ✨ Configurable CSS source (local file, external URL)
- ✨ Support for Git repository or CDN hosted stylesheets
- ✨ Enhanced admin interface for CSS management
- 🐛 Fixed external CSS loading with jsDelivr CDN
- 📝 Updated documentation with CSS configuration

### Version 1.1.0
- 🐛 Fixed session handling for WPEngine and managed hosting
- ✨ Added transient-based authentication fallback
- 🔧 Improved redirect logic to prevent loops
- ⚡ Enhanced cache bypass headers
- 🌐 Better IP detection for proxy environments

### Version 1.0.0
- 🎉 Initial release
- 🔒 Password protection for entire site
- 🚫 501 HTTP status for SEO blocking
- 📱 Responsive login page design

## 📄 License

This plugin is licensed under the **GPL v2 or later**.

```
WordPress Password Plugin
Copyright (C) 2025 Loopdash

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
```

## 👨‍💻 Author

**Gery Brkospy**  
[Loopdash](https://loopdash.com/)  
Email: gary@loopdash.com

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🌟 Support

- **Documentation:** [GitHub Wiki](https://github.com/loopdash/wp-password/wiki)
- **Issues:** [GitHub Issues](https://github.com/loopdash/wp-password/issues)
- **Website:** [Loopdash.com](https://loopdash.com/)

## 💬 FAQ

**Q: Does this replace WordPress's built-in password protection?**  
A: Yes, this provides site-wide protection with SEO blocking, unlike WordPress's post-level protection.

**Q: Will this affect my production site?**  
A: This is designed for staging sites. You can safely disable protection for production.

**Q: Can I use this on multiple sites?**  
A: Yes! Use external CSS for consistent branding across all sites.

**Q: Does it work with multisite?**  
A: Yes, activate per-site or network-wide.

**Q: What's the performance impact?**  
A: Minimal - one session check per request, bypassed after authentication.

**Q: Can I customize the login page?**  
A: Yes, through external CSS or by editing the local CSS file.

---

**Made with ❤️ by [Loopdash](https://loopdash.com/)**

*Bringing simplicity and sophistication to web development*
