<?php
/**
 * Optional settings for the auto_prepend_file install.
 *
 * Copy this file to `config.php` in the same directory.
 *
 * WHY A SEPARATE FILE: when Sentry starts from prepend.php it runs before
 * WordPress exists, so anything defined in wp-config.php is not available
 * yet. Settings that need to apply to a standalone backdoor request — the log
 * location, the alert address — have to live somewhere WordPress-independent.
 *
 * IMPORTANT: define each constant in ONE place only. If you set
 * CAZ_SENTRY_LOG_DIR here, remove it from wp-config.php, otherwise PHP emits
 * a "constant already defined" warning on every page load.
 */

if (!defined('ABSPATH') && !defined('CAZ_SENTRY_ABSPATH')) {
    exit;
}

// Where the journal is written. Outside the webroot is strongly preferred:
// whoever is getting into the site cannot then read or delete the record of
// what they did.
if (!defined('CAZ_SENTRY_LOG_DIR')) {
    define('CAZ_SENTRY_LOG_DIR', dirname(dirname(dirname(dirname(__DIR__)))) . '/sentry-logs');
}

// Where high and critical findings are emailed, batched, at most one message
// every 15 minutes. In the prepend context WordPress (and therefore wp_mail)
// is not loaded, so Sentry falls back to PHP's own mail().
if (!defined('CAZ_SENTRY_ALERT_EMAIL')) {
    define('CAZ_SENTRY_ALERT_EMAIL', 'you@example.com');
}

// Set to 'light' to load Sentry but leave the write watcher off.
// if (!defined('CAZ_SENTRY_MODE')) {
//     define('CAZ_SENTRY_MODE', 'light');
// }
