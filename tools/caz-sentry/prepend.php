<?php
/**
 * Standalone bootstrap for PHP's auto_prepend_file directive.
 *
 * WHY THIS EXISTS
 *
 * Installed as a must-use plugin, Sentry only sees requests that boot
 * WordPress. A standalone backdoor — a stray PHP file in the web root, a
 * shell dropped into uploads/ — is reached directly over HTTP and never loads
 * WordPress at all. The mu-plugin never runs, so the watcher never sees what
 * that shell writes. Only the hourly scan notices, and only after the fact.
 *
 * auto_prepend_file closes that gap: PHP runs this file before *every* PHP
 * script on the site, whether or not WordPress is involved. A shell invoked
 * directly is therefore watched from its first instruction.
 *
 * THIS IS THE HIGHEST-RISK WAY TO INSTALL SENTRY.
 *
 * A fatal error here takes down every PHP request on the site, wp-admin
 * included, and the only way back is file access. Everything below is
 * therefore wrapped, guarded, and written to do nothing at all rather than
 * risk anything. Read the "Turning it off" note at the bottom before using it.
 *
 * NOTE ON ABSPATH
 *
 * This file deliberately never defines ABSPATH. WordPress core, themes and
 * plugins guard direct access with `if (!defined('ABSPATH')) exit;`, and
 * defining it globally from a prepend file would silently disable that guard
 * across the whole site. Sentry resolves paths through its own constants
 * instead.
 */

// Throwable arrived in PHP 7. Below that, do nothing rather than guess.
if (PHP_VERSION_ID < 70000) {
    return;
}

call_user_func(function () {
    try {
        // Already running (mu-plugin or a second prepend). Nothing to do.
        if (class_exists('CAZ_Sentry_Write_Watcher', false)) {
            return;
        }

        $dir = __DIR__;

        // Kill switch. Create an empty file named caz-sentry-off next to this
        // one and Sentry stops loading, without editing any PHP or ini file.
        if (@file_exists($dir . '/caz-sentry-off')) {
            return;
        }

        // Expected layout: <root>/wp-content/mu-plugins/caz-sentry/prepend.php
        $root = dirname(dirname(dirname($dir)));

        // Only proceed if this really is a WordPress root. If Sentry has been
        // moved elsewhere, the computed paths would be wrong, and wrong paths
        // are worse than no watcher.
        if (!@is_file($root . '/wp-settings.php')) {
            return;
        }

        if (!defined('CAZ_SENTRY_ABSPATH')) {
            define('CAZ_SENTRY_ABSPATH', $root . '/');
        }
        if (!defined('CAZ_SENTRY_CONTENT_DIR')) {
            define('CAZ_SENTRY_CONTENT_DIR', dirname(dirname($dir)));
        }

        // Optional settings that must be readable without WordPress. See
        // config.sample.php.
        if (@is_file($dir . '/config.php')) {
            include_once $dir . '/config.php';
        }

        // Only the classes that work without WordPress. Baseline scanning,
        // the database tripwires and the admin screen all need WordPress and
        // are loaded later by the mu-plugin.
        foreach (array('Context', 'Signatures', 'Journal', 'Alerts', 'Guard', 'WriteWatcher') as $class) {
            $file = $dir . '/includes/' . $class . '.php';
            if (!@is_file($file)) {
                return; // incomplete install; do nothing
            }
            require_once $file;
        }

        if (defined('CAZ_SENTRY_MODE') && CAZ_SENTRY_MODE === 'light') {
            return;
        }

        if (!CAZ_Sentry_Guard::may_arm()) {
            return;
        }

        CAZ_Sentry_Guard::arm();
        CAZ_Sentry_Write_Watcher::register();
    } catch (Throwable $e) {
        // Observation must never cost availability. If anything at all goes
        // wrong, the request continues as though Sentry were not installed.
        return;
    }
});

/*
 * TURNING IT OFF
 *
 * Fastest, no file editing: create an empty file named `caz-sentry-off` in
 * this directory. Sentry stops loading on the next request.
 *
 * Properly: remove the auto_prepend_file line from .user.ini (or php.ini).
 * .user.ini changes can take a few minutes to apply — PHP caches it for
 * user_ini.cache_ttl seconds, 300 by default.
 */
