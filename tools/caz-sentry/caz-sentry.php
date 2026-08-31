<?php
/**
 * Plugin Name: Sentry (change forensics)
 * Description: Records every change to this WordPress install and, crucially, which code made it. Built to answer "what keeps putting this back?".
 * Version:     1.0.0
 * Author:      Site operations
 * License:     GPL-2.0-or-later
 *
 * Works either as a normal plugin or, preferably, as a must-use plugin so it
 * loads before anything it is watching. See README.md.
 */

if (!defined('ABSPATH')) {
    exit;
}

// prepend.php may already have started the watcher before WordPress existed.
// In that case the class is loaded but the WordPress-side hooks are not, so
// finish the job rather than returning early.
if (class_exists('CAZ_Sentry', false)) {
    CAZ_Sentry::boot_wp();
    return;
}

define('CAZ_SENTRY_VERSION', '1.0.0');
define('CAZ_SENTRY_PATH', __DIR__);

// Sentry resolves paths through its own constants rather than reading ABSPATH
// directly, so that prepend.php can run outside WordPress without defining
// ABSPATH itself. Defining ABSPATH globally would disable the
// `if (!defined('ABSPATH')) exit;` direct-access guard that WordPress files,
// themes and plugins rely on — a protection worth keeping intact.
if (!defined('CAZ_SENTRY_ABSPATH')) {
    define('CAZ_SENTRY_ABSPATH', ABSPATH);
}
if (!defined('CAZ_SENTRY_CONTENT_DIR')) {
    define('CAZ_SENTRY_CONTENT_DIR', defined('WP_CONTENT_DIR') ? WP_CONTENT_DIR : ABSPATH . 'wp-content');
}

class CAZ_Sentry
{
    private static $earlyBooted = false;
    private static $wpBooted    = false;
    private static $mode        = null;

    public static function load_classes()
    {
        static $loaded = false;
        if ($loaded) {
            return;
        }
        $loaded = true;

        foreach (array('Context', 'Signatures', 'Journal', 'Alerts', 'Guard', 'WriteWatcher', 'Baseline', 'DbWatcher', 'AdminPage') as $class) {
            require_once CAZ_SENTRY_PATH . '/includes/' . $class . '.php';
        }
    }

    /**
     * Full mode intercepts writes; light mode relies on scans and hooks only.
     */
    public static function mode()
    {
        if (self::$mode !== null) {
            return self::$mode;
        }

        if (defined('CAZ_SENTRY_MODE')) {
            self::$mode = (CAZ_SENTRY_MODE === 'light') ? 'light' : 'full';
            return self::$mode;
        }

        // The option lookup needs a live database connection; when we are
        // loaded from wp-config.php there is not one yet, so assume full.
        if (function_exists('get_option') && isset($GLOBALS['wpdb']) && is_object($GLOBALS['wpdb'])) {
            self::$mode = (get_option('caz_sentry_mode', 'full') === 'light') ? 'light' : 'full';
        } else {
            self::$mode = 'full';
        }

        return self::$mode;
    }

    /**
     * Everything that must happen before other code gets a chance to run.
     */
    public static function boot_early()
    {
        if (self::$earlyBooted) {
            return;
        }
        self::$earlyBooted = true;

        self::load_classes();

        if (self::mode() !== 'full') {
            return;
        }
        // prepend.php may have armed the watcher already, before WordPress
        // loaded. Do not arm it twice.
        if (CAZ_Sentry_Write_Watcher::is_active()) {
            return;
        }
        if (!CAZ_Sentry_Guard::may_arm()) {
            return;
        }

        CAZ_Sentry_Guard::arm();
        CAZ_Sentry_Write_Watcher::register();
    }

    /**
     * Everything that needs the WordPress hook system.
     */
    public static function boot_wp()
    {
        if (self::$wpBooted || !function_exists('add_action')) {
            return;
        }
        self::$wpBooted = true;

        self::load_classes();

        CAZ_Sentry_DbWatcher::boot();

        if (is_admin()) {
            CAZ_Sentry_AdminPage::boot();
        }

        add_action('caz_sentry_scan', array(__CLASS__, 'run_scan'));
        add_action('init', array(__CLASS__, 'ensure_schedule'));
    }

    public static function ensure_schedule()
    {
        if (!wp_next_scheduled('caz_sentry_scan')) {
            // Start soon so the baseline exists within minutes of install,
            // then settle into the hourly rhythm.
            wp_schedule_event(time() + 60, 'hourly', 'caz_sentry_scan');
        }
    }

    public static function run_scan()
    {
        CAZ_Sentry_Baseline::scan('cron');
    }

}

CAZ_Sentry::boot_early();
CAZ_Sentry::boot_wp();
