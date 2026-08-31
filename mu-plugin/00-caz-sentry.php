<?php
/**
 * Plugin Name: Sentry loader
 * Description: Loads Sentry as a must-use plugin so it starts before every other plugin on the site.
 *
 * Drop this file at wp-content/mu-plugins/00-caz-sentry.php and put the
 * caz-sentry folder at wp-content/mu-plugins/caz-sentry/.
 *
 * The 00- prefix matters: must-use plugins load in alphabetical order, and
 * Sentry needs to be first so that it is watching before anything else runs.
 */

if (!defined('ABSPATH')) {
    exit;
}

$caz_sentry_main = __DIR__ . '/caz-sentry/caz-sentry.php';

if (file_exists($caz_sentry_main)) {
    require_once $caz_sentry_main;
}
