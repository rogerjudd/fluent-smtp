<?php
/**
 * Database-side tripwires.
 *
 * Plenty of WordPress infections never touch a file. They live in wp_options,
 * in a scheduled event, in a hidden administrator account, or in the post
 * content itself. These hooks watch the places that persistence actually uses.
 */

if (!defined('ABSPATH') && !defined('CAZ_SENTRY_ABSPATH')) {
    exit;
}

class CAZ_Sentry_DbWatcher
{
    const MAX_VALUE_SCAN = 262144;

    /** Options that should almost never change on a settled site. */
    private static $watchedOptions = array(
        'siteurl'               => 'critical',
        'home'                  => 'critical',
        'users_can_register'    => 'high',
        'default_role'          => 'high',
        'admin_email'           => 'high',
        'new_admin_email'       => 'high',
        'active_plugins'        => 'medium',
        'template'              => 'high',
        'stylesheet'            => 'high',
        'wp_user_roles'         => 'high',
        'permalink_structure'   => 'medium',
        'fs_method'             => 'medium',
        'auto_update_plugins'   => 'medium',
        'recently_activated'    => 'info',
        'blog_public'           => 'medium',
    );

    public static function boot()
    {
        add_action('updated_option', array(__CLASS__, 'on_option_change'), 10, 3);
        add_action('added_option', array(__CLASS__, 'on_option_added'), 10, 2);
        add_action('deleted_option', array(__CLASS__, 'on_option_deleted'), 10, 1);

        add_action('user_register', array(__CLASS__, 'on_user_register'), 10, 1);
        add_action('set_user_role', array(__CLASS__, 'on_role_change'), 10, 3);
        add_action('profile_update', array(__CLASS__, 'on_profile_update'), 10, 2);
        add_action('deleted_user', array(__CLASS__, 'on_user_deleted'), 10, 1);

        add_filter('pre_schedule_event', array(__CLASS__, 'on_schedule_event'), 10, 2);

        add_action('activated_plugin', array(__CLASS__, 'on_plugin_activated'), 10, 2);
        add_action('deactivated_plugin', array(__CLASS__, 'on_plugin_deactivated'), 10, 2);
        add_action('switch_theme', array(__CLASS__, 'on_theme_switch'), 10, 1);
        add_action('upgrader_process_complete', array(__CLASS__, 'on_upgrade'), 10, 2);

        add_action('post_updated', array(__CLASS__, 'on_post_updated'), 10, 3);
    }

    // ------------------------------------------------------------- options

    public static function on_option_change($option, $old, $new)
    {
        if (self::ignorable_option($option)) {
            return;
        }

        $severity = isset(self::$watchedOptions[$option]) ? self::$watchedOptions[$option] : null;
        $hits     = self::scan_value($new);

        if (!$severity && !$hits) {
            return;
        }
        if ($hits) {
            $worst = CAZ_Sentry_Signatures::worst_severity($hits);
            $severity = self::higher($severity, $worst);
        }

        // An unchanged serialisation is a no-op write; ignore it.
        if (self::flatten($old) === self::flatten($new)) {
            return;
        }

        $event = array(
            'type'     => 'option_changed',
            'severity' => $severity,
            'option'   => $option,
            'blame'    => self::blame(),
            'old'      => CAZ_Sentry_Context::clip(self::flatten($old), 600),
            'new'      => CAZ_Sentry_Context::clip(self::flatten($new), 1200),
        );
        if ($hits) {
            $event['signatures'] = $hits;
        }

        CAZ_Sentry_Journal::write($event);
    }

    public static function on_option_added($option, $value)
    {
        if (self::ignorable_option($option)) {
            return;
        }

        $hits = self::scan_value($value);
        if (!$hits && !isset(self::$watchedOptions[$option])) {
            return;
        }

        CAZ_Sentry_Journal::write(array(
            'type'       => 'option_added',
            'severity'   => $hits ? CAZ_Sentry_Signatures::worst_severity($hits) : 'medium',
            'option'     => $option,
            'signatures' => $hits,
            'blame'      => self::blame(),
            'new'        => CAZ_Sentry_Context::clip(self::flatten($value), 1200),
        ));
    }

    public static function on_option_deleted($option)
    {
        if (!isset(self::$watchedOptions[$option])) {
            return;
        }
        CAZ_Sentry_Journal::write(array(
            'type'     => 'option_deleted',
            'severity' => 'high',
            'option'   => $option,
            'blame'    => self::blame(),
        ));
    }

    private static function ignorable_option($option)
    {
        $option = (string) $option;

        if (strpos($option, '_transient_') === 0 || strpos($option, '_site_transient_') === 0) {
            return true;
        }
        // High-churn bookkeeping that would drown the journal.
        static $noise = array(
            'cron' => 1, 'rewrite_rules' => 1, 'wp_force_deactivated_plugins' => 1,
            'litespeed.admin_display.messages' => 1, 'rocket_boxes' => 1,
            'action_scheduler_lock_async-request-runner' => 1,
        );

        return isset($noise[$option]);
    }

    private static function scan_value($value)
    {
        $flat = self::flatten($value);
        if ($flat === '' || strlen($flat) > self::MAX_VALUE_SCAN) {
            return array();
        }
        return CAZ_Sentry_Signatures::match($flat);
    }

    private static function flatten($value)
    {
        if (is_scalar($value) || $value === null) {
            return (string) $value;
        }
        $encoded = @json_encode($value, JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
        return $encoded === false ? '(unserialisable)' : $encoded;
    }

    // --------------------------------------------------------------- users

    public static function on_user_register($user_id)
    {
        $user = get_userdata($user_id);
        if (!$user) {
            return;
        }
        $roles = (array) $user->roles;
        $admin = in_array('administrator', $roles, true);

        CAZ_Sentry_Journal::write(array(
            'type'      => 'user_created',
            'severity'  => $admin ? 'critical' : 'medium',
            'user_id'   => (int) $user_id,
            'login'     => $user->user_login,
            'email'     => $user->user_email,
            'roles'     => array_values($roles),
            'blame'     => self::blame(),
        ));
    }

    public static function on_role_change($user_id, $role, $old_roles)
    {
        if ($role !== 'administrator' && !in_array('administrator', (array) $old_roles, true)) {
            return;
        }
        $user = get_userdata($user_id);

        CAZ_Sentry_Journal::write(array(
            'type'      => 'role_changed',
            'severity'  => $role === 'administrator' ? 'critical' : 'high',
            'user_id'   => (int) $user_id,
            'login'     => $user ? $user->user_login : '?',
            'new_role'  => $role,
            'old_roles' => array_values((array) $old_roles),
            'blame'     => self::blame(),
        ));
    }

    public static function on_profile_update($user_id, $old_user)
    {
        $user = get_userdata($user_id);
        if (!$user || !$old_user) {
            return;
        }

        $changes = array();
        if ($user->user_email !== $old_user->user_email) {
            $changes['email'] = array($old_user->user_email, $user->user_email);
        }
        if ($user->user_pass !== $old_user->user_pass) {
            $changes['password'] = 'changed';
        }
        if ($user->user_login !== $old_user->user_login) {
            $changes['login'] = array($old_user->user_login, $user->user_login);
        }

        if (!$changes) {
            return;
        }

        $admin = in_array('administrator', (array) $user->roles, true);

        CAZ_Sentry_Journal::write(array(
            'type'     => 'user_updated',
            'severity' => $admin ? 'high' : 'info',
            'user_id'  => (int) $user_id,
            'login'    => $user->user_login,
            'changes'  => $changes,
            'blame'    => self::blame(),
        ));
    }

    public static function on_user_deleted($user_id)
    {
        CAZ_Sentry_Journal::write(array(
            'type'     => 'user_deleted',
            'severity' => 'medium',
            'user_id'  => (int) $user_id,
            'blame'    => self::blame(),
        ));
    }

    // ---------------------------------------------------------------- cron

    /**
     * Scheduled events are the standard way an infection survives a cleanup:
     * the payload is deleted, the cron entry re-downloads it an hour later.
     */
    public static function on_schedule_event($pre, $event)
    {
        if (!is_object($event) || empty($event->hook)) {
            return $pre;
        }

        $hook = (string) $event->hook;

        // A hook with no listener registered is scheduling work that only the
        // attacker's code knows how to perform.
        $orphan = !has_action($hook);

        if (!$orphan && !CAZ_Sentry_Signatures::match($hook)) {
            return $pre;
        }

        CAZ_Sentry_Journal::write(array(
            'type'      => 'cron_scheduled',
            'severity'  => $orphan ? 'high' : 'medium',
            'hook'      => $hook,
            'schedule'  => isset($event->schedule) ? $event->schedule : '(once)',
            'timestamp' => isset($event->timestamp) ? gmdate('Y-m-d H:i:s', (int) $event->timestamp) . ' UTC' : '',
            'args'      => CAZ_Sentry_Context::clip(self::flatten(isset($event->args) ? $event->args : array()), 600),
            'orphan'    => $orphan ? 1 : 0,
            'blame'     => self::blame(),
        ));

        return $pre;
    }

    // ------------------------------------------------- plugins and themes

    public static function on_plugin_activated($plugin, $network = false)
    {
        CAZ_Sentry_Journal::write(array(
            'type'     => 'plugin_activated',
            'severity' => 'medium',
            'plugin'   => $plugin,
            'blame'    => self::blame(),
        ));
    }

    public static function on_plugin_deactivated($plugin, $network = false)
    {
        CAZ_Sentry_Journal::write(array(
            'type'     => 'plugin_deactivated',
            'severity' => 'medium',
            'plugin'   => $plugin,
            'blame'    => self::blame(),
        ));
    }

    public static function on_theme_switch($theme)
    {
        CAZ_Sentry_Journal::write(array(
            'type'     => 'theme_switched',
            'severity' => 'high',
            'theme'    => (string) $theme,
            'blame'    => self::blame(),
        ));
    }

    public static function on_upgrade($upgrader, $data)
    {
        CAZ_Sentry_Journal::write(array(
            'type'     => 'package_installed',
            'severity' => 'info',
            'action'   => isset($data['action']) ? $data['action'] : '',
            'kind'     => isset($data['type']) ? $data['type'] : '',
            'items'    => CAZ_Sentry_Context::clip(self::flatten($data), 600),
            'blame'    => self::blame(),
        ));
    }

    // ---------------------------------------------------------------- posts

    public static function on_post_updated($post_id, $post_after, $post_before)
    {
        if (!is_object($post_after) || !is_object($post_before)) {
            return;
        }
        if (in_array($post_after->post_type, array('revision', 'nav_menu_item'), true)) {
            return;
        }

        $after  = (string) $post_after->post_content;
        $before = (string) $post_before->post_content;

        if ($after === $before) {
            return;
        }

        $hits = CAZ_Sentry_Signatures::match($after);

        // Content that gained a script or iframe it did not have before.
        $gained = array();
        foreach (array('<script', '<iframe', 'base64,', 'eval(') as $needle) {
            if (substr_count(strtolower($after), $needle) > substr_count(strtolower($before), $needle)) {
                $gained[] = $needle;
            }
        }

        if (!$hits && !$gained) {
            return;
        }

        CAZ_Sentry_Journal::write(array(
            'type'       => 'post_content_injected',
            'severity'   => $hits ? CAZ_Sentry_Signatures::worst_severity($hits) : 'medium',
            'post_id'    => (int) $post_id,
            'post_type'  => $post_after->post_type,
            'title'      => CAZ_Sentry_Context::clip($post_after->post_title, 120),
            'gained'     => $gained,
            'signatures' => $hits,
            'blame'      => self::blame(),
        ));
    }

    // -------------------------------------------------------------- helper

    /** Return whichever of two severities is more serious. */
    private static function higher($a, $b)
    {
        $rank = array('info' => 0, 'medium' => 1, 'high' => 2, 'critical' => 3);
        if ($a === null || !isset($rank[$a])) {
            return $b;
        }
        if ($b === null || !isset($rank[$b])) {
            return $a;
        }
        return $rank[$b] > $rank[$a] ? $b : $a;
    }

    /**
     * Cheap caller attribution for hook-based events: the first frame outside
     * WordPress core's hook machinery and outside this tool.
     */
    private static function blame()
    {
        $frames = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 25);
        $root   = rtrim(str_replace('\\', '/', CAZ_SENTRY_ABSPATH), '/');
        $self   = str_replace('\\', '/', dirname(dirname(__FILE__)));

        foreach ($frames as $frame) {
            if (empty($frame['file'])) {
                continue;
            }
            $file = str_replace('\\', '/', $frame['file']);

            if (strpos($file, $self) === 0) {
                continue;
            }
            if (preg_match('#/wp-includes/(plugin|class-wp-hook|option|functions)\.php$#', $file)) {
                continue;
            }

            $rel = strpos($file, $root . '/') === 0 ? substr($file, strlen($root) + 1) : $file;

            return $rel . ':' . (isset($frame['line']) ? (int) $frame['line'] : 0);
        }

        return '';
    }
}
