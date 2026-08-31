<?php
/**
 * Rate-limited notification of serious events.
 *
 * The journal is the record; this is the tap on the shoulder. It batches
 * everything from one request into a single message and refuses to send more
 * than one message per cooldown window, so a reinfection loop cannot turn
 * into a thousand emails.
 */

if (!defined('ABSPATH') && !defined('CAZ_SENTRY_ABSPATH')) {
    exit;
}

class CAZ_Sentry_Alerts
{
    const COOLDOWN_SECONDS = 900; // 15 minutes
    const MAX_IN_MESSAGE   = 15;

    private static $queue      = array();
    private static $registered = false;

    public static function queue(array $event)
    {
        if (!self::enabled()) {
            return;
        }

        self::$queue[] = $event;

        if (!self::$registered) {
            self::$registered = true;
            register_shutdown_function(array(__CLASS__, 'flush'));
        }
    }

    private static function enabled()
    {
        if (defined('CAZ_SENTRY_ALERTS') && !CAZ_SENTRY_ALERTS) {
            return false;
        }
        return (bool) self::recipient();
    }

    public static function recipient()
    {
        if (defined('CAZ_SENTRY_ALERT_EMAIL') && CAZ_SENTRY_ALERT_EMAIL) {
            return CAZ_SENTRY_ALERT_EMAIL;
        }
        $stored = self::state_get('alert_email', '');

        return $stored ? $stored : '';
    }

    /**
     * Read a small piece of state.
     *
     * When Sentry is started from prepend.php there is no WordPress, so no
     * options table — and that is exactly the case that matters, because a
     * standalone backdoor request is the one we most want to hear about.
     * Fall back to a file beside the journal.
     */
    private static function state_get($key, $default = 0)
    {
        if (function_exists('get_option') && isset($GLOBALS['wpdb'])) {
            return get_option('caz_sentry_' . $key, $default);
        }

        CAZ_Sentry_Journal::ignore_start();
        $raw = @file_get_contents(CAZ_Sentry_Journal::dir() . '/alerts.json');
        CAZ_Sentry_Journal::ignore_end();

        $state = $raw ? json_decode($raw, true) : null;

        return (is_array($state) && isset($state[$key])) ? $state[$key] : $default;
    }

    private static function state_set($key, $value)
    {
        if (function_exists('update_option') && isset($GLOBALS['wpdb'])) {
            update_option('caz_sentry_' . $key, $value, false);
            return;
        }

        $path = CAZ_Sentry_Journal::dir() . '/alerts.json';

        CAZ_Sentry_Journal::ignore_start();
        $raw   = @file_get_contents($path);
        $state = $raw ? json_decode($raw, true) : array();
        if (!is_array($state)) {
            $state = array();
        }
        $state[$key] = $value;
        @file_put_contents($path, json_encode($state), LOCK_EX);
        CAZ_Sentry_Journal::ignore_end();
    }

    /** wp_mail when WordPress is up, PHP's mail() when it is not. */
    private static function send($to, $subject, $body)
    {
        if (function_exists('wp_mail')) {
            return (bool) @wp_mail($to, $subject, $body);
        }
        if (function_exists('mail')) {
            return (bool) @mail($to, $subject, $body);
        }
        return false;
    }

    public static function flush()
    {
        if (!self::$queue) {
            return;
        }

        $queue      = self::$queue;
        self::$queue = array();

        $last = (int) self::state_get('last_alert', 0);
        $now  = time();

        if (($now - $last) < self::COOLDOWN_SECONDS) {
            // Still record that events were suppressed so the count in the
            // dashboard matches reality.
            self::state_set('suppressed', (int) self::state_get('suppressed', 0) + count($queue));
            return;
        }

        self::state_set('last_alert', $now);

        $suppressed = (int) self::state_get('suppressed', 0);
        if ($suppressed) {
            self::state_set('suppressed', 0);
        }

        // WordPress may not be loaded at all — a standalone backdoor request
        // never boots it — so fall back to the hostname.
        $host    = isset($_SERVER['HTTP_HOST']) ? (string) $_SERVER['HTTP_HOST'] : 'this site';
        $site    = function_exists('get_bloginfo') ? get_bloginfo('name') : $host;
        $subject = sprintf('[Sentry] %d suspicious event%s on %s', count($queue), count($queue) === 1 ? '' : 's', $site);

        $body  = "CAZ Sentry recorded activity worth looking at.\n\n";
        $body .= 'Site: ' . (function_exists('home_url') ? home_url('/') : $host) . "\n";
        $body .= 'Time: ' . gmdate('Y-m-d H:i:s') . " UTC\n";

        if (!function_exists('wp_mail')) {
            $body .= "\nNOTE: this request never loaded WordPress. That means it hit a PHP\n"
                   . "file directly rather than going through the site — which is exactly\n"
                   . "how a standalone backdoor is used. Treat the entry point below as\n"
                   . "hostile until proven otherwise.\n";
        }

        $body .= "\n";

        $context = CAZ_Sentry_Context::snapshot();
        $body .= "Request that triggered this:\n";
        $body .= '  ' . (isset($context['method']) ? $context['method'] : '?') . ' ' . (isset($context['uri']) ? $context['uri'] : '(no uri)') . "\n";
        $body .= '  IP: ' . (isset($context['ip']) ? $context['ip'] : '?') . "\n";
        $body .= '  User: ' . (!empty($context['user_login']) ? $context['user_login'] : 'not logged in') . "\n";
        $body .= '  Entry point: ' . (isset($context['entry']) ? $context['entry'] : '?')
               . ($context['is_cron'] ? ' (cron)' : '') . ($context['is_cli'] ? ' (cli)' : '') . "\n\n";

        $body .= str_repeat('-', 60) . "\n\n";

        foreach (array_slice($queue, 0, self::MAX_IN_MESSAGE) as $i => $event) {
            $body .= ($i + 1) . '. [' . strtoupper($event['severity']) . '] ' . $event['type'] . "\n";
            if (!empty($event['path'])) {
                $body .= '   File:    ' . $event['path'] . "\n";
            }
            if (!empty($event['option'])) {
                $body .= '   Option:  ' . $event['option'] . "\n";
            }
            if (!empty($event['blame'])) {
                $body .= '   Written by: ' . $event['blame'] . "\n";
            }
            if (!empty($event['origin'])) {
                $body .= '   Component:  ' . $event['origin'] . "\n";
            }
            if (!empty($event['signatures'])) {
                $body .= '   Matched:    ' . implode(', ', (array) $event['signatures']) . "\n";
            }
            if (!empty($event['stack'])) {
                $body .= "   Call stack:\n";
                foreach (array_slice((array) $event['stack'], 0, 8) as $frame) {
                    $body .= '     ' . $frame . "\n";
                }
            }
            $body .= "\n";
        }

        if (count($queue) > self::MAX_IN_MESSAGE) {
            $body .= '… and ' . (count($queue) - self::MAX_IN_MESSAGE) . " more events in this request.\n\n";
        }
        if ($suppressed) {
            $body .= $suppressed . " further events were recorded during the notification cooldown.\n\n";
        }

        if (function_exists('admin_url')) {
            $body .= "Full detail: " . admin_url('tools.php?page=caz-sentry') . "\n";
        }
        $body .= "Journal:     " . CAZ_Sentry_Journal::dir() . "/events.log\n";

        self::send(self::recipient(), $subject, $body);

        self::webhook($queue);
    }

    private static function webhook($queue)
    {
        $url = defined('CAZ_SENTRY_WEBHOOK') ? CAZ_SENTRY_WEBHOOK : self::state_get('webhook', '');
        if (!$url || !function_exists('wp_remote_post')) {
            return;
        }

        @wp_remote_post($url, array(
            'timeout'  => 5,
            'blocking' => false,
            'headers'  => array('Content-Type' => 'application/json'),
            'body'     => wp_json_encode(array(
                'site'    => function_exists('home_url') ? home_url('/') : '',
                'count'   => count($queue),
                'events'  => array_slice($queue, 0, 5),
                'context' => CAZ_Sentry_Context::snapshot(),
            )),
        ));
    }
}
