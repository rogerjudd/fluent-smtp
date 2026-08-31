<?php
/**
 * Rate-limited notification of serious events.
 *
 * The journal is the record; this is the tap on the shoulder. It batches
 * everything from one request into a single message and refuses to send more
 * than one message per cooldown window, so a reinfection loop cannot turn
 * into a thousand emails.
 */

if (!defined('ABSPATH')) {
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
        if (function_exists('get_option')) {
            $stored = get_option('caz_sentry_alert_email', '');
            if ($stored) {
                return $stored;
            }
        }
        return '';
    }

    public static function flush()
    {
        if (!self::$queue || !function_exists('wp_mail')) {
            return;
        }

        $queue      = self::$queue;
        self::$queue = array();

        $last = (int) get_option('caz_sentry_last_alert', 0);
        $now  = time();

        if (($now - $last) < self::COOLDOWN_SECONDS) {
            // Still record that events were suppressed so the count in the
            // dashboard matches reality.
            update_option('caz_sentry_suppressed', (int) get_option('caz_sentry_suppressed', 0) + count($queue), false);
            return;
        }

        update_option('caz_sentry_last_alert', $now, false);

        $suppressed = (int) get_option('caz_sentry_suppressed', 0);
        if ($suppressed) {
            update_option('caz_sentry_suppressed', 0, false);
        }

        $site    = function_exists('get_bloginfo') ? get_bloginfo('name') : 'WordPress';
        $subject = sprintf('[Sentry] %d suspicious event%s on %s', count($queue), count($queue) === 1 ? '' : 's', $site);

        $body  = "CAZ Sentry recorded activity worth looking at.\n\n";
        $body .= 'Site: ' . (function_exists('home_url') ? home_url('/') : '') . "\n";
        $body .= 'Time: ' . gmdate('Y-m-d H:i:s') . " UTC\n\n";

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

        $body .= "Full detail: " . (function_exists('admin_url') ? admin_url('tools.php?page=caz-sentry') : '') . "\n";
        $body .= "Journal:     " . CAZ_Sentry_Journal::dir() . "/events.log\n";

        @wp_mail(self::recipient(), $subject, $body);

        self::webhook($queue);
    }

    private static function webhook($queue)
    {
        $url = defined('CAZ_SENTRY_WEBHOOK') ? CAZ_SENTRY_WEBHOOK : get_option('caz_sentry_webhook', '');
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
