<?php
/**
 * Fail-safe for the stream wrapper.
 *
 * Taking over file:// is powerful but intrusive, so the wrapper serves a
 * probation period. Each request marks "in flight" before registering and
 * clears the mark on a clean shutdown. If requests keep dying while the
 * wrapper is on, it disables itself and the site keeps running in light mode.
 *
 * Once a run of clean requests proves it out, the guard stops writing state
 * altogether so there is no per-request IO cost in steady state.
 */

if (!defined('ABSPATH')) {
    exit;
}

class CAZ_Sentry_Guard
{
    const PROBATION_REQUESTS = 25;
    const FAILURE_LIMIT      = 3;

    private static $state    = null;
    private static $armed    = false;
    private static $stateFile = '';

    private static function file()
    {
        if (self::$stateFile === '') {
            self::$stateFile = CAZ_Sentry_Journal::dir() . '/guard.json';
        }
        return self::$stateFile;
    }

    private static function load()
    {
        if (self::$state !== null) {
            return self::$state;
        }

        CAZ_Sentry_Journal::ignore_start();
        $raw = @file_get_contents(self::file());
        CAZ_Sentry_Journal::ignore_end();

        $state = $raw ? json_decode($raw, true) : null;
        if (!is_array($state)) {
            $state = array('inflight' => 0, 'failures' => 0, 'clean' => 0, 'verified' => 0, 'disabled' => 0);
        }

        self::$state = $state + array('inflight' => 0, 'failures' => 0, 'clean' => 0, 'verified' => 0, 'disabled' => 0);

        return self::$state;
    }

    private static function save()
    {
        CAZ_Sentry_Journal::ignore_start();
        @file_put_contents(self::file(), json_encode(self::$state), LOCK_EX);
        CAZ_Sentry_Journal::ignore_end();
    }

    /**
     * @return bool Whether it is safe to register the stream wrapper.
     */
    public static function may_arm()
    {
        $state = self::load();

        if (!empty($state['disabled'])) {
            return false;
        }

        // Proven stable: no further bookkeeping, no per-request writes.
        if (!empty($state['verified'])) {
            return true;
        }

        // A previous request armed the wrapper and never reached shutdown.
        if (!empty($state['inflight'])) {
            self::$state['failures']++;
            self::$state['inflight'] = 0;

            if (self::$state['failures'] >= self::FAILURE_LIMIT) {
                self::$state['disabled'] = 1;
                self::save();
                CAZ_Sentry_Journal::write(array(
                    'type'     => 'watcher_auto_disabled',
                    'severity' => 'warn',
                    'note'     => 'Requests failed to complete ' . self::FAILURE_LIMIT . ' times with the write watcher active, so it has been switched off. Scans and database tripwires continue. Delete guard.json in the log directory to re-arm.',
                ));
                return false;
            }

            self::save();
        }

        return true;
    }

    public static function arm()
    {
        $state = self::load();

        if (!empty($state['verified'])) {
            self::$armed = true;
            return;
        }

        self::$state['inflight'] = 1;
        self::save();
        self::$armed = true;

        register_shutdown_function(array(__CLASS__, 'disarm'));
    }

    public static function disarm()
    {
        if (!self::$armed || !empty(self::$state['verified'])) {
            return;
        }

        // A fatal error still runs shutdown functions, so only count the
        // request as clean if PHP is not unwinding from one.
        $error = error_get_last();
        $fatal = $error && in_array($error['type'], array(E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR, E_USER_ERROR), true);

        if ($fatal) {
            self::$state['inflight'] = 1; // leave the mark so the next boot counts it
            self::save();
            return;
        }

        self::$state['inflight'] = 0;
        self::$state['failures'] = 0;
        self::$state['clean']++;

        if (self::$state['clean'] >= self::PROBATION_REQUESTS) {
            self::$state['verified'] = 1;
            CAZ_Sentry_Journal::write(array(
                'type'     => 'watcher_verified',
                'severity' => 'info',
                'note'     => 'Write watcher completed ' . self::PROBATION_REQUESTS . ' clean requests and is now in steady state.',
            ));
        }

        self::save();
    }

    public static function status()
    {
        return self::load();
    }

    public static function reset()
    {
        self::$state = array('inflight' => 0, 'failures' => 0, 'clean' => 0, 'verified' => 0, 'disabled' => 0);
        self::save();
    }
}
