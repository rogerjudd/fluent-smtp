<?php
/**
 * Append-only forensic journal.
 *
 * Every write here bypasses the stream wrapper (see ignore_start/ignore_end) so
 * that logging can never recurse into the watcher that produced the event.
 */

if (!defined('ABSPATH') && !defined('CAZ_SENTRY_ABSPATH')) {
    exit;
}

class CAZ_Sentry_Journal
{
    const MAX_BYTES     = 8388608; // 8 MB per file before rotation
    const KEEP_ROTATIONS = 5;
    const MAX_PER_REQUEST = 400;   // hard stop so a runaway loop cannot fill the disk

    private static $dir = null;
    private static $written = 0;
    private static $seen = array();
    private static $overflowNoted = false;

    /**
     * Resolve (and create) the log directory.
     *
     * Define CAZ_SENTRY_LOG_DIR in wp-config.php to place it outside the
     * webroot, which is strongly preferred: malware cannot read what it
     * cannot reach, and a wp-content wipe will not take the evidence with it.
     */
    public static function dir()
    {
        if (self::$dir !== null) {
            return self::$dir;
        }

        if (defined('CAZ_SENTRY_LOG_DIR') && CAZ_SENTRY_LOG_DIR) {
            $dir = rtrim(CAZ_SENTRY_LOG_DIR, '/\\');
        } else {
            $dir = CAZ_SENTRY_CONTENT_DIR . '/caz-sentry';
        }

        self::$dir = $dir;
        self::ensure_dir($dir);

        return self::$dir;
    }

    private static function ensure_dir($dir)
    {
        self::ignore_start();

        if (is_dir($dir)) {
            // Already set up; the guard files were written alongside it, so
            // do not pay for four stat calls on every request.
            self::ignore_end();
            return;
        }

        @mkdir($dir, 0755, true);

        // Deny direct web access in case the directory sits inside the webroot.
        $guards = array(
            '.htaccess' => "Require all denied\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n",
            'index.php' => "<?php // Silence is golden.\n",
            'web.config' => "<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
        );

        foreach ($guards as $name => $body) {
            $path = $dir . '/' . $name;
            if (!file_exists($path)) {
                @file_put_contents($path, $body);
            }
        }

        self::ignore_end();
    }

    /**
     * Record one event. $event must contain at least 'type'.
     */
    public static function write(array $event)
    {
        if (self::$written >= self::MAX_PER_REQUEST) {
            if (!self::$overflowNoted) {
                self::$overflowNoted = true;
                self::$written = 0; // allow this one final line through
                self::write(array(
                    'type'     => 'journal_overflow',
                    'severity' => 'warn',
                    'note'     => 'Per-request event cap reached; further events in this request were dropped.',
                ));
                self::$written = self::MAX_PER_REQUEST + 1;
            }
            return;
        }

        $event['ts']  = microtime(true);
        $event['at']  = gmdate('Y-m-d H:i:s', (int) $event['ts']) . ' UTC';
        $event['req'] = CAZ_Sentry_Context::request_id();

        if (!isset($event['severity'])) {
            $event['severity'] = 'info';
        }

        // Collapse identical repeats inside one request (e.g. a loop rewriting
        // the same file) so the journal stays readable.
        $fingerprint = md5($event['type'] . '|' . (isset($event['path']) ? $event['path'] : '') . '|' . (isset($event['blame']) ? $event['blame'] : ''));
        if (isset(self::$seen[$fingerprint])) {
            self::$seen[$fingerprint]++;
            return;
        }
        self::$seen[$fingerprint] = 1;

        // The request fingerprint is expensive to build, so attach it only to
        // the first event of a request and reference it by id thereafter.
        if (self::$written === 0) {
            $event['context'] = CAZ_Sentry_Context::snapshot();
        }

        self::append('events.log', $event);
        self::$written++;

        if (in_array($event['severity'], array('critical', 'high'), true)) {
            CAZ_Sentry_Alerts::queue($event);
        }
    }

    public static function append($file, array $row)
    {
        $dir = self::dir();
        $path = $dir . '/' . $file;

        $line = json_encode($row, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        if ($line === false) {
            $line = json_encode(array('type' => 'encode_failure', 'orig_type' => isset($row['type']) ? $row['type'] : '?'));
        }

        self::ignore_start();
        self::rotate_if_needed($path);
        @file_put_contents($path, $line . "\n", FILE_APPEND | LOCK_EX);
        self::ignore_end();
    }

    private static function rotate_if_needed($path)
    {
        if (!file_exists($path)) {
            return;
        }
        if (filesize($path) < self::MAX_BYTES) {
            return;
        }

        for ($i = self::KEEP_ROTATIONS - 1; $i >= 1; $i--) {
            $from = $path . '.' . $i;
            $to   = $path . '.' . ($i + 1);
            if (file_exists($from)) {
                @rename($from, $to);
            }
        }
        @rename($path, $path . '.1');
    }

    /**
     * Read the most recent $limit events, newest first.
     */
    public static function tail($file = 'events.log', $limit = 200, $filter = null)
    {
        $path = self::dir() . '/' . $file;
        $rows = array();

        self::ignore_start();
        $candidates = array($path);
        for ($i = 1; $i <= self::KEEP_ROTATIONS; $i++) {
            $candidates[] = $path . '.' . $i;
        }

        foreach ($candidates as $candidate) {
            if (count($rows) >= $limit || !file_exists($candidate)) {
                continue;
            }
            $lines = @file($candidate, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (!$lines) {
                continue;
            }
            $lines = array_reverse($lines);
            foreach ($lines as $line) {
                if (count($rows) >= $limit) {
                    break;
                }
                $row = json_decode($line, true);
                if (!is_array($row)) {
                    continue;
                }
                if (is_callable($filter) && !call_user_func($filter, $row)) {
                    continue;
                }
                $rows[] = $row;
            }
        }
        self::ignore_end();

        return $rows;
    }

    public static function ignore_start()
    {
        if (class_exists('CAZ_Sentry_Write_Watcher', false)) {
            CAZ_Sentry_Write_Watcher::ignore_start();
        }
    }

    public static function ignore_end()
    {
        if (class_exists('CAZ_Sentry_Write_Watcher', false)) {
            CAZ_Sentry_Write_Watcher::ignore_end();
        }
    }
}
