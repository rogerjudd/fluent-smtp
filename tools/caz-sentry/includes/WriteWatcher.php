<?php
/**
 * Intercepts every filesystem write by taking over the file:// stream wrapper.
 *
 * This is the piece that ordinary malware scanners do not give you. A scanner
 * tells you index.php changed an hour ago. This tells you which line of which
 * file called file_put_contents(), during which HTTP request, from which IP —
 * including when the caller is eval()'d code with no file of its own.
 *
 * Safety posture:
 *  - It never blocks a write. It observes, records, and gets out of the way.
 *  - Every native call is wrapped so a failure inside the watcher degrades to
 *    normal filesystem behaviour rather than a broken site.
 *  - A self-test runs at registration; if the wrapper misbehaves on this PHP
 *    build it unregisters itself before any page is served.
 *  - A probation guard disables the wrapper automatically if requests start
 *    dying while it is active (see CAZ_Sentry_Guard).
 */

if (!defined('ABSPATH')) {
    exit;
}

class CAZ_Sentry_Write_Watcher
{
    const PROTOCOL       = 'file';
    const CAPTURE_LIMIT  = 262144; // bytes retained for signature scanning
    const SAMPLE_BYTES   = 2048;   // bytes copied into the journal

    /** @var resource|null Set by PHP when a stream context is supplied. */
    public $context;

    private $handle    = null;
    private $path      = '';
    private $mode      = '';
    private $dirHandle = null;

    private $watching   = false;
    private $quiet      = false;
    private $capture    = '';
    private $bytes      = 0;
    private $trace      = null;
    private $logged     = false;
    private $existed    = false;
    private $sizeBefore = 0;

    private static $active   = false;
    private static $depth    = 0;
    private static $ignore   = 0;
    private static $selfDir  = '';
    private static $roots    = array();
    private static $quietPaths = array();
    private static $skipped  = 0;

    /** Extensions worth watching. Everything else passes through untouched. */
    private static $watchExt = array(
        'php' => 1, 'php3' => 1, 'php4' => 1, 'php5' => 1, 'php7' => 1, 'php8' => 1,
        'phtml' => 1, 'phps' => 1, 'phar' => 1, 'inc' => 1, 'module' => 1,
        'js' => 1, 'mjs' => 1, 'htaccess' => 1, 'ini' => 1, 'json' => 1,
        'ico' => 1, 'gif' => 1, 'png' => 1, 'jpg' => 1, 'jpeg' => 1, 'svg' => 1,
        'txt' => 1, 'html' => 1, 'htm' => 1, 'suspected' => 1,
    );

    private static $watchNames = array(
        '.htaccess' => 1, '.user.ini' => 1, 'wp-config.php' => 1,
        '.htpasswd' => 1, 'php.ini' => 1, 'web.config' => 1, 'robots.txt' => 1,
    );

    // ---------------------------------------------------------------- setup

    public static function register()
    {
        if (self::$active) {
            return true;
        }

        self::$selfDir = dirname(dirname(__FILE__));

        $root = defined('ABSPATH') ? rtrim(str_replace('\\', '/', ABSPATH), '/') : '';
        $content = defined('WP_CONTENT_DIR') ? rtrim(str_replace('\\', '/', WP_CONTENT_DIR), '/') : $root . '/wp-content';

        self::$roots = array_values(array_unique(array_filter(array($root, $content))));

        // Paths that legitimately churn on every request. Writes here are not
        // journalled unless the content itself trips a signature, so the log
        // stays readable without creating a blind spot.
        //
        // The system temp directory is deliberately NOT listed. Anything
        // outside the install is already ignored by watch_level(), and on
        // hosts where upload_tmp_dir sits inside the webroot, quieting it
        // would hide exactly the staging directory an attacker would use.
        self::$quietPaths = array(
            $content . '/cache/',
            $content . '/wp-rocket-config/',
            $content . '/uploads/cache/',
            $content . '/uploads/elementor/css/',
            $content . '/uploads/fluentform/',
            $content . '/upgrade/',
            $content . '/caz-sentry/',
            $content . '/uploads/caz-sentry/',
            $content . '/et-cache/',
        );
        if (defined('CAZ_SENTRY_LOG_DIR') && CAZ_SENTRY_LOG_DIR) {
            self::$quietPaths[] = rtrim(str_replace('\\', '/', CAZ_SENTRY_LOG_DIR), '/') . '/';
        }

        if (!@stream_wrapper_unregister(self::PROTOCOL)) {
            return false;
        }
        if (!@stream_wrapper_register(self::PROTOCOL, __CLASS__)) {
            @stream_wrapper_restore(self::PROTOCOL);
            return false;
        }

        self::$active = true;

        if (!self::self_test()) {
            self::unregister();
            CAZ_Sentry_Journal::write(array(
                'type'     => 'watcher_selftest_failed',
                'severity' => 'warn',
                'note'     => 'The file:// wrapper did not behave correctly on this PHP build. Falling back to light mode (scans + database tripwires still run).',
                'php'      => PHP_VERSION,
            ));
            return false;
        }

        return true;
    }

    public static function unregister()
    {
        if (!self::$active) {
            return;
        }
        self::$active = false;
        @stream_wrapper_restore(self::PROTOCOL);
    }

    public static function is_active()
    {
        return self::$active;
    }

    public static function skipped_count()
    {
        return self::$skipped;
    }

    /**
     * Prove the wrapper can round-trip a file before we let it serve a page.
     */
    private static function self_test()
    {
        $probe = CAZ_Sentry_Journal::dir() . '/.selftest';

        self::ignore_start();
        $ok = false;
        $written = @file_put_contents($probe, 'caz-sentry-probe');
        if ($written === 16) {
            $ok = (@file_get_contents($probe) === 'caz-sentry-probe') && @is_file($probe);
        }
        @unlink($probe);
        self::ignore_end();

        return $ok;
    }

    /** Suspend logging (used by our own IO so it cannot recurse). */
    public static function ignore_start()
    {
        self::$ignore++;
    }

    public static function ignore_end()
    {
        if (self::$ignore > 0) {
            self::$ignore--;
        }
    }

    // ------------------------------------------------- native delegation

    private static function native_on()
    {
        if (self::$depth++ === 0 && self::$active) {
            @stream_wrapper_restore(self::PROTOCOL);
        }
    }

    private static function native_off()
    {
        if (--self::$depth === 0 && self::$active) {
            @stream_wrapper_unregister(self::PROTOCOL);
            @stream_wrapper_register(self::PROTOCOL, __CLASS__);
        }
        if (self::$depth < 0) {
            self::$depth = 0;
        }
    }

    // ------------------------------------------------------ path handling

    private static function normalise($path)
    {
        $path = str_replace('\\', '/', (string) $path);
        if (stripos($path, 'file://') === 0) {
            $path = substr($path, 7);
        }
        return $path;
    }

    private static function is_write_mode($mode)
    {
        return (bool) preg_match('/[waxc+]/', (string) $mode);
    }

    /**
     * @return int 0 = ignore entirely, 1 = journal every write, 2 = quiet
     *             (journal only when the content trips a signature)
     */
    private static function watch_level($path)
    {
        if (self::$ignore > 0) {
            return 0;
        }

        $path = self::normalise($path);

        if ($path === '' || strpos($path, '://') !== false) {
            return 0;
        }
        if (self::$selfDir !== '' && strpos($path, str_replace('\\', '/', self::$selfDir)) === 0) {
            return 0;
        }

        $inRoot = false;
        foreach (self::$roots as $root) {
            if ($root !== '' && strpos($path, $root . '/') === 0) {
                $inRoot = true;
                break;
            }
        }
        if (!$inRoot) {
            return 0;
        }

        $name = basename($path);
        $ext  = strtolower((string) pathinfo($name, PATHINFO_EXTENSION));

        $interesting = isset(self::$watchNames[$name])
            || ($ext !== '' && isset(self::$watchExt[$ext]))
            || $ext === '';

        if (!$interesting) {
            return 0;
        }

        foreach (self::$quietPaths as $quiet) {
            if ($quiet !== '' && strpos($path, $quiet) === 0) {
                return 2;
            }
        }

        return 1;
    }

    // ----------------------------------------------------------- reporting

    /**
     * Build a caller trace, skipping our own frames, and work out who to blame.
     */
    private static function trace()
    {
        $frames = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 40);

        $stack   = array();
        $blame   = '';
        $origin  = '';
        $viaEval = false;
        $selfDir = str_replace('\\', '/', self::$selfDir);

        foreach ($frames as $frame) {
            $file = isset($frame['file']) ? str_replace('\\', '/', $frame['file']) : '';

            if ($file !== '' && $selfDir !== '' && strpos($file, $selfDir) === 0) {
                continue;
            }

            $fn = '';
            if (isset($frame['class'])) {
                $fn .= $frame['class'] . (isset($frame['type']) ? $frame['type'] : '::');
            }
            $fn .= isset($frame['function']) ? $frame['function'] : '?';

            $line = isset($frame['line']) ? (int) $frame['line'] : 0;

            if ($file !== '' && (strpos($file, "eval()'d code") !== false
                || strpos($file, 'runtime-created function') !== false
                || strpos($file, 'assert code') !== false)) {
                $viaEval = true;
            }

            $stack[] = self::rel($file) . ':' . $line . ' ' . $fn . '()';

            if ($blame === '' && $file !== '') {
                $blame  = self::rel($file) . ':' . $line;
                $origin = self::origin($file);
            }

            if (count($stack) >= 25) {
                break;
            }
        }

        // If filtering our own frames left nothing to point at, fall back to
        // the raw stack rather than reporting a blank culprit.
        if ($blame === '') {
            foreach ($frames as $frame) {
                if (empty($frame['file'])) {
                    continue;
                }
                $file  = str_replace('\\', '/', $frame['file']);
                $blame = self::rel($file) . ':' . (isset($frame['line']) ? (int) $frame['line'] : 0);
                if ($origin === '') {
                    $origin = self::origin($file);
                }
                break;
            }
        }

        return array(
            'blame'    => $blame,
            'origin'   => $viaEval ? 'eval()d-code' : $origin,
            'via_eval' => $viaEval ? 1 : 0,
            'stack'    => $stack,
        );
    }

    /** Attribute a file to the plugin/theme/core component that owns it. */
    private static function origin($file)
    {
        $file = str_replace('\\', '/', (string) $file);

        if (preg_match('#/wp-content/plugins/([^/]+)/#', $file, $m)) {
            return 'plugin:' . $m[1];
        }
        if (preg_match('#/wp-content/mu-plugins/([^/]+)#', $file, $m)) {
            return 'mu-plugin:' . $m[1];
        }
        if (preg_match('#/wp-content/themes/([^/]+)/#', $file, $m)) {
            return 'theme:' . $m[1];
        }
        if (preg_match('#/wp-content/uploads/#', $file)) {
            return 'uploads(!)';
        }
        if (preg_match('#/wp-(includes|admin)/#', $file, $m)) {
            return 'core:wp-' . $m[1];
        }
        if ($file !== '' && basename($file) === 'wp-cron.php') {
            return 'core:cron';
        }
        return $file === '' ? 'unknown' : 'other';
    }

    private static function rel($file)
    {
        if ($file === '') {
            return '(no file)';
        }
        $root = defined('ABSPATH') ? rtrim(str_replace('\\', '/', ABSPATH), '/') : '';
        $file = str_replace('\\', '/', $file);
        if ($root !== '' && strpos($file, $root . '/') === 0) {
            return substr($file, strlen($root) + 1);
        }
        return $file;
    }

    /**
     * Decide how loudly to shout about a completed write.
     */
    private static function classify($path, $hits, $origin, $viaEval, $isNew)
    {
        $rank  = array('info' => 0, 'medium' => 1, 'high' => 2, 'critical' => 3);
        $level = $hits ? CAZ_Sentry_Signatures::worst_severity($hits) : 'info';

        $bump = function ($candidate) use (&$level, $rank) {
            if ($rank[$candidate] > $rank[$level]) {
                $level = $candidate;
            }
        };

        $path = self::normalise($path);
        $name = basename($path);
        $ext  = strtolower((string) pathinfo($name, PATHINFO_EXTENSION));
        $isPhp = in_array($ext, array('php', 'phtml', 'php5', 'php7', 'php8', 'phar', 'inc'), true);

        // Executable code appearing in the media library is never legitimate.
        if (strpos($path, '/wp-content/uploads/') !== false && $isPhp) {
            $bump('critical');
        }
        // PHP disguised as an image.
        if (in_array($ext, array('ico', 'gif', 'png', 'jpg', 'jpeg', 'txt', 'svg'), true) && $hits) {
            $bump('critical');
        }
        if ($viaEval) {
            $bump('critical');
        }
        if (in_array($name, array('wp-config.php', '.htaccess', '.user.ini', '.htpasswd', 'php.ini'), true)) {
            $bump('high');
        }
        if (preg_match('#/wp-(includes|admin)/#', $path)) {
            $bump('high');
        }
        if ($isNew && $isPhp && preg_match('#/wp-content/(plugins|themes|mu-plugins)/#', $path)) {
            $bump('medium');
        }
        if ($origin === 'uploads(!)') {
            $bump('critical');
        }

        return $level;
    }

    private function report($type, array $extra = array())
    {
        if ($this->logged) {
            return;
        }
        $this->logged = true;

        $trace = $this->trace ? $this->trace : self::trace();
        $hits  = $this->capture !== '' ? CAZ_Sentry_Signatures::match($this->capture) : array();

        if ($this->quiet && !$hits) {
            self::$skipped++;
            return;
        }

        $severity = self::classify($this->path, $hits, $trace['origin'], $trace['via_eval'], !$this->existed);

        $event = array(
            'type'       => $type,
            'severity'   => $severity,
            'path'       => self::rel(self::normalise($this->path)),
            'mode'       => $this->mode,
            'bytes'      => $this->bytes,
            'created'    => $this->existed ? 0 : 1,
            'size_before'=> $this->sizeBefore,
            'blame'      => $trace['blame'],
            'origin'     => $trace['origin'],
            'via_eval'   => $trace['via_eval'],
            'stack'      => $trace['stack'],
        );

        if ($hits) {
            $event['signatures'] = $hits;
        }
        if ($this->capture !== '') {
            $event['sample'] = CAZ_Sentry_Context::clip($this->capture, self::SAMPLE_BYTES);
        }

        CAZ_Sentry_Journal::write(array_merge($event, $extra));
    }

    /** Log a path-level operation (unlink/rename/mkdir/touch/chmod). */
    private static function report_op($type, $path, array $extra = array())
    {
        $trace = self::trace();

        $event = array(
            'type'     => $type,
            'severity' => self::classify($path, array(), $trace['origin'], $trace['via_eval'], false),
            'path'     => self::rel(self::normalise($path)),
            'blame'    => $trace['blame'],
            'origin'   => $trace['origin'],
            'via_eval' => $trace['via_eval'],
            'stack'    => $trace['stack'],
        );

        CAZ_Sentry_Journal::write(array_merge($event, $extra));
    }

    // ------------------------------------------------------- stream methods

    public function stream_open($path, $mode, $options, &$opened_path)
    {
        $this->path = $path;
        $this->mode = $mode;

        $usePath = (bool) ($options & STREAM_USE_PATH);
        $report  = (bool) ($options & STREAM_REPORT_ERRORS);

        $isWrite = self::is_write_mode($mode);
        $level   = $isWrite ? self::watch_level($path) : 0;

        if ($level > 0) {
            $this->watching = true;
            $this->quiet    = ($level === 2);
        }

        self::native_on();

        if ($this->watching) {
            $real = self::normalise($path);
            $this->existed    = @file_exists($real);
            $this->sizeBefore = $this->existed ? (int) @filesize($real) : 0;
        }

        if (is_resource($this->context)) {
            $handle = $report
                ? fopen($path, $mode, $usePath, $this->context)
                : @fopen($path, $mode, $usePath, $this->context);
        } else {
            $handle = $report ? fopen($path, $mode, $usePath) : @fopen($path, $mode, $usePath);
        }

        if ($handle && $usePath) {
            $meta = @stream_get_meta_data($handle);
            if (!empty($meta['uri'])) {
                $opened_path = $meta['uri'];
            }
        }

        self::native_off();

        if (!$handle) {
            return false;
        }

        $this->handle = $handle;

        // Truncating modes destroy the old contents; note the fact even if the
        // process dies before any bytes are written.
        if ($this->watching && strpos($mode, 'w') === 0 && $this->existed) {
            $this->trace = self::trace();
        }

        return true;
    }

    public function stream_read($count)
    {
        self::native_on();
        $data = fread($this->handle, $count);
        self::native_off();
        return $data;
    }

    public function stream_write($data)
    {
        if ($this->watching) {
            if ($this->trace === null) {
                $this->trace = self::trace();
            }
            $this->bytes += strlen($data);
            $room = self::CAPTURE_LIMIT - strlen($this->capture);
            if ($room > 0) {
                $this->capture .= substr($data, 0, $room);
            }
        }

        self::native_on();
        $written = fwrite($this->handle, $data);
        self::native_off();

        return $written;
    }

    public function stream_close()
    {
        if ($this->watching && ($this->bytes > 0 || $this->trace !== null)) {
            $this->report('file_write');
        }

        self::native_on();
        if (is_resource($this->handle)) {
            fclose($this->handle);
        }
        self::native_off();

        $this->handle = null;
        return true;
    }

    public function __destruct()
    {
        // Belt and braces: if the script dies before fclose(), still record it.
        if ($this->watching && !$this->logged && $this->bytes > 0) {
            $this->report('file_write', array('note' => 'stream not closed cleanly'));
        }
    }

    public function stream_eof()
    {
        self::native_on();
        $eof = feof($this->handle);
        self::native_off();
        return $eof;
    }

    public function stream_seek($offset, $whence = SEEK_SET)
    {
        self::native_on();
        $result = fseek($this->handle, $offset, $whence);
        self::native_off();
        return $result === 0;
    }

    public function stream_tell()
    {
        self::native_on();
        $pos = ftell($this->handle);
        self::native_off();
        return $pos;
    }

    public function stream_stat()
    {
        self::native_on();
        $stat = is_resource($this->handle) ? fstat($this->handle) : false;
        self::native_off();
        return $stat;
    }

    public function stream_flush()
    {
        self::native_on();
        $ok = is_resource($this->handle) ? fflush($this->handle) : false;
        self::native_off();
        return $ok;
    }

    public function stream_lock($operation)
    {
        if ($operation === 0 || !is_resource($this->handle)) {
            return true;
        }
        self::native_on();
        $ok = flock($this->handle, $operation);
        self::native_off();
        return $ok;
    }

    public function stream_truncate($new_size)
    {
        if ($this->watching && $this->trace === null) {
            $this->trace = self::trace();
        }
        self::native_on();
        $ok = ftruncate($this->handle, $new_size);
        self::native_off();
        return $ok;
    }

    public function stream_set_option($option, $arg1, $arg2)
    {
        if (!is_resource($this->handle)) {
            return false;
        }

        self::native_on();
        $ok = false;
        switch ($option) {
            case STREAM_OPTION_BLOCKING:
                $ok = stream_set_blocking($this->handle, (bool) $arg1);
                break;
            case STREAM_OPTION_READ_TIMEOUT:
                $ok = stream_set_timeout($this->handle, $arg1, $arg2);
                break;
            case STREAM_OPTION_WRITE_BUFFER:
                $ok = (stream_set_write_buffer($this->handle, $arg2) === 0);
                break;
            case STREAM_OPTION_READ_BUFFER:
                $ok = (stream_set_read_buffer($this->handle, $arg2) === 0);
                break;
        }
        self::native_off();

        return $ok;
    }

    public function stream_cast($cast_as)
    {
        return is_resource($this->handle) ? $this->handle : false;
    }

    // -------------------------------------------------------- path methods

    public function url_stat($path, $flags)
    {
        self::native_on();
        $quiet = (bool) ($flags & STREAM_URL_STAT_QUIET);
        $link  = (bool) ($flags & STREAM_URL_STAT_LINK);

        if ($link) {
            $stat = $quiet ? @lstat($path) : lstat($path);
        } else {
            $stat = $quiet ? @stat($path) : stat($path);
        }
        self::native_off();

        return $stat;
    }

    public function unlink($path)
    {
        $watched = self::watch_level($path) === 1;

        self::native_on();
        $ok = @unlink($path);
        self::native_off();

        if ($watched && $ok) {
            self::report_op('file_delete', $path);
        }

        return $ok;
    }

    public function rename($from, $to)
    {
        // Malware routinely stages a payload under a harmless name and renames
        // it into place, so the rename is often the real event.
        $watched = (self::watch_level($from) === 1) || (self::watch_level($to) === 1);

        self::native_on();
        $ok = @rename($from, $to);
        self::native_off();

        if ($watched && $ok) {
            self::report_op('file_rename', $to, array('from' => self::rel(self::normalise($from))));
        }

        return $ok;
    }

    public function mkdir($path, $mode, $options)
    {
        $recursive = (bool) ($options & STREAM_MKDIR_RECURSIVE);

        self::native_on();
        $ok = is_resource($this->context)
            ? @mkdir($path, $mode, $recursive, $this->context)
            : @mkdir($path, $mode, $recursive);
        self::native_off();

        return $ok;
    }

    public function rmdir($path, $options)
    {
        self::native_on();
        $ok = is_resource($this->context) ? @rmdir($path, $this->context) : @rmdir($path);
        self::native_off();

        return $ok;
    }

    public function stream_metadata($path, $option, $value)
    {
        $watched = self::watch_level($path) === 1;

        self::native_on();
        $ok = false;
        $label = '';

        switch ($option) {
            case STREAM_META_TOUCH:
                $label = 'touch';
                $mtime = isset($value[0]) ? $value[0] : null;
                $atime = isset($value[1]) ? $value[1] : null;
                if ($mtime === null) {
                    $ok = @touch($path);
                } elseif ($atime === null) {
                    $ok = @touch($path, $mtime);
                } else {
                    $ok = @touch($path, $mtime, $atime);
                }
                break;
            case STREAM_META_ACCESS:
                $label = 'chmod';
                $ok = @chmod($path, $value);
                break;
            case STREAM_META_OWNER:
            case STREAM_META_OWNER_NAME:
                $label = 'chown';
                $ok = @chown($path, $value);
                break;
            case STREAM_META_GROUP:
            case STREAM_META_GROUP_NAME:
                $label = 'chgrp';
                $ok = @chgrp($path, $value);
                break;
        }
        self::native_off();

        // Backdating mtime is how an intruder hides from a "recently modified"
        // sweep, so a touch() on a watched file is always worth a line.
        if ($watched && $ok && $label === 'touch') {
            self::report_op('file_touch', $path, array(
                'set_mtime' => isset($value[0]) ? gmdate('Y-m-d H:i:s', (int) $value[0]) . ' UTC' : 'now',
                'severity'  => 'high',
            ));
        } elseif ($watched && $ok && $label === 'chmod' && (((int) $value & 0002) || ((int) $value & 0111))) {
            self::report_op('file_chmod', $path, array('mode' => decoct((int) $value)));
        }

        return $ok;
    }

    // --------------------------------------------------------- dir methods

    public function dir_opendir($path, $options)
    {
        self::native_on();
        $this->dirHandle = is_resource($this->context)
            ? @opendir($path, $this->context)
            : @opendir($path);
        self::native_off();

        return (bool) $this->dirHandle;
    }

    public function dir_readdir()
    {
        self::native_on();
        $entry = is_resource($this->dirHandle) ? readdir($this->dirHandle) : false;
        self::native_off();
        return $entry;
    }

    public function dir_rewinddir()
    {
        self::native_on();
        if (is_resource($this->dirHandle)) {
            rewinddir($this->dirHandle);
        }
        self::native_off();
        return true;
    }

    public function dir_closedir()
    {
        self::native_on();
        if (is_resource($this->dirHandle)) {
            closedir($this->dirHandle);
        }
        self::native_off();
        $this->dirHandle = null;
        return true;
    }
}
