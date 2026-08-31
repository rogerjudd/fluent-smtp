<?php
/**
 * Filesystem baseline and change detection.
 *
 * The write watcher catches injections that happen through PHP. This catches
 * everything else: an intruder with FTP/SSH credentials, a cPanel file
 * manager session, or a system cron job outside WordPress entirely. If a file
 * changes and no corresponding write event exists in the journal, the entry
 * point is not PHP — which is itself a decisive finding.
 */

if (!defined('ABSPATH') && !defined('CAZ_SENTRY_ABSPATH')) {
    exit;
}

class CAZ_Sentry_Baseline
{
    const MAX_FILES        = 80000;
    const MAX_HASH_BYTES   = 8388608; // files larger than this are tracked by size+mtime only
    const MAX_EVENTS       = 200;
    const TIME_BUDGET      = 45;      // seconds

    /** Directories never walked: churn, vendor noise, or our own storage. */
    private static $prune = array(
        '/wp-content/cache',
        '/wp-content/upgrade',
        '/wp-content/updraft',
        '/wp-content/caz-sentry',
        '/wp-content/uploads/caz-sentry',
        '/wp-content/et-cache',
        '/wp-content/wp-rocket-config',
        '/node_modules',
        '/.git',
        '/.svn',
        '/wp-content/uploads/backup',
    );

    /**
     * Directories where any new file deserves a hard look, because code
     * placed there runs on every request.
     */
    private static $criticalDirs = array(
        '/wp-content/mu-plugins',
    );

    /**
     * Sentry is itself installed into mu-plugins, so without this it would
     * report its own files as critical findings on the first scan. They are
     * still baselined — tampering with them must be visible — but they are
     * not flagged on the strength of where they live.
     */
    private static function is_self($rel)
    {
        $rel = '/' . ltrim(str_replace('\\', '/', (string) $rel), '/');

        // Derived from this file's own location rather than assumed, so that
        // installing under a different directory name cannot make Sentry
        // report itself as a critical finding.
        static $own = null;
        if ($own === null) {
            $dir  = str_replace('\\', '/', dirname(dirname(__FILE__)));
            $root = rtrim(str_replace('\\', '/', CAZ_SENTRY_ABSPATH), '/');

            $own = (strpos($dir, $root . '/') === 0)
                ? substr($dir, strlen($root)) . '/'
                : '/caz-sentry/';
        }

        return strpos($rel, $own) === 0
            || strpos($rel, '/caz-sentry/') !== false
            || basename($rel) === '00-caz-sentry.php';
    }

    /** Extensions that can execute, or that commonly carry a payload. */
    private static $risky = array(
        'php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phps', 'phar',
        'inc', 'js', 'mjs', 'html', 'htm', 'htaccess', 'ini', 'sh', 'pl', 'cgi', 'py',
    );

    public static function file()
    {
        return CAZ_Sentry_Journal::dir() . '/baseline.json.gz';
    }

    /**
     * Walk the install and compare against the stored baseline.
     *
     * @param string $reason What triggered this scan (cron, manual, activation).
     * @return array Summary counts.
     */
    public static function scan($reason = 'cron')
    {
        $started = microtime(true);

        CAZ_Sentry_Journal::ignore_start();

        $previous = self::load();
        $first    = empty($previous['files']);
        $lastScan = isset($previous['scanned_at']) ? (int) $previous['scanned_at'] : 0;
        $known    = isset($previous['suspicious']) && is_array($previous['suspicious']) ? $previous['suspicious'] : array();

        $current = self::walk($lastScan, $started);

        CAZ_Sentry_Journal::ignore_end();

        $summary = array(
            'reason'    => $reason,
            'files'     => count($current['files']),
            'added'     => 0,
            'modified'  => 0,
            'removed'   => 0,
            'suspicious'=> count($current['suspicious']),
            'truncated' => $current['truncated'],
            'seconds'   => round(microtime(true) - $started, 2),
        );

        if ($first) {
            // Nothing to compare against yet; record the starting point quietly.
            self::save($current['files'], $current['suspicious']);
            $summary['first_run'] = 1;
            CAZ_Sentry_Journal::write(array(
                'type'     => 'baseline_created',
                'severity' => 'info',
                'summary'  => $summary,
                'note'     => 'Baseline recorded. Future scans report changes against it.',
            ));
            self::report_suspicious($current['suspicious'], $known);
            return $summary;
        }

        $old = $previous['files'];
        $new = $current['files'];
        $emitted = 0;

        foreach ($new as $path => $meta) {
            if (!isset($old[$path])) {
                $summary['added']++;
                if ($emitted < self::MAX_EVENTS) {
                    $emitted++;
                    self::report_change('file_added', $path, $meta, null);
                }
                continue;
            }
            if ($old[$path][0] !== $meta[0] || $old[$path][1] !== $meta[1]) {
                $summary['modified']++;
                if ($emitted < self::MAX_EVENTS) {
                    $emitted++;
                    self::report_change('file_modified', $path, $meta, $old[$path]);
                }
            }
        }

        foreach ($old as $path => $meta) {
            if (!isset($new[$path])) {
                $summary['removed']++;
                if ($emitted < self::MAX_EVENTS) {
                    $emitted++;
                    self::report_change('file_removed', $path, null, $meta);
                }
            }
        }

        self::report_suspicious($current['suspicious'], $known);
        self::save($new, $current['suspicious']);

        $changed = $summary['added'] + $summary['modified'] + $summary['removed'];
        CAZ_Sentry_Journal::write(array(
            'type'     => 'baseline_scan',
            'severity' => $changed > 0 ? 'medium' : 'info',
            'summary'  => $summary,
        ));

        return $summary;
    }

    private static function walk($lastScan, $started)
    {
        $root = rtrim(str_replace('\\', '/', CAZ_SENTRY_ABSPATH), '/');

        $files      = array();
        $suspicious = array();
        $truncated  = 0;
        $count      = 0;

        $uploads = $root . '/wp-content/uploads';
        $stack   = array($root);

        while ($stack) {
            $dir = array_pop($stack);

            if ((microtime(true) - $started) > self::TIME_BUDGET || $count >= self::MAX_FILES) {
                $truncated = 1;
                break;
            }

            $handle = @opendir($dir);
            if (!$handle) {
                continue;
            }

            while (($entry = readdir($handle)) !== false) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }

                $full = $dir . '/' . $entry;
                $rel  = substr($full, strlen($root));

                if (@is_link($full)) {
                    // A symlink pointing out of the webroot is a finding in itself.
                    $target = @readlink($full);
                    if ($target && strpos(str_replace('\\', '/', (string) $target), $root) !== 0) {
                        $suspicious[$rel] = array('reason' => 'symlink_escapes_webroot', 'target' => $target, 'severity' => 'high');
                    }
                    continue;
                }

                if (@is_dir($full)) {
                    if (!self::pruned($rel)) {
                        $stack[] = $full;
                    }
                    continue;
                }

                $inUploads = strpos($full, $uploads . '/') === 0;
                $ext       = strtolower((string) pathinfo($entry, PATHINFO_EXTENSION));
                $risky     = in_array($ext, self::$risky, true) || $entry[0] === '.' || $ext === '';

                // Name and location alone can condemn a file, anywhere in the
                // install — a known backdoor name, a random hex name, or PHP
                // sitting in mu-plugins or a cache directory.
                $byName = self::is_self($rel) ? null : CAZ_Sentry_Signatures::match_filename($rel);
                if ($byName) {
                    $suspicious[$rel] = $byName;
                }

                if ($inUploads) {
                    $found = self::inspect_upload($full, $rel, $entry, $ext, $risky, $lastScan);
                    if ($found && !isset($suspicious[$rel])) {
                        $suspicious[$rel] = $found;
                    }
                    if (!$risky) {
                        continue; // do not baseline every image in the media library
                    }
                }

                if (!$risky && !$inUploads) {
                    // Track everything outside uploads, but hash cheaply.
                    $risky = true;
                }

                $size  = (int) @filesize($full);
                $mtime = (int) @filemtime($full);
                $perm  = @fileperms($full);
                $hash  = ($size > 0 && $size <= self::MAX_HASH_BYTES) ? (string) @md5_file($full) : 'size:' . $size;

                $files[$rel] = array($hash, $size, $mtime, $perm ? substr(decoct($perm), -4) : '');
                $count++;

                if ($perm && (($perm & 0002) || ($perm & 0020))) {
                    $suspicious[$rel] = array('reason' => 'world_or_group_writable', 'mode' => substr(decoct($perm), -4), 'severity' => 'medium');
                }

                if ($count >= self::MAX_FILES) {
                    $truncated = 1;
                    break;
                }
            }

            closedir($handle);
        }

        return array('files' => $files, 'suspicious' => $suspicious, 'truncated' => $truncated);
    }

    /**
     * The media library should contain media. Anything executable there, or
     * anything whose bytes disagree with its extension, is a planted file.
     */
    private static function inspect_upload($full, $rel, $entry, $ext, $risky, $lastScan)
    {
        if (in_array($ext, array('php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'phps'), true)) {
            return array('reason' => 'php_file_in_uploads', 'severity' => 'critical');
        }

        // "invoice.pdf.php" and friends.
        if (preg_match('/\.(?:php|phtml|phar)\./i', $entry)) {
            return array('reason' => 'double_extension', 'severity' => 'critical');
        }

        if ($ext === 'htaccess' || $entry === '.htaccess' || $entry === '.user.ini') {
            $body = (string) @file_get_contents($full, false, null, 0, 8192);
            $hits = CAZ_Sentry_Signatures::match($body);
            if ($hits) {
                return array('reason' => 'htaccess_in_uploads', 'signatures' => $hits, 'severity' => 'critical');
            }
        }

        // Sniff only files that appeared or changed since the last scan, so a
        // large media library does not cost a full read every hour.
        $mtime = (int) @filemtime($full);
        if ($lastScan > 0 && $mtime <= $lastScan) {
            return null;
        }
        if ((int) @filesize($full) > 4194304) {
            return null;
        }

        $head = (string) @file_get_contents($full, false, null, 0, 1024);
        if ($head === '') {
            return null;
        }

        if (stripos($head, '<?php') !== false || stripos($head, '<?=') !== false) {
            return array('reason' => 'php_code_inside_non_php_file', 'severity' => 'critical');
        }
        if (stripos($head, '<script') !== false && in_array($ext, array('jpg', 'jpeg', 'png', 'gif', 'ico', 'svg', 'bmp', 'webp'), true)) {
            return array('reason' => 'script_tag_inside_image', 'severity' => 'high');
        }

        return null;
    }

    private static function pruned($rel)
    {
        foreach (self::$prune as $needle) {
            if (strpos($rel, $needle) === 0) {
                return true;
            }
        }
        return false;
    }

    private static function report_change($type, $path, $now, $before)
    {
        $event = array(
            'type'     => $type,
            'severity' => 'medium',
            'path'     => ltrim($path, '/'),
            'source'   => 'baseline_scan',
        );

        if ($now) {
            $event['size']  = $now[1];
            $event['mtime'] = gmdate('Y-m-d H:i:s', $now[2]) . ' UTC';
            $event['perms'] = $now[3];
        }
        if ($before && $now) {
            $event['size_before']  = $before[1];
            $event['mtime_before'] = gmdate('Y-m-d H:i:s', $before[2]) . ' UTC';
            // A file whose contents changed but whose mtime went backwards (or
            // stayed put) has been deliberately backdated.
            if ($now[2] <= $before[2]) {
                $event['severity']  = 'critical';
                $event['backdated'] = 1;
            }
        }

        if ($type !== 'file_removed') {
            $full = rtrim(CAZ_SENTRY_ABSPATH, '/') . $path;
            $ext  = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
            if (in_array($ext, array('php', 'phtml', 'js', 'htaccess', 'inc', 'html', 'ini'), true) || strpos($path, '.htaccess') !== false) {
                CAZ_Sentry_Journal::ignore_start();
                $body = (string) @file_get_contents($full, false, null, 0, 262144);
                CAZ_Sentry_Journal::ignore_end();
                $hits = CAZ_Sentry_Signatures::match($body);
                if ($hits) {
                    $event['signatures'] = $hits;
                    $event['severity']   = CAZ_Sentry_Signatures::worst_severity($hits);
                    $event['sample']     = CAZ_Sentry_Context::clip(ltrim($body), 1200);
                }
            }
        }

        // Core files should only change during an update, and updates leave a
        // matching write event behind. A silent core change is not routine.
        if (preg_match('#^/wp-(includes|admin)/#', $path) || preg_match('#^/[^/]+\.php$#', $path)) {
            if ($event['severity'] === 'medium') {
                $event['severity'] = 'high';
            }
            $event['core'] = 1;
        }

        foreach (self::$criticalDirs as $dir) {
            if (strpos($path, $dir . '/') === 0 && !self::is_self($path)) {
                $event['severity'] = 'critical';
                $event['note']     = 'This directory runs on every page load, before any other plugin.';
                break;
            }
        }

        $byName = self::is_self($path) ? null : CAZ_Sentry_Signatures::match_filename($path);
        if ($byName) {
            $event['filename_flag'] = $byName['reason'];
            $event['severity']      = $byName['severity'];
        }

        CAZ_Sentry_Journal::write($event);
    }

    private static function report_suspicious($suspicious, $known)
    {
        $count = 0;

        foreach ($suspicious as $path => $info) {
            if (isset($known[$path])) {
                continue; // already reported; do not repeat every hour
            }
            if ($count++ >= self::MAX_EVENTS) {
                break;
            }
            CAZ_Sentry_Journal::write(array_merge(array(
                'type'   => 'suspicious_file',
                'path'   => ltrim($path, '/'),
                'source' => 'baseline_scan',
            ), $info));
        }
    }

    private static $cache = null;

    public static function load()
    {
        if (self::$cache !== null) {
            return self::$cache;
        }

        CAZ_Sentry_Journal::ignore_start();
        $raw = @file_get_contents(self::file());
        CAZ_Sentry_Journal::ignore_end();

        $data = null;
        if ($raw !== false && $raw !== '') {
            $json = @gzdecode($raw);
            if ($json !== false) {
                $data = json_decode($json, true);
            }
        }

        self::$cache = is_array($data) ? $data : array('files' => array(), 'suspicious' => array(), 'scanned_at' => 0);

        return self::$cache;
    }

    private static function save($files, $suspicious)
    {
        $payload = array(
            'version'    => 1,
            'scanned_at' => time(),
            'files'      => $files,
            'suspicious' => $suspicious,
        );

        CAZ_Sentry_Journal::ignore_start();
        $body = gzencode(json_encode($payload, JSON_UNESCAPED_SLASHES), 6);
        if ($body !== false) {
            @file_put_contents(self::file(), $body, LOCK_EX);
        }
        CAZ_Sentry_Journal::ignore_end();

        self::$cache = $payload;
    }
}
