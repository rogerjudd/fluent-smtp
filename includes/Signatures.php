<?php
/**
 * Heuristics for "does this content look like an injection?".
 *
 * These are triage aids, not a verdict. A hit raises an event's severity and
 * pushes it to the top of the report; it does not block anything. False
 * positives are expected (minified JS and some legitimate plugins trip a few
 * of these), which is why every event records the surrounding evidence.
 */

if (!defined('ABSPATH') && !defined('CAZ_SENTRY_ABSPATH')) {
    exit;
}

class CAZ_Sentry_Signatures
{
    /** name => array(regex, severity) */
    private static $patterns = array(
        // --- PHP execution primitives fed by decoders or user input ---------
        'eval_decoder'      => array('/\beval\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|str_rot13|strrev|pack|hex2bin|convert_uu)/i', 'critical'),
        'eval_superglobal'  => array('/\b(?:eval|assert)\s*\(\s*(?:@\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/i', 'critical'),
        'assert_decoder'    => array('/\bassert\s*\(\s*(?:@\s*)?(?:base64_decode|gzinflate|str_rot13|strrev)/i', 'critical'),
        // The /e modifier lives inside the quoted pattern, after the closing
        // delimiter: preg_replace("/.*/e", $_POST['c'], "").
        'preg_replace_e'    => array('/\bpreg_replace\s*\(\s*([\'"]).{1,200}?[\/#~|}\]][a-zA-Z]{0,8}e[a-zA-Z]{0,8}\1/s', 'critical'),
        'create_function'   => array('/\bcreate_function\s*\(/i', 'high'),
        'decoder_chain'     => array('/\b(?:gzinflate|gzuncompress|gzdecode)\s*\(\s*(?:@\s*)?(?:base64_decode|str_rot13|strrev)\s*\(/i', 'critical'),
        'double_decode'     => array('/base64_decode\s*\(\s*(?:@\s*)?(?:str_rot13|strrev|base64_decode)\s*\(/i', 'high'),

        // --- Variable-function and variable-variable obfuscation -----------
        'var_func_call'     => array('/\$(?:[a-zA-Z_]\w*)\s*\(\s*(?:@\s*)?\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/i', 'critical'),
        'globals_obfusc'    => array('/\$\{\s*[\'"](?:\\\\x[0-9a-fA-F]{2}){3,}/', 'critical'),
        'hex_var_name'      => array('/\$\{?[\'"]?(?:\\\\x[0-9a-fA-F]{2}){4,}/', 'high'),
        'chr_chain'         => array('/(?:\bchr\s*\(\s*\d+\s*\)\s*\.\s*){5,}/i', 'high'),
        'long_hex_string'   => array('/(?:\\\\x[0-9a-fA-F]{2}){40,}/', 'high'),

        // --- Shells and remote fetch ---------------------------------------
        'shell_exec'        => array('/\b(?:shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(/i', 'high'),
        'system_call'       => array('/\b(?:system|exec)\s*\(\s*(?:@\s*)?\$_(?:GET|POST|REQUEST|COOKIE)/i', 'critical'),
        'remote_include'    => array('/\b(?:include|require)(?:_once)?\s*\(?\s*[\'"]https?:\/\//i', 'critical'),
        'remote_eval_fetch' => array('/\beval\s*\(\s*(?:@\s*)?(?:file_get_contents|curl_exec)\s*\(/i', 'critical'),
        'raw_ip_callback'   => array('/(?:wp_remote_(?:get|post)|file_get_contents|curl_init)\s*\(\s*[\'"]https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/i', 'high'),

        // --- Backdoor plumbing ---------------------------------------------
        'php_writer'        => array('/\bfile_put_contents\s*\([^,]{0,200}\.(?:php|phtml|phar)[\'"]/i', 'high'),
        'upload_to_web'     => array('/\bmove_uploaded_file\s*\([^)]{0,200}\.(?:php|phtml)/i', 'critical'),
        'mtime_backdate'    => array('/\btouch\s*\(\s*\$?\w[^,]{0,120},\s*(?:\d{9,10}|filemtime|strtotime)/i', 'high'),
        'error_suppress_eval' => array('/@\s*eval\s*\(/i', 'critical'),
        'auto_prepend'      => array('/auto_prepend_file|auto_append_file/i', 'high'),
        'php_handler_img'   => array('/(?:AddType|AddHandler)\s+[^\n]*php[^\n]*\.(?:jpg|jpeg|png|gif|ico|txt)/i', 'critical'),

        // --- WordPress-specific persistence --------------------------------
        'silent_admin'      => array('/wp_insert_user|wp_create_user/i', 'medium'),
        'role_escalation'   => array('/->set_role\s*\(\s*[\'"]administrator|[\'"]role[\'"]\s*=>\s*[\'"]administrator/i', 'high'),
        'hide_from_list'    => array('/pre_user_query|users_list_table|remove_action\s*\(\s*[\'"]admin_notices/i', 'medium'),
        'plugin_hider'      => array('/all_plugins|filter\s*\(\s*[\'"]all_plugins/i', 'medium'),

        // --- Injected front-end payloads -----------------------------------
        'js_eval_atob'      => array('/\beval\s*\(\s*(?:window\.)?atob\s*\(/i', 'critical'),
        'js_unescape_write' => array('/document\.write\s*\(\s*unescape\s*\(/i', 'high'),
        'js_fromcharcode'   => array('/String\.fromCharCode\s*\(\s*(?:\d{1,3}\s*,\s*){20,}/i', 'high'),
        'js_hidden_iframe'  => array('/<iframe[^>]{0,200}(?:width\s*=\s*[\'"]?0|display\s*:\s*none|visibility\s*:\s*hidden)/i', 'high'),
        'js_redirect_ua'    => array('/(?:googlebot|bingbot)[^\n]{0,200}(?:location\.href|window\.location|header\s*\(\s*[\'"]Location)/i', 'critical'),

        // --- Output-prepending injectors ------------------------------------
        'gif_marker_in_php' => array('/GIF89a?;?\s*<\?php|<\?php[^\n]{0,200}GIF89/i', 'critical'),
        'ob_start_injector' => array('/ob_start\s*\(\s*[\'"]?\w*(?:callback|inject|repl)/i', 'high'),
        'header_prepend'    => array('/add_action\s*\(\s*[\'"](?:muplugins_loaded|plugins_loaded)[\'"][^)]{0,80}(?:ob_start|print|echo)/i', 'high'),

        // --- .htaccess tampering -------------------------------------------
        // Off-site redirects are handled separately, in offsite_redirect(),
        // because the rule depends on which hostnames belong to this site.
        'htaccess_php_exec' => array('/php_(?:value|flag)\s+(?:auto_prepend_file|allow_url_include|safe_mode)/i', 'critical'),
    );

    /**
     * Hostnames that legitimately belong to this site.
     *
     * Set CAZ_SENTRY_SITE_HOSTS (comma separated) to be explicit. Otherwise
     * this is inferred, which is good enough for the redirect check.
     */
    private static function own_hosts()
    {
        $hosts = array();

        if (defined('CAZ_SENTRY_SITE_HOSTS') && CAZ_SENTRY_SITE_HOSTS) {
            foreach (explode(',', CAZ_SENTRY_SITE_HOSTS) as $host) {
                $host = trim($host);
                if ($host !== '') {
                    $hosts[] = $host;
                }
            }
        }

        if (!$hosts && function_exists('home_url')) {
            $parts = @parse_url(home_url());
            if (!empty($parts['host'])) {
                $hosts[] = $parts['host'];
            }
        }

        if (!$hosts && !empty($_SERVER['HTTP_HOST'])) {
            $hosts[] = (string) $_SERVER['HTTP_HOST'];
        }

        return $hosts;
    }

    /**
     * A rewrite rule sending traffic to a host that is not this site's.
     *
     * Returns false when the site's own hostnames cannot be determined —
     * guessing there would flag every legitimate redirect on the site.
     */
    private static function offsite_redirect($content)
    {
        $hosts = self::own_hosts();
        if (!$hosts) {
            return false;
        }

        $alternatives = array();
        foreach ($hosts as $host) {
            $host = preg_replace('/^www\./i', '', $host);
            $alternatives[] = preg_quote($host, '/');
        }

        $pattern = '/RewriteRule[^\n]*https?:\/\/(?!(?:www\.)?(?:' . implode('|', $alternatives) . '))/i';

        return (bool) @preg_match($pattern, $content);
    }

    /**
     * @return array List of matched signature names (with severity suffix).
     */
    public static function match($content, $limit = 8)
    {
        $content = (string) $content;
        if ($content === '') {
            return array();
        }

        // Cap the scanned window; injections live at the head or the tail of a
        // file, so look at both ends rather than the (possibly huge) middle.
        if (strlen($content) > 262144) {
            $content = substr($content, 0, 131072) . "\n" . substr($content, -131072);
        }

        $hits = array();
        foreach (self::$patterns as $name => $spec) {
            if (count($hits) >= $limit) {
                break;
            }
            if (@preg_match($spec[0], $content)) {
                $hits[] = $name;
            }
        }

        if (count($hits) < $limit && strpos($content, 'RewriteRule') !== false && self::offsite_redirect($content)) {
            $hits[] = 'htaccess_redirect';
        }

        foreach (self::structural_hits($content) as $hit) {
            if (count($hits) >= $limit) {
                break;
            }
            $hits[] = $hit;
        }

        return $hits;
    }

    /**
     * Shape-based tells that no single regex captures: enormous one-liners,
     * base64 blobs, and PHP tags buried far from the start of a file.
     */
    private static function structural_hits($content)
    {
        $hits = array();

        // Inline data: URIs are long base64 blobs and entirely legitimate, so
        // take them out before looking for an unexplained one.
        $stripped = preg_replace('/data:[^;,\s]*;base64,[A-Za-z0-9+\/=]+/i', '', $content);

        if (preg_match('/[A-Za-z0-9+\/]{500,}={0,2}/', $stripped, $blob)) {
            // Real encoded data uses most of the alphabet. A long run of one
            // or two repeated characters is padding or filler, not a payload.
            $distinct = count(array_filter(count_chars($blob[0], 1)));
            if ($distinct >= 16) {
                $hits[] = 'long_base64_blob';
            }
        }

        // A single line of several KB is how packed droppers arrive.
        $longest = 0;
        foreach (explode("\n", substr($content, 0, 200000)) as $line) {
            $len = strlen($line);
            if ($len > $longest) {
                $longest = $len;
            }
        }
        if ($longest > 5000 && strpos($content, '<?php') !== false) {
            $hits[] = 'packed_single_line';
        }

        // PHP opening tag appearing well past the start of an otherwise
        // non-PHP file is the classic "appended to the bottom" pattern.
        $pos = strpos($content, '<?php');
        if ($pos !== false && $pos > 4096) {
            $hits[] = 'late_php_tag';
        }

        return $hits;
    }

    /**
     * Long-standing, publicly documented web shells.
     *
     * Names specific to your own incident do not belong here — put them in
     * CAZ_SENTRY_EXTRA_BACKDOOR_NAMES (see config.sample.php) so that a list
     * of what was found on your server is not committed to a repository.
     */
    private static $knownBadNames = array(
        'alfa.php'      => 1,
        'wso.php'       => 1,
        'c99.php'       => 1,
        'r57.php'       => 1,
        'wp-conflg.php' => 1,
        'wp-cofig.php'  => 1,
    );

    /**
     * The built-in list plus anything configured for this particular site.
     */
    private static function bad_names()
    {
        static $names = null;
        if ($names !== null) {
            return $names;
        }

        $names = self::$knownBadNames;

        if (defined('CAZ_SENTRY_EXTRA_BACKDOOR_NAMES') && CAZ_SENTRY_EXTRA_BACKDOOR_NAMES) {
            foreach (explode(',', CAZ_SENTRY_EXTRA_BACKDOOR_NAMES) as $name) {
                $name = strtolower(trim($name));
                if ($name !== '') {
                    $names[$name] = 1;
                }
            }
        }

        return $names;
    }

    /**
     * Judge a file by its name and location alone — useful before the content
     * is even read, and the fastest way to spot a re-dropped backdoor.
     *
     * @param string $relPath Path relative to the WordPress root.
     * @return array|null array('reason' => ..., 'severity' => ...)
     */
    public static function match_filename($relPath)
    {
        $relPath = ltrim(str_replace('\\', '/', (string) $relPath), '/');
        $name    = basename($relPath);
        $lower   = strtolower($name);
        $ext     = strtolower((string) pathinfo($name, PATHINFO_EXTENSION));
        $isPhp   = in_array($ext, array('php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'phps'), true);

        $bad = self::bad_names();
        if (isset($bad[$lower])) {
            return array('reason' => 'known_backdoor_filename', 'severity' => 'critical');
        }

        // Two forms of the same trick: "shell.php.jpg" (php buried in the
        // middle) and "invoice.pdf.php" (a document name with php tacked on).
        if (preg_match('/\.(?:php|phtml|phar)\./i', $name)) {
            return array('reason' => 'double_extension', 'severity' => 'critical');
        }
        if ($isPhp && preg_match('/\.(?:jpe?g|png|gif|bmp|webp|svg|ico|pdf|docx?|xlsx?|pptx?|csv|txt|zip|gz|mp[34]|avi|mov)\.[a-z0-9]+$/i', $name)) {
            return array('reason' => 'double_extension', 'severity' => 'critical');
        }

        // Randomly generated shell names: twelve hex characters and the like.
        if ($isPhp && preg_match('/^[0-9a-f]{8,32}\.[a-z0-9]+$/i', $name)) {
            return array('reason' => 'random_hex_filename', 'severity' => 'critical');
        }
        // Generated names that are not hex: all lowercase, no word structure,
        // and digit-heavy. Deliberately narrow — CamelCase class files and
        // ordinary lowercase names like "abstractlogger.php" must not trip it.
        $stem = strtolower((string) pathinfo($name, PATHINFO_FILENAME));
        if ($isPhp
            && preg_match('/^[a-z0-9]{16,40}$/', $stem)
            && preg_match_all('/[0-9]/', $stem) >= 4
            && $stem === (string) pathinfo($name, PATHINFO_FILENAME)) {
            return array('reason' => 'random_filename', 'severity' => 'high');
        }

        // Must-use plugins run on every single page load, before anything
        // else. That is how the header injection on this site was delivered,
        // so any PHP landing there is treated as an emergency.
        if ($isPhp && strpos($relPath, 'wp-content/mu-plugins/') === 0) {
            return array('reason' => 'mu_plugin_executes_on_every_page_load', 'severity' => 'critical');
        }

        // A cache directory holds generated markup, never executable code.
        // Anchored to the real WordPress cache locations: plenty of vendor
        // packages ship a legitimate directory named "cache".
        if ($isPhp && preg_match('#^wp-content/(?:cache|et-cache|uploads/cache)/#', $relPath)) {
            return array('reason' => 'php_file_in_cache_directory', 'severity' => 'critical');
        }

        if ($isPhp && strpos($relPath, 'wp-content/uploads/') === 0) {
            return array('reason' => 'php_file_in_uploads', 'severity' => 'critical');
        }

        return null;
    }

    public static function worst_severity(array $hits)
    {
        $rank = array('info' => 0, 'medium' => 1, 'high' => 2, 'critical' => 3);
        $worst = 'info';

        // Signatures that are evaluated dynamically rather than from the
        // pattern table still need a severity.
        $dynamic = array('htaccess_redirect' => 'high');

        foreach ($hits as $hit) {
            if (isset($dynamic[$hit])) {
                $severity = $dynamic[$hit];
            } else {
                $severity = isset(self::$patterns[$hit]) ? self::$patterns[$hit][1] : 'medium';
            }
            if ($rank[$severity] > $rank[$worst]) {
                $worst = $severity;
            }
        }

        return $worst;
    }
}
