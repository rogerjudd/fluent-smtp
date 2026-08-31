<?php
/**
 * Heuristics for "does this content look like an injection?".
 *
 * These are triage aids, not a verdict. A hit raises an event's severity and
 * pushes it to the top of the report; it does not block anything. False
 * positives are expected (minified JS and some legitimate plugins trip a few
 * of these), which is why every event records the surrounding evidence.
 */

if (!defined('ABSPATH')) {
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

        // --- .htaccess tampering -------------------------------------------
        'htaccess_redirect' => array('/RewriteRule[^\n]*https?:\/\/(?!(?:www\.)?concealedaz\.com)/i', 'high'),
        'htaccess_php_exec' => array('/php_(?:value|flag)\s+(?:auto_prepend_file|allow_url_include|safe_mode)/i', 'critical'),
    );

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

    public static function worst_severity(array $hits)
    {
        $rank = array('info' => 0, 'medium' => 1, 'high' => 2, 'critical' => 3);
        $worst = 'info';

        foreach ($hits as $hit) {
            $severity = isset(self::$patterns[$hit]) ? self::$patterns[$hit][1] : 'medium';
            if ($rank[$severity] > $rank[$worst]) {
                $worst = $severity;
            }
        }

        return $worst;
    }
}
