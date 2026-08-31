<?php
/**
 * Captures who/what was driving the request that touched a file.
 *
 * This is the half of the answer that a file-integrity scanner cannot give
 * you: not just "index.php changed" but "it changed during POST /xmlrpc.php
 * from 203.0.113.9 while logged out".
 */

if (!defined('ABSPATH') && !defined('CAZ_SENTRY_ABSPATH')) {
    exit;
}

class CAZ_Sentry_Context
{
    private static $requestId = null;
    private static $snapshot  = null;

    /** Keys whose values are never recorded, even in full-capture mode. */
    private static $secretKeys = array(
        'pwd', 'pass', 'password', 'password1', 'password2', 'user_pass',
        'auth', 'token', 'key', 'api_key', 'apikey', 'secret', 'nonce',
        '_wpnonce', 'cc', 'card', 'cvv', 'cvc', 'ssn',
    );

    public static function request_id()
    {
        if (self::$requestId === null) {
            self::$requestId = substr(md5(uniqid('', true) . mt_rand()), 0, 12);
        }
        return self::$requestId;
    }

    public static function snapshot()
    {
        if (self::$snapshot !== null) {
            return self::$snapshot;
        }

        $snap = array(
            'sapi'    => php_sapi_name(),
            'method'  => self::server('REQUEST_METHOD'),
            'uri'     => self::server('REQUEST_URI'),
            'host'    => self::server('HTTP_HOST'),
            'script'  => self::server('SCRIPT_NAME'),
            'query'   => self::server('QUERY_STRING'),
            'referer' => self::server('HTTP_REFERER'),
            'agent'   => self::server('HTTP_USER_AGENT'),
            'ip'      => self::client_ip(),
            'ip_chain'=> self::ip_chain(),
            'is_cron' => (defined('DOING_CRON') && DOING_CRON) ? 1 : 0,
            'is_cli'  => (php_sapi_name() === 'cli' || defined('WP_CLI')) ? 1 : 0,
            'is_ajax' => (defined('DOING_AJAX') && DOING_AJAX) ? 1 : 0,
            'is_rest' => (defined('REST_REQUEST') && REST_REQUEST) ? 1 : 0,
            'pid'     => function_exists('getmypid') ? getmypid() : 0,
        );

        // Entry point matters: xmlrpc.php, wp-cron.php, admin-ajax.php and
        // stray files in uploads/ are the usual doorways.
        $snap['entry'] = basename((string) self::server('SCRIPT_FILENAME'));

        $snap['get']  = self::describe_input(isset($_GET) ? $_GET : array());
        $snap['post'] = self::describe_input(isset($_POST) ? $_POST : array());
        if (!empty($_COOKIE)) {
            $snap['cookies'] = array_slice(array_keys($_COOKIE), 0, 40);
        }

        // A raw body that is not reflected in $_POST means a non-form payload
        // (JSON, or a hand-rolled uploader) — worth knowing about.
        $rawLen = (int) self::server('CONTENT_LENGTH');
        if ($rawLen > 0 && empty($_POST)) {
            $snap['raw_body_bytes'] = $rawLen;
            $snap['content_type']   = self::server('CONTENT_TYPE');
        }

        if (function_exists('wp_get_current_user') && function_exists('did_action') && did_action('init')) {
            $user = wp_get_current_user();
            if ($user && $user->ID) {
                $snap['user_id']    = (int) $user->ID;
                $snap['user_login'] = $user->user_login;
                $snap['user_roles'] = array_values((array) $user->roles);
            } else {
                $snap['user_id'] = 0;
            }
        }

        self::$snapshot = $snap;

        return $snap;
    }

    private static function server($key)
    {
        return isset($_SERVER[$key]) ? self::clip((string) $_SERVER[$key], 512) : '';
    }

    /**
     * Record the shape of the input without hoovering up credentials.
     * Values are captured only when CAZ_SENTRY_CAPTURE_POST is enabled, and
     * never for keys that look like secrets.
     */
    private static function describe_input($input)
    {
        if (empty($input) || !is_array($input)) {
            return array();
        }

        $capture = defined('CAZ_SENTRY_CAPTURE_POST') && CAZ_SENTRY_CAPTURE_POST;
        $out = array();
        $i = 0;

        foreach ($input as $key => $value) {
            if ($i++ >= 40) {
                $out['…'] = '(' . (count($input) - 40) . ' more keys)';
                break;
            }

            $flat = is_scalar($value) ? (string) $value : json_encode($value);
            $flat = (string) $flat;

            $entry = array('len' => strlen($flat));

            // Always flag payloads that look like code, regardless of capture
            // mode — that is the whole point of watching input.
            $hits = CAZ_Sentry_Signatures::match($flat);
            if ($hits) {
                $entry['signatures'] = $hits;
                $entry['sample'] = self::clip($flat, 400);
            } elseif ($capture && !self::is_secret($key)) {
                $entry['value'] = self::clip($flat, 200);
            }

            $out[self::clip((string) $key, 64)] = $entry;
        }

        return $out;
    }

    private static function is_secret($key)
    {
        $key = strtolower((string) $key);
        foreach (self::$secretKeys as $needle) {
            if (strpos($key, $needle) !== false) {
                return true;
            }
        }
        return false;
    }

    public static function client_ip()
    {
        foreach (array('HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR') as $key) {
            if (empty($_SERVER[$key])) {
                continue;
            }
            $value = (string) $_SERVER[$key];
            $parts = explode(',', $value);
            $ip = trim($parts[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
        return '';
    }

    private static function ip_chain()
    {
        $chain = array();
        foreach (array('REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP') as $key) {
            if (!empty($_SERVER[$key])) {
                $chain[$key] = self::clip((string) $_SERVER[$key], 200);
            }
        }
        return $chain;
    }

    public static function clip($string, $max)
    {
        $string = (string) $string;
        if (strlen($string) <= $max) {
            return $string;
        }
        return substr($string, 0, $max) . '…[' . strlen($string) . ' bytes]';
    }
}
