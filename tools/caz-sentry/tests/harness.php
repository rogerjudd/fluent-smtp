<?php
/**
 * Standalone test harness — no WordPress required.
 *
 * Builds a throwaway directory that looks like a WordPress install, turns the
 * watcher on, then acts like malware: drops a backdoor in uploads, writes
 * through eval()'d code, stages-and-renames a payload, and backdates an
 * mtime. Then it asserts the journal caught each one and attributed it.
 *
 * Run:  php tools/caz-sentry/tests/harness.php
 */

error_reporting(E_ALL);

$root = sys_get_temp_dir() . '/caz-sentry-test-' . getmypid();

foreach (array(
    '/wp-includes', '/wp-admin',
    '/wp-content/plugins/legit', '/wp-content/plugins/compromised',
    '/wp-content/themes/twentytwenty', '/wp-content/uploads/2026/08',
    '/wp-content/cache', '/wp-content/mu-plugins', '/wp-content/upgrade',
) as $dir) {
    mkdir($root . $dir, 0755, true);
}

file_put_contents($root . '/index.php', "<?php // front controller\n");
file_put_contents($root . '/wp-includes/version.php', "<?php \$wp_version = '6.5';\n");

define('ABSPATH', $root . '/');
define('WP_CONTENT_DIR', $root . '/wp-content');
define('CAZ_SENTRY_ABSPATH', $root . '/');
define('CAZ_SENTRY_CONTENT_DIR', $root . '/wp-content');
define('CAZ_SENTRY_LOG_DIR', $root . '/sentry-logs');

// Site-specific detection is configured, never hardcoded. These stand in for
// what an operator would put in config.php after finding shells on their own
// server.
define('CAZ_SENTRY_EXTRA_BACKDOOR_NAMES', 'evilshell.php, dropper2.php');
define('CAZ_SENTRY_SITE_HOSTS', 'example.com');

foreach (array('Context', 'Signatures', 'Journal', 'Alerts', 'Guard', 'WriteWatcher', 'Baseline') as $class) {
    require_once dirname(__DIR__) . '/includes/' . $class . '.php';
}

// ---------------------------------------------------------------- utilities

$GLOBALS['caz_pass'] = 0;
$GLOBALS['caz_fail'] = 0;

function check($label, $condition, $detail = '')
{
    if ($condition) {
        $GLOBALS['caz_pass']++;
        echo "  \033[32mPASS\033[0m  $label\n";
    } else {
        $GLOBALS['caz_fail']++;
        echo "  \033[31mFAIL\033[0m  $label" . ($detail ? "\n         $detail" : '') . "\n";
    }
}

function events()
{
    $path = CAZ_SENTRY_LOG_DIR . '/events.log';
    if (!file_exists($path)) {
        return array();
    }
    $out = array();
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $row = json_decode($line, true);
        if (is_array($row)) {
            $out[] = $row;
        }
    }
    return $out;
}

function find_event($type, $pathNeedle = null)
{
    foreach (events() as $event) {
        if ($event['type'] !== $type) {
            continue;
        }
        if ($pathNeedle !== null && (empty($event['path']) || strpos($event['path'], $pathNeedle) === false)) {
            continue;
        }
        return $event;
    }
    return null;
}

// ------------------------------------------------------- register the watcher

echo "\n=== Registration ===\n";

$registered = CAZ_Sentry_Write_Watcher::register();
check('stream wrapper registers and passes its self-test', $registered);

if (!$registered) {
    echo "\nCannot continue without the wrapper.\n";
    exit(1);
}

// ------------------------------------------------- normal filesystem still works

echo "\n=== Ordinary filesystem behaviour is unchanged ===\n";

$plain = $root . '/wp-content/themes/twentytwenty/functions.php';
$bytes = file_put_contents($plain, "<?php\n// theme functions\n");
check('file_put_contents returns the byte count', $bytes === 25, "got " . var_export($bytes, true));
check('file_get_contents round-trips', file_get_contents($plain) === "<?php\n// theme functions\n");
check('file_exists works', file_exists($plain));
check('filesize works', filesize($plain) === 25);
check('is_file / is_dir work', is_file($plain) && is_dir(dirname($plain)));

require $plain; // must not fatal
check('require() through the wrapper works', true);

$fh = fopen($plain, 'a');
fwrite($fh, "// appended\n");
fclose($fh);
check('append mode works', strpos(file_get_contents($plain), '// appended') !== false);

$listing = scandir($root . '/wp-content/plugins');
check('scandir works', in_array('compromised', $listing, true), print_r($listing, true));

check('glob works', count(glob($root . '/wp-content/plugins/*')) === 2);
copy($plain, $plain . '.bak');
check('copy works', file_exists($plain . '.bak'));
unlink($plain . '.bak');
check('unlink works', !file_exists($plain . '.bak'));

// ------------------------------------------------------ simulated infection

echo "\n=== Simulated infection ===\n";

// 1. A compromised plugin drops a PHP backdoor into the media library.
file_put_contents($root . '/wp-content/plugins/compromised/dropper.php', '<?php
function caz_test_drop($target) {
    file_put_contents($target, \'<?php @eval(base64_decode($_POST["x"])); ?>\');
}
');
require $root . '/wp-content/plugins/compromised/dropper.php';
caz_test_drop($root . '/wp-content/uploads/2026/08/thumb.php');

$drop = find_event('file_write', 'uploads/2026/08/thumb.php');
check('backdoor written into uploads is journalled', $drop !== null);
if ($drop) {
    check('  severity is critical', $drop['severity'] === 'critical', 'got ' . $drop['severity']);
    check('  signature matched', !empty($drop['signatures']), print_r($drop, true));
    check('  blamed on the dropper, not on WordPress',
        strpos($drop['blame'], 'wp-content/plugins/compromised/dropper.php') === 0,
        'blame was ' . $drop['blame']);
    check('  component attributed to the plugin',
        $drop['origin'] === 'plugin:compromised', 'origin was ' . $drop['origin']);
    check('  call stack recorded', !empty($drop['stack']) && count($drop['stack']) >= 2);
    check('  content sample captured', strpos($drop['sample'], 'base64_decode') !== false);
    check('  recorded as a newly created file', $drop['created'] === 1);
}

// 2. Code running inside eval() writes to a core file. This is the case a
//    scanner can never attribute, because there is no file to point at.
file_put_contents($root . '/wp-content/plugins/compromised/loader.php', '<?php
function caz_test_eval_write($target) {
    // The payload never exists as a file of its own: it is assembled at
    // runtime and executed, which is why a file scanner cannot attribute it.
    $code = base64_decode("ZmlsZV9wdXRfY29udGVudHMoJHRhcmdldCwgJzw/cGhwIEBpbmNsdWRlKGJhc2U2NF9kZWNvZGUoJF9QT1NUWyJ4Il0pKTsgJyk7");
    eval($code);
}
');
require $root . '/wp-content/plugins/compromised/loader.php';
caz_test_eval_write($root . '/wp-includes/version.php');

$evil = find_event('file_write', 'wp-includes/version.php');
check('write from eval()d code is journalled', $evil !== null);
if ($evil) {
    check('  flagged as coming from eval', $evil['via_eval'] === 1, print_r($evil, true));
    check('  origin reported as eval()d-code', $evil['origin'] === "eval()d-code", 'got ' . $evil['origin']);
    check('  severity raised to critical', $evil['severity'] === 'critical', 'got ' . $evil['severity']);
}

// 3. Stage under a harmless name, then rename into place.
file_put_contents($root . '/wp-content/uploads/2026/08/tmpfile.txt', '<?php eval($_GET["c"]); ?>');
rename($root . '/wp-content/uploads/2026/08/tmpfile.txt', $root . '/wp-content/uploads/2026/08/shell.php');

check('staged payload is journalled', find_event('file_write', 'tmpfile.txt') !== null);
$rename = find_event('file_rename', 'shell.php');
check('rename into place is journalled', $rename !== null);
if ($rename) {
    check('  rename records where it came from',
        strpos($rename['from'], 'tmpfile.txt') !== false, print_r($rename, true));
    check('  rename into uploads/*.php is critical', $rename['severity'] === 'critical', 'got ' . $rename['severity']);
}

// 4. Backdate the mtime to hide from a "recently modified" sweep.
touch($root . '/wp-includes/version.php', strtotime('2019-01-01'));
$touch = find_event('file_touch', 'wp-includes/version.php');
check('mtime backdating is journalled', $touch !== null);
if ($touch) {
    check('  records the timestamp it was set to',
        strpos($touch['set_mtime'], '2019-01-01') === 0, print_r($touch, true));
}

// 5. Cache directories are quiet, but not blind.
file_put_contents($root . '/wp-content/cache/page.html', '<html>ordinary cached page</html>');
check('routine cache writes stay out of the journal',
    find_event('file_write', 'cache/page.html') === null);

file_put_contents($root . '/wp-content/cache/evil.php', '<?php eval(gzinflate(base64_decode("x"))); ?>');
check('a payload hidden in the cache directory is still caught',
    find_event('file_write', 'cache/evil.php') !== null);

// 6. Reads must never be journalled.
$before = count(events());
for ($i = 0; $i < 20; $i++) {
    file_get_contents($root . '/index.php');
}
check('reads generate no events', count(events()) === $before);

// --------------------------------------------------------------- baseline

echo "\n=== Real-world infection shapes ===\n";

// Standalone PHP shells reached directly by URL, plus a must-use plugin that
// prepends junk to every page. Filenames here are stand-ins: the ones that
// matter on a given server are supplied through config.php, never committed.

file_put_contents($root . '/evilshell.php', "<?php /* shell */ ?>");
$known = find_event('file_write', 'evilshell.php');
check('a known backdoor filename is caught on sight', $known !== null);
if ($known) {
    check('  flagged by filename', isset($known['filename_flag']) && $known['filename_flag'] === 'known_backdoor_filename',
        print_r($known, true));
    check('  severity is critical', $known['severity'] === 'critical', 'got ' . $known['severity']);
}

file_put_contents($root . '/wp-content/a1b2c3d4e5f6.php', "<?php /* generated name */ ?>");
$hex = find_event('file_write', 'a1b2c3d4e5f6.php');
check('a randomly generated hex filename is caught', $hex !== null);
if ($hex) {
    check('  flagged as a random hex name', $hex['filename_flag'] === 'random_hex_filename', print_r($hex, true));
}

// cache.php files were part of this infection, and cache directories are a
// quiet path -- PHP written there must still be reported.
file_put_contents($root . '/wp-content/cache/cache.php', "<?php /* looks harmless */ ?>");
$cachePhp = find_event('file_write', 'cache/cache.php');
check('PHP written into a quiet cache directory is still reported', $cachePhp !== null);
if ($cachePhp) {
    check('  severity is critical', $cachePhp['severity'] === 'critical', 'got ' . $cachePhp['severity']);
    check('  reason names the cache directory',
        $cachePhp['filename_flag'] === 'php_file_in_cache_directory', print_r($cachePhp, true));
}

// The header injection on this site came from wp-content/mu-plugins/index.php.
file_put_contents($root . '/wp-content/mu-plugins/index.php', "<?php ob_start('inject_cb'); echo \"GIF89a;\"; ?>");
$mu = find_event('file_write', 'mu-plugins/index.php');
check('a must-use plugin being written is caught', $mu !== null);
if ($mu) {
    check('  severity is critical', $mu['severity'] === 'critical', 'got ' . $mu['severity']);
    check('  reason explains it runs on every page load',
        $mu['filename_flag'] === 'mu_plugin_executes_on_every_page_load', print_r($mu, true));
    check('  GIF89 marker matched by signature',
        in_array('gif_marker_in_php', (array) $mu['signatures'], true), print_r($mu['signatures'], true));
}

// Plugin updates unpack PHP into wp-content/upgrade constantly; that must not
// become noise now that PHP bypasses quiet paths elsewhere.
mkdir($root . '/wp-content/upgrade/some-plugin', 0755, true);
$updateBytes = file_put_contents($root . '/wp-content/upgrade/some-plugin/some-plugin.php', "<?php\n// ordinary plugin file\n");
check('the plugin-update write actually happened', $updateBytes === 30, 'wrote ' . var_export($updateBytes, true));
check('routine plugin-update writes stay quiet',
    find_event('file_write', 'upgrade/some-plugin') === null);

echo "\n=== Baseline scanner ===\n";

CAZ_Sentry_Write_Watcher::unregister();

// Mirror the recommended install layout so the scanner meets Sentry's own
// files sitting in the same directory it treats as critical.
mkdir($root . '/wp-content/mu-plugins/caz-sentry/includes', 0755, true);
file_put_contents($root . '/wp-content/mu-plugins/00-caz-sentry.php', "<?php // loader\n");
file_put_contents($root . '/wp-content/mu-plugins/caz-sentry/caz-sentry.php', "<?php // main\n");
file_put_contents($root . '/wp-content/mu-plugins/caz-sentry/includes/Journal.php', "<?php // journal\n");
check('wrapper unregisters cleanly', !CAZ_Sentry_Write_Watcher::is_active());
check('filesystem still works after unregister', file_get_contents($root . '/index.php') !== false);

$first = CAZ_Sentry_Baseline::scan('test-first');
check('first scan creates a baseline', !empty($first['first_run']));
check('first scan finds the planted shell',
    $first['suspicious'] >= 2, 'suspicious=' . $first['suspicious']);

// Sentry installs itself into mu-plugins, where any PHP is normally critical.
// It must baseline its own files without reporting them as findings.
$suspiciousNow = (array) CAZ_Sentry_Baseline::load()['suspicious'];
$baselinedNow  = (array) CAZ_Sentry_Baseline::load()['files'];

$selfFlagged = array();
foreach ($suspiciousNow as $path => $info) {
    if (strpos($path, 'caz-sentry') !== false) {
        $selfFlagged[] = $path;
    }
}
check('Sentry does not report its own files as findings',
    $selfFlagged === array(), implode(', ', $selfFlagged));
check('Sentry still baselines its own files, so tampering stays visible',
    isset($baselinedNow['/wp-content/mu-plugins/00-caz-sentry.php'])
    && isset($baselinedNow['/wp-content/mu-plugins/caz-sentry/includes/Journal.php']),
    implode(', ', array_slice(array_keys($baselinedNow), 0, 6)));
check('a genuinely malicious must-use plugin is still reported',
    isset($suspiciousNow['/wp-content/mu-plugins/index.php']),
    implode(', ', array_keys($suspiciousNow)));

$sus = find_event('suspicious_file', 'uploads/2026/08/shell.php');
check('planted shell reported as suspicious', $sus !== null);
if ($sus) {
    check('  reason is php in uploads', $sus['reason'] === 'php_file_in_uploads', print_r($sus, true));
}

// Change a file behind the watcher's back, the way FTP access would.
file_put_contents($root . '/wp-content/plugins/legit/legit.php', "<?php\n// clean\n");
CAZ_Sentry_Baseline::scan('test-second');
file_put_contents($root . '/wp-content/plugins/legit/legit.php', "<?php\n@eval(base64_decode(\$_POST['q']));\n");
touch($root . '/wp-content/plugins/legit/legit.php', strtotime('2020-01-01'));

$third = CAZ_Sentry_Baseline::scan('test-third');
check('out-of-band modification is detected', $third['modified'] >= 1, print_r($third, true));

$mod = find_event('file_modified', 'plugins/legit/legit.php');
check('modified file reported', $mod !== null);
if ($mod) {
    check('  signature matched in the new content', !empty($mod['signatures']), print_r($mod, true));
    check('  backdated timestamp noticed', !empty($mod['backdated']));
    check('  severity is critical', $mod['severity'] === 'critical', 'got ' . $mod['severity']);
}

// A repeat scan must not re-report the same suspicious files.
$before = count(events());
CAZ_Sentry_Baseline::scan('test-fourth');
$after = events();
$repeats = 0;
foreach (array_slice($after, $before) as $event) {
    if ($event['type'] === 'suspicious_file') {
        $repeats++;
    }
}
check('already-reported suspicious files are not repeated every scan', $repeats === 0, "repeated $repeats");

// -------------------------------------------------------------- signatures

echo "\n=== Signature accuracy ===\n";

$malicious = array(
    'eval + base64'      => '<?php eval(base64_decode("aGVsbG8=")); ?>',
    'assert + rot13'     => '<?php assert(str_rot13("riny")); ?>',
    'preg_replace /e'    => '<?php preg_replace("/.*/e", $_POST["c"], ""); ?>',
    'variable function'  => '<?php $f = "system"; $f($_GET["cmd"]); ?>',
    'gzinflate chain'    => '<?php eval(gzinflate(base64_decode($x))); ?>',
    'js atob eval'       => '<script>eval(atob("YWxlcnQoMSk="))</script>',
    'hex obfuscation'    => '<?php ${"\x47\x4c\x4f\x42\x41\x4c\x53"}["x"]; ?>',
    'htaccess php in jpg'=> "AddType application/x-httpd-php .jpg\n",
);

foreach ($malicious as $label => $sample) {
    check("detects: $label", CAZ_Sentry_Signatures::match($sample) !== array());
}

$benign = array(
    'plain WordPress plugin header' => "<?php\n/*\nPlugin Name: Thing\n*/\nadd_action('init', 'thing_init');\nfunction thing_init() { return true; }\n",
    'ordinary jQuery usage'         => "jQuery(document).ready(function($){ $('.a').on('click', function(){ window.location.href='/x'; }); });",
    'a normal stylesheet'           => ".header{color:#333;background:#fff;font-family:system-ui,sans-serif}",
    'legitimate base64 image data'  => '<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUg">',
    'large inline data: URI'        => '<img src="data:image/png;base64,' . str_repeat('iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB', 60) . '">',
    'repeated filler in a cache file'=> '<html><body>' . str_repeat('x', 4000) . '</body></html>',
    'minified css bundle'           => str_repeat('.a{margin:0;padding:0}.b{display:flex;gap:8px}', 80),
);

foreach ($benign as $label => $sample) {
    $hits = CAZ_Sentry_Signatures::match($sample);
    check("no false positive: $label", $hits === array(), 'matched: ' . implode(', ', $hits));
}

echo "\n=== Filename judgements ===\n";

$badNames = array(
    'wp-content/uploads/2026/08/shell.php'      => 'php_file_in_uploads',
    'wp-content/mu-plugins/index.php'           => 'mu_plugin_executes_on_every_page_load',
    'evilshell.php'                              => 'known_backdoor_filename',
    'wp-content/plugins/x/dropper2.php'         => 'known_backdoor_filename',
    'wp-content/a1b2c3d4e5f6.php'               => 'random_hex_filename',
    'wp-content/uploads/invoice.pdf.php'        => 'double_extension',
    'wp-content/cache/cache.php'                => 'php_file_in_cache_directory',
);
foreach ($badNames as $path => $expected) {
    $verdict = CAZ_Sentry_Signatures::match_filename($path);
    check("condemns: $path", $verdict && $verdict['reason'] === $expected,
        $verdict ? 'got ' . $verdict['reason'] : 'no verdict');
}

// The configured names are what make the first two entries above fire; a
// plausible-looking shell name that was NOT configured must not be guessed at.
check('an unconfigured filename is not guessed at',
    CAZ_Sentry_Signatures::match_filename('wp-content/plugins/x/somethingelse.php') === null,
    'flagged a name that is in neither the built-in nor the configured list');

$okNames = array(
    'wp-content/plugins/fluent-smtp/fluent-smtp.php',
    'wp-includes/class-wp-query.php',
    'wp-content/themes/twentytwenty/functions.php',
    'wp-admin/admin-ajax.php',
    'wp-content/plugins/elementor/includes/base/controls-stack.php',
    'wp-content/uploads/2026/08/photo.jpg',
    'index.php',
);
foreach ($okNames as $path) {
    $verdict = CAZ_Sentry_Signatures::match_filename($path);
    check("allows: $path", $verdict === null, $verdict ? 'flagged as ' . $verdict['reason'] : '');
}

// ------------------------------------------------------------------ guard

echo "\n=== Off-site redirect detection uses this site's own hostnames ===\n";

// CAZ_SENTRY_SITE_HOSTS is 'example.com' for this run.
check('a rewrite to somebody else\'s domain is flagged',
    in_array('htaccess_redirect', CAZ_Sentry_Signatures::match("RewriteRule ^(.*)$ https://evil-domain.test/x [R,L]\n"), true));
check('a rewrite to this site is not',
    !in_array('htaccess_redirect', CAZ_Sentry_Signatures::match("RewriteRule ^(.*)$ https://example.com/x [R,L]\n"), true));
check('the www form of this site is not either',
    !in_array('htaccess_redirect', CAZ_Sentry_Signatures::match("RewriteRule ^(.*)$ https://www.example.com/x [R,L]\n"), true));
check('an ordinary .htaccess is left alone',
    CAZ_Sentry_Signatures::match("RewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\n") === array());

echo "\n=== Fail-safe guard ===\n";

CAZ_Sentry_Guard::reset();
check('guard starts clean', CAZ_Sentry_Guard::may_arm());

// Simulate three requests that armed the watcher and never reached shutdown.
for ($i = 0; $i < 3; $i++) {
    $state = json_decode(file_get_contents(CAZ_SENTRY_LOG_DIR . '/guard.json'), true);
    $state['inflight'] = 1;
    file_put_contents(CAZ_SENTRY_LOG_DIR . '/guard.json', json_encode($state));

    $reflection = new ReflectionClass('CAZ_Sentry_Guard');
    $prop = $reflection->getProperty('state');
    $prop->setAccessible(true);
    $prop->setValue(null, null);

    $allowed = CAZ_Sentry_Guard::may_arm();
}

check('watcher disables itself after repeated crashed requests', $allowed === false);
check('the auto-disable is recorded in the journal', find_event('watcher_auto_disabled') !== null);

// ----------------------------------------------------------------- cleanup

echo "\n=== Result ===\n";
printf("  %d passed, %d failed\n\n", $GLOBALS['caz_pass'], $GLOBALS['caz_fail']);

$rm = function ($dir) use (&$rm) {
    foreach (array_diff((array) scandir($dir), array('.', '..')) as $entry) {
        $path = $dir . '/' . $entry;
        is_dir($path) ? $rm($path) : @unlink($path);
    }
    @rmdir($dir);
};
$rm($root);

exit($GLOBALS['caz_fail'] === 0 ? 0 : 1);
