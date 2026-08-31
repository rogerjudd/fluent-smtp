<?php
/**
 * Tests the auto_prepend_file install path.
 *
 * This is the one that has to work when WordPress is absent entirely — the
 * case of a standalone backdoor reached directly over HTTP. It also has to
 * fail silently rather than fatally, because a prepend file that dies takes
 * every PHP request on the site with it.
 *
 * Runs each scenario in a separate PHP process, because prepend.php defines
 * constants and registers a stream wrapper that cannot be undone cleanly
 * inside one process.
 *
 * Run:  php tools/caz-sentry/tests/prepend-test.php
 */

error_reporting(E_ALL);

$pass = 0;
$fail = 0;

function check($label, $condition, $detail = '')
{
    global $pass, $fail;
    if ($condition) {
        $pass++;
        echo "  \033[32mPASS\033[0m  $label\n";
    } else {
        $fail++;
        echo "  \033[31mFAIL\033[0m  $label" . ($detail ? "\n         $detail" : '') . "\n";
    }
}

function rmtree($dir)
{
    if (!is_dir($dir)) {
        return;
    }
    foreach (array_diff((array) scandir($dir), array('.', '..')) as $entry) {
        $path = $dir . '/' . $entry;
        is_dir($path) ? rmtree($path) : @unlink($path);
    }
    @rmdir($dir);
}

/**
 * Build a fake WordPress install with Sentry in place as a must-use plugin.
 *
 * @param bool $realWordPress Whether to create wp-settings.php, the marker
 *                            prepend.php uses to confirm it knows where it is.
 */
function build_site($realWordPress = true)
{
    $root = sys_get_temp_dir() . '/caz-prepend-' . getmypid() . '-' . mt_rand(1000, 9999);

    mkdir($root . '/wp-content/mu-plugins/caz-sentry', 0755, true);
    mkdir($root . '/wp-content/uploads', 0755, true);

    if ($realWordPress) {
        file_put_contents($root . '/wp-settings.php', "<?php // pretend core\n");
    }

    $src = dirname(__DIR__);
    $dst = $root . '/wp-content/mu-plugins/caz-sentry';

    mkdir($dst . '/includes', 0755, true);
    copy($src . '/prepend.php', $dst . '/prepend.php');
    copy($src . '/caz-sentry.php', $dst . '/caz-sentry.php');
    foreach (glob($src . '/includes/*.php') as $file) {
        copy($file, $dst . '/includes/' . basename($file));
    }

    return $root;
}

/** Run a snippet in a fresh PHP process with prepend.php loaded first. */
function run_with_prepend($root, $snippet)
{
    $script = $root . '/runner.php';
    file_put_contents($script, "<?php\nrequire '" . $root . "/wp-content/mu-plugins/caz-sentry/prepend.php';\n" . $snippet . "\n");

    $output = array();
    $status = 0;
    exec('php ' . escapeshellarg($script) . ' 2>&1', $output, $status);

    return array('out' => implode("\n", $output), 'status' => $status);
}

function journal($root)
{
    $path = $root . '/wp-content/caz-sentry/events.log';
    if (!file_exists($path)) {
        return array();
    }
    $rows = array();
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $row = json_decode($line, true);
        if (is_array($row)) {
            $rows[] = $row;
        }
    }
    return $rows;
}

// ---------------------------------------------------------------------------

echo "\n=== A backdoor reached directly, with WordPress never loaded ===\n";

$root = build_site();

// This is the scenario: a standalone shell writes a payload. Nothing here
// loads WordPress, so the mu-plugin install would have seen none of it.
$result = run_with_prepend($root, <<<'PHP'
echo defined('ABSPATH') ? "ABSPATH_DEFINED\n" : "ABSPATH_UNDEFINED\n";
echo class_exists('CAZ_Sentry_Write_Watcher') ? "WATCHER_LOADED\n" : "WATCHER_MISSING\n";
file_put_contents(__DIR__ . '/wp-content/uploads/payload.php', '<?php @eval(base64_decode($_POST["x"])); ?>');
echo "DONE\n";
PHP
);

check('the request completes normally', $result['status'] === 0, $result['out']);
check('the watcher loaded without WordPress',
    strpos($result['out'], 'WATCHER_LOADED') !== false, $result['out']);

// Defining ABSPATH globally would disable the `if (!defined('ABSPATH')) exit;`
// guard that WordPress files use to block direct access. It must stay undefined.
check('ABSPATH is NOT defined, so direct-access guards keep working',
    strpos($result['out'], 'ABSPATH_UNDEFINED') !== false, $result['out']);

$events = journal($root);
$write  = null;
foreach ($events as $event) {
    if ($event['type'] === 'file_write' && strpos($event['path'], 'uploads/payload.php') !== false) {
        $write = $event;
    }
}

check('the write is journalled even though WordPress never ran', $write !== null,
    'events: ' . count($events));
if ($write) {
    check('  severity is critical', $write['severity'] === 'critical', 'got ' . $write['severity']);
    check('  signature matched', !empty($write['signatures']), print_r($write, true));
    check('  blamed on the script that ran',
        strpos($write['blame'], 'runner.php') !== false, 'blame was ' . $write['blame']);
    check('  the request context was captured',
        isset($write['context']) && $write['context']['sapi'] === 'cli', print_r($write, true));
}

rmtree($root);

echo "\n=== It refuses to run when it cannot confirm where it is ===\n";

// No wp-settings.php: the computed paths would be guesses, and acting on a
// wrong root is worse than not acting.
$root   = build_site(false);
$result = run_with_prepend($root, 'echo class_exists("CAZ_Sentry_Write_Watcher") ? "WATCHER_LOADED\n" : "WATCHER_MISSING\n";');

check('the request still completes', $result['status'] === 0, $result['out']);
check('the watcher declines to start outside a WordPress root',
    strpos($result['out'], 'WATCHER_MISSING') !== false, $result['out']);
rmtree($root);

echo "\n=== The kill switch ===\n";

$root = build_site();
touch($root . '/wp-content/mu-plugins/caz-sentry/caz-sentry-off');
$result = run_with_prepend($root, 'echo class_exists("CAZ_Sentry_Write_Watcher") ? "WATCHER_LOADED\n" : "WATCHER_MISSING\n";');

check('an empty caz-sentry-off file stops it loading',
    strpos($result['out'], 'WATCHER_MISSING') !== false, $result['out']);
check('and the request is unaffected', $result['status'] === 0, $result['out']);
rmtree($root);

echo "\n=== A broken install must not take the site down ===\n";

$root = build_site();
// Simulate a half-finished upload, or a scanner quarantining one file.
unlink($root . '/wp-content/mu-plugins/caz-sentry/includes/WriteWatcher.php');
$result = run_with_prepend($root, 'echo "REQUEST_SERVED\n";');

check('a missing class file does not fatal the request',
    $result['status'] === 0 && strpos($result['out'], 'REQUEST_SERVED') !== false, $result['out']);
check('and nothing is printed into the response',
    trim($result['out']) === 'REQUEST_SERVED', 'output was: ' . $result['out']);
rmtree($root);

echo "\n=== A quarantined Signatures.php is survivable ===\n";

// Sucuri or similar may quarantine exactly this file, since it contains
// malware patterns. Losing it must degrade, not break.
$root = build_site();
unlink($root . '/wp-content/mu-plugins/caz-sentry/includes/Signatures.php');
$result = run_with_prepend($root, 'echo "REQUEST_SERVED\n";');

check('a quarantined Signatures.php does not fatal the request',
    $result['status'] === 0 && trim($result['out']) === 'REQUEST_SERVED', $result['out']);
rmtree($root);

echo "\n=== Result ===\n";
printf("  %d passed, %d failed\n\n", $pass, $fail);

exit($fail === 0 ? 0 : 1);
