<?php
/**
 * Tools -> Sentry: the read-out.
 *
 * The headline view is "Who is writing to your site" — write events grouped
 * by the code that performed them. When something reinfects the site on a
 * schedule, the offending file and line rises to the top of that table.
 */

if (!defined('ABSPATH')) {
    exit;
}

class CAZ_Sentry_AdminPage
{
    const CAP  = 'manage_options';
    const SLUG = 'caz-sentry';

    public static function boot()
    {
        add_action('admin_menu', array(__CLASS__, 'menu'));
        add_action('admin_post_caz_sentry_action', array(__CLASS__, 'handle_action'));
    }

    public static function menu()
    {
        $hook = add_management_page(
            'Sentry',
            'Sentry',
            self::CAP,
            self::SLUG,
            array(__CLASS__, 'render')
        );

        add_action('load-' . $hook, array(__CLASS__, 'maybe_notice'));
    }

    public static function maybe_notice()
    {
        // Placeholder for screen options; kept so the load hook exists.
    }

    // -------------------------------------------------------------- actions

    public static function handle_action()
    {
        if (!current_user_can(self::CAP)) {
            wp_die('Not allowed.');
        }
        check_admin_referer('caz_sentry_action');

        $action = isset($_POST['caz_action']) ? sanitize_key($_POST['caz_action']) : '';
        $notice = '';

        switch ($action) {
            case 'scan':
                $summary = CAZ_Sentry_Baseline::scan('manual');
                $notice  = sprintf(
                    'Scan finished in %ss: %d files tracked, %d added, %d modified, %d removed, %d suspicious.',
                    $summary['seconds'], $summary['files'], $summary['added'],
                    $summary['modified'], $summary['removed'], $summary['suspicious']
                );
                break;

            case 'rebuild_baseline':
                CAZ_Sentry_Journal::ignore_start();
                @unlink(CAZ_Sentry_Baseline::file());
                CAZ_Sentry_Journal::ignore_end();
                CAZ_Sentry_Baseline::scan('rebuild');
                $notice = 'Baseline rebuilt from the current state of the filesystem. Only changes from this point on will be reported.';
                break;

            case 'rearm':
                CAZ_Sentry_Guard::reset();
                $notice = 'Write watcher re-armed. It will start on the next page load and serve a fresh probation period.';
                break;

            case 'settings':
                update_option('caz_sentry_alert_email', sanitize_email(isset($_POST['alert_email']) ? wp_unslash($_POST['alert_email']) : ''), false);
                update_option('caz_sentry_webhook', esc_url_raw(isset($_POST['webhook']) ? wp_unslash($_POST['webhook']) : ''), false);
                update_option('caz_sentry_mode', (isset($_POST['mode']) && $_POST['mode'] === 'light') ? 'light' : 'full', false);
                $notice = 'Settings saved.';
                break;

            case 'test_alert':
                CAZ_Sentry_Journal::write(array(
                    'type'     => 'test_alert',
                    'severity' => 'high',
                    'note'     => 'Manual test triggered from the dashboard.',
                    'path'     => 'wp-content/example-of-a-finding.php',
                    'blame'    => 'wp-content/plugins/example/loader.php:42',
                    'origin'   => 'plugin:example',
                ));
                update_option('caz_sentry_last_alert', 0, false);
                CAZ_Sentry_Alerts::flush();
                $notice = 'Test event written and notification sent to ' . CAZ_Sentry_Alerts::recipient() . '.';
                break;

            case 'clear_journal':
                CAZ_Sentry_Journal::ignore_start();
                $dir = CAZ_Sentry_Journal::dir();
                foreach ((array) @glob($dir . '/events.log*') as $file) {
                    @unlink($file);
                }
                CAZ_Sentry_Journal::ignore_end();
                $notice = 'Journal cleared.';
                break;
        }

        wp_safe_redirect(add_query_arg(
            array('page' => self::SLUG, 'caz_notice' => rawurlencode($notice)),
            admin_url('tools.php')
        ));
        exit;
    }

    // --------------------------------------------------------------- render

    public static function render()
    {
        if (!current_user_can(self::CAP)) {
            return;
        }

        $tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'overview';
        $notice = isset($_GET['caz_notice']) ? sanitize_text_field(wp_unslash($_GET['caz_notice'])) : '';

        echo '<div class="wrap"><h1>Sentry</h1>';
        echo '<p class="description">Records what changes on this site, and which code changed it.</p>';

        if ($notice) {
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html($notice) . '</p></div>';
        }

        $tabs = array(
            'overview' => 'Overview',
            'events'   => 'Events',
            'files'    => 'Files',
            'settings' => 'Settings',
        );

        echo '<h2 class="nav-tab-wrapper">';
        foreach ($tabs as $key => $label) {
            printf(
                '<a href="%s" class="nav-tab %s">%s</a>',
                esc_url(admin_url('tools.php?page=' . self::SLUG . '&tab=' . $key)),
                $tab === $key ? 'nav-tab-active' : '',
                esc_html($label)
            );
        }
        echo '</h2>';

        switch ($tab) {
            case 'events':
                self::tab_events();
                break;
            case 'files':
                self::tab_files();
                break;
            case 'settings':
                self::tab_settings();
                break;
            default:
                self::tab_overview();
        }

        echo '</div>';
    }

    private static function tab_overview()
    {
        $guard  = CAZ_Sentry_Guard::status();
        $base   = CAZ_Sentry_Baseline::load();
        $events = CAZ_Sentry_Journal::tail('events.log', 2000);

        // --- status ------------------------------------------------------
        echo '<h2>Status</h2><table class="widefat striped" style="max-width:900px"><tbody>';

        $watcher = CAZ_Sentry::mode() === 'light'
            ? 'Off (light mode selected in settings)'
            : (CAZ_Sentry_Write_Watcher::is_active()
                ? 'Active — every write is being attributed to the code that made it'
                : (!empty($guard['disabled'])
                    ? 'Disabled automatically after repeated failed requests. Re-arm below once you have looked at the journal.'
                    : 'Not active for this request'));

        self::row('Write watcher', $watcher);
        self::row('Probation', !empty($guard['verified'])
            ? 'Passed — running in steady state'
            : (int) $guard['clean'] . ' of 25 clean requests, ' . (int) $guard['failures'] . ' failures');
        self::row('Files baselined', number_format_i18n(count($base['files'])));
        self::row('Last scan', !empty($base['scanned_at'])
            ? esc_html(gmdate('Y-m-d H:i:s', $base['scanned_at']) . ' UTC (' . human_time_diff($base['scanned_at']) . ' ago)')
            : 'never');
        self::row('Next scheduled scan', wp_next_scheduled('caz_sentry_scan')
            ? esc_html(gmdate('Y-m-d H:i:s', wp_next_scheduled('caz_sentry_scan')) . ' UTC')
            : 'not scheduled');
        self::row('Journal', '<code>' . esc_html(CAZ_Sentry_Journal::dir()) . '</code>');
        self::row('Alerts to', CAZ_Sentry_Alerts::recipient() ? esc_html(CAZ_Sentry_Alerts::recipient()) : '<em>not configured</em>');
        echo '</tbody></table>';

        self::action_buttons();

        // --- the headline table ------------------------------------------
        echo '<h2>Who is writing to your site</h2>';
        echo '<p class="description">Write events grouped by the code that performed them. If something keeps reinfecting the site, it shows up here.</p>';

        $groups = array();
        foreach ($events as $event) {
            if (!in_array($event['type'], array('file_write', 'file_rename', 'file_delete', 'file_touch', 'file_chmod'), true)) {
                continue;
            }
            $key = (isset($event['origin']) ? $event['origin'] : '?') . ' | ' . (isset($event['blame']) ? $event['blame'] : '?');
            if (!isset($groups[$key])) {
                $groups[$key] = array(
                    'origin' => isset($event['origin']) ? $event['origin'] : '?',
                    'blame'  => isset($event['blame']) ? $event['blame'] : '?',
                    'count'  => 0,
                    'worst'  => 'info',
                    'last'   => '',
                    'paths'  => array(),
                    'sigs'   => array(),
                );
            }
            $g = &$groups[$key];
            $g['count']++;
            if (self::rank($event['severity']) > self::rank($g['worst'])) {
                $g['worst'] = $event['severity'];
            }
            if ($g['last'] === '') {
                $g['last'] = $event['at'];
            }
            if (!empty($event['path']) && count($g['paths']) < 5 && !in_array($event['path'], $g['paths'], true)) {
                $g['paths'][] = $event['path'];
            }
            foreach ((array) (isset($event['signatures']) ? $event['signatures'] : array()) as $sig) {
                $g['sigs'][$sig] = 1;
            }
            unset($g);
        }

        uasort($groups, function ($a, $b) {
            $diff = self::rank($b['worst']) - self::rank($a['worst']);
            return $diff !== 0 ? $diff : ($b['count'] - $a['count']);
        });

        if (!$groups) {
            echo '<p><em>No write events recorded yet. If the watcher only just started, give it time — or wait for the injection to happen again.</em></p>';
        } else {
            echo '<table class="widefat striped"><thead><tr>'
                . '<th style="width:90px">Severity</th><th>Component</th><th>Code that wrote it</th>'
                . '<th style="width:70px">Writes</th><th style="width:150px">Last seen</th><th>Files touched</th>'
                . '</tr></thead><tbody>';

            foreach (array_slice($groups, 0, 40) as $g) {
                printf(
                    '<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>',
                    self::badge($g['worst']),
                    esc_html($g['origin']),
                    esc_html($g['blame']),
                    $g['sigs'] ? '<br><small style="color:#b32d2e">' . esc_html(implode(', ', array_keys($g['sigs']))) . '</small>' : '',
                    (int) $g['count'],
                    esc_html($g['last']),
                    '<small>' . esc_html(implode(', ', $g['paths'])) . '</small>'
                );
            }
            echo '</tbody></table>';
        }

        // --- severity roll-up --------------------------------------------
        $counts = array('critical' => 0, 'high' => 0, 'medium' => 0, 'info' => 0, 'warn' => 0);
        foreach ($events as $event) {
            $sev = isset($event['severity']) ? $event['severity'] : 'info';
            if (isset($counts[$sev])) {
                $counts[$sev]++;
            }
        }
        echo '<h2>Journal summary</h2><p>';
        foreach ($counts as $sev => $n) {
            echo self::badge($sev) . ' ' . (int) $n . ' &nbsp; ';
        }
        echo '</p>';
    }

    private static function tab_events()
    {
        $severity = isset($_GET['severity']) ? sanitize_key($_GET['severity']) : '';
        $type     = isset($_GET['etype']) ? sanitize_key($_GET['etype']) : '';

        $filter = function ($row) use ($severity, $type) {
            if ($severity && (!isset($row['severity']) || $row['severity'] !== $severity)) {
                return false;
            }
            if ($type && (!isset($row['type']) || $row['type'] !== $type)) {
                return false;
            }
            return true;
        };

        $events = CAZ_Sentry_Journal::tail('events.log', 300, $filter);

        echo '<form method="get" style="margin:16px 0">';
        echo '<input type="hidden" name="page" value="' . esc_attr(self::SLUG) . '"><input type="hidden" name="tab" value="events">';
        echo '<select name="severity"><option value="">All severities</option>';
        foreach (array('critical', 'high', 'medium', 'info', 'warn') as $sev) {
            printf('<option value="%s"%s>%s</option>', esc_attr($sev), selected($severity, $sev, false), esc_html(ucfirst($sev)));
        }
        echo '</select> ';
        echo '<input type="text" name="etype" value="' . esc_attr($type) . '" placeholder="event type, e.g. file_write"> ';
        submit_button('Filter', 'secondary', '', false);
        echo '</form>';

        if (!$events) {
            echo '<p><em>Nothing recorded yet for this filter.</em></p>';
            return;
        }

        echo '<table class="widefat striped"><thead><tr>'
            . '<th style="width:160px">When (UTC)</th><th style="width:90px">Severity</th>'
            . '<th style="width:150px">Type</th><th>Detail</th></tr></thead><tbody>';

        foreach ($events as $event) {
            $label = '';
            foreach (array('path', 'option', 'login', 'hook', 'plugin', 'theme', 'note') as $key) {
                if (!empty($event[$key])) {
                    $label = $event[$key];
                    break;
                }
            }

            echo '<tr><td>' . esc_html(isset($event['at']) ? $event['at'] : '') . '</td>';
            echo '<td>' . self::badge(isset($event['severity']) ? $event['severity'] : 'info') . '</td>';
            echo '<td><code>' . esc_html(isset($event['type']) ? $event['type'] : '?') . '</code></td>';
            echo '<td><strong>' . esc_html(is_scalar($label) ? $label : '') . '</strong>';

            if (!empty($event['blame'])) {
                echo '<br><small>written by <code>' . esc_html($event['blame']) . '</code>'
                   . (!empty($event['origin']) ? ' (' . esc_html($event['origin']) . ')' : '') . '</small>';
            }
            if (!empty($event['signatures'])) {
                echo '<br><small style="color:#b32d2e">matched: ' . esc_html(implode(', ', (array) $event['signatures'])) . '</small>';
            }

            echo '<details style="margin-top:6px"><summary>Full record</summary>'
               . '<pre style="white-space:pre-wrap;word-break:break-all;background:#f6f7f7;padding:8px;max-height:420px;overflow:auto">'
               . esc_html(wp_json_encode($event, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES))
               . '</pre></details>';

            echo '</td></tr>';
        }

        echo '</tbody></table>';
    }

    private static function tab_files()
    {
        $base = CAZ_Sentry_Baseline::load();

        echo '<h2>Suspicious files</h2>';
        if (empty($base['suspicious'])) {
            echo '<p><em>None found in the last scan.</em></p>';
        } else {
            echo '<table class="widefat striped"><thead><tr><th style="width:90px">Severity</th><th>Path</th><th>Why</th></tr></thead><tbody>';
            foreach ($base['suspicious'] as $path => $info) {
                printf(
                    '<tr><td>%s</td><td><code>%s</code></td><td>%s</td></tr>',
                    self::badge(isset($info['severity']) ? $info['severity'] : 'medium'),
                    esc_html(ltrim($path, '/')),
                    esc_html(isset($info['reason']) ? $info['reason'] : '')
                        . (!empty($info['signatures']) ? '<br><small>' . esc_html(implode(', ', (array) $info['signatures'])) . '</small>' : '')
                );
            }
            echo '</tbody></table>';
        }

        echo '<h2>Recent file changes</h2>';
        $changes = CAZ_Sentry_Journal::tail('events.log', 150, function ($row) {
            return isset($row['type']) && in_array($row['type'], array('file_added', 'file_modified', 'file_removed', 'suspicious_file'), true);
        });

        if (!$changes) {
            echo '<p><em>No filesystem changes detected since the baseline was taken.</em></p>';
            return;
        }

        echo '<table class="widefat striped"><thead><tr><th style="width:160px">When (UTC)</th><th style="width:90px">Severity</th><th style="width:130px">Change</th><th>Path</th></tr></thead><tbody>';
        foreach ($changes as $event) {
            printf(
                '<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td><code>%s</code>%s</td></tr>',
                esc_html(isset($event['at']) ? $event['at'] : ''),
                self::badge(isset($event['severity']) ? $event['severity'] : 'info'),
                esc_html($event['type']),
                esc_html(isset($event['path']) ? $event['path'] : ''),
                !empty($event['backdated']) ? '<br><small style="color:#b32d2e">timestamp was backdated to hide the change</small>' : ''
            );
        }
        echo '</tbody></table>';
    }

    private static function tab_settings()
    {
        $mode = CAZ_Sentry::mode();

        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field('caz_sentry_action');
        echo '<input type="hidden" name="action" value="caz_sentry_action">';
        echo '<input type="hidden" name="caz_action" value="settings">';

        echo '<table class="form-table"><tbody>';

        echo '<tr><th scope="row">Mode</th><td>';
        printf(
            '<label><input type="radio" name="mode" value="full" %s> <strong>Full</strong> — intercept every write and record the code that made it. Adds a small overhead to each request.</label><br>',
            checked($mode, 'full', false)
        );
        printf(
            '<label><input type="radio" name="mode" value="light" %s> <strong>Light</strong> — hourly scans and database tripwires only. No per-write attribution.</label>',
            checked($mode, 'light', false)
        );
        echo '<p class="description">Run in Full until the source is identified, then switch to Light for ongoing monitoring.</p>';
        echo '</td></tr>';

        echo '<tr><th scope="row"><label for="caz-alert-email">Alert email</label></th><td>';
        echo '<input type="email" class="regular-text" id="caz-alert-email" name="alert_email" value="' . esc_attr(get_option('caz_sentry_alert_email', '')) . '">';
        echo '<p class="description">High and critical events are emailed here, batched, at most once every 15 minutes.</p></td></tr>';

        echo '<tr><th scope="row"><label for="caz-webhook">Webhook (optional)</label></th><td>';
        echo '<input type="url" class="regular-text" id="caz-webhook" name="webhook" value="' . esc_attr(get_option('caz_sentry_webhook', '')) . '">';
        echo '<p class="description">Same alerts POSTed as JSON, for Slack-style relays.</p></td></tr>';

        echo '</tbody></table>';
        submit_button('Save settings');
        echo '</form>';

        echo '<hr><h2>Maintenance</h2>';
        self::action_buttons(true);
    }

    // --------------------------------------------------------------- helpers

    private static function action_buttons($includeDestructive = false)
    {
        $buttons = array(
            'scan'   => array('Run a scan now', 'primary'),
            'rearm'  => array('Re-arm write watcher', 'secondary'),
        );
        if ($includeDestructive) {
            $buttons['rebuild_baseline'] = array('Rebuild baseline from current files', 'secondary');
            $buttons['test_alert']       = array('Send a test alert', 'secondary');
            $buttons['clear_journal']    = array('Clear journal', 'secondary delete');
        }

        echo '<p>';
        foreach ($buttons as $action => $spec) {
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline-block;margin-right:8px">';
            wp_nonce_field('caz_sentry_action');
            echo '<input type="hidden" name="action" value="caz_sentry_action">';
            echo '<input type="hidden" name="caz_action" value="' . esc_attr($action) . '">';
            submit_button($spec[0], $spec[1], '', false);
            echo '</form>';
        }
        echo '</p>';
    }

    private static function row($label, $value)
    {
        echo '<tr><th scope="row" style="width:220px">' . esc_html($label) . '</th><td>' . wp_kses_post($value) . '</td></tr>';
    }

    private static function rank($severity)
    {
        $rank = array('info' => 0, 'warn' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4);
        return isset($rank[$severity]) ? $rank[$severity] : 0;
    }

    private static function badge($severity)
    {
        $colours = array(
            'critical' => '#b32d2e',
            'high'     => '#d63638',
            'medium'   => '#dba617',
            'warn'     => '#996800',
            'info'     => '#646970',
        );
        $colour = isset($colours[$severity]) ? $colours[$severity] : '#646970';

        return '<span style="display:inline-block;padding:2px 8px;border-radius:9px;font-size:11px;'
             . 'font-weight:600;color:#fff;background:' . $colour . '">' . esc_html(strtoupper($severity)) . '</span>';
    }
}
