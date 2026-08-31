# Sentry — WordPress change forensics

Answers one question: **what keeps putting the malicious code back?**

A malware scanner tells you `index.php` changed two hours ago. That is the
wrong half of the answer — you already know the site is being reinfected.
Sentry records the *cause*: which file, which line, which HTTP request, which
IP, and which user account performed the write, at the moment it happened.

## What it is, and what it is not

**It is** an evidence recorder. It watches, attributes, and reports.

**It is not** a firewall, a scanner, or a cleaner. It does not block anything,
remove anything, or patch anything. Run it *alongside* whatever cleanup and
protection you use — it is the thing that tells you where to aim.

It never blocks a write, because a tool that guesses wrong and blocks a
legitimate write breaks the site. It observes and gets out of the way.

## How it catches things

Three independent layers, so an attacker has to evade all of them:

| Layer | Catches | Gives you |
|---|---|---|
| **Write watcher** | Anything written by PHP | The exact file:line that wrote it, plus the full call stack — including code running inside `eval()`, which has no file of its own |
| **Baseline scanner** | Anything else — FTP/SFTP, cPanel file manager, a system cron job, a compromised hosting account | Hourly diff of every file against a known-good snapshot, including files whose timestamps were backdated to hide the change |
| **Database tripwires** | Infections that never touch a file | New admin users, changed `siteurl`/`home`, scheduled events with no code behind them, script tags injected into page content |

The two file layers are deliberately redundant, and the redundancy is itself
diagnostic:

> If the baseline scan reports a changed file and there is **no matching write
> event** in the journal, the change did not come through PHP. That means
> someone has FTP/SSH/panel credentials, and no amount of WordPress-level
> hardening will stop it. That finding alone changes what you do next.

## Installing

### Recommended: as a must-use plugin

Must-use plugins load before every normal plugin, so Sentry is already
watching before the malicious code gets a turn. Over SFTP:

```
wp-content/mu-plugins/00-caz-sentry.php     <- from mu-plugin/00-caz-sentry.php
wp-content/mu-plugins/caz-sentry/           <- this whole folder
```

The `00-` prefix matters — must-use plugins load alphabetically, and Sentry
needs to be first. Create `wp-content/mu-plugins/` if it does not exist.

There is nothing to activate. Visit **Tools → Sentry** to confirm it is live.

### Alternative: as a normal plugin

Run `./package.sh`, then upload the resulting `caz-sentry.zip` through
**Plugins → Add New → Upload Plugin** and activate it.

This works, but it loads *after* other plugins, so a write performed very
early by another plugin could be missed. Use the mu-plugin install if you can.

### Optional, and worth doing: put the evidence out of reach

By default the journal lives at `wp-content/caz-sentry/`, protected by an
`.htaccess` deny rule. Anything with write access to your site can still reach
it. Moving it above the webroot means an attacker who owns the site does not
own the log of what they did.

Add to `wp-config.php`, above the `/* That's all, stop editing! */` line:

```php
define( 'CAZ_SENTRY_LOG_DIR', dirname( ABSPATH ) . '/sentry-logs' );
define( 'CAZ_SENTRY_ALERT_EMAIL', 'you@example.com' );
```

### Optional: catch writes that happen before WordPress loads

For maximum coverage, load Sentry from `wp-config.php` itself — earlier than
even a must-use plugin. Add this **immediately after** the `ABSPATH`
definition at the bottom of `wp-config.php`:

```php
if ( file_exists( ABSPATH . 'wp-content/mu-plugins/caz-sentry/caz-sentry.php' ) ) {
    require_once ABSPATH . 'wp-content/mu-plugins/caz-sentry/caz-sentry.php';
}
```

Safe to do alongside the mu-plugin install — Sentry detects the double load
and ignores the second one.

## Settings

All optional; the defaults are sensible.

| Constant (`wp-config.php`) | Default | Purpose |
|---|---|---|
| `CAZ_SENTRY_LOG_DIR` | `wp-content/caz-sentry` | Where the journal lives. Point it outside the webroot. |
| `CAZ_SENTRY_ALERT_EMAIL` | — | Email for high/critical findings, batched, max one message per 15 min. |
| `CAZ_SENTRY_MODE` | `full` | `light` turns the write watcher off, leaving scans and tripwires. |
| `CAZ_SENTRY_WEBHOOK` | — | POST the same alerts as JSON. |
| `CAZ_SENTRY_ALERTS` | `true` | Set `false` to silence notifications entirely. |
| `CAZ_SENTRY_CAPTURE_POST` | `false` | Record POST *values*, not just field names. See the privacy note below. |

Email, webhook and mode are also editable at **Tools → Sentry → Settings**.

**Privacy note:** by default Sentry records the *names* of submitted form
fields, never their values — so passwords, card numbers and customer details
stay out of the journal. The exception is a value that itself matches a
malware signature, which is recorded because that is the evidence. Turning on
`CAZ_SENTRY_CAPTURE_POST` records values for non-sensitive-looking fields too;
useful for a day or two while hunting, not something to leave on.

## Reading the results

**Tools → Sentry → Overview** leads with *Who is writing to your site*: every
write event grouped by the code that performed it, worst first.

When a site is being reinfected on a schedule, the source rises to the top of
that table. A real row looks like:

```
CRITICAL  plugin:some-plugin   wp-content/plugins/some-plugin/inc/cache.php:88   14 writes
                               eval_decoder, long_base64_blob
                               wp-content/uploads/2026/08/thumb.php, wp-content/index.php
```

That is your answer: line 88 of that file, fourteen times, dropping payloads
into two locations. Open the event's **Full record** for the call stack that
led there, and the request that triggered it.

Two patterns are worth recognising immediately:

- **`origin: eval()d-code`** — the code doing the writing was assembled at
  runtime and executed. There is no file on disk to find, which is why
  scanners keep missing it. The call stack shows which file ran the `eval()`.
- **`is_cron: 1` with no user** — the reinfection is on a timer. Check
  **Events** filtered to `cron_scheduled`, especially entries marked
  `orphan: 1` — a scheduled job with no code registered to handle it is a
  standing appointment for a payload that has not been downloaded yet.

### Event types

| Type | Meaning |
|---|---|
| `file_write` | A file was written. Includes the call stack and a content sample. |
| `file_rename` | A file was renamed — the classic "stage, then move into place". |
| `file_touch` | An mtime was set, usually backdated to hide from a "recently modified" sweep. Always worth reading. |
| `file_added` / `file_modified` / `file_removed` | Found by the hourly scan. `backdated: 1` means the timestamp disagrees with the content change. |
| `suspicious_file` | PHP in `uploads/`, a double extension like `invoice.pdf.php`, script tags inside an image, a symlink pointing outside the webroot. |
| `option_changed` | A high-risk setting moved, or an option value that contains code. |
| `user_created` / `role_changed` | A new account, or someone gaining administrator. Critical if administrator. |
| `cron_scheduled` | A scheduled event. `orphan: 1` means nothing on the site knows how to run it. |
| `post_content_injected` | Page or post content gained a `<script>`, `<iframe>` or encoded payload. |

## Tuned to this site's infection

This infection worked in two different places, which is why it was hard to
pin down. Sentry is calibrated for both.

**Hidden backdoor files.** Standalone PHP shells reached directly by URL —
`accesson.php`, `filefuns.php`, `68425ec92487.php`, and `cache.php` files.
They never appear in a page, so nothing in "View Source" would show them.
Sentry treats these as critical the instant one is written, on the filename
alone, before any content is even read:

- Exact names already seen here (`accesson.php`, `filefuns.php`) plus the
  classic shells. Add more to `$knownBadNames` in `includes/Signatures.php`
  as new ones turn up.
- Randomly generated hex names, which is what `68425ec92487.php` is.
- Double extensions, in both forms (`invoice.pdf.php`, `shell.php.jpg`).
- PHP anywhere under `uploads/` or in a cache directory. **The cache case
  matters here specifically:** cache directories churn constantly and are
  otherwise suppressed to keep the journal readable, but PHP written into one
  is never routine and is always reported. That is how a `cache.php` would be
  caught rather than lost in the noise.

**The must-use plugin injector.** `wp-content/mu-plugins/index.php` prepending
junk ahead of the real page HTML, with `GIF89` markers — the visible homepage
corruption. Must-use plugins run before every other plugin on every page load,
which is what made it so effective.

- Any PHP written into `wp-content/mu-plugins/` is critical, full stop.
- `GIF89` markers in a PHP file, and output-prepending patterns
  (`ob_start` with a callback, an early `muplugins_loaded`/`plugins_loaded`
  hook that echoes) match by signature.
- Installing Sentry as a must-use plugin puts it in that same directory. It
  loads first (`00-` sorts before `index.php`), so if that injector is
  recreated, Sentry is already watching and will name whatever wrote it.
  Sentry's own files are baselined but exempt from the mu-plugins rule, so it
  does not report itself.

Nothing here replaces the daily tripwire that checks whether the known files
are back. That answers *"is it back?"*. This answers *"what put it there?"* —
and the absence of a write event, when a file reappears, is the finding that
points at leaked credentials rather than a vulnerable plugin.

## The first 48 hours

1. Install as a must-use plugin, set the alert email, and load **Tools → Sentry**.
2. Let the first scan finish — it records the baseline. Findings it reports
   immediately are things already on disk; deal with those separately.
3. **Clean the known infection**, or leave it and wait. Either works: Sentry
   is watching for the *next* write.
4. When the reinfection happens, the alert email names the file and line.
5. Fix the cause: update or remove the offending plugin/theme, rotate every
   password (WordPress admins, SFTP/hosting, database), and delete stray admin
   accounts and orphaned cron jobs listed in the journal.
6. Once it is quiet for a few days, switch to **Light** mode in Settings for
   ongoing monitoring at no measurable cost.

## Cost

Roughly **12 ms per page** on a request performing ~3,800 filesystem
operations (measured; a typical WordPress page does fewer). That is a few
percent of a normal page's server time and will not be visible to visitors,
but it is not nothing — which is why Light mode exists for once the source is
found. Reads take the fast path and are never journalled; routine cache and
Elementor CSS writes are suppressed unless the content itself looks malicious.

## Safety

Taking over the `file://` stream wrapper is powerful and intrusive, so it is
fenced in:

- **Self-test at startup.** The wrapper proves it can round-trip a file before
  a page is served. If it cannot, it unregisters itself and drops to Light
  mode automatically.
- **Probation guard.** For the first 25 requests each one is marked in flight
  and cleared on clean shutdown. Three requests that die while the watcher is
  active and it switches itself off, logging why. The site keeps working.
- **It never blocks.** Every failure path falls through to normal filesystem
  behaviour.
- **It never recurses.** Sentry's own writes bypass the watcher.

To turn it off: set Light mode in Settings, or delete
`wp-content/mu-plugins/00-caz-sentry.php`. To re-enable after an auto-disable,
use **Re-arm write watcher** on the Overview tab.

## Tests

```
php tools/caz-sentry/tests/harness.php
```

Builds a throwaway WordPress-shaped directory, turns the watcher on, and then
behaves like malware: drops a backdoor into `uploads/`, writes through
`eval()`'d code, stages-and-renames a payload, and backdates an mtime. It
asserts each one was caught and correctly attributed, that ordinary
filesystem behaviour is unchanged, that reads are never logged, and that the
fail-safe guard trips.

It also replays this site's specific infection: a `cache.php` dropped into a
cache directory, a shell named `accesson.php`, a `68425ec92487.php`, and a
`mu-plugins/index.php` carrying `GIF89` markers — checking each is caught and
that ordinary plugin updates and Sentry's own files are not. 91 assertions,
no WordPress required.
