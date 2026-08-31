# Sentry — WordPress change forensics

Answers one question: **what keeps putting the malicious code back?**

> **Reviewing this before allowing it on a server?** Start with
> [REVIEW.md](REVIEW.md) — it is written for you, and names up front the two
> things that will most likely trip a malware scanner.

> **Keep operational detail out of this repository.** The code is GPL and
> nothing here is secret, but a repo like this tends to accumulate the names
> of a specific site's backdoors, its domains, and its timeline. Those belong
> in `config.php`, which is git-ignored — not in commits or issues. A
> published list of what you found on your server is an inventory of your
> compromise.

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

**Name the folder `caz-sentry`.** If you clone this repository, the directory
takes the repository's name, so rename it — the loader looks for
`caz-sentry/caz-sentry.php` beside itself. (Sentry works out its own location
independently for the purpose of not reporting its own files, so a different
name will not produce false findings; the loader still needs to find it.)

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

### The blind spot in every install above, and how to close it

**A must-use plugin only sees requests that load WordPress.** A standalone
backdoor does not. When someone requests `yoursite.com/some-shell.php`
directly, PHP runs that one file and nothing else — no WordPress, no
mu-plugins, no Sentry. Whatever that shell writes is invisible to the write
watcher. The hourly scan still notices the *result*, but by then the
attribution is gone.

If the shells on your server are that kind — reached by typing the URL,
invisible to visitors and to "View Source" — this is the gap that matters
most, and the mu-plugin install alone will not close it.

PHP's `auto_prepend_file` closes it. That directive runs a chosen file before
*every* PHP script on the server, WordPress or not — so a shell invoked
directly is watched from its first instruction. Create or edit `.user.ini` in
the web root:

```ini
auto_prepend_file = "/full/path/to/wp-content/mu-plugins/caz-sentry/prepend.php"
```

Use the absolute filesystem path, not a URL. Then copy `config.sample.php` to
`config.php` and set the log directory and alert address there — at that point
in the request `wp-config.php` has not been read, so its constants do not
exist yet. Define each constant in one file only.

**This is the highest-risk install, and the trade is real.** A fatal error in a
prepended file breaks every PHP request on the site, wp-admin included, and
the only way back is file access. `prepend.php` is built for that: it wraps
everything, refuses to start unless it can confirm it is in a WordPress root,
does nothing if any of its own files are missing, and is covered by a test
suite that specifically checks a broken or partially quarantined install still
serves requests normally. But test it on staging first if you have one.

Two ways out, in order of speed:

1. Create an empty file named `caz-sentry-off` in the `caz-sentry` directory.
   Sentry stops loading on the next request; no PHP or ini editing.
2. Remove the `auto_prepend_file` line from `.user.ini`. Changes there can take
   up to five minutes to apply, since PHP caches the file
   (`user_ini.cache_ttl`, 300 seconds by default).

It never defines `ABSPATH`. That is deliberate: WordPress files, themes and
plugins block direct access with `if (!defined('ABSPATH')) exit;`, and defining
it globally from a prepend file would quietly disable that protection across
the entire site. Sentry resolves paths through its own constants instead.

### Also optional: load early from wp-config.php

Less coverage than `auto_prepend_file` (it still only applies to requests that
load WordPress) but lower risk. Add this **immediately after** the `ABSPATH`
definition at the bottom of `wp-config.php`:

```php
if ( file_exists( ABSPATH . 'wp-content/mu-plugins/caz-sentry/caz-sentry.php' ) ) {
    require_once ABSPATH . 'wp-content/mu-plugins/caz-sentry/caz-sentry.php';
}
```

Safe alongside any of the installs above — Sentry detects a double load and
finishes the setup rather than starting twice.

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
| `CAZ_SENTRY_EXTRA_BACKDOOR_NAMES` | — | Comma-separated backdoor filenames found on **your** server. Put these in `config.php`, not in tracked source. |
| `CAZ_SENTRY_SITE_HOSTS` | inferred | Comma-separated hostnames that belong to this site, used to spot off-site redirects in `.htaccess`. |

Email, webhook and mode are also editable at **Tools → Sentry → Settings**.

The last two describe your site rather than your preferences. Set them in
`config.php` (git-ignored), so that a list of your backdoors and your domains
never lands in a repository.

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

## Tuning it to your incident

Two infection shapes are common, and Sentry is calibrated for both.

**Hidden backdoor files.** Standalone PHP shells reached by typing the URL.
They never appear in a page, so nothing in "View Source" shows them, and a
visitor would never trip over one. Sentry treats these as critical the moment
one is written, on the filename alone, before the contents are read:

- Long-standing public shell names, built in.
- **Names from your own incident**, which you add via
  `CAZ_SENTRY_EXTRA_BACKDOOR_NAMES` in `config.php`. Keep them there rather
  than in the source: a list of the backdoors found on your server is an
  inventory of your compromise, and `config.php` is git-ignored for that
  reason.
- Randomly generated names — a run of hex characters, or an all-lowercase,
  digit-heavy stem.
- Double extensions, in both forms (`invoice.pdf.php`, `shell.php.jpg`).
- PHP anywhere under `uploads/` or in a cache directory. **The cache case is
  easy to miss:** cache directories churn constantly and are otherwise
  suppressed to keep the journal readable, but PHP written into one is never
  routine and is always reported, so a shell parked there does not get lost in
  the noise.

**Output injected ahead of the page.** A must-use plugin, or an early hook,
prepending markup before the real page HTML — spam links, a redirect, hostile
JavaScript, or the `GIF89` markers that come with image-disguised payloads.
Must-use plugins run before every other plugin on every page load, which is
what makes that spot so effective.

- Any PHP written into `wp-content/mu-plugins/` is critical, full stop.
- `GIF89` markers in a PHP file, and output-prepending patterns (`ob_start`
  with a callback, an early `muplugins_loaded`/`plugins_loaded` hook that
  echoes) match by signature.
- Installing Sentry as a must-use plugin puts it in that same directory. It
  loads first (`00-` sorts ahead of `index.php`), so if such an injector is
  recreated, Sentry is already watching and will name whatever wrote it.
  Sentry's own files are baselined but exempt from the mu-plugins rule, so it
  does not report itself.

None of this replaces a routine check for whether known-bad files are back.
That answers *"is it back?"*. This answers *"what put it there?"*.

Nothing about your site should end up in the tracked source. Domains go in
`CAZ_SENTRY_SITE_HOSTS`, backdoor names in `CAZ_SENTRY_EXTRA_BACKDOOR_NAMES`,
both in `config.php`. Publishing a detection ruleset tells whoever is getting
in exactly what you are watching for.

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
php tools/caz-sentry/tests/prepend-test.php
```

Builds a throwaway WordPress-shaped directory, turns the watcher on, and then
behaves like malware: drops a backdoor into `uploads/`, writes through
`eval()`'d code, stages-and-renames a payload, and backdates an mtime. It
asserts each one was caught and correctly attributed, that ordinary
filesystem behaviour is unchanged, that reads are never logged, and that the
fail-safe guard trips.

It also replays the two infection shapes above: a PHP file dropped into a
cache directory, a configured backdoor name, a random hex name, and a
`mu-plugins/index.php` carrying `GIF89` markers — checking each is caught,
that a name in neither the built-in nor the configured list is *not* guessed
at, and that ordinary plugin updates and Sentry's own files are left alone.

`prepend-test.php` covers the `auto_prepend_file` install in separate PHP
processes with no WordPress present at all: a backdoor writing a payload is
still caught and attributed, `ABSPATH` stays undefined so direct-access guards
keep working, the kill switch works, and a broken or partially quarantined
install still serves requests normally rather than taking the site down.

114 assertions across both suites, no WordPress required.
