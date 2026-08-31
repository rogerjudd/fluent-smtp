# Note for a hosting or security reviewer

You have probably been sent here by a site owner asking you to whitelist this
before their scanner quarantines it. This page is written for you, so you can
decide quickly.

## What it is

A read-only forensic logger for WordPress. It records **which code writes to
files on the site**, along with the request that triggered the write — URL,
IP, logged-in user, whether it was cron or CLI.

It exists because a scanner reports *that* a file changed, not *what changed
it*. When a site is being reinfected after every cleanup, the missing piece is
attribution.

## What it does not do

- It does not block, modify, delete, or quarantine anything.
- It does not phone home. No telemetry, no external calls, except an optional
  operator-configured email alert or webhook.
- It does not collect visitor data. Submitted form field *names* are recorded;
  values are not, unless a value itself matches a malware pattern, and never
  for fields that look like credentials.

Every failure path falls through to normal filesystem behaviour. It observes
and gets out of the way.

## Two things that will probably trip your scanner

Flagged here so you can see them before your tooling does.

**1. `includes/Signatures.php` contains malware patterns.**

The file holds the detection ruleset: literal strings such as
`eval(base64_decode`, `gzinflate`, `shell_exec`, `preg_replace` with the `/e`
modifier, `GIF89`, and the names of well-known web shells. These are the
patterns it searches *for*. They appear in a static array of regular
expressions and are never executed.

This is the standard false positive for security tooling — a signature
database looks like the thing it detects.

**2. `includes/WriteWatcher.php` overrides the `file://` stream wrapper.**

It calls `stream_wrapper_unregister('file')` and registers a class in its
place, so that every filesystem write can be recorded with the PHP call stack
of whatever performed it. This is what lets it attribute a write to a specific
file and line — including writes made from `eval()`'d code, which has no file
on disk.

The wrapper delegates every operation to the native handler and returns its
result unchanged. It never alters, blocks, or rewrites data. It is an unusual
technique, which is why it is called out here rather than left for you to
find.

## Safety measures, if you are weighing the risk of it running

- **Self-test at startup.** It proves the wrapper can round-trip a file before
  any page is served. If it cannot, it unregisters itself and continues in a
  reduced mode.
- **Probation guard.** For the first 25 requests each is marked in flight and
  cleared on clean shutdown. Three requests that die while the watcher is
  active and it disables itself permanently, logging why.
- **Kill switch.** An empty file named `caz-sentry-off` in the install
  directory stops it loading on the next request, with no PHP or ini editing.
- **It never defines `ABSPATH`.** The optional `prepend.php` bootstrap runs
  before WordPress loads, and deliberately avoids defining `ABSPATH` because
  doing so would disable the `if (!defined('ABSPATH')) exit;` direct-access
  guard used throughout WordPress, themes and plugins.

## Verifying what is on the server

`CHECKSUMS.txt` in this repository lists a SHA-256 for every installed file at
this commit. Compare it against the files in place to confirm the server is
running exactly the source reviewed here.

(To be clear about what that does and does not prove: it confirms the files
match this source. It is a consistency check, not a signature — anyone able to
edit the files could also edit a checksum list. Treat it as "is the server
running what I read?", nothing more.)

## Where it installs

```
wp-content/mu-plugins/00-caz-sentry.php     loader
wp-content/mu-plugins/caz-sentry/           the tool
```

Optionally, `auto_prepend_file` in `.user.ini` pointing at
`caz-sentry/prepend.php`, which extends the watcher to requests that never
load WordPress — the case of a standalone backdoor reached directly by URL.

## Tests

```
php tests/harness.php
php tests/prepend-test.php
```

No WordPress required. They build a throwaway install, simulate an infection
against it, and assert that ordinary filesystem behaviour is unchanged, that
reads are never logged, that the fail-safe guard trips, and that a broken or
partially quarantined install still serves requests normally rather than
taking the site down.
