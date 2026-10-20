# Site Sentinel

A small file-integrity and malware monitor for web sites. It notices new, modified and removed files, flags anything that looks like malware, and alerts the site owner. It is one PHP file that runs from cron, so it works on shared hosting without root as well as on a dedicated server.

It **detects and alerts**. It never deletes or changes your site files, and it is not a replacement for backups, updates, strong passwords or two-factor login.

## Requirements

- PHP 7.4 or newer on the command line (`php -v`). Optional: `curl`, `sodium` (signed rule updates), `clamscan`, `yara`.
- Permission to run a cron job as the account that owns the site.

## Install

1. Get `sentinel.php`: build it with `php build/build.php`, then use `dist/sentinel.php`. Alternatively download the `site-sentinel` artifact from a successful **Test and build** run on the trusted default branch in GitHub Actions. The artifact includes the script, documentation, license and SHA-256 checksum; GitHub may require you to sign in to download it.
2. Put it **outside the web root**, for example `/home/you/sentinel/sentinel.php`. The config and state directory are created next to it.
3. Initialise it, giving at least one place to send alerts:

   ```
   php sentinel.php init --root=/home/you/public_html --email=owner@example.com
   ```

   `init` detects WordPress, scans the site once and refuses to create a baseline if it already finds malware (a baseline taken on an infected site would treat the malware as normal). Clean the site and run it again, or add `--force` if you accept that.
4. Paste the cron lines it prints into the crontab (`crontab -e`, or cPanel > Cron Jobs).
5. Check alerts arrive: `php sentinel.php test-alert`.
6. Recommended: set `heartbeat_url` in `sentinel.json` to a healthchecks.io-style URL. Sentinel pings it after every completed run, so you are told if it stops running or is deleted.
7. After deliberately editing the config, run `php sentinel.php accept --self` to trust the new config, then `php sentinel.php doctor` for local hosting checks. `doctor` never sends alerts or contacts remote services. Reprint the cron commands at any time with `php sentinel.php cron`.

See [the shared-hosting guide](docs/SHARED-HOSTING.md) for cPanel-style installation, email delivery, updates and troubleshooting.

## Commands

| Command | Purpose |
|---|---|
| `init` | Create the config and baseline, print cron lines. |
| `check` | Quick scan (stat-only walk, then scan only new or changed files). Run every 5-10 minutes. |
| `full` | Nightly scan: hash every code file, verify WordPress core and plugin checksums. |
| `accept` | Mark the current state as known-good: everything, or `--path=wp-content/plugins/foo` (repeatable). `--self` re-trusts the Sentinel files after you upgrade them. |
| `update-rules` | Download, verify and install the latest rules bundle. |
| `test-alert` | Send a test alert through every channel. |
| `doctor` | Read-only local hosting checks, excluded paths and last scan history. No scan, network requests or test alerts. |
| `cron` | Print cron entries with this PHP executable and safely quoted paths; never changes your crontab. |
| `db-init` | Trust separately reviewed privileged accounts and options (opt-in database module). |
| `db-check` | Check privileged accounts/options and budgeted post content. |
| `db-accept` | Trust reviewed changes: `--scope=admins` or `--scope=options`. |

Exit codes: `0` clean, `1` findings reported, `2` tool error.
For `doctor`, these mean `0` no local issues detected, `1` configuration warnings and `2` a local setup error. A passing doctor does not prove alert delivery or malware absence.

## What it reports

- **Critical:** known malware patterns or hashes (built in, plus anything from ClamAV/YARA if installed), PHP files in `wp-content/uploads` (including `shell.php.jpg`), PHP code hidden inside images, a WordPress core or repository-plugin file that does not match wordpress.org's official checksum, an executable newly created in a `tmp` directory, content changed while size and timestamp were left alone, and any change to Sentinel's own files.
- **Warning:** new or modified code that is not explained by an update, a PHP extension hidden before another one anywhere (`evil.php.jpg`), changes to `wp-config.php`, `.htaccess` or `mu-plugins`, new symlinks, files that became world-writable, removed core files.
- **Info:** things that were explained and accepted automatically (a plugin updated from 1.0 to 1.1, files verified against official checksums). Info appears in the next alert that is sent anyway; it never sends one by itself.

Each problem alerts once, and Critical problems remind you every `remind_hours` (default 24) while detected. Held changes stay out of the baseline, so they keep showing in `check` output until you run `accept`. Accepting records the current file state; it does not whitelist malware patterns, unsafe locations or official checksum mismatches, which `full` checks again even in unchanged files.

`full` rehashes code files and re-evaluates trusted files against current detection rules and WordPress checksums without treating unchanged files as unexplained edits. Optional external scanners also recheck unchanged code that was not verified against an official package. Non-code files remain stat-only for content-integrity comparisons; upload images are inspected for embedded PHP.

### WordPress updates

Core/repository plugin files matching official checksums are accepted automatically. **Unverified premium/custom updates require review by default**, even with a version-header bump. Review and acknowledge only the intended directory with `accept --path=wp-content/plugins/foo`. The explicit legacy setting `auto_accept_unverified_updates: true` restores the weaker header-version heuristic; an attacker can change that header too. Generic-site changes also require review and scoped acceptance.

## Configuration

`init` writes `sentinel.json`. The commonly edited keys:

| Key | Meaning |
|---|---|
| `site_name` | Appears in alert subjects. |
| `channels` | List of `email` (`to`, optional `from`), `ntfy` (`url`), `telegram` (`token`, `chat_id`), `webhook` (`url`), `file` (`path`). Each takes an optional `min_severity` (`info`, `warning` default, `critical`). |
| `watch` | Directories (relative to `site_root`) to monitor. Default `["."]`. |
| `exclude` | Patterns to skip: `dir/` for a directory, `*.log`, `**` for any depth. A pattern with a `/` is anchored at the site root. |
| `sensitive` | Files that raise a Warning on any change. |
| `uploads_dir` | Where PHP must never appear. Set automatically for WordPress. |
| `budget_seconds`, `budget_memory_mb` | Shared cooperative comparison/analysis budgets. HTTP/external timeouts shrink with remaining time. Individual file I/O, checkpointing and alerts can overrun; this is not an OS process limit. |
| `scan_batch_files`, `continue_full` | Default batch size 64 (maximum 1000). Pending full scans continue during checks by default, sharing time with quick scans. |
| `auto_accept_unverified_updates` | False by default: unverified updates stay held for review. |
| `database` | Optional read-only account/options/post checks; see [database setup](docs/DATABASE.md). Disabled by default. |
| `update_grace_seconds` | Files that arrived in the last N seconds (default 120) get no checksum-mismatch or unexplained-change finding yet; they are judged on the next run. This stops a scan that lands in the middle of a WordPress update from raising a false alarm. Malware pattern hits, PHP in uploads and `wp-config.php`/`.htaccess` changes are never delayed. `0` disables it. |
| `max_scan_bytes` | For files larger than this, the first and last half are scanned (malware is often appended). |
| `wp_checksums` | Set `false` to stop contacting wordpress.org. |
| `heartbeat_url` | URL pinged after each completed run. |
| `clamscan_path`, `yara_path`, `yara_rules` | Optional external scanners; found on `PATH` automatically (YARA also needs `yara_rules`). |
| `rules_url`, `rules_public_key`, `allow_unsigned_rules` | See [docs/RULES.md](docs/RULES.md). |

See `examples/sentinel.json`. To watch a server's `/tmp`, use a second config with `"site_root": "/tmp"`, `"profile": "generic"` and `"temp_root": true`. On a dedicated server, `examples/systemd/` has timers you can use instead of cron.

## Limits you should know about

- On shared hosting an attacker who controls the account can also edit Sentinel, its config and its baseline. Sentinel watches its own files and raises Critical if they change, but that is a tripwire, not a defence. The heartbeat is what tells you the monitor itself was disabled, and alerts leave the server immediately.
- Detection is rule-based: it catches common webshells and anything that violates the file-integrity rules, not novel malware. File changes that should never happen are the more reliable signal.
- Email from shared hosts is often filtered. Add a second channel (ntfy or Telegram) at least for Critical alerts.
- Symlinks are never followed, so a symlinked directory (for example `wp-content/uploads` pointing elsewhere, common with deploy tools) is not monitored. `init` lists the ones it finds; give each target its own config with `site_root` set to the target.
- `wp-config.php` kept one directory above the site root is outside the watched tree.
- File monitoring cannot detect database-only incidents. Optional [database monitoring](docs/DATABASE.md) needs explicit configuration and its own reviewed baseline.
- Excluded directories are not scanned at all, including for malware. Review the WordPress cache/backup exclusions for each site.
- A heartbeat confirms a run processed its slice, even if the traversal was partial; it does not prove complete scan coverage. `doctor` shows the last completed traversal separately. Pending full scans continue during scheduled checks unless continue_full is disabled. Initialisation also pauses safely: repeat the same init command to resume, or use --restart to discard only unfinished initial-scan progress.

## Upgrade to 0.2

Replace the script from a reviewed build and run `accept --self` for that deliberate upgrade. Existing file baselines remain usable. Unverified updates now require review unless you explicitly select the legacy policy. Database checks stay off until configured and initialised separately.

## Development

```
php tests/run.php            # all tests (no network, temporary directories only)
php tests/run.php Walker     # tests whose name contains "Walker"
php build/compat.php         # PHP 7.4 syntax check
php build/build.php          # produce dist/sentinel.php
```

Tests need no Composer or framework. Source is in `src/` (one class per file, listed in `build/files.php`); `build/build.php` concatenates it into the single distributable.

## License

Site Sentinel is free software, released under the GNU General Public License, version 3 or (at your option) any later version. See `LICENSE`. It comes with no warranty. Rule bundles keep the licenses of their sources (see `docs/RULES.md`).
