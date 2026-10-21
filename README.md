# Site Sentinel

A small file-integrity and malware monitor for web sites. It notices new, modified and removed files, flags anything that looks like malware, and alerts the site owner. It is one PHP file that runs from cron, so it works on shared hosting without root as well as on a dedicated server.

It **detects and alerts**. It never deletes or changes your site files, and it is not a replacement for backups, updates, strong passwords or two-factor login.

## Client package (no terminal needed)

For a site owner who can upload files and add one cron job but has no terminal (for example on xneelo shared hosting), each GitHub release includes `site-sentinel.zip`. It is a `sentinel` folder to extract next to `public_html`, with `INSTALL-XNEELO.txt` inside. The owner:

1. uploads and extracts it with the hosting file manager,
2. puts their email address in `settings.txt` (plain `name = value` lines, not JSON),
3. adds one cron job: `/usr/bin/php-wrapper /usr/home/FTP-USERNAME/sentinel/sentinel.php run`,
4. runs it once and waits for the "Site Sentinel is now protecting ..." email.

Send the client the release asset link, `https://github.com/bromedia/site-sentinel/releases/latest/download/site-sentinel.zip`, not the release page, whose "Source code (zip)" is the wrong download.

`run` sets Sentinel up on its first run, then checks on every run and adds a full scan once a day. It prints nothing when all is well, and a packaged `sentinel.php` started without arguments does the same job, in case a hosting cron wrapper drops the argument.
- **Setup** happens only while the shipped `SETUP-PENDING.txt` is present and the state folder shows no earlier install. A missing baseline on an installed site is reported, never silently recreated. If the setup scan flags files, setup still finishes for the rest of the site: the flagged files are left out of the baseline and reported on every run (daily for Critical) until they are cleaned, removed, or dismissed and accepted. The welcome email then arrives as a security alert listing them.
- **Alerts** are in plain language (`"audience": "client"`) and name the contact from `settings.txt`; they never ask the owner to run commands. Technical detail follows at the end, for the developer the alert is forwarded to. File names are escaped, so a file cannot add its own text to an alert.
- **Plugin and theme update approval** is a visible yes/no line in `settings.txt`. The package ships with `yes`; see [WordPress updates](#wordpress-updates).
- **Changed files** is a visible `tell me` / `quiet` line in `settings.txt` (item 5). The package ships with `tell me`; `quiet_folders` and the trade-off are in [Configuration](#configuration).
- **Changing `settings.txt`** is announced to the previous and the new recipients, setting by setting and in the previous settings' words, and retried until it has gone out. If `settings.txt` has a mistake or goes missing, Sentinel keeps using the last settings that worked and says so.

These protect against mistakes and casual tampering. Anyone who can write the sentinel folder can also edit what Sentinel remembers there, so for client installs a heartbeat (the `heartbeat =` line) is what notices Sentinel being switched off.

Build the ZIP locally with `php build/package.php`. `INSTALL-XNEELO.txt` also covers updates, false positives and reinstalling, for the developer, using temporary cron jobs instead of a terminal.

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
| `run` | The single scheduled job for packaged installs: first-run setup, then `check`, plus `full` once a day. Silent when all is well. |
| `dismiss` | Mark a reviewed false positive: `dismiss <id> --reason="..."` (the id is shown next to the finding). `--list` shows dismissals, `--remove=<id>` undoes one. |
| `update-rules` | Download, verify and install the latest rules bundle. |
| `test-alert` | Send a test alert through every channel. |
| `doctor` | Read-only local hosting checks, excluded paths and last scan history. No scan, network requests or test alerts. |
| `cron` | Print cron entries with this PHP executable and safely quoted paths; never changes your crontab. |

Exit codes: `0` clean, `1` findings reported, `2` tool error.
For `doctor`, these mean `0` no local issues detected, `1` configuration warnings and `2` a local setup error. A passing doctor does not prove alert delivery or malware absence.

## What it reports

- **Critical:** known malware patterns or hashes (built in, plus anything from ClamAV/YARA if installed), PHP files in `wp-content/uploads` (including `shell.php.jpg`), PHP code hidden inside images, a WordPress core or repository-plugin file that does not match wordpress.org's official checksum, an executable newly created in a `tmp` directory, content changed while size and timestamp were left alone, and any change to Sentinel's own files (the script, its config, and the rules and dismissals it keeps; a rules or dismissals file changed by hand is also ignored until you run `accept --self`).
- **Warning:** new or modified code that is not explained by an update, a PHP extension hidden before another one anywhere (`evil.php.jpg`), changes to `wp-config.php`, `.htaccess`, `mu-plugins` or the drop-ins WordPress loads without activation (`object-cache.php`, `sunrise.php`, `fatal-error-handler.php` …), new symlinks, files that became world-writable, removed core files.
- **Info:** things that were explained and accepted automatically (files verified against official checksums, a repository plugin updated to a published version). Info appears in the next alert that is sent anyway; it never sends one by itself.

Every alert email, and the setup email when setup found flagged files, carries the full plain-text report as an attachment (every finding and every changed file, one line each, cut at 2 MB with a pointer to the server copy), and the email says so; a client email lists at most 10 files per section and counts the rest, which are in the report. The complete copies, the newest 30, are kept in `sentinel/state/reports/`. If the report cannot be saved or attached, the email says so and goes out anyway.

Each problem alerts once, and Critical problems remind you every `remind_hours` (default 24) until fixed or accepted. Held changes stay out of the baseline, so they keep showing in `check` output until you run `accept`.

`full` rehashes code files, so it catches content changes that left size and timestamp alone. Files whose content has not changed since they were baselined or accepted are not scanned again: a rules update does not yet find malware that was already in the baseline.

### Reviewed false positives

Some legitimate files match a detection: a vendor's obfuscated licence check, an `index.php` guard file a plugin drops into uploads. Once you have looked at one and are sure it is harmless, dismiss it with the id shown next to it in the alert or `check` output:

```
php sentinel.php dismiss 912559fc1210 --reason="Vendor licence check in Premium 2.0, reviewed"
```

A dismissal covers that one rule on that one file with its exact current content: if the file changes, or a different rule matches it, you are alerted again. It records who dismissed it, when and why (`dismiss --list`). Only detections can be dismissed; changes (`unexplained-change`, `unverified-update`, a changed `wp-config.php`, and so on) are reviewed and then accepted with `accept --path=...`, so a new file that matched a rule usually needs both. `dismiss` refuses a file that has changed since it was reported, so you only ever dismiss what you saw. `dismiss --remove=<id>` puts the finding back: the file is taken out of the baseline, so the next scan examines it as a new file, with every check a new file gets, and it stays out of the baseline until it is reviewed and accepted again. If `dismissals.json` is changed by hand, or Sentinel's record of its own files (`selfcheck.json`) goes missing, scans ignore the dismissals and raise a Critical alert, and `dismiss` refuses to edit the file until you have reviewed it and run `accept --self` (which lists what it trusts). This is a tripwire against tampering by someone who doesn't know Sentinel, not a defence against someone who does: anyone who can write the state directory can also edit the baseline. The heartbeat is what tells you the monitor itself was disabled.

### WordPress updates

Core and repository plugins are verified against wordpress.org checksums, so updates are recognised without help. Premium or custom plugins and themes have no official checksums, and a version number proves nothing (whoever can edit the files can edit the `Version:` header). So their changes are one Warning per plugin or theme, held until you review and accept that directory, for example `php sentinel.php accept --path=wp-content/plugins/foo`: `unverified-update` when the version changed, `unexplained-change` when it did not. Any further change while one is waiting alerts again. The same applies to a repository plugin whose new version wordpress.org has not published. If you would rather have premium updates accepted quietly, set `auto_accept_unverified_updates` to `true`. A plugin is only treated as premium when wordpress.org confirms it does not host it: a repository plugin bumped to an unpublished version, or any plugin while wordpress.org cannot be reached, still raises a Warning. For other sites (`generic` profile) changes are Warnings until you `accept`; run `php sentinel.php accept` after each deploy, for example as the last line of your deploy script.

WordPress installs in subfolders of the site (up to three levels down, for example `shop/` or `clients/blog/`) are found on every run and get the WordPress path rules under their folder: PHP in their `wp-content/uploads` is Critical, their `wp-config.php` and other sensitive files are reported by name, their cache and backup folders are excluded (unless you set your own `exclude` list, which replaces the defaults), and each one is checked like WordPress in the website folder: its core files against the official checksums for its own version and locale (downloaded once per release, however many installs share it), and its plugin and theme updates by version header under the same update policy, accepted with `accept --path=<folder>/wp-content/plugins/<name>`. `doctor` lists the installs it found.

## Configuration

`init` writes `sentinel.json`. The commonly edited keys:

| Key | Meaning |
|---|---|
| `site_name` | Appears in alert subjects. |
| `channels` | List of `email` (`to`, optional `from`), `ntfy` (`url`), `telegram` (`token`, `chat_id`), `webhook` (`url`), `file` (`path`). Each takes an optional `min_severity` (`info`, `warning` default, `critical`). |
| `watch` | Directories (relative to `site_root`) to monitor. Default `["."]`. |
| `exclude` | Patterns to skip: `dir/` for a directory, `*.log`, `**` for any depth. A pattern with a `/` is anchored at the site root. Leave it out for the defaults (`init` does); a list you set replaces them, also for WordPress in subfolders. |
| `sensitive` | Files that raise a Warning on any change. Like `exclude`: left out for the defaults, replaced by a list you set. |
| `uploads_dir` | Where PHP must never appear. Set automatically for WordPress. |
| `budget_seconds`, `budget_memory_mb` | Cooperative budgets for file comparison. Comparison pauses and resumes on the next invocation of the same command. Analysis, checksum requests, external scanners and initialisation can exceed these budgets; they are not hard process limits. |
| `update_grace_seconds` | Files that arrived in the last N seconds (default 120) get no checksum-mismatch or unexplained-change finding yet; they are judged on the next run. This stops a scan that lands in the middle of a WordPress update from raising a false alarm. Malware pattern hits, PHP in uploads and `wp-config.php`/`.htaccess` changes are never delayed. `0` disables it. |
| `max_scan_bytes` | For files larger than this, the first and last half are scanned (malware is often appended). |
| `wp_checksums` | Set `false` to stop contacting wordpress.org. |
| `settings_file`, `audience`, `contact` | Used by the client package: a `settings.txt` with recipients, site name, contact, the update policy and `changed_files` (`tell me` or `quiet`); `client` for plain-language alerts. Relative paths in the config are relative to the config file. |
| `auto_accept_unverified_updates` | Default `false`. `true` accepts a premium plugin or theme update on its version change alone, as earlier releases did. Never applies to a wordpress.org plugin bumped to a version wordpress.org has not published, nor while wordpress.org cannot be reached to confirm a plugin is not hosted there. That safeguard needs `wp_checksums`: with it off, nothing is looked up and every version bump is auto-accepted. |
| `quiet_changes`, `quiet_folders` | `quiet_changes` (`true`/`false`, default `false`; anything other than `true` is not quiet) records changes that nothing flags without an email, everywhere; `settings.txt` `changed_files = quiet` sets it for the client package and wins over this key. `quiet_folders` (patterns like `exclude`, but always anchored at the website folder: `app/` means `<website folder>/app/` only, never a folder called `app` inside a theme or a plugin called `app`) does the same for those folders only, and works with `changed_files = tell me`. The trade-off: a quiet change is not emailed, so a tampered file that matches no malware pattern and is not sensitive is listed in the server report and in the next alert's report instead. Malware hits, a file with an earlier detection nobody has reviewed, PHP in uploads, core and server configuration files, sensitive files and drop-ins, and files that became world-writable are always emailed; changes in a run where a configured scanner cannot run are reported as usual. The protection for wordpress.org plugins (an edited repository plugin, or one wordpress.org cannot be asked about, is never quiet) needs `wp_checksums`: with `wp_checksums: false` it is off for quiet too, and core files are recognised only by their path. |
| `heartbeat_url` | URL pinged after each completed run. |
| `clamscan_path`, `clamdscan_path`, `yara_path`, `yara_rules` | Optional external scanners; found on `PATH` automatically (YARA also needs `yara_rules`). `clamdscan` (the host's clamd service, run with `--fdpass`) is preferred when present, with `clamscan` as the fallback; setting only `clamscan_path` uses plain clamscan. |
| `rules_url`, `rules_public_key`, `allow_unsigned_rules` | See [docs/RULES.md](docs/RULES.md). |

See `examples/sentinel.json`. To watch a server's `/tmp`, use a second config with `"site_root": "/tmp"`, `"profile": "generic"` and `"temp_root": true`. On a dedicated server, `examples/systemd/` has timers you can use instead of cron.

## Limits you should know about

- On shared hosting an attacker who controls the account can also edit Sentinel, its config and its baseline. Sentinel watches its own files and raises Critical if they change, but that is a tripwire, not a defence. The heartbeat is what tells you the monitor itself was disabled, and alerts leave the server immediately.
- Detection is rule-based: it catches common webshells and anything that violates the file-integrity rules, not novel malware. File changes that should never happen are the more reliable signal.
- Email from shared hosts is often filtered. Add a second channel (ntfy or Telegram) at least for Critical alerts.
- Symlinks are never followed, so a symlinked directory (for example `wp-content/uploads` pointing elsewhere, common with deploy tools) is not monitored. `init` lists the ones it finds; give each target its own config with `site_root` set to the target.
- `wp-config.php` kept one directory above the site root is outside the watched tree.
- The WordPress database is not inspected: spam posts, rogue users and injected options may produce no file changes.
- Excluded directories are not scanned at all, including for malware. Review the WordPress cache/backup exclusions for each site.
- A heartbeat confirms a run processed its slice, even if the traversal was partial; it does not prove complete scan coverage. `doctor` shows the last completed traversal separately. A partial `full` scan resumes on the next `full`, not on a `check`.

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
