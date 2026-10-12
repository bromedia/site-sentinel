# Site Sentinel — Design

Date: 2026-10-12
Status: Draft for review
Name: `site-sentinel` is a placeholder.

## 1. Purpose

A small, low-resource file-integrity and malware monitor for web sites. It
detects new, modified and removed files, flags anything that looks like
malware, and alerts the site owner. It runs on shared hosting without root
and on a dedicated server.

Intended use: run by Conor on his own dedicated server, and installed or
recommended to clients, most of whom are WordPress sites on shared hosting.
It must not be WordPress-only.

Open source (license to be chosen; see section 14).

### Success criteria

- A client can install it in minutes: download one file, run `init`, paste the
  printed cron line.
- Normal WordPress updates do not cause alerts.
- A real change (webshell dropped, core file edited, PHP in uploads) produces a
  clear alert naming the file and the reason.
- A scheduled run is cheap enough for shared hosting (bounded time and memory).
- Detection rules update without changing the tool.

### Non-goals (v1)

Real-time inotify monitoring, central dashboard, WordPress plugin front-end,
quarantine or auto-clean, Joomla/Drupal checksum support, SMTP delivery.
The tool detects and alerts only. It never deletes or modifies site files.

## 2. Constraints and assumptions

- Language: PHP CLI, compatible with PHP 7.4 and later. PHP is available on
  every WordPress host and runnable from cron.
- No required extensions beyond those in a default PHP CLI build. Optional:
  `sodium` (rule signature verification), `curl` (otherwise stream wrappers).
- No root, no daemons, no SQLite requirement.
- One distributable file, `sentinel.php`, built from a few source files.
- Alerts go to the site owner. The config accepts several recipients.

## 3. Commands

| Command | Purpose |
|---|---|
| `init` | Detect profile, write config, run a full scan, print the cron line. Warns or refuses if the site already has Critical findings. |
| `check` | Frequent scan. Stat-only walk of watched paths, then scan only new or changed files. |
| `full` | Nightly scan. Hash everything in scope, verify WordPress core and plugin checksums. |
| `accept` | Mark the current state (or given paths) as known-good. |
| `update-rules` | Fetch, verify and install a new rules bundle. |
| `test-alert` | Send a test alert through every configured channel. |

Exit codes: 0 clean, 1 findings reported, 2 tool error.

## 4. Components

- **Config** (JSON): site name, profile, watch roots, exclusions, alert
  channels and recipients, thresholds, time and memory budgets, optional
  heartbeat URL.
- **State directory** (hidden, outside web root when possible, mode 700):
  baseline file, alert-dedupe state, lock file, rules bundle.
- **Baseline**: flat sorted line-based file, one line per file: path, size,
  mtime, permissions, hash (hash may be empty for stat-only entries). Streamed
  line by line so memory stays flat on large sites.
- **Walker**: iterates watch roots, applies exclusions, yields file metadata.
- **Differ**: compares walker output to the baseline and yields new, modified
  and removed files.
- **Scanners** (pluggable; run only on new or modified files):
  - WordPress checksums: core via the wordpress.org checksum API, repo plugins
    via the plugin-checksums API. No wp-cli required.
  - Pattern rules: regexes for PHP webshells and obfuscation.
  - Bad-hash list.
  - Location rules: PHP under `uploads`, PHP code inside image files,
    executables newly created in temp directories.
  - Optional `clamscan`/`clamd` and `yara`, used automatically when present.
- **Classifier**: assigns severity and groups changes by plugin/theme
  directory.
- **Alerter**: formats one digest per run and sends it through each channel.
- **Self-check**: hashes the script, config and rules file each run.

## 5. Data flow (`check`)

1. Acquire lock (`flock`); exit quietly if another run holds it.
2. Walk watch roots; diff against the baseline into new/modified/removed.
3. Run the scanners on new and modified files.
4. Classify each finding and group by plugin/theme directory.
5. Drop findings already alerted for the same file and hash state.
6. Send one digest to each channel.
7. Update the baseline. Changes that scanned clean are accepted automatically.
   Suspicious ones stay flagged until `accept`.
8. Ping the heartbeat URL if configured.

`full` is the same flow with hashing of the whole scope and checksum
verification enabled.

## 6. Severity

- **Critical**: scanner hit (known-bad hash, strong webshell pattern); PHP file
  under `uploads`; WordPress core or repo-plugin file not matching the official
  checksum; newly created executable in a temp directory; tool self-check
  failure.
- **Warning**: unexplained new or modified files in themes, plugins or
  mu-plugins; changes to `wp-config.php` or `.htaccess`; removed core files.
- **Info**: explained and auto-accepted changes (updates). Digest only, no push
  alert.

## 7. WordPress update handling

- Core and repo plugins: a changed file that matches the official checksum for
  the installed version is a legitimate update and is accepted silently.
- Premium or custom plugins and themes: changes are grouped by directory. If
  the version header changed and every file scans clean, report one Info line
  and accept. If any file does not scan clean, report Critical.
- Generic profile: no checksums, so changes are Warning until `accept` (or a
  post-deploy hook runs `accept`).
- Default exclusions: cache, upgrade and log directories. `uploads` is not
  hashed file by file; new files there are checked for PHP code.

## 8. Rules and updates

- Rules live in a separate bundle (patterns, bad hashes, version, source
  attributions). The script itself changes rarely.
- `update-rules` downloads the bundle from a configurable URL (default: a
  GitHub release for this project).
- Verification: ed25519 signature via sodium when available; otherwise a
  SHA-256 manifest fetched over HTTPS. A bundle that fails verification is
  discarded and an alert is raised.
- The default bundle is curated by the maintainer from sources whose licenses
  permit redistribution. Candidates (license to be verified before bundling):
  Linux Malware Detect signatures, php-malware-finder, Neo23x0 signature-base.
  Each retained rule keeps its source and license in the bundle metadata.

## 9. Alerts

- Channels: email via `mail()`, ntfy, Telegram, generic webhook. A second
  channel is recommended for Critical alerts because shared-host email
  deliverability is poor.
- One plain-text digest per run: site name, host, time, highest severity, then
  each file with reason, severity and a suggested action.
- Dedupe: each file/hash state alerts once; unresolved Critical findings
  remind daily.
- Heartbeat (optional): after each successful run, ping a URL (healthchecks.io
  style). Missing pings are alerted by the external service. Recommended in
  setup, since it is the only signal for a disabled or deleted monitor.

## 10. Self-protection and limits

- Install script, config and state outside the web root where the host allows;
  permissions 600/700.
- Self-check raises Critical when the script, config or rules file changes.
  This is a tripwire, not a defence against an attacker with account access,
  and the documentation says so.
- `init` runs a full scan first; Critical findings block baseline creation
  unless forced, so an already-infected site is not blessed as known-good.
- Documentation states plainly: detection and alerting only; not a substitute
  for backups, updates, strong passwords or 2FA.

## 11. Resource safety and errors

- Lock file prevents overlapping runs.
- Each run has a time and memory budget. The walk records its position and
  resumes on the next run if the budget is hit.
- Lowers its own priority via `nice` where available.
- Unreadable paths and scan errors appear in the digest. The tool never fails
  silently; fatal errors alert and exit 2.
- Network failures (checksum API, rules update) degrade to "check skipped"
  warnings, never to false clean results.

## 12. Testing

- Plain `php` test scripts with fixtures, no framework dependency.
- Cover: baseline diff (new, modified, removed, renamed); severity
  classification; checksum matching against recorded API responses (no live
  network); rule matching against synthetic test strings (no real malware);
  lock file, time budget and resume; alert formatting via a fake channel;
  `init` refusal on a dirty site.
- All tests use temporary directories and never touch real sites.
- Run on the newest local PHP; lint for 7.4 syntax compatibility.

## 13. Packaging

Develop as a few focused source files under `src/`. A small build script
produces the single distributable `sentinel.php`. Install on a site:
download the file, run `php sentinel.php init`, add the printed cron line.
A systemd timer example is provided for the dedicated server.

## 14. Open items

- Project name (placeholder `site-sentinel`).
- Open-source license for the code (e.g. MIT or GPL); rule licenses constrain
  the bundle separately.
- Final choice of bundled rule sources after license verification.
- Default rules URL and signing key management.
