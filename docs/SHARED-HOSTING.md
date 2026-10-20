# Running Sentinel on WordPress shared hosting

Sentinel is a PHP CLI program, not a WordPress plugin. It needs the hosting account's file permissions and server cron facility. It does not load WordPress, require its database credentials, or depend on visitors triggering WP-Cron. Root, Composer, WP-CLI, ClamAV and YARA are not required.

## Install

1. Build on a computer with PHP: `php build/build.php`. Upload `dist/sentinel.php` using SFTP or the hosting file manager. You can also download the `site-sentinel` artifact from a successful trusted default-branch **Test and build** workflow run in GitHub Actions. Do not deploy an unreviewed pull-request artifact.
2. Place it outside the public web directory, for example `/home/client/sentinel/sentinel.php` alongside `/home/client/public_html/`. Keep the generated config and state there too; do not grant world-write permissions.
3. Find the account's CLI PHP binary with `command -v php` and check `php -v`. A hosting panel's website PHP setting may differ from its CLI setting. The minimum supported version is PHP 7.4; use a maintained version supplied by the host.
4. Initialise with absolute paths. Replace `/usr/local/bin/php` below with the actual CLI executable:

```sh
/usr/local/bin/php /home/client/sentinel/sentinel.php init \
  --root=/home/client/public_html \
  --name="Client website" \
  --email=owner@example.com
```

Initialisation scans before creating the baseline. Investigate any refusal instead of adding `--force` automatically. It is a rule-based scan, not proof that the site is malware-free. On a large site, initialise at a quiet time: the initial scan has no cooperative time budget.

If there is no SSH/terminal, ask the host to execute this command, or temporarily schedule it once in the hosting cron panel with output captured in a private file outside the public directory. Remove that temporary job after it succeeds. Opening the script in a browser does not run it.

## Check the setup and notifications

```sh
/usr/local/bin/php /home/client/sentinel/sentinel.php doctor
/usr/local/bin/php /home/client/sentinel/sentinel.php test-alert
```

`doctor` shows private placement, readable baseline, writable state, alert configuration, HTTP transport availability, exclusions and scan history. It does not contact WordPress.org or send alerts, and cannot determine whether the host's cron is actually installed. Missing scan history is expected before the first scans.

Email uses native PHP `mail()`. WordPress SMTP plugins do not affect it. Set an appropriate `from` address in the generated `sentinel.json`, verify the message arrives, and add another external channel for critical findings. Telegram credentials and webhook URLs stay in the private config; doctor does not display them.

Configure `heartbeat_url` with an external monitoring service that alerts when pings stop. Match the external service's interval and grace to your cron schedule. A ping means the process ran successfully enough to finish a slice, not that an entire tree was checked or the site was clean.

After your deliberate config edits:

```sh
/usr/local/bin/php /home/client/sentinel/sentinel.php accept --self
/usr/local/bin/php /home/client/sentinel/sentinel.php check
/usr/local/bin/php /home/client/sentinel/sentinel.php full
/usr/local/bin/php /home/client/sentinel/sentinel.php cron
```

Review the manual scan output. Copy the printed cron entries into the account's crontab or hosting cron panel. The generated commands use the actual PHP binary, quote paths and escape cron's special `%` character. They discard normal output but preserve stderr for cron error reporting; configure cron email delivery or redirect stderr into a private log with rotation. Do not use `2>&1` with `/dev/null` while commissioning the monitor.

The printed schedule is every ten minutes for `check` and 03:17 nightly for `full`, in the server's timezone. In panels with separate schedule fields, enter the timing there and only the command in the command field.

## Routine operation

- `check` is the inexpensive, metadata-based pass. It analyses new/changed files; a same-size, same-mtime code edit needs `full` to detect it.
- `full` rehashes every code file to catch edits that kept the same size and timestamp. It is more expensive. Files whose content is unchanged since they were baselined or accepted are not scanned again, so new rules do not yet reach them. The budget only covers comparison; analysis/network work can take additional time. Check the host's resource limits during a pilot.
- A partial scan resumes when the same command runs again. If `full` is partial and scheduled only nightly, the next slice will be the following night. Run `full` again manually or adjust its schedule to complete coverage in an acceptable time. A ten-minute `check` does not resume `full`.
- `doctor` distinguishes each mode's last processed run from its last complete traversal. Complete traversal does not imply zero findings or successful verification of every file. Older installations have no history until they run the upgraded monitor.
- Rule updates are optional and require your own configured rules URL/key; no maintained external feed is configured by default. New rules apply to files as they are added or changed; they do not rescan files already in the baseline.
- Verified WordPress.org updates are recognised automatically. Premium/custom update recognition uses a version change plus no scanner findings; it is not an authenticity guarantee. Keep an eye on those updates.

After reviewing your own development changes, accept the smallest relevant path, for example:

```sh
/usr/local/bin/php /home/client/sentinel/sentinel.php accept \
  --path=wp-content/themes/client-child
```

`accept` does not perform a malware review for you. Do not use a whole-site accept as a routine way to clear unexplained alerts: once accepted, a file is trusted until its content changes.

Use a separate config and state directory for every site, passed with `--config=/absolute/path/client.json`. Ensure each corresponding `init` also uses its own `--state` directory. For symlinked uploads, give the target a separate config; Sentinel never follows symlinks. Review sites with relocated `wp-config.php` or a nonstandard content-directory layout before relying on WordPress-specific checks.

This remains a file monitor: it does not inspect posts, users, options or other database content, block requests, repair files or replace backups.
