# Quiet changes: only alert about changes that look like hacking

Date: 2026-10-21. Status: proposal for approval.

## Why

Sentinel alerts about every code change it cannot explain (no official checksum, no version change it may approve). That is right when nobody touches the site, but noisy when someone does: a developer deploying custom code, or a client editing their own theme or adding their own plugin. Each change becomes a "Website files changed" email, and every deploy repeats it. People stop reading alerts that are usually their own work.

Per-deploy signing was ruled out: clients change their own sites, so no signing step can cover every change. Instead, a site can choose to be told only about changes that look like hacking. Signature scanning cannot catch everything; the bigger malware database (next project) narrows that gap. This is an explicit, documented trade-off that the site owner or developer turns on.

## The behaviour

A new setting decides what happens to a change that **nothing flags**:

- **Notify (default, today's behaviour):** an unexplained code change or unverified update is reported (`unexplained-change`, `unverified-update`) and kept out of the baseline until accepted.
- **Quiet:** the same change is accepted into the baseline and recorded, with no email, **provided every check on it is clean** (see "Never quiet").

### Never quiet

Whatever the setting, these still alert exactly as today:
- anything a detection rule or ClamAV flags (`Digest::MONITORING` failures included — a check that could not run is never treated as clean: the file stays held and retried);
- a file with an unresolved earlier detection (`detection-unresolved`), and changes in its plugin or theme (the laundering protection);
- PHP in uploads, PHP hidden in images and other location rules;
- sensitive files (`.htaccess`, `wp-config.php`, `.user.ini`, mu-plugins …), symlinks, files becoming world-writable;
- WordPress core: checksum mismatches, unexpected files in core folders, removed core files;
- Sentinel's own files (self-tamper), settings changes, monitoring problems.

So "quiet" only ever covers ordinary code changes outside WordPress core that no rule or scanner objects to.

### Where it is set

1. **Per site, by the owner:** a line in `settings.txt`:
   ```
   # 5. Changes to the website's files that do not look like hacking: tell me or quiet
   #    tell me: every change that cannot be verified sends an email (safest).
   #    quiet:   such changes are recorded without an email; anything that looks like hacking,
   #             and changes to sensitive files, still send an email straight away.
   changed_files = tell me
   ```
   Accepts `tell me` / `quiet` (also `yes`/`no` for the old style; my call on exact words, open to change).
2. **Per folder, by the developer:** `sentinel.json` gets `quiet_folders` (patterns like `exclude`, e.g. `["custom-app/"]`). Those folders are quiet whatever `settings.txt` says; the rest of the site follows the site setting. This covers "my own app on a client's account" without silencing the client's WordPress sites.

### What a quiet change leaves behind

- It is accepted into the baseline (so it is not re-reported) and its plugin/theme version is recorded as if approved.
- A report is still written to `state/reports/` for every run that accepted something quietly (same format as alert reports, status `accepted: quiet (no email)`), so a developer can see afterwards what changed and when. No email.
- The next alert email's report lists recent quiet acceptances (since the last email), so whoever investigates a real alert sees what was quietly accepted before it.
- `doctor` shows the setting, the quiet folders, and when something was last accepted quietly.

## Safety rules

- Changing `changed_files` is announced like every settings change (both old and new recipients are told), so someone redirecting the site to quiet cannot do it silently.
- `quiet_folders` lives in `sentinel.json`, which is tamper-checked: editing it raises the existing self-tamper alert.
- The welcome email states the setting in plain words (`Changed files: you are told about every change` / `recorded quietly unless they look like hacking`).
- Quiet never applies to the first run (setup) or to files flagged at setup.

## Non-goals

- A weekly or daily summary email of quiet changes (could come later if owners ask).
- Changing what counts as "looks like hacking" (that is the malware-database project).
- A config UI (later project).

## Anti-goals

- A quiet setting that silences a detection, a check that could not run, a sensitive-file change or a core change.
- Quiet changes that leave no trace at all.
- A change of the setting that nobody is told about.

## Constraints

- PHP 7.4, no dependencies; default behaviour unchanged for existing installs (no setting = tell me).
- Public repository: no real client names.
- Works with the existing update policy (`approve_plugin_updates_automatically`): quiet covers unverified updates too, but the laundering and repository-plugin protections still apply (a repository plugin whose files fail its official checksums is a mismatch, not a quiet change).

## Left to the builder

- Exact wording of the settings line, welcome line and doctor lines, within the tone above.
- How Analyzer marks a change as quiet-eligible (the decision belongs where `unexplained-change` / `unverified-update` are built today).
- How the "recent quiet acceptances" list is kept for the next alert's report.
