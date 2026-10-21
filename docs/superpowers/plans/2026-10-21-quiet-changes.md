# Quiet Changes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A site (owner, via `settings.txt`) or a folder (developer, via `sentinel.json`) can choose to have changes that nothing flags recorded quietly instead of emailed; anything that looks like hacking, sensitive files and WordPress core still alert.

**Architecture:** `Settings`/`Config` gain the switch and the folder list plus `Config::isQuiet()` and `Config::isCorePath()`. At the Analyzer's group step, files that would become `unexplained-change` / `unverified-update` and are quiet-eligible are accepted with a new status instead. Monitor keeps a bounded log of quiet acceptances, writes a server report when it accepted something quietly without emailing, and lists recent quiet acceptances in the next alert's report. Owner-facing surfaces (settings template, welcome, settings-change notice, doctor, docs) state the setting.

**Tech Stack:** PHP 7.4+, no dependencies; tests via `php tests/run.php`.

**Spec:** `docs/superpowers/specs/2026-10-21-quiet-changes-design.md`

## Global Constraints

- PHP 7.4 compatible (`php build/compat.php`), no Composer dependencies; new files go in `build/files.php`.
- Default unchanged: no `changed_files` line and no `quiet_folders` = today's behaviour ("tell me").
- `settings.txt` key `changed_files`, values (case-insensitive) `tell me` | `quiet`; also `yes` (= tell me) | `no` (= quiet). Anything else is a settings error (existing settings-problem flow).
- `sentinel.json` key `quiet_folders`: list of patterns with the same syntax as `exclude` (`PathFilter`).
- New report status (exact): `accepted: quiet (no email)`.
- Never quiet: any detection hit or ClamAV hit; a check that could not run (`Digest::MONITORING`); a plugin/theme with an unresolved or same-run detection (Analyzer's `$unresolvedGroups`); location rules (PHP in uploads etc.); sensitive files; symlinks; world-writable; WordPress core paths (also when checksums could not be downloaded); Sentinel's own files; setup (first run).
- Changing `changed_files` is announced by the existing settings-changed email; `quiet_folders` is protected by the existing `sentinel.json` tamper check.
- Public repository: no real client names. No literal malware-family names in shipped files. Client emails never show commands; the footer stays the last owner line before `--`.

## Review Focus

- Quiet site, WordPress checksums could not be downloaded, a core file changes: must alert, not be quiet. → Task 2.
- Quiet site, a plugin update where one file has a pattern hit: the hit alerts and the rest of that plugin's changes are NOT quiet (same-run detection makes the group suspect). → Task 2.
- A busy quiet folder (a developer deploying hundreds of files several times a day): the quiet log stays bounded and the next alert's report says how many earlier entries were dropped. → Task 3.
- An invalid `changed_files` value: settings problem email, last good settings kept (existing flow), nothing becomes quiet. → Task 1.
- The baseline save fails in a run with quiet acceptances: those files show `pending: not saved …` (existing mapping of `accepted: *`), and are not logged as quietly accepted. → Task 3.

---

### Task 1: The switch and the folder list

**Files:**
- Modify: `src/Settings.php` (parse, `toArray`, `fromArray`), `src/Config.php` (overlay from settings, `quiet_folders`, `isQuiet`, `isCorePath`, `toArray`)
- Test: `tests/test_package.php` (Settings), `tests/test_config.php`

**Interfaces:**
- Produces:
  - `Settings::$quietChanges` (`?bool`, null when the line is absent); `toArray()['changed_files']` = `'quiet'` | `'tell me'` | `null`; `fromArray` reads it back.
  - `Config::$quietChanges` (`bool`, default false; set from settings, or raw `quiet_changes` bool in sentinel.json for developer installs) and `Config::$quietFolders` (`string[]`, from `quiet_folders`; written back by `toArray()` only when configured).
  - `Config::isQuiet(string $rel): bool` — `$quietChanges` or `$rel` matches `quiet_folders`.
  - `Config::isCorePath(string $rel): bool` — true for WordPress core locations of any install in `wordpressInstalls()`: `<prefix>wp-admin/…`, `<prefix>wp-includes/…`, and root-level core files of that install (`index.php`, `xmlrpc.php`, `wp-*.php` directly in the install folder, excluding `wp-config.php` which is already sensitive).

- [ ] **Step 1: Write the failing tests:** `Settings: changed_files accepts tell me / quiet / yes / no and rejects anything else` (`tell me`→false, `Quiet`→true, `yes`→false, `no`→true, `maybe`→error containing `changed_files must be "tell me" or "quiet"`; round-trip through `toArray`/`fromArray`); `Config: quiet from settings or quiet_folders; core paths recognised` (settings quiet → `isQuiet('anything.php')`; `quiet_folders: ["app/"]` → `isQuiet('app/x.php')` true, `isQuiet('wp-content/plugins/p/p.php')` false; `isCorePath` true for `wp-includes/load.php`, `wp-login.php`, `shop/wp-admin/x.php` (nested install `shop`), false for `wp-content/plugins/x.php` and `wp-config.php`).
- [ ] **Step 2: Run** `php tests/run.php changed_files` and `php tests/run.php "core paths"` → FAIL.
- [ ] **Step 3: Implement** in `Settings` and `Config`.
- [ ] **Step 4: Run** `php tests/run.php` → all pass; `php build/compat.php` → OK.
- [ ] **Step 5: Commit** `git commit -am "Settings and config: changed_files (tell me | quiet) and quiet_folders"`

### Task 2: Quiet acceptance in the Analyzer

**Files:**
- Modify: `src/Analyzer.php` (group step where `unexplained-change` / `unverified-update` are built), `src/Report.php` (`STATUSES`, new constant)
- Test: `tests/test_analyzer.php`, `tests/test_monitor.php`

**Interfaces:**
- Consumes: `Config::isQuiet`, `Config::isCorePath` (Task 1).
- Produces:
  - `Report::QUIET = 'accepted: quiet (no email)'`, appended to `Report::STATUSES` (append only: existing indices are used by Analyzer).
  - In the group loop: a changed file is quiet-eligible when `isQuiet($rel) && !isCorePath($rel)` and its group is not in `$unresolvedGroups`. Eligible files get outcome `Report::QUIET`, no finding, no hold; the remaining files of the group are judged exactly as today (finding + hold). If every changed file of a bumped group is quiet-eligible, the version is recorded (no `version_holds`), and an `info` line `<group> accepted quietly (<N> file(s))` is added.
  - `analyze()` return gains `'quiet' => string[]` (paths accepted quietly this run).

- [ ] **Step 1: Write the failing tests** (Analyzer/Monitor fixtures with `profile wordpress`, `update_grace_seconds 0`):
  - `Quiet: an unexplained change and an unverified update are accepted quietly, recorded, and no finding is raised` (quiet site; theme file edited; premium plugin bumped → no findings, outcomes `accepted: quiet (no email)`, baseline updated, version recorded).
  - `Quiet: never for a detection, a same-run detection in the plugin, an unresolved detection, PHP in uploads, a sensitive file, or core` — one case each, all still produce their usual finding; core case with WordPress checksums unavailable (FakeHttp with no checksum route) changing `wp-includes/load.php`.
  - `Quiet folders: only files in quiet_folders are quiet; a group split across both is partly reported` (quiet_folders `["app/"]`, change `app/x.php` and `wp-content/themes/t/f.php` → app quiet, theme `unexplained-change`).
  - `Quiet: a failed scan check keeps the file held, not quiet` (PCRE trick as in tests/test_scanners.php → `held: judged next run`).
- [ ] **Step 2: Run** `php tests/run.php Quiet` → FAIL.
- [ ] **Step 3: Implement** in `Analyzer::analyze()` and `Report`.
- [ ] **Step 4: Run** `php tests/run.php` → all pass.
- [ ] **Step 5: Commit** `git commit -am "Analyzer: changes nothing flags are accepted quietly where the site or folder asks for it"`

### Task 3: Quiet log, server report, and the next alert's report

**Files:**
- Modify: `src/Monitor.php`, `src/Report.php`
- Test: `tests/test_monitor.php`, `tests/test_package.php`, `tests/test_report.php`

**Interfaces:**
- Consumes: `$a['quiet']`, `$a['outcomes']` (Task 2); `Report::write`, `Report::attachment` (existing).
- Produces:
  - State file `quiet-log.json`: list of `{path, group, ts}`; appended with this run's `$a['quiet']` only after the baseline save succeeded; capped at the newest **2000** entries, with a `dropped` counter for older ones; cleared after an alert email is delivered (`Alerter` result ok), which is when its entries have been shown.
  - When a run accepted something quietly and no email is due: `Report::write` is still called (server copy only, no email), so `state/reports/` records it.
  - `Report::write(..., array $notes, array $quietSince = [])`: new optional last parameter `['entries' => [{path, group, ts}], 'dropped' => int]`; when non-empty the report gets a section `ACCEPTED QUIETLY SINCE THE LAST EMAIL (<N>)`, grouped by group, each line with path and UTC time, ending with `(<dropped> earlier not listed)` when `dropped > 0`. Monitor passes the log when an email is due.

- [ ] **Step 1: Write the failing tests:**
  - `run: a quiet change writes a server report and sends no email` (packaged, `changed_files = quiet`, theme file changed → no mail; one report in `state/reports` listing it with `accepted: quiet (no email)`).
  - `run: the next alert's report lists what was accepted quietly since the last email, then the list starts again` (quiet change, then PHP dropped in uploads → alert; attachment has the section with the quiet file; after that alert, another quiet change and another alert → section lists only the newer one).
  - `Quiet log is capped at 2000 and counts what it dropped` (unit test on the log helper with 2,050 entries → 2,000 kept, `dropped` 50, report says `(50 earlier not listed)`).
  - `Quiet: a failed baseline save logs nothing as quiet and shows pending` (force the save to fail as in tests/test_storage_failures.php → outcome `pending: not saved …`, quiet log unchanged).
- [ ] **Step 2: Run** `php tests/run.php quiet` → FAIL.
- [ ] **Step 3: Implement** in `Monitor` (log helper as a small private method or class — builder's choice — in an existing file unless it grows past a screen) and `Report`.
- [ ] **Step 4: Run** `php tests/run.php` → all pass.
- [ ] **Step 5: Commit** `git commit -am "Quiet changes leave a trace: server report, and a list in the next alert's report"`

### Task 4: Owner and developer surfaces

**Files:**
- Modify: `package/settings.txt` (new item 5), `src/Run.php` (welcome line; settings-changed label), `src/Doctor.php`, `README.md`, `package/INSTALL-XNEELO.txt`
- Test: `tests/test_package.php`, `tests/test_cli.php` (doctor)

**Interfaces:**
- Consumes: `Config::$quietChanges`, `Config::$quietFolders` (Task 1); `quiet-log.json` (Task 3).
- Produces:
  - `package/settings.txt` item 5 (exact text, keep the existing numbering style):
    ```
    # 5. Changes to the website's files that do not look like hacking: tell me or quiet
    #    tell me: every change that cannot be verified sends an email (safest).
    #    quiet:   such changes are recorded without an email; anything that looks like hacking,
    #             and changes to sensitive files, still send an email straight away.
    changed_files = tell me
    ```
  - Welcome email line (with the other "What was set up" lines): `  Changed files: you are told about every change that cannot be verified` or `  Changed files: recorded quietly unless they look like hacking`; plus, when `quiet_folders` is set, `  Recorded quietly in: <patterns>`.
  - Settings-changed notice label: `'changed_files' => 'Changed files'`, showing `tell me` / `quiet`.
  - doctor lines: `Changed files: tell me` or `Changed files: quiet (changes that nothing flags are recorded without an email)`; `Quiet folders: <patterns>` when set; `Last accepted quietly: <UTC time>` from the quiet log when present.
  - README: the `changed_files` and `quiet_folders` settings in the config tables, with the trade-off in one sentence each; INSTALL-XNEELO: one owner-facing line in GOOD TO KNOW.

- [ ] **Step 1: Write the failing tests:** `run: the welcome and the settings notice state the changed-files setting` (welcome contains each line for tell me / quiet / quiet folders; changing `changed_files` to quiet sends the settings-changed email with `Changed files: quiet (was: tell me)`); `doctor shows the changed-files setting, quiet folders and the last quiet acceptance`; `the shipped settings.txt has item 5 and parses as tell me`.
- [ ] **Step 2: Run** `php tests/run.php "changed-files"` → FAIL.
- [ ] **Step 3: Implement** the surfaces and docs.
- [ ] **Step 4: Run** `php tests/run.php` → all pass; `php build/compat.php` OK; `php build/build.php` and `php build/package.php "$(mktemp -d)/p.zip"` succeed.
- [ ] **Step 5: Commit** `git commit -am "Changed-files setting: settings.txt, welcome, settings notice, doctor, docs"`
