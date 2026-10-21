# Client Emails Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Client emails name the contact once, in a footer, and every alert carries a full plain-text report of all findings and changed files, also kept on the server.

**Architecture:** A new `Report` class streams the report to `state/reports/` and returns a capped attachment. `Analyzer::analyze()` additionally returns a per-file outcome so the report can say what happened to each changed file. Notifiers accept an optional attachment: email sends `multipart/mixed`, other channels add a pointer line. `Monitor` and `Run` build the report when they send, and never let a report failure stop an alert.

**Tech Stack:** PHP 7.4+, no dependencies, `mail()`; tests via `php tests/run.php`.

**Spec:** `docs/superpowers/specs/2026-10-21-client-emails-design.md`

**Base:** written against the detection-laundering PR #10 head (`82dcee8`). Before Task 1, rebase this branch onto `master` once #10 has merged, and re-read `Digest::forClient`, `Analyzer::analyze` and `Monitor::execute` if #10 changed in review.

## Global Constraints

- PHP 7.4 compatible (`php build/compat.php`), no Composer dependencies; new files are added to `build/files.php`.
- `mail()` may be the only channel; an alert must go out even when the report cannot be built, written or attached.
- Client emails never show a command (existing test `client emails never show commands` must keep passing).
- No literal malware-family names in shipped files (existing test).
- Public repository: no real client site names, folders or plugins in code, tests, fixtures or docs.
- Attachment cap: **2 MB**. Server copies kept: **newest 30 and at most 50 MB in total** in `state/reports/`; the newest is never deleted.
- Report and pointer lines: relative paths and metadata only. No file contents, credentials, or absolute paths (they contain the hosting account name); the report's own location is given as `sentinel/state/reports/<name>`.
- The owner's next action is always in the email body; the footer only says who to ask and never implies the contact receives or monitors alerts.
- Report file name: `sentinel-report-<site-slug>-<YYYYMMDD-HHMM>.txt` (UTC; slug = lowercase `a-z0-9`, other runs collapsed to `-`, trimmed, max 40 chars, `site` if empty).
- Footer line (exact copy): `Questions about this email? Contact <contact>.` Omitted when `contact` is empty; the body then says `your web developer`.

## Review Focus

- A run with tens of thousands of changed files: memory stays bounded (report streamed to disk), attachment capped at 2 MB with a final `[report cut at 2 MB; the full report is on the server: <path>]` line, email still sent. → Task 1, Task 4.
- `state/reports/` cannot be written (full disk, permissions): the email goes out without an attachment and its body says `The full report could not be saved: <reason>`. → Task 4.
- `mail()` refuses the message with the attachment: the email is retried once without it, with the same body note. → Task 3.
- A site name with spaces, accents, slashes or only symbols produces a safe file name. → Task 1.
- No `contact` set: no footer, and no sentence reads "contact ." or similar. → Task 5.

---

### Task 1: Report builder

**Files:**
- Create: `src/Report.php`
- Modify: `build/files.php` (add `Report.php` after `Digest.php`)
- Test: `tests/test_report.php`

**Interfaces:**
- Produces:
  - `Report::fileName(string $site, int $ts): string`
  - `Report::write(string $dir, array $meta, array $findings, array $dueKeys, array $changes, array $outcomes, array $notes): string` — streams the report to `$dir/<fileName>`, prunes `$dir` to the newest 30 reports, returns the file path; throws `\RuntimeException` if the file cannot be written.
    - `$meta`: `['site' => string, 'root' => string, 'ts' => int, 'version' => string, 'mode' => string, 'complete' => bool]`
    - `$findings`: `Finding[]` (every finding of the run); `$dueKeys`: `Finding::key()` values of those in this email
    - `$changes`: `Differ::diff()['changes']` entries (`type`, `path`, `old`, `new` records with `size`, `mtime`, `hash`, `content_same`)
    - `$outcomes`: `array<string,string>` path => status (Task 2)
  - `Report::CAP = 2097152`; `Report::attachment(string $file, int $cap = self::CAP): array{name:string, path:string, content:string}` — content cut at `$cap` bytes with the cut line from Review Focus.
  - `Report::STATUSES` — the status strings: `reported`, `accepted: official copy`, `accepted: approved update`, `accepted: not code`, `accepted: permissions only`, `accepted: removed`, `held: judged next run` (review follow-up: `pending: not saved (the record of website files could not be updated)`, used instead of any `accepted: *` when the run's save failed).

- [ ] **Step 1: Write the failing tests** in `tests/test_report.php`:
  - `Report lists every finding and every changed file, grouped, with nothing truncated`: 30 modified files in one theme plus 2 findings → report contains all 30 paths, both findings with rule, path, message, `[id …]` for dismissable ones and hash, `in this email` for due keys and `reported earlier` for the rest, group headings from `Analyzer::groupOf`, and no `more)`.
  - `Report shows each file's change type, size, time, code-file SHA-256 and status` (one `new`, `modified`, `removed`, permissions-only change; statuses from `$outcomes`; a path missing from `$outcomes` shows `reported` if it has a finding, else `accepted: not code`).
  - `Report file names are safe for any site name`: `'My Shop'` → `sentinel-report-my-shop-20261021-1430.txt`; `'Café / Bar'` → `…-caf-bar-…`; `'***'` → `…-site-…`; a 60-char name → slug of 40 chars.
  - `Report labels a partial scan and its scope`: `complete => false` → header and changed-files heading say `part of a scan: changes found in this part only; the scan resumes on the next run`; `complete => true` → `complete scan` (review follow-up: complete after resuming → `final part of a scan: the scan is now complete; this report covers this part only`).
  - `Report holds no absolute paths or contents`: with `root` = `/home/acct/public_html` and a note containing that root, the report contains neither `/home/acct` nor any file content, and the note shows the path relative to the website folder.
  - `Report keeps the newest 30 and cuts the attachment at the cap`: write 32 reports → 30 remain, the two oldest gone; with reports totalling over 50 MB the oldest are pruned until under it, never the newest; `attachment($file, 100)` content is ≤ 100 bytes plus the cut line naming `$file`; under the cap the content equals the file.
- [ ] **Step 2: Run** `php tests/run.php Report` → FAIL (`Class "Sentinel\Report" not found`).
- [ ] **Step 3: Implement `Report`** in `src/Report.php`; write line by line with `fopen`/`fwrite` (no full string in memory); header lines in the spec's order (site, website folder, time UTC, Sentinel version, scan mode, complete or partial).
- [ ] **Step 4: Run** `php tests/run.php Report` → PASS; `php build/compat.php` → `OK`.
- [ ] **Step 5: Commit** `git add src/Report.php build/files.php tests/test_report.php && git commit -m "Report: full plain-text record of findings and changed files"`

### Task 2: Per-file outcomes from the Analyzer

**Files:**
- Modify: `src/Analyzer.php` (`analyze()`: every `continue`/hold branch records an outcome; the `unexplained-change` / `unverified-update` messages drop the five-name sample)
- Test: `tests/test_analyzer.php`, adjust message assertions in existing tests that expect `(+N more)` or the sample

**Interfaces:**
- Consumes: `Report::STATUSES` (Task 1)
- Produces: `analyze()` return gains `'outcomes' => array<string,string>` (path => one of `Report::STATUSES`) for every path in `$changes`. Messages become `<N> file(s) changed without a version change (each one is listed in the report)` and `Version <a> -> <b>, but <N> changed file(s) could not be verified against an official source (each one is listed in the report)`, plus the existing `#10` suffix about unreviewed detections.

- [ ] **Step 1: Write the failing test** `Analyzer reports an outcome for every changed file`: one change of each kind (official checksum verified; non-code file; permissions-only; removed non-sensitive; fresh file in grace; pattern hit; approved update under auto-approve; unexplained change) → `outcomes` has exactly one entry per path with the matching status; and `assertNotContains('more)', …)` on every message.
- [ ] **Step 2: Run** `php tests/run.php "outcome for every changed file"` → FAIL (undefined index `outcomes`).
- [ ] **Step 3: Implement** in `Analyzer::analyze()`; the `$initial` (setup) return gets `'outcomes' => []`.
- [ ] **Step 4: Run** `php tests/run.php` → all pass (update the existing assertions that quoted the old sample messages).
- [ ] **Step 5: Commit** `git commit -am "Analyzer: an outcome for every changed file; lists move to the report"`

### Task 3: Attachments through the notifiers

**Files:**
- Modify: `src/Notifier.php` (interface), `src/Notifiers.php` (all notifiers), `src/Alerter.php`
- Modify: `tests/helpers_notify.php` (`FakeNotifier`), `tests/test_package.php` (`MailBox` also records `headers`)
- Test: `tests/test_notify.php`

**Interfaces:**
- Consumes: the attachment array from `Report::attachment()` (Task 1)
- Produces:
  - `Notifier::send(string $subject, string $body, int $severity, ?array $attachment = null): void`
  - `Alerter::send(string $subject, string $body, int $topSeverity, ?array $attachment = null): array` (unchanged return)
  - `EmailNotifier`: with an attachment, `multipart/mixed` with a random boundary; part 1 `text/plain; charset=UTF-8`, `Content-Transfer-Encoding: 8bit` (so body text stays readable in the raw message and existing `assertContains` checks keep working); part 2 `text/plain; charset=UTF-8; name="<name>"`, `Content-Disposition: attachment; filename="<name>"`, base64 in 76-char lines. If `mail()` returns false with an attachment, retry once without it and append `The full report could not be attached; it is saved on the server: <path>` to the body.
  - Other notifiers append one line: `Full report saved on the server: sentinel/state/reports/<name>` (the attachment array carries this relative `path`; never an absolute path).

- [ ] **Step 1: Write the failing tests:** `EmailNotifier attaches the report as a well-formed multipart message` (parse headers + body: boundary declared and used, two parts, attachment decodes to the content, filename present); `EmailNotifier retries without the attachment when mail() refuses it` (mailer fails when headers contain `multipart`, succeeds otherwise → delivered once, body has the note); `other channels get a pointer to the server copy` (ntfy/webhook/file body ends with the pointer line); without an attachment every notifier sends exactly what it sends today.
- [ ] **Step 2: Run** `php tests/run.php Notifier` → FAIL.
- [ ] **Step 3: Implement** the interface change in every notifier (and `FakeNotifier`, which also stores `attachment`), MIME building in `EmailNotifier`, pass-through in `Alerter`.
- [ ] **Step 4: Run** `php tests/run.php` → all pass; `php build/compat.php` → `OK`.
- [ ] **Step 5: Commit** `git commit -am "Notifiers: optional report attachment; email as multipart, others point to the server copy"`

### Task 4: Monitor builds, keeps and attaches the report

**Files:**
- Modify: `src/Monitor.php` (where `Digest::forConfig` and `Alerter::send` are called)
- Test: `tests/test_package.php` (packaged, end to end), `tests/test_monitor.php`

**Interfaces:**
- Consumes: `Report::write`, `Report::attachment` (Task 1), `$a['outcomes']` (Task 2), `Alerter::send(..., $attachment)` (Task 3)
- Produces: when `$due` is non-empty, for both audiences (`forClient` and `build` digests alike), a report in `$state->path('reports')` covering all `$findings`, the due keys, `$d['changes']`, `$a['outcomes']` and `$a['notes']`; attached to the alert. On `\Throwable` from `Report::write`: no attachment, and the digest body gets `The full report could not be saved: <reason>` before the footer/technical section.

- [ ] **Step 1: Write the failing tests:**
  - `run: an alert about 30 changed files attaches a report that lists all 30, and keeps it on the server` (packaged site, 30 theme files changed → one mail with an attachment containing every path; `state/reports/` holds the same file).
  - `run: the alert still goes out when the report cannot be saved` (make `state/reports` a file, not a folder → mail sent, no attachment, body has the note).
  - `run: a large change list is listed in full and the attachment uses Report::CAP` (3,000 changed files → attachment and server copy both list all 3,000; the cap itself is unit-tested in Task 1).
- [ ] **Step 2: Run** `php tests/run.php "report"` → FAIL.
- [ ] **Step 3: Implement** in `Monitor::execute()`; reports are only written when an email is due.
- [ ] **Step 4: Run** `php tests/run.php` → all pass.
- [ ] **Step 5: Commit** `git commit -am "Monitor: every alert carries the full report, also kept on the server"`

### Task 5: Contact in the footer, once

**Files:**
- Modify: `src/Digest.php` (`forClient`, plus a `footer()` helper), `src/Run.php` (welcome, setup-placement, settings-changed, settings-problem, records-missing emails; `who()`)
- Test: `tests/test_package.php`, `tests/test_notify.php`

**Interfaces:**
- Produces: `Digest::footer(string $contact): string` returning the exact footer copy or `''`. Body sentences refer to "the contact below" when a contact is set, else "your web developer". The footer sits after the owner-facing body and before `--` / the developer section.
- Rule kept: `settingsChanged` and `recordsMissing` pass the previous, trusted contact (`$old['contact']`) to the footer; the change list line `Contact named in alerts: … (was: …)` stays.

- [ ] **Step 1: Write the failing tests:** every client alert body still states the owner's next action (e.g. `forward this email`) without relying on the attachment; `client emails name the contact once, in the footer` — for each client email (alerts of every group, welcome, setup with flagged files, setup placement, settings problem, records missing) with `contact = Bro Media (info@bromedia.co.za)`: `substr_count($body, 'Bro Media') === 1` and the footer line is present; for the settings-changed email the count excludes the change-list line and the footer names the old contact after a contact change; with an empty contact no footer and `your web developer` appears; existing `never show commands` still passes.
- [ ] **Step 2: Run** `php tests/run.php "contact once"` → FAIL.
- [ ] **Step 3: Implement** the wording changes; keep tone (plain, calm, no commands); the welcome's "If you ever receive an alert, contact …" becomes "If you ever receive an alert, forward it to the contact below."
- [ ] **Step 4: Run** `php tests/run.php` → all pass.
- [ ] **Step 5: Commit** `git commit -am "Client emails: the contact once, in a footer"`

### Task 6: Setup email with flagged files carries the report

**Files:**
- Modify: `src/Run.php` (`firstRun` with flagged files; `sendWelcome` keeps the attachment path in `welcome-pending.json` and re-reads the server copy on retry)
- Modify: `README.md`, `package/INSTALL-XNEELO.txt` (one line each: alerts include an attached full report; copies are in `sentinel/state/reports/`)
- Test: `tests/test_package.php`

**Interfaces:**
- Consumes: `Report::write` with `$changes = []`, `$outcomes = []`, the flagged findings as `$findings` and `$dueKeys`; `Report::attachment`; `Alerter::send(..., $attachment)`.
- Produces: `welcome-pending.json` gains `report` (server path); a missing file on retry sends without attachment plus the "could not be attached" note.

- [ ] **Step 1: Write the failing test** `run: setup with a flagged file sends the report with the welcome, also on a retry` (flagged file → mail has attachment listing the finding; make the mailer fail once, then succeed → the retried mail has the same attachment; delete the server copy before another retry → note instead of attachment).
- [ ] **Step 2: Run** `php tests/run.php "sends the report with the welcome"` → FAIL.
- [ ] **Step 3: Implement** in `Run::firstRun` and `Run::sendWelcome`; update the two docs.
- [ ] **Step 4: Run** `php tests/run.php` → all pass; `php build/compat.php` → OK; `php build/build.php` and `php build/package.php "$(mktemp -d)/p.zip"` succeed.
- [ ] **Step 5: Commit** `git commit -am "Setup email with flagged files carries the report; docs"`
