# Client emails: contact in the footer, and a full report

Date: 2026-10-21. Status: draft for approval. Builds on master after the detection-laundering PR (#10) is merged, because both change `Analyzer`, `Monitor`, `Run` and `Digest`; the implementation plan is written against master once #10 has merged.

## Why

Packaged installs email the site owner, at the addresses the owner puts in `settings.txt`. The developer who installed Sentinel does not receive these emails. Owners are not technical; they read the email, decide whether to worry, and pass it to whoever looks after their website.

Two things get in the way today:

1. **The contact is everywhere.** The `contact` setting (for example `Bro Media (info@bromedia.co.za)`) is woven into the body up to three times in one alert ("If you or <contact> just installed updates...", "contact <contact> today", and the welcome's "If you ever receive an alert, contact <contact>"). It reads like the developer's advert, not the owner's security notice.
2. **The details stop short.** A change is summarised as five file names and "(+25 more)" (`Analyzer`, `unexplained-change` / `unverified-update`). Nobody can investigate "25 more". The owner or their developer needs every changed file to check what happened.

## Goals

- The contact appears once per email, as a footer line, e.g. `Questions about this email? Contact Bro Media (info@bromedia.co.za).` The body refers to it neutrally ("forward this email to the contact below", "whoever looks after your website").
- Every alert email carries a full report: every finding and every changed file, nothing truncated, attached as a plain-text file.
- The email body stays short: what happened, how worried to be, what to do, and a pointer to the attached report.
- The same report is kept on the server, so a developer can still get it if the attachment is stripped or lost.

## Non-goals

- HTML emails, logos or styling.
- Changing what triggers an alert, its severity, or dedupe and reminder timing. (The per-site setting for quiet clean changes is a separate project.)
- A config UI (later project).
- Reports for non-email channels beyond a pointer line (see below).

## Anti-goals (a failure even if it works)

- An owner email that shows a command to run. Commands stay in the developer section or the report.
- An alert that gets lost because of the attachment: if building or attaching the report fails, the email still goes out without it, and says so.
- Emails that land in spam more often because of the attachment.
- Literal malware-family names in shipped files (existing invariant; the report quotes rule IDs and messages, which already respect it).

## What changes

### Email body (owner-facing)

- Remove the contact from body sentences in all client emails: alerts (`Digest::forClient`), the welcome and setup emails (`Run`), settings notices, records-missing and settings-problem emails.
- Which contact the footer names follows the existing rule (decided): the "settings changed" and "records missing" emails name the **previous, trusted** contact, so someone who edits `settings.txt` to redirect alerts cannot also change who the owner is told to call. The settings notice's own change list (`Contact named in alerts: <new> (was: <old>)`) is data, not a contact sentence, and is exempt from the "contact appears once" test.
- Add one footer line, after the body and before the developer section, built from `contact`: `Questions about this email? Contact <contact>.` With no contact set, the footer is omitted and the body says "your web developer", as today.
- Each section summarises in a few lines; for many files: `30 files changed in wp-content/themes/Avada. The full list is in the attached report.`
- The "Technical details for your web developer" section stays, but short: one line per finding with rule, path and dismiss id. The per-file lists move to the report.

### The report

- Plain text, UTF-8, named `sentinel-report-<site-slug>-<YYYYMMDD-HHMM>.txt`.
- Contents, in this order:
  - header: site name, website folder, time (UTC), Sentinel version, scan mode and whether the scan was complete;
  - findings: every finding the run produced (not only the ones due for this email), grouped by severity, each with rule, path, message, dismiss id and content hash, and marked `in this email` or `reported earlier`. The email body covers only the due findings, as today;
  - changed files: **every file in the run's change list, one line each**, nothing summarised (decided: the owner asked for a full record to investigate from). Grouped by plugin/theme/folder (`Analyzer::groupOf`), each line with change type (new, modified, removed, permissions only), size, modification time, SHA-256 for code files, and a status:
    - `reported` (part of a finding),
    - `accepted: official copy` (matches the WordPress.org checksums),
    - `accepted: approved update` (an update explained under the update policy with no detection; after #10 a version change explains nothing in a plugin with an unresolved detection),
    - `accepted: not code` (uploads, images and other non-code files that changed),
    - `held: judged next run` (inside the update grace period, or retried after a scan error);
  - notes (scanner problems, checksums that could not be downloaded).
  `Analyzer::analyze()` will need to return per-file outcomes rather than only counts and info strings; how is left to the builder.
- Sent with every email that has findings or changed files: alerts, and a setup email with flagged files. The plain welcome on a clean site has no report.
- Built for every install, client or technical audience (decided as my call): email channels attach it on both; the technical digest (`Digest::build`) keeps its own wording.

### Sending

- `EmailNotifier` sends `multipart/mixed`: a `text/plain` body part and the report as a `text/plain` attachment (`Content-Disposition: attachment`, base64). The `$mailer` callable signature stays the same, so tests keep capturing mail.
- If the report exceeds a size cap (my call: 2 MB), the attachment is cut at the cap with a final line saying so; the server copy is always complete.

### Server copy

- Each report is also written to `state/reports/` (same name). Keep the newest 30 (my call), oldest deleted first.
- Non-email channels (ntfy, Telegram, webhook, file) get one extra line: `Full report saved on the server: <path>`.
- A failure to write the report never stops the alert (existing rule: alerts go out when state writes fail).

## Constraints

- PHP 7.4 compatible, no dependencies; `mail()` may be the only channel.
- Shared hosting: the report must build within the run's memory, including on sites with tens of thousands of changes (stream or cap, don't build huge strings blindly).
- The repository is public: no real site names, folders or plugins from any client in code, tests, fixtures or docs.
- Tests: client emails never show commands (existing test), the contact appears exactly once, nothing is truncated in the report, the attachment is well-formed MIME, and an email still goes out when the report can't be built.

## Left to the builder

- Exact wording of body sentences and footer, within the tone above.
- Report layout details (column order, separators).
- How the report data is collected (passing the full change list from `Monitor` to `Digest` is the obvious route).
