# Optional database monitoring

Database checks are disabled by default. They need PHP mysqli with read-timeout support, and tokenizer when extracting credentials from WordPress. The monitor never includes or executes wp-config.php, WordPress, themes or plugins. All content queries are reads; charset/query-timeout settings affect the connection only.

## Setup

Review the site's existing administrators and security settings first. `db-init` trusts that current snapshot; it cannot decide whether an administrator already present is legitimate.

Add to your private `sentinel.json`:

```json
"database": { "enabled": true }
```

By default, credentials are extracted from literal DB_HOST, DB_NAME, DB_USER, DB_PASSWORD and table_prefix definitions in wp-config.php in the site root or parent. Computed/environment-based credentials and ambiguous declarations are refused. Use `database.wp_config` for a different absolute config path.

Prefer a separate database user with **SELECT only** on the site's tables. Store its credentials in a private JSON file outside the public web directory, readable only by the hosting account:

```json
{
  "host": "localhost",
  "port": 3306,
  "socket": "",
  "name": "client_wordpress",
  "user": "client_sentinel_reader",
  "password": "replace-with-reader-password",
  "table_prefix": "wp_"
}
```

Set `database.credentials_file` to that absolute path. It takes precedence over WordPress-config extraction. No plaintext credentials are copied to Sentinel's baseline or alerts. The existing WordPress account can be used if the host cannot provision a reader account, but a SELECT-only account also enforces read-only behavior at the server.

After deliberate configuration edits, use your host's actual CLI PHP executable:

```sh
php sentinel.php accept --self
php sentinel.php doctor
php sentinel.php db-init
php sentinel.php db-check
```

Doctor checks configuration locally without connecting to the database. Regular check/full jobs include database checks after opt-in, with time reserved for them. The normal ten-minute cron is sufficient; unfinished post scans resume on the next run.

## Coverage and alerts

- Privileged accounts: administrator role, custom roles granting manage_options, or direct manage_options capability. New privileged accounts are Critical; removals/details/capability changes are Warnings. Only account IDs and hashes are retained; login/email/password-hash/capability contents never appear in alerts or state.
- Security options: siteurl, home, active_plugins, template, stylesheet, users_can_register, default_role, admin_email and the site's user_roles option. Changes are Critical except admin_email (Warning). Values are compared as hashes.
- Posts/pages: cyclic traversal in numeric ID order, with a saved cursor. Gambling/spam phrases and script/PHP-like content raise Warnings. Legitimate casino articles, embeds and code examples can match. These are review prompts, not proof of malware. Alerts contain IDs, not titles, URLs or content.
- Bulk posts: 20 or more new monitored posts since the preceding check raises a Warning. Legitimate imports can trigger it; this is an ID-based count, not a posts-per-hour measure.

Account/option changes remain untrusted until reviewed. Accept only the intended scope:

```sh
php sentinel.php db-accept --scope=admins
php sentinel.php db-accept --scope=options
```

These commands only change Sentinel's private snapshot. Post content is never whitelisted. If all eligible channels fail, post progress and the burst watermark remain available for retry. Intentional severity filtering is respected.

## Limits

Defaults: batch_size 20 posts, max_post_bytes 262144, new_post_threshold 20, query_timeout_seconds 3, max_admins 1000 candidate records. batch_size times max_post_bytes cannot exceed 8MB. post_types defaults to ["post", "page"]; explicitly add custom types. Revisions, inherited attachments, trash and auto-drafts are excluded.

Large bodies are sampled at the beginning/end with an explicit warning; their middle is not scanned. Arbitrary plugin tables, postmeta, comments, every user/option, database triggers and database-server accounts are outside this module. It targets ordinary single-site layouts; multisite/network administrator coverage requires a separate extension.

MySQL/MariaDB connect, read and query timeouts are bounded. The process budget is cooperative; an individual query/batch, checkpoint or notification may overrun. Doctor distinguishes progress, complete coverage and failed attempts. Retain external heartbeat monitoring and backups.
