<?php
declare(strict_types=1);

namespace Sentinel;

final class Digest
{
    private const COMPROMISE = 'Treat this as a possible compromise: keep a copy of the file for analysis, remove or restore it, then check recent logins, plugin/theme vulnerabilities and file permissions. Restore from a clean backup if it is confirmed.';

    private const ACTIONS = [
        'php-in-uploads' => 'PHP does not belong in uploads. Inspect the file, delete it if it is not yours, and find out how it got there (vulnerable plugin, stolen credentials).',
        'php-in-media' => 'A media file carrying PHP code is a disguised webshell. Delete it and find out how it was uploaded.',
        'checksum-mismatch' => 'Reinstall the official version of this file and find out how it was changed.',
        'unexpected-file' => 'This file is not in the official package. If you did not add it, inspect and remove it.',
        'stealth-modification' => 'Someone changed the content and reset the timestamp. Inspect the file and restore it from a clean copy.',
        'unexplained-change' => 'If you did not just deploy or update this, review the files. If you did, run: php sentinel.php accept',
        'unverified-update' => 'The version number changed, but nothing official vouches for the new files (a premium plugin or theme, or a version wordpress.org has not published). If you or auto-updates installed it, run: php sentinel.php accept --path=<the directory shown>. If not, treat it as a compromise.',
        'sensitive-file-changed' => 'Review the change. If it was intentional, run: php sentinel.php accept --path=<file>',
        'sensitive-file-removed' => 'Restore the file from a backup if the removal was not intentional.',
        'core-file-removed' => 'Reinstall WordPress core files (wp core download --force --skip-content) if the removal was not intentional.',
        'symlink' => 'Symbolic links can expose other accounts or system files. Remove it unless you created it.',
        'world-writable' => 'Set sane permissions (644 for files, 755 for directories).',
        'self-tamper' => 'A Sentinel file changed. If you updated Sentinel, run: php sentinel.php accept --self. Otherwise treat as a compromise.',
        'run-error' => 'Sentinel could not complete its check, so the site is not being monitored. Fix the cause and run it again.',
        'state-write-failed' => 'Sentinel could not save its state, usually because the disk or account quota is full. Free space; until then it keeps rescanning the same files and cannot record changes as reviewed.',
        'scan-error' => 'A detection rule could not run on this file, which can happen with unusually large or deliberately crafted files. Inspect it manually.',
        'unreadable' => 'Fix the file permissions so Sentinel can read it, or exclude it.',
        'unreadable-dir' => 'Fix the directory permissions so Sentinel can read it, or exclude it.',
        'config-in-uploads' => 'Server configuration in uploads can enable code execution. Inspect and remove it if it is not yours.',
        'exec-in-temp' => 'An executable appeared in a temp directory. Inspect it and find out which process created it.',
    ];

    /**
     * @param Finding[] $findings
     * @param string[] $info
     * @param string[] $notes
     * @return array{subject: string, body: string, top: int}
     */
    public static function build(string $site, string $host, int $ts, array $findings, array $info, array $notes): array
    {
        usort($findings, function (Finding $a, Finding $b) {
            return $b->severity <=> $a->severity ?: PathOrder::compare($a->path, $b->path);
        });
        $top = Finding::INFO;
        $crit = 0;
        $warn = 0;
        foreach ($findings as $f) {
            $top = max($top, $f->severity);
            if ($f->severity >= Finding::CRITICAL) {
                $crit++;
            } elseif ($f->severity === Finding::WARNING) {
                $warn++;
            }
        }
        $subject = sprintf('[Sentinel][%s] %s: %d critical, %d warning', Finding::label($top), $site, $crit, $warn);

        $lines = [
            "Site Sentinel alert: $site ($host)",
            'Time: ' . gmdate('Y-m-d H:i:s', $ts) . ' UTC',
            'Highest severity: ' . Finding::label($top),
            '',
        ];
        $current = null;
        foreach ($findings as $f) {
            if ($f->severity !== $current) {
                $current = $f->severity;
                $count = 0;
                foreach ($findings as $g) {
                    $count += $g->severity === $current ? 1 : 0;
                }
                $lines[] = Finding::label($current) . " ($count)";
            }
            $lines[] = '  ' . $f->path;
            $lines[] = '    ' . $f->rule . ': ' . $f->message;
            $lines[] = '    What to do: ' . self::action($f);
            if (Dismissals::dismissable($f)) {
                $lines[] = '    If you reviewed it and it is harmless: php sentinel.php dismiss ' . $f->id() . ' --reason="..."';
            }
            $lines[] = '';
        }
        if ($notes) {
            $lines[] = 'Notes';
            foreach ($notes as $n) {
                $lines[] = '  - ' . $n;
            }
            $lines[] = '';
        }
        if ($info) {
            $lines[] = 'Info';
            foreach ($info as $i) {
                $lines[] = '  - ' . $i;
            }
            $lines[] = '';
        }
        return ['subject' => $subject, 'body' => implode("\n", $lines), 'top' => $top];
    }

    /** Problems with Sentinel itself rather than with the website's files. */
    private const MONITORING = ['run-error', 'state-write-failed', 'self-tamper', 'unreadable', 'unreadable-dir', 'scan-error'];
    /** Changes to review, as opposed to files that look suspicious in themselves. */
    private const CHANGES = [
        'unexplained-change', 'unverified-update', 'sensitive-file-changed', 'sensitive-file-removed',
        'core-file-removed', 'symlink', 'world-writable',
    ];

    /** The digest the config asks for: technical (commands) or client (plain language). */
    public static function forConfig(Config $c, int $ts, array $findings, array $info, array $notes): array
    {
        return $c->audience === 'client'
            ? self::forClient($c->siteName, $ts, $findings, $info, $notes, $c->contact)
            : self::build($c->siteName, (string)gethostname(), $ts, $findings, $info, $notes);
    }

    /**
     * Plain language for site owners: what happened and who to contact, never a command to run.
     * The technical detail follows at the end, for the developer the email gets forwarded to.
     *
     * @param Finding[] $findings
     * @param string[] $info
     * @param string[] $notes
     * @return array{subject: string, body: string, top: int}
     */
    public static function forClient(string $site, int $ts, array $findings, array $info, array $notes, string $contact): array
    {
        $who = $contact !== '' ? $contact : 'your web developer';
        $groups = ['hack' => [], 'check' => [], 'changes' => [], 'monitoring' => []];
        $top = Finding::INFO;
        foreach ($findings as $f) {
            $top = max($top, $f->severity);
            if (in_array($f->rule, self::MONITORING, true)) {
                $groups['monitoring'][] = $f;
            } elseif (in_array($f->rule, self::CHANGES, true)) {
                $groups['changes'][] = $f;
            } elseif ($f->severity >= Finding::CRITICAL) {
                $groups['hack'][] = $f;
            } else {
                $groups['check'][] = $f;
            }
        }
        if ($groups['hack']) {
            $subject = "Security alert: $site may have been hacked";
        } elseif ($groups['monitoring']) {
            $subject = "Security monitoring problem on $site";
        } elseif ($groups['check']) {
            $subject = "Please check: unusual files on $site";
        } else {
            $subject = "Website files changed on $site";
        }

        $lines = ["Site Sentinel: $site", date('j M Y, H:i T', $ts), '']; // the server's local time for owners
        $paths = function (array $fs): array {
            $out = [];
            foreach ($fs as $f) {
                $out['  - ' . $f->path] = true;
            }
            return array_keys($out);
        };
        if ($groups['hack']) {
            $lines[] = 'POSSIBLE HACK';
            $lines[] = 'Files were found that look like hacking tools or tampering:';
            $lines = array_merge($lines, $paths($groups['hack']));
            $lines[] = "What to do: contact $who today and forward them this email.";
            $lines[] = "Please don't delete or change anything yourself: these files help";
            $lines[] = 'show how the attacker got in.';
            $lines[] = '';
        }
        if ($groups['check']) {
            $lines[] = 'UNUSUAL FILES';
            $lines[] = "These files are unusual for a website. They may be harmless, but $who";
            $lines[] = 'should check them:';
            $lines = array_merge($lines, $paths($groups['check']));
            $lines[] = '';
        }
        if ($groups['changes']) {
            $lines[] = 'WEBSITE FILES CHANGED';
            $lines[] = 'Files changed without an update that could be verified:';
            $lines = array_merge($lines, $paths($groups['changes']));
            $lines[] = "If you or $who just installed updates or made changes, this is";
            $lines[] = "expected. If nobody did, contact $who.";
            $lines[] = '';
        }
        if ($groups['monitoring']) {
            $lines[] = 'MONITORING PROBLEM';
            $lines[] = 'Site Sentinel could not fully check the website, or its own files changed.';
            $lines[] = "Until this is fixed, problems may go unnoticed. Please forward this email to $who.";
            $lines[] = '';
        }
        $lines[] = '--';
        $lines[] = 'Technical details for your web developer:';
        foreach ($findings as $f) {
            $lines[] = '  ' . Finding::label($f->severity) . ' ' . $f->rule . ' ' . $f->path . (Dismissals::dismissable($f) ? ' [id ' . $f->id() . ']' : '');
            $lines[] = '    ' . $f->message;
        }
        foreach ($notes as $n) {
            $lines[] = '  note: ' . $n;
        }
        foreach ($info as $i) {
            $lines[] = '  info: ' . $i;
        }
        return ['subject' => $subject, 'body' => implode("\n", $lines), 'top' => $top];
    }

    private static function action(Finding $f): string
    {
        if (isset(self::ACTIONS[$f->rule])) {
            return self::ACTIONS[$f->rule];
        }
        if ($f->severity >= Finding::CRITICAL) {
            return self::COMPROMISE;
        }
        return 'Review the file. If the change is expected, run: php sentinel.php accept --path=<file>';
    }
}
