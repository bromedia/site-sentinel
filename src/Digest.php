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
        'sensitive-file-changed' => 'Review the change. If it was intentional, run: php sentinel.php accept --path=<file>',
        'sensitive-file-removed' => 'Restore the file from a backup if the removal was not intentional.',
        'core-file-removed' => 'Reinstall WordPress core files (wp core download --force --skip-content) if the removal was not intentional.',
        'symlink' => 'Symbolic links can expose other accounts or system files. Remove it unless you created it.',
        'world-writable' => 'Set sane permissions (644 for files, 755 for directories).',
        'self-tamper' => 'A Sentinel file changed. If you updated Sentinel, run: php sentinel.php accept --self. Otherwise treat as a compromise.',
        'run-error' => 'Sentinel could not complete its check, so the site is not being monitored. Fix the cause and run it again.',
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
