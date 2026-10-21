<?php
declare(strict_types=1);

namespace Sentinel;

/**
 * The full plain-text record that goes with an alert email: every finding of the run and every
 * changed file, one line each, nothing summarised. Metadata only: relative paths, sizes, times
 * and hashes, never file contents or absolute paths (those contain the hosting account name).
 * It is streamed to disk line by line, so a site with tens of thousands of changes does not need
 * the whole report in memory. The saved copy is always complete; an email attachment is cut at CAP.
 */
final class Report
{
    /** Attachment size cap in bytes (2 MB). */
    public const CAP = 2097152;
    /** Server copies kept: the newest KEEP files, and at most MAX_BYTES in total. */
    public const KEEP = 30;
    public const MAX_BYTES = 52428800;

    public const STATUSES = [
        'reported',
        'accepted: official copy',
        'accepted: approved update',
        'accepted: not code',
        'accepted: permissions only',
        'accepted: removed',
        'held: judged next run',
        self::UNSAVED,
    ];

    /** What an accepted change becomes when the record of website files could not be saved. */
    public const UNSAVED = 'pending: not saved (the record of website files could not be updated)';

    private const PARTIAL = 'part of a scan: changes found in this part only; the scan resumes on the next run';
    private const COMPLETE = 'complete scan';
    private const PREFIX = 'sentinel-report-';

    /** sentinel-report-<site-slug>-<YYYYMMDD-HHMM>.txt, safe for any site name. */
    public static function fileName(string $site, int $ts): string
    {
        $slug = trim((string)preg_replace('/[^a-z0-9]+/', '-', strtolower($site)), '-');
        $slug = trim(substr($slug, 0, 40), '-');
        if ($slug === '') {
            $slug = 'site';
        }
        return self::PREFIX . $slug . '-' . gmdate('Ymd-Hi', $ts) . '.txt';
    }

    /** Where the saved copy is, relative to the account's home: sentinel/state/reports/<name>. */
    public static function displayPath(string $stateDir, string $name): string
    {
        $dir = rtrim($stateDir, '/');
        return basename(dirname($dir)) . '/' . basename($dir) . '/reports/' . $name;
    }

    /**
     * Writes the report to $dir/<fileName> (or <fileName>-2, -3, ... when a report of the same
     * minute is already there: never overwritten, never written through a planted link) and
     * prunes older copies.
     *
     * @param array{site:string, root:string, ts:int, version:string, mode:string, complete:bool, nested?:string[], home?:string} $meta
     *        root (the website folder) and home (the folder holding the sentinel folder) are only used
     *        to turn absolute paths in any line into relative ones
     * @param Finding[] $findings every finding of the run
     * @param string[] $dueKeys Finding::key() of the findings in this email
     * @param array[] $changes Differ::diff()['changes']
     * @param array<string,string> $outcomes path => one of STATUSES
     * @param string[] $notes
     * @return string the file written
     */
    public static function write(string $dir, array $meta, array $findings, array $dueKeys, array $changes, array $outcomes, array $notes): string
    {
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException("cannot create report folder");
        }
        $name = self::fileName((string)$meta['site'], (int)$meta['ts']);
        for ($n = 1;; $n++) {
            $file = rtrim($dir, '/') . '/' . ($n === 1 ? $name : substr($name, 0, -4) . "-$n.txt");
            $fh = @fopen($file, 'xb'); // fails on anything already there, a link included
            if ($fh !== false) {
                break;
            }
            if ((!file_exists($file) && !is_link($file)) || $n >= 100) {
                throw new \RuntimeException('cannot write report');
            }
        }
        @chmod($file, 0600);
        try {
            self::stream($fh, $meta, $findings, array_flip($dueKeys), $changes, $outcomes, $notes);
        } catch (\Throwable $e) {
            @fclose($fh);
            @unlink($file);
            throw $e instanceof \RuntimeException ? $e : new \RuntimeException('cannot write report', 0, $e);
        }
        // Buffered data only reaches the disk at flush or close: a failure there is a failed report too.
        $flushed = @fflush($fh);
        $closed = @fclose($fh);
        if (!$flushed || !$closed) {
            @unlink($file);
            throw new \RuntimeException('cannot write report');
        }
        self::prune($dir, $file);
        return $file;
    }

    /**
     * Writes all of $data. A write cut short (disk full, quota, file-size limit) is retried for the
     * rest; when nothing more can be written the report is incomplete and this throws.
     *
     * @param resource $fh
     */
    private static function writeAll($fh, string $data): void
    {
        $done = 0;
        $total = strlen($data);
        while ($done < $total) {
            $n = @fwrite($fh, $done === 0 ? $data : substr($data, $done));
            if ($n === false || $n <= 0) {
                throw new \RuntimeException('cannot write report');
            }
            $done += $n;
        }
    }

    /** @param resource $fh */
    private static function stream($fh, array $meta, array $findings, array $due, array $changes, array $outcomes, array $notes): void
    {
        $scrub = self::pathScrubber((string)($meta['root'] ?? ''), (string)($meta['home'] ?? ''));
        $put = function (string $line) use ($fh, $scrub): void {
            self::writeAll($fh, Finding::line($scrub($line)) . "\n");
        };
        $scope = !empty($meta['complete']) ? self::COMPLETE : self::PARTIAL;

        $put('Site Sentinel report: ' . $meta['site']);
        $put('Time: ' . gmdate('Y-m-d H:i:s', (int)$meta['ts']) . ' UTC');
        $put('Sentinel version: ' . $meta['version']);
        $put('Scan mode: ' . $meta['mode']);
        $put('Coverage: ' . $scope);
        $put('');

        // Findings: every one of the run, worst first.
        usort($findings, function (Finding $a, Finding $b) {
            return $b->severity <=> $a->severity ?: PathOrder::compare($a->path, $b->path);
        });
        $put('FINDINGS (' . count($findings) . ')');
        $put('');
        $current = null;
        foreach ($findings as $f) {
            if ($f->severity !== $current) {
                $current = $f->severity;
                $count = 0;
                foreach ($findings as $g) {
                    $count += $g->severity === $current ? 1 : 0;
                }
                $put(Finding::label($current) . " ($count)");
            }
            $put('  ' . $f->path);
            $put('    ' . $f->rule . ': ' . $f->message);
            $extra = [isset($due[$f->key()]) ? 'in this email' : 'reported earlier'];
            if (Dismissals::dismissable($f)) {
                $extra[] = '[id ' . $f->id() . ']';
            }
            if ($f->hash !== '') {
                $extra[] = 'sha256 ' . $f->hash;
            }
            $put('    ' . implode(' | ', $extra));
            $put('');
        }
        if (!$findings) {
            $put('  none');
            $put('');
        }

        // Changed files, grouped by plugin, theme or folder.
        $nested = (array)($meta['nested'] ?? []);
        $groups = [];
        $total = 0;
        foreach ($changes as $i => $c) {
            if ($c['type'] === 'dropped') {
                continue; // left the monitored set (excluded now), not a change to the site
            }
            $groups[Analyzer::groupOf((string)$c['path'], $nested)][] = $i;
            $total++;
        }
        uksort($groups, [PathOrder::class, 'compare']);
        $put("CHANGED FILES ($total) - $scope; times are UTC");
        $put('');
        foreach ($groups as $group => $indexes) {
            $put($group . ' (' . count($indexes) . ')');
            foreach ($indexes as $i) {
                $c = $changes[$i];
                $path = (string)$c['path'];
                $status = $outcomes[$path] ?? 'reported'; // never claimed as accepted without an outcome saying so
                $put('  ' . self::changeLine($c) . ' [' . $status . '] ' . $path);
            }
            $put('');
        }
        if (!$total) {
            $put('  none');
            $put('');
        }

        if ($notes) {
            $put('NOTES');
            foreach ($notes as $n) {
                $put('  - ' . $n);
            }
        }
    }

    /** "modified  1234 B  2026-10-21 14:02  sha256:<hash or ->" */
    private static function changeLine(array $c): string
    {
        $rec = $c['type'] === 'removed' ? (array)$c['old'] : (array)$c['new'];
        $type = $c['type'] === 'new' ? 'new' : ($c['type'] === 'removed' ? 'removed' : 'modified');
        if ($type === 'modified' && self::permissionsOnly($c)) {
            $type = 'permissions only';
        }
        $hash = (string)($rec['hash'] ?? '');
        return $type . ' | ' . (int)($rec['size'] ?? 0) . ' B | ' . gmdate('Y-m-d H:i', (int)($rec['mtime'] ?? 0))
            . ' | sha256 ' . ($hash !== '' ? $hash : '-');
    }

    /** Only the mode changed: same content (or, for files that are not hashed, same size and time). */
    private static function permissionsOnly(array $c): bool
    {
        $old = (array)$c['old'];
        $new = (array)$c['new'];
        if (!isset($old['mode'], $new['mode']) || $old['mode'] === $new['mode']) {
            return false;
        }
        return !empty($c['content_same']) || (($old['size'] ?? null) === ($new['size'] ?? 0) && ($old['mtime'] ?? null) === ($new['mtime'] ?? 0));
    }

    /**
     * Turns the absolute paths of the website folder and of the account's home (as given and as
     * resolved through links) into relative ones: "<root>/x" becomes "x" and "<home>/sentinel/x"
     * becomes "sentinel/x". Only the exact folder matches, so "<root>_old" is left alone; a folder
     * that is the file system root is never used. Used for the report and for everything sent.
     *
     * @return callable(string): string
     */
    public static function pathScrubber(string $root, string $home): callable
    {
        $map = [];
        foreach ([[$home, '~'], [$root, '.']] as [$dir, $bare]) { // the website folder wins a tie
            foreach ([$dir, $dir !== '' ? (string)realpath($dir) : ''] as $d) {
                $d = rtrim($d, '/');
                if ($d !== '' && $d[0] === '/') {
                    $map[$d] = $bare;
                }
            }
        }
        if (!$map) {
            return function (string $line): string {
                return $line;
            };
        }
        uksort($map, function ($a, $b) {
            return strlen((string)$b) <=> strlen((string)$a); // the most specific folder first
        });
        $quoted = array_map(function ($d) {
            return preg_quote((string)$d, '#');
        }, array_keys($map));
        $re = '#(?<![A-Za-z0-9._~/-])(' . implode('|', $quoted) . ')(?:(/)|(?![A-Za-z0-9._~-]))#';
        return function (string $line) use ($re, $map): string {
            return (string)preg_replace_callback($re, function ($m) use ($map) {
                return isset($m[2]) && $m[2] === '/' ? '' : $map[$m[1]];
            }, $line);
        };
    }

    /** Deletes old copies: keeps the newest KEEP and at most MAX_BYTES in total; $newest is never deleted. */
    public static function prune(string $dir, string $newest = ''): void
    {
        $files = [];
        foreach ((array)@scandir($dir) as $name) {
            $p = rtrim($dir, '/') . '/' . $name;
            if (strpos((string)$name, self::PREFIX) === 0 && substr((string)$name, -4) === '.txt' && is_file($p)) {
                $files[$p] = [(int)@filemtime($p), (int)@filesize($p)];
            }
        }
        uksort($files, function ($a, $b) use ($files, $newest) {
            if ($a === $newest || $b === $newest) {
                return $a === $newest ? -1 : 1;
            }
            return $files[$b][0] <=> $files[$a][0] ?: strcmp($b, $a);
        });
        $kept = 0;
        $bytes = 0;
        foreach ($files as $p => [, $size]) {
            if ($kept > 0 && ($kept >= self::KEEP || $bytes + $size > self::MAX_BYTES)) {
                @unlink($p);
                continue;
            }
            $kept++;
            $bytes += $size;
        }
    }

    /**
     * The report as an email attachment, cut at $cap bytes (at a line end) with a final line saying
     * where the complete copy is. $displayPath is shown instead of the real path.
     *
     * @return array{name:string, path:string, content:string}
     */
    public static function attachment(string $file, string $displayPath, int $cap = self::CAP): array
    {
        $size = @filesize($file);
        $fh = $size === false ? false : @fopen($file, 'rb');
        if ($fh === false) {
            throw new \RuntimeException('cannot read report');
        }
        $content = (string)fread($fh, $cap + 1);
        fclose($fh);
        if (strlen($content) > $cap) {
            $content = substr($content, 0, $cap);
            $nl = strrpos($content, "\n");
            if ($nl !== false) {
                $content = substr($content, 0, $nl + 1);
            }
            $limit = $cap % 1048576 === 0 ? intdiv($cap, 1048576) . ' MB' : $cap . ' bytes';
            $content = rtrim($content, "\n") . "\n[report cut at $limit; the full report is on the server: $displayPath]\n";
        }
        return ['name' => basename($file), 'path' => $displayPath, 'content' => $content];
    }
}
