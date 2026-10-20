<?php
declare(strict_types=1);

namespace Sentinel;

final class Analyzer
{
    private $config;
    private $patterns;
    private $locations;
    private $wp;
    private $external;
    private $sensitive;
    private $dismissals;

    public function __construct(Config $config, PatternScanner $patterns, LocationScanner $locations, ?WpChecksum $wp, ExternalScanner $external, ?Dismissals $dismissals = null)
    {
        $this->config = $config;
        $this->patterns = $patterns;
        $this->locations = $locations;
        $this->wp = $wp;
        $this->external = $external;
        $this->sensitive = new PathFilter($config->sensitive);
        $this->dismissals = $dismissals;
    }

    public static function groupOf(string $rel): string
    {
        if (preg_match('#^(wp-content/(?:plugins|themes)/[^/]+)/#', $rel, $m)) {
            return $m[1];
        }
        $p = strpos($rel, '/');
        return $p === false ? '.' : substr($rel, 0, $p);
    }

    /** Whether a record needs scanning at all (everything else is stat-only). */
    public function wantsAnalysis(array $rec): bool
    {
        return ($rec['mode'] & 0170000) === 0120000
            || $this->config->isCodeFile($rec['path'])
            || $this->config->isUploads($rec['path'])
            || ($rec['mode'] & 0111) !== 0;
    }

    /**
     * @param array[] $changes from Differ::diff
     * @param array<string,string> $oldVersions stored plugin/theme versions
     * @param array<string,string> $newVersions versions currently on disk
     * @param int $now current unix time; with update_grace_seconds > 0, update-explainable findings for files that arrived within the grace period are deferred (held, not reported). 0 disables deferral
     * @return array{findings: Finding[], info: string[], hold: array<string,bool>, held_groups: array<string,bool>, notes: string[]}
     */
    public function analyze(array $changes, array $oldVersions, array $newVersions, bool $initial = false, int $now = 0): array
    {
        $grace = $this->config->updateGraceSeconds;
        $deferred = 0;
        $findings = [];
        $info = [];
        $hold = [];
        $groups = [];
        $queue = [];
        $queueHashes = [];
        $dismissed = 0;
        $official = 0;
        $removed = 0;

        foreach ($changes as $c) {
            if ($c['type'] === 'dropped') {
                continue;
            }
            $rel = (string)$c['path'];

            if ($c['type'] === 'removed') {
                $oldHash = (string)($c['old']['hash'] ?? '');
                if ($this->wp !== null && $this->wp->isCorePath($rel)) {
                    $findings[] = new Finding(Finding::WARNING, $rel, 'core-file-removed', 'WordPress core file was removed', $oldHash);
                    $hold[$rel] = true;
                } elseif ($this->sensitive->matches($rel)) {
                    $findings[] = new Finding(Finding::WARNING, $rel, 'sensitive-file-removed', 'Sensitive file was removed', $oldHash);
                    $hold[$rel] = true;
                } else {
                    $removed++;
                }
                continue;
            }

            $rec = $c['new'];
            $isNew = $c['type'] === 'new';
            $hash = (string)$rec['hash'];

            if (($rec['mode'] & 0170000) === 0120000) {
                $findings[] = new Finding(Finding::WARNING, $rel, 'symlink', 'Symbolic link ' . ($isNew ? 'created' : 'changed'));
                $hold[$rel] = true;
                continue;
            }
            if ($c['unreadable']) {
                $findings[] = new Finding(Finding::WARNING, $rel, 'unreadable', 'File could not be read for hashing and scanning');
                $hold[$rel] = true;
                continue;
            }

            $hits = $this->locations->scan($rel, $rec, $isNew);
            if ($this->config->isCodeFile($rel)) {
                $hits = array_merge($hits, $this->patterns->scan($rel, $this->config->abs($rel), $hash));
            }

            $status = ($this->wp !== null && !$this->config->isUploads($rel)) ? $this->wp->verify($rel) : WpChecksum::UNKNOWN;
            if ($status === WpChecksum::VERIFIED) {
                $official++;
                continue;
            }
            // An update copies many files over a few seconds; a scan that lands mid-copy must not call that tampering.
            // ctime, not mtime, because extracting an archive restores old mtimes. Scanner hits are never delayed.
            $fresh = $grace > 0 && $now > 0 && ($now - max((int)$rec['mtime'], (int)($rec['ctime'] ?? 0))) < $grace;
            if ($fresh && !$hits && ($status === WpChecksum::MISMATCH || $status === WpChecksum::EXTRA) && !$c['stealth']) {
                $hold[$rel] = true;
                $deferred++;
                continue;
            }
            if ($status === WpChecksum::MISMATCH) {
                $hits[] = new Finding(Finding::CRITICAL, $rel, 'checksum-mismatch', 'Differs from the official WordPress.org file', $hash);
            } elseif ($status === WpChecksum::EXTRA) {
                $hits[] = new Finding(Finding::WARNING, $rel, 'unexpected-file', 'Not part of the official package for this version', $hash);
            }
            if ($c['stealth']) {
                $hits[] = new Finding(Finding::CRITICAL, $rel, 'stealth-modification', 'Content changed but size and modification time did not', $hash);
            }
            // Detections are pinned to the file's content, so a dismissal (and alert dedupe) covers
            // exactly what was reviewed; a dismissed hit no longer holds the file, and the change
            // itself is then judged like any other.
            $hits = $this->undismissed($this->pinned($hits, $rel, $hash), $dismissed);
            if ($hits) {
                foreach ($hits as $h) {
                    $findings[] = $h;
                }
                $hold[$rel] = true;
                continue;
            }

            if ($c['type'] === 'modified' && $c['content_same']) {
                if (($rec['mode'] & 0002) !== 0 && (((int)($c['old']['mode'] ?? 0)) & 0002) === 0) {
                    $findings[] = new Finding(Finding::WARNING, $rel, 'world-writable', 'File became world-writable', $hash);
                    $hold[$rel] = true;
                }
                continue;
            }
            if ($this->sensitive->matches($rel)) {
                $findings[] = new Finding(Finding::WARNING, $rel, 'sensitive-file-changed', 'Sensitive file was ' . ($isNew ? 'created' : 'modified'), $hash);
                $hold[$rel] = true;
                continue;
            }
            if (!$this->config->isCodeFile($rel)) {
                continue;
            }
            if ($fresh) {
                $hold[$rel] = true;
                $deferred++;
                continue;
            }
            $queue[$rel] = $this->config->abs($rel);
            $queueHashes[$rel] = $hash;
            $groups[self::groupOf($rel)][$rel] = $hash;
        }

        if ($queue) {
            foreach ($this->external->scan($queue) as $f) {
                $f = new Finding($f->severity, $f->path, $f->rule, $f->message, $f->hash !== '' ? $f->hash : (string)($queueHashes[$f->path] ?? ''));
                if (!$this->undismissed([$f], $dismissed)) {
                    continue;
                }
                $findings[] = $f;
                $hold[$f->path] = true;
                foreach (array_keys($groups) as $g) {
                    unset($groups[$g][$f->path]);
                }
            }
        }

        foreach ($groups as $g => $files) {
            $g = (string)$g;
            if (!$files) {
                continue;
            }
            $old = $oldVersions[$g] ?? null;
            $new = $newVersions[$g] ?? null;
            // Files reach this point only if no official checksum vouched for them, so a version
            // bump alone proves nothing: anyone who can edit the files can edit the Version header.
            $bumped = $old !== null && $new !== null && $old !== $new;
            if ($bumped && $this->config->autoAcceptUnverifiedUpdates && $this->confirmedNotRepositoryPlugin($g, $old)) {
                $info[] = sprintf('%s updated %s -> %s (%d file(s), not verified)', $g, $old, $new, count($files));
                continue;
            }
            $names = array_map('strval', array_keys($files));
            $sample = implode(', ', array_slice($names, 0, 5)) . (count($names) > 5 ? sprintf(' (+%d more)', count($names) - 5) : '');
            // Keyed on the changed files' contents, so any further change while this waits for review alerts again.
            $contentKey = sha1(implode(',', $names) . '|' . implode(',', array_values($files)));
            $findings[] = $bumped
                ? new Finding(
                    Finding::WARNING,
                    $g,
                    'unverified-update',
                    sprintf('Version %s -> %s, but %d changed file(s) could not be verified against an official source: %s', $old, $new, count($names), $sample),
                    sha1($old . '>' . $new . '|' . $contentKey)
                )
                : new Finding(
                    Finding::WARNING,
                    $g,
                    'unexplained-change',
                    sprintf('%d file(s) changed without a version change: %s', count($names), $sample),
                    $contentKey
                );
            foreach ($names as $n) {
                $hold[$n] = true;
            }
        }

        $notes = $this->wp !== null ? $this->wp->notes() : [];
        $notes = array_merge($notes, $this->external->errors());

        if ($initial) {
            $crit = array_values(array_filter($findings, function (Finding $f) {
                return $f->severity >= Finding::CRITICAL;
            }));
            return ['findings' => $crit, 'info' => [], 'hold' => [], 'held_groups' => [], 'notes' => $notes];
        }

        if ($dismissed > 0) {
            $info[] = sprintf('%d reviewed finding(s) not reported again (see: dismiss --list)', $dismissed);
        }
        if ($official > 0) {
            $info[] = sprintf('%d file(s) verified against official WordPress.org checksums', $official);
        }
        if ($removed > 0) {
            $info[] = sprintf('%d file(s) removed', $removed);
        }
        if ($deferred > 0) {
            $info[] = sprintf('%d file(s) changed within the last %d seconds; they will be judged on the next run', $deferred, $grace);
        }
        $heldGroups = [];
        foreach (array_keys($hold) as $p) {
            $heldGroups[self::groupOf((string)$p)] = true;
        }
        return ['findings' => $findings, 'info' => $info, 'hold' => $hold, 'held_groups' => $heldGroups, 'notes' => $notes];
    }

    /**
     * Gives findings without a content hash (non-code files are not hashed by the scan) the
     * sha256 of the file, computed at most once.
     *
     * @param Finding[] $hits
     * @return Finding[]
     */
    private function pinned(array $hits, string $rel, string $hash): array
    {
        $content = $hash;
        foreach ($hits as $i => $h) {
            if ($h->hash !== '') {
                continue;
            }
            if ($content === '') {
                $content = (string)@hash_file('sha256', $this->config->abs($rel));
            }
            $hits[$i] = new Finding($h->severity, $h->path, $h->rule, $h->message, $content);
        }
        return $hits;
    }

    /**
     * @param Finding[] $hits
     * @return Finding[] the hits that have not been dismissed
     */
    private function undismissed(array $hits, int &$dismissed): array
    {
        if ($this->dismissals === null) {
            return $hits;
        }
        $out = [];
        foreach ($hits as $h) {
            if ($this->dismissals->covers($h)) {
                $dismissed++;
            } else {
                $out[] = $h;
            }
        }
        return $out;
    }

    /**
     * Legacy auto-accept is only for plugins and themes wordpress.org definitely does not host.
     * A plugin whose previous version is published there is a repository plugin, so new files
     * that did not verify mean an unpublished version; and if wordpress.org could not be asked,
     * that is unknown, which must not be treated as "premium". Themes have no checksum API, and
     * with wp_checksums off nothing is ever looked up, so both stay eligible.
     */
    private function confirmedNotRepositoryPlugin(string $group, string $oldVersion): bool
    {
        if ($this->wp === null || !preg_match('#^wp-content/plugins/([^/]+)$#', $group, $m)) {
            return true;
        }
        return $this->wp->releaseStatus($m[1], $oldVersion) === WpChecksum::RELEASE_ABSENT;
    }
}
