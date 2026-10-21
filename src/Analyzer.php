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
    /** @var array<string,array{sha256:string,rules:string[],severity:int,first:int}> Detections::all() */
    private $unresolved;

    public function __construct(Config $config, PatternScanner $patterns, LocationScanner $locations, ?WpChecksum $wp, ExternalScanner $external, ?Dismissals $dismissals = null, array $unresolved = [])
    {
        $this->config = $config;
        $this->patterns = $patterns;
        $this->locations = $locations;
        $this->wp = $wp;
        $this->external = $external;
        $this->sensitive = new PathFilter($config->sensitivePatterns());
        $this->dismissals = $dismissals;
        $this->unresolved = $unresolved;
    }

    /**
     * A file reported as possible hacking that changed or disappeared before anyone reviewed the
     * report. Keyed on what is there now, so each further change alerts again.
     *
     * @param array{sha256:string,rules:string[],severity:int,first:int} $entry
     */
    public static function unresolvedFinding(string $path, string $currentHash, array $entry, string $since): Finding
    {
        return new Finding(
            (int)($entry['severity'] ?? Finding::CRITICAL),
            $path,
            'detection-unresolved',
            sprintf(
                'Reported as possible hacking (%s)%s, but not reviewed: until it is, changes to it are not accepted and version changes of its plugin or theme are not approved automatically',
                implode(', ', $entry['rules']),
                $since !== '' ? " and $since since" : ''
            ),
            $since === 'removed' ? sha1('removed|' . $entry['sha256']) : $currentHash
        );
    }

    /** @param string[] $nested WordPress installs in subfolders, whose plugins and themes are grouped the same way */
    public static function groupOf(string $rel, array $nested = []): string
    {
        if (preg_match('#^(wp-content/(?:plugins|themes)/[^/]+)/#', $rel, $m)) {
            return $m[1];
        }
        foreach ($nested as $prefix) {
            if (strpos($rel, $prefix . '/') === 0 && preg_match('#^(wp-content/(?:plugins|themes)/[^/]+)/#', substr($rel, strlen($prefix) + 1), $m)) {
                return $prefix . '/' . $m[1];
            }
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
     * @return array{findings: Finding[], info: string[], hold: array<string,bool>, version_holds: array<string,bool>, notes: string[], detected: array<string,array{sha256:string,rules:string[],severity:int}>, resolved: array<string,bool>}
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
        $versionHolds = [];
        $detected = [];
        $resolved = [];
        $pending = [];
        $unresolvedGroups = [];
        foreach (array_keys($this->unresolved) as $path) {
            $unresolvedGroups[self::groupOf((string)$path, $this->config->nestedWordPress)] = true;
        }
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
                if (isset($this->unresolved[$rel])) {
                    $resolved[$rel] = true; // the official file is back
                }
                continue;
            }
            // An update copies many files over a few seconds; a scan that lands mid-copy must not call that tampering.
            // ctime, not mtime, because extracting an archive restores old mtimes. Scanner hits are never delayed.
            $fresh = $grace > 0 && $now > 0 && ($now - max((int)$rec['mtime'], (int)($rec['ctime'] ?? 0))) < $grace;
            if ($fresh && !$hits && ($status === WpChecksum::MISMATCH || $status === WpChecksum::EXTRA) && !$c['stealth']) {
                $hold[$rel] = true;
                $versionHolds[self::groupOf($rel, $this->config->nestedWordPress)] = true; // judged with this update on the next run
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
                    if (!in_array($h->rule, Digest::MONITORING, true)) { // a check that failed is retried, not remembered
                        $detected[$rel]['sha256'] = $h->hash;
                        $detected[$rel]['rules'][] = $h->rule;
                        $detected[$rel]['severity'] = max((int)($detected[$rel]['severity'] ?? 0), $h->severity);
                    }
                }
                $hold[$rel] = true;
                continue;
            }
            if (isset($this->unresolved[$rel])) {
                // Reported before and not reviewed since: the change is not judged on its own (it may
                // be the detected code rewritten so that nothing matches), and stays out of the baseline.
                // A code file still goes to the external scanners, whose finding then says more.
                $hold[$rel] = true;
                $pending[$rel] = $this->pinned([new Finding(Finding::WARNING, $rel, 'detection-unresolved', '', $hash)], $rel, $hash)[0]->hash;
                if ($this->config->isCodeFile($rel)) {
                    $queue[$rel] = $this->config->abs($rel);
                    $queueHashes[$rel] = $hash;
                }
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
                $versionHolds[self::groupOf($rel, $this->config->nestedWordPress)] = true;
                $deferred++;
                continue;
            }
            $queue[$rel] = $this->config->abs($rel);
            $queueHashes[$rel] = $hash;
            $groups[self::groupOf($rel, $this->config->nestedWordPress)][$rel] = $hash;
        }

        if ($queue) {
            $externalHits = $this->external->scan($queue);
            foreach ($externalHits as $f) {
                $f = new Finding($f->severity, $f->path, $f->rule, $f->message, $f->hash !== '' ? $f->hash : (string)($queueHashes[$f->path] ?? ''));
                if (!$this->undismissed([$f], $dismissed)) {
                    continue;
                }
                $findings[] = $f;
                $hold[$f->path] = true;
                if (!in_array($f->rule, Digest::MONITORING, true)) { // a check that failed is retried, not remembered
                    $detected[$f->path]['sha256'] = $f->hash;
                    $detected[$f->path]['rules'][] = $f->rule;
                    $detected[$f->path]['severity'] = max((int)($detected[$f->path]['severity'] ?? 0), $f->severity);
                }
                unset($pending[$f->path]);
                foreach (array_keys($groups) as $g) {
                    unset($groups[$g][$f->path]);
                }
            }
        }

        foreach ($pending as $rel => $content) {
            $entry = $this->unresolved[$rel];
            $findings[] = self::unresolvedFinding((string)$rel, $content, $entry, $content === $entry['sha256'] ? '' : 'changed');
        }
        // A detection in this run counts too: an update arriving with it is not explained by its
        // version either, so the files and the recorded version wait for review together.
        foreach (array_keys($detected) as $rel) {
            $unresolvedGroups[self::groupOf((string)$rel, $this->config->nestedWordPress)] = true;
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
            // Nor does it for a plugin with a file reported as possible hacking and not reviewed:
            // the bump could be covering for that file.
            $suspect = isset($unresolvedGroups[$g]);
            if ($bumped && !$suspect && $this->config->autoAcceptUnverifiedUpdates && $this->confirmedNotRepositoryPlugin($g, $old)) {
                $info[] = sprintf('%s updated %s -> %s (%d file(s), not verified)', $g, $old, $new, count($files));
                continue;
            }
            $names = array_map('strval', array_keys($files));
            $sample = implode(', ', array_slice($names, 0, 5)) . (count($names) > 5 ? sprintf(' (+%d more)', count($names) - 5) : '');
            // Keyed on the changed files' contents, so any further change while this waits for review alerts again.
            $contentKey = sha1(implode(',', $names) . '|' . implode(',', array_values($files)));
            if ($bumped) {
                $versionHolds[$g] = true; // the update itself awaits review
            }
            $findings[] = $bumped
                ? new Finding(
                    Finding::WARNING,
                    $g,
                    'unverified-update',
                    sprintf('Version %s -> %s, but %d changed file(s) could not be verified against an official source: %s', $old, $new, count($names), $sample)
                        . ($suspect ? '; it also has a file reported as possible hacking that has not been reviewed' : ''),
                    sha1($old . '>' . $new . '|' . $contentKey)
                )
                : new Finding(
                    Finding::WARNING,
                    $g,
                    'unexplained-change',
                    sprintf('%d file(s) changed without a version change: %s', count($names), $sample)
                        . ($suspect ? '; it also has a file reported as possible hacking that has not been reviewed' : ''),
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
            return ['findings' => $crit, 'info' => [], 'hold' => [], 'version_holds' => [], 'notes' => $notes, 'detected' => [], 'resolved' => []];
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
        // Only an update that is still waiting (for review, or for its copy to finish) keeps a
        // plugin's or theme's stored version. A file held for its own finding does not: freezing
        // the version then would let later edits pass as part of an update that was already done.
        return ['findings' => $findings, 'info' => $info, 'hold' => $hold, 'version_holds' => $versionHolds, 'notes' => $notes, 'detected' => $detected, 'resolved' => $resolved];
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
        if ($this->wp === null || !preg_match('#^(?:.+/)?wp-content/plugins/([^/]+)$#', $group, $m)) {
            return true;
        }
        return $this->wp->releaseStatus($m[1], $oldVersion) === WpChecksum::RELEASE_ABSENT;
    }
}
