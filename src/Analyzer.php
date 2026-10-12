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

    public function __construct(Config $config, PatternScanner $patterns, LocationScanner $locations, ?WpChecksum $wp, ExternalScanner $external)
    {
        $this->config = $config;
        $this->patterns = $patterns;
        $this->locations = $locations;
        $this->wp = $wp;
        $this->external = $external;
        $this->sensitive = new PathFilter($config->sensitive);
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
     * @return array{findings: Finding[], info: string[], hold: array<string,bool>, held_groups: array<string,bool>, notes: string[]}
     */
    public function analyze(array $changes, array $oldVersions, array $newVersions, bool $initial = false): array
    {
        $findings = [];
        $info = [];
        $hold = [];
        $groups = [];
        $queue = [];
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
            if ($status === WpChecksum::MISMATCH) {
                $hits[] = new Finding(Finding::CRITICAL, $rel, 'checksum-mismatch', 'Differs from the official WordPress.org file', $hash);
            } elseif ($status === WpChecksum::EXTRA) {
                $hits[] = new Finding(Finding::WARNING, $rel, 'unexpected-file', 'Not part of the official package for this version', $hash);
            }
            if ($c['stealth']) {
                $hits[] = new Finding(Finding::CRITICAL, $rel, 'stealth-modification', 'Content changed but size and modification time did not', $hash);
            }
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
            $queue[$rel] = $this->config->abs($rel);
            $groups[self::groupOf($rel)][$rel] = $hash;
        }

        if ($queue) {
            foreach ($this->external->scan($queue) as $f) {
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
            if ($old !== null && $new !== null && $old !== $new) {
                $info[] = sprintf('%s updated %s -> %s (%d file(s))', $g, $old, $new, count($files));
                continue;
            }
            $names = array_map('strval', array_keys($files));
            $sample = implode(', ', array_slice($names, 0, 5)) . (count($names) > 5 ? sprintf(' (+%d more)', count($names) - 5) : '');
            $findings[] = new Finding(
                Finding::WARNING,
                $g,
                'unexplained-change',
                sprintf('%d file(s) changed without a version change: %s', count($names), $sample),
                sha1(implode(',', $names) . '|' . implode(',', array_values($files)))
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

        if ($official > 0) {
            $info[] = sprintf('%d file(s) verified against official WordPress.org checksums', $official);
        }
        if ($removed > 0) {
            $info[] = sprintf('%d file(s) removed', $removed);
        }
        $heldGroups = [];
        foreach (array_keys($hold) as $p) {
            $heldGroups[self::groupOf((string)$p)] = true;
        }
        return ['findings' => $findings, 'info' => $info, 'hold' => $hold, 'held_groups' => $heldGroups, 'notes' => $notes];
    }
}
