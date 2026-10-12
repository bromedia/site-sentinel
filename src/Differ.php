<?php
declare(strict_types=1);

namespace Sentinel;

final class Differ
{
    private $config;
    private $filter;

    public function __construct(Config $config)
    {
        $this->config = $config;
        $this->filter = new PathFilter($config->exclusions());
    }

    /**
     * Returns [record, unreadable]. Only code files are hashed.
     *
     * @return array{0: array, 1: bool}
     */
    public function record(array $meta): array
    {
        $isLink = ($meta['mode'] & 0170000) === 0120000;
        if ($isLink || !$this->config->isCodeFile($meta['path'])) {
            return [$meta, false];
        }
        $h = @hash_file('sha256', $this->config->abs($meta['path']));
        if ($h === false) {
            return [$meta, true];
        }
        $meta['hash'] = $h;
        return [$meta, false];
    }

    /**
     * Merge-compares the walk (strictly after $startAfter) with the baseline.
     *
     * @return array{changes: array, stopped_at: ?string, complete: bool, unreadable: string[]}
     */
    public function diff(string $baselineFile, string $startAfter, Budget $budget, bool $full): array
    {
        $walker = new Walker($this->config);
        $walk = $walker->walk($startAfter);
        $base = Baseline::read($baselineFile);
        while ($base->valid() && $startAfter !== '' && PathOrder::compare($base->current()['path'], $startAfter) <= 0) {
            $base->next();
        }

        $changes = [];
        $last = $startAfter;
        $processed = 0;
        $complete = true;
        while (true) {
            if ($processed > 0 && $budget->exceeded()) {
                $complete = false;
                break;
            }
            $w = $walk->valid() ? $walk->current() : null;
            $b = $base->valid() ? $base->current() : null;
            if ($w === null && $b === null) {
                break;
            }
            if ($b === null) {
                $cmp = -1;
            } elseif ($w === null) {
                $cmp = 1;
            } else {
                $cmp = PathOrder::compare($w['path'], $b['path']);
            }
            if ($cmp < 0) {
                [$rec, $unreadable] = $this->record($w);
                $changes[] = $this->change('new', $w['path'], null, $rec, ['unreadable' => $unreadable]);
                $last = $w['path'];
                $walk->next();
            } elseif ($cmp > 0) {
                $type = $this->filter->matches($b['path']) ? 'dropped' : 'removed';
                $changes[] = $this->change($type, $b['path'], $b, null);
                $last = $b['path'];
                $base->next();
            } else {
                $c = $this->compare($w, $b, $full);
                if ($c !== null) {
                    $changes[] = $c;
                }
                $last = $w['path'];
                $walk->next();
                $base->next();
            }
            $processed++;
        }
        return ['changes' => $changes, 'stopped_at' => $complete ? null : $last, 'complete' => $complete, 'unreadable' => $walker->unreadable()];
    }

    private function compare(array $w, array $b, bool $full): ?array
    {
        $statChanged = $w['size'] !== $b['size'] || $w['mtime'] !== $b['mtime'] || $w['mode'] !== $b['mode'];
        if (!$statChanged && !$full) {
            return null;
        }
        [$rec, $unreadable] = $this->record($w);
        if (!$statChanged) {
            if ($unreadable || $rec['hash'] === '' || $b['hash'] === '' || $rec['hash'] === $b['hash']) {
                return null;
            }
            return $this->change('modified', $w['path'], $b, $rec, ['stealth' => true]);
        }
        $same = $rec['hash'] !== '' && $rec['hash'] === $b['hash'];
        return $this->change('modified', $w['path'], $b, $rec, ['content_same' => $same, 'unreadable' => $unreadable]);
    }

    private function change(string $type, string $path, ?array $old, ?array $new, array $flags = []): array
    {
        return array_merge([
            'type' => $type, 'path' => $path, 'old' => $old, 'new' => $new,
            'stealth' => false, 'content_same' => false, 'unreadable' => false,
        ], $flags);
    }
}
