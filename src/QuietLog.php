<?php
declare(strict_types=1);

namespace Sentinel;

/**
 * What was accepted quietly since the last alert email was delivered, kept in state/quiet-log.json
 * so the next alert's report can list it. Only the newest CAP entries are kept; `dropped` counts the
 * older ones that were let go, so the report can say how many are not listed.
 */
final class QuietLog
{
    public const FILE = 'quiet-log.json';
    public const CAP = 2000;
    /** A larger file is not ours (the state folder is writable by anything on the account): it is not read. */
    public const MAX_BYTES = 2097152;

    private $state;
    /** @var array<int,array{path:string,group:string,ts:int}> */
    private $entries = [];
    private $dropped = 0;

    public function __construct(State $state)
    {
        $this->state = $state;
        // An oversized file is treated as empty (and replaced by the next save); the server reports
        // still hold what was accepted.
        $size = @filesize($state->path(self::FILE));
        $data = $size !== false && $size > self::MAX_BYTES ? [] : $state->readJson(self::FILE);
        $entries = $data['entries'] ?? [];
        foreach (is_array($entries) ? $entries : [] as $e) {
            if (is_array($e) && isset($e['path'], $e['group'], $e['ts']) && is_string($e['path']) && is_string($e['group']) && is_int($e['ts'])) {
                $this->entries[] = ['path' => $e['path'], 'group' => $e['group'], 'ts' => $e['ts']];
            }
        }
        $d = $data['dropped'] ?? 0;
        $this->dropped = is_int($d) ? max(0, $d) : 0;
        $this->trim();
    }

    /** Keeps the newest CAP entries; the rest are counted as dropped. */
    private function trim(): void
    {
        $extra = count($this->entries) - self::CAP;
        if ($extra > 0) {
            $this->entries = array_slice($this->entries, $extra);
            $this->dropped += $extra;
        }
    }

    /**
     * Adds what a run accepted quietly and saves, keeping the newest CAP entries.
     *
     * @param string[] $paths
     * @param string[] $nested WordPress installs in subfolders, for the group of each path
     */
    public function add(array $paths, int $ts, array $nested = []): void
    {
        foreach ($paths as $path) {
            $path = (string)$path;
            if (!preg_match('//u', $path)) { // a file name that is not UTF-8 must not make the log unwritable
                $path = (string)preg_replace('/[^\x00-\x7F]/', '?', $path);
            }
            $this->entries[] = ['path' => $path, 'group' => Analyzer::groupOf($path, $nested), 'ts' => $ts];
        }
        $this->trim();
        $this->save();
    }

    /** The list starts again: its entries have been shown in an alert that was delivered. */
    public function clear(): void
    {
        if (!$this->entries && $this->dropped === 0) {
            return;
        }
        $this->entries = [];
        $this->dropped = 0;
        $this->save();
    }

    /** @return array{entries: array<int,array{path:string,group:string,ts:int}>, dropped: int} as Report::write takes it */
    public function pending(): array
    {
        return ['entries' => $this->entries, 'dropped' => $this->dropped];
    }

    private function save(): void
    {
        $this->state->writeJson(self::FILE, $this->pending());
    }
}
