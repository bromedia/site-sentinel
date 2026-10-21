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

    private $state;
    /** @var array<int,array{path:string,group:string,ts:int}> */
    private $entries = [];
    private $dropped = 0;

    public function __construct(State $state)
    {
        $this->state = $state;
        $data = $state->readJson(self::FILE);
        foreach ((array)($data['entries'] ?? []) as $e) {
            if (is_array($e) && isset($e['path'], $e['group'], $e['ts'])) {
                $this->entries[] = ['path' => (string)$e['path'], 'group' => (string)$e['group'], 'ts' => (int)$e['ts']];
            }
        }
        $this->dropped = max(0, (int)($data['dropped'] ?? 0));
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
            $this->entries[] = ['path' => (string)$path, 'group' => Analyzer::groupOf((string)$path, $nested), 'ts' => $ts];
        }
        $extra = count($this->entries) - self::CAP;
        if ($extra > 0) {
            $this->entries = array_slice($this->entries, $extra);
            $this->dropped += $extra;
        }
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
