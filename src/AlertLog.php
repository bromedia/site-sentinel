<?php
declare(strict_types=1);

namespace Sentinel;

final class AlertLog
{
    private const FORGET_AFTER = 604800; // 7 days

    private $state;
    /** @var array<string,array{first:int,alerted:int,seen:int,sev:int}> */
    private $entries;

    public function __construct(State $state)
    {
        $this->state = $state;
        $this->entries = $state->readJson('alerts.json');
    }

    /**
     * @param Finding[] $findings
     * @return Finding[] findings that should be alerted now
     */
    public function due(array $findings, int $now, int $remindSeconds): array
    {
        $out = [];
        foreach ($findings as $f) {
            if ($f->severity < Finding::WARNING) {
                continue;
            }
            $e = $this->entries[$f->key()] ?? null;
            if ($e === null || (int)$e['alerted'] === 0) {
                $out[] = $f;
            } elseif ($f->severity >= Finding::CRITICAL && $now - (int)$e['alerted'] >= $remindSeconds) {
                $out[] = $f;
            }
        }
        return $out;
    }

    /**
     * @param Finding[] $current every finding seen this run
     * @param Finding[] $sent the ones an alert was successfully sent for
     */
    public function commit(array $current, array $sent, int $now): void
    {
        $sentKeys = [];
        foreach ($sent as $f) {
            $sentKeys[$f->key()] = true;
        }
        foreach ($current as $f) {
            $k = $f->key();
            $e = $this->entries[$k] ?? ['first' => $now, 'alerted' => 0, 'seen' => $now, 'sev' => $f->severity];
            $e['seen'] = $now;
            if (isset($sentKeys[$k])) {
                $e['alerted'] = $now;
            }
            $this->entries[$k] = $e;
        }
        foreach ($this->entries as $k => $e) {
            if ($now - (int)$e['seen'] > self::FORGET_AFTER) {
                unset($this->entries[$k]);
            }
        }
        $this->state->writeJson('alerts.json', $this->entries);
    }

    public function clear(): void
    {
        $this->entries = [];
        $this->state->writeJson('alerts.json', []);
    }
}
