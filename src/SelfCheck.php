<?php
declare(strict_types=1);

namespace Sentinel;

final class SelfCheck
{
    private $state;
    /** @var array<string,string> */
    private $files;

    /** @param array<string,string> $files label => absolute path */
    public function __construct(State $state, array $files)
    {
        $this->state = $state;
        $this->files = $files;
    }

    /** @return Finding[] */
    public function check(): array
    {
        $stored = $this->state->readJson('selfcheck.json');
        if ($stored === []) {
            $this->record();
            return [];
        }
        $out = [];
        foreach ($this->files as $label => $path) {
            $was = $stored[$label] ?? null;
            if ($was === null) {
                continue;
            }
            $now = is_file($path) ? (string)hash_file('sha256', $path) : '';
            if ($now !== $was) {
                $out[] = new Finding(
                    Finding::CRITICAL,
                    $label . ' (' . $path . ')',
                    'self-tamper',
                    $now === '' ? 'Sentinel file is missing' : 'Sentinel file changed since it was last accepted',
                    $now
                );
            }
        }
        return $out;
    }

    public function record(): void
    {
        $map = [];
        foreach ($this->files as $label => $path) {
            if (is_file($path)) {
                $map[$label] = (string)hash_file('sha256', $path);
            }
        }
        $this->state->writeJson('selfcheck.json', $map);
    }
}
