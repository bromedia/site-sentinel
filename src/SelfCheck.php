<?php
declare(strict_types=1);

namespace Sentinel;

final class SelfCheck
{
    private $state;
    /** @var array<string,string> */
    private $files;
    /** @var string[] labels found changed by the last check() */
    private $untrusted = [];

    /** @param array<string,string> $files label => absolute path */
    public function __construct(State $state, array $files)
    {
        $this->state = $state;
        $this->files = $files;
    }

    /**
     * The recorded map is the whole truth: a label recorded as '' (or not recorded at all)
     * means the file was absent, so a file that appears later, such as a hand-placed
     * rules.json or dismissals.json, is flagged like any other change.
     *
     * @return Finding[]
     */
    public function check(): array
    {
        $stored = $this->state->readJson('selfcheck.json');
        $this->untrusted = [];
        if (!$this->files) {
            return [];
        }
        if ($stored === []) {
            // Written at setup and only rewritten by Sentinel, so on an installed site an empty
            // or unreadable record means it was lost or tampered with. Re-recording it here would
            // trust whatever rules or dismissals file sits next to it, so nothing is trusted until
            // someone reviews the files and runs accept --self.
            foreach ($this->files as $label => $path) {
                if (self::hashOf($path) !== '') {
                    $this->untrusted[] = (string)$label;
                }
            }
            return [new Finding(
                Finding::CRITICAL,
                'sentinel',
                'self-tamper',
                "Sentinel's record of its own files (selfcheck.json) is missing or unreadable, so its rules and dismissals are not trusted; review them, then run accept --self",
                sha1('selfcheck-missing|' . implode(',', array_map([self::class, 'hashOf'], array_values($this->files))))
            )];
        }
        $out = [];
        foreach ($this->files as $label => $path) {
            $was = (string)($stored[$label] ?? '');
            $now = self::hashOf($path);
            if ($now === $was) {
                continue;
            }
            $this->untrusted[] = (string)$label;
            if ($was === '') {
                $message = 'Sentinel file appeared since the Sentinel files were last accepted';
            } elseif ($now === '') {
                $message = 'Sentinel file is missing';
            } else {
                $message = 'Sentinel file changed since it was last accepted';
            }
            $out[] = new Finding(Finding::CRITICAL, $label . ' (' . $path . ')', 'self-tamper', $message, $now);
        }
        return $out;
    }

    /**
     * Whether one tracked file is exactly as last trusted. A label never recorded counts as
     * absent, so a file that has appeared since is not trusted. Before the first record of
     * all, nothing has been trusted yet and an absent file is fine.
     */
    public function isTrusted(string $label): bool
    {
        if (!isset($this->files[$label])) {
            throw new \InvalidArgumentException("unknown Sentinel file '$label'");
        }
        $stored = $this->state->readJson('selfcheck.json');
        return self::hashOf($this->files[$label]) === (string)($stored[$label] ?? '');
    }

    /** @return string[] labels of the files the last check() found changed, missing or new */
    public function untrusted(): array
    {
        return $this->untrusted;
    }

    /**
     * What has changed since the files were last trusted, without recording anything.
     *
     * @return array<string,string> label => 'changed' | 'appeared' | 'missing'
     */
    public function changes(): array
    {
        $stored = $this->state->readJson('selfcheck.json');
        $out = [];
        foreach ($this->files as $label => $path) {
            $was = (string)($stored[$label] ?? '');
            $now = self::hashOf($path);
            if ($now !== $was) {
                $out[(string)$label] = $was === '' ? 'appeared' : ($now === '' ? 'missing' : 'changed');
            }
        }
        return $out;
    }

    /** Trusts the current state of every tracked file (accept --self, init). */
    public function record(): void
    {
        $map = [];
        foreach ($this->files as $label => $path) {
            $map[$label] = self::hashOf($path);
        }
        $this->state->writeJson('selfcheck.json', $map);
    }

    /**
     * Trusts the current state of one file that Sentinel itself just wrote (rules, dismissals),
     * leaving the others alone so an unrelated tampered file stays flagged.
     */
    public function trust(string $label): void
    {
        if (!isset($this->files[$label])) {
            throw new \InvalidArgumentException("unknown Sentinel file '$label'");
        }
        $map = $this->state->readJson('selfcheck.json');
        $map[$label] = self::hashOf($this->files[$label]);
        $this->state->writeJson('selfcheck.json', $map);
    }

    private static function hashOf(string $path): string
    {
        return is_file($path) ? (string)hash_file('sha256', $path) : '';
    }
}
