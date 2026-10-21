<?php
declare(strict_types=1);

namespace Sentinel;

final class Accept
{
    /**
     * @param string[] $paths relative paths to accept (a directory accepts everything below it); empty = everything
     * @param array<string,string> $selfFiles
     * @return array{exit:int, lines:string[]}
     */
    public static function run(Config $config, State $state, array $paths, bool $self, array $selfFiles): array
    {
        if ($self) {
            // Say exactly what becomes trusted: after an upgrade this is the routine answer to the
            // self-tamper alert, and it must not quietly bless a rules or dismissals file too.
            $check = new SelfCheck($state, $selfFiles);
            $changes = $check->changes();
            $check->record();
            $lines = ['recorded the current Sentinel files as trusted'];
            foreach ($changes as $label => $what) {
                $lines[] = sprintf('  %s (%s): %s since it was last trusted', $label, $selfFiles[$label], $what);
            }
            if (!$changes) {
                $lines[] = '  (nothing had changed)';
            }
            return ['exit' => 0, 'lines' => $lines];
        }
        $baselineFile = $state->path('baseline.txt');
        if (!is_file($baselineFile)) {
            return ['exit' => 2, 'lines' => ['no baseline found; run "init" first']];
        }
        $paths = array_values(array_filter(array_map(function ($p) {
            return trim((string)$p, '/');
        }, $paths), function ($p) {
            return $p !== '';
        }));

        $d = (new Differ($config))->diff($baselineFile, '', new Budget(86400.0, PHP_INT_MAX), true);
        $updates = [];
        foreach ($d['changes'] as $c) {
            if ($paths && !self::wanted((string)$c['path'], $paths)) {
                continue;
            }
            $updates[$c['path']] = in_array($c['type'], ['removed', 'dropped'], true) ? null : $c['new'];
        }
        if ($updates) {
            Baseline::applyUpdates($baselineFile, $updates, $baselineFile);
        }

        if ($config->hasWordPress()) {
            $current = VersionTracker::read($config);
            if (!$paths) {
                $state->writeJson('versions.json', $current);
            } else {
                $store = $state->readJson('versions.json');
                foreach ($current as $g => $v) {
                    foreach ($paths as $p) {
                        if ($p === $g || strpos($p, $g . '/') === 0 || strpos($g, $p . '/') === 0) {
                            $store[$g] = $v;
                        }
                    }
                }
                $state->writeJson('versions.json', $store);
            }
        }
        @unlink($state->path('resume.json'));
        if (!$paths) {
            (new AlertLog($state))->clear();
        }
        return ['exit' => 0, 'lines' => [sprintf('accepted %d change(s)', count($updates))]];
    }

    private static function wanted(string $path, array $paths): bool
    {
        foreach ($paths as $p) {
            if ($path === $p || strpos($path, $p . '/') === 0) {
                return true;
            }
        }
        return false;
    }
}
