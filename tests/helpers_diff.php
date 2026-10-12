<?php
declare(strict_types=1);

function bigBudget(): \Sentinel\Budget
{
    return new \Sentinel\Budget(3600.0, PHP_INT_MAX);
}

/** Writes a complete baseline of the current tree (every change accepted). */
function snapshot(\Sentinel\Config $c, string $baselineFile): void
{
    $d = (new \Sentinel\Differ($c))->diff($baselineFile, '', bigBudget(), true);
    $u = [];
    foreach ($d['changes'] as $ch) {
        $u[$ch['path']] = in_array($ch['type'], ['removed', 'dropped'], true) ? null : $ch['new'];
    }
    \Sentinel\Baseline::applyUpdates($baselineFile, $u, $baselineFile);
}

/** Full-budget diff; returns changes keyed by path. */
function diffByPath(\Sentinel\Config $c, string $baselineFile, bool $full = false): array
{
    $out = [];
    foreach ((new \Sentinel\Differ($c))->diff($baselineFile, '', bigBudget(), $full)['changes'] as $ch) {
        $out[$ch['path']] = $ch;
    }
    return $out;
}

/** Rewrites a file with a distinct mtime so stat-based detection notices. */
function bump(string $root, string $rel, string $content, int $secondsAhead = 100): void
{
    file_put_contents($root . '/' . $rel, $content);
    touch($root . '/' . $rel, time() + $secondsAhead);
}
