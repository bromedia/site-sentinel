<?php
declare(strict_types=1);

namespace Sentinel;

/**
 * Files reported as possible hacking whose report nobody has resolved yet. While a plugin or theme
 * has one, a version change does not explain its changes and its version is not recorded:
 * otherwise replacing the detected code with code no pattern catches and raising the version would
 * pass as an update. A detection is resolved by review (accept --path, or dismissing every rule on
 * that exact content) or by the file verifying against the official WordPress.org copy. Removing or
 * editing the file does not resolve it: anyone who can write the site's files can do that.
 */
final class Detections
{
    public const FILE = 'detections.json';

    private $state;
    /** @var array<string,array{sha256:string,rules:string[],severity:int,first:int}> path => entry */
    private $entries;
    private $changed = false;

    public function __construct(State $state)
    {
        $this->state = $state;
        $this->entries = array_filter($state->readJson(self::FILE), function ($e) {
            return is_array($e) && isset($e['sha256'], $e['rules']) && is_array($e['rules']);
        });
    }

    /** @return array<string,array{sha256:string,rules:string[],severity:int,first:int}> */
    public function all(): array
    {
        return $this->entries;
    }

    /**
     * The latest detection on a path replaces an earlier one, so reviewing what is there now is
     * what resolves it. The highest severity seen is kept until it is resolved, so a Critical that
     * is later rewritten into something that only raises a Warning, or nothing, stays Critical.
     *
     * @param string[] $rules
     */
    public function record(string $path, string $sha256, array $rules, int $severity, int $now): void
    {
        $rules = array_values(array_unique($rules));
        sort($rules);
        $old = $this->entries[$path] ?? null;
        $severity = max($severity, (int)($old['severity'] ?? $severity));
        if ($old !== null && $old['sha256'] === $sha256 && $old['rules'] === $rules && (int)($old['severity'] ?? -1) === $severity) {
            return;
        }
        $this->entries[$path] = ['sha256' => $sha256, 'rules' => $rules, 'severity' => $severity, 'first' => (int)($old['first'] ?? $now)];
        $this->changed = true;
    }

    /**
     * Only files of a plugin or theme whose version is tracked are remembered: a version change
     * explains nothing anywhere else, so a detection there needs no memory beyond its own alert.
     */
    public static function tracked(Config $config, string $path): bool
    {
        $group = Analyzer::groupOf($path, $config->nestedWordPress);
        foreach ($config->wordpressInstalls() as $prefix) {
            if (preg_match('#^' . preg_quote($prefix === '' ? '' : $prefix . '/', '#') . 'wp-content/(?:plugins|themes)/[^/]+$#', $group)) {
                return true;
            }
        }
        return false;
    }

    public function resolve(string $path): void
    {
        if (isset($this->entries[$path])) {
            unset($this->entries[$path]);
            $this->changed = true;
        }
    }

    /** Whether every rule of a path's detection is dismissed for exactly that content. */
    public function dismissed(string $path, Dismissals $dismissals): bool
    {
        $e = $this->entries[$path] ?? null;
        if ($e === null || !$e['rules']) {
            return false;
        }
        foreach ($e['rules'] as $rule) {
            if (!$dismissals->covers(new Finding(Finding::CRITICAL, $path, (string)$rule, '', $e['sha256']))) {
                return false;
            }
        }
        return true;
    }

    /** @return array<string,bool> plugins and themes (Analyzer::groupOf) with an unresolved detection */
    public function groups(array $nested): array
    {
        $out = [];
        foreach (array_keys($this->entries) as $path) {
            $out[Analyzer::groupOf((string)$path, $nested)] = true;
        }
        return $out;
    }

    public function save(): void
    {
        if ($this->changed) {
            $this->state->writeJson(self::FILE, $this->entries);
            $this->changed = false;
        }
    }
}
