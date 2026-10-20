<?php
declare(strict_types=1);

namespace Sentinel;

/**
 * Reviewed false positives. A dismissal covers one detection rule on one file with one exact
 * content (sha256), so any change to the file, or a different rule matching it, alerts again.
 * Each entry records who dismissed it, when and why. The file is tracked by SelfCheck, so an
 * entry added by hand rather than through "dismiss" raises a Critical self-tamper finding.
 */
final class Dismissals
{
    public const FILE = 'dismissals.json';

    /** Changes and Sentinel's own problems are resolved with accept or by fixing them, not dismissed. */
    private const NOT_DISMISSABLE = [
        'unexplained-change', 'unverified-update', 'sensitive-file-changed', 'sensitive-file-removed',
        'core-file-removed', 'symlink', 'world-writable', 'stealth-modification', 'self-tamper',
        'run-error', 'state-write-failed', 'unreadable', 'unreadable-dir', 'scan-error', 'setup',
    ];

    private const REASON_MAX = 500;
    private const UNTRUSTED = 'dismissals.json was changed outside the dismiss command.';

    private $state;
    /** @var array[] */
    private $entries;

    public function __construct(State $state)
    {
        $this->state = $state;
        $raw = $state->readJson(self::FILE);
        $this->entries = array_values(array_filter((array)($raw['dismissals'] ?? []), function ($e) {
            return is_array($e) && isset($e['rule'], $e['path'], $e['sha256']);
        }));
    }

    /** Whether this kind of finding can be dismissed at all (it must also be pinned to content). */
    public static function dismissable(Finding $f): bool
    {
        return $f->hash !== '' && !in_array($f->rule, self::NOT_DISMISSABLE, true);
    }

    public function covers(Finding $f): bool
    {
        if (!self::dismissable($f)) {
            return false;
        }
        foreach ($this->entries as $e) {
            if ($e['rule'] === $f->rule && $e['path'] === $f->path && $e['sha256'] === $f->hash) {
                return true;
            }
        }
        return false;
    }

    public function count(): int
    {
        return count($this->entries);
    }

    /**
     * The "dismiss" command: dismiss <id> --reason=TEXT | --list | --remove=<id>
     *
     * @param array<string,mixed> $opts from Cli::parse
     * @param array<string,string> $selfFiles
     * @return array{exit:int, lines:string[]}
     */
    public static function run(Config $config, State $state, array $opts, array $selfFiles): array
    {
        if (!empty($opts['list'])) {
            $lines = (new self($state))->listLines($config);
            if (!(new SelfCheck($state, $selfFiles))->isTrusted('dismissals')) {
                array_unshift($lines, 'WARNING: ' . self::UNTRUSTED . ' These entries are not being applied.');
                return ['exit' => 1, 'lines' => $lines];
            }
            return ['exit' => 0, 'lines' => $lines];
        }
        // Same lock as scans, so the file that is checked is the file that is changed.
        try {
            $lock = Lock::acquire($state->path('lock'));
        } catch (\Throwable $e) {
            return self::fail($e->getMessage());
        }
        if ($lock === null) {
            return self::fail('a scan is running; try again when it has finished');
        }
        try {
            // Saving re-trusts the whole file, so a file changed by hand must never be saved over:
            // a forged entry in it would become trusted along with the real one.
            if (!(new SelfCheck($state, $selfFiles))->isTrusted('dismissals')) {
                return self::fail(self::UNTRUSTED . ' Nothing was changed. Review it with dismiss --list; run accept --self only if you made that change, otherwise delete the file and run accept --self.');
            }
            $d = new self($state);
            if (isset($opts['remove'])) {
                return $d->remove($config, (string)$opts['remove'], $selfFiles);
            }
            $id = strtolower((string)($opts['_'][0] ?? ''));
            return $d->dismiss($config, $id, is_string($opts['reason'] ?? null) ? $opts['reason'] : '', $selfFiles);
        } finally {
            $lock->release();
        }
    }

    private function dismiss(Config $config, string $id, string $reason, array $selfFiles): array
    {
        if (!preg_match('/^[0-9a-f]{8,40}$/', $id)) {
            return self::fail('usage: dismiss <id> --reason="why this is harmless" (the id is shown next to the finding in alerts and check output)');
        }
        $reason = trim((string)preg_replace('/[\x00-\x1F\x7F]+/', ' ', $reason));
        if ($reason === '') {
            return self::fail('a --reason is required, so the dismissal can be audited later');
        }
        if (strlen($reason) > self::REASON_MAX) {
            return self::fail('--reason is limited to ' . self::REASON_MAX . ' characters');
        }
        $matches = [];
        foreach ((new AlertLog($this->state))->entries() as $key => $e) {
            if (strpos((string)$key, $id) === 0 && isset($e['rule'], $e['path'], $e['hash'])) {
                // The alert log is not tamper-checked, so an entry counts only if its fields really
                // produce its id: otherwise a forged entry could turn this id into a dismissal of
                // some other file.
                $f = new Finding(Finding::WARNING, (string)$e['path'], (string)$e['rule'], '', (string)$e['hash']);
                if ($f->key() === (string)$key) {
                    $matches[(string)$key] = $e;
                }
            }
        }
        if (!$matches) {
            return self::fail("no reported finding has id $id; ids are shown next to findings in alerts and check output");
        }
        if (count($matches) > 1) {
            return self::fail("id $id is ambiguous; use more of its characters");
        }
        $key = (string)array_keys($matches)[0];
        $e = $matches[$key];
        $f = new Finding((int)($e['sev'] ?? Finding::WARNING), (string)$e['path'], (string)$e['rule'], (string)($e['message'] ?? ''), (string)$e['hash']);
        if (!self::dismissable($f)) {
            return self::fail("'{$f->rule}' findings cannot be dismissed: review the change and use accept --path=..., or fix the cause");
        }
        $current = is_file($config->abs($f->path)) ? (string)@hash_file('sha256', $config->abs($f->path)) : '';
        if ($current !== $f->hash) {
            return self::fail("{$f->path} has changed (or is gone) since this finding was reported; run check and review it again");
        }
        if ($this->covers($f)) {
            return ['exit' => 0, 'lines' => ["already dismissed: {$f->rule} on {$f->path}"]];
        }
        $this->entries[] = [
            'id' => substr($key, 0, 12),
            'rule' => $f->rule,
            'path' => $f->path,
            'sha256' => $f->hash,
            'severity' => Finding::label($f->severity),
            'message' => $f->message,
            'reason' => $reason,
            'by' => self::who(),
            'at' => time(),
        ];
        $this->save($selfFiles);
        return ['exit' => 0, 'lines' => [
            sprintf('dismissed %s: %s on %s', substr($key, 0, 12), $f->rule, $f->path),
            'It stays dismissed only while the file content is unchanged; any change, or another rule matching, alerts again.',
        ]];
    }

    private function remove(Config $config, string $id, array $selfFiles): array
    {
        $id = strtolower($id);
        if (!preg_match('/^[0-9a-f]{8,40}$/', $id)) {
            return self::fail('usage: dismiss --remove=<id> (see dismiss --list)');
        }
        $keep = [];
        $removed = [];
        foreach ($this->entries as $e) {
            $key = self::keyOf($e);
            if (strpos($key, $id) === 0) {
                $removed[$key] = $e;
            } else {
                $keep[] = $e;
            }
        }
        if (!$removed) {
            return self::fail("no dismissal has id $id (see dismiss --list)");
        }
        if (count($removed) > 1) {
            return self::fail("id $id is ambiguous; use more of its characters");
        }
        $key = (string)array_keys($removed)[0];
        $e = $removed[$key];
        $path = (string)$e['path'];
        // Scans only analyse files that changed, and this one may have been accepted since it was
        // dismissed. Taking it out of the baseline makes the next scan treat it as a new file, so
        // it gets every check a new file gets, and it stays out of the baseline until those
        // checks have really run and it is reviewed again.
        // Order matters: each step can fail, and until the last one the dismissal is still in
        // place, so the command can simply be run again.
        $baseline = $this->state->path('baseline.txt');
        if (is_file($baseline)) {
            Baseline::applyUpdates($baseline, [$path => null], $baseline);
        }
        (new AlertLog($this->state))->forget($key); // so it alerts again when next detected
        $this->entries = $keep;
        $this->save($selfFiles);
        return ['exit' => 0, 'lines' => [sprintf('removed dismissal %s: %s on %s; the next scan examines the file again as a new file', substr($key, 0, 12), $e['rule'], $path)]];
    }

    /** @return string[] */
    private function listLines(Config $config): array
    {
        if (!$this->entries) {
            return ['no dismissed findings'];
        }
        $lines = [];
        foreach ($this->entries as $e) {
            $abs = $config->abs((string)$e['path']);
            $applies = is_file($abs) && (string)@hash_file('sha256', $abs) === $e['sha256'];
            $lines[] = sprintf(
                '%s  %s %s on %s%s',
                substr(self::keyOf($e), 0, 12),
                (string)($e['severity'] ?? ''),
                $e['rule'],
                $e['path'],
                $applies ? '' : '  (file changed or removed: no longer applies)'
            );
            $lines[] = sprintf('    by %s on %s UTC: %s', (string)($e['by'] ?? '?'), gmdate('Y-m-d H:i', (int)($e['at'] ?? 0)), (string)($e['reason'] ?? ''));
        }
        return $lines;
    }

    private function save(array $selfFiles): void
    {
        $this->state->writeJson(self::FILE, ['dismissals' => $this->entries]);
        (new SelfCheck($this->state, $selfFiles))->trust('dismissals');
    }

    private static function keyOf(array $e): string
    {
        return (new Finding(Finding::WARNING, (string)$e['path'], (string)$e['rule'], '', (string)$e['sha256']))->key();
    }

    private static function who(): string
    {
        if (function_exists('posix_getpwuid') && function_exists('posix_geteuid')) {
            $pw = @posix_getpwuid(posix_geteuid());
            if (is_array($pw) && ($pw['name'] ?? '') !== '') {
                return (string)$pw['name'];
            }
        }
        $u = (string)getenv('USER');
        return $u !== '' ? $u : (string)get_current_user();
    }

    private static function fail(string $message): array
    {
        return ['exit' => 2, 'lines' => ['error: ' . $message]];
    }
}
