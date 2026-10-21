<?php
declare(strict_types=1);

namespace Sentinel;

final class ExternalScanner
{
    private const CLAM_CHUNK = 100;
    private const YARA_MAX_FILES = 200;

    private $clamscan;
    /** clamdscan, preferred: the host's clamd service scans with its own, already loaded database. */
    private $clamdscan;
    private $yara;
    private $yaraRules;
    /** @var string[] */
    private $errors = [];
    private $disabledNote;
    /** @var string[] configured scanners that cannot run, reported with every scan */
    private $unavailable;

    /** @param string[] $unavailable */
    public function __construct(?string $clamscan, ?string $yara, ?string $yaraRules, ?string $disabledNote = null, array $unavailable = [], ?string $clamdscan = null)
    {
        $this->disabledNote = $disabledNote;
        $this->unavailable = $unavailable;
        $this->clamscan = $clamscan;
        $this->clamdscan = $clamdscan;
        $this->yara = $yara !== null && $yaraRules !== null && $yaraRules !== '' ? $yara : null;
        $this->yaraRules = $yaraRules;
    }

    public static function fromConfig(Config $c): ExternalScanner
    {
        $clam = $c->clamscanPath !== '' ? $c->clamscanPath : self::find('clamscan');
        // clamdscan is looked for on PATH only when clamscan_path does not pin plain clamscan.
        $clamd = $c->clamdscanPath !== '' ? $c->clamdscanPath : ($c->clamscanPath === '' ? self::find('clamdscan') : null);
        $yara = $c->yaraPath !== '' ? $c->yaraPath : self::find('yara');
        // A scanner the config asks for but that cannot run is said so on every scan; otherwise its
        // findings would simply stop, which looks exactly like a clean result.
        $unavailable = [];
        if ($clam !== null && !is_executable($clam)) {
            $clam = null;
        }
        if ($clam === null && $c->clamscanPath !== '') {
            $unavailable[] = "clamscan_path is set but {$c->clamscanPath} cannot be run; ClamAV scanning skipped";
        }
        if ($clamd !== null && !is_executable($clamd)) {
            $clamd = null;
        }
        if ($clamd === null && $c->clamdscanPath !== '') {
            $unavailable[] = "clamdscan_path is set but {$c->clamdscanPath} cannot be run; the clamd service is not used";
        }
        $yaraWanted = $c->yaraPath !== '' || $c->yaraRules !== '';
        if ($yara === null || !is_executable($yara)) {
            if ($yaraWanted) {
                $unavailable[] = 'YARA is configured but its program ' . ($c->yaraPath !== '' ? $c->yaraPath : '(yara, not found on PATH)') . ' cannot be run; YARA scanning skipped';
            }
            $yara = null;
        } elseif ($c->yaraRules === '' || !is_file($c->yaraRules)) {
            if ($yaraWanted) {
                $unavailable[] = 'YARA is configured but its rules file ' . ($c->yaraRules !== '' ? $c->yaraRules : '(yara_rules is not set)') . ' is missing; YARA scanning skipped';
            }
            $yara = null;
        }
        if (($clam !== null || $clamd !== null || $yara !== null) && !Proc::available()) {
            return new ExternalScanner(null, null, null, 'ClamAV/YARA found but proc_open is disabled on this host; external scanning skipped', $unavailable);
        }
        return new ExternalScanner($clam, $yara, $c->yaraRules, null, $unavailable, $clamd);
    }

    /** Which ClamAV programs a scan will use, for doctor (nothing is run). */
    public function describeClamav(): string
    {
        if ($this->clamdscan !== null) {
            return 'ClamAV: the clamd service through ' . $this->clamdscan . ($this->clamscan !== null ? ', falling back to ' . $this->clamscan : '') . '; whether it can scan is checked on the next scan';
        }
        if ($this->clamscan !== null) {
            return 'ClamAV: ' . $this->clamscan . ' (no clamd service found); whether it can scan is checked on the next scan';
        }
        return $this->disabledNote !== null ? 'ClamAV: not used (' . $this->disabledNote . ')' : 'ClamAV: not found (optional)';
    }

    public static function find(string $bin): ?string
    {
        foreach (explode(PATH_SEPARATOR, (string)getenv('PATH')) as $dir) {
            $p = rtrim($dir, '/') . '/' . $bin;
            // Quietly: under open_basedir (xneelo allows /usr/bin, not /bin) a PATH folder outside
            // it makes is_file() warn, and a warning in cron output becomes an email.
            if ($dir !== '' && @is_file($p) && @is_executable($p)) {
                return $p;
            }
        }
        return null;
    }

    /**
     * Configured scanners that cannot run on this host, known without running anything (for doctor).
     *
     * @return string[]
     */
    public function cannotRun(): array
    {
        return $this->disabledNote !== null ? array_merge($this->unavailable, [$this->disabledNote]) : $this->unavailable;
    }

    public function enabled(): bool
    {
        return $this->clamscan !== null || $this->clamdscan !== null || $this->yara !== null;
    }

    /** @return string[] */
    public function errors(): array
    {
        return $this->errors;
    }

    /**
     * @param array<int|string,string> $files rel => abs
     * @return Finding[]
     */
    public function scan(array $files): array
    {
        $this->errors = $files ? $this->unavailable : [];
        if (!$files || !$this->enabled()) {
            if ($files && $this->disabledNote !== null) {
                $this->errors[] = $this->disabledNote;
            }
            return [];
        }
        $byAbs = [];
        foreach ($files as $rel => $abs) {
            $byAbs[$abs] = (string)$rel;
        }
        $out = [];
        // clamd first, then clamscan. A program that cannot scan at all (no database, clamd not
        // reachable) is dropped for the rest of the run and said once, rather than once per chunk.
        $engines = array_filter(['clamdscan' => $this->clamdscan, 'clamscan' => $this->clamscan], 'is_string');
        $seen = [];
        foreach (array_chunk(array_keys($byAbs), self::CLAM_CHUNK) as $chunk) {
            if (!$engines) {
                break;
            }
            foreach ($engines as $name => $bin) {
                // Paths are absolute, so they cannot be read as options; clamdscan gets no "--".
                $cmd = $name === 'clamdscan' ? array_merge([$bin, '--fdpass', '--no-summary', '--infected'], $chunk) : array_merge([$bin, '--no-summary', '--infected', '--'], $chunk);
                $r = Proc::run($cmd, 300);
                foreach (explode("\n", $r['out']) as $line) {
                    if (preg_match('/^(.*): (.+) FOUND$/', $line, $m) && isset($byAbs[$m[1]]) && !isset($seen[$m[1] . "\0" . $m[2]])) {
                        $seen[$m[1] . "\0" . $m[2]] = true;
                        $out[] = new Finding(Finding::CRITICAL, $byAbs[$m[1]], 'clamav:' . $m[2], 'ClamAV signature match: ' . $m[2]);
                    }
                }
                if (!$r['timed_out'] && ($r['exit'] === 0 || $r['exit'] === 1)) {
                    break;
                }
                $unusable = self::cannotScan($name, $r);
                if ($unusable === null) {
                    // Some files could not be scanned (unreadable, too big); the rest were.
                    $this->errors[] = $name . ' failed (' . ($r['timed_out'] ? 'timed out' : 'exit ' . $r['exit']) . '): ' . $this->firstLine($r['err'] !== '' ? $r['err'] : $r['out']);
                    break;
                }
                $this->errors[] = $unusable;
                unset($engines[$name]); // the next program, if any, scans this chunk instead
            }
        }
        $this->errors = array_values(array_unique($this->errors));
        if ($this->yara !== null) {
            $n = 0;
            foreach ($byAbs as $abs => $rel) {
                if (++$n > self::YARA_MAX_FILES) {
                    $this->errors[] = 'yara skipped ' . (count($byAbs) - self::YARA_MAX_FILES) . ' file(s): per-run limit reached';
                    break;
                }
                $r = Proc::run([$this->yara, (string)$this->yaraRules, (string)$abs], 30);
                if ($r['timed_out'] || $r['exit'] !== 0) {
                    $this->errors[] = 'yara failed on ' . $rel . ' (' . ($r['timed_out'] ? 'timed out' : 'exit ' . $r['exit']) . '): ' . $this->firstLine($r['err']);
                    continue;
                }
                foreach (explode("\n", $r['out']) as $line) {
                    if (preg_match('/^(\S+)\s+(.+)$/', $line, $m)) {
                        $out[] = new Finding(Finding::CRITICAL, $rel, 'yara:' . $m[1], 'YARA rule match: ' . $m[1]);
                    }
                }
            }
        }
        return $out;
    }

    /**
     * Why a ClamAV program cannot scan anything this run, or null when only some files failed.
     *
     * @param array{exit:int, out:string, err:string, timed_out:bool} $r
     */
    private static function cannotScan(string $name, array $r): ?string
    {
        $text = $r['err'] . "\n" . $r['out'];
        if ($r['exit'] === -1 && !$r['timed_out']) {
            return "$name cannot be started ({$r['err']}); it is not used this run";
        }
        if ($name === 'clamdscan' && ($r['timed_out'] || preg_match('/connect|clamd|socket|ping/i', $text))) {
            return "ClamAV's scanning service (clamd) cannot be reached; it is not used this run";
        }
        if ($name === 'clamscan' && preg_match('/database|cli_load/i', $text)) {
            return 'ClamAV is installed but cannot read its virus database as this user (clamscan: ' . self::line($text) . '); clamscan is not used this run';
        }
        return null;
    }

    private static function line(string $s): string
    {
        $s = trim($s);
        $p = strpos($s, "\n");
        return $p === false ? $s : substr($s, 0, $p);
    }

    private function firstLine(string $s): string
    {
        $s = trim($s);
        $p = strpos($s, "\n");
        return $p === false ? $s : substr($s, 0, $p);
    }
}
