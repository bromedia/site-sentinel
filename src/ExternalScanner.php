<?php
declare(strict_types=1);

namespace Sentinel;

final class ExternalScanner
{
    private const CLAM_CHUNK = 100;
    private const YARA_MAX_FILES = 200;

    private $clamscan;
    private $yara;
    private $yaraRules;
    /** @var string[] */
    private $errors = [];
    private $disabledNote;
    /** @var string[] configured scanners that cannot run, reported with every scan */
    private $unavailable;

    /** @param string[] $unavailable */
    public function __construct(?string $clamscan, ?string $yara, ?string $yaraRules, ?string $disabledNote = null, array $unavailable = [])
    {
        $this->disabledNote = $disabledNote;
        $this->unavailable = $unavailable;
        $this->clamscan = $clamscan;
        $this->yara = $yara !== null && $yaraRules !== null && $yaraRules !== '' ? $yara : null;
        $this->yaraRules = $yaraRules;
    }

    public static function fromConfig(Config $c): ExternalScanner
    {
        $clam = $c->clamscanPath !== '' ? $c->clamscanPath : self::find('clamscan');
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
        if (($clam !== null || $yara !== null) && !Proc::available()) {
            return new ExternalScanner(null, null, null, 'ClamAV/YARA found but proc_open is disabled on this host; external scanning skipped', $unavailable);
        }
        return new ExternalScanner($clam, $yara, $c->yaraRules, null, $unavailable);
    }

    public static function find(string $bin): ?string
    {
        foreach (explode(PATH_SEPARATOR, (string)getenv('PATH')) as $dir) {
            $p = rtrim($dir, '/') . '/' . $bin;
            if ($dir !== '' && is_file($p) && is_executable($p)) {
                return $p;
            }
        }
        return null;
    }

    public function enabled(): bool
    {
        return $this->clamscan !== null || $this->yara !== null;
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
        if ($this->clamscan !== null) {
            foreach (array_chunk(array_keys($byAbs), self::CLAM_CHUNK) as $chunk) {
                $r = Proc::run(array_merge([$this->clamscan, '--no-summary', '--infected', '--'], $chunk), 300);
                if ($r['timed_out'] || ($r['exit'] !== 0 && $r['exit'] !== 1)) {
                    $this->errors[] = 'clamscan failed (' . ($r['timed_out'] ? 'timed out' : 'exit ' . $r['exit']) . '): ' . $this->firstLine($r['err']);
                    continue;
                }
                foreach (explode("\n", $r['out']) as $line) {
                    if (preg_match('/^(.*): (.+) FOUND$/', $line, $m) && isset($byAbs[$m[1]])) {
                        $out[] = new Finding(Finding::CRITICAL, $byAbs[$m[1]], 'clamav:' . $m[2], 'ClamAV signature match: ' . $m[2]);
                    }
                }
            }
        }
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

    private function firstLine(string $s): string
    {
        $s = trim($s);
        $p = strpos($s, "\n");
        return $p === false ? $s : substr($s, 0, $p);
    }
}
