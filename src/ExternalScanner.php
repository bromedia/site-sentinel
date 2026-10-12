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

    public function __construct(?string $clamscan, ?string $yara, ?string $yaraRules)
    {
        $this->clamscan = $clamscan;
        $this->yara = $yara !== null && $yaraRules !== null && $yaraRules !== '' ? $yara : null;
        $this->yaraRules = $yaraRules;
    }

    public static function fromConfig(Config $c): ExternalScanner
    {
        $clam = $c->clamscanPath !== '' ? $c->clamscanPath : self::find('clamscan');
        $yara = $c->yaraPath !== '' ? $c->yaraPath : self::find('yara');
        if ($clam !== null && !is_executable($clam)) {
            $clam = null;
        }
        if ($yara !== null && (!is_executable($yara) || $c->yaraRules === '' || !is_file($c->yaraRules))) {
            $yara = null;
        }
        return new ExternalScanner($clam, $yara, $c->yaraRules);
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
        $this->errors = [];
        if (!$files || !$this->enabled()) {
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
