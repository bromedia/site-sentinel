<?php
declare(strict_types=1);

namespace Sentinel;

final class PatternScanner
{
    private $rules;
    private $maxBytes;

    public function __construct(Rules $rules, int $maxBytes)
    {
        $this->rules = $rules;
        $this->maxBytes = $maxBytes;
    }

    /** @return Finding[] */
    public function scan(string $rel, string $abs, string $sha256): array
    {
        $out = [];
        if ($sha256 !== '' && ($name = $this->rules->badHash($sha256)) !== null) {
            $out[] = new Finding(Finding::CRITICAL, $rel, 'bad-hash', 'Matches a known-bad file hash: ' . $name, $sha256);
        }
        $content = self::headTail($abs, $this->maxBytes);
        if ($content === null) {
            return $out;
        }
        foreach ($this->rules->matchContent($content) as $p) {
            $sev = $p['severity'] === 'critical' ? Finding::CRITICAL : Finding::WARNING;
            $out[] = new Finding($sev, $rel, $p['id'], $p['description'], $sha256);
        }
        return $out;
    }

    /**
     * The whole file if it fits in $maxBytes, otherwise its first and last
     * half-budget joined by a newline (attackers append payloads to big files).
     */
    public static function headTail(string $abs, int $maxBytes): ?string
    {
        $size = @filesize($abs);
        $fh = $size === false ? false : @fopen($abs, 'rb');
        if ($fh === false) {
            return null;
        }
        if ($size <= $maxBytes) {
            $c = stream_get_contents($fh);
        } else {
            $half = intdiv($maxBytes, 2);
            $head = (string)fread($fh, $half);
            fseek($fh, -$half, SEEK_END);
            $c = $head . "\n" . (string)fread($fh, $half);
        }
        fclose($fh);
        return $c === false ? null : $c;
    }
}
