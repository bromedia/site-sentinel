<?php
declare(strict_types=1);

namespace Sentinel;

final class PathFilter
{
    /** @var string[] */
    private $regexes = [];

    public function __construct(array $patterns)
    {
        foreach ($patterns as $p) {
            $p = trim((string)$p);
            if ($p !== '') {
                $this->regexes[] = self::toRegex($p);
            }
        }
    }

    public function matches(string $rel): bool
    {
        foreach ($this->regexes as $re) {
            if (preg_match($re, $rel) === 1) {
                return true;
            }
        }
        return false;
    }

    private static function toRegex(string $p): string
    {
        $isDir = substr($p, -1) === '/';
        $leading = $p[0] === '/';
        $p = trim($p, '/');
        $anchored = $leading || strpos($p, '/') !== false;
        $out = '';
        $len = strlen($p);
        for ($i = 0; $i < $len; $i++) {
            $c = $p[$i];
            if ($c === '*') {
                if (substr($p, $i, 3) === '**/') {
                    $out .= '(?:.*/)?';
                    $i += 2;
                } elseif (substr($p, $i, 2) === '**') {
                    $out .= '.*';
                    $i += 1;
                } else {
                    $out .= '[^/]*';
                }
            } elseif ($c === '?') {
                $out .= '[^/]';
            } else {
                $out .= preg_quote($c, '#');
            }
        }
        $head = $anchored ? '^' : '(?:^|/)';
        $tail = $isDir ? '(?:/.*)?' : '';
        return '#' . $head . $out . $tail . '$#s';
    }
}
