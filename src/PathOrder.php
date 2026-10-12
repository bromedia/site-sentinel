<?php
declare(strict_types=1);

namespace Sentinel;

final class PathOrder
{
    /** Compares two relative paths segment by segment, in byte order. */
    public static function compare(string $a, string $b): int
    {
        if ($a === $b) {
            return 0;
        }
        $pa = explode('/', $a);
        $pb = explode('/', $b);
        $n = min(count($pa), count($pb));
        for ($i = 0; $i < $n; $i++) {
            $c = strcmp($pa[$i], $pb[$i]);
            if ($c !== 0) {
                return $c < 0 ? -1 : 1;
            }
        }
        return count($pa) <=> count($pb);
    }
}
