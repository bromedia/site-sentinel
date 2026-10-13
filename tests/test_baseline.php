<?php
declare(strict_types=1);

use Sentinel\Baseline;
use Sentinel\PathOrder;

function brec(string $path, int $size = 1, string $hash = ''): array
{
    return ['path' => $path, 'size' => $size, 'mtime' => 1700000000, 'mode' => 0100644, 'hash' => $hash];
}

t('Baseline round-trips odd file names (Review Focus 1)', function () {
    $f = tmpdir() . '/b.txt';
    $names = ['123', "a\tb.php", "line\nbreak.php", '100%25.txt', "ünï/çode.php", 'z', "cr\rname"];
    usort($names, [PathOrder::class, 'compare']);
    $recs = [];
    foreach ($names as $i => $n) {
        $recs[] = brec((string)$n, $i, $i % 2 ? str_repeat('a', 64) : '');
    }
    assertSame(count($recs), Baseline::write($f, $recs));
    assertSame($recs, iterator_to_array(Baseline::read($f), false));
    assertSame(0600, fileperms($f) & 0777);
});

t('Baseline::read of a missing file is empty and a corrupt line throws', function () {
    $dir = tmpdir();
    assertSame([], iterator_to_array(Baseline::read($dir . '/nope.txt'), false));
    file_put_contents($dir . '/bad.txt', "good\t1\t1\t100644\t\nthis line is garbage\n");
    assertThrows(RuntimeException::class, function () use ($dir) {
        iterator_to_array(Baseline::read($dir . '/bad.txt'), false);
    });
});

t('Baseline::applyUpdates inserts, replaces and deletes in order, including all-digit paths', function () {
    $f = tmpdir() . '/b.txt';
    Baseline::write($f, [brec('a'), brec('c'), brec('e')]);
    // '123' becomes the integer key 123 in a PHP array literal.
    Baseline::applyUpdates($f, ['e' => null, 'b' => brec('b'), 'c' => brec('c', 9), '123' => brec('123'), 'z' => brec('z')], $f);
    $recs = iterator_to_array(Baseline::read($f), false);
    assertSame(['123', 'a', 'b', 'c', 'z'], array_column($recs, 'path'));
    assertSame(9, $recs[3]['size']);
});

t('Baseline::applyUpdates builds a baseline from nothing and leaves no temp file', function () {
    $dir = tmpdir();
    Baseline::applyUpdates($dir . '/b.txt', ['x' => brec('x'), 'a/b' => brec('a/b')], $dir . '/b.txt');
    assertSame(['a/b', 'x'], array_column(iterator_to_array(Baseline::read($dir . '/b.txt'), false), 'path'));
    assertSame(['b.txt'], array_values(array_diff(scandir($dir), ['.', '..'])));
});
