<?php
declare(strict_types=1);

use Sentinel\Baseline;
use Sentinel\Budget;
use Sentinel\Differ;

t('Differ finds new, modified and removed files and ignores unchanged ones', function () {
    $root = tmpdir();
    putFile($root, 'a.php', '<?php // a');
    putFile($root, 'b.txt', 'b');
    putFile($root, 'c.php', '<?php // c');
    $c = makeConfig($root);
    $b = tmpdir() . '/b.txt';
    snapshot($c, $b);
    bump($root, 'a.php', '<?php // a changed');
    unlink($root . '/c.php');
    putFile($root, 'd.php', '<?php // d');
    putFile($root, 'n.txt', 'n');
    $ch = diffByPath($c, $b);
    assertSame(['a.php', 'c.php', 'd.php', 'n.txt'], array_keys($ch));
    assertSame('modified', $ch['a.php']['type']);
    assertTrue($ch['a.php']['old']['hash'] !== $ch['a.php']['new']['hash']);
    assertSame(64, strlen($ch['a.php']['new']['hash']));
    assertSame('removed', $ch['c.php']['type']);
    assertSame('new', $ch['d.php']['type']);
    assertSame(64, strlen($ch['d.php']['new']['hash']));
    assertSame('', $ch['n.txt']['new']['hash'], 'non-code files are stat-only');
});

t('Differ marks touch-only changes as content_same', function () {
    $root = tmpdir();
    putFile($root, 'a.php', '<?php // a');
    $c = makeConfig($root);
    $b = tmpdir() . '/b.txt';
    snapshot($c, $b);
    touch($root . '/a.php', time() + 500);
    $ch = diffByPath($c, $b);
    assertSame('modified', $ch['a.php']['type']);
    assertTrue($ch['a.php']['content_same']);
});

t('Differ detects same-size same-mtime edits only in full mode (stealth)', function () {
    $root = tmpdir();
    $f = putFile($root, 'a.php', 'AAAA', time() - 1000);
    $c = makeConfig($root);
    $b = tmpdir() . '/b.txt';
    snapshot($c, $b);
    $m = filemtime($f);
    file_put_contents($f, 'BBBB');
    touch($f, $m);
    clearstatcache();
    assertSame([], diffByPath($c, $b, false));
    $ch = diffByPath($c, $b, true);
    assertSame('modified', $ch['a.php']['type']);
    assertTrue($ch['a.php']['stealth']);
});

t('Differ drops baseline entries that are now excluded instead of reporting them removed', function () {
    $root = tmpdir();
    putFile($root, 'keep.php', '<?php');
    putFile($root, 'tmp/x.php', '<?php');
    $b = tmpdir() . '/b.txt';
    snapshot(makeConfig($root), $b);
    $ch = diffByPath(makeConfig($root, ['exclude' => ['tmp/']]), $b);
    assertSame(['tmp/x.php'], array_keys($ch));
    assertSame('dropped', $ch['tmp/x.php']['type']);
});

t('Differ treats a file replaced by a directory as removed plus new', function () {
    $root = tmpdir();
    putFile($root, 'x', 'file');
    $c = makeConfig($root);
    $b = tmpdir() . '/b.txt';
    snapshot($c, $b);
    unlink($root . '/x');
    putFile($root, 'x/y.php', '<?php');
    $ch = diffByPath($c, $b);
    assertSame('removed', $ch['x']['type']);
    assertSame('new', $ch['x/y.php']['type']);
});

t('Differ stops at the budget and resumes strictly after stopped_at (Review Focus 5)', function () {
    $root = tmpdir();
    foreach (['f1', 'f2', 'f3', 'f4', 'f5'] as $n) {
        putFile($root, $n . '.txt', $n);
    }
    $c = makeConfig($root);
    $b = tmpdir() . '/b.txt';
    snapshot($c, $b);
    bump($root, 'f1.txt', 'one!');
    bump($root, 'f5.txt', 'five!');
    $seen = [];
    $after = '';
    $runs = 0;
    do {
        $t = 0.0;
        // Each clock() call advances 0.6s; with a 1s budget a run handles exactly two entries.
        $budget = new Budget(1.0, PHP_INT_MAX, function () use (&$t) { $t += 0.6; return $t; });
        $d = (new Differ($c))->diff($b, $after, $budget, false);
        foreach ($d['changes'] as $ch) {
            $seen[] = $ch['path'];
        }
        $after = (string)$d['stopped_at'];
        $runs++;
    } while (!$d['complete'] && $runs < 10);
    assertSame(['f1.txt', 'f5.txt'], $seen);
    assertSame(3, $runs);
    assertSame(null, $d['stopped_at']);
});

t('Differ always makes progress even with an already-exceeded budget', function () {
    $root = tmpdir();
    putFile($root, 'a.txt', 'a');
    putFile($root, 'b.txt', 'b');
    $c = makeConfig($root);
    $d = (new Differ($c))->diff(tmpdir() . '/none.txt', '', new Budget(0.0, 1), false);
    assertSame(1, count($d['changes']));
    assertSame('a.txt', $d['stopped_at']);
});

t('Differ surfaces a corrupt baseline instead of treating everything as new (Review Focus 5)', function () {
    $root = tmpdir();
    putFile($root, 'a.txt', 'a');
    $b = tmpdir() . '/b.txt';
    file_put_contents($b, "garbage without tabs\n");
    assertThrows(RuntimeException::class, function () use ($root, $b) {
        (new Differ(makeConfig($root)))->diff($b, '', bigBudget(), false);
    });
});

t('Differ flags unreadable code files', function () {
    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        skip('root can read everything');
    }
    $root = tmpdir();
    $f = putFile($root, 'locked.php', '<?php');
    chmod($f, 0000);
    $ch = diffByPath(makeConfig($root), tmpdir() . '/none.txt');
    chmod($f, 0644);
    assertTrue($ch['locked.php']['unreadable']);
});

t('Budget::iniBytes parses memory_limit values', function () {
    assertSame(0, Budget::iniBytes('-1'));
    assertSame(0, Budget::iniBytes(''));
    assertSame(128 * 1048576, Budget::iniBytes('128M'));
    assertSame(2 * 1073741824, Budget::iniBytes('2G'));
    assertSame(512 * 1024, Budget::iniBytes('512K'));
    assertSame(1000, Budget::iniBytes('1000'));
});
