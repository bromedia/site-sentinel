<?php
declare(strict_types=1);

use Sentinel\Baseline;
use Sentinel\Proc;

/**
 * Makes the next write of $file fail like a full disk: its temp file becomes a
 * link to /dev/full, where every write fails with ENOSPC. False if unsupported.
 */
function failNextWrite(string $file): bool
{
    return is_writable('/dev/full') && @symlink('/dev/full', $file . '.tmp');
}

function baselineOf(int $count, string $prefix = 'dir/file-'): array
{
    $recs = [];
    for ($i = 0; $i < $count; $i++) {
        $recs[] = brec(sprintf('%s%05d.php', $prefix, $i), $i, hash('sha256', (string)$i));
    }
    return $recs;
}

function assertNoTemp(string $file): void
{
    clearstatcache();
    assertTrue(!file_exists($file . '.tmp') && !is_link($file . '.tmp'), 'temp file must be removed');
}

t('Baseline::applyUpdates on a full disk keeps the previous baseline byte-for-byte and throws', function () {
    $f = tmpdir() . '/baseline.txt';
    Baseline::write($f, baselineOf(200));
    $before = (string)file_get_contents($f);
    if (!failNextWrite($f)) {
        skip('/dev/full or symlinks unavailable');
    }
    assertThrows(RuntimeException::class, function () use ($f) {
        Baseline::applyUpdates($f, ['dir/file-00007.php' => brec('dir/file-00007.php', 99)], $f);
    });
    assertSame($before, (string)file_get_contents($f));
    assertNoTemp($f);
});

t('Baseline::write on a full disk keeps the previous baseline byte-for-byte and throws', function () {
    $f = tmpdir() . '/baseline.txt';
    Baseline::write($f, baselineOf(200));
    $before = (string)file_get_contents($f);
    if (!failNextWrite($f)) {
        skip('/dev/full or symlinks unavailable');
    }
    assertThrows(RuntimeException::class, function () use ($f) {
        Baseline::write($f, baselineOf(300, 'other/file-'));
    });
    assertSame($before, (string)file_get_contents($f));
    assertNoTemp($f);
});

t('A rewrite that succeeds partway, then hits the file-size limit, never replaces the baseline', function () {
    if (!Proc::available() || !is_executable('/bin/sh')) {
        skip('needs proc_open and /bin/sh');
    }
    $dir = tmpdir();
    $f = $dir . '/baseline.txt';
    Baseline::write($f, baselineOf(1000)); // ~100KB, far above the limit below
    $before = (string)file_get_contents($f);
    $script = $dir . '/rewrite.php';
    file_put_contents($script, '<?php
require ' . var_export(__DIR__ . '/bootstrap.php', true) . ';
try {
    Sentinel\Baseline::applyUpdates($argv[1], ["dir/file-00500.php" => null], $argv[1]);
    echo "installed";
} catch (Throwable $e) {
    fwrite(STDERR, $e->getMessage());
    exit(3);
}');
    // ulimit -f 8: writes beyond 4KB fail (EFBIG) after the first 4KB succeeded; SIGXFSZ is
    // ignored so PHP sees a failed write instead of being killed.
    $cmd = "trap '' XFSZ; ulimit -f 8; exec " . escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($script) . ' ' . escapeshellarg($f);
    $r = Proc::run(['/bin/sh', '-c', $cmd], 30);
    assertSame(3, $r['exit'], 'expected a reported failure, got: ' . $r['out'] . $r['err']);
    assertContains('cannot write', $r['err']);
    assertSame($before, (string)file_get_contents($f));
    assertNoTemp($f);
});

t('Monitor still alerts findings when the baseline cannot be saved, keeps it intact and rescans', function () {
    [$root, , $state, $m, $n] = monitorFixture(['index.php' => '<?php', 'notes.txt' => 'v1']);
    $f = $state->path('baseline.txt');
    putFile($root, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    putFile($root, 'notes.txt', 'version 2'); // a clean change that must be written to the baseline
    $before = (string)file_get_contents($f);
    if (!failNextWrite($f)) {
        skip('/dev/full or symlinks unavailable');
    }
    $r = $m->run('check');
    assertSame(1, $r['exit'], implode("\n", $r['lines']));
    assertSame(1, count($n->sent), 'the run still alerts');
    assertContains('evil.php', $n->sent[0]['body']);
    assertContains('state-write-failed', $n->sent[0]['body']);
    assertSame($before, (string)file_get_contents($f));
    assertNoTemp($f);

    // Space is back: the same changes are found again and saved; nothing is lost.
    $r2 = $m->run('check');
    assertSame(1, $r2['exit'], 'evil.php is still held');
    assertNotContains('state-write-failed', implode("\n", $r2['lines']));
    assertContains("notes.txt\t9\t", (string)file_get_contents($f));
    assertNotContains('evil.php', (string)file_get_contents($f));
});
