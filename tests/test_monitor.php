<?php
declare(strict_types=1);

use Sentinel\Baseline;
use Sentinel\Budget;
use Sentinel\Channel;
use Sentinel\Finding;
use Sentinel\Lock;
use Sentinel\Monitor;
use Sentinel\State;
use Sentinel\VersionTracker;

/** @return array{0:string,1:\Sentinel\Config,2:State,3:Monitor,4:FakeNotifier,5:FakeHttp,6:FakeClock} */
function monitorFixture(array $files = [], array $cfg = [], array $self = []): array
{
    $root = tmpdir();
    foreach ($files as $rel => $content) {
        putFile($root, $rel, $content);
    }
    $config = makeConfig($root, $cfg);
    $state = new State($config->stateDir);
    snapshot($config, $state->path('baseline.txt'));
    $notifier = new FakeNotifier();
    $http = new FakeHttp();
    $clock = new FakeClock();
    $m = new Monitor($config, $state, $http, [new Channel($notifier, Finding::WARNING)], $self, $clock);
    return [$root, $config, $state, $m, $notifier, $http, $clock];
}

t('Monitor: a clean run exits 0 and sends nothing', function () {
    [, , , $m, $n] = monitorFixture(['index.php' => '<?php', 'a.txt' => 'a']);
    $r = $m->run('check');
    assertSame(0, $r['exit']);
    assertSame(0, count($n->sent));
    assertContains('0 change(s), 0 critical, 0 warning, scan complete', $r['lines'][0]);
});

t('Monitor: a malware hit alerts once, stays held, and reminds after remind_hours', function () {
    [$root, , , $m, $n, , $clock] = monitorFixture(['index.php' => '<?php']);
    putFile($root, 'lib/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $r = $m->run('check');
    assertSame(1, $r['exit']);
    assertSame(1, count($n->sent));
    assertContains('[Sentinel][CRITICAL]', $n->sent[0]['subject']);
    assertContains('lib/evil.php', $n->sent[0]['body']);

    $r2 = $m->run('check');
    assertSame(1, $r2['exit'], 'still reported, because it is held out of the baseline');
    assertSame(1, count($n->sent), 'but not re-alerted');

    $clock->t += 86400 + 10;
    $m->run('check');
    assertSame(2, count($n->sent), 'Critical findings remind daily');
});

t('Monitor: a failing channel does not mark findings alerted, so the next run retries (Review Focus 4)', function () {
    [$root, , , $m, $n] = monitorFixture();
    putFile($root, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $n->fail = true;
    $r = $m->run('check');
    assertSame(1, $r['exit']);
    assertSame(0, count($n->sent));
    assertContains('FAILED', implode("\n", $r['lines']));
    $n->fail = false;
    $m->run('check');
    assertSame(1, count($n->sent));
});

t('Monitor: a missing baseline is an error, not "everything is new" (Review Focus 5)', function () {
    [$root, , $state, $m, $n] = monitorFixture(['a.php' => '<?php']);
    unlink($state->path('baseline.txt'));
    $r = $m->run('check');
    assertSame(2, $r['exit']);
    assertContains('no baseline', implode("\n", $r['lines']));
    assertSame(1, count($n->sent));
    assertContains('[Sentinel][CRITICAL]', $n->sent[0]['subject']);
    assertContains('run "init" first', $n->sent[0]['body']);
    assertTrue(!is_file($state->path('baseline.txt')), 'must not invent a baseline');
    $m->run('check');
    assertSame(1, count($n->sent), 'the same error alerts once');
});

t('Monitor: a corrupt baseline is an error and is left untouched (Review Focus 5)', function () {
    [, , $state, $m, $n] = monitorFixture(['a.php' => '<?php']);
    file_put_contents($state->path('baseline.txt'), "not a baseline\n");
    $r = $m->run('check');
    assertSame(2, $r['exit']);
    assertContains('corrupt baseline', implode("\n", $r['lines']));
    assertSame("not a baseline\n", file_get_contents($state->path('baseline.txt')));
    assertSame(1, count($n->sent));
});

t('Monitor: clean changes update the baseline, code changes are held and alerted once', function () {
    [$root, , , $m, $n] = monitorFixture(['notes.txt' => 'one', 'lib/a.php' => '<?php // a']);
    bump($root, 'notes.txt', 'two');
    $r = $m->run('check');
    assertSame(0, $r['exit']);
    assertContains('1 change(s)', $r['lines'][0]);
    assertContains('0 change(s)', $m->run('check')['lines'][0], 'baseline was updated');

    bump($root, 'lib/a.php', '<?php // edited');
    $r2 = $m->run('check');
    assertSame(1, $r2['exit']);
    assertSame(1, count($n->sent));
    assertContains('unexplained-change', $n->sent[0]['body']);
    $r3 = $m->run('check');
    assertSame(1, $r3['exit']);
    assertContains('1 change(s)', $r3['lines'][0], 'held out of the baseline');
    assertSame(1, count($n->sent));
});

t('Monitor: a budget-limited scan resumes where it stopped and finishes (Review Focus 5)', function () {
    [$root, , $state, $m, $n] = monitorFixture(['f1.txt' => '1', 'f2.txt' => '2', 'f3.txt' => '3', 'f4.txt' => '4', 'f5.txt' => '5']);
    bump($root, 'f1.txt', 'one!');
    bump($root, 'f5.txt', 'five!');
    $total = 0;
    $runs = 0;
    do {
        $t = 0.0;
        $budget = new Budget(1.0, PHP_INT_MAX, function () use (&$t) { $t += 0.6; return $t; });
        $r = $m->run('check', $budget);
        $partial = strpos($r['lines'][0], 'partial scan') !== false;
        if ($partial) {
            assertContains('resuming after', $r['lines'][0]);
            assertTrue(isset($state->readJson('resume.json')['check']));
        }
        preg_match('/(\d+) change\(s\)/', $r['lines'][0], $mm);
        $total += (int)$mm[1];
        $runs++;
    } while ($partial && $runs < 10);
    assertSame(2, $total);
    assertSame(3, $runs);
    assertTrue(!isset($state->readJson('resume.json')['check']));
    assertContains('0 change(s)', $m->run('check')['lines'][0]);
    assertSame(0, count($n->sent));
});

t('Monitor: two overlapping runs do not both scan (Review Focus 5)', function () {
    [$root, , $state, $m, $n] = monitorFixture();
    putFile($root, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $lock = Lock::acquire($state->path('lock'));
    $r = $m->run('check');
    assertSame(0, $r['exit']);
    assertContains('another run is in progress', $r['lines'][0]);
    assertSame(0, count($n->sent));
    $lock->release();
    assertSame(1, $m->run('check')['exit']);
});

t('Monitor: heartbeat is pinged after a completed run but not after an error', function () {
    [, , $state, $m, , $http] = monitorFixture([], ['heartbeat_url' => 'https://hb.example/ping']);
    $http->route('https://hb.example/ping', 200, 'OK');
    $m->run('check');
    assertSame(1, count($http->calls));
    assertSame('https://hb.example/ping', $http->calls[0][1]);

    unlink($state->path('baseline.txt'));
    $m->run('check');
    assertSame(1, count($http->calls));

    [, , , $m2, , $http2] = monitorFixture([], ['heartbeat_url' => 'https://hb.example/ping']);
    $r = $m2->run('check');
    assertContains('heartbeat failed', implode("\n", $r['lines']));
});

t('Monitor: tampering with the script is a Critical finding', function () {
    $dir = tmpdir();
    $script = putFile($dir, 'sentinel.php', '<?php // v1');
    [, , , $m, $n] = monitorFixture([], [], ['script' => $script]);
    assertSame(0, $m->run('check')['exit']);
    file_put_contents($script, '<?php // evil');
    $r = $m->run('check');
    assertSame(1, $r['exit']);
    assertContains('self-tamper', $n->sent[0]['body']);
});

t('Monitor: with no channels configured it refuses to run', function () {
    $root = tmpdir();
    $config = makeConfig($root);
    $m = new Monitor($config, new State($config->stateDir), new FakeHttp(), [], []);
    $r = $m->run('check');
    assertSame(2, $r['exit']);
    assertContains('no alert channels', $r['lines'][0]);
});

t('Monitor: a WordPress plugin update is explained, silent, and advances stored versions', function () {
    $files = [
        'wp-config.php' => '<?php',
        'wp-content/plugins/foo/foo.php' => "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n// v1\n",
    ];
    [$root, $config, $state, $m, $n] = monitorFixture($files, ['profile' => 'wordpress', 'wp_checksums' => false]);
    $state->writeJson('versions.json', VersionTracker::read($config));
    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// v2\n");
    $r = $m->run('check');
    assertSame(0, $r['exit']);
    assertSame(0, count($n->sent), 'Info never alerts on its own');
    assertSame(['wp-content/plugins/foo' => '1.1'], $state->readJson('versions.json'));
    assertContains('0 change(s)', $m->run('check')['lines'][0]);

    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// quiet edit\n");
    assertSame(1, $m->run('check')['exit']);
    assertSame(1, count($n->sent));
    assertContains("Info\n", $n->sent[0]['body'] . "Info\n");
});

t('Monitor: a held plugin group keeps its old stored version', function () {
    $files = [
        'wp-config.php' => '<?php',
        'wp-content/plugins/foo/foo.php' => "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n// v1\n",
    ];
    [$root, $config, $state, $m] = monitorFixture($files, ['profile' => 'wordpress', 'wp_checksums' => false]);
    $state->writeJson('versions.json', VersionTracker::read($config));
    putFile($root, 'wp-content/plugins/foo/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// v2\n");
    assertSame(1, $m->run('check')['exit']);
    assertSame(['wp-content/plugins/foo' => '1.0'], $state->readJson('versions.json'));
});

t('Monitor: an unreadable directory is reported', function () {
    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        skip('root can read everything');
    }
    [$root, , , $m, $n] = monitorFixture(['a.txt' => 'a']);
    putFile($root, 'locked/x.txt', 'x');
    chmod($root . '/locked', 0000);
    $r = $m->run('check');
    chmod($root . '/locked', 0755);
    assertSame(1, $r['exit']);
    assertContains('unreadable-dir', $n->sent[0]['body']);
});

t('Monitor: an unusable lock file is an error with an alert, not a silent skip', function () {
    [$root, , $state, $m, $n] = monitorFixture();
    putFile($root, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    mkdir($state->path('lock')); // the lock path is now a directory
    $r = $m->run('check');
    assertSame(2, $r['exit']);
    assertContains('lock', implode("\n", $r['lines']));
    assertSame(1, count($n->sent));
    assertContains('run-error', $n->sent[0]['body']);
});

t('Monitor: a change that just arrived is deferred, then judged on a later run', function () {
    [$root, , , $m, $n, , $clock] = monitorFixture(['lib/a.php' => '<?php // a'], ['update_grace_seconds' => 120]);
    $clock->t = time();
    bump($root, 'lib/a.php', '<?php // a edited', 0);
    $r = $m->run('check');
    assertSame(0, $r['exit']);
    assertSame(0, count($n->sent), 'no alert while the files may still be arriving');
    assertContains('1 change(s)', $r['lines'][0], 'and not accepted into the baseline either');

    $clock->t = time() + 600;
    $r2 = $m->run('check');
    assertSame(1, $r2['exit']);
    assertSame(1, count($n->sent));
    assertContains('unexplained-change', $n->sent[0]['body']);
});
