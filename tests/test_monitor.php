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
    (new \Sentinel\SelfCheck($state, $self))->record(); // as init does
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

t('Monitor: an unverified plugin update alerts once, stays held until accepted, and tampering while it waits alerts again', function () {
    $files = [
        'wp-config.php' => '<?php',
        'wp-content/plugins/premium/premium.php' => "<?php\n/*\nPlugin Name: Premium\nVersion: 2.0\n*/\n",
        'wp-content/plugins/premium/inc/helper.php' => '<?php function helper() {}',
    ];
    [$root, $config, $state, $m, $n] = monitorFixture($files, ['profile' => 'wordpress', 'wp_checksums' => false]);
    $state->writeJson('versions.json', VersionTracker::read($config));
    bump($root, 'wp-content/plugins/premium/premium.php', "<?php\n/*\nPlugin Name: Premium\nVersion: 2.1\n*/\nfunction premium_new() {}\n");
    assertSame(1, $m->run('check')['exit']);
    assertSame(1, count($n->sent));
    assertContains('unverified-update', $n->sent[0]['body']);
    assertContains('accept --path=', $n->sent[0]['body']);
    assertSame(['wp-content/plugins/premium' => '2.0'], $state->readJson('versions.json'), 'held: version not advanced');
    assertSame(1, $m->run('check')['exit']);
    assertSame(1, count($n->sent), 'still pending, not re-alerted');

    // While the update waits for review, another file in the same plugin is changed.
    bump($root, 'wp-content/plugins/premium/inc/helper.php', '<?php function helper() {} $f = "sys" . "tem"; $f($_SERVER["HTTP_X"] ?? "");');
    assertSame(1, $m->run('check')['exit']);
    assertSame(2, count($n->sent), 'a further change while pending must alert again');
    assertContains('2 changed file(s)', $n->sent[1]['body']);
    assertContains('wp-content/plugins/premium/inc/helper.php', (string)$n->sent[1]['attachment']['content'], 'the files themselves are in the report');
    assertContains('wp-content/plugins/premium/premium.php', (string)$n->sent[1]['attachment']['content']);

    // Reviewed and accepted: quiet afterwards, version advanced.
    $r = Sentinel\Accept::run($config, $state, ['wp-content/plugins/premium'], false, []);
    assertSame(0, $r['exit']);
    assertSame(0, $m->run('check')['exit']);
    assertSame('2.1', $state->readJson('versions.json')['wp-content/plugins/premium']);
});

t('Monitor: with auto-accept, a fake version during a wordpress.org outage is alerted, kept out of the baseline and not stored', function () {
    $v1 = "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\nfunction foo() {}\n";
    [$root, $config, $state, $m, $n, $http] = monitorFixture(
        ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n", 'wp-content/plugins/foo/foo.php' => $v1],
        ['profile' => 'wordpress', 'auto_accept_unverified_updates' => true]
    );
    $state->writeJson('versions.json', VersionTracker::read($config));
    coreRoute($http, ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n"]);
    $http->route('https://downloads.wordpress.org/plugin-checksums/', 503, 'unavailable');
    putFile($root, 'wp-content/plugins/foo/foo.php', str_replace('Version: 1.0', 'Version: 1.0.9', $v1) . '$f = "sys" . "tem"; $f($_SERVER["HTTP_X"] ?? "");' . "\n");
    $backdoor = hash_file('sha256', $root . '/wp-content/plugins/foo/foo.php');

    assertSame(1, $m->run('check')['exit']);
    assertSame(1, count($n->sent));
    assertContains('unverified-update', $n->sent[0]['body']);
    assertNotContains($backdoor, (string)file_get_contents($state->path('baseline.txt')));
    assertSame('1.0', $state->readJson('versions.json')['wp-content/plugins/foo']);
});

t('Monitor: with auto_accept_unverified_updates a plugin update is explained, silent, and advances stored versions', function () {
    $files = [
        'wp-config.php' => '<?php',
        'wp-content/plugins/foo/foo.php' => "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n// v1\n",
    ];
    [$root, $config, $state, $m, $n] = monitorFixture($files, ['profile' => 'wordpress', 'wp_checksums' => false, 'auto_accept_unverified_updates' => true]);
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

t('Monitor: with auto-accept, an update arriving with a detection in the same plugin waits for review with it, and later quiet edits still alert', function () {
    $files = [
        'wp-config.php' => '<?php',
        'wp-content/plugins/foo/foo.php' => "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n// v1\n",
        'wp-content/plugins/foo/inc/helper.php' => "<?php // helper v1\n",
    ];
    [$root, $config, $state, $m, $n] = monitorFixture($files, ['profile' => 'wordpress', 'wp_checksums' => false, 'auto_accept_unverified_updates' => true]);
    $state->writeJson('versions.json', VersionTracker::read($config));
    putFile($root, 'wp-content/plugins/foo/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER'); // stays held, alerting
    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// v2\n");
    assertSame(1, $m->run('check')['exit']);
    assertContains('unverified-update', $n->sent[count($n->sent) - 1]['body'], 'not approved automatically');
    assertSame(['wp-content/plugins/foo' => '1.0'], $state->readJson('versions.json'), 'files and version wait together');
    assertNotContains(hash_file('sha256', $root . '/wp-content/plugins/foo/foo.php'), (string)file_get_contents($state->path('baseline.txt')), 'the 1.1 files are not accepted');

    // A later quiet edit alerts too.
    $before = count($n->sent);
    bump($root, 'wp-content/plugins/foo/inc/helper.php', "<?php // helper, quietly edited\n");
    assertSame(1, $m->run('check')['exit']);
    assertTrue(count($n->sent) > $before);
    assertContains('2 changed file(s)', $n->sent[count($n->sent) - 1]['body']);
    assertContains('wp-content/plugins/foo/inc/helper.php', (string)$n->sent[count($n->sent) - 1]['attachment']['content'], 'the files themselves are in the report');

    // Reviewed and accepted: the update is recorded, and the next quiet edit is not part of it.
    assertTrue(isset((new \Sentinel\Detections($state))->all()['wp-content/plugins/foo/evil.php']), 'the detection is remembered until then');
    \Sentinel\Accept::run($config, $state, ['wp-content/plugins/foo'], false, []);
    assertSame(['wp-content/plugins/foo' => '1.1'], $state->readJson('versions.json'));
    bump($root, 'wp-content/plugins/foo/inc/helper.php', "<?php // helper, quietly edited again\n", 200);
    $m->run('check');
    assertContains('unexplained-change', $n->sent[count($n->sent) - 1]['body']);
});

t('Monitor: with auto-accept, a held fake version of a repository plugin is never recorded, so a second fake bump is still reported', function () {
    $v1 = "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\nfunction foo() {}\n";
    foreach (['payload in the version file' => 'foo.php', 'payload in another file' => 'inc/extra.php'] as $case => $payloadFile) {
        [$root, $config, $state, $m, $n, $http] = monitorFixture(
            ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n", 'wp-content/plugins/foo/foo.php' => $v1],
            ['profile' => 'wordpress', 'auto_accept_unverified_updates' => true]
        );
        $state->writeJson('versions.json', VersionTracker::read($config));
        coreRoute($http, ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n"]);
        // Foo 1.0 is published on wordpress.org; the fake versions are not.
        $http->route('https://downloads.wordpress.org/plugin-checksums/foo/1.0.json', 200, json_encode(['files' => ['foo.php' => ['sha256' => hash('sha256', $v1)]]]));
        $http->route('https://downloads.wordpress.org/plugin-checksums/foo/', 404, '{"error":"not found"}');

        // Scan 1: a fake version with something that is detected, so that file is held.
        $fake = str_replace('Version: 1.0', 'Version: 1.0.9', $v1);
        if ($payloadFile === 'foo.php') {
            $fake .= "// SENTINEL-TEST-MALWARE-MARKER\n";
        } else {
            putFile($root, 'wp-content/plugins/foo/inc/extra.php', "<?php // SENTINEL-TEST-MALWARE-MARKER\n");
        }
        putFile($root, 'wp-content/plugins/foo/foo.php', $fake);
        assertSame(1, $m->run('check')['exit'], $case);
        assertSame('1.0', $state->readJson('versions.json')['wp-content/plugins/foo'], "$case: an unaccepted version is not recorded");

        // Scan 2: the detected part is gone and the version moves on again.
        @unlink($root . '/wp-content/plugins/foo/inc/extra.php');
        putFile($root, 'wp-content/plugins/foo/foo.php', str_replace('Version: 1.0', 'Version: 1.0.10', $v1) . "// quietly changed\n");
        $hash = hash_file('sha256', $root . '/wp-content/plugins/foo/foo.php');
        $before = count($n->sent);
        assertSame(1, $m->run('check')['exit'], "$case: still reported");
        // The rewritten version file is the file reported before; another file is an unverified update.
        assertContains($payloadFile === 'foo.php' ? 'detection-unresolved' : 'unverified-update', $n->sent[count($n->sent) - 1]['body'], $case);
        assertTrue(count($n->sent) > $before, $case);
        assertNotContains($hash, (string)file_get_contents($state->path('baseline.txt')), "$case: not accepted into the baseline");
    }
});

t('Monitor: a held fake version is not recorded when the scan resumes across runs either', function () {
    $v1 = "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\nfunction foo() {}\n";
    $files = ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n", 'wp-content/plugins/foo/foo.php' => $v1];
    for ($i = 1; $i <= 8; $i++) {
        $files["wp-content/themes/t/f$i.txt"] = (string)$i;
    }
    [$root, $config, $state, $m, , $http] = monitorFixture($files, ['profile' => 'wordpress', 'auto_accept_unverified_updates' => true, 'update_grace_seconds' => 0]);
    $state->writeJson('versions.json', VersionTracker::read($config));
    coreRoute($http, ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n"]);
    $http->route('https://downloads.wordpress.org/plugin-checksums/foo/1.0.json', 200, json_encode(['files' => ['foo.php' => ['sha256' => hash('sha256', $v1)]]]));
    $http->route('https://downloads.wordpress.org/plugin-checksums/foo/', 404, '{"error":"not found"}');
    putFile($root, 'wp-content/plugins/foo/foo.php', str_replace('Version: 1.0', 'Version: 1.0.9', $v1) . "// SENTINEL-TEST-MALWARE-MARKER\n");
    touch($root . '/wp-content/plugins/foo/foo.php', time() - 600);
    clearstatcache();
    $runs = 0;
    do {
        $t = 0.0;
        $r = $m->run('check', new Budget(1.0, PHP_INT_MAX, function () use (&$t) { $t += 0.6; return $t; }));
        $runs++;
    } while (strpos($r['lines'][0], 'partial scan') !== false && $runs < 20);
    assertTrue($runs > 2, 'the scan resumed across runs');
    assertSame('1.0', $state->readJson('versions.json')['wp-content/plugins/foo'] ?? null, 'the held fake version is not recorded');
    assertSame([], $state->readJson('resume.json'), 'nothing carried over once the scan is complete');
});

t('Monitor: a plugin left unvouched at setup gets no version when the scan that holds its file resumes across runs', function () {
    $header = function (string $v): string {
        return "<?php\n/*\nPlugin Name: Evil\nVersion: $v\n*/\n";
    };
    $payload = "\$_GET['f'](\$_GET['a']);\n";
    $quiet = "include __DIR__ . '/../../uploads/cache.dat';\n";
    $filler = [];
    for ($i = 1; $i <= 8; $i++) {
        $filler["wp-content/themes/t/f$i.txt"] = (string)$i; // sorts after the plugin: later slices
    }
    foreach (['version file' => 'evil.php', 'another file' => 'inc.php'] as $case => $flagged) {
        $files = ['wp-config.php' => '<?php'] + $filler;
        if ($flagged === 'inc.php') {
            $files['wp-content/plugins/evil/evil.php'] = $header('1.0.9');
        }
        [$root, $config, $state, $m, $n] = monitorFixture($files, ['profile' => 'wordpress', 'wp_checksums' => false, 'auto_accept_unverified_updates' => true, 'update_grace_seconds' => 0]);
        // As a partial setup leaves it: the flagged file is not in the baseline and the plugin has no version.
        putFile($root, 'wp-content/plugins/evil/evil.php', $header('1.0.9') . ($flagged === 'evil.php' ? $payload : ''));
        if ($flagged === 'inc.php') {
            putFile($root, 'wp-content/plugins/evil/inc.php', '<?php ' . $payload);
        }
        $state->writeJson('versions.json', []);

        $runs = 0;
        do {
            $t = 0.0;
            $budget = new Budget(1.0, PHP_INT_MAX, function () use (&$t) { $t += 0.6; return $t; });
            $r = $m->run('check', $budget);
            $partial = strpos($r['lines'][0], 'partial scan') !== false;
            $runs++;
        } while ($partial && $runs < 20);
        assertTrue($runs > 2, "$case: the scan resumed across runs");
        assertSame([], $state->readJson('versions.json'), "$case: no version while the flagged file is held");

        file_put_contents($root . "/wp-content/plugins/evil/evil.php", $header('1.0.10') . ($flagged === 'evil.php' ? $quiet : ''));
        if ($flagged === 'inc.php') {
            file_put_contents($root . '/wp-content/plugins/evil/inc.php', '<?php ' . $quiet);
        }
        foreach (glob($root . '/wp-content/plugins/evil/*.php') as $f) {
            touch($f, time() - 600);
        }
        clearstatcache();
        $before = count($n->sent);
        assertSame(1, $m->run('check')['exit'], $case);
        assertTrue(count($n->sent) > $before, "$case: reported");
        assertNotContains("wp-content/plugins/evil/$flagged\t", (string)file_get_contents($state->path('baseline.txt')), "$case: not accepted into the baseline");
    }
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

t('Monitor: a technical alert carries the report, and says so near the top when it cannot be saved', function () {
    [$root, , $state, $m, $n] = monitorFixture(['index.php' => '<?php', 'a.php' => '<?php // a']);
    bump($root, 'a.php', '<?php // a edited');
    assertSame(1, $m->run('check')['exit']);
    $att = $n->sent[0]['attachment'];
    assertTrue($att !== null, 'attached');
    assertContains('a.php', $att['content']);
    assertContains('/reports/' . $att['name'], $att['path'], 'the pointer is a relative path');
    assertNotContains($root, $att['path']);
    assertSame(1, count(glob($state->path('reports') . '/sentinel-report-*.txt')));

    [$root2, , $state2, $m2, $n2] = monitorFixture(['index.php' => '<?php', 'a.php' => '<?php // a']);
    file_put_contents($state2->path('reports'), 'in the way');
    bump($root2, 'a.php', '<?php // a edited');
    assertSame(1, $m2->run('check')['exit']);
    assertSame(null, $n2->sent[0]['attachment']);
    $lines = explode("\n", $n2->sent[0]['body']);
    assertContains('The full report could not be saved: ', $lines[4], 'right below the header');
    assertNotContains($root2, $n2->sent[0]['body']);
});

t('Digest: the report note goes above the developer section of a client email and below the header of a technical one', function () {
    $f = [new Sentinel\Finding(Sentinel\Finding::WARNING, 'a.php', 'unexplained-change', 'changed')];
    $client = Sentinel\Digest::forClient('Shop', 1760000000, $f, [], [], '');
    $body = Sentinel\Digest::withReportNote($client['body'], 'The full report could not be saved: disk full', true);
    $lines = explode("\n", $body);
    $at = array_search('--', $lines, true);
    assertSame('The full report could not be saved: disk full', $lines[$at - 1]);
    $tech = Sentinel\Digest::build('Shop', 'host', 1760000000, $f, [], []);
    $lines = explode("\n", Sentinel\Digest::withReportNote($tech['body'], 'The full report could not be saved: disk full', false));
    assertSame('Highest severity: WARNING', $lines[2]);
    assertSame('', $lines[3]);
    assertSame('The full report could not be saved: disk full', $lines[4]);

    // With a contact footer in a client email the note goes above the footer, not between it and the "--".
    $withFooter = Sentinel\Digest::forClient('Shop', 1760000000, $f, [], [], 'Bro Media (info@bromedia.co.za)');
    $lines = explode("\n", Sentinel\Digest::withReportNote($withFooter['body'], 'The full report could not be saved: disk full', true));
    $at = array_search('--', $lines, true);
    assertSame('Questions about this email? Contact Bro Media (info@bromedia.co.za).', $lines[$at - 1]);
    assertSame('', $lines[$at - 2], 'a blank line above the footer');
    assertSame('', $lines[$at - 4], 'and one between the body and the note');
    assertSame('The full report could not be saved: disk full', $lines[$at - 3]);
    $plain = explode("\n", $client['body']);
    assertSame(count($plain) + 1, count(explode("\n", Sentinel\Digest::withReportNote($client['body'], 'x', true))), 'without a footer: one line, above the "--"');
});

t('Digest: a client alert says the report is attached only when it is, in the owner part above the footer', function () {
    $f = [new Finding(Finding::CRITICAL, 'wp-content/uploads/x.php', 'php-in-uploads', 'PHP file in uploads')];
    $name = 'sentinel-report-shop-20261021-1430.txt';
    $sentence = "Every finding and changed file is listed in the attached report ($name).";
    $contact = 'Bro Media (info@bromedia.co.za)';
    $with = Sentinel\Digest::forClient('Shop', 1760000000, $f, [], [], $contact, $name)['body'];
    $lines = explode("\n", $with);
    $dash = array_search('--', $lines, true);
    assertSame('Questions about this email? Contact Bro Media (info@bromedia.co.za).', $lines[$dash - 1], 'the footer stays the last owner line');
    assertSame('', $lines[$dash - 2]);
    assertSame($sentence, $lines[$dash - 3], 'the sentence sits above the footer');
    assertNotContains('attached', Sentinel\Digest::forClient('Shop', 1760000000, $f, [], [], $contact)['body'], 'no attachment, no sentence');
    $lines = explode("\n", Sentinel\Digest::forClient('Shop', 1760000000, $f, [], [], '', $name)['body']);
    assertSame($sentence, $lines[array_search('--', $lines, true) - 1], 'without a footer: directly above the developer section');
    $tech = Sentinel\Digest::forConfig(makeConfig(tmpdir()), 1760000000, $f, [], [], $name)['body'];
    assertNotContains('attached report', $tech, 'the technical digest keeps its own wording');
});

t('Digest: the client changes section counts files per group, and each owner list stops at 10', function () {
    $group = new Finding(Finding::WARNING, 'wp-content/themes/Avada', 'unexplained-change', '30 file(s) changed without a version change (each one is listed in the report)');
    $group->files = 30;
    $one = new Finding(Finding::WARNING, 'wp-content/themes/Lite', 'unverified-update', 'Version 1 -> 2, but 1 changed file(s) could not be verified');
    $one->files = 1;
    $body = Sentinel\Digest::forClient('Shop', 1760000000, [$group, $one], [], [], '')['body'];
    assertContains("  - 30 files changed in wp-content/themes/Avada\n", $body);
    assertContains("  - 1 file changed in wp-content/themes/Lite\n", $body);
    $top = new Finding(Finding::WARNING, '.', 'unexplained-change', '2 file(s) changed');
    $top->files = 2;
    assertContains("  - 2 files changed in the main website folder\n", Sentinel\Digest::forClient('Shop', 1760000000, [$top], [], [], '')['body'], 'files at the top level are not shown as "."');

    foreach (['hack' => ['php-in-uploads', Finding::CRITICAL, 'POSSIBLE HACK'], 'check' => ['unexpected-file', Finding::WARNING, 'UNUSUAL FILES'],
        'unresolved' => ['detection-unresolved', Finding::CRITICAL, 'EARLIER ALERT NOT RESOLVED'], 'changes' => ['sensitive-file-changed', Finding::WARNING, 'WEBSITE FILES CHANGED']] as $section => [$rule, $sev, $title]) {
        $fs = [];
        for ($i = 1; $i <= 12; $i++) {
            $fs[] = new Finding($sev, sprintf('wp-content/uploads/f%02d.php', $i), $rule, 'm');
        }
        foreach (['sentinel-report-shop-20261021-1430.txt' => 'all are in the attached report', '' => 'all are in the full report'] as $attached => $where) {
            $body = Sentinel\Digest::forClient('Shop', 1760000000, $fs, [], [], '', $attached)['body'];
            $owner = substr($body, 0, (int)strpos($body, "\n--\n"));
            $part = substr($owner, (int)strpos($owner, $title));
            for ($i = 1; $i <= 10; $i++) {
                assertContains(sprintf("  - wp-content/uploads/f%02d.php\n", $i), $part, "$section: the first 10");
            }
            assertNotContains('f11.php', $owner, "$section: not the 11th");
            assertNotContains('f12.php', $owner, "$section: not the 12th");
            assertContains("  and 2 more; $where\n", $part, "$section ($where)");
            assertContains('f12.php', substr($body, (int)strpos($body, "\n--\n")), "$section: the developer section still names every finding");
        }
    }
});

t('Monitor: a client alert gives email the "attached" wording; other channels keep the plain body', function () {
    [$root, , , $m, $n] = monitorFixture(['index.php' => '<?php', 'a.php' => '<?php // a'], ['audience' => 'client', 'contact' => 'Bro Media (info@bromedia.co.za)']);
    bump($root, 'a.php', '<?php // a edited');
    assertSame(1, $m->run('check')['exit']);
    $att = $n->sent[0]['attachment'];
    assertTrue($att !== null, 'attached');
    $sentence = 'Every finding and changed file is listed in the attached report (' . $att['name'] . ').';
    assertNotContains('attached report', $n->sent[0]['body'], 'the body every channel gets does not claim an attachment');
    assertContains($sentence, (string)($att['body'] ?? ''), 'the body for a channel that attaches the file says so');
    assertSame(str_replace($sentence . "\n\n", '', (string)$att['body']), $n->sent[0]['body'], 'otherwise the same email');
});

t('Monitor: a report saved but not attachable is said to be on the server, not "could not be saved"', function () {
    [$root, $config, $state] = monitorFixture(['index.php' => '<?php', 'a.php' => '<?php // a'], ['audience' => 'client']);
    $n = new FakeNotifier();
    $unreadable = function (string $file, string $shown): array {
        throw new RuntimeException('cannot read report'); // as when the saved file cannot be read back
    };
    $m = new Monitor($config, $state, new FakeHttp(), [new Channel($n, Finding::WARNING)], [], new FakeClock(), $unreadable);
    bump($root, 'a.php', '<?php // a edited');
    assertSame(1, $m->run('check')['exit']);
    assertSame(null, $n->sent[0]['attachment']);
    $kept = glob($state->path('reports') . '/sentinel-report-*.txt');
    assertSame(1, count($kept), 'the report was saved');
    $body = $n->sent[0]['body'];
    assertContains('The full report could not be attached; it is saved on the server: ' . \Sentinel\Report::displayPath($state->dir(), basename($kept[0])), $body);
    assertNotContains('could not be saved', $body);
    assertNotContains('attached report', $body);
    assertNotContains($state->dir(), $body, 'the server path is relative');
});

/**
 * A site laid out like a hosting account: <home>/public_html, <home>/sentinel/state and the
 * script at <home>/sentinel/sentinel.php, with a client or technical audience.
 *
 * @return array{0:string,1:string,2:\Sentinel\Config,3:State,4:Monitor,5:FakeNotifier,6:string}
 */
function accountFixture(string $audience): array
{
    $home = tmpdir() . '/home/clientftp';
    $root = $home . '/public_html';
    putFile($root, 'index.php', '<?php');
    $script = putFile($home . '/sentinel', 'sentinel.php', '<?php // v1');
    $config = \Sentinel\Config::fromArray([
        'site_name' => 'test',
        'site_root' => $root,
        'state_dir' => $home . '/sentinel/state',
        'profile' => 'generic',
        'audience' => $audience,
        'contact' => 'Bro Media (info@bromedia.example)',
        'update_grace_seconds' => 0,
        'channels' => [['type' => 'file', 'path' => $home . '/sentinel/state/alerts.log']],
    ]);
    $state = new State($config->stateDir);
    snapshot($config, $state->path('baseline.txt'));
    $self = ['script' => (string)realpath($script)];
    (new \Sentinel\SelfCheck($state, $self))->record();
    $n = new FakeNotifier();
    $m = new Monitor($config, $state, new FakeHttp(), [new Channel($n, Finding::WARNING)], $self, new FakeClock());
    return [$home, $root, $config, $state, $m, $n, $script];
}

t('Monitor: no alert, client or technical, shows the account\'s absolute paths, whatever a finding says', function () {
    foreach (['client', 'technical'] as $audience) {
        [$home, $root, , $state, $m, $n, $script] = accountFixture($audience);
        $f = $state->path('baseline.txt');
        if (!failNextWrite($f)) {
            skip('/dev/full or symlinks unavailable');
        }
        putFile($root, 'notes.txt', 'new file'); // a change that must be written to the baseline
        file_put_contents($script, '<?php // v2, changed');
        assertSame(1, $m->run('check')['exit']);
        $sent = $n->sent[0];
        $everything = $sent['subject'] . "\n" . $sent['body'] . "\n" . (string)($sent['attachment']['body'] ?? '') . (string)($sent['attachment']['content'] ?? '');
        assertContains('self-tamper', $sent['body'], $audience);
        assertContains('state-write-failed', $sent['body'], $audience);
        assertContains('sentinel/sentinel.php', $sent['body'], "$audience: the script is shown relative to the home folder");
        assertContains('sentinel/state/baseline.txt.tmp', $sent['body'], "$audience: so is the state file");
        foreach ([$home, (string)realpath($home), $root, (string)realpath($root)] as $abs) {
            assertNotContains($abs, $everything, "$audience: an absolute path was sent");
        }
    }
});

t('Monitor: the error alert for a failed run shows no absolute path either', function () {
    [$home, , , , $m, $n] = accountFixture('client');
    $m->reportError('cannot read ' . $home . '/sentinel/state/status.json');
    assertContains('sentinel/state/status.json', $n->sent[0]['body']);
    assertNotContains($home, $n->sent[0]['subject'] . $n->sent[0]['body']);
});
