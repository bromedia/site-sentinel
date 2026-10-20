<?php

declare(strict_types=1);

t('Strict default holds version bumps and unrelated inserted files', function () {
    [$root,$c,$b] = wpFixture();
    $old = Sentinel\VersionTracker::read($c);
    assertSame(false, $c->autoAcceptUnverifiedUpdates);
    bump($root, 'wp-content/plugins/foo/foo.php', pluginHeader('1.1'));
    putFile($root, 'wp-content/plugins/foo/inserted.php', '<?php // unrelated');
    $r = runAnalysis($c, $b, null, $old);
    assertSame(['unverified-update@wp-content/plugins/foo'], ruleList($r));
    assertTrue(isset($r['hold']['wp-content/plugins/foo/foo.php'], $r['hold']['wp-content/plugins/foo/inserted.php']));
});
t('Strict policy still accepts verified repository updates', function () {
    [$root,$c,$b] = wpFixture();
    $old = Sentinel\VersionTracker::read($c);
    $body = pluginHeader('1.1');
    bump($root, 'wp-content/plugins/foo/foo.php', $body);
    $http = new FakeHttp();
    coreRoute($http, []);
    $http->route('https://downloads.wordpress.org/plugin-checksums/foo/1.1.json', 200, json_encode(['files' => ['foo.php' => ['sha256' => hash('sha256', $body)]]]));
    $r = runAnalysis($c, $b, analyzerFor($c, new Sentinel\WpChecksum($http, $c, tmpdir())), $old);
    assertSame([], $r['findings']);
    assertSame([], $r['hold']);
});
t('Quick checks continue pending full scans and finish both modes', function () {
    [,, $state,$m] = monitorFixture(['a.php' => '<?php','b.php' => '<?php','c.php' => '<?php']);
    $m->run('full', new Sentinel\Budget(0.0, 1));
    assertTrue(isset($state->readJson('resume.json')['full']));
    $r = $m->run('check', bigBudget());
    assertSame(0, $r['exit']);
    assertContains('check:', implode("\n", $r['lines']));
    assertContains('full:', implode("\n", $r['lines']));
    assertTrue(!isset($state->readJson('resume.json')['full']));
});
t('Analysis reports its processed prefix at a deadline', function () {
    [$root,$c,$b] = wpFixture();
    putFile($root, 'x.php', '<?php // x');
    putFile($root, 'y.php', '<?php // y');
    $tick = 0.0;
    $budget = new Sentinel\Budget(0.5, PHP_INT_MAX, function () use (&$tick) {
        return ++$tick;
    });
    $r = analyzerFor($c)->analyze(array_values(diffByPath($c, $b)), [], [], false, 0, $budget);
    assertSame(1, $r['processed']);
    assertTrue(isset($r['hold']['x.php']));
    assertTrue(!isset($r['hold']['y.php']));
});
t('Comparison batches bound memory independently of the time budget', function () {
    $root = tmpdir(); for ($i = 0; $i < 20; $i++) {
        putFile($root, sprintf('%02d.php', $i), '<?php');
    }
    $d = (new Sentinel\Differ(makeConfig($root)))->diff(tmpdir() . '/missing', '', bigBudget(), true, true, 3);
    assertSame(3, count($d['changes']));
    assertSame(false, $d['complete']);
    assertSame('02.php', $d['stopped_at']);
});
t('HTTP timeouts shrink to remaining scan time', function () {
    $inner = new class implements Sentinel\HttpClient{
        public $timeouts = [];
        public function request(string $method, string $url, string $body = '', array $headers = [], int $timeout = 10): array
        {
            $this->timeouts[] = $timeout;
            return ['status' => 200,'body' => ''];
        }
    };
    $now = 0.0;
    $budget = new Sentinel\Budget(2, PHP_INT_MAX, function () use (&$now) {
        return $now;
    });
    $http = new Sentinel\BudgetHttp($inner, $budget);
    $http->request('GET', 'https://example.test');
    $now = 1.8;
    $http->request('GET', 'https://example.test');
    assertSame([2,1], $inner->timeouts);
});
t('Initialisation checkpoints, rolls back stray appends and activates only a complete baseline', function () {
    [$site,$tool,$opts] = initFixture(['a.php' => '<?php','b.php' => '<?php','c.php' => '<?php']);
    $r = Sentinel\Init::run($opts, $tool . '/sentinel.php', new FakeHttp(), new Sentinel\Budget(0, 1));
    assertContains('paused after 1 file', implode("\n", $r['lines']));
    assertTrue(!is_file($tool . '/sentinel.json'));
    file_put_contents($tool . '/sentinel-state/baseline.init', 'junk', FILE_APPEND);
    assertSame(0, Sentinel\Init::run($opts, $tool . '/sentinel.php', new FakeHttp(), bigBudget())['exit']);
    assertSame(['a.php','b.php','c.php'], array_column(iterator_to_array(Sentinel\Baseline::read($tool . '/sentinel-state/baseline.txt')), 'path'));
});
t('Initialisation refuses malware found on a later slice', function () {
    [$site,$tool,$opts] = initFixture(['a.php' => '<?php','z.php' => '<?php // SENTINEL-TEST-MALWARE-MARKER']);
    Sentinel\Init::run($opts, $tool . '/sentinel.php', new FakeHttp(), new Sentinel\Budget(0, 1));
    assertSame(1, Sentinel\Init::run($opts, $tool . '/sentinel.php', new FakeHttp(), bigBudget())['exit']);
    assertTrue(!is_file($tool . '/sentinel.json'));
    assertTrue(!is_file($tool . '/sentinel-state/baseline.txt'));
});
t('Held plugin versions survive a partial cycle ending with a clean slice', function () {
    [$root,$c,$state,$m] = monitorFixture(['wp-content/plugins/foo/a.php' => '<?php','wp-content/plugins/foo/foo.php' => pluginHeader('1.0'),'zz.txt' => 'last'], ['profile' => 'wordpress','wp_checksums' => false,'auto_accept_unverified_updates' => true,'scan_batch_files' => 1]);
    $state->writeJson('versions.json', Sentinel\VersionTracker::read($c));
    bump($root, 'wp-content/plugins/foo/a.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    bump($root, 'wp-content/plugins/foo/foo.php', pluginHeader('1.1'));
    $runs = 0;
    do {
        $m->run('check', new Sentinel\Budget(0, 1));
        $runs++;
    } while (isset($state->readJson('resume.json')['check']) && $runs < 20);
    assertTrue($runs < 20);
    assertSame('1.0', $state->readJson('versions.json')['wp-content/plugins/foo']);
});
