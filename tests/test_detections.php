<?php
declare(strict_types=1);

use Sentinel\{Accept, Budget, Channel, Detections, Finding, Monitor, VersionTracker};

/** A plugin with a version file and a helper, set up clean with its version recorded. */
function laundering(array $cfg = []): array
{
    $files = [
        'wp-config.php' => '<?php',
        'wp-content/plugins/evil/evil.php' => launderHeader('1.0'),
        'wp-content/plugins/evil/inc.php' => "<?php // helper\n",
        'wp-content/plugins/other/other.php' => "<?php\n/*\nPlugin Name: Other\nVersion: 2.0\n*/\n",
    ];
    for ($i = 1; $i <= 8; $i++) {
        $files["wp-content/themes/t/f$i.txt"] = (string)$i; // sorts after the plugins: later slices
    }
    $fx = monitorFixture($files, $cfg + ['profile' => 'wordpress', 'wp_checksums' => false, 'auto_accept_unverified_updates' => true, 'update_grace_seconds' => 0]);
    $fx[2]->writeJson('versions.json', VersionTracker::read($fx[1]));
    return $fx;
}

function launderHeader(string $v, string $body = ''): string
{
    return "<?php\n/*\nPlugin Name: Evil\nVersion: $v\n*/\n" . $body;
}

/** Writes files as an edit made a while ago (outside the update grace period). */
function launderWrite(string $root, array $files): void
{
    foreach ($files as $rel => $content) {
        putFile($root, $rel, $content);
        touch($root . '/' . $rel, time() - 600);
    }
    clearstatcache();
}

/** Runs a check that resumes across several runs until it completes; returns the number of runs. */
function launderSliced($m): int
{
    $runs = 0;
    do {
        $t = 0.0;
        $r = $m->run('check', new Budget(1.0, PHP_INT_MAX, function () use (&$t) { $t += 0.6; return $t; }));
        $runs++;
    } while (strpos($r['lines'][0], 'partial scan') !== false && $runs < 30);
    return $runs;
}

const LAUNDER_PAYLOAD = "\$_GET['f'](\$_GET['a']);\n";
const LAUNDER_QUIET = "include __DIR__ . '/../../uploads/cache.dat';\n";

t('Detections: a file detected on a normal run cannot be rewritten quietly and passed as an update', function () {
    foreach (['version file' => 'evil.php', 'another file' => 'inc.php'] as $case => $file) {
        foreach (['in one run' => false, 'across resumed scans' => true] as $how => $sliced) {
            [$root, , $state, $m, $n] = laundering();
            $detected = $file === 'evil.php' ? launderHeader('1.0', LAUNDER_PAYLOAD) : '<?php ' . LAUNDER_PAYLOAD;
            launderWrite($root, ["wp-content/plugins/evil/$file" => $detected]);
            $sliced ? assertTrue(launderSliced($m) > 2, "$case $how: resumed") : $m->run('check');
            assertContains('request-callable', $n->sent[count($n->sent) - 1]['body'], "$case $how: detected");
            assertTrue(isset((new Detections($state))->all()["wp-content/plugins/evil/$file"]), "$case $how: remembered");

            // The detected code is rewritten so that nothing matches, and the version raised.
            $quiet = ['wp-content/plugins/evil/evil.php' => launderHeader('1.0.10', $file === 'evil.php' ? LAUNDER_QUIET : '')];
            if ($file === 'inc.php') {
                $quiet['wp-content/plugins/evil/inc.php'] = '<?php ' . LAUNDER_QUIET;
            }
            launderWrite($root, $quiet);
            $before = count($n->sent);
            if ($sliced) {
                launderSliced($m);
            } else {
                assertSame(1, $m->run('check')['exit'], "$case $how");
            }
            $mail = implode("\n", array_column(array_slice($n->sent, $before), 'body'));
            assertContains("wp-content/plugins/evil/$file", $mail, "$case $how: reported");
            assertContains('detection-unresolved', $mail, "$case $how: as the earlier report, unresolved");
            assertNotContains(hash_file('sha256', $root . "/wp-content/plugins/evil/$file"), (string)file_get_contents($state->path('baseline.txt')), "$case $how: not accepted");
            assertSame('1.0', $state->readJson('versions.json')['wp-content/plugins/evil'], "$case $how: version not advanced");
        }
    }
});

t('Detections: resolved by accept --path (version tracked again, quiet), not by removing the file', function () {
    // accept --path after review: the plugin's version is tracked again and later updates are approved.
    [$root, $config, $state, $m, $n] = laundering();
    launderWrite($root, ['wp-content/plugins/evil/inc.php' => '<?php ' . LAUNDER_PAYLOAD]);
    $m->run('check');
    launderWrite($root, ['wp-content/plugins/evil/evil.php' => launderHeader('1.0.10'), 'wp-content/plugins/evil/inc.php' => '<?php ' . LAUNDER_QUIET]);
    assertSame(1, $m->run('check')['exit']);
    Accept::run($config, $state, ['wp-content/plugins/evil'], false, []);
    assertSame([], (new Detections($state))->all());
    $before = count($n->sent);
    assertSame(0, $m->run('check')['exit']);
    assertSame('1.0.10', $state->readJson('versions.json')['wp-content/plugins/evil']);
    launderWrite($root, ['wp-content/plugins/evil/evil.php' => launderHeader('1.0.11', '// a genuine update')]);
    assertSame(0, $m->run('check')['exit'], 'approved automatically again');
    assertSame('1.0.11', $state->readJson('versions.json')['wp-content/plugins/evil']);
    assertSame($before, count($n->sent));

    // Removing the detected file is not a review: it is said once, and updates still wait.
    [$root, $config, $state, $m, $n] = laundering();
    launderWrite($root, ['wp-content/plugins/evil/inc.php' => '<?php ' . LAUNDER_PAYLOAD]);
    $m->run('check');
    unlink($root . '/wp-content/plugins/evil/inc.php');
    clearstatcache();
    $r = $m->run('check');
    assertSame(1, $r['exit']);
    assertContains('wp-content/plugins/evil/inc.php detection-unresolved', implode("\n", $r['lines']));
    assertContains('removed since', $n->sent[count($n->sent) - 1]['body']);
    launderWrite($root, ['wp-content/plugins/evil/evil.php' => launderHeader('1.0.10'), 'wp-content/plugins/evil/new.php' => '<?php ' . LAUNDER_QUIET]);
    assertSame(1, $m->run('check')['exit']);
    assertContains('unverified-update', $n->sent[count($n->sent) - 1]['body'], 'a bump after the removal is not approved automatically');
    assertSame('1.0', $state->readJson('versions.json')['wp-content/plugins/evil']);
    Accept::run($config, $state, ['wp-content/plugins/evil/inc.php'], false, []);
    assertSame([], (new Detections($state))->all(), 'accepting the removed path resolves it');
});

t('Detections: dismissing every rule on the detected content resolves it (then accept, as for any dismissal)', function () {
    [, $www, $dir] = packagedSite([
        'wp-content/plugins/evil/evil.php' => launderHeader('1.0'),
        'wp-content/plugins/evil/inc.php' => "<?php // helper\n",
    ]);
    $mail = new MailBox();
    assertSame(0, runPackaged($dir, $mail)['exit']);
    launderWrite($www, ['wp-content/plugins/evil/inc.php' => '<?php ' . LAUNDER_PAYLOAD]);
    $r = runPackaged($dir, $mail);
    assertSame(1, $r['exit']);
    assertTrue(preg_match('/\[id ([0-9a-f]{12})\]/', $r['text'], $m) === 1, $r['text']);
    assertTrue(is_file($dir . '/state/' . Detections::FILE));
    assertContains('not reviewed yet (their plugin or theme is not updated automatically until accept --path): wp-content/plugins/evil/inc.php', runPackaged($dir, $mail, ['doctor'])['text']);
    assertSame(0, runPackaged($dir, $mail, ['dismiss', $m[1], '--reason=test fixture'])['exit']);
    runPackaged($dir, $mail, ['accept', '--path=wp-content/plugins/evil/inc.php']);
    $n = count($mail->sent);
    assertSame(0, runPackaged($dir, $mail)['exit'], 'quiet once dismissed and accepted');
    assertSame([], $mail->since($n));
    assertSame('[]', trim((string)file_get_contents($dir . '/state/' . Detections::FILE)));
    // A genuine update of that plugin is approved again.
    launderWrite($www, ['wp-content/plugins/evil/evil.php' => launderHeader('1.1', '// update')]);
    assertSame(0, runPackaged($dir, $mail)['exit']);
});

t('Detections: another plugin with a detection does not hold back a genuine update of an unrelated plugin', function () {
    [$root, , $state, $m, $n] = laundering();
    launderWrite($root, ['wp-content/plugins/evil/inc.php' => '<?php ' . LAUNDER_PAYLOAD]);
    $m->run('check');
    $before = count($n->sent);
    launderWrite($root, ['wp-content/plugins/other/other.php' => "<?php\n/*\nPlugin Name: Other\nVersion: 2.1\n*/\n// update\n"]);
    $m->run('check');
    assertSame('2.1', $state->readJson('versions.json')['wp-content/plugins/other'], 'approved automatically');
    assertNotContains('wp-content/plugins/other', implode("\n", array_column(array_slice($n->sent, $before), 'body')));
});

t('Detections: a detection outside plugins and themes is remembered too; state from before (no file, or a damaged one) keeps working', function () {
    [$root, $config, $state, $m] = laundering();
    assertTrue(!is_file($state->path(Detections::FILE)), 'state from before has no detections file');
    assertSame(0, $m->run('check')['exit']);
    launderWrite($root, ['wp-content/uploads/x.php' => '<?php echo 1;']);
    assertSame(1, $m->run('check')['exit']);
    assertSame(['wp-content/uploads/x.php'], array_keys((new Detections($state))->all()), 'PHP in uploads is reported and remembered');
    unlink($root . '/wp-content/uploads/x.php');
    clearstatcache();
    $r = $m->run('check');
    assertSame(1, $r['exit'], 'cleaning it up is not a review');
    assertContains('wp-content/uploads/x.php detection-unresolved', implode("\n", $r['lines']));
    Accept::run($config, $state, ['wp-content/uploads/x.php'], false, []);
    assertSame([], (new Detections($state))->all(), 'accepting the removed path resolves it');
    assertSame(0, $m->run('check')['exit']);

    file_put_contents($state->path(Detections::FILE), json_encode(['a.php' => 'junk', 'b.php' => ['sha256' => 'x']]));
    assertSame([], (new Detections($state))->all(), 'damaged entries are ignored');
    assertSame(0, $m->run('check')['exit']);
});

t('Detections: the official file coming back (verified against wordpress.org) resolves it', function () {
    $v1 = "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\nfunction foo() {}\n";
    [$root, $config, $state, $m, , $http] = monitorFixture(
        ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n", 'wp-content/plugins/foo/foo.php' => $v1],
        ['profile' => 'wordpress', 'auto_accept_unverified_updates' => true, 'update_grace_seconds' => 0]
    );
    $state->writeJson('versions.json', VersionTracker::read($config));
    coreRoute($http, ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n"]);
    $http->route('https://downloads.wordpress.org/plugin-checksums/foo/1.0.json', 200, json_encode(['files' => ['foo.php' => ['sha256' => hash('sha256', $v1)]]]));
    launderWrite($root, ['wp-content/plugins/foo/foo.php' => $v1 . LAUNDER_PAYLOAD]);
    assertSame(1, $m->run('check')['exit']);
    assertTrue(isset((new Detections($state))->all()['wp-content/plugins/foo/foo.php']));
    launderWrite($root, ['wp-content/plugins/foo/foo.php' => $v1]);
    $m->run('check');
    assertSame([], (new Detections($state))->all());
});

t('Detections: files flagged at setup are remembered like any detection', function () {
    [, , $dir] = packagedSite(['wp-content/plugins/evil/evil.php' => launderHeader('1.0', LAUNDER_PAYLOAD), 'wp-content/uploads/x.php' => '<?php echo 1;']);
    assertSame(1, runPackaged($dir, new MailBox())['exit']);
    $d = json_decode((string)file_get_contents($dir . '/state/' . Detections::FILE), true);
    assertSame(['wp-content/plugins/evil/evil.php', 'wp-content/uploads/x.php'], array_keys($d), 'in a plugin or not');
    assertSame(['request-callable'], $d['wp-content/plugins/evil/evil.php']['rules']);
});

t('Detections: an unresolved detection keeps its original severity: Critical stays Critical, Warning stays Warning', function () {
    $cases = [
        'critical' => ['<?php ' . LAUNDER_PAYLOAD, 'CRITICAL'],
        'warning' => ['<?php echo ' . str_repeat('chr(65) . ', 9) . "'';\n", 'WARNING'],
    ];
    foreach ($cases as $case => [$detected, $label]) {
        [$root, $config, $state, , , $http, $clock] = laundering();
        $critOnly = new FakeNotifier(); // a channel that hears only about Critical findings
        $m = new Monitor($config, $state, $http, [new Channel($critOnly, Finding::CRITICAL)], [], $clock);
        launderWrite($root, ['wp-content/plugins/evil/inc.php' => $detected]);
        $m->run('check');
        $heard = count($critOnly->sent);
        launderWrite($root, ['wp-content/plugins/evil/inc.php' => '<?php ' . LAUNDER_QUIET]);
        $r = $m->run('check');
        assertContains("  $label wp-content/plugins/evil/inc.php detection-unresolved", implode("\n", $r['lines']), $case);
        if ($label === 'CRITICAL') {
            assertSame($heard + 1, count($critOnly->sent), 'the Critical-only channel hears about the rewrite');
        }
        // Removing the file keeps the severity too.
        unlink($root . '/wp-content/plugins/evil/inc.php');
        clearstatcache();
        assertContains("  $label wp-content/plugins/evil/inc.php detection-unresolved", implode("\n", $m->run('check')['lines']), "$case: removed");
    }
});

t('Detections: the official file restored with its original timestamp is verified and resolves it, though nothing looks changed', function () {
    $v1 = "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\nfunction foo() {}\n";
    [$root, $config, $state, $m, , $http] = monitorFixture(
        ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n", 'wp-content/plugins/foo/foo.php' => $v1],
        ['profile' => 'wordpress', 'auto_accept_unverified_updates' => true, 'update_grace_seconds' => 0]
    );
    $state->writeJson('versions.json', VersionTracker::read($config));
    coreRoute($http, ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n"]);
    $http->route('https://downloads.wordpress.org/plugin-checksums/foo/1.0.json', 200, json_encode(['files' => ['foo.php' => ['sha256' => hash('sha256', $v1)]]]));
    $file = $root . '/wp-content/plugins/foo/foo.php';
    $mtime = filemtime($file);
    launderWrite($root, ['wp-content/plugins/foo/foo.php' => $v1 . LAUNDER_PAYLOAD]);
    assertSame(1, $m->run('check')['exit']);
    assertTrue(isset((new Detections($state))->all()['wp-content/plugins/foo/foo.php']));
    file_put_contents($file, $v1);
    touch($file, $mtime);
    clearstatcache();
    foreach (['check', 'full'] as $mode) {
        $r = $m->run($mode);
        assertSame(0, $r['exit'], "$mode: " . implode("\n", $r['lines']));
    }
    assertSame([], (new Detections($state))->all());
});

t('Detections: a rule that failed to run is retried, never remembered as a detection, and does not replace a real one', function () {
    [$root, , $state, $m, $n] = laundering();
    $heavy = '<?php $x = ' . str_repeat('chr(1) . ', 7) . "1;\n"; // a rule fails under the limit below, clean otherwise
    $jit = ini_set('pcre.jit', '0');
    $limit = ini_set('pcre.backtrack_limit', '10');
    try {
        launderWrite($root, ['wp-content/plugins/evil/inc.php' => $heavy]);
        $r = $m->run('check');
    } finally {
        ini_set('pcre.jit', (string)$jit);
        ini_set('pcre.backtrack_limit', (string)$limit);
    }
    assertContains('scan-error', implode("\n", $r['lines']), 'the failure is reported');
    assertSame([], (new Detections($state))->all(), 'a scan error is not a detection');
    // Scanning works again: the file is judged normally, and an update of its plugin is approved as usual.
    launderWrite($root, ['wp-content/plugins/evil/evil.php' => launderHeader('1.1')]);
    $r = $m->run('check');
    assertNotContains('detection-unresolved', implode("\n", $r['lines']));
    assertSame('1.1', $state->readJson('versions.json')['wp-content/plugins/evil'] ?? null, implode("\n", $r['lines']));

    // A real detection is not replaced by a later scan error on the same file.
    launderWrite($root, ['wp-content/plugins/evil/inc.php' => '<?php ' . LAUNDER_PAYLOAD]);
    $m->run('check');
    $jit = ini_set('pcre.jit', '0');
    $limit = ini_set('pcre.backtrack_limit', '10');
    try {
        launderWrite($root, ['wp-content/plugins/evil/inc.php' => $heavy]);
        $m->run('check');
    } finally {
        ini_set('pcre.jit', (string)$jit);
        ini_set('pcre.backtrack_limit', (string)$limit);
    }
    assertSame(['request-callable'], (new Detections($state))->all()['wp-content/plugins/evil/inc.php']['rules'] ?? null);
});

t('Detections: Critical, then only a Warning rule, then nothing: stays Critical until reviewed, with reminders', function () {
    [$root, $config, $state, , , $http, $clock] = laundering();
    $critOnly = new FakeNotifier();
    $m = new Monitor($config, $state, $http, [new Channel($critOnly, Finding::CRITICAL)], [], $clock);
    $file = 'wp-content/plugins/evil/inc.php';
    $steps = [
        'critical hit' => '<?php ' . LAUNDER_PAYLOAD,
        'only a warning rule' => '<?php echo ' . str_repeat('chr(65) . ', 9) . "'';\n",
        'nothing matches' => '<?php ' . LAUNDER_QUIET,
    ];
    foreach ($steps as $step => $content) {
        $heard = count($critOnly->sent);
        launderWrite($root, [$file => $content]);
        $m->run('check');
        assertSame($heard + 1, count($critOnly->sent), "$step: the Critical-only channel hears about it");
        assertSame(Finding::CRITICAL, (new Detections($state))->all()[$file]['severity'] ?? null, "$step: still stored as Critical");
    }
    // Not reviewed a day later: a Critical reminder.
    $clock->t += 25 * 3600;
    $heard = count($critOnly->sent);
    $r = $m->run('check');
    assertContains("  CRITICAL $file detection-unresolved", implode("\n", $r['lines']));
    assertSame($heard + 1, count($critOnly->sent), 'daily reminder');
});

t('Detections: on a quiet site, a detected file outside plugins and themes rewritten clean is not accepted quietly', function () {
    [$root, , $state, $m, $n] = monitorFixture(
        ['wp-config.php' => '<?php', 'lib/ok.php' => '<?php // ok'],
        ['profile' => 'wordpress', 'wp_checksums' => false, 'quiet_changes' => true]
    );
    putFile($root, 'lib/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    assertSame(1, $m->run('check')['exit']);
    assertSame(1, count($n->sent), 'the detection is emailed');

    bump($root, 'lib/evil.php', '<?php // rewritten so that no rule matches');
    $r = $m->run('check');
    assertSame(1, $r['exit'], implode("\n", $r['lines']));
    assertContains('lib/evil.php detection-unresolved', implode("\n", $r['lines']));
    assertSame(2, count($n->sent), 'the rewrite is emailed too');
    assertNotContains('accepted: quiet', (string)$n->sent[1]['attachment']['content']);
    assertNotContains('lib/evil.php', (string)file_get_contents($state->path('baseline.txt')), 'not accepted into the baseline');
    assertSame([], $state->readJson('quiet-log.json')['entries'] ?? [], 'nothing was accepted quietly');
    assertSame(['lib/evil.php'], array_keys((new Detections($state))->all()), 'remembered until reviewed');

    // Another file of the same folder is not quiet either while the detection is unresolved.
    bump($root, 'lib/ok.php', '<?php // ok, edited');
    $r = $m->run('check');
    assertContains('unexplained-change', implode("\n", $r['lines']));
});

t('Detections: on a quiet site, a root file flagged at setup and rewritten clean is not accepted quietly', function () {
    $mail = new MailBox();
    [, $www, $dir] = packagedSite(['evil.php' => '<?php // SENTINEL-TEST-MALWARE-MARKER'], "email = owner@client.example\nchanged_files = quiet");
    assertSame(1, runPackaged($dir, $mail)['exit'], 'setup flags it');
    file_put_contents($www . '/evil.php', '<?php // rewritten so that no rule matches');
    touch($www . '/evil.php', time() - 600);
    clearstatcache();
    $r = runPackaged($dir, $mail);
    assertSame(1, $r['exit'], $r['text']);
    assertContains('evil.php detection-unresolved', $r['text']);
    assertNotContains('evil.php', (string)file_get_contents($dir . '/state/baseline.txt'), 'not accepted into the baseline');
    assertSame(['evil.php'], array_keys((new Sentinel\State($dir . '/state'))->readJson(Detections::FILE)), 'remembered until reviewed');
});
