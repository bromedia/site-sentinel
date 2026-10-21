<?php
declare(strict_types=1);

use Sentinel\{Accept, Budget, Detections, VersionTracker};

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

t('Detections: a detection outside plugins and themes is not remembered; state from before (no file, or a damaged one) keeps working', function () {
    [$root, , $state, $m] = laundering();
    assertTrue(!is_file($state->path(Detections::FILE)), 'state from before has no detections file');
    assertSame(0, $m->run('check')['exit']);
    launderWrite($root, ['wp-content/uploads/x.php' => '<?php echo 1;']);
    assertSame(1, $m->run('check')['exit']);
    assertSame([], (new Detections($state))->all(), 'PHP in uploads is reported, not remembered');
    unlink($root . '/wp-content/uploads/x.php');
    clearstatcache();
    assertSame(0, $m->run('check')['exit'], 'and cleaning it up is enough');

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
    assertSame(['wp-content/plugins/evil/evil.php'], array_keys($d));
    assertSame(['request-callable'], $d['wp-content/plugins/evil/evil.php']['rules']);
});
