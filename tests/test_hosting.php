<?php
declare(strict_types=1);

use Sentinel\Cli;
use Sentinel\Cron;
use Sentinel\Doctor;
use Sentinel\Proc;

t('Cron uses the running PHP binary and safely quotes paths for both cron and the shell', function () {
    $tool = tmpdir();
    $record = $tool . '/argv.json';
    $script = putFile($tool, "sentinel ' 50% \$(false).php", '<?php file_put_contents(' . var_export($record, true) . ', json_encode($argv));');
    $config = $tool . "/config ' 25% \$(false).json";
    $lines = Cron::lines($script, $config);
    assertContains(escapeshellarg(PHP_BINARY), $lines[0]);
    assertContains('\\%', $lines[0]);
    assertNotContains('2>&1', $lines[0], 'cron errors must remain visible');
    $command = (string)preg_replace('/^(?:\S+\s+){5}/', '', $lines[0]);
    // cron removes the escaping backslash before passing a literal percent to the shell.
    $r = Proc::run(['/bin/sh', '-c', str_replace('\\%', '%', $command)], 30);
    assertSame(0, $r['exit'], $r['err']);
    assertSame([$script, 'check', '--config=' . $config], json_decode((string)file_get_contents($record), true));
    assertThrows(InvalidArgumentException::class, function () use ($script) {
        Cron::lines($script, "/config\n* * * * * injected");
    });
});

t('Doctor is read-only, reports hosting gaps and never sends network requests or alerts', function () {
    [$script, $configFile, $alerts] = cliSite();
    $http = new FakeHttp();
    $dir = dirname($configFile) . '/sentinel-state';
    $before = [];
    foreach (glob($dir . '/*') as $file) {
        $before[$file] = hash_file('sha256', $file);
    }
    $r = Cli::execute(['doctor', '--config=' . $configFile], $script, $http);
    assertSame(1, $r['exit'], 'missing heartbeat is a warning');
    $out = implode("\n", $r['out']);
    assertContains('no external heartbeat', $out);
    assertContains('Excluded (not scanned)', $out);
    assertContains('full: last processed run not recorded', $out);
    assertSame([], $http->calls);
    assertTrue(!is_file($alerts));
    $after = [];
    foreach (glob($dir . '/*') as $file) {
        $after[$file] = hash_file('sha256', $file);
    }
    assertSame($before, $after);
    $cron = Cli::execute(['cron', '--config=' . $configFile], $script, $http);
    assertSame(Cron::lines($script, $configFile), $cron['out']);
});

t('Doctor reports a missing baseline or state directory without creating either', function () {
    $root = tmpdir();
    $tool = tmpdir();
    $state = $tool . '/not-created';
    $c = makeConfig($root, ['state_dir' => $state]);
    $r = Doctor::run($c, $tool . '/sentinel.php', $tool . '/sentinel.json');
    assertSame(2, $r['exit']);
    assertContains('baseline missing', implode("\n", $r['lines']));
    assertTrue(!file_exists($state));
});

t('Doctor warns about public state, symlinked uploads and wp-config above the watched root', function () {
    $parent = tmpdir();
    mkdir($parent . '/public_html');
    putFile($parent, 'wp-config.php', '<?php');
    $root = $parent . '/public_html';
    mkdir($root . '/wp-content');
    symlink(tmpdir(), $root . '/wp-content/uploads');
    $c = makeConfig($root, ['profile' => 'wordpress', 'state_dir' => $root . '/state']);
    $r = Doctor::run($c, $root . '/sentinel.php', $root . '/sentinel.json');
    $out = implode("\n", $r['lines']);
    assertContains('is inside the site root', $out);
    assertContains('wp-config.php is above the site root', $out);
    assertContains('uploads directory is a symlink', $out);
});

t('Doctor reports last complete coverage separately from partial progress', function () {
    [, $c, $state, $m, , , $clock] = monitorFixture(['a.php' => '<?php', 'b.php' => '<?php']);
    assertSame(0, $m->run('full')['exit']);
    $complete = $clock->t;
    $clock->t += 600;
    $m->run('full', new Sentinel\Budget(0.0, 1));
    $history = $state->readJson('status.json')['full'];
    assertSame($complete, $history['last_complete']);
    assertSame($clock->t, $history['last_run']);
    assertSame(false, $history['complete']);
    $r = Doctor::run($c, tmpdir() . '/sentinel.php', tmpdir() . '/sentinel.json');
    assertContains('full has a partial scan pending', implode("\n", $r['lines']));
    assertContains('check does not resume full', implode("\n", $r['lines']));
});

t('Full scan detects a newly installed rule in unchanged trusted code', function () {
    [, , $state, $m, $n] = monitorFixture(['index.php' => '<?php // newly-known-signature']);
    $before = (string)file_get_contents($state->path('baseline.txt'));
    $state->writeJson('rules.json', ['version' => 1, 'patterns' => [
        ['id' => 'new-rule', 'severity' => 'critical', 'regex' => '/newly-known-signature/'],
    ]]);
    assertSame(0, $m->run('check')['exit'], 'quick scans remain stat-based');
    $r = $m->run('full');
    assertSame(1, $r['exit']);
    assertContains('0 change(s), 1 critical', $r['lines'][0]);
    assertContains('new-rule', $n->sent[0]['body']);
    assertSame($before, (string)file_get_contents($state->path('baseline.txt')));
    $m->run('full');
    assertSame(1, count($n->sent), 'unchanged findings are deduplicated');
});

t('Full scan checks unchanged WordPress files against official checksums', function () {
    [, , , $m, $n, $http] = monitorFixture([
        'wp-config.php' => '<?php',
        'wp-includes/version.php' => "<?php \$wp_version = '6.4.2';",
        'wp-includes/compromised.php' => '<?php // baselined tampering',
    ], ['profile' => 'wordpress']);
    coreRoute($http, ['wp-includes/compromised.php' => '<?php // original']);
    assertSame(0, $m->run('check')['exit']);
    $r = $m->run('full');
    assertSame(1, $r['exit']);
    assertContains('checksum-mismatch', $n->sent[0]['body']);
});

t('Full scan checks unchanged upload images and leaves clean sensitive files quiet', function () {
    [, , , $m, $n] = monitorFixture([
        'wp-config.php' => '<?php // config',
        '.htaccess' => 'RewriteEngine On',
        'wp-content/uploads/photo.jpg' => 'GIF89a <?php echo 1;',
    ], ['uploads_dir' => 'wp-content/uploads']);
    assertSame(0, $m->run('check')['exit']);
    $r = $m->run('full');
    assertSame(1, $r['exit']);
    assertContains('php-in-media', $n->sent[0]['body']);
    assertNotContains('sensitive-file-changed', $n->sent[0]['body']);
    assertNotContains('unexplained-change', $n->sent[0]['body']);
});

t('Full reanalysis resumes and reaches unchanged malware beyond its first slice', function () {
    [, , $state, $m, $n] = monitorFixture([
        'a.php' => '<?php', 'b.php' => '<?php', 'c.php' => '<?php // SENTINEL-TEST-MALWARE-MARKER',
    ]);
    $runs = 0;
    do {
        $r = $m->run('full', new Sentinel\Budget(0.0, 1));
        $runs++;
        $pending = isset($state->readJson('resume.json')['full']);
    } while ($pending && $runs < 10);
    assertSame(false, $pending);
    assertSame(4, $runs);
    assertSame(1, count($n->sent));
    assertContains('c.php', $n->sent[0]['body']);
    assertSame(true, $state->readJson('status.json')['full']['complete']);
});

t('Full reanalysis does not claim existing trusted symlinks have changed', function () {
    [$root, $c, $state, $m, $n] = monitorFixture(['index.php' => '<?php']);
    symlink($root . '/index.php', $root . '/existing-link');
    snapshot($c, $state->path('baseline.txt'));
    assertSame(0, $m->run('full')['exit']);
    assertSame([], $n->sent);
});
