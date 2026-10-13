<?php
declare(strict_types=1);

use Sentinel\Config;
use Sentinel\NativeHttp;
use Sentinel\Proc;

function buildDist(string $target): void
{
    $r = Proc::run([PHP_BINARY, __DIR__ . '/../build/build.php', $target], 60);
    assertSame(0, $r['exit'], $r['out'] . $r['err']);
}

/** @return array{exit:int, out:string, err:string} */
function sentinel(string $dist, array $args): array
{
    $r = Proc::run(array_merge([PHP_BINARY, $dist], $args), 120);
    return ['exit' => $r['exit'], 'out' => $r['out'], 'err' => $r['err']];
}

function plugin(string $version, string $body): string
{
    return "<?php\n/*\nPlugin Name: Foo\nVersion: $version\n*/\n// $body\n";
}

t('build produces a valid single file that reports its version and usage', function () {
    $dist = tmpdir() . '/sentinel.php';
    buildDist($dist);
    $lint = Proc::run([PHP_BINARY, '-l', $dist], 30);
    assertSame(0, $lint['exit'], $lint['out'] . $lint['err']);
    assertSame(trim((string)file_get_contents(__DIR__ . '/../VERSION')), trim(sentinel($dist, ['version'])['out']));
    assertContains('update-rules', sentinel($dist, ['help'])['out']);
    // No shebang: under a web server it would be emitted as output ahead of declare(strict_types).
    assertSame('<?php', substr((string)file_get_contents($dist), 0, 5));
});

t('the built script refuses to run under a web server (answers 404, prints nothing)', function () {
    $docroot = tmpdir();
    buildDist($docroot . '/sentinel.php');
    $sock = stream_socket_server('tcp://127.0.0.1:0');
    $name = stream_socket_get_name($sock, false);
    $port = (int)substr($name, (int)strrpos($name, ':') + 1);
    fclose($sock);
    $proc = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', $docroot], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    try {
        for ($i = 0; $i < 50; $i++) {
            $c = @fsockopen('127.0.0.1', $port, $en, $es, 0.2);
            if ($c) {
                fclose($c);
                break;
            }
            usleep(100000);
        }
        $r = (new NativeHttp())->request('GET', "http://127.0.0.1:$port/sentinel.php", '', [], 5);
        assertSame(404, $r['status']);
        assertSame('', $r['body']);
    } finally {
        proc_terminate($proc);
        proc_close($proc);
    }
});

t('end to end: a WordPress site with the tool installed inside the web root', function () {
    $site = tmpdir();
    $out = tmpdir();
    $alerts = $out . '/alerts.log';
    $dist = $site . '/sentinel.php';
    buildDist($dist);
    putFile($site, 'wp-config.php', '<?php // config');
    putFile($site, 'wp-includes/version.php', "<?php\n\$wp_version = '6.4.2';\n");
    putFile($site, 'index.php', '<?php // front controller');
    putFile($site, 'wp-content/plugins/foo/foo.php', plugin('1.0', 'v1'));
    putFile($site, 'wp-content/uploads/2026/photo.jpg', 'GIF89a');
    putFile($site, 'wp-content/cache/page.html', '<html>');
    $cfg = ['--config=' . $site . '/sentinel.json'];

    $init = sentinel($dist, ['init', '--root=' . $site, '--file=' . $alerts, '--no-wp-checksums', '--name=E2E', '--config=' . $site . '/sentinel.json', '--state=' . $site . '/.sentinel']);
    assertSame(0, $init['exit'], $init['out'] . $init['err']);
    assertContains('profile wordpress', $init['out']);
    assertContains('*/10 * * * * php', $init['out']);

    // This test edits files in quick succession; the update grace period (covered by its own tests) would defer them.
    $cfgJson = json_decode((string)file_get_contents($site . '/sentinel.json'), true);
    assertSame(120, $cfgJson['update_grace_seconds']);
    $cfgJson['update_grace_seconds'] = 0;
    file_put_contents($site . '/sentinel.json', json_encode($cfgJson));
    // Editing the config is itself a tripwire event until it is accepted.
    $tamper = sentinel($dist, array_merge(['check'], ['--config=' . $site . '/sentinel.json']));
    assertSame(1, $tamper['exit']);
    assertContains('self-tamper', $tamper['out']);
    assertSame(0, sentinel($dist, ['accept', '--self', '--config=' . $site . '/sentinel.json'])['exit']);
    unlink($alerts); // forget the tripwire alert so the next assertions start from a clean log

    // Everything the tool put inside the web root is invisible to it.
    $clean = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(0, $clean['exit'], $clean['out'] . $clean['err']);
    assertContains('0 change(s)', $clean['out']);
    assertTrue(!is_file($alerts), 'no alert for a clean site');

    // PHP in uploads: Critical, alerted once.
    putFile($site, 'wp-content/uploads/2026/x.php', '<?php echo 1;');
    $r = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(1, $r['exit'], $r['out'] . $r['err']);
    assertContains('php-in-uploads', $r['out']);
    assertSame(1, substr_count((string)file_get_contents($alerts), 'php-in-uploads: PHP file in the uploads directory'));
    sentinel($dist, array_merge(['check'], $cfg));
    assertSame(1, substr_count((string)file_get_contents($alerts), 'php-in-uploads: PHP file in the uploads directory'), 'second run does not re-alert');

    // Malware marker in a plugin.
    putFile($site, 'wp-content/plugins/foo/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $r = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(1, $r['exit']);
    assertContains('test-marker', (string)file_get_contents($alerts));

    // Cleaning up returns the site to clean.
    unlink($site . '/wp-content/uploads/2026/x.php');
    unlink($site . '/wp-content/plugins/foo/evil.php');
    assertSame(0, sentinel($dist, array_merge(['check'], $cfg))['exit']);

    // A real plugin update (version bump) is silent.
    $before = (string)file_get_contents($alerts);
    bump($site, 'wp-content/plugins/foo/foo.php', plugin('1.1', 'v2'));
    $r = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(0, $r['exit'], $r['out'] . $r['err']);
    assertSame($before, (string)file_get_contents($alerts));

    // A quiet edit without a version change is a Warning; accept clears it.
    bump($site, 'wp-content/plugins/foo/foo.php', plugin('1.1', 'quietly changed'), 200);
    $r = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(1, $r['exit']);
    assertContains('unexplained-change', (string)file_get_contents($alerts));
    assertSame(0, sentinel($dist, array_merge(['accept'], $cfg))['exit']);
    assertSame(0, sentinel($dist, array_merge(['check'], $cfg))['exit']);
    assertSame(0, sentinel($dist, array_merge(['full'], $cfg))['exit']);

    // Replacing the script is tampering until it is accepted.
    file_put_contents($dist, "\n// modified\n", FILE_APPEND);
    $r = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(1, $r['exit']);
    assertContains('self-tamper', (string)file_get_contents($alerts));
    assertSame(0, sentinel($dist, array_merge(['accept', '--self'], $cfg))['exit']);
    assertSame(0, sentinel($dist, array_merge(['check'], $cfg))['exit']);

    // Losing the baseline is an error, never a flood of "new" files.
    unlink($site . '/.sentinel/baseline.txt');
    $r = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(2, $r['exit']);
    assertContains('no baseline', $r['err']);
});

t('end to end: init refuses an infected site unless forced', function () {
    $site = tmpdir();
    $out = tmpdir();
    $dist = $out . '/sentinel.php';
    buildDist($dist);
    putFile($site, 'index.php', '<?php');
    putFile($site, 'lib/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $args = ['init', '--root=' . $site, '--file=' . $out . '/alerts.log', '--no-wp-checksums'];
    $r = sentinel($dist, $args);
    assertSame(1, $r['exit'], $r['out'] . $r['err']);
    assertContains('lib/evil.php', $r['out']);
    assertTrue(!is_file($out . '/sentinel-state/baseline.txt'));
    $forced = sentinel($dist, array_merge($args, ['--force']));
    assertSame(0, $forced['exit'], $forced['out'] . $forced['err']);
    assertTrue(is_file($out . '/sentinel-state/baseline.txt'));
});

t('the example config loads once its paths are filled in', function () {
    $raw = json_decode((string)file_get_contents(__DIR__ . '/../examples/sentinel.json'), true);
    assertTrue(is_array($raw));
    $raw['site_root'] = tmpdir();
    $raw['state_dir'] = tmpdir();
    $c = Config::fromArray($raw);
    assertTrue(count($c->channels) >= 3);
});
