<?php
declare(strict_types=1);

use Sentinel\Accept;
use Sentinel\VersionTracker;

/** Lines of a Monitor run that report a finding, as "SEVERITY path rule". */
function findingLines(array $r): array
{
    preg_match_all('/^\s+(CRITICAL|WARNING)\s+(\S+)\s+(\S+)/m', implode("\n", $r['lines']), $m, PREG_SET_ORDER);
    return array_map(function ($x) {
        return $x[1] . ' ' . $x[2] . ' ' . $x[3];
    }, $m);
}

function coreCalls(FakeHttp $http): int
{
    return count(array_filter($http->calls, function ($c) {
        return strpos($c[1], 'core/checksums') !== false;
    }));
}

t('WordPress in subfolders: each install is checked against its own release, fetched once per release', function () {
    $core642 = ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n", 'wp-includes/load.php' => "<?php // load 6.4.2\n"];
    $core65 = ['wp-includes/version.php' => "<?php\n\$wp_version = '6.5';\n", 'wp-includes/load.php' => "<?php // load 6.5\n"];
    $files = ['index.php' => '<?php // a plain site', 'wp-admin/tool.php' => '<?php // not WordPress', 'store/wp-includes/load.php' => '<?php // before the update'];
    foreach (['books' => $core642, 'store' => $core642, 'shop/dev' => $core65] as $p => $core) {
        foreach ($core as $rel => $c) {
            $files += ["$p/$rel" => $c];
        }
    }
    [$root, $config, , $m, $n, $http] = monitorFixture($files);
    assertSame('generic', $config->profile);
    coreRoute($http, $core642, '6.4.2');
    coreRoute($http, $core65, '6.5');

    bump($root, 'books/wp-includes/load.php', "<?php // changed by someone\n");
    bump($root, 'store/wp-includes/load.php', $core642['wp-includes/load.php']); // updated to the official file
    putFile($root, 'shop/dev/wp-admin/extra.php', '<?php // not in WordPress 6.5');
    bump($root, 'wp-admin/tool.php', '<?php // edited'); // outside every install: no WordPress rules
    $r = $m->run('check');
    $found = findingLines($r);
    sort($found);
    assertSame([
        'CRITICAL books/wp-includes/load.php checksum-mismatch',
        'WARNING shop/dev/wp-admin/extra.php unexpected-file',
        'WARNING wp-admin unexplained-change',
    ], $found, implode("\n", $r['lines']));
    assertContains('1 file(s) verified against official WordPress.org checksums', end($n->sent)['body'], 'store/wp-includes/load.php');
    assertSame(2, coreCalls($http), 'books and store share 6.4.2: one download for both');
});

t('WordPress in subfolders: checksums that cannot be downloaded are noted, and the change is still reported', function () {
    $core = ['wp-includes/version.php' => "<?php\n\$wp_version = '6.5';\n", 'wp-includes/load.php' => "<?php // load\n"];
    [$root, , , $m, $n, $http] = monitorFixture([
        'books/wp-includes/version.php' => $core['wp-includes/version.php'], 'books/wp-includes/load.php' => $core['wp-includes/load.php'],
        'cafe/wp-includes/version.php' => $core['wp-includes/version.php'], 'cafe/wp-includes/load.php' => $core['wp-includes/load.php'],
    ]);
    $http->route('https://api.wordpress.org/core/checksums/', 503, 'unavailable');
    bump($root, 'books/wp-includes/load.php', "<?php // changed\n");
    bump($root, 'cafe/wp-includes/load.php', "<?php // changed too\n");
    $r = $m->run('check');
    assertSame(['WARNING books unexplained-change', 'WARNING cafe unexplained-change'], findingLines($r), implode("\n", $r['lines']));
    assertSame(1, coreCalls($http), 'a failed download is not repeated for every install on that release');
    assertContains('WordPress core checksums unavailable (HTTP 503)', end($n->sent)['body']);
});

t('WordPress in subfolders: plugin updates follow the update policy, repository plugins are verified, accept --path works', function () {
    $shop = "<?php\n/*\nPlugin Name: Shop\nVersion: 1.0\n*/\n";
    $foo = "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\nfunction foo() {}\n";
    $site = [
        'books/wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n",
        'books/wp-content/plugins/shop/shop.php' => $shop,
        'books/wp-content/plugins/foo/foo.php' => $foo,
        'books/wp-content/themes/twenty/style.css' => "/*\nTheme Name: Twenty\nVersion: 2.0\n*/\n",
    ];
    $routes = function (FakeHttp $http) use ($foo): void {
        coreRoute($http, ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n"]);
        $http->route('https://downloads.wordpress.org/plugin-checksums/foo/1.0.json', 200, json_encode(['files' => ['foo.php' => ['sha256' => hash('sha256', $foo)]]]));
        $http->route('https://downloads.wordpress.org/plugin-checksums/', 404, '{"error":"not found"}');
    };

    // Approved automatically: a premium plugin's update is accepted, with a note.
    [$root, $config, $state, $m, , $http] = monitorFixture($site, ['auto_accept_unverified_updates' => true]);
    $state->writeJson('versions.json', VersionTracker::read($config));
    assertSame(['books/wp-content/plugins/foo' => '1.0', 'books/wp-content/plugins/shop' => '1.0', 'books/wp-content/themes/twenty' => '2.0'], $state->readJson('versions.json'));
    $routes($http);
    bump($root, 'books/wp-content/plugins/shop/shop.php', str_replace('1.0', '1.1', $shop) . "// new code\n");
    $r = $m->run('check');
    assertSame([], findingLines($r), implode("\n", $r['lines']));
    assertSame('1.1', $state->readJson('versions.json')['books/wp-content/plugins/shop']);
    assertContains(hash_file('sha256', $root . '/books/wp-content/plugins/shop/shop.php'), (string)file_get_contents($state->path('baseline.txt')), 'the update is accepted');
    // ...but not a fake version of a plugin wordpress.org publishes.
    bump($root, 'books/wp-content/plugins/foo/foo.php', str_replace('1.0', '1.0.9', $foo) . "// quietly changed\n");
    assertSame(['WARNING books/wp-content/plugins/foo unverified-update'], findingLines($m->run('check')));

    // Reported for review: the update waits until accepted by path.
    [$root, $config, $state, $m, , $http] = monitorFixture($site, ['auto_accept_unverified_updates' => false]);
    $state->writeJson('versions.json', VersionTracker::read($config));
    $routes($http);
    bump($root, 'books/wp-content/plugins/shop/shop.php', str_replace('1.0', '1.1', $shop) . "// new code\n");
    assertSame(['WARNING books/wp-content/plugins/shop unverified-update'], findingLines($m->run('check')));
    assertSame('1.0', $state->readJson('versions.json')['books/wp-content/plugins/shop'], 'not recorded before review');
    Accept::run($config, $state, ['books/wp-content/plugins/shop'], false, []);
    assertSame('1.1', $state->readJson('versions.json')['books/wp-content/plugins/shop']);
    $r = $m->run('check');
    assertSame([], findingLines($r), implode("\n", $r['lines']));
});

t('WordPress in subfolders: state from before (no or root-only versions.json) keeps working', function () {
    $foo = "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n";
    // A WordPress website folder whose versions.json was written by the earlier version, root keys only.
    [$root, $config, $state, $m, , $http] = monitorFixture([
        'wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n",
        'wp-content/plugins/foo/foo.php' => $foo,
        'blog/wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n",
        'blog/wp-content/plugins/foo/foo.php' => $foo,
    ], ['profile' => 'wordpress', 'wp_checksums' => false, 'auto_accept_unverified_updates' => true]);
    $state->writeJson('versions.json', ['wp-content/plugins/foo' => '1.0']);
    $r = $m->run('check');
    assertSame(0, $r['exit'], implode("\n", $r['lines']));
    $v = $state->readJson('versions.json');
    ksort($v);
    assertSame(['blog/wp-content/plugins/foo' => '1.0', 'wp-content/plugins/foo' => '1.0'], $v);
    bump($root, 'wp-content/plugins/foo/foo.php', str_replace('1.0', '1.1', $foo));
    bump($root, 'blog/wp-content/plugins/foo/foo.php', str_replace('1.0', '1.2', $foo));
    $r = $m->run('check');
    assertSame([], findingLines($r), implode("\n", $r['lines']));
    assertSame('1.1', $state->readJson('versions.json')['wp-content/plugins/foo']);
    assertSame('1.2', $state->readJson('versions.json')['blog/wp-content/plugins/foo']);

    // A plain website folder: the earlier version wrote no versions.json at all.
    [$root, , $state, $m] = monitorFixture(['books/wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n", 'books/wp-content/plugins/foo/foo.php' => $foo], ['wp_checksums' => false, 'auto_accept_unverified_updates' => true]);
    assertSame(0, $m->run('check')['exit']);
    assertSame(['books/wp-content/plugins/foo' => '1.0'], $state->readJson('versions.json'));
    bump($root, 'books/wp-content/plugins/foo/foo.php', str_replace('1.0', '1.1', $foo));
    assertSame([], findingLines($m->run('check')));
    assertSame('1.1', $state->readJson('versions.json')['books/wp-content/plugins/foo']);
});
