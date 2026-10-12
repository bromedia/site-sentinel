<?php
declare(strict_types=1);

use Sentinel\Config;
use Sentinel\PathOrder;
use Sentinel\Walker;

function walkPaths(Config $c, string $after = ''): array
{
    return array_column(iterator_to_array((new Walker($c))->walk($after), false), 'path');
}

t('Walker yields files in PathOrder, skips excluded dirs and never follows symlinks', function () {
    $root = tmpdir();
    putFile($root, 'a/b.txt', '1');
    putFile($root, 'a/c/d.txt', '1');
    putFile($root, 'a.txt', '1');
    putFile($root, 'z.txt', '1');
    putFile($root, 'cache/x.php', '1');
    symlink($root . '/a', $root . '/link');
    $c = makeConfig($root, ['exclude' => ['cache/']]);
    assertSame(['a/b.txt', 'a/c/d.txt', 'a.txt', 'link', 'z.txt'], walkPaths($c));
    $recs = iterator_to_array((new Walker($c))->walk(), false);
    $link = array_values(array_filter($recs, function ($r) { return $r['path'] === 'link'; }))[0];
    assertSame(0120000, $link['mode'] & 0170000);
});

t('Walker resumes strictly after a path, pruning whole directories', function () {
    $root = tmpdir();
    putFile($root, 'a/b.txt', '1');
    putFile($root, 'a/c/d.txt', '1');
    putFile($root, 'a.txt', '1');
    putFile($root, 'z.txt', '1');
    $c = makeConfig($root);
    assertSame(['a/c/d.txt', 'a.txt', 'z.txt'], walkPaths($c, 'a/b.txt'));
    assertSame(['a.txt', 'z.txt'], walkPaths($c, 'a/c/d.txt'));
    assertSame(['z.txt'], walkPaths($c, 'a.txt'));
    assertSame([], walkPaths($c, 'z.txt'));
});

t('Walker order matches PathOrder for odd names (Review Focus 1)', function () {
    $root = tmpdir();
    $names = ['123', "a\tb.php", "line\nbreak.php", 'Zed', "ünï.php", 'a b.php', 'dir/123', 'dir.txt', 'dir/ä'];
    foreach ($names as $n) {
        putFile($root, $n, 'x');
    }
    $expected = $names;
    usort($expected, [PathOrder::class, 'compare']);
    assertSame($expected, walkPaths(makeConfig($root)));
});

t('Walker does not see the state dir, config or script inside the web root (Review Focus 3)', function () {
    $root = tmpdir();
    putFile($root, 'index.php', '<?php');
    putFile($root, '.sentinel/baseline.txt', 'x');
    putFile($root, 'sentinel.php', '<?php');
    putFile($root, 'sentinel.json', '{}');
    $c = Config::fromArray(['site_name' => 'x', 'site_root' => $root, 'state_dir' => $root . '/.sentinel', 'profile' => 'generic']);
    $c->addExclusion($root . '/sentinel.php');
    $c->addExclusion($root . '/sentinel.json');
    assertSame(['index.php'], walkPaths($c));
});

t('Walker honours watch roots and reports unreadable directories', function () {
    $root = tmpdir();
    putFile($root, 'index.php', '1');
    putFile($root, 'wp-content/a.php', '1');
    putFile($root, 'other/x.php', '1');
    assertSame(['index.php', 'wp-content/a.php'], walkPaths(makeConfig($root, ['watch' => ['wp-content', 'index.php']])));

    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        skip('root can read everything');
    }
    putFile($root, 'locked/y.php', '1');
    chmod($root . '/locked', 0000);
    $w = new Walker(makeConfig($root));
    iterator_to_array($w->walk(), false);
    chmod($root . '/locked', 0755);
    assertSame(['locked'], $w->unreadable());
});
