<?php
declare(strict_types=1);

use Sentinel\Config;
use Sentinel\VersionTracker;
use Sentinel\WpChecksum;

function wpSite(string $root, string $version = '6.4.2'): Config
{
    putFile($root, 'wp-config.php', '<?php');
    putFile($root, 'wp-includes/version.php', "<?php\n\$wp_version = '$version';\n");
    return makeConfig($root, ['profile' => 'wordpress']);
}

/** @param array<string,string> $files path => official content */
function coreRoute(FakeHttp $http, array $files, string $version = '6.4.2'): void
{
    $sums = [];
    foreach ($files as $rel => $content) {
        $sums[$rel] = md5($content);
    }
    $http->route('https://api.wordpress.org/core/checksums/1.0/?version=' . $version, 200, json_encode(['checksums' => $sums]));
}

function pluginHeader(string $version): string
{
    return "<?php\n/*\nPlugin Name: Foo\nVersion: $version\n*/\n";
}

t('VersionTracker reads plugin and theme versions and skips unversioned directories', function () {
    $root = tmpdir();
    $c = wpSite($root);
    putFile($root, 'wp-content/plugins/foo/foo.php', pluginHeader('1.2.3'));
    putFile($root, 'wp-content/plugins/foo/readme.php', "<?php // Version: 9.9.9 (not a plugin header)\n");
    putFile($root, 'wp-content/plugins/nover/nover.php', "<?php // nothing\n");
    putFile($root, 'wp-content/plugins/.hidden/x.php', pluginHeader('7'));
    putFile($root, 'wp-content/themes/twenty/style.css', "/*\nTheme Name: Twenty\nVersion: 2.0 */\n");
    assertSame([
        'wp-content/plugins/foo' => '1.2.3',
        'wp-content/themes/twenty' => '2.0',
    ], VersionTracker::read($c));
    assertSame('1.2.3', VersionTracker::dirVersion($c, 'wp-content/plugins/foo'));
    assertSame(null, VersionTracker::dirVersion($c, 'wp-content/plugins/missing'));
});

t('WpChecksum verifies core files against the official checksums and caches them', function () {
    $root = tmpdir();
    $c = wpSite($root);
    putFile($root, 'wp-includes/a.php', 'A');
    putFile($root, 'wp-includes/bad.php', 'tampered');
    putFile($root, 'wp-includes/extra.php', 'E');
    putFile($root, 'wp-content/themes/x/t.php', 'T');
    $cache = tmpdir();
    $http = new FakeHttp();
    coreRoute($http, ['wp-includes/a.php' => 'A', 'wp-includes/bad.php' => 'original']);
    $wp = new WpChecksum($http, $c, $cache);
    assertSame(WpChecksum::VERIFIED, $wp->verify('wp-includes/a.php'));
    assertSame(WpChecksum::MISMATCH, $wp->verify('wp-includes/bad.php'));
    assertSame(WpChecksum::EXTRA, $wp->verify('wp-includes/extra.php'));
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-content/themes/x/t.php'));
    assertTrue($wp->isCorePath('wp-includes/a.php'));
    assertTrue(!$wp->isCorePath('wp-content/themes/x/t.php'));
    assertSame(1, count($http->calls), 'core map fetched once');
    assertSame([], $wp->notes());

    $offline = new FakeHttp();
    $again = new WpChecksum($offline, $c, $cache);
    assertSame(WpChecksum::VERIFIED, $again->verify('wp-includes/a.php'));
    assertSame(0, count($offline->calls), 'second run uses the disk cache');
});

t('WpChecksum never claims match or mismatch when wordpress.org is unreachable (Review Focus 4)', function () {
    $root = tmpdir();
    $c = wpSite($root);
    putFile($root, 'wp-includes/a.php', 'A');
    putFile($root, 'wp-content/plugins/foo/foo.php', pluginHeader('1.0'));
    $http = new FakeHttp(); // no routes: every request fails
    $wp = new WpChecksum($http, $c, tmpdir());
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-includes/a.php'));
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-content/plugins/foo/foo.php'));
    assertTrue(count($wp->notes()) >= 2, 'expected notes, got ' . json_encode($wp->notes()));
    assertContains('unavailable', implode(' ', $wp->notes()));
    assertTrue($wp->isCorePath('wp-includes/anything.php'), 'falls back to the directory prefix');
    // Each lookup is attempted once per run, not once per file.
    $before = count($http->calls);
    $wp->verify('wp-includes/b.php');
    $wp->verify('wp-content/plugins/foo/other.php');
    assertSame($before, count($http->calls));
});

t('WpChecksum verifies repository plugins and stays silent for premium ones', function () {
    $root = tmpdir();
    $c = wpSite($root);
    putFile($root, 'wp-content/plugins/foo/foo.php', pluginHeader('1.0'));
    putFile($root, 'wp-content/plugins/foo/inc/x.php', 'X');
    putFile($root, 'wp-content/plugins/foo/inc/y.php', 'Y-tampered');
    putFile($root, 'wp-content/plugins/foo/inc/new.php', 'N');
    putFile($root, 'wp-content/plugins/premium/premium.php', pluginHeader('3.1'));
    putFile($root, 'wp-content/plugins/noheader/a.php', '<?php');
    putFile($root, 'wp-content/plugins/we ird/b.php', pluginHeader('1'));
    $http = new FakeHttp();
    coreRoute($http, ['index.php' => 'x']);
    // The real wordpress.org shape: files => path => {md5, sha256}, each a string or a list.
    $http->route('https://downloads.wordpress.org/plugin-checksums/foo/1.0.json', 200, json_encode([
        'plugin' => 'foo', 'version' => '1.0', 'source' => 'https://plugins.svn.wordpress.org/foo/tags/1.0/', 'zip' => 'https://downloads.wordpress.org/plugin/foo.1.0.zip',
        'files' => [
            'inc/x.php' => ['md5' => md5('X'), 'sha256' => [hash('sha256', 'X')]],
            'inc/y.php' => ['md5' => md5('Y'), 'sha256' => hash('sha256', 'Y')],
            'foo.php' => ['md5' => [md5(pluginHeader('1.0'))]],
        ],
    ]));
    $http->route('https://downloads.wordpress.org/plugin-checksums/premium/', 404, '{"error":"not found"}');
    $wp = new WpChecksum($http, $c, tmpdir());
    assertSame(WpChecksum::VERIFIED, $wp->verify('wp-content/plugins/foo/inc/x.php'));
    assertSame(WpChecksum::MISMATCH, $wp->verify('wp-content/plugins/foo/inc/y.php'));
    assertSame(WpChecksum::VERIFIED, $wp->verify('wp-content/plugins/foo/foo.php'));
    assertSame(WpChecksum::EXTRA, $wp->verify('wp-content/plugins/foo/inc/new.php'));
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-content/plugins/premium/premium.php'));
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-content/plugins/noheader/a.php'));
    $calls = count($http->calls);
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-content/plugins/we ird/b.php'));
    assertSame($calls, count($http->calls), 'unsafe slugs are never sent to the API');
    assertSame([], $wp->notes(), 'a 404 means "not in the repository" and is not a problem');
});

t('WpChecksum reports a missing WordPress version as a note', function () {
    $root = tmpdir();
    putFile($root, 'wp-config.php', '<?php');
    $c = makeConfig($root, ['profile' => 'wordpress']);
    $wp = new WpChecksum(new FakeHttp(), $c, tmpdir());
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-includes/a.php'));
    assertContains('version', implode(' ', $wp->notes()));
});

t('WpChecksum treats an unrecognised plugin checksum response as unknown, with a note', function () {
    $root = tmpdir();
    $c = wpSite($root);
    putFile($root, 'wp-content/plugins/foo/foo.php', pluginHeader('1.0'));
    $http = new FakeHttp();
    coreRoute($http, ['index.php' => 'x']);
    // An old/unexpected shape must never be read as "no files match" or as a silent premium plugin.
    $http->route('https://downloads.wordpress.org/plugin-checksums/foo/1.0.json', 200, json_encode(['sha256' => ['foo.php' => 'abc']]));
    $wp = new WpChecksum($http, $c, tmpdir());
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-content/plugins/foo/foo.php'));
    assertContains('unexpected format', implode(' ', $wp->notes()));
});
