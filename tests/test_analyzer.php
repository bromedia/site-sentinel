<?php
declare(strict_types=1);

use Sentinel\Analyzer;
use Sentinel\Config;
use Sentinel\ExternalScanner;
use Sentinel\Finding;
use Sentinel\LocationScanner;
use Sentinel\PatternScanner;
use Sentinel\Report;
use Sentinel\Rules;
use Sentinel\VersionTracker;
use Sentinel\WpChecksum;

function analyzerFor(Config $c, ?WpChecksum $wp = null, ?ExternalScanner $x = null): Analyzer
{
    return new Analyzer($c, new PatternScanner(Rules::builtin(), 1048576), new LocationScanner($c), $wp, $x ?? new ExternalScanner(null, null, null));
}

/** Creates a WordPress site, snapshots it, and returns [root, config, baselineFile]. */
function wpFixture(array $files = [], array $cfg = []): array
{
    $root = tmpdir();
    putFile($root, 'wp-config.php', '<?php // config');
    putFile($root, 'wp-includes/version.php', "<?php\n\$wp_version = '6.4.2';\n");
    putFile($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n// v1\n");
    putFile($root, 'wp-content/uploads/pic.jpg', 'GIF89a');
    foreach ($files as $rel => $content) {
        putFile($root, $rel, $content);
    }
    $c = makeConfig($root, array_merge(['profile' => 'wordpress'], $cfg));
    $b = tmpdir() . '/b.txt';
    snapshot($c, $b);
    return [$root, $c, $b];
}

function runAnalysis(Config $c, string $b, ?Analyzer $a = null, array $old = [], bool $initial = false, bool $full = false, int $now = 0): array
{
    $changes = array_values(diffByPath($c, $b, $full));
    $new = VersionTracker::read($c);
    return ($a ?? analyzerFor($c))->analyze($changes, $old, $new, $initial, $now);
}

function ruleList(array $r): array
{
    $out = array_map(function (Finding $f) { return $f->rule . '@' . $f->path; }, $r['findings']);
    sort($out);
    return $out;
}

t('Analyzer: PHP in uploads is Critical and held, a benign new image passes', function () {
    [$root, $c, $b] = wpFixture();
    putFile($root, 'wp-content/uploads/x.php', '<?php echo 1;');
    putFile($root, 'wp-content/uploads/new.jpg', 'GIF89a');
    $r = runAnalysis($c, $b);
    assertSame(['php-in-uploads@wp-content/uploads/x.php'], ruleList($r));
    assertSame(Finding::CRITICAL, $r['findings'][0]->severity);
    assertSame(['wp-content/uploads/x.php' => true], $r['hold']);
});

t('Analyzer: scanner hits in a plugin are Critical, held, and not double-reported as unexplained', function () {
    [$root, $c, $b] = wpFixture();
    $old = VersionTracker::read($c);
    putFile($root, 'wp-content/plugins/foo/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $r = runAnalysis($c, $b, null, $old);
    assertSame(['test-marker@wp-content/plugins/foo/evil.php'], ruleList($r));
    assertTrue(isset($r['hold']['wp-content/plugins/foo/evil.php']));
    // A file held for its own finding does not hold the plugin's stored version.
    assertSame([], $r['version_holds']);
});

t('Analyzer: an unverified version bump is a held Warning by default, and a change without one too', function () {
    [$root, $c, $b] = wpFixture();
    $old = VersionTracker::read($c);
    assertSame(['wp-content/plugins/foo' => '1.0'], $old);

    // Anyone who can edit the files can edit the Version header, so a bump alone proves nothing.
    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// v2\n");
    $r = runAnalysis($c, $b, null, $old);
    assertSame(['unverified-update@wp-content/plugins/foo'], ruleList($r));
    assertSame(Finding::WARNING, $r['findings'][0]->severity);
    assertContains('1.0 -> 1.1', $r['findings'][0]->message);
    assertTrue(isset($r['hold']['wp-content/plugins/foo/foo.php']));
    assertTrue(isset($r['version_holds']['wp-content/plugins/foo']));

    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n// quietly edited\n");
    $r2 = runAnalysis($c, $b, null, $old);
    assertSame(['unexplained-change@wp-content/plugins/foo'], ruleList($r2));
    assertSame(Finding::WARNING, $r2['findings'][0]->severity);
    assertTrue(isset($r2['hold']['wp-content/plugins/foo/foo.php']));
});

t('Analyzer: auto_accept_unverified_updates restores the quiet Info for premium plugin updates', function () {
    [$root, $c, $b] = wpFixture([], ['auto_accept_unverified_updates' => true]);
    $old = VersionTracker::read($c);
    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// v2\n");
    $r = runAnalysis($c, $b, null, $old);
    assertSame([], ruleList($r));
    assertSame([], $r['hold']);
    assertContains('wp-content/plugins/foo updated 1.0 -> 1.1 (1 file(s), not verified)', implode("\n", $r['info']));
});

t('Analyzer: even with auto-accept, a wordpress.org plugin bumped to an unpublished version is a Warning', function () {
    $v1 = "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n// v1\n";
    [$root, $c, $b] = wpFixture([], ['auto_accept_unverified_updates' => true]);
    $old = VersionTracker::read($c);
    $http = new FakeHttp();
    coreRoute($http, []);
    $http->route('https://downloads.wordpress.org/plugin-checksums/foo/1.0.json', 200, json_encode(['files' => ['foo.php' => ['sha256' => hash('sha256', $v1)]]]));
    $http->route('https://downloads.wordpress.org/plugin-checksums/foo/', 404, '{"error":"not found"}');
    $a = analyzerFor($c, new WpChecksum($http, $c, tmpdir()));

    // A backdoor plus a Version header wordpress.org never published: previously silent.
    bump($root, 'wp-content/plugins/foo/foo.php', str_replace('Version: 1.0', 'Version: 1.0.9', $v1) . '$f = "sys" . "tem"; $f($_SERVER["HTTP_X"] ?? "");' . "\n");
    $r = runAnalysis($c, $b, $a, $old);
    assertSame(['unverified-update@wp-content/plugins/foo'], ruleList($r));
    assertTrue(isset($r['hold']['wp-content/plugins/foo/foo.php']));
    assertSame([], $r['info']);
});

t('Analyzer: with auto-accept, only a definite "not on wordpress.org" accepts; an unreachable wordpress.org holds', function () {
    $v1 = "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n// v1\n";
    $bumped = str_replace('Version: 1.0', 'Version: 1.0.9', $v1) . '$f = "sys" . "tem"; $f($_SERVER["HTTP_X"] ?? "");' . "\n";
    foreach ([[503, 'unavailable'], [0, '']] as [$status, $body]) {
        [$root, $c, $b] = wpFixture([], ['auto_accept_unverified_updates' => true]);
        $old = VersionTracker::read($c);
        $http = new FakeHttp();
        coreRoute($http, []);
        if ($status !== 0) {
            $http->route('https://downloads.wordpress.org/plugin-checksums/', $status, $body);
        } // status 0: no route at all, i.e. a dead network
        $a = analyzerFor($c, new WpChecksum($http, $c, tmpdir()));
        bump($root, 'wp-content/plugins/foo/foo.php', $bumped);
        $r = runAnalysis($c, $b, $a, $old);
        assertSame(['unverified-update@wp-content/plugins/foo'], ruleList($r), "status $status");
        assertTrue(isset($r['hold']['wp-content/plugins/foo/foo.php']), "status $status");
        assertContains("Checksums for plugin 'foo' unavailable", implode("\n", $r['notes']), "status $status");
    }

    // A definite 404 for the previous version: a premium plugin, so the legacy setting applies.
    [$root, $c, $b] = wpFixture([], ['auto_accept_unverified_updates' => true]);
    $old = VersionTracker::read($c);
    $http = new FakeHttp();
    coreRoute($http, []);
    $http->route('https://downloads.wordpress.org/plugin-checksums/foo/', 404, '{"error":"not found"}');
    bump($root, 'wp-content/plugins/foo/foo.php', str_replace('Version: 1.0', 'Version: 1.1', $v1));
    $r = runAnalysis($c, $b, analyzerFor($c, new WpChecksum($http, $c, tmpdir())), $old);
    assertSame([], ruleList($r));
    assertContains('wp-content/plugins/foo updated 1.0 -> 1.1', implode("\n", $r['info']));
});

t('Analyzer: a brand-new plugin directory is a Warning and many files make one finding', function () {
    [$root, $c, $b] = wpFixture();
    $old = VersionTracker::read($c);
    putFile($root, 'wp-content/plugins/bar/bar.php', "<?php\n/*\nPlugin Name: Bar\nVersion: 2.0\n*/\n");
    for ($i = 0; $i < 8; $i++) {
        putFile($root, "wp-content/plugins/bar/inc/f$i.php", '<?php // ' . $i);
    }
    $r = runAnalysis($c, $b, null, $old);
    assertSame(['unexplained-change@wp-content/plugins/bar'], ruleList($r));
    assertContains('9 file(s)', $r['findings'][0]->message);
    assertContains('each one is listed in the report', $r['findings'][0]->message);
    assertNotContains('more', $r['findings'][0]->message);
});

t('Analyzer: official checksum match is accepted silently and beats pattern hits; mismatch and extras are flagged', function () {
    [$root, $c, $b] = wpFixture();
    $marker = '<?php // SENTINEL-TEST-MALWARE-MARKER';
    bump($root, 'wp-includes/ok.php', 'official');
    bump($root, 'wp-includes/odd.php', $marker);
    bump($root, 'wp-includes/tampered.php', 'tampered');
    bump($root, 'wp-includes/extra.php', 'extra');
    $http = new FakeHttp();
    coreRoute($http, ['wp-includes/ok.php' => 'official', 'wp-includes/odd.php' => $marker, 'wp-includes/tampered.php' => 'original']);
    $wp = new WpChecksum($http, $c, tmpdir());
    $r = runAnalysis($c, $b, analyzerFor($c, $wp));
    assertSame(['checksum-mismatch@wp-includes/tampered.php', 'unexpected-file@wp-includes/extra.php'], ruleList($r));
    assertContains('2 file(s) verified', implode("\n", $r['info']));
    $sev = [];
    foreach ($r['findings'] as $f) {
        $sev[$f->rule] = $f->severity;
    }
    ksort($sev);
    assertSame(['checksum-mismatch' => Finding::CRITICAL, 'unexpected-file' => Finding::WARNING], $sev);
});

t('Analyzer: stealth modification is Critical', function () {
    [$root, $c, $b] = wpFixture(['lib/a.php' => 'AAAA']);
    $m = filemtime($root . '/lib/a.php');
    file_put_contents($root . '/lib/a.php', 'BBBB');
    touch($root . '/lib/a.php', $m);
    clearstatcache();
    $r = runAnalysis($c, $b, null, [], false, true);
    assertSame(['stealth-modification@lib/a.php'], ruleList($r));
    assertSame(Finding::CRITICAL, $r['findings'][0]->severity);
});

t('Analyzer: initial mode keeps only Critical findings and holds nothing', function () {
    [$root, $c, $b] = wpFixture();
    $old = VersionTracker::read($c);
    putFile($root, 'wp-content/plugins/bar/bar.php', "<?php\n/*\nPlugin Name: Bar\nVersion: 2.0\n*/\n");
    putFile($root, 'wp-content/uploads/x.php', '<?php echo 1;');
    $r = runAnalysis($c, $b, null, $old, true);
    assertSame(['php-in-uploads@wp-content/uploads/x.php'], ruleList($r));
    assertSame([], $r['hold']);
    assertSame([], $r['info']);
});

t('Analyzer: symlinks, sensitive files and world-writable changes are Warnings', function () {
    [$root, $c, $b] = wpFixture();
    symlink('/etc', $root . '/wp-content/etc-link');
    bump($root, 'wp-config.php', '<?php // edited');
    chmod($root . '/wp-content/plugins/foo/foo.php', 0666);
    $r = runAnalysis($c, $b, null, VersionTracker::read($c));
    assertSame(['sensitive-file-changed@wp-config.php', 'symlink@wp-content/etc-link', 'world-writable@wp-content/plugins/foo/foo.php'], ruleList($r));
    foreach ($r['findings'] as $f) {
        assertSame(Finding::WARNING, $f->severity);
    }
});

t('Analyzer: a touch-only change is silent', function () {
    [$root, $c, $b] = wpFixture();
    touch($root . '/wp-config.php', time() + 900);
    touch($root . '/wp-content/plugins/foo/foo.php', time() + 900);
    $r = runAnalysis($c, $b, null, VersionTracker::read($c));
    assertSame([], ruleList($r));
    assertSame([], $r['hold']);
});

t('Analyzer: removed core and sensitive files are Warnings, other removals are counted', function () {
    [$root, $c, $b] = wpFixture(['wp-includes/a.php' => 'A', 'notes.txt' => 'n']);
    $http = new FakeHttp();
    coreRoute($http, ['wp-includes/a.php' => 'A']);
    $wp = new WpChecksum($http, $c, tmpdir());
    unlink($root . '/wp-includes/a.php');
    unlink($root . '/wp-config.php');
    unlink($root . '/notes.txt');
    $r = runAnalysis($c, $b, analyzerFor($c, $wp));
    assertSame(['core-file-removed@wp-includes/a.php', 'sensitive-file-removed@wp-config.php'], ruleList($r));
    assertContains('1 file(s) removed', implode("\n", $r['info']));
    assertSame(2, count($r['hold']));
});

t('Analyzer: external scanner hits are Critical, held, and leave their group', function () {
    [$root, $c, $b] = wpFixture(['lib/clean.php' => 'ok']);
    $clam = fakeTool(tmpdir(), 'clamscan', 'rc=0
for f in "$@"; do
  case "$f" in -*) continue;; esac
  if grep -q EICAR "$f"; then echo "$f: Fake.Eicar FOUND"; rc=1; fi
done
exit $rc
');
    bump($root, 'lib/clean.php', 'still ok');
    putFile($root, 'lib/x.php', 'EICAR');
    $r = runAnalysis($c, $b, analyzerFor($c, null, new ExternalScanner($clam, null, null)));
    assertSame(['clamav:Fake.Eicar@lib/x.php', 'unexplained-change@lib'], ruleList($r));
    assertContains('1 file(s)', array_values(array_filter($r['findings'], function ($f) { return $f->rule === 'unexplained-change'; }))[0]->message);
});

t('Analyzer: unreadable files and initial-scan wants', function () {
    [$root, $c, $b] = wpFixture();
    $a = analyzerFor($c);
    assertTrue($a->wantsAnalysis(['path' => 'x.php', 'mode' => 0100644]));
    assertTrue($a->wantsAnalysis(['path' => 'wp-content/uploads/a.jpg', 'mode' => 0100644]));
    assertTrue($a->wantsAnalysis(['path' => 'x.txt', 'mode' => 0100755]));
    assertTrue($a->wantsAnalysis(['path' => 'x.txt', 'mode' => 0120777]));
    assertTrue(!$a->wantsAnalysis(['path' => 'readme.txt', 'mode' => 0100644]));
    assertSame('wp-content/plugins/foo', Analyzer::groupOf('wp-content/plugins/foo/inc/a.php'));
    assertSame('wp-content/themes/t', Analyzer::groupOf('wp-content/themes/t/style.css'));
    assertSame('wp-includes', Analyzer::groupOf('wp-includes/a.php'));
    assertSame('.', Analyzer::groupOf('index.php'));

    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        skip('root can read everything');
    }
    $f = putFile($root, 'lib/locked.php', '<?php');
    chmod($f, 0000);
    $r = runAnalysis($c, $b);
    chmod($f, 0644);
    assertSame(['unreadable@lib/locked.php'], ruleList($r));
});

t('Analyzer: a double-extension PHP file in a theme is never accepted silently', function () {
    [$root, $c, $b] = wpFixture();
    putFile($root, 'wp-content/themes/t/evil.php.jpg', 'GIF89a');
    $r = runAnalysis($c, $b, null, VersionTracker::read($c));
    assertSame(['double-extension@wp-content/themes/t/evil.php.jpg'], ruleList($r));
    assertTrue(isset($r['hold']['wp-content/themes/t/evil.php.jpg']));
});

t('Analyzer: files that just arrived are given a grace period before update-explainable findings', function () {
    [$root, $c, $b] = wpFixture(['lib/old.php' => '<?php // old'], ['update_grace_seconds' => 120]);
    $old = VersionTracker::read($c);
    putFile($root, 'wp-includes/tampered.php', 'tampered');
    putFile($root, 'lib/a.php', '<?php // a');
    $http = new FakeHttp();
    coreRoute($http, ['wp-includes/tampered.php' => 'official-new-version']);
    $analyzer = analyzerFor($c, new WpChecksum($http, $c, tmpdir()));

    // Just arrived: a mid-update checksum mismatch and an unexplained plugin/lib change are deferred, not alerted or accepted.
    $r = runAnalysis($c, $b, $analyzer, $old, false, false, time());
    assertSame([], ruleList($r));
    assertSame(['lib/a.php' => true, 'wp-includes/tampered.php' => true], array_map(function () { return true; }, $r['hold']));
    assertContains('2 file(s) changed within the last 120', implode("\n", $r['info']));

    // The same state a few minutes later is judged normally.
    $later = runAnalysis($c, $b, analyzerFor($c, new WpChecksum($http, $c, tmpdir())), $old, false, false, time() + 600);
    assertSame(['checksum-mismatch@wp-includes/tampered.php', 'unexplained-change@lib'], ruleList($later));
});

t('Analyzer: the grace period never delays scanner hits or sensitive changes', function () {
    [$root, $c, $b] = wpFixture([], ['update_grace_seconds' => 120]);
    putFile($root, 'lib/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    putFile($root, 'wp-content/uploads/x.php', '<?php echo 1;');
    bump($root, 'wp-config.php', '<?php // edited by someone', 0);
    $r = runAnalysis($c, $b, null, VersionTracker::read($c), false, false, time());
    assertSame(['php-in-uploads@wp-content/uploads/x.php', 'sensitive-file-changed@wp-config.php', 'test-marker@lib/evil.php'], ruleList($r));
});

t('Analyzer: a zero grace period or no clock disables deferral', function () {
    [$root, $c, $b] = wpFixture([], ['update_grace_seconds' => 0]);
    putFile($root, 'lib/a.php', '<?php // a');
    assertSame(['unexplained-change@lib'], ruleList(runAnalysis($c, $b, null, [], false, false, time())));
    [$root2, $c2, $b2] = wpFixture([], ['update_grace_seconds' => 120]);
    putFile($root2, 'lib/a.php', '<?php // a');
    assertSame(['unexplained-change@lib'], ruleList(runAnalysis($c2, $b2, null, [], false, false, 0)));
});

t('Analyzer reports an outcome for every changed file', function () {
    [$root, $c, $b] = wpFixture([
        'wp-includes/ok.php' => 'old',
        'notes.txt' => 'n',
        'lib/perm.php' => '<?php // perm',
        'lib/gone.php' => '<?php // gone',
    ], ['auto_accept_unverified_updates' => true, 'update_grace_seconds' => 120]);
    $old = VersionTracker::read($c);
    bump($root, 'wp-includes/ok.php', 'official');                    // verified against the official checksum
    bump($root, 'notes.txt', 'changed');                               // not code
    chmod($root . '/lib/perm.php', 0600);                              // permissions only
    unlink($root . '/lib/gone.php');                                   // removed, not sensitive
    bump($root, 'lib/fresh.php', '<?php // fresh', 1000);              // arrived inside the grace period
    putFile($root, 'wp-content/themes/t/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER'); // pattern hit
    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// v2\n"); // approved update
    bump($root, 'lib/a.php', '<?php // a');                            // unexplained change
    bump($root, 'lib/b.php', '<?php // b');
    $http = new FakeHttp();
    coreRoute($http, ['wp-includes/ok.php' => 'official']);
    $http->route('https://downloads.wordpress.org/plugin-checksums/foo/', 404, '{"error":"not found"}');
    $a = analyzerFor($c, new WpChecksum($http, $c, tmpdir()));
    $changes = array_values(diffByPath($c, $b));
    $r = $a->analyze($changes, $old, VersionTracker::read($c), false, time() + 600);

    $expected = [
        'wp-includes/ok.php' => 'accepted: official copy',
        'notes.txt' => 'accepted: not code',
        'lib/perm.php' => 'accepted: permissions only',
        'lib/gone.php' => 'accepted: removed',
        'lib/fresh.php' => 'held: judged next run',
        'wp-content/themes/t/evil.php' => 'reported',
        'wp-content/plugins/foo/foo.php' => 'accepted: approved update',
        'lib/a.php' => 'reported',
        'lib/b.php' => 'reported',
    ];
    $got = $r['outcomes'];
    ksort($expected);
    ksort($got);
    assertSame($expected, $got);
    $paths = array_map(function ($ch) { return $ch['path']; }, $changes);
    sort($paths);
    assertSame($paths, array_keys($got), 'one outcome per changed path');
    foreach ($got as $status) {
        assertTrue(in_array($status, Report::STATUSES, true), $status);
    }
    foreach ($r['findings'] as $f) {
        assertNotContains('more)', $f->message);
        assertNotContains('lib/a.php', $f->message);
    }
    $unexplained = array_values(array_filter($r['findings'], function ($f) { return $f->rule === 'unexplained-change'; }));
    assertSame('2 file(s) changed without a version change (each one is listed in the report)', $unexplained[0]->message);
});

t('Analyzer: an unverified update message points to the report instead of sampling files', function () {
    [$root, $c, $b] = wpFixture();
    $old = VersionTracker::read($c);
    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// v2\n");
    $r = runAnalysis($c, $b, null, $old);
    assertSame('Version 1.0 -> 1.1, but 1 changed file(s) could not be verified against an official source (each one is listed in the report)', $r['findings'][0]->message);
    assertSame(['wp-content/plugins/foo/foo.php' => 'reported'], $r['outcomes']);
});

/** Runs the Analyzer over the changes since $b with a scanner built from the given rule list. */
function analyzeWithRules(Config $c, string $b, array $patternRules, array $extra = [], array $old = [], int $now = 0): array
{
    $unresolved = $extra['unresolved'] ?? [];
    $a = new Analyzer(
        $c,
        new PatternScanner(Rules::fromArray(['patterns' => $patternRules]), 1048576),
        new LocationScanner($c),
        null,
        $extra['external'] ?? new ExternalScanner(null, null, null),
        $extra['dismissals'] ?? null,
        $unresolved
    );
    return $a->analyze(array_values(diffByPath($c, $b)), $old, VersionTracker::read($c), false, $now);
}

function heavyRule(): array
{
    return ['id' => 'heavy', 'severity' => 'critical', 'regex' => '/^(a+)+$/', 'description' => 'heavy rule'];
}

function markerRule(): array
{
    return ['id' => 'marker', 'severity' => 'critical', 'regex' => '/SENTINEL-TEST-MALWARE-MARKER/', 'description' => 'marker'];
}

/** Runs $fn with PCRE limits so low that heavyRule() fails to run, restoring them afterwards. */
function withBrokenRegex(callable $fn)
{
    $jit = ini_set('pcre.jit', '0');
    $limit = ini_set('pcre.backtrack_limit', '100');
    try {
        return $fn();
    } finally {
        ini_set('pcre.jit', (string)$jit);
        ini_set('pcre.backtrack_limit', (string)$limit);
    }
}

t('Analyzer outcome: a rule that failed to run alone is held for the next run; beside a real hit it is reported', function () {
    [$root, $c, $b] = wpFixture();
    putFile($root, 'lib/slow.php', str_repeat('a', 40) . '!');
    $r = withBrokenRegex(function () use ($c, $b) {
        return analyzeWithRules($c, $b, [heavyRule()]);
    });
    assertSame(['scan-error@lib/slow.php'], ruleList($r));
    assertSame(['lib/slow.php' => Report::STATUSES[6]], $r['outcomes']);
    assertSame([], $r['detected'], 'a check that failed is retried, not remembered');

    putFile($root, 'lib/slow.php', str_repeat('a', 40) . '! SENTINEL-TEST-MALWARE-MARKER');
    $r = withBrokenRegex(function () use ($c, $b) {
        return analyzeWithRules($c, $b, [heavyRule(), markerRule()]);
    });
    assertSame(['marker@lib/slow.php', 'scan-error@lib/slow.php'], ruleList($r));
    assertSame(['lib/slow.php' => Report::STATUSES[0]], $r['outcomes']);
});

t('Analyzer outcome: a rule that failed to run beside an unreviewed detection that was worse is reported', function () {
    [$root, $c, $b] = wpFixture();
    putFile($root, 'lib/slow.php', str_repeat('a', 40) . '!');
    $unresolved = ['lib/slow.php' => ['sha256' => str_repeat('0', 64), 'rules' => ['marker'], 'severity' => Finding::CRITICAL, 'first' => 1]];
    $r = withBrokenRegex(function () use ($c, $b, $unresolved) {
        return analyzeWithRules($c, $b, [heavyRule()], ['unresolved' => $unresolved]);
    });
    assertSame(['detection-unresolved@lib/slow.php', 'scan-error@lib/slow.php'], ruleList($r));
    assertSame(['lib/slow.php' => Report::STATUSES[0]], $r['outcomes']);
});

t('Analyzer outcome: an external scanner hit is reported, a clean file goes on to the update logic', function () {
    [$root, $c, $b] = wpFixture();
    $clam = fakeTool(tmpdir(), 'clamscan', 'rc=0
for f in "$@"; do
  case "$f" in -*) continue;; esac
  if grep -q EICAR "$f"; then echo "$f: Fake.Eicar FOUND"; rc=1; fi
done
exit $rc
');
    putFile($root, 'lib/bad.php', '<?php // EICAR');
    putFile($root, 'lib/fine.php', '<?php // fine');
    $r = analyzeWithRules($c, $b, [], ['external' => new ExternalScanner($clam, null, null)]);
    assertSame(['clamav:Fake.Eicar@lib/bad.php', 'unexplained-change@lib'], ruleList($r));
    assertSame(['lib/bad.php' => Report::STATUSES[0], 'lib/fine.php' => Report::STATUSES[0]], $r['outcomes']);
    assertSame(['lib/bad.php'], array_keys($r['detected']));
});

t('Analyzer outcome: a dismissed hit does not decide the status, the rest of the logic does', function () {
    [$root, $c, $b] = wpFixture([], ['update_grace_seconds' => 120]);
    $content = '<?php // SENTINEL-TEST-MALWARE-MARKER';
    $st = new Sentinel\State(tmpdir());
    $st->writeJson(Sentinel\Dismissals::FILE, ['dismissals' => [
        ['rule' => 'marker', 'path' => 'lib/seen.php', 'sha256' => hash('sha256', $content)],
        ['rule' => 'marker', 'path' => 'lib/new.php', 'sha256' => hash('sha256', $content)],
    ]]);
    $dismissals = new Sentinel\Dismissals($st);

    // Arrived just now: the dismissed hit leaves the file to the grace period.
    putFile($root, 'lib/seen.php', $content);
    $r = analyzeWithRules($c, $b, [markerRule()], ['dismissals' => $dismissals], [], time());
    assertSame([], ruleList($r));
    assertSame(['lib/seen.php' => Report::STATUSES[6]], $r['outcomes']);

    // Settled: it is an unexplained change like any other file nobody vouches for.
    $r = analyzeWithRules($c, $b, [markerRule()], ['dismissals' => $dismissals], [], time() + 600);
    assertSame(['unexplained-change@lib'], ruleList($r));
    assertSame(['lib/seen.php' => Report::STATUSES[0]], $r['outcomes']);
    assertContains('reviewed finding(s) not reported again', implode("\n", $r['info']));
});

t('Analyzer outcome: findings on symlinks, unreadable, world-writable and sensitive files and removals are reported', function () {
    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        skip('root can read everything');
    }
    [$root, $c, $b] = wpFixture(['wp-includes/a.php' => 'A', 'wp-content/plugins/foo/inc.php' => '<?php // inc']);
    symlink('/etc', $root . '/wp-content/etc-link');
    bump($root, 'wp-config.php', '<?php // edited');
    chmod($root . '/wp-content/plugins/foo/foo.php', 0666);
    putFile($root, 'lib/locked.php', '<?php');
    chmod($root . '/lib/locked.php', 0000);
    $http = new FakeHttp();
    coreRoute($http, ['wp-includes/a.php' => 'A']);
    unlink($root . '/wp-includes/a.php'); // core file removed
    try {
        $r = runAnalysis($c, $b, analyzerFor($c, new WpChecksum($http, $c, tmpdir())), VersionTracker::read($c));
    } finally {
        chmod($root . '/lib/locked.php', 0644);
    }
    $expected = [
        'lib/locked.php' => 'unreadable',
        'wp-config.php' => 'sensitive-file-changed',
        'wp-content/etc-link' => 'symlink',
        'wp-content/plugins/foo/foo.php' => 'world-writable',
        'wp-includes/a.php' => 'core-file-removed',
    ];
    $got = [];
    foreach ($r['findings'] as $f) {
        $got[$f->path] = $f->rule;
    }
    ksort($got);
    assertSame($expected, $got);
    $want = array_fill_keys(array_keys($expected), Report::STATUSES[0]);
    $outcomes = $r['outcomes'];
    ksort($outcomes);
    assertSame($want, $outcomes);

    // A sensitive file removed.
    [$root, $c, $b] = wpFixture();
    unlink($root . '/wp-config.php');
    $r = runAnalysis($c, $b, null, VersionTracker::read($c));
    assertSame(['sensitive-file-removed@wp-config.php'], ruleList($r));
    assertSame(['wp-config.php' => Report::STATUSES[0]], $r['outcomes']);
});

t('Analyzer outcome: with auto-accept, a version bump in a plugin with an unreviewed detection is reported, not approved', function () {
    [$root, $c, $b] = wpFixture([], ['auto_accept_unverified_updates' => true]);
    $old = VersionTracker::read($c);
    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// v2\n");
    $unresolved = ['wp-content/plugins/foo/other.php' => ['sha256' => str_repeat('0', 64), 'rules' => ['marker'], 'severity' => Finding::CRITICAL, 'first' => 1]];
    $r = analyzeWithRules($c, $b, [], ['unresolved' => $unresolved], $old);
    assertSame(['unverified-update@wp-content/plugins/foo'], ruleList($r));
    assertSame(['wp-content/plugins/foo/foo.php' => Report::STATUSES[0]], $r['outcomes']);
});
