<?php
declare(strict_types=1);

use Sentinel\Finding;
use Sentinel\Report;

function reportMeta(array $patch = []): array
{
    return array_merge([
        'site' => 'Example Shop', 'root' => '/home/acct/public_html', 'ts' => gmmktime(14, 30, 0, 10, 21, 2026),
        'version' => '1.2.3', 'mode' => 'incremental', 'complete' => true,
    ], $patch);
}

function reportRec(int $size = 100, int $mtime = 1792000000, string $hash = '', int $mode = 0100644): array
{
    return ['path' => '', 'size' => $size, 'mtime' => $mtime, 'ctime' => $mtime, 'mode' => $mode, 'hash' => $hash];
}

function reportChange(string $type, string $path, ?array $old, ?array $new, array $flags = []): array
{
    return array_merge(['type' => $type, 'path' => $path, 'old' => $old, 'new' => $new, 'stealth' => false, 'content_same' => false, 'unreadable' => false], $flags);
}

function reportText(array $meta, array $findings, array $due, array $changes, array $outcomes = [], array $notes = []): string
{
    $file = Report::write(tmpdir() . '/reports', $meta, $findings, $due, $changes, $outcomes, $notes);
    return (string)file_get_contents($file);
}

t('Report lists every finding and every changed file, grouped, with nothing truncated', function () {
    $changes = [];
    for ($i = 1; $i <= 30; $i++) {
        $p = sprintf('wp-content/themes/shopfront/inc/part-%02d.php', $i);
        $changes[] = reportChange('modified', $p, reportRec(10, 1), reportRec(20, 2, str_repeat('a', 64)));
    }
    $changes[] = reportChange('new', 'wp-content/uploads/2026/shell.php', null, reportRec(5, 3, str_repeat('b', 64)));
    $hit = new Finding(Finding::CRITICAL, 'wp-content/uploads/2026/shell.php', 'php-in-uploads', 'PHP file in uploads', str_repeat('b', 64));
    $old = new Finding(Finding::WARNING, 'wp-content/themes/shopfront/inc/part-01.php', 'unexplained-change', 'Changed without an update');
    $text = reportText(reportMeta(), [$old, $hit], [$hit->key()], $changes);
    for ($i = 1; $i <= 30; $i++) {
        assertContains(sprintf('wp-content/themes/shopfront/inc/part-%02d.php', $i), $text);
    }
    assertContains('php-in-uploads: PHP file in uploads', $text);
    assertContains('unexplained-change: Changed without an update', $text);
    assertContains('[id ' . $hit->id() . ']', $text, 'a dismissable finding shows its id');
    assertContains('sha256 ' . str_repeat('b', 64), $text);
    assertNotContains('[id ' . $old->id() . ']', $text, 'a change cannot be dismissed');
    assertContains('in this email', $text);
    assertContains('reported earlier', $text);
    assertContains("wp-content/themes/shopfront (30)\n", $text, 'heading from Analyzer::groupOf');
    assertContains("wp-content (1)\n", $text);
    assertNotContains('more)', $text);
    assertTrue(strpos($text, 'CRITICAL (1)') < strpos($text, 'WARNING (1)'), 'worst first');
});

t("Report shows each file's change type, size, time, code-file SHA-256 and status", function () {
    $h = str_repeat('c', 64);
    $changes = [
        reportChange('new', 'a/new.php', null, reportRec(111, 1792000000, $h)),
        reportChange('modified', 'a/mod.php', reportRec(1, 1, 'x'), reportRec(222, 1792000000, $h)),
        reportChange('removed', 'a/gone.php', reportRec(333, 1792000000, $h), null),
        reportChange('modified', 'a/perm.php', reportRec(444, 1792000000, $h, 0100644), reportRec(444, 1792000100, $h, 0100666), ['content_same' => true]),
        reportChange('new', 'a/pic.jpg', null, reportRec(555, 1792000000)),
        reportChange('new', 'a/flagged.php', null, reportRec(666, 1792000000, $h)),
    ];
    $f = new Finding(Finding::WARNING, 'a/flagged.php', 'unexpected-file', 'Not part of the package', $h);
    $outcomes = [
        'a/new.php' => 'accepted: official copy', 'a/mod.php' => 'held: judged next run',
        'a/gone.php' => 'accepted: removed', 'a/perm.php' => 'accepted: permissions only',
    ];
    $text = reportText(reportMeta(), [$f], [], $changes, $outcomes);
    $lines = [];
    foreach (explode("\n", $text) as $l) {
        if (preg_match('# (a/\S+)$#', $l, $m)) {
            $lines[$m[1]] = $l;
        }
    }
    assertContains('new | 111 B | ' . gmdate('Y-m-d H:i', 1792000000) . ' | sha256 ' . $h . ' [accepted: official copy]', $lines['a/new.php']);
    assertContains('modified | 222 B', $lines['a/mod.php']);
    assertContains('[held: judged next run]', $lines['a/mod.php']);
    assertContains('removed | 333 B', $lines['a/gone.php']);
    assertContains('[accepted: removed]', $lines['a/gone.php']);
    assertContains('permissions only | 444 B', $lines['a/perm.php']);
    assertContains('[accepted: permissions only]', $lines['a/perm.php']);
    assertContains('sha256 -', $lines['a/pic.jpg']);
    assertContains('[reported]', $lines['a/pic.jpg'], 'no outcome and no finding: never claimed as accepted');
    assertContains('[reported]', $lines['a/flagged.php'], 'no outcome but a finding');
    assertSame(true, in_array('reported', Report::STATUSES, true) && in_array('held: judged next run', Report::STATUSES, true));
});

t('Report file names are safe for any site name', function () {
    $ts = gmmktime(14, 30, 0, 10, 21, 2026);
    assertSame('sentinel-report-my-shop-20261021-1430.txt', Report::fileName('My Shop', $ts));
    assertSame('sentinel-report-caf-bar-20261021-1430.txt', Report::fileName('Café / Bar', $ts));
    assertSame('sentinel-report-site-20261021-1430.txt', Report::fileName('***', $ts));
    assertSame('sentinel-report-' . str_repeat('a', 40) . '-20261021-1430.txt', Report::fileName(str_repeat('a', 60), $ts));
    assertSame('sentinel-report-' . str_repeat('a', 39) . '-20261021-1430.txt', Report::fileName(str_repeat('a', 39) . ' b', $ts), 'no dash left dangling at the cut');
});

t('Report labels a partial scan and its scope', function () {
    $part = 'part of a scan: changes found in this part only; the scan resumes on the next run';
    $text = reportText(reportMeta(['complete' => false]), [], [], [reportChange('new', 'x/a.php', null, reportRec())]);
    assertSame(2, substr_count($text, $part), 'header and changed-files heading');
    assertNotContains('complete scan', $text);
    $text = reportText(reportMeta(['complete' => true]), [], [], [reportChange('new', 'x/a.php', null, reportRec())]);
    assertContains('Coverage: complete scan', $text);
    assertNotContains('part of a scan', $text);
    assertContains('Site Sentinel report: Example Shop', $text);
    assertContains('Time: 2026-10-21 14:30:00 UTC', $text);
    assertContains('Sentinel version: 1.2.3', $text);
    assertContains('Scan mode: incremental', $text);
});

t('Report holds no absolute paths or contents', function () {
    $root = tmpdir();
    putFile($root, 'wp-config.php', "<?php define('DB_PASSWORD', 'hunter2-secret');");
    $note = "Checksums for WordPress 6.5 could not be downloaded ($root/wp-includes) and $root";
    $text = reportText(reportMeta(['root' => $root]), [], [], [reportChange('modified', 'wp-config.php', reportRec(1, 1, 'x'), reportRec(2, 2, 'y'))], [], [$note]);
    assertNotContains($root, $text);
    assertNotContains('/home/', $text);
    assertNotContains('hunter2-secret', $text);
    assertContains('(wp-includes)', $text, 'the note shows the path relative to the website folder');

    // Findings carry absolute paths too: the account's home (the folder holding the sentinel
    // folder) and the website folder, also reached through a link, are scrubbed from every line.
    $base = tmpdir();
    $home = $base . '/home/acct';
    $real = $base . '/www/users/acct';
    mkdir($home . '/sentinel/state', 0700, true);
    mkdir($real, 0755, true);
    symlink($real, $home . '/public_html');
    $site = $home . '/public_html';
    $findings = [
        new Finding(Finding::CRITICAL, "sentinel.php ($home/sentinel/sentinel.php)", 'self-tamper', 'Sentinel file changed since it was last accepted', 'h1'),
        new Finding(Finding::CRITICAL, 'sentinel', 'state-write-failed', "Scan state could not be saved (cannot write $home/sentinel/state/baseline.txt.tmp (disk full or over quota?)). The previous baseline was kept", 'h2'),
        new Finding(Finding::WARNING, 'wp-content/x.php', 'unexpected-file', "Seen at $real/wp-content/x.php and $site/wp-content/x.php", 'h3'),
    ];
    $notes = ["'old' is a symlink to a directory ($home/public_html_old) and is not monitored.", "Checksums missing for $site"];
    $text = reportText(reportMeta(['root' => $site, 'home' => $home]), $findings, [], [], [], $notes);
    foreach ([$base, $home, $site, $real, '/home/acct', '/www/users'] as $abs) {
        assertNotContains($abs, $text, 'no absolute path remains');
    }
    assertContains('sentinel.php (sentinel/sentinel.php)', $text, 'self-tamper path relative to the home folder');
    assertContains('cannot write sentinel/state/baseline.txt.tmp (disk full', $text, 'state path relative to the home folder');
    assertContains('Seen at wp-content/x.php and wp-content/x.php', $text, 'the website folder, real or linked, relative to itself');
    assertContains('(public_html_old)', $text, 'a sibling folder is not taken for the website folder');
    assertContains('Checksums missing for .', $text);

    // A home that is the file system root (a state folder right under /) is never scrubbed as a prefix.
    $text = reportText(reportMeta(['root' => '', 'home' => '/']), [new Finding(Finding::WARNING, 'a.php', 'unexpected-file', 'see /etc/passwd')], [], []);
    assertContains('see /etc/passwd', $text);
});

t('Report keeps the newest 30 and cuts the attachment at the cap', function () {
    $dir = tmpdir() . '/reports';
    $first = gmmktime(10, 0, 0, 10, 21, 2026);
    $written = [];
    for ($i = 0; $i < 32; $i++) {
        $ts = $first + $i * 60;
        $written[] = Report::write($dir, reportMeta(['ts' => $ts]), [], [], [], [], []);
        touch(end($written), $ts); // as if each was written at its own time
    }
    assertSame(30, count(glob($dir . '/sentinel-report-*.txt')));
    assertTrue(!is_file($written[0]) && !is_file($written[1]), 'the two oldest are gone');
    assertTrue(is_file($written[2]) && is_file($written[31]));

    // Over 50 MB in total: the oldest go first, never the newest.
    $dir2 = tmpdir() . '/reports';
    mkdir($dir2);
    $big = [];
    for ($i = 0; $i < 4; $i++) {
        $big[$i] = $dir2 . '/' . Report::fileName('big', $first + $i * 60);
        $fh = fopen($big[$i], 'wb');
        ftruncate($fh, 20 * 1048576); // sparse
        fclose($fh);
        touch($big[$i], $first + $i * 60);
    }
    $new = Report::write($dir2, reportMeta(['site' => 'big', 'ts' => $first + 10 * 60]), [], [], [], [], []);
    assertTrue(is_file($new), 'the newest is kept');
    assertTrue(is_file($big[3]) && is_file($big[2]), 'the next newest fit under 50 MB');
    assertTrue(!is_file($big[1]) && !is_file($big[0]), 'older ones are pruned until under the limit');

    // Even a single report over the limit is not deleted.
    $dir3 = tmpdir() . '/reports';
    mkdir($dir3);
    $only = $dir3 . '/' . Report::fileName('big', $first);
    $fh = fopen($only, 'wb');
    ftruncate($fh, 60 * 1048576);
    fclose($fh);
    Report::prune($dir3, $only);
    assertTrue(is_file($only));

    // Attachment: under the cap it is the file, over it is cut at a line end plus a line naming the saved copy.
    $file = tmpdir() . '/r.txt';
    file_put_contents($file, str_repeat("0123456789\n", 50));
    $shown = 'sentinel/state/reports/r.txt';
    $a = Report::attachment($file, $shown);
    assertSame((string)file_get_contents($file), $a['content']);
    assertSame('r.txt', $a['name']);
    assertSame($shown, $a['path']);
    $a = Report::attachment($file, $shown, 100);
    $cut = "[report cut at 100 bytes; the full report is on the server: $shown]";
    assertContains($cut, $a['content']);
    assertTrue(strlen($a['content']) <= 100 + strlen($cut) + 2);
    assertSame($cut . "\n", substr($a['content'], -strlen($cut) - 1));
    assertNotContains($file, $a['content'], 'only the display path is named');
    $large = tmpdir() . '/large.txt';
    file_put_contents($large, str_repeat(str_repeat('x', 99) . "\n", 21000));
    $a = Report::attachment($large, $shown);
    assertContains("[report cut at 2 MB; the full report is on the server: $shown]", $a['content'], 'default cap is 2 MB');
    assertTrue(strlen($a['content']) < Report::CAP + 200);
    assertSame('sentinel/state/reports/n.txt', Report::displayPath('/home/acct/sentinel/state/', 'n.txt'));
    assertThrows(RuntimeException::class, function () {
        Report::write('/proc/nonexistent/reports', reportMeta(), [], [], [], [], []);
    });
});

t('Report: two reports in the same minute are both kept, never one written over the other or through a link', function () {
    $dir = tmpdir() . '/reports';
    $ts = gmmktime(14, 30, 0, 10, 21, 2026);
    $first = Report::write($dir, reportMeta(['ts' => $ts, 'mode' => 'check']), [], [], [], [], []);
    $second = Report::write($dir, reportMeta(['ts' => $ts, 'mode' => 'full']), [], [], [], [], []);
    $third = Report::write($dir, reportMeta(['ts' => $ts, 'mode' => 'full']), [], [], [], [], []);
    assertSame($dir . '/sentinel-report-example-shop-20261021-1430.txt', $first);
    assertSame($dir . '/sentinel-report-example-shop-20261021-1430-2.txt', $second);
    assertSame($dir . '/sentinel-report-example-shop-20261021-1430-3.txt', $third);
    assertContains('Scan mode: check', (string)file_get_contents($first), 'the first is not overwritten');
    assertContains('Scan mode: full', (string)file_get_contents($second));
    assertSame(3, count(glob($dir . '/sentinel-report-*.txt')), 'pruning counts the numbered names');

    // A link planted where the next report would go is not written through.
    $dir2 = tmpdir() . '/reports';
    mkdir($dir2);
    $target = tmpdir() . '/target.txt';
    file_put_contents($target, 'keep me');
    symlink($target, $dir2 . '/' . Report::fileName('Example Shop', $ts));
    $file = Report::write($dir2, reportMeta(['ts' => $ts]), [], [], [], [], []);
    assertSame('keep me', (string)file_get_contents($target));
    assertSame($dir2 . '/sentinel-report-example-shop-20261021-1430-2.txt', $file);
});
