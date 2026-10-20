<?php
declare(strict_types=1);

use Sentinel\Cli;
use Sentinel\Dismissals;
use Sentinel\Finding;

/** CLI site with no update grace period and its config re-trusted; returns [script, config, alerts, siteRoot, stateDir]. */
function dismissSite(array $patch = []): array
{
    [$script, $config, $alerts] = cliSite(array_merge(['update_grace_seconds' => 0], $patch));
    $cfg = json_decode((string)file_get_contents($config), true);
    assertSame(0, Cli::execute(['accept', '--self', '--config=' . $config], $script, new FakeHttp())['exit']);
    return [$script, $config, $alerts, (string)$cfg['site_root'], (string)$cfg['state_dir']];
}

function sentinelCli(string $script, string $config, array $args): array
{
    $r = Cli::execute(array_merge($args, ['--config=' . $config]), $script, new FakeHttp());
    $r['text'] = implode("\n", array_merge($r['out'], $r['err']));
    return $r;
}

/** The dismissal id printed next to $rule on $path in check output. */
function shownId(array $r, string $path, string $rule): string
{
    if (!preg_match('#' . preg_quote($path . ' ' . $rule, '#') . ' \[id ([0-9a-f]{12})\]#', $r['text'], $m)) {
        throw new RuntimeException("no id shown for $rule on $path in:\n" . $r['text']);
    }
    return $m[1];
}

t('dismiss: a reviewed false positive stops alerting while the file is unchanged; the change itself still needs accept', function () {
    [$script, $config, $alerts, $root] = dismissSite();
    putFile($root, 'lib/licence.php', '<?php eval(base64_decode("ZWNobyAnb2snOw=="));');
    $r = sentinelCli($script, $config, ['check']);
    assertSame(1, $r['exit']);
    $id = shownId($r, 'lib/licence.php', 'eval-decoder');
    assertContains('dismiss ' . $id . ' --reason=', (string)file_get_contents($alerts), 'the alert says how to dismiss it');

    assertContains('a --reason is required', sentinelCli($script, $config, ['dismiss', $id])['text']);
    $d = sentinelCli($script, $config, ['dismiss', $id, '--reason=Vendor licence check, reviewed']);
    assertSame(0, $d['exit'], $d['text']);

    $r2 = sentinelCli($script, $config, ['check']);
    assertNotContains('eval-decoder', $r2['text']);
    assertNotContains('self-tamper', $r2['text'], 'a dismissal made with the command is trusted');
    assertContains('unexplained-change', $r2['text'], 'the new file is still an unaccepted change');
    assertSame(0, sentinelCli($script, $config, ['accept', '--path=lib/licence.php'])['exit']);
    assertSame(0, sentinelCli($script, $config, ['check'])['exit']);

    $list = sentinelCli($script, $config, ['dismiss', '--list'])['text'];
    assertContains($id, $list);
    assertContains('Vendor licence check, reviewed', $list);
    assertNotContains('no longer applies', $list);

    // Changed content is a different finding: alerted again, with a new id.
    putFile($root, 'lib/licence.php', '<?php eval(base64_decode("ZWNobyAnbGljZW5jZSB2Mic7"));'); // different size: check is stat-based
    $r3 = sentinelCli($script, $config, ['check']);
    assertSame(1, $r3['exit']);
    assertTrue(shownId($r3, 'lib/licence.php', 'eval-decoder') !== $id);
    assertContains('no longer applies', sentinelCli($script, $config, ['dismiss', '--list'])['text']);
});

t('dismiss refuses unknown ids, change findings, and files that changed after they were reported', function () {
    [$script, $config, , $root] = dismissSite();
    assertContains('no reported finding has id', sentinelCli($script, $config, ['dismiss', 'abcdef123456', '--reason=x'])['text']);

    putFile($root, 'new.php', '<?php // plain new code');
    $r = sentinelCli($script, $config, ['check']);
    assertContains('unexplained-change', $r['text']);
    assertNotContains('[id ', $r['text'], 'change findings get no dismissal id');

    putFile($root, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $id = shownId(sentinelCli($script, $config, ['check']), 'evil.php', 'test-marker');
    putFile($root, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER and more');
    $d = sentinelCli($script, $config, ['dismiss', $id, '--reason=looked at it']);
    assertSame(2, $d['exit']);
    assertContains('has changed', $d['text'], 'only the content that was reviewed can be dismissed');
});

t('dismiss: findings on non-code files are pinned to their content, so a changed image alerts again', function () {
    [$script, $config, , $root] = dismissSite(['uploads_dir' => 'uploads']);
    putFile($root, 'uploads/pic.jpg', 'GIF89a <?php echo 1; ?>');
    $id = shownId(sentinelCli($script, $config, ['check']), 'uploads/pic.jpg', 'php-in-media');
    assertSame(0, sentinelCli($script, $config, ['dismiss', $id, '--reason=test fixture image'])['exit']);
    assertNotContains('php-in-media', sentinelCli($script, $config, ['check'])['text']);
    putFile($root, 'uploads/pic.jpg', 'GIF89a <?php system($_GET["c"]); ?>');
    assertContains('php-in-media', sentinelCli($script, $config, ['check'])['text']);
});

t('dismiss --remove brings the finding back at the next scan', function () {
    [$script, $config, $alerts, $root] = dismissSite();
    putFile($root, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $id = shownId(sentinelCli($script, $config, ['check']), 'evil.php', 'test-marker');
    sentinelCli($script, $config, ['dismiss', $id, '--reason=fixture']);
    assertNotContains('test-marker', sentinelCli($script, $config, ['check'])['text']);
    $before = substr_count((string)file_get_contents($alerts), 'test-marker');
    assertContains('analysed again from the next scan', sentinelCli($script, $config, ['dismiss', '--remove=' . $id])['text']);
    assertContains('test-marker', sentinelCli($script, $config, ['check'])['text']);
    assertSame($before + 1, substr_count((string)file_get_contents($alerts), 'test-marker'), 'and it is alerted again');
    assertContains('no dismissal has id', sentinelCli($script, $config, ['dismiss', '--remove=' . $id])['text']);
});

t('A dismissals file edited by hand is flagged and ignored, so it cannot whitelist a webshell', function () {
    [$script, $config, , $root, $stateDir] = dismissSite();
    putFile($root, 'shell.php', '<?php eval($_POST["x"]);');
    file_put_contents($stateDir . '/' . Dismissals::FILE, json_encode(['dismissals' => [
        ['rule' => 'eval-request', 'path' => 'shell.php', 'sha256' => hash_file('sha256', $root . '/shell.php'), 'reason' => 'x'],
    ]]));
    $r = sentinelCli($script, $config, ['check']);
    assertContains('eval-request', $r['text'], 'the forged dismissal is not applied');
    assertContains('self-tamper', $r['text']);
    assertContains('dismissals (', $r['text']);
});

t('A rules file placed by hand is flagged and the built-in rules are used instead', function () {
    [$script, $config, $alerts, $root, $stateDir] = dismissSite();
    file_put_contents($stateDir . '/rules.json', json_encode(['version' => 999, 'patterns' => [], 'hashes' => []]));
    putFile($root, 'shell.php', '<?php eval(base64_decode($_POST["x"]));');
    $r = sentinelCli($script, $config, ['check']);
    assertContains('eval-decoder', $r['text'], 'detection still works');
    assertContains('self-tamper', $r['text']);
    assertContains('built-in rules were used', (string)file_get_contents($alerts));
});

t('Dismissals cover only the same rule, path and content, and never change findings', function () {
    $st = new Sentinel\State(tmpdir());
    $st->writeJson(Dismissals::FILE, ['dismissals' => [['rule' => 'eval-decoder', 'path' => 'a.php', 'sha256' => str_repeat('a', 64)]]]);
    $d = new Dismissals($st);
    assertTrue($d->covers(new Finding(Finding::CRITICAL, 'a.php', 'eval-decoder', '', str_repeat('a', 64))));
    assertTrue(!$d->covers(new Finding(Finding::CRITICAL, 'a.php', 'eval-decoder', '', str_repeat('b', 64))));
    assertTrue(!$d->covers(new Finding(Finding::CRITICAL, 'a.php', 'eval-request', '', str_repeat('a', 64))));
    assertTrue(!$d->covers(new Finding(Finding::CRITICAL, 'b.php', 'eval-decoder', '', str_repeat('a', 64))));
    assertTrue(!Dismissals::dismissable(new Finding(Finding::WARNING, 'x', 'unexplained-change', '', str_repeat('a', 64))));
    assertTrue(!Dismissals::dismissable(new Finding(Finding::CRITICAL, 'x', 'stealth-modification', '', str_repeat('a', 64))));
    assertTrue(!Dismissals::dismissable(new Finding(Finding::CRITICAL, 'x', 'eval-decoder', '', '')), 'unpinned findings cannot be dismissed');
});

t('dismiss: external scanner (ClamAV) findings are pinned to content and can be dismissed', function () {
    if (!Sentinel\Proc::available()) {
        skip('needs proc_open');
    }
    $clam = fakeTool(tmpdir(), 'clamscan', 'st=0; for f in "$@"; do case "$f" in *flagged*) echo "$f: Php.Heur.Test FOUND"; st=1;; esac; done; exit $st' . "\n");
    [$script, $config, , $root] = dismissSite(['clamscan_path' => $clam]);
    putFile($root, 'lib/flagged.php', '<?php // a vendor file ClamAV dislikes');
    $id = shownId(sentinelCli($script, $config, ['check']), 'lib/flagged.php', 'clamav:Php.Heur.Test');
    assertSame(0, sentinelCli($script, $config, ['dismiss', $id, '--reason=heuristic false positive, vendor file'])['exit']);
    assertNotContains('clamav:', sentinelCli($script, $config, ['check'])['text']);
    putFile($root, 'lib/flagged.php', '<?php // a vendor file ClamAV dislikes, now edited');
    assertContains('clamav:Php.Heur.Test', sentinelCli($script, $config, ['check'])['text']);
});

t('An honest dismiss refuses to save over a dismissals file changed by hand (it would trust the forged entry)', function () {
    [$script, $config, , $root, $stateDir] = dismissSite();
    putFile($root, 'lib/licence.php', '<?php eval(base64_decode("ZWNobyAnb2snOw=="));');
    $id = shownId(sentinelCli($script, $config, ['check']), 'lib/licence.php', 'eval-decoder');
    putFile($root, 'shell.php', '<?php eval($_POST["x"]);');
    $forged = json_encode(['dismissals' => [
        ['rule' => 'eval-request', 'path' => 'shell.php', 'sha256' => hash_file('sha256', $root . '/shell.php'), 'reason' => 'forged'],
    ]]);
    file_put_contents($stateDir . '/' . Dismissals::FILE, $forged);

    $d = sentinelCli($script, $config, ['dismiss', $id, '--reason=honest review']);
    assertSame(2, $d['exit']);
    assertContains('changed outside the dismiss command', $d['text']);
    assertSame($forged, (string)file_get_contents($stateDir . '/' . Dismissals::FILE), 'nothing was saved');
    $r = sentinelCli($script, $config, ['check']);
    assertContains('eval-request', $r['text'], 'the webshell is still reported');
    assertContains('self-tamper', $r['text'], 'and so is the forged file');
    assertSame(2, sentinelCli($script, $config, ['dismiss', '--remove=' . $id])['exit'], 'removal is refused too');
    $list = sentinelCli($script, $config, ['dismiss', '--list']);
    assertSame(1, $list['exit']);
    assertContains('not being applied', $list['text']);
});

t('Removing a dismissal brings the finding back even after the file was accepted, until it is dismissed again', function () {
    [$script, $config, $alerts, $root, $stateDir] = dismissSite();
    putFile($root, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $id = shownId(sentinelCli($script, $config, ['check']), 'evil.php', 'test-marker');
    assertSame(0, sentinelCli($script, $config, ['dismiss', $id, '--reason=fixture'])['exit']);
    assertSame(0, sentinelCli($script, $config, ['accept', '--path=evil.php'])['exit']);
    assertSame(0, sentinelCli($script, $config, ['check'])['exit'], 'dismissed and accepted: quiet');
    $before = substr_count((string)file_get_contents($alerts), 'test-marker');

    $baseline = (string)file_get_contents($stateDir . '/baseline.txt');
    assertSame(0, sentinelCli($script, $config, ['dismiss', '--remove=' . $id])['exit']);
    $r = sentinelCli($script, $config, ['check']);
    assertSame(1, $r['exit']);
    assertSame($baseline, (string)file_get_contents($stateDir . '/baseline.txt'), 're-analysis never writes the baseline');
    assertContains('test-marker', $r['text']);
    assertSame($before + 1, substr_count((string)file_get_contents($alerts), 'test-marker'), 'alerted again');
    assertContains('test-marker', sentinelCli($script, $config, ['check'])['text'], 'and it keeps being reported');
    assertContains('test-marker', sentinelCli($script, $config, ['full'])['text']);
    assertSame(0, sentinelCli($script, $config, ['dismiss', $id, '--reason=reviewed again'])['exit']);
    assertSame(0, sentinelCli($script, $config, ['check'])['exit']);
    assertSame([], json_decode((string)file_get_contents($stateDir . '/' . Dismissals::RECHECK_FILE), true), 'queue cleared');
});

t('dismiss waits for a running scan instead of racing it', function () {
    [$script, $config, , $root, $stateDir] = dismissSite();
    putFile($root, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $id = shownId(sentinelCli($script, $config, ['check']), 'evil.php', 'test-marker');
    $lock = Sentinel\Lock::acquire($stateDir . '/lock');
    try {
        $d = sentinelCli($script, $config, ['dismiss', $id, '--reason=fixture']);
        assertSame(2, $d['exit']);
        assertContains('a scan is running', $d['text']);
    } finally {
        $lock->release();
    }
    assertSame(0, sentinelCli($script, $config, ['dismiss', $id, '--reason=fixture'])['exit']);
});

t('A removed dismissal of a new-file-only detection (config in uploads) is detected again after accept', function () {
    [$script, $config, , $root] = dismissSite(['uploads_dir' => 'uploads']);
    putFile($root, 'uploads/.htaccess', "Options +ExecCGI\n");
    $id = shownId(sentinelCli($script, $config, ['check']), 'uploads/.htaccess', 'config-in-uploads');
    assertSame(0, sentinelCli($script, $config, ['dismiss', $id, '--reason=fixture'])['exit']);
    assertSame(0, sentinelCli($script, $config, ['accept', '--path=uploads/.htaccess'])['exit']);
    assertSame(0, sentinelCli($script, $config, ['dismiss', '--remove=' . $id])['exit']);
    assertContains('config-in-uploads', sentinelCli($script, $config, ['check'])['text']);
    assertContains('config-in-uploads', sentinelCli($script, $config, ['full'])['text'], 'and it stays reported');
});

t('A recheck that could not run (scanner failure) stays pending and reports once the scanner works', function () {
    if (!Sentinel\Proc::available()) {
        skip('needs proc_open');
    }
    $flag = tmpdir() . '/clam-broken';
    $clam = fakeTool(tmpdir(), 'clamscan', 'if [ -f ' . escapeshellarg($flag) . ' ]; then echo "database error" >&2; exit 2; fi; st=0; for f in "$@"; do case "$f" in *flagged*) echo "$f: Php.Heur.Test FOUND"; st=1;; esac; done; exit $st' . "\n");
    [$script, $config, , $root, $stateDir] = dismissSite(['clamscan_path' => $clam]);
    putFile($root, 'lib/flagged.php', '<?php // vendor file');
    $id = shownId(sentinelCli($script, $config, ['check']), 'lib/flagged.php', 'clamav:Php.Heur.Test');
    sentinelCli($script, $config, ['dismiss', $id, '--reason=fixture']);
    sentinelCli($script, $config, ['accept', '--path=lib/flagged.php']);
    sentinelCli($script, $config, ['dismiss', '--remove=' . $id]);

    touch($flag);
    $broken = sentinelCli($script, $config, ['check']);
    assertNotContains('clamav:Php', $broken['text']);
    assertSame(1, count(Dismissals::recheckQueue(new Sentinel\State($stateDir))), 'a failed check is not a clean check');
    unlink($flag);
    assertContains('clamav:Php.Heur.Test', sentinelCli($script, $config, ['check'])['text']);
});

t('dismiss --remove keeps the dismissal when queueing the recheck fails, so it can be retried', function () {
    [$script, $config, , $root, $stateDir] = dismissSite();
    putFile($root, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $id = shownId(sentinelCli($script, $config, ['check']), 'evil.php', 'test-marker');
    sentinelCli($script, $config, ['dismiss', $id, '--reason=fixture']);
    sentinelCli($script, $config, ['accept', '--path=evil.php']);
    mkdir($stateDir . '/' . Dismissals::RECHECK_FILE); // the queue cannot be written
    set_error_handler(function () { return true; });
    try {
        $rm = sentinelCli($script, $config, ['dismiss', '--remove=' . $id]);
    } finally {
        restore_error_handler();
    }
    rmdir($stateDir . '/' . Dismissals::RECHECK_FILE);
    assertSame(2, $rm['exit']);
    assertContains($id, sentinelCli($script, $config, ['dismiss', '--list'])['text'], 'nothing was removed');
    assertSame(0, sentinelCli($script, $config, ['check'])['exit'], 'still dismissed meanwhile');
    assertSame(0, sentinelCli($script, $config, ['dismiss', '--remove=' . $id])['exit'], 'a retry works');
    assertContains('test-marker', sentinelCli($script, $config, ['check'])['text']);
});

t('A queued recheck whose file could not be fully scanned this run stays pending', function () {
    [$script, $config, , $root, $stateDir] = dismissSite();
    // A trusted rules bundle with a rule that backtracks, so it can be made to fail on demand.
    file_put_contents($stateDir . '/rules.json', json_encode(['version' => 1, 'patterns' => [
        ['id' => 'slow-rule', 'severity' => 'critical', 'regex' => '/(x+x+)+y/'],
    ]]));
    assertSame(0, sentinelCli($script, $config, ['accept', '--self'])['exit']);
    putFile($root, 'evil.php', '<?php // xxxxxxxxxxxxxxxxy');
    $id = shownId(sentinelCli($script, $config, ['check']), 'evil.php', 'slow-rule');
    sentinelCli($script, $config, ['dismiss', $id, '--reason=fixture']);
    sentinelCli($script, $config, ['accept', '--path=evil.php']);
    sentinelCli($script, $config, ['dismiss', '--remove=' . $id]);

    $oldJit = ini_set('pcre.jit', '0');
    $old = ini_set('pcre.backtrack_limit', '1');
    try {
        $r = sentinelCli($script, $config, ['check']);
    } finally {
        ini_set('pcre.backtrack_limit', (string)$old);
        ini_set('pcre.jit', (string)$oldJit);
    }
    assertContains('scan-error', $r['text'], 'the rule could not be evaluated this run');
    assertNotContains('slow-rule [id', $r['text']);
    assertSame(1, count(Dismissals::recheckQueue(new Sentinel\State($stateDir))), 'an incomplete scan is not a clean one');
    assertContains('slow-rule', sentinelCli($script, $config, ['check'])['text']);
});
