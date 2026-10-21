<?php
declare(strict_types=1);

use Sentinel\ExternalScanner;
use Sentinel\Finding;
use Sentinel\Proc;

t('Proc::run captures output, exit code and stderr', function () {
    $r = Proc::run(['/bin/sh', '-c', 'echo out; echo err >&2; exit 3'], 5);
    assertSame(3, $r['exit']);
    assertSame("out\n", $r['out']);
    assertSame("err\n", $r['err']);
    assertSame(false, $r['timed_out']);
    // PHP 7.4 can start a child that exits 127; newer PHP may fail proc_open itself.
    $missing = Proc::run(['/nonexistent/binary'], 5);
    assertTrue(in_array($missing['exit'], [-1, 127], true));
    assertSame(false, $missing['timed_out']);
});

t('Proc::run starts commands under an open_basedir that leaves out /dev (xneelo php-wrapper)', function () {
    $dir = tmpdir();
    $script = $dir . '/child.php';
    file_put_contents($script, '<?php
require ' . var_export(__DIR__ . '/bootstrap.php', true) . ';
$r = Sentinel\\Proc::run([PHP_BINARY, "-r", "echo 42;"], 10);
echo json_encode(["exit" => $r["exit"], "out" => $r["out"], "err" => $r["err"]]);');
    $basedir = $dir . PATH_SEPARATOR . dirname(__DIR__);
    $r = Proc::run([PHP_BINARY, '-d', 'open_basedir=' . $basedir, $script], 30);
    assertSame(0, $r['exit'], $r['out'] . $r['err']);
    $j = json_decode($r['out'], true);
    assertSame(['exit' => 0, 'out' => '42', 'err' => ''], $j, $r['out']);
});

t('Proc::run kills a command that exceeds the timeout', function () {
    $start = microtime(true);
    $r = Proc::run(['/bin/sleep', '10'], 1);
    assertTrue($r['timed_out']);
    assertTrue(microtime(true) - $start < 5, 'did not wait for the full sleep');
});

t('ExternalScanner reports ClamAV hits as Critical findings', function () {
    $dir = tmpdir();
    $clam = fakeTool($dir, 'clamscan', 'rc=0
for f in "$@"; do
  case "$f" in -*) continue;; esac
  if grep -q EICAR "$f"; then echo "$f: Fake.Eicar FOUND"; rc=1; fi
done
exit $rc
');
    $bad = putFile($dir, 'bad.php', 'x EICAR x');
    $good = putFile($dir, 'good.php', 'fine');
    $s = new ExternalScanner($clam, null, null);
    assertTrue($s->enabled());
    $f = $s->scan(['sub/bad.php' => $bad, 'good.php' => $good, '123' => $good]);
    assertSame(1, count($f));
    assertSame('sub/bad.php', $f[0]->path);
    assertSame('clamav:Fake.Eicar', $f[0]->rule);
    assertSame(Finding::CRITICAL, $f[0]->severity);
    assertSame([], $s->errors());
});

t('ExternalScanner reports YARA hits and skips YARA when no rules file exists', function () {
    $dir = tmpdir();
    $yara = fakeTool($dir, 'yara', 'if grep -q YARAHIT "$2"; then echo "RuleX $2"; fi
exit 0
');
    file_put_contents($dir . '/rules.yar', 'rule RuleX { condition: false }');
    $hit = putFile($dir, 'hit.php', 'YARAHIT');
    $miss = putFile($dir, 'miss.php', 'nothing');
    $s = new ExternalScanner(null, $yara, $dir . '/rules.yar');
    $f = $s->scan(['hit.php' => $hit, 'miss.php' => $miss]);
    assertSame(['yara:RuleX'], array_map(function ($x) { return $x->rule; }, $f));
    assertSame('hit.php', $f[0]->path);

    $cfg = makeConfig(tmpdir(), ['yara_path' => $yara, 'yara_rules' => $dir . '/missing.yar']);
    assertTrue(!ExternalScanner::fromConfig($cfg)->enabled());
    $cfg2 = makeConfig(tmpdir(), ['yara_path' => $yara, 'yara_rules' => $dir . '/rules.yar']);
    assertTrue(ExternalScanner::fromConfig($cfg2)->enabled());
});

t('ExternalScanner records tool failures as errors, not findings', function () {
    $dir = tmpdir();
    $clam = fakeTool($dir, 'clamscan', 'echo "ERROR: cannot load database" >&2
exit 2
');
    $f = putFile($dir, 'a.php', 'x');
    $s = new ExternalScanner($clam, null, null);
    assertSame([], $s->scan(['a.php' => $f]));
    assertTrue(count($s->errors()) === 1);
    assertContains('clamscan', $s->errors()[0]);
    assertSame([], (new ExternalScanner(null, null, null))->scan(['a.php' => $f]));
});

t('ExternalScanner prefers the clamd service (clamdscan --fdpass) and parses its hits like clamscan', function () {
    $dir = tmpdir();
    $log = $dir . '/calls';
    $scan = 'rc=0
for f in "$@"; do
  case "$f" in -*) continue;; esac
  if grep -q EICAR "$f"; then echo "$f: Fake.Eicar FOUND"; rc=1; fi
done
exit $rc
';
    $clamd = fakeTool($dir, 'clamdscan', 'echo "clamdscan $*" >> ' . escapeshellarg($log) . "
" . $scan);
    $clam = fakeTool($dir, 'clamscan', 'echo "clamscan $*" >> ' . escapeshellarg($log) . "
" . $scan);
    $bad = putFile($dir, 'bad.php', 'x EICAR x');
    $good = putFile($dir, 'good.php', 'fine');
    $s = new ExternalScanner($clam, null, null, null, [], $clamd);
    $f = $s->scan(['bad.php' => $bad, 'good.php' => $good]);
    assertSame(['bad.php clamav:Fake.Eicar'], array_map(function ($x) { return $x->path . ' ' . $x->rule; }, $f));
    assertSame([], $s->errors());
    $calls = file($log, FILE_IGNORE_NEW_LINES);
    assertSame(1, count($calls), implode("\n", $calls));
    assertContains('clamdscan --fdpass --no-summary --infected', $calls[0]);
});

t('ExternalScanner falls back to clamscan when clamd cannot be reached, and says why once', function () {
    $dir = tmpdir();
    $clamd = fakeTool($dir, 'clamdscan', 'echo "ERROR: Could not connect to clamd on LocalSocket /var/run/clamav/clamd.ctl: No such file or directory" >&2
exit 2
');
    $clam = fakeTool($dir, 'clamscan', 'for f in "$@"; do case "$f" in *bad*) echo "$f: Fake.Hit FOUND"; exit 1;; esac; done; exit 0
');
    $files = [];
    for ($i = 0; $i < 250; $i++) { // three chunks: clamd is given up on after the first
        $files["f$i.php"] = putFile($dir, "f$i.php", 'x');
    }
    $files['bad.php'] = putFile($dir, 'bad.php', 'x');
    $s = new ExternalScanner($clam, null, null, null, [], $clamd);
    $f = $s->scan($files);
    assertSame(['bad.php'], array_map(function ($x) { return $x->path; }, $f));
    assertSame(["ClamAV's scanning service (clamd) cannot be reached; it is not used this run"], $s->errors());
});

t('ExternalScanner: ClamAV that cannot read its database is said once per run and never counts as clean', function () {
    $dir = tmpdir();
    $log = $dir . '/calls';
    // What xneelo's clamscan prints for a site user: the database in /var/lib/clamav is unreadable.
    $clam = fakeTool($dir, 'clamscan', 'echo x >> ' . escapeshellarg($log) . '
echo "LibClamAV Error: cli_loaddbdir: No supported database files found in /var/lib/clamav" >&2
echo "ERROR: Cannot open file or directory" >&2
exit 2
');
    $files = [];
    for ($i = 0; $i < 250; $i++) {
        $files["f$i.php"] = putFile($dir, "f$i.php", 'x');
    }
    $s = new ExternalScanner($clam, null, null);
    assertSame([], $s->scan($files));
    assertSame(1, count(file($log)), 'not retried for every chunk');
    assertSame(1, count($s->errors()));
    assertContains('cannot read its virus database', $s->errors()[0]);
});

t('ExternalScanner::fromConfig finds clamdscan on PATH unless clamscan_path pins plain clamscan; doctor names the mode', function () {
    $dir = tmpdir();
    $clamd = fakeTool($dir, 'clamdscan', "exit 0\n");
    $clam = fakeTool($dir, 'clamscan', "exit 0\n");
    $oldPath = (string)getenv('PATH');
    putenv('PATH=' . $dir . PATH_SEPARATOR . $oldPath);
    try {
        $auto = ExternalScanner::fromConfig(makeConfig(tmpdir()));
        assertContains('the clamd service through ' . $clamd . ', falling back to ' . $clam, $auto->describeClamav());
        $pinned = ExternalScanner::fromConfig(makeConfig(tmpdir(), ['clamscan_path' => $clam]));
        assertContains('ClamAV: ' . $clam . ' (no clamd service found)', $pinned->describeClamav());
        $missing = ExternalScanner::fromConfig(makeConfig(tmpdir(), ['clamdscan_path' => $dir . '/nope']));
        $missing->scan(['a.php' => $clam]);
        assertContains('clamdscan_path is set but', implode(' ', $missing->errors()));
    } finally {
        putenv('PATH=' . $oldPath);
    }
    assertSame('ClamAV: not found (optional)', (new ExternalScanner(null, null, null))->describeClamav());
});

t('ExternalScanner::find stays quiet for PATH folders outside open_basedir (cron PATH /usr/bin:/bin on xneelo)', function () {
    $dir = tmpdir();
    $script = $dir . '/child.php';
    file_put_contents($script, '<?php
set_error_handler(function ($no, $str) { if (error_reporting() & $no) { echo "WARNING: $str\\n"; } return true; });
require ' . var_export(__DIR__ . '/bootstrap.php', true) . ';
var_export(Sentinel\\ExternalScanner::find("definitely-not-a-real-binary-xyz"));');
    $r = Proc::run(['/usr/bin/env', 'PATH=' . $dir . ':/usr/bin:/bin', PHP_BINARY, '-d', 'open_basedir=' . $dir . PATH_SEPARATOR . dirname(__DIR__), $script], 30);
    assertSame(0, $r['exit'], $r['out'] . $r['err']);
    assertSame('NULL', trim($r['out']), 'no open_basedir warnings');
});

t('ExternalScanner::find locates executables on PATH', function () {
    assertSame('/bin/sh', realpath((string)ExternalScanner::find('sh')) === realpath('/bin/sh') ? '/bin/sh' : 'other');
    assertSame(null, ExternalScanner::find('definitely-not-a-real-binary-xyz'));
});

t('ExternalScanner degrades with a note when proc_open is disabled (common on shared hosts)', function () {
    $dir = tmpdir();
    $script = $dir . '/child.php';
    file_put_contents($script, '<?php
require ' . var_export(__DIR__ . '/bootstrap.php', true) . ';
$root = ' . var_export($dir, true) . ';
$tool = $root . "/clamscan";
file_put_contents($tool, "#!/bin/sh\nexit 0\n");
chmod($tool, 0755);
$c = Sentinel\Config::fromArray(["site_name" => "x", "site_root" => $root, "state_dir" => $root . "/s", "clamscan_path" => $tool]);
$s = Sentinel\ExternalScanner::fromConfig($c);
echo json_encode([
    "available" => Sentinel\Proc::available(),
    "enabled" => $s->enabled(),
    "findings" => count($s->scan(["a.php" => $root . "/a.php"])),
    "errors" => $s->errors(),
    "run" => Sentinel\Proc::run(["/bin/true"], 1)["exit"],
]);');
    $r = Proc::run([PHP_BINARY, '-d', 'disable_functions=proc_open', $script], 30);
    assertSame(0, $r['exit'], $r['out'] . $r['err']);
    $j = json_decode($r['out'], true);
    assertSame(false, $j['available']);
    assertSame(false, $j['enabled']);
    assertSame(0, $j['findings']);
    assertSame(-1, $j['run']);
    assertContains('proc_open', implode(' ', $j['errors']));
});
