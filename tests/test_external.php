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
    assertSame(-1, Proc::run(['/nonexistent/binary'], 5)['exit']);
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

t('ExternalScanner::find locates executables on PATH', function () {
    assertSame('/bin/sh', realpath((string)ExternalScanner::find('sh')) === realpath('/bin/sh') ? '/bin/sh' : 'other');
    assertSame(null, ExternalScanner::find('definitely-not-a-real-binary-xyz'));
});
