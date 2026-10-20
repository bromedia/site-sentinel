<?php
declare(strict_types=1);

use Sentinel\AlertLog;
use Sentinel\Finding;
use Sentinel\Lock;
use Sentinel\SelfCheck;
use Sentinel\State;

t('State creates a private directory and round-trips JSON atomically', function () {
    $dir = tmpdir() . '/nested/state';
    $s = new State($dir);
    assertSame(0700, fileperms($dir) & 0777);
    $s->writeJson('x.json', ['a' => [1, 2], 'b' => 'ü']);
    assertSame(['a' => [1, 2], 'b' => 'ü'], $s->readJson('x.json'));
    assertSame(0600, fileperms($dir . '/x.json') & 0777);
    assertSame(['x.json'], array_values(array_diff(scandir($dir), ['.', '..'])));
    assertSame([], $s->readJson('missing.json'));
    file_put_contents($dir . '/bad.json', '{broken');
    assertSame([], $s->readJson('bad.json'));
    assertSame($dir . '/baseline.txt', $s->path('baseline.txt'));
});

t('State refuses a directory it cannot create', function () {
    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        skip('root can write anywhere');
    }
    assertThrows(RuntimeException::class, function () {
        new State('/proc/definitely/not/creatable');
    });
});

t('Lock is exclusive while held, free after release, and a leftover file is not stale (Review Focus 5)', function () {
    $f = tmpdir() . '/lock';
    $a = Lock::acquire($f);
    assertTrue($a !== null);
    assertSame(null, Lock::acquire($f));
    $a->release();
    $b = Lock::acquire($f);
    assertTrue($b !== null);
    $b->release();
    file_put_contents($f, 'left behind by a crashed run');
    $c = Lock::acquire($f);
    assertTrue($c !== null);
});

t('AlertLog alerts once, reminds Critical findings, retries failed sends and forgets old entries', function () {
    $state = new State(tmpdir());
    $crit = new Finding(Finding::CRITICAL, 'a.php', 'r', 'm', 'h');
    $warn = new Finding(Finding::WARNING, 'b.php', 'r', 'm', 'h');
    $info = new Finding(Finding::INFO, 'c.php', 'r', 'm', 'h');
    $day = 86400;

    $log = new AlertLog($state);
    assertSame([$crit, $warn], $log->due([$crit, $warn, $info], 1000, $day));
    $log->commit([$crit, $warn, $info], [$crit, $warn], 1000);

    $log = new AlertLog($state); // reloaded from disk
    assertSame([], $log->due([$crit, $warn], 1000 + 3600, $day));
    assertSame([$crit], $log->due([$crit, $warn], 1000 + $day, $day), 'only Critical reminds');

    // A send that failed leaves the finding un-alerted so the next run retries it.
    $failed = new Finding(Finding::CRITICAL, 'd.php', 'r', 'm', 'h');
    $log->commit([$failed], [], 2000);
    $log = new AlertLog($state);
    assertSame([$failed], $log->due([$failed], 2100, $day));

    // Unseen for more than 7 days: forgotten, so it alerts as new again.
    $log->commit([], [], 1000 + 8 * $day);
    $log = new AlertLog($state);
    assertSame([$warn], $log->due([$warn], 1000 + 8 * $day, $day));

    $log->clear();
    assertSame([$warn], (new AlertLog($state))->due([$warn], 5, $day));
});

t('SelfCheck records on first use, then flags changed or missing tool files', function () {
    $dir = tmpdir();
    $state = new State($dir . '/state');
    $script = putFile($dir, 'sentinel.php', '<?php // v1');
    $config = putFile($dir, 'sentinel.json', '{}');
    $files = ['script' => $script, 'config' => $config, 'rules' => $state->path('rules.json')];
    $sc = new SelfCheck($state, $files);
    assertSame([], $sc->check());
    assertSame([], $sc->check());

    file_put_contents($script, '<?php // tampered');
    $f = $sc->check();
    assertSame(1, count($f));
    assertSame('self-tamper', $f[0]->rule);
    assertSame(Finding::CRITICAL, $f[0]->severity);
    assertContains('script', $f[0]->path);

    $sc->record();
    assertSame([], $sc->check());

    unlink($config);
    $f = $sc->check();
    assertSame(1, count($f));
    assertContains('missing', $f[0]->message);

    // A tracked file that appears without Sentinel writing it is tampering: an empty rules.json
    // dropped into the state directory would otherwise switch off pattern detection silently.
    file_put_contents($config, '{}');
    $sc->record();
    file_put_contents($state->path('rules.json'), '{"version":1}');
    $f = $sc->check();
    assertSame(1, count($f));
    assertContains('appeared', $f[0]->message);
    $sc->record(); // accept --self
    assertSame([], $sc->check());
    file_put_contents($state->path('rules.json'), '{"version":2}');
    assertSame(1, count($sc->check()));
});

t('SelfCheck::trust re-trusts only the file Sentinel just wrote, so other tampering stays flagged', function () {
    $dir = tmpdir();
    $state = new State($dir . '/state');
    $script = putFile($dir, 'sentinel.php', '<?php // v1');
    $files = ['script' => $script, 'rules' => $state->path('rules.json')];
    $sc = new SelfCheck($state, $files);
    $sc->record();
    file_put_contents($script, '<?php // tampered');
    file_put_contents($state->path('rules.json'), '{"version":1}');
    $sc->trust('rules'); // what update-rules does after installing a verified bundle
    $f = $sc->check();
    assertSame(1, count($f));
    assertContains('script', $f[0]->path);
    assertThrows(InvalidArgumentException::class, function () use ($sc) {
        $sc->trust('nope');
    });
});

t('SelfCheck treats a label missing from an older record as absent, so a file that later appears is flagged', function () {
    $dir = tmpdir();
    $state = new State($dir . '/state');
    $script = putFile($dir, 'sentinel.php', '<?php');
    $state->writeJson('selfcheck.json', ['script' => hash_file('sha256', $script)]); // written by an earlier version
    $sc = new SelfCheck($state, ['script' => $script, 'dismissals' => $state->path('dismissals.json')]);
    assertSame([], $sc->check(), 'upgrading alone raises nothing');
    file_put_contents($state->path('dismissals.json'), '{"dismissals":[]}');
    assertSame(1, count($sc->check()));
});

t('Lock::acquire throws when the lock file cannot be opened, instead of looking busy', function () {
    $dir = tmpdir();
    mkdir($dir . '/lock'); // a directory where the lock file should be
    assertThrows(RuntimeException::class, function () use ($dir) {
        Lock::acquire($dir . '/lock');
    });
});
