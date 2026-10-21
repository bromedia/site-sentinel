<?php
declare(strict_types=1);

use Sentinel\Accept;
use Sentinel\Baseline;
use Sentinel\Channel;
use Sentinel\Cli;
use Sentinel\Finding;
use Sentinel\Init;
use Sentinel\Monitor;
use Sentinel\NativeHttp;
use Sentinel\SelfCheck;
use Sentinel\State;

/** @return array{0:string,1:string,2:array,3:string} site root, tool dir, init options, alerts log */
function initFixture(array $files = [], array $extra = []): array
{
    $site = tmpdir();
    $tool = tmpdir();
    foreach ($files as $rel => $content) {
        putFile($site, $rel, $content);
    }
    putFile($tool, 'sentinel.php', '<?php // the tool');
    $alerts = $tool . '/alerts.log';
    $opts = array_merge(['root' => $site, 'file' => $alerts, 'no-wp-checksums' => true], $extra);
    return [$site, $tool, $opts, $alerts];
}

t('Cli::parse understands --k=v, flags, repeated --path and bare words', function () {
    assertSame(
        ['root' => '/x', 'force' => true, 'path' => ['a', 'b'], '_' => ['word']],
        Cli::parse(['--root=/x', '--force', '--path=a', 'word', '--path=b'])
    );
});

t('Init creates config, baseline, versions and prints cron lines', function () {
    [$site, $tool, $opts] = initFixture([
        'wp-config.php' => '<?php',
        'wp-content/plugins/foo/foo.php' => "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n",
        'index.php' => '<?php // home',
        'readme.txt' => 'hello',
    ], ['name' => 'Client A']);
    $r = Init::run($opts, $tool . '/sentinel.php', new FakeHttp());
    assertSame(0, $r['exit'], implode("\n", $r['lines']));
    $out = implode("\n", $r['lines']);
    assertContains('profile wordpress', $out);
    assertContains(Sentinel\Cron::lines($tool . '/sentinel.php', $tool . '/sentinel.json')[0], $out);
    assertContains(' full --config=', $out);
    assertContains('heartbeat', $out);

    assertSame(0600, fileperms($tool . '/sentinel.json') & 0777);
    $cfg = json_decode((string)file_get_contents($tool . '/sentinel.json'), true);
    assertSame('Client A', $cfg['site_name']);
    assertSame('wordpress', $cfg['profile']);
    assertSame($tool . '/sentinel-state', $cfg['state_dir']);

    $state = new State($tool . '/sentinel-state');
    $paths = array_column(iterator_to_array(Baseline::read($state->path('baseline.txt')), false), 'path');
    assertSame(['index.php', 'readme.txt', 'wp-config.php', 'wp-content/plugins/foo/foo.php'], $paths);
    assertSame(['wp-content/plugins/foo' => '1.0'], $state->readJson('versions.json'));
    assertTrue(is_file($state->path('selfcheck.json')));
});

t('Init refuses a site that already contains malware unless forced, leaving nothing behind', function () {
    [$site, $tool, $opts] = initFixture(['index.php' => '<?php', 'lib/evil.php' => '<?php // SENTINEL-TEST-MALWARE-MARKER']);
    $r = Init::run($opts, $tool . '/sentinel.php', new FakeHttp());
    assertSame(1, $r['exit']);
    assertContains('lib/evil.php', implode("\n", $r['lines']));
    assertContains('--force', implode("\n", $r['lines']));
    assertTrue(!is_file($tool . '/sentinel-state/baseline.txt'));
    assertTrue(!is_file($tool . '/sentinel-state/baseline.init'), 'temp baseline removed');
    assertTrue(!is_file($tool . '/sentinel.json'), 'a refused init leaves no config, so cleaning the site is enough to retry');

    unlink($site . '/lib/evil.php');
    $clean = Init::run($opts, $tool . '/sentinel.php', new FakeHttp());
    assertSame(0, $clean['exit'], implode("\n", $clean['lines']));

    $again = Init::run($opts, $tool . '/sentinel.php', new FakeHttp());
    assertSame(2, $again['exit']);
    assertContains('already exists', implode("\n", $again['lines']));

    putFile($site, 'lib/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $forced = Init::run(array_merge($opts, ['force' => true]), $tool . '/sentinel.php', new FakeHttp());
    assertSame(0, $forced['exit']);
    assertContains('WARNING', implode("\n", $forced['lines']));
    assertTrue(is_file($tool . '/sentinel-state/baseline.txt'));
});

t('Init validates its options', function () {
    [$site, $tool, $opts] = initFixture();
    $noRoot = $opts;
    unset($noRoot['root']);
    assertSame(2, Init::run($noRoot, $tool . '/sentinel.php', new FakeHttp())['exit']);
    $noChannel = $opts;
    unset($noChannel['file']);
    $r = Init::run($noChannel, $tool . '/sentinel.php', new FakeHttp());
    assertSame(2, $r['exit']);
    assertContains('alert channel', implode("\n", $r['lines']));
    $badEmail = Init::run(array_merge($noChannel, ['email' => 'nope']), $tool . '/sentinel.php', new FakeHttp());
    assertSame(2, $badEmail['exit']);
});

t('Init with tool files inside the site root leaves them out of the baseline (Review Focus 3)', function () {
    [$site, , $opts] = initFixture(['index.php' => '<?php']);
    putFile($site, 'sentinel.php', '<?php // tool');
    $r = Init::run(array_merge($opts, ['config' => $site . '/sentinel.json', 'state' => $site . '/.sentinel']), $site . '/sentinel.php', new FakeHttp());
    assertSame(0, $r['exit'], implode("\n", $r['lines']));
    $paths = array_column(iterator_to_array(Baseline::read($site . '/.sentinel/baseline.txt'), false), 'path');
    assertSame(['index.php'], $paths);
});

t('After init a check is clean, and accept makes held changes known-good', function () {
    [$site, $tool, $opts] = initFixture(['index.php' => '<?php', 'lib/a.php' => '<?php // a', 'lib/b.php' => '<?php // b']);
    Init::run($opts, $tool . '/sentinel.php', new FakeHttp());
    $config = \Sentinel\Config::load($tool . '/sentinel.json');
    $state = new State($config->stateDir);
    $notifier = new FakeNotifier();
    $selfFiles = ['script' => $tool . '/sentinel.php', 'config' => $tool . '/sentinel.json', 'rules' => $state->path('rules.json')];
    $clock = new FakeClock();
    $clock->t = time() + 3600; // well past the default update grace period of every file this test touches
    $m = new Monitor($config, $state, new FakeHttp(), [new Channel($notifier, Finding::WARNING)], $selfFiles, $clock);
    assertSame(0, $m->run('check')['exit']);

    bump($site, 'lib/a.php', '<?php // a edited');
    bump($site, 'lib/b.php', '<?php // b edited');
    assertSame(1, $m->run('check')['exit']);
    assertSame(1, count($notifier->sent));

    $r = Accept::run($config, $state, ['lib/a.php'], false, $selfFiles);
    assertSame(0, $r['exit']);
    assertContains('1 change(s)', implode("\n", $r['lines']));
    $after = $m->run('check');
    assertSame(1, $after['exit']);
    assertSame(2, count($notifier->sent), 'the remaining set of changes is a new finding');
    $latest = $notifier->sent[1]['body'];
    assertContains('1 file(s) changed without a version change', $latest); // the files themselves are in the report
    assertNotContains('2 file(s) changed', $latest);

    $all = Accept::run($config, $state, [], false, $selfFiles);
    assertContains('1 change(s)', implode("\n", $all['lines']));
    assertSame(0, $m->run('check')['exit']);
    assertSame([], $state->readJson('alerts.json'), 'accepting everything clears the alert log');
});

t('Accept --self re-trusts the tool files and a missing baseline is an error', function () {
    [$site, $tool, $opts] = initFixture(['index.php' => '<?php']);
    Init::run($opts, $tool . '/sentinel.php', new FakeHttp());
    $config = \Sentinel\Config::load($tool . '/sentinel.json');
    $state = new State($config->stateDir);
    $selfFiles = ['script' => $tool . '/sentinel.php'];
    file_put_contents($tool . '/sentinel.php', '<?php // upgraded');
    assertSame(1, count((new SelfCheck($state, $selfFiles))->check()));
    $r = Accept::run($config, $state, [], true, $selfFiles);
    assertSame(0, $r['exit']);
    assertSame([], (new SelfCheck($state, $selfFiles))->check());

    unlink($state->path('baseline.txt'));
    assertSame(2, Accept::run($config, $state, [], false, $selfFiles)['exit']);
});

t('Cli runs commands end to end with a config file', function () {
    [$site, $tool, $opts, $alerts] = initFixture(['index.php' => '<?php']);
    $script = $tool . '/sentinel.php';

    $init = Cli::execute(['init', '--root=' . $site, '--file=' . $alerts, '--no-wp-checksums'], $script, new FakeHttp());
    assertSame(0, $init['exit'], implode("\n", $init['out']) . implode("\n", $init['err']));

    $check = Cli::execute(['check', '--config=' . $tool . '/sentinel.json'], $script, new FakeHttp());
    assertSame(0, $check['exit']);
    assertContains('0 change(s)', $check['out'][0]);

    $test = Cli::execute(['test-alert', '--config=' . $tool . '/sentinel.json'], $script, new FakeHttp());
    assertSame(0, $test['exit']);
    assertContains('file: sent', implode("\n", $test['out']));
    assertContains('TEST', (string)file_get_contents($alerts));

    putFile($site, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $bad = Cli::execute(['check', '--config=' . $tool . '/sentinel.json'], $script, new FakeHttp());
    assertSame(1, $bad['exit']);
    assertContains('evil.php', implode("\n", $bad['out']));

    $upd = Cli::execute(['update-rules', '--config=' . $tool . '/sentinel.json'], $script, new FakeHttp());
    assertSame(2, $upd['exit']);
    assertContains('rules_url', implode("\n", $upd['err']));
});

t('Cli reports usage errors, missing config and versions', function () {
    $v = Cli::execute(['version'], '/x/sentinel.php');
    assertSame(0, $v['exit']);
    assertSame(\Sentinel\VERSION, $v['out'][0]);
    $h = Cli::execute(['help'], '/x/sentinel.php');
    assertSame(0, $h['exit']);
    assertContains('update-rules', implode("\n", $h['out']));
    $none = Cli::execute([], '/x/sentinel.php');
    assertSame(0, $none['exit']);
    $bad = Cli::execute(['frobnicate'], '/x/sentinel.php');
    assertSame(2, $bad['exit']);
    assertContains('unknown command', implode("\n", $bad['err']));
    $noConfig = Cli::execute(['check', '--config=/nonexistent/sentinel.json'], '/x/sentinel.php');
    assertSame(2, $noConfig['exit']);
    assertContains('cannot read config', implode("\n", $noConfig['err']));
});

/** Initialises a site through the CLI and returns [script, configFile, alertsLog, config JSON as array]. */
function cliSite(array $configPatch = []): array
{
    [$site, $tool, , $alerts] = initFixture(['index.php' => '<?php']);
    $script = $tool . '/sentinel.php';
    $init = Cli::execute(['init', '--root=' . $site, '--file=' . $alerts, '--no-wp-checksums'], $script, new FakeHttp());
    assertSame(0, $init['exit'], implode("\n", $init['err']));
    $cfg = json_decode((string)file_get_contents($tool . '/sentinel.json'), true);
    $cfg = array_merge($cfg, $configPatch);
    file_put_contents($tool . '/sentinel.json', json_encode($cfg));
    return [$script, $tool . '/sentinel.json', $alerts];
}

t('update-rules: a download failure raises a Warning alert, deduplicated', function () {
    [$script, $config, $alerts] = cliSite(['rules_url' => 'https://rules.example/rules.json', 'allow_unsigned_rules' => true]);
    $r = Cli::execute(['update-rules', '--config=' . $config], $script, new FakeHttp());
    assertSame(2, $r['exit']);
    $log = (string)file_get_contents($alerts);
    assertContains('[Sentinel][WARNING]', $log);
    assertContains('rules update failed', $log);
    Cli::execute(['update-rules', '--config=' . $config], $script, new FakeHttp());
    assertSame(1, substr_count((string)file_get_contents($alerts), 'rules update failed'), 'the same failure alerts once');
});

t('update-rules: a verification failure raises a Critical alert and installs nothing', function () {
    [$script, $config, $alerts] = cliSite(['rules_url' => 'https://rules.example/rules.json', 'allow_unsigned_rules' => true]);
    $http = new FakeHttp();
    $http->route('https://rules.example/rules.json.sha256', 200, str_repeat('0', 64) . "  rules.json\n");
    $http->route('https://rules.example/rules.json', 200, json_encode(['version' => 1, 'patterns' => []]));
    $r = Cli::execute(['update-rules', '--config=' . $config], $script, $http);
    assertSame(2, $r['exit']);
    $log = (string)file_get_contents($alerts);
    assertContains('[Sentinel][CRITICAL]', $log);
    assertContains('rules checksum mismatch', $log);
    assertTrue(!is_file(dirname($config) . '/sentinel-state/rules.json'));
});

t('update-rules: running it without a rules_url is a usage error, not an alert', function () {
    [$script, $config, $alerts] = cliSite();
    $r = Cli::execute(['update-rules', '--config=' . $config], $script, new FakeHttp());
    assertSame(2, $r['exit']);
    assertContains('rules_url', implode("\n", $r['err']));
    assertTrue(!is_file($alerts), 'no alert for a missing setting');
});

t('Init tells the owner about symlinked directories, which are not followed', function () {
    [$site, $tool, $opts] = initFixture(['index.php' => '<?php']);
    $real = tmpdir();
    putFile($real, 'shell.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    mkdir($site . '/wp-content');
    symlink($real, $site . '/wp-content/uploads');
    symlink($site . '/index.php', $site . '/home-link'); // a symlink to a file is not a directory
    $r = Init::run($opts, $tool . '/sentinel.php', new FakeHttp());
    assertSame(0, $r['exit'], implode("\n", $r['lines']));
    $out = implode("\n", $r['lines']);
    assertContains("'wp-content/uploads' is a symlink to a directory", $out);
    assertContains($real, $out);
    assertContains('does not follow symlinks', $out);
    assertNotContains("'home-link'", $out);
});
