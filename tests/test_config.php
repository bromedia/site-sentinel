<?php
declare(strict_types=1);

use Sentinel\Config;
use Sentinel\ConfigException;
use Sentinel\PathFilter;

t('Config detects the WordPress profile and applies its defaults', function () {
    $root = tmpdir();
    putFile($root, 'wp-config.php', '<?php');
    $c = makeConfig($root, ['profile' => '']);
    assertSame('wordpress', $c->profile);
    assertSame('wp-content/uploads', $c->uploadsDir);
    assertTrue(in_array('wp-content/cache/', $c->exclude, true));
    assertTrue(in_array('php', $c->codeExtensions, true));
});

t('Config rejects bad input', function () {
    $root = tmpdir();
    assertThrows(ConfigException::class, function () {
        Config::fromArray(['site_name' => 'x', 'site_root' => '/nonexistent-dir-xyz', 'state_dir' => '/tmp/s']);
    });
    assertThrows(ConfigException::class, function () use ($root) {
        Config::fromArray(['site_name' => '', 'site_root' => $root, 'state_dir' => '/tmp/s']);
    });
    assertThrows(ConfigException::class, function () use ($root) {
        makeConfig($root, ['channels' => [['type' => 'pigeon']]]);
    });
    assertThrows(ConfigException::class, function () use ($root) {
        makeConfig($root, ['channels' => [['type' => 'email', 'to' => ['not-an-address']]]]);
    });
    assertThrows(ConfigException::class, function () use ($root) {
        makeConfig($root, ['watch' => ['../etc']]);
    });
});

t('Config normalises watch roots', function () {
    $root = tmpdir();
    assertSame(['.'], makeConfig($root, ['watch' => ['wp-content', '.']])->watch);
    assertSame(['a', 'b'], makeConfig($root, ['watch' => ['b', 'a/x', 'a', './a']])->watch);
    assertSame(['.'], makeConfig($root, ['watch' => []])->watch);
});

t('Config normalises channels', function () {
    $c = makeConfig(tmpdir(), ['channels' => [
        ['type' => 'email', 'to' => 'owner@example.com'],
        ['type' => 'ntfy', 'url' => 'https://ntfy.sh/x', 'min_severity' => 'CRITICAL'],
    ]]);
    assertSame(['owner@example.com'], $c->channels[0]['to']);
    assertSame('warning', $c->channels[0]['min_severity']);
    assertSame('critical', $c->channels[1]['min_severity']);
});

t('Config excludes its own state dir and tool files inside the site root (Review Focus 3)', function () {
    $root = tmpdir();
    $c = Config::fromArray(['site_name' => 'x', 'site_root' => $root, 'state_dir' => $root . '/.sentinel', 'profile' => 'generic']);
    $f = new PathFilter($c->exclusions());
    assertTrue($f->matches('.sentinel'));
    assertTrue($f->matches('.sentinel/baseline.txt'));
    $c->addExclusion($root . '/sentinel.php');
    $f = new PathFilter($c->exclusions());
    assertTrue($f->matches('sentinel.php'));
    assertTrue(!$f->matches('sub/sentinel.php'));
});

t('Config classifies code files and uploads paths', function () {
    $root = tmpdir();
    putFile($root, 'wp-config.php', '<?php');
    $c = makeConfig($root, ['profile' => 'wordpress']);
    assertTrue($c->isCodeFile('a/b/Shell.PHP'));
    assertTrue($c->isCodeFile('.htaccess'));
    assertTrue(!$c->isCodeFile('wp-content/uploads/a.jpg'));
    assertTrue($c->isUploads('wp-content/uploads/2026/a.jpg'));
    assertTrue(!$c->isUploads('wp-content/uploads2/a.jpg'));
});

t('Config round-trips through toArray and abs handles the root', function () {
    $root = tmpdir();
    $c = makeConfig($root, ['budget_seconds' => 7, 'rules_url' => 'https://example.com/rules.json']);
    $again = Config::fromArray($c->toArray());
    assertSame($c->toArray(), $again->toArray());
    assertSame(7, $again->budgetSeconds);
    assertSame($c->siteRoot . '/a/b', $c->abs('a/b'));
    assertSame($c->siteRoot, $c->abs(''));
});

t('Config::load reads JSON and reports unreadable or invalid files', function () {
    $root = tmpdir();
    $dir = tmpdir();
    file_put_contents($dir . '/c.json', json_encode(['site_name' => 'j', 'site_root' => $root, 'state_dir' => $dir . '/s', 'profile' => 'generic']));
    assertSame('j', Config::load($dir . '/c.json')->siteName);
    assertThrows(ConfigException::class, function () use ($dir) { Config::load($dir . '/missing.json'); });
    file_put_contents($dir . '/bad.json', '{nope');
    assertThrows(ConfigException::class, function () use ($dir) { Config::load($dir . '/bad.json'); });
});
