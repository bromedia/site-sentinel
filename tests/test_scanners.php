<?php
declare(strict_types=1);

use Sentinel\Config;
use Sentinel\Finding;
use Sentinel\LocationScanner;
use Sentinel\PatternScanner;
use Sentinel\Rules;

function rulesOf(array $findings): array
{
    return array_map(function (Finding $f) { return $f->rule; }, $findings);
}

function lrec(string $root, string $rel): array
{
    $st = lstat($root . '/' . $rel);
    return ['path' => $rel, 'size' => (int)$st['size'], 'mtime' => (int)$st['mtime'], 'mode' => (int)$st['mode'], 'hash' => ''];
}

function wpConfig(string $root): Config
{
    putFile($root, 'wp-config.php', '<?php');
    return makeConfig($root, ['profile' => 'wordpress']);
}

t('Finding key is stable and depends on rule, path and hash', function () {
    $a = new Finding(Finding::CRITICAL, 'a.php', 'r', 'm', 'h1');
    assertSame($a->key(), (new Finding(Finding::WARNING, 'a.php', 'r', 'other message', 'h1'))->key());
    assertTrue($a->key() !== (new Finding(Finding::CRITICAL, 'a.php', 'r', 'm', 'h2'))->key());
    assertSame('CRITICAL', Finding::label(Finding::CRITICAL));
    assertSame(Finding::WARNING, Finding::parseSeverity('Warning'));
    assertSame(Finding::INFO, Finding::parseSeverity('INFO'));
});

t('Builtin rules match known-bad snippets and not ordinary code', function () {
    $r = Rules::builtin();
    $ids = function (string $code) use ($r) {
        return array_column($r->matchContent($code), 'id');
    };
    assertSame(['test-marker'], $ids('<?php // SENTINEL-TEST-MALWARE-MARKER'));
    assertSame(['eval-decoder'], $ids('<?php eval(base64_decode($payload));'));
    assertSame(['exec-request'], $ids('<?php system($_GET["c"]);'));
    assertSame(['request-callable'], $ids('<?php $_POST["f"]($x);'));
    assertSame([], $ids('<?php echo htmlspecialchars($_GET["q"]); $x = base64_decode($y);'));
});

t('Rules::fromArray validates entries and exposes bad hashes', function () {
    assertThrows(InvalidArgumentException::class, function () {
        Rules::fromArray(['patterns' => [['id' => 'x', 'severity' => 'critical', 'regex' => '/(unclosed/']]]);
    });
    assertThrows(InvalidArgumentException::class, function () {
        Rules::fromArray(['patterns' => [['id' => 'x', 'severity' => 'loud', 'regex' => '/a/']]]);
    });
    assertThrows(InvalidArgumentException::class, function () {
        Rules::fromArray(['hashes' => [['sha256' => 'nothex']]]);
    });
    $sha = hash('sha256', 'bad');
    $r = Rules::fromArray(['version' => 5, 'patterns' => [], 'hashes' => [['sha256' => strtoupper($sha), 'name' => 'Evil.A']]]);
    assertSame(5, $r->version);
    assertSame('Evil.A', $r->badHash($sha));
    assertSame(null, $r->badHash(hash('sha256', 'good')));
});

t('Rules::load reads a bundle from disk', function () {
    $f = tmpdir() . '/rules.json';
    file_put_contents($f, json_encode(['version' => 3, 'patterns' => [['id' => 'p', 'severity' => 'warning', 'regex' => '/needle/', 'description' => 'Needle']]]));
    $r = Rules::load($f);
    assertSame(3, $r->version);
    assertSame(['p'], array_column($r->matchContent('hay needle hay'), 'id'));
});

t('PatternScanner reports pattern hits and bad hashes with the file hash', function () {
    $root = tmpdir();
    $abs = putFile($root, 'a.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $sha = hash_file('sha256', $abs);
    $s = new PatternScanner(Rules::builtin(), 1048576);
    $f = $s->scan('a.php', $abs, $sha);
    assertSame(['test-marker'], rulesOf($f));
    assertSame(Finding::CRITICAL, $f[0]->severity);
    assertSame($sha, $f[0]->hash);

    $bad = Rules::fromArray(['hashes' => [['sha256' => $sha, 'name' => 'Known.Bad']]]);
    $f2 = (new PatternScanner($bad, 1048576))->scan('a.php', $abs, $sha);
    assertSame(['bad-hash'], rulesOf($f2));
    assertSame([], $s->scan('missing.php', $root . '/missing.php', ''));
});

t('PatternScanner sees a payload appended to a file larger than max_scan_bytes (Review Focus 2)', function () {
    $root = tmpdir();
    $pad = str_repeat("// padding line\n", 200000); // ~3.2MB
    $tail = putFile($root, 'tail.php', "<?php\n" . $pad . "// SENTINEL-TEST-MALWARE-MARKER\n");
    $head = putFile($root, 'head.php', "<?php // SENTINEL-TEST-MALWARE-MARKER\n" . $pad);
    $mid = putFile($root, 'mid.php', "<?php\n" . $pad . "// SENTINEL-TEST-MALWARE-MARKER\n" . $pad);
    $s = new PatternScanner(Rules::builtin(), 1048576);
    assertSame(['test-marker'], rulesOf($s->scan('tail.php', $tail, '')));
    assertSame(['test-marker'], rulesOf($s->scan('head.php', $head, '')));
    // Documented limit: the middle of a file larger than max_scan_bytes is not read.
    assertSame([], $s->scan('mid.php', $mid, ''));
});

t('LocationScanner flags PHP in uploads, including double extensions', function () {
    $root = tmpdir();
    $c = wpConfig($root);
    foreach (['wp-content/uploads/shell.php', 'wp-content/uploads/a/b.PHTML', 'wp-content/uploads/pic.php.jpg', 'wp-content/uploads/ok.jpg'] as $p) {
        putFile($root, $p, 'x');
    }
    $s = new LocationScanner($c);
    assertSame(['php-in-uploads'], rulesOf($s->scan('wp-content/uploads/shell.php', lrec($root, 'wp-content/uploads/shell.php'), true)));
    assertSame(['php-in-uploads'], rulesOf($s->scan('wp-content/uploads/a/b.PHTML', lrec($root, 'wp-content/uploads/a/b.PHTML'), true)));
    assertSame(['php-in-uploads'], rulesOf($s->scan('wp-content/uploads/pic.php.jpg', lrec($root, 'wp-content/uploads/pic.php.jpg'), true)));
    assertSame([], $s->scan('wp-content/uploads/ok.jpg', lrec($root, 'wp-content/uploads/ok.jpg'), true));
    // Same extension outside uploads is not a location finding.
    putFile($root, 'wp-content/themes/t/functions.php', '<?php');
    assertSame([], $s->scan('wp-content/themes/t/functions.php', lrec($root, 'wp-content/themes/t/functions.php'), true));
});

t('LocationScanner finds PHP hidden in new media and config files in uploads', function () {
    $root = tmpdir();
    $c = wpConfig($root);
    putFile($root, 'wp-content/uploads/head.jpg', "<?php system(\$_GET['c']); ?>\xFF\xD8");
    putFile($root, 'wp-content/uploads/tail.png', str_repeat("\x89PNG", 5000) . '<?php echo 1;');
    putFile($root, 'wp-content/uploads/.htaccess', 'AddHandler application/x-httpd-php .jpg');
    $s = new LocationScanner($c);
    assertSame(['php-in-media'], rulesOf($s->scan('wp-content/uploads/head.jpg', lrec($root, 'wp-content/uploads/head.jpg'), true)));
    assertSame(['php-in-media'], rulesOf($s->scan('wp-content/uploads/tail.png', lrec($root, 'wp-content/uploads/tail.png'), true)));
    // An existing image that later gains PHP code is just as dangerous as a new one.
    assertSame(['php-in-media'], rulesOf($s->scan('wp-content/uploads/head.jpg', lrec($root, 'wp-content/uploads/head.jpg'), false)));
    putFile($root, 'wp-content/uploads/clean.jpg', "\xFF\xD8 just an image");
    assertSame([], $s->scan('wp-content/uploads/clean.jpg', lrec($root, 'wp-content/uploads/clean.jpg'), false));
    $f = $s->scan('wp-content/uploads/.htaccess', lrec($root, 'wp-content/uploads/.htaccess'), true);
    assertSame(['config-in-uploads'], rulesOf($f));
    assertSame(Finding::WARNING, $f[0]->severity);
});

t('LocationScanner flags new executables in temp paths and ignores symlinks', function () {
    $root = tmpdir();
    $c = makeConfig($root);
    $x = putFile($root, 'tmp/run', '#!/bin/sh');
    chmod($x, 0755);
    $y = putFile($root, 'bin/tool', '#!/bin/sh');
    chmod($y, 0755);
    $s = new LocationScanner($c);
    assertSame(['exec-in-temp'], rulesOf($s->scan('tmp/run', lrec($root, 'tmp/run'), true)));
    assertSame([], $s->scan('tmp/run', lrec($root, 'tmp/run'), false));
    assertSame([], $s->scan('bin/tool', lrec($root, 'bin/tool'), true));

    $t = makeConfig($root, ['temp_root' => true]);
    assertSame(['exec-in-temp'], rulesOf((new LocationScanner($t))->scan('bin/tool', lrec($root, 'bin/tool'), true)));

    symlink($x, $root . '/tmp/link');
    assertSame([], $s->scan('tmp/link', lrec($root, 'tmp/link'), true));
});

t('LocationScanner flags a PHP extension hidden before a media extension outside uploads', function () {
    $root = tmpdir();
    $c = makeConfig($root);
    putFile($root, 'themes/t/evil.php.jpg', 'x');
    putFile($root, 'themes/t/ok.php', '<?php');
    putFile($root, 'themes/t/photo.jpg', 'x');
    $s = new LocationScanner($c);
    $f = $s->scan('themes/t/evil.php.jpg', lrec($root, 'themes/t/evil.php.jpg'), true);
    assertSame(['double-extension'], rulesOf($f));
    assertSame(Finding::WARNING, $f[0]->severity);
    assertSame([], $s->scan('themes/t/ok.php', lrec($root, 'themes/t/ok.php'), true));
    assertSame([], $s->scan('themes/t/photo.jpg', lrec($root, 'themes/t/photo.jpg'), true));
});

t('PatternScanner reports a rule that failed to run instead of treating the file as clean', function () {
    $root = tmpdir();
    $abs = putFile($root, 'a.php', str_repeat('a', 40) . '!');
    $rules = Rules::fromArray(['patterns' => [['id' => 'heavy', 'severity' => 'critical', 'regex' => '/^(a+)+$/', 'description' => 'heavy rule']]]);
    $jit = ini_set('pcre.jit', '0');
    $limit = ini_set('pcre.backtrack_limit', '100');
    try {
        $f = (new PatternScanner($rules, 1048576))->scan('a.php', $abs, 'abc');
    } finally {
        ini_set('pcre.jit', (string)$jit);
        ini_set('pcre.backtrack_limit', (string)$limit);
    }
    assertSame(['scan-error'], rulesOf($f));
    assertSame(Finding::WARNING, $f[0]->severity);
    assertContains("'heavy'", $f[0]->message);
    // The same rule on an ordinary file is unaffected.
    $ok = putFile($root, 'b.php', '<?php echo 1;');
    assertSame([], (new PatternScanner($rules, 1048576))->scan('b.php', $ok, ''));
});

t('ExternalScanner says when a configured scanner cannot run, instead of going quiet', function () {
    $root = tmpdir();
    $c = makeConfig($root, ['yara_rules' => $root . '/missing.yar', 'clamscan_path' => $root . '/no-clamscan']);
    $x = Sentinel\ExternalScanner::fromConfig($c);
    $x->scan(['a.php' => $root . '/a.php']);
    $errors = implode("\n", $x->errors());
    assertContains('ClamAV scanning skipped', $errors);
    assertContains('YARA scanning skipped', $errors);
    // Merely having yara installed, with nothing configured, is not a problem worth reporting.
    $quiet = Sentinel\ExternalScanner::fromConfig(makeConfig($root));
    $quiet->scan(['a.php' => $root . '/a.php']);
    assertNotContains('skipped', implode("\n", $quiet->errors()));
});
