<?php
declare(strict_types=1);

use Sentinel\Config;
use Sentinel\Proc;
use Sentinel\RulesUpdater;
use Sentinel\SelfCheck;
use Sentinel\State;

function rulesBundle(int $version, string $regex = '/needle/'): string
{
    return json_encode(['version' => $version, 'patterns' => [['id' => 'p' . $version, 'severity' => 'critical', 'regex' => $regex, 'description' => 'Needle']], 'hashes' => []]);
}

/** @return array{0:RulesUpdater,1:State,2:FakeHttp,3:SelfCheck} */
function updaterFor(array $cfg = []): array
{
    $config = makeConfig(tmpdir(), array_merge(['rules_url' => 'https://rules.example/rules.json'], $cfg));
    $state = new State($config->stateDir);
    $http = new FakeHttp();
    $self = new SelfCheck($state, ['rules' => $state->path('rules.json')]);
    return [new RulesUpdater($config, $state, $http, $self), $state, $http, $self];
}

function serveUnsigned(FakeHttp $http, string $bundle, ?string $sha = null): void
{
    $http->route('https://rules.example/rules.json.sha256', 200, ($sha ?? hash('sha256', $bundle)) . "  rules.json\n");
    $http->route('https://rules.example/rules.json', 200, $bundle);
}

t('RulesUpdater refuses unsigned rules by default and without a rules_url', function () {
    [$u, $state, $http] = updaterFor();
    serveUnsigned($http, rulesBundle(1));
    assertThrows(RuntimeException::class, function () use ($u) { $u->update(); });
    assertTrue(!is_file($state->path('rules.json')));
    try {
        $u->update();
    } catch (RuntimeException $e) {
        assertContains('refusing to install unsigned rules', $e->getMessage());
    }
    [$none] = updaterFor(['rules_url' => '']);
    try {
        $none->update();
        throw new Exception('expected failure');
    } catch (RuntimeException $e) {
        assertContains('rules_url', $e->getMessage());
    }
});

t('RulesUpdater installs a SHA-256-verified bundle only when allowed, and warns', function () {
    [$u, $state, $http, $self] = updaterFor(['allow_unsigned_rules' => true]);
    $bundle = rulesBundle(3);
    serveUnsigned($http, $bundle);
    $lines = $u->update();
    assertContains('WARNING', implode("\n", $lines));
    assertContains('installed rules version 3', implode("\n", $lines));
    assertSame($bundle, file_get_contents($state->path('rules.json')));
    assertSame(0600, fileperms($state->path('rules.json')) & 0777);
    $self->record();
    assertSame([], $self->check());
});

t('RulesUpdater rejects checksum mismatches, replays, bad rules and keeps the old bundle', function () {
    [$u, $state, $http] = updaterFor(['allow_unsigned_rules' => true]);
    serveUnsigned($http, rulesBundle(5));
    $u->update();
    $installed = file_get_contents($state->path('rules.json'));

    serveUnsigned($http, rulesBundle(6), str_repeat('0', 64));
    assertThrows(RuntimeException::class, function () use ($u) { $u->update(); });

    serveUnsigned($http, rulesBundle(4));
    try {
        $u->update();
        throw new Exception('expected a downgrade to be refused');
    } catch (RuntimeException $e) {
        assertContains('older than', $e->getMessage());
    }

    serveUnsigned($http, rulesBundle(7, '/(unclosed/'));
    assertThrows(Exception::class, function () use ($u) { $u->update(); });

    serveUnsigned($http, 'not json at all');
    assertThrows(Exception::class, function () use ($u) { $u->update(); });

    assertSame($installed, file_get_contents($state->path('rules.json')));

    serveUnsigned($http, rulesBundle(5));
    assertContains('already up to date', implode("\n", $u->update()));
});

t('RulesUpdater reports an unreachable rules server', function () {
    [$u] = updaterFor(['allow_unsigned_rules' => true]);
    assertThrows(RuntimeException::class, function () use ($u) { $u->update(); });
});

t('RulesUpdater verifies ed25519 signatures when sodium is available', function () {
    if (!function_exists('sodium_crypto_sign_keypair')) {
        skip('sodium extension not installed');
    }
    $kp = sodium_crypto_sign_keypair();
    $pub = base64_encode(sodium_crypto_sign_publickey($kp));
    $bundle = rulesBundle(2);
    $sig = base64_encode(sodium_crypto_sign_detached($bundle, sodium_crypto_sign_secretkey($kp)));

    [$u, $state, $http] = updaterFor(['rules_public_key' => $pub]);
    $http->route('https://rules.example/rules.json.sig', 200, $sig . "\n");
    $http->route('https://rules.example/rules.json', 200, $bundle);
    assertContains('signature verified', implode("\n", $u->update()));
    assertSame($bundle, file_get_contents($state->path('rules.json')));

    [$u2, $state2, $http2] = updaterFor(['rules_public_key' => $pub, 'allow_unsigned_rules' => true]);
    $http2->route('https://rules.example/rules.json.sig', 200, $sig);
    $http2->route('https://rules.example/rules.json', 200, rulesBundle(2, '/tampered/'));
    assertThrows(RuntimeException::class, function () use ($u2) { $u2->update(); });
    assertTrue(!is_file($state2->path('rules.json')), 'a failed signature never falls back to the weaker check');
});

t('sign-rules tool produces a signature the updater accepts', function () {
    if (!function_exists('sodium_crypto_sign_keypair')) {
        skip('sodium extension not installed');
    }
    $dir = tmpdir();
    $tool = __DIR__ . '/../bin/sign-rules.php';
    $k = Proc::run([PHP_BINARY, $tool, 'keygen'], 20);
    assertSame(0, $k['exit'], $k['err']);
    preg_match('/public key[^:]*: (\S+)/', $k['out'], $pm);
    preg_match('/secret key[^:]*: (\S+)/', $k['out'], $sm);
    file_put_contents($dir . '/secret.key', $sm[1]);
    file_put_contents($dir . '/rules.json', rulesBundle(9));
    $s = Proc::run([PHP_BINARY, $tool, 'sign', $dir . '/rules.json', $dir . '/secret.key'], 20);
    assertSame(0, $s['exit'], $s['err']);
    assertTrue(is_file($dir . '/rules.json.sig') && is_file($dir . '/rules.json.sha256'));

    [$u, $state, $http] = updaterFor(['rules_public_key' => $pm[1]]);
    $http->route('https://rules.example/rules.json.sig', 200, (string)file_get_contents($dir . '/rules.json.sig'));
    $http->route('https://rules.example/rules.json', 200, (string)file_get_contents($dir . '/rules.json'));
    assertContains('signature verified', implode("\n", $u->update()));
});
