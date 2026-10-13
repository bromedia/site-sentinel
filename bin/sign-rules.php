#!/usr/bin/env php
<?php
declare(strict_types=1);

// Maintainer tool for signing rules bundles.
//   php bin/sign-rules.php keygen
//   php bin/sign-rules.php sign rules.json secret.key
// Requires the sodium extension.

if (!function_exists('sodium_crypto_sign_keypair')) {
    fwrite(STDERR, "the sodium extension is required\n");
    exit(2);
}

$cmd = $argv[1] ?? '';
if ($cmd === 'keygen') {
    $kp = sodium_crypto_sign_keypair();
    echo 'public key (put in rules_public_key): ' . base64_encode(sodium_crypto_sign_publickey($kp)) . "\n";
    echo 'secret key (keep offline, pass to sign): ' . base64_encode(sodium_crypto_sign_secretkey($kp)) . "\n";
    exit(0);
}
if ($cmd === 'sign' && isset($argv[2], $argv[3])) {
    $data = file_get_contents($argv[2]);
    $secret = base64_decode(trim((string)file_get_contents($argv[3])), true);
    if ($data === false || $secret === false || strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
        fwrite(STDERR, "cannot read the bundle or the secret key is invalid\n");
        exit(2);
    }
    file_put_contents($argv[2] . '.sig', base64_encode(sodium_crypto_sign_detached($data, $secret)) . "\n");
    file_put_contents($argv[2] . '.sha256', hash('sha256', $data) . '  ' . basename($argv[2]) . "\n");
    echo 'wrote ' . $argv[2] . ".sig and " . $argv[2] . ".sha256\n";
    exit(0);
}
fwrite(STDERR, "usage: php bin/sign-rules.php keygen | sign <rules.json> <secret-key-file>\n");
exit(2);
