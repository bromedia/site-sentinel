<?php
declare(strict_types=1);

// Usage: php build/package.php [output.zip]   (default: dist/site-sentinel-<version>.zip)
// Builds the client package: a "sentinel" folder that is uploaded next to public_html and
// scheduled with one cron job ("run"). Contents: the built script, package/*, and the license.
$root = dirname(__DIR__);
$version = trim((string)file_get_contents($root . '/VERSION'));
$script = $root . '/dist/sentinel.php';

passthru(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/build.php') . ' ' . escapeshellarg($script), $rc);
if ($rc !== 0) {
    exit($rc);
}
if (!class_exists('ZipArchive')) {
    fwrite(STDERR, "the zip extension is required to build the package\n");
    exit(1);
}

$target = $argv[1] ?? $root . '/dist/site-sentinel-' . $version . '.zip';
@unlink($target);
$zip = new ZipArchive();
if ($zip->open($target, ZipArchive::CREATE | ZipArchive::EXCL) !== true) {
    fwrite(STDERR, "cannot create $target\n");
    exit(1);
}
$files = [
    'sentinel/sentinel.php' => $script,
    'sentinel/sentinel.json' => $root . '/package/sentinel.json',
    'sentinel/settings.txt' => $root . '/package/settings.txt',
    'sentinel/SETUP-PENDING.txt' => $root . '/package/SETUP-PENDING.txt',
    'sentinel/.htaccess' => $root . '/package/.htaccess',
    'sentinel/INSTALL-XNEELO.txt' => $root . '/package/INSTALL-XNEELO.txt',
    'sentinel/LICENSE.txt' => $root . '/LICENSE',
];
$zip->addEmptyDir('sentinel');
foreach ($files as $name => $path) {
    if (!is_file($path)) {
        fwrite(STDERR, "missing $path\n");
        exit(1);
    }
    // Ordinary permissions on purpose: a hosting file manager may extract as a different system user
    // than the one cron runs as, and owner-only files could then not even be read by Sentinel. The
    // folder belongs outside the web root, its .htaccess blocks web access, and Sentinel creates its
    // state directory itself with owner-only permissions.
    $zip->addFile($path, $name);
}
if (!$zip->close()) {
    fwrite(STDERR, "cannot write $target\n");
    exit(1);
}
echo 'packaged ' . $target . ' (' . filesize($target) . " bytes)\n";
