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
// Ordinary permissions, set explicitly so they never depend on the build machine: 755 for the
// folder, 644 for files. Not owner-only, because a hosting file manager may extract as a different
// system user than the one cron runs as. Never world-writable: ZipArchive records a bare folder as
// 0777, which unzip applies as it is, and then any account on a shared server that can reach the
// folder could replace sentinel.php, which cron runs every few hours. The folder belongs outside
// the web root, its .htaccess blocks web access, and Sentinel creates its state directory itself
// with owner-only permissions.
$zip->addEmptyDir('sentinel');
$zip->setExternalAttributesName('sentinel/', ZipArchive::OPSYS_UNIX, (040755 << 16));
foreach ($files as $name => $path) {
    if (!is_file($path)) {
        fwrite(STDERR, "missing $path\n");
        exit(1);
    }
    $zip->addFile($path, $name);
    $zip->setExternalAttributesName($name, ZipArchive::OPSYS_UNIX, (0100644 << 16));
}
if (!$zip->close()) {
    fwrite(STDERR, "cannot write $target\n");
    exit(1);
}
echo 'packaged ' . $target . ' (' . filesize($target) . " bytes)\n";
