<?php
declare(strict_types=1);

// Usage: php build/build.php [output-file]   (default: dist/sentinel.php)
$root = dirname(__DIR__);
$files = require __DIR__ . '/files.php';
$version = trim((string)file_get_contents($root . '/VERSION'));

$out = "<?php\ndeclare(strict_types=1);\n\n"
    . "// Site Sentinel " . $version . " - file-integrity and malware monitor.\n"
    . "// License: GPL-3.0-or-later. See LICENSE in the source repository. No warranty.\n\n"
    . "namespace Sentinel;\n\n"
    . 'const VERSION = ' . var_export($version, true) . ";\n\n"
    . "// Never run through a web server, even if the file is dropped into a web root.\n"
    . "if (PHP_SAPI !== 'cli') {\n    http_response_code(404);\n    exit;\n}\n";

foreach ($files as $f) {
    $src = file_get_contents($root . '/src/' . $f);
    if ($src === false) {
        fwrite(STDERR, "missing src/$f\n");
        exit(1);
    }
    $src = preg_replace('/\A<\?php\s+declare\(strict_types=1\);\s+namespace Sentinel;\s*/', '', $src, 1, $n);
    if ($n !== 1) {
        fwrite(STDERR, "src/$f must start with <?php, declare(strict_types=1); and namespace Sentinel;\n");
        exit(1);
    }
    $out .= "\n// ---- $f ----\n" . $src;
}
$out .= "\nexit(Cli::main(\$argv));\n";

$target = $argv[1] ?? $root . '/dist/sentinel.php';
if (!is_dir(dirname($target)) && !mkdir(dirname($target), 0755, true)) {
    fwrite(STDERR, "cannot create " . dirname($target) . "\n");
    exit(1);
}
file_put_contents($target, $out);
echo 'built ' . $target . ' (' . strlen($out) . ' bytes from ' . count($files) . " files)\n";
