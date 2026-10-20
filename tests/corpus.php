<?php
declare(strict_types=1);

// False-positive check: runs the built-in rules over trees of legitimate code and lists every match.
// Usage: php tests/corpus.php DIR [DIR ...]      exit 1 if anything matched
// CI runs it over pinned checkouts of WordPress and popular plugins (see .github/workflows/ci.yml).
require __DIR__ . '/bootstrap.php';

use Sentinel\PatternScanner;
use Sentinel\Rules;

$rules = Rules::builtin();
$allow = [];
foreach (file(__DIR__ . '/corpus-allow.txt', FILE_IGNORE_NEW_LINES) ?: [] as $line) {
    if ($line !== '' && $line[0] !== '#') {
        [$rule, $suffix] = explode("\t", $line) + ['', ''];
        $allow[] = [$rule, $suffix];
    }
}
$allowed = 0;
$exts = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'inc', 'js', 'html', 'htm', 'shtml'];
$hits = 0;
$files = 0;
$t0 = microtime(true);
foreach (array_slice($argv, 1) as $dir) {
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        $path = (string)$file;
        if (strpos($path, '/.git/') !== false || !$file->isFile()) {
            continue;
        }
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if (!in_array($ext, $exts, true)) {
            continue;
        }
        $files++;
        $content = PatternScanner::headTail($path, 2097152);
        $failed = [];
        foreach ($rules->matchContent((string)$content, $failed, $ext) as $p) {
            foreach ($allow as [$rule, $suffix]) {
                if ($rule === $p['id'] && substr($path, -strlen($suffix)) === $suffix) {
                    $allowed++;
                    continue 2;
                }
            }
            $hits++;
            preg_match($p['regex'], (string)$content, $m);
            echo $p['id'] . "\t" . $path . "\t" . substr(str_replace(["\n", "\r"], ' ', $m[0] ?? ''), 0, 120) . "\n";
        }
        foreach ($failed as $f) {
            echo 'PCRE-ERROR ' . $f['id'] . "\t" . $path . "\t" . $f['error'] . "\n";
            $hits++;
        }
    }
}
fprintf(STDERR, "%d file(s), %d unexpected match(es), %d allowed, %.1fs\n", $files, $hits, $allowed, microtime(true) - $t0);
exit($hits > 0 ? 1 : 0);
