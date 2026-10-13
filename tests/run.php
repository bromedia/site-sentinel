<?php
declare(strict_types=1);

// Usage: php tests/run.php [name-substring]
error_reporting(E_ALL);
set_error_handler(function ($no, $str, $file, $line) {
    if (!(error_reporting() & $no)) {
        return false;
    }
    throw new ErrorException($str, 0, $no, $file, $line);
});

require __DIR__ . '/lib.php';
require __DIR__ . '/bootstrap.php';
foreach (glob(__DIR__ . '/helpers_*.php') as $f) {
    require $f;
}
foreach (glob(__DIR__ . '/test_*.php') as $f) {
    require $f;
}

$filter = $argv[1] ?? '';
$pass = 0;
$fail = 0;
$skipped = 0;
foreach ($GLOBALS['__tests'] as [$name, $fn]) {
    if ($filter !== '' && stripos($name, $filter) === false) {
        continue;
    }
    try {
        $fn();
        $pass++;
        echo "ok   $name\n";
    } catch (SkipTest $e) {
        $skipped++;
        echo "skip $name ({$e->getMessage()})\n";
    } catch (Throwable $e) {
        $fail++;
        echo "FAIL $name\n     " . str_replace("\n", "\n     ", $e->getMessage()) . "\n     at " . basename($e->getFile()) . ':' . $e->getLine() . "\n";
    }
}
foreach ($GLOBALS['__tmp'] as $d) {
    rmrf($d);
}
echo "\n$pass passed, $fail failed, $skipped skipped\n";
exit($fail > 0 ? 1 : 0);
