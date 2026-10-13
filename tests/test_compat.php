<?php
declare(strict_types=1);

require_once __DIR__ . '/../build/compat.php';

t('compat flags PHP 8-only syntax', function () {
    $bad = "<?php\n\$x = match(1) { 1 => 2 };\nif (str_contains('a', 'b')) {}\n"
        . "class A { function __construct(private int \$x) {} }\n"
        . "function f(int|string \$v): mixed {}\ntry {} catch (Exception) {}\n\$a?->b;\n";
    $v = compat_violations($bad, 'x');
    assertTrue(count($v) >= 6, "only found:\n" . implode("\n", $v));
});

t('compat accepts PHP 7.4 code', function () {
    $ok = "<?php\n\$f = fn(\$a) => \$a + 1;\nclass A { public int \$x = 1; public function __construct(int \$x) { \$this->x = \$x; } }\n"
        . "\$s = 'str_contains(match) is only a string';\n";
    assertSame([], compat_violations($ok, 'x'));
});

t('src, build and bin are PHP 7.4 clean', function () {
    $all = [];
    $files = array_merge(glob(__DIR__ . '/../src/*.php') ?: [], glob(__DIR__ . '/../build/*.php') ?: [], glob(__DIR__ . '/../bin/*.php') ?: []);
    foreach ($files as $f) {
        $all = array_merge($all, compat_violations((string)file_get_contents($f), basename($f)));
    }
    assertSame([], $all, implode("\n", $all));
});
