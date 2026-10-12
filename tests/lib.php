<?php
declare(strict_types=1);

final class SkipTest extends Exception
{
}

$GLOBALS['__tests'] = [];
$GLOBALS['__tmp'] = [];

function t(string $name, callable $fn): void
{
    $GLOBALS['__tests'][] = [$name, $fn];
}

function skip(string $why): void
{
    throw new SkipTest($why);
}

function assertTrue($cond, string $msg = 'expected true'): void
{
    if ($cond !== true) {
        throw new RuntimeException($msg);
    }
}

function assertSame($expected, $actual, string $msg = ''): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(($msg !== '' ? $msg . ': ' : '') . 'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}

function assertContains(string $needle, string $haystack, string $msg = ''): void
{
    if (strpos($haystack, $needle) === false) {
        throw new RuntimeException(($msg !== '' ? $msg . ': ' : '') . 'expected to find ' . var_export($needle, true) . ' in ' . var_export($haystack, true));
    }
}

function assertNotContains(string $needle, string $haystack, string $msg = ''): void
{
    if (strpos($haystack, $needle) !== false) {
        throw new RuntimeException(($msg !== '' ? $msg . ': ' : '') . 'did not expect ' . var_export($needle, true) . ' in ' . var_export($haystack, true));
    }
}

function assertThrows(string $class, callable $fn): void
{
    try {
        $fn();
    } catch (Throwable $e) {
        if (!($e instanceof $class)) {
            throw new RuntimeException("expected $class, got " . get_class($e) . ': ' . $e->getMessage());
        }
        return;
    }
    throw new RuntimeException("expected $class to be thrown");
}

function tmpdir(): string
{
    $d = sys_get_temp_dir() . '/sentinel-test-' . bin2hex(random_bytes(6));
    mkdir($d, 0700, true);
    $GLOBALS['__tmp'][] = $d;
    return $d;
}

function rmrf(string $p): void
{
    if (is_link($p) || is_file($p)) {
        @unlink($p);
        return;
    }
    if (!is_dir($p)) {
        return;
    }
    foreach (scandir($p) as $n) {
        if ($n !== '.' && $n !== '..') {
            rmrf($p . '/' . $n);
        }
    }
    @rmdir($p);
}

function putFile(string $root, string $rel, string $content, ?int $mtime = null): string
{
    $abs = $root . '/' . $rel;
    if (!is_dir(dirname($abs))) {
        mkdir(dirname($abs), 0755, true);
    }
    file_put_contents($abs, $content);
    if ($mtime !== null) {
        touch($abs, $mtime);
    }
    return $abs;
}
