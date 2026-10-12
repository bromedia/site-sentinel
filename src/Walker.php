<?php
declare(strict_types=1);

namespace Sentinel;

final class Walker
{
    private $config;
    private $filter;
    /** @var string[] */
    private $unreadable = [];

    public function __construct(Config $config)
    {
        $this->config = $config;
        $this->filter = new PathFilter($config->exclusions());
    }

    /** @return string[] */
    public function unreadable(): array
    {
        return $this->unreadable;
    }

    /** @return \Generator<int, array> */
    public function walk(string $startAfter = ''): \Generator
    {
        foreach ($this->config->watch as $w) {
            yield from $this->visit($w === '.' ? '' : $w, $startAfter);
        }
    }

    private function visit(string $rel, string $startAfter): \Generator
    {
        if ($rel !== '' && $this->filter->matches($rel)) {
            return;
        }
        $abs = $this->config->abs($rel);
        $st = @lstat($abs);
        if ($st === false) {
            return;
        }
        $isDir = ($st['mode'] & 0170000) === 0040000;
        if (!$isDir) {
            if ($rel !== '' && PathOrder::compare($rel, $startAfter) > 0) {
                yield ['path' => $rel, 'size' => (int)$st['size'], 'mtime' => (int)$st['mtime'], 'mode' => (int)$st['mode'], 'hash' => ''];
            }
            return;
        }
        // Everything below this directory sorts before $startAfter: skip it whole.
        if ($startAfter !== '' && $rel !== '' && PathOrder::compare($rel, $startAfter) < 0 && strpos($startAfter, $rel . '/') !== 0) {
            return;
        }
        $names = @scandir($abs, SCANDIR_SORT_NONE);
        if ($names === false) {
            $this->unreadable[] = $rel === '' ? '.' : $rel;
            return;
        }
        $names = array_values(array_filter($names, function ($n) {
            return $n !== '.' && $n !== '..';
        }));
        sort($names, SORT_STRING);
        foreach ($names as $n) {
            yield from $this->visit($rel === '' ? (string)$n : $rel . '/' . $n, $startAfter);
        }
    }
}
