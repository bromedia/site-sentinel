<?php
declare(strict_types=1);

namespace Sentinel;

final class State
{
    private $dir;

    public function __construct(string $dir)
    {
        $this->dir = rtrim($dir, '/');
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            throw new \RuntimeException('cannot create state directory ' . $this->dir);
        }
        @chmod($this->dir, 0700);
    }

    public function dir(): string
    {
        return $this->dir;
    }

    public function path(string $name): string
    {
        return $this->dir . '/' . $name;
    }

    public function readJson(string $name): array
    {
        $f = $this->path($name);
        if (!is_file($f)) {
            return [];
        }
        $d = json_decode((string)file_get_contents($f), true);
        return is_array($d) ? $d : [];
    }

    public function writeJson(string $name, array $data): void
    {
        $f = $this->path($name);
        $tmp = $f . '.tmp';
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false || file_put_contents($tmp, $json) === false) {
            @unlink($tmp);
            throw new \RuntimeException('cannot write ' . $f);
        }
        @chmod($tmp, 0600);
        if (!rename($tmp, $f)) {
            @unlink($tmp);
            throw new \RuntimeException('cannot replace ' . $f);
        }
    }
}
