<?php
declare(strict_types=1);

namespace Sentinel;

final class Budget
{
    private $deadline;
    private $memoryBytes;
    private $clock;

    public function __construct(float $seconds, int $memoryBytes, ?callable $clock = null)
    {
        $this->clock = $clock ?? function (): float {
            return microtime(true);
        };
        $this->deadline = ($this->clock)() + $seconds;
        $this->memoryBytes = $memoryBytes;
    }

    public function exceeded(): bool
    {
        return ($this->clock)() >= $this->deadline || memory_get_usage(true) >= $this->memoryBytes;
    }

    public function remaining(): float
    {
        return max(0.0, $this->deadline - ($this->clock)());
    }

    public function slice(float $fraction): Budget
    {
        return new Budget($this->remaining() * $fraction, $this->memoryBytes, $this->clock);
    }

    public function timeout(int $maximum): int
    {
        return max(1, min($maximum, (int)ceil($this->remaining())));
    }

    public static function forConfig(Config $c): Budget
    {
        $limit = self::iniBytes((string)ini_get('memory_limit'));
        $cfg = $c->budgetMemoryMb * 1048576;
        $bytes = $limit > 0 ? min($cfg, (int)($limit * 0.8)) : $cfg;
        return new Budget((float)$c->budgetSeconds, $bytes);
    }

    public static function iniBytes(string $v): int
    {
        $v = trim($v);
        if ($v === '' || $v === '-1') {
            return 0;
        }
        $n = (int)$v;
        switch (strtolower(substr($v, -1))) {
            case 'g':
                return $n * 1073741824;
            case 'm':
                return $n * 1048576;
            case 'k':
                return $n * 1024;
        }
        return $n;
    }
}
