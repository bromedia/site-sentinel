<?php
declare(strict_types=1);

namespace Sentinel;

final class Finding
{
    public const INFO = 1;
    public const WARNING = 2;
    public const CRITICAL = 3;

    public $severity;
    public $path;
    public $rule;
    public $message;
    public $hash;

    public function __construct(int $severity, string $path, string $rule, string $message, string $hash = '')
    {
        $this->severity = $severity;
        $this->path = $path;
        $this->rule = $rule;
        $this->message = $message;
        $this->hash = $hash;
    }

    /** Identity used for alert dedupe: the same rule on the same file content alerts once. */
    public function key(): string
    {
        return sha1($this->rule . "\0" . $this->path . "\0" . $this->hash);
    }

    /** Short form of key() shown to the owner, for example to dismiss a reviewed false positive. */
    public function id(): string
    {
        return substr($this->key(), 0, 12);
    }

    public static function label(int $severity): string
    {
        if ($severity >= self::CRITICAL) {
            return 'CRITICAL';
        }
        return $severity === self::WARNING ? 'WARNING' : 'INFO';
    }

    public static function parseSeverity(string $s): int
    {
        switch (strtolower(trim($s))) {
            case 'critical':
                return self::CRITICAL;
            case 'info':
                return self::INFO;
        }
        return self::WARNING;
    }
}
