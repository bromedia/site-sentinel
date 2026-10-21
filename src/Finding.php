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
    /** For a finding about a plugin, theme or folder: how many changed files it stands for (0 = not such a finding). */
    public $files = 0;

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

    /**
     * Text as it may be shown in an alert or output line: control characters and Unicode
     * direction overrides are written as %XX, so a file name cannot add lines to an alert
     * ("...please ignore this email") or disguise its own extension.
     */
    public static function shown(string $text): string
    {
        return (string)preg_replace_callback('/[\x00-\x09\x0B-\x1F\x7F]|\xE2\x80[\xAA-\xAE]|\xE2\x81[\xA6-\xA9]/', function ($m) {
            return strtoupper(implode('', array_map(function ($b) {
                return '%' . bin2hex($b);
            }, str_split($m[0]))));
        }, $text);
    }

    /** One line of output: like shown(), and a newline is escaped too. */
    public static function line(string $text): string
    {
        return str_replace("\n", '%0A', self::shown($text));
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
