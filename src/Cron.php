<?php
declare(strict_types=1);

namespace Sentinel;

final class Cron
{
    /** Commands are printed only; Sentinel never edits the user's crontab. */
    public static function lines(string $script, string $configFile): array
    {
        $command = self::arg(PHP_BINARY) . ' ' . self::arg($script);
        $config = ' --config=' . self::arg($configFile);
        return [
            '*/10 * * * * ' . $command . ' check' . $config . ' >/dev/null',
            '17 3 * * * ' . $command . ' full' . $config . ' >/dev/null',
            '# optional, once a rules_url is configured:',
            '# 41 4 * * 1 ' . $command . ' update-rules' . $config . ' >/dev/null',
        ];
    }

    private static function arg(string $value): string
    {
        if (strpos($value, "\n") !== false || strpos($value, "\r") !== false || strpos($value, "\0") !== false) {
            throw new \InvalidArgumentException('cron paths must not contain newlines or NUL bytes');
        }
        // cron interprets percent signs even inside shell quotes.
        return str_replace('%', '\\%', escapeshellarg($value));
    }
}
