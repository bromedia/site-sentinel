<?php
declare(strict_types=1);

namespace Sentinel;

final class LocationScanner
{
    private const MEDIA_EXT = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'ico', 'bmp'];

    private $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /** @return Finding[] */
    public function scan(string $rel, array $record, bool $isNew): array
    {
        if (($record['mode'] & 0170000) === 0120000) {
            return [];
        }
        $out = [];
        $hash = (string)$record['hash'];
        $base = strtolower(basename($rel));
        $parts = explode('.', $base);
        array_shift($parts);
        $ext = $parts ? end($parts) : '';
        $isMedia = in_array($ext, self::MEDIA_EXT, true);

        if ($this->config->isUploads($rel)) {
            if (array_intersect($parts, Config::PHP_EXT)) {
                $out[] = new Finding(Finding::CRITICAL, $rel, 'php-in-uploads', 'PHP file in the uploads directory', $hash);
            } elseif ($isMedia && $this->hasPhpTag($this->config->abs($rel))) {
                $out[] = new Finding(Finding::CRITICAL, $rel, 'php-in-media', 'Media file containing PHP code', $hash);
            }
            if ($isNew && ($base === '.htaccess' || $base === '.user.ini')) {
                $out[] = new Finding(Finding::WARNING, $rel, 'config-in-uploads', 'Server configuration file in the uploads directory', $hash);
            }
        }

        if (!$this->config->isUploads($rel) && array_intersect(array_slice($parts, 0, -1), Config::PHP_EXT) && !in_array($ext, Config::PHP_EXT, true)) {
            $out[] = new Finding(Finding::WARNING, $rel, 'double-extension', 'PHP extension hidden before another extension (e.g. shell.php.jpg)', $hash);
        }

        if ($isNew && !$isMedia && ($record['mode'] & 0111) !== 0 && $this->inTemp($rel)) {
            $out[] = new Finding(Finding::CRITICAL, $rel, 'exec-in-temp', 'New executable file in a temp directory', $hash);
        }
        return $out;
    }

    private function inTemp(string $rel): bool
    {
        if ($this->config->tempRoot) {
            return true;
        }
        foreach (explode('/', dirname($rel)) as $seg) {
            if ($seg === 'tmp' || $seg === 'temp') {
                return true;
            }
        }
        return false;
    }

    private function hasPhpTag(string $abs): bool
    {
        $c = PatternScanner::headTail($abs, 131072);
        return $c !== null && (stripos($c, '<?php') !== false || strpos($c, '<?=') !== false);
    }
}
