<?php
declare(strict_types=1);

namespace Sentinel;

final class VersionTracker
{
    /** @return array<string,string> group directory => version */
    public static function read(Config $c): array
    {
        $out = [];
        foreach (['wp-content/plugins', 'wp-content/themes'] as $dir) {
            $names = @scandir($c->abs($dir), SCANDIR_SORT_NONE);
            if ($names === false) {
                continue;
            }
            sort($names, SORT_STRING);
            foreach ($names as $n) {
                if ($n === '' || $n[0] === '.') {
                    continue;
                }
                $v = self::dirVersion($c, $dir . '/' . $n);
                if ($v !== null) {
                    $out[$dir . '/' . $n] = $v;
                }
            }
        }
        return $out;
    }

    public static function dirVersion(Config $c, string $relDir): ?string
    {
        $f = self::versionFile($c, $relDir);
        return $f !== null ? self::header($c->abs($f), strpos($relDir, 'wp-content/themes/') !== 0) : null;
    }

    /** The file whose header gives a plugin's or theme's version (relative path), if any. */
    public static function versionFile(Config $c, string $relDir): ?string
    {
        $abs = $c->abs($relDir);
        if (!is_dir($abs)) {
            return null;
        }
        if (strpos($relDir, 'wp-content/themes/') === 0) {
            return self::header($abs . '/style.css', false) !== null ? $relDir . '/style.css' : null;
        }
        $names = @scandir($abs, SCANDIR_SORT_NONE);
        if ($names === false) {
            return null;
        }
        sort($names, SORT_STRING);
        foreach ($names as $f) {
            if (substr($f, -4) === '.php' && self::header($abs . '/' . $f, true) !== null) {
                return $relDir . '/' . $f;
            }
        }
        return null;
    }

    private static function header(string $file, bool $needPluginName): ?string
    {
        $fh = @fopen($file, 'rb');
        if ($fh === false) {
            return null;
        }
        $head = (string)fread($fh, 8192);
        fclose($fh);
        if ($needPluginName && !preg_match('/^[ \t\/*#@]*Plugin Name:/mi', $head)) {
            return null;
        }
        if (!preg_match('/^[ \t\/*#@]*Version:[ \t]*(.+)$/mi', $head, $m)) {
            return null;
        }
        $v = trim((string)preg_replace('/\s*\*\/.*$/', '', $m[1]));
        return $v === '' ? null : $v;
    }
}
