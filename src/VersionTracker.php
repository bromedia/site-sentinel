<?php
declare(strict_types=1);

namespace Sentinel;

final class VersionTracker
{
    /**
     * Plugin and theme versions of every WordPress install; keys of an install in a subfolder start
     * with its folder (books/wp-content/plugins/x), so those of the website folder are unchanged.
     *
     * @return array<string,string> group directory => version
     */
    public static function read(Config $c): array
    {
        $out = [];
        foreach ($c->wordpressInstalls() as $prefix) {
            $out += self::readInstall($c, $prefix);
        }
        return $out;
    }

    /** @return array<string,string> */
    private static function readInstall(Config $c, string $prefix): array
    {
        $out = [];
        foreach ([Config::inInstall($prefix, 'wp-content/plugins'), Config::inInstall($prefix, 'wp-content/themes')] as $dir) {
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
        return $f !== null ? self::header($c->abs($f), !self::isTheme($relDir)) : null;
    }

    /** The file whose header gives a plugin's or theme's version (relative path), if any. */
    public static function versionFile(Config $c, string $relDir): ?string
    {
        $abs = $c->abs($relDir);
        if (!is_dir($abs)) {
            return null;
        }
        if (self::isTheme($relDir)) {
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

    private static function isTheme(string $relDir): bool
    {
        return (bool)preg_match('#(?:^|/)wp-content/themes/[^/]+$#', $relDir);
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
