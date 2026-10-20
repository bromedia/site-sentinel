<?php

declare(strict_types=1);

namespace Sentinel;

final class DatabaseException extends \RuntimeException
{
}
final class DatabaseCredentials
{
    public static function load(Config $c): array
    {
        $file = $c->database['credentials_file'];
        if ($file !== '') {
            $raw = json_decode(self::read($file), true);
            if (!is_array($raw)) {
                throw new DatabaseException('database credentials file must contain a JSON object');
            }
        } else {
            $file = $c->database['wp_config'];
            if ($file === '') {
                $file = is_file($c->abs('wp-config.php')) ? $c->abs('wp-config.php') : dirname($c->siteRoot) . '/wp-config.php';
            }
            $raw = self::parseWordPress(self::read($file));
        }
        foreach (['host','user','password','name','table_prefix'] as $key) {
            if (!isset($raw[$key]) || !is_string($raw[$key])) {
                throw new DatabaseException('database credentials require literal host, user, password, name and table_prefix; use credentials_file for environment-based configs');
            }
        }
        if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $raw['table_prefix'])) {
            throw new DatabaseException('invalid database table prefix');
        }
        $raw['port'] = (int)($raw['port'] ?? 3306);
        $raw['socket'] = (string)($raw['socket'] ?? '');
        if (preg_match('/^\[([^]]+)\](?::(\d+))?$/', $raw['host'], $m)) {
            $raw['host'] = $m[1];
            $raw['port'] = isset($m[2]) ? (int)$m[2] : $raw['port'];
        } elseif (preg_match('/^([^:]+):(\d+)$/', $raw['host'], $m)) {
            $raw['host'] = $m[1];
            $raw['port'] = (int)$m[2];
        } elseif (preg_match('#^([^:]+):(/.+)$#', $raw['host'], $m)) {
            $raw['host'] = $m[1];
            $raw['socket'] = $m[2];
        }
        if ($raw['port'] < 1 || $raw['port'] > 65535) {
            throw new DatabaseException('invalid database port');
        }
        return $raw;
    }
    private static function read(string $file): string
    {
        if (!is_readable($file) || filesize($file) > 1048576) {
            throw new DatabaseException('database credential source is unreadable or larger than 1MB');
        }
        $text = file_get_contents($file);
        if ($text === false) {
            throw new DatabaseException('cannot read database credential source');
        }
        return $text;
    }
    /** Tokenise literal strings only. Never execute the WordPress configuration. */
    public static function parseWordPress(string $text): array
    {
        $tokens = array_values(array_filter(token_get_all($text), function ($t) {
            return !is_array($t) || !in_array($t[0], [T_WHITESPACE,T_COMMENT,T_DOC_COMMENT,T_INLINE_HTML], true);
        }));
        $raw = [];
        $map = ['DB_HOST' => 'host','DB_USER' => 'user','DB_PASSWORD' => 'password','DB_NAME' => 'name'];
        for ($i = 0,$n = count($tokens); $i < $n; $i++) {
            $t = $tokens[$i];
            if (is_array($t) && $t[0] === T_STRING && strtolower($t[1]) === 'define' && ($tokens[$i + 1] ?? null) === '(' && ($tokens[$i + 3] ?? null) === ',' && ($tokens[$i + 5] ?? null) === ')') {
                $key = self::literal($tokens[$i + 2] ?? null);
                $v = self::literal($tokens[$i + 4] ?? null);
                if (isset($map[$key ?? '']) && $v !== null) {
                    if (isset($raw[$map[$key]])) {
                        throw new DatabaseException('ambiguous WordPress database constants; use credentials_file');
                    }
                    $raw[$map[$key]] = $v;
                }
            }
            if (is_array($t) && $t[0] === T_VARIABLE && $t[1] === '$table_prefix' && ($tokens[$i + 1] ?? null) === '=' && ($tokens[$i + 3] ?? null) === ';') {
                $v = self::literal($tokens[$i + 2] ?? null);
                if ($v !== null) {
                    if (isset($raw['table_prefix'])) {
                        throw new DatabaseException('ambiguous table prefix; use credentials_file');
                    }
                    $raw['table_prefix'] = $v;
                }
            }
        }
        return $raw;
    }
    private static function literal($t): ?string
    {
        if (!is_array($t) || $t[0] !== T_CONSTANT_ENCAPSED_STRING) {
            return null;
        }
        $s = substr($t[1], 1, -1);
        if ($t[1][0] === "'") {
            return strtr($s, ["\\\\" => "\\","\\'" => "'"]);
        }
        return preg_replace_callback('/\\\\(?:[0-7]{1,3}|x[0-9a-fA-F]{1,2}|.)/s', function ($m) {
            $e = substr($m[0], 1);
            $map = ['n' => "\n",'r' => "\r",'t' => "\t",'v' => "\v",'e' => chr(27),'f' => "\f",'\\' => '\\','$' => '$','"' => '"'];
            if (isset($map[$e])) {
                return $map[$e];
            }
            if (preg_match('/^[0-7]{1,3}$/', $e)) {
                return chr(octdec($e) & 255);
            }
            if (preg_match('/^x[0-9a-fA-F]{1,2}$/', $e)) {
                return chr(hexdec(substr($e, 1)));
            }
            return $m[0];
        }, $s);
    }
}
