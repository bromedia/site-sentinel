<?php
declare(strict_types=1);

namespace Sentinel;

final class Baseline
{
    public static function encodePath(string $p): string
    {
        return strtr($p, ['%' => '%25', "\t" => '%09', "\n" => '%0A', "\r" => '%0D']);
    }

    public static function decodePath(string $s): string
    {
        return strtr($s, ['%09' => "\t", '%0A' => "\n", '%0D' => "\r", '%25' => '%']);
    }

    public static function formatLine(array $r): string
    {
        return self::encodePath($r['path']) . "\t" . $r['size'] . "\t" . $r['mtime'] . "\t" . decoct($r['mode']) . "\t" . $r['hash'] . "\n";
    }

    public static function parseLine(string $line): ?array
    {
        $f = explode("\t", rtrim($line, "\r\n"), 5);
        if (count($f) !== 5 || $f[0] === '' || !ctype_digit($f[1]) || !ctype_digit($f[2]) || !ctype_digit($f[3])) {
            return null;
        }
        if ($f[4] !== '' && !ctype_xdigit($f[4])) {
            return null;
        }
        return ['path' => self::decodePath($f[0]), 'size' => (int)$f[1], 'mtime' => (int)$f[2], 'mode' => (int)octdec($f[3]), 'hash' => $f[4]];
    }

    /** @return \Generator<int, array> */
    public static function read(string $file): \Generator
    {
        if (!is_file($file)) {
            return;
        }
        $fh = @fopen($file, 'rb');
        if ($fh === false) {
            throw new \RuntimeException("cannot open baseline $file");
        }
        try {
            $n = 0;
            while (($line = fgets($fh)) !== false) {
                $n++;
                $rec = self::parseLine($line);
                if ($rec === null) {
                    throw new \RuntimeException("corrupt baseline line $n");
                }
                yield $rec;
            }
        } finally {
            fclose($fh);
        }
    }

    public static function write(string $file, iterable $records): int
    {
        $tmp = $file . '.tmp';
        $fh = @fopen($tmp, 'wb');
        if ($fh === false) {
            throw new \RuntimeException("cannot write $tmp");
        }
        @chmod($tmp, 0600);
        $n = 0;
        try {
            foreach ($records as $r) {
                fwrite($fh, self::formatLine($r));
                $n++;
            }
        } catch (\Throwable $e) {
            fclose($fh);
            @unlink($tmp);
            throw $e;
        }
        fclose($fh);
        if (!rename($tmp, $file)) {
            @unlink($tmp);
            throw new \RuntimeException("cannot replace $file");
        }
        return $n;
    }

    /** @param array<int|string, ?array> $updates path => record, or null to delete */
    public static function applyUpdates(string $oldFile, array $updates, string $newFile): void
    {
        $keys = array_map('strval', array_keys($updates));
        usort($keys, [PathOrder::class, 'compare']);
        $n = count($keys);
        $i = 0;
        $tmp = $newFile . '.tmp';
        $fh = @fopen($tmp, 'wb');
        if ($fh === false) {
            throw new \RuntimeException("cannot write $tmp");
        }
        @chmod($tmp, 0600);
        try {
            foreach (self::read($oldFile) as $rec) {
                while ($i < $n && PathOrder::compare($keys[$i], $rec['path']) < 0) {
                    if ($updates[$keys[$i]] !== null) {
                        fwrite($fh, self::formatLine($updates[$keys[$i]]));
                    }
                    $i++;
                }
                if ($i < $n && $keys[$i] === $rec['path']) {
                    if ($updates[$keys[$i]] !== null) {
                        fwrite($fh, self::formatLine($updates[$keys[$i]]));
                    }
                    $i++;
                    continue;
                }
                fwrite($fh, self::formatLine($rec));
            }
            for (; $i < $n; $i++) {
                if ($updates[$keys[$i]] !== null) {
                    fwrite($fh, self::formatLine($updates[$keys[$i]]));
                }
            }
        } catch (\Throwable $e) {
            fclose($fh);
            @unlink($tmp);
            throw $e;
        }
        fclose($fh);
        if (!rename($tmp, $newFile)) {
            @unlink($tmp);
            throw new \RuntimeException("cannot replace $newFile");
        }
    }
}
