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

    /**
     * Writes a new baseline from $records. The file is replaced only once every
     * record has been written and the temp file closed cleanly; on any failure the
     * previous baseline is left untouched and an exception is thrown.
     */
    public static function write(string $file, iterable $records): int
    {
        $tmp = $file . '.tmp';
        $fh = self::openTemp($tmp);
        $n = 0;
        try {
            foreach ($records as $r) {
                self::put($fh, self::formatLine($r), $tmp);
                $n++;
            }
        } catch (\Throwable $e) {
            self::abandon($fh, $tmp);
            throw $e;
        }
        self::install($fh, $tmp, $file);
        return $n;
    }

    /**
     * Merges $updates into $oldFile and installs the result as $newFile, with the
     * same all-or-nothing guarantee as write().
     *
     * @param array<int|string, ?array> $updates path => record, or null to delete
     */
    public static function applyUpdates(string $oldFile, array $updates, string $newFile): void
    {
        $keys = array_map('strval', array_keys($updates));
        usort($keys, [PathOrder::class, 'compare']);
        $n = count($keys);
        $i = 0;
        $tmp = $newFile . '.tmp';
        $fh = self::openTemp($tmp);
        try {
            foreach (self::read($oldFile) as $rec) {
                while ($i < $n && PathOrder::compare($keys[$i], $rec['path']) < 0) {
                    if ($updates[$keys[$i]] !== null) {
                        self::put($fh, self::formatLine($updates[$keys[$i]]), $tmp);
                    }
                    $i++;
                }
                if ($i < $n && $keys[$i] === $rec['path']) {
                    if ($updates[$keys[$i]] !== null) {
                        self::put($fh, self::formatLine($updates[$keys[$i]]), $tmp);
                    }
                    $i++;
                    continue;
                }
                self::put($fh, self::formatLine($rec), $tmp);
            }
            for (; $i < $n; $i++) {
                if ($updates[$keys[$i]] !== null) {
                    self::put($fh, self::formatLine($updates[$keys[$i]]), $tmp);
                }
            }
        } catch (\Throwable $e) {
            self::abandon($fh, $tmp);
            throw $e;
        }
        self::install($fh, $tmp, $newFile);
    }

    /** @return resource */
    private static function openTemp(string $tmp)
    {
        $fh = @fopen($tmp, 'wb');
        if ($fh === false) {
            throw new \RuntimeException("cannot write $tmp");
        }
        @chmod($tmp, 0600);
        return $fh;
    }

    /**
     * Writes all of $data or throws. fwrite() can write part of a buffer and
     * report it (a full disk or quota typically shows up this way), then fail.
     *
     * @param resource $fh
     */
    private static function put($fh, string $data, string $tmp): void
    {
        $len = strlen($data);
        $done = 0;
        while ($done < $len) {
            $w = @fwrite($fh, $done === 0 ? $data : substr($data, $done));
            if ($w === false || $w === 0) {
                throw new \RuntimeException("cannot write $tmp (disk full or over quota?)");
            }
            $done += $w;
        }
    }

    /** @param resource $fh */
    private static function abandon($fh, string $tmp): void
    {
        @fclose($fh);
        @unlink($tmp);
    }

    /** @param resource $fh */
    private static function install($fh, string $tmp, string $file): void
    {
        $flushed = @fflush($fh);
        $closed = @fclose($fh);
        if (!$flushed || !$closed) {
            @unlink($tmp);
            throw new \RuntimeException("cannot finish writing $tmp (disk full or over quota?)");
        }
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            throw new \RuntimeException("cannot replace $file");
        }
    }
}
