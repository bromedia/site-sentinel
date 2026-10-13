<?php
declare(strict_types=1);

namespace Sentinel;

final class Lock
{
    private $fh;

    private function __construct($fh)
    {
        $this->fh = $fh;
    }

    /** @throws \RuntimeException when the lock file cannot be opened; null means another run holds the lock */
    public static function acquire(string $file): ?Lock
    {
        $fh = @fopen($file, 'c');
        if ($fh === false) {
            // Not "someone else holds it": the lock cannot work at all, and monitoring must not silently stop.
            throw new \RuntimeException('cannot open the lock file ' . $file);
        }
        if (!flock($fh, LOCK_EX | LOCK_NB)) {
            fclose($fh);
            return null;
        }
        return new Lock($fh);
    }

    public function release(): void
    {
        if ($this->fh !== null) {
            flock($this->fh, LOCK_UN);
            fclose($this->fh);
            $this->fh = null;
        }
    }

    public function __destruct()
    {
        $this->release();
    }
}
