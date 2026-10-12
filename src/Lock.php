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

    public static function acquire(string $file): ?Lock
    {
        $fh = @fopen($file, 'c');
        if ($fh === false) {
            return null;
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
