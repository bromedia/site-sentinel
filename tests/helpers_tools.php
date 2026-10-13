<?php
declare(strict_types=1);

/** Writes an executable /bin/sh script named $name into $dir and returns its path. */
function fakeTool(string $dir, string $name, string $script): string
{
    $p = $dir . '/' . $name;
    file_put_contents($p, "#!/bin/sh\n" . $script);
    chmod($p, 0755);
    return $p;
}
