<?php
declare(strict_types=1);

define('Sentinel\VERSION', trim((string)file_get_contents(__DIR__ . '/../VERSION')));

foreach (require __DIR__ . '/../build/files.php' as $f) {
    require_once __DIR__ . '/../src/' . $f;
}
