<?php
declare(strict_types=1);

/** Builds a generic-profile Config for $root with a throw-away state dir and a file alert channel. */
function makeConfig(string $root, array $extra = []): \Sentinel\Config
{
    $state = tmpdir();
    return \Sentinel\Config::fromArray(array_merge([
        'site_name' => 'test',
        'site_root' => $root,
        'state_dir' => $state,
        'profile' => 'generic',
        'update_grace_seconds' => 0, // tests opt in to the grace period explicitly
        'channels' => [['type' => 'file', 'path' => $state . '/alerts.log']],
    ], $extra));
}
