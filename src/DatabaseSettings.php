<?php
declare(strict_types=1);
namespace Sentinel;
final class DatabaseSettings
{
    public static function normalize($raw): array
    {
        if (!is_array($raw)) {
            throw new ConfigException('database must be an object');
        }
        $out = ['enabled' => (bool)($raw['enabled'] ?? false), 'wp_config' => (string)($raw['wp_config'] ?? ''), 'credentials_file' => (string)($raw['credentials_file'] ?? '')];
        foreach (['wp_config', 'credentials_file'] as $key) {
            if ($out[$key] !== '' && $out[$key][0] !== '/') {
                throw new ConfigException('database.' . $key . ' must be an absolute path');
            }
        }
        foreach (['batch_size' => [20,100], 'max_post_bytes' => [262144,1048576], 'new_post_threshold' => [20,1000000], 'query_timeout_seconds' => [3,30], 'max_admins' => [1000,10000]] as $key => $limits) {
            $v = (int)($raw[$key] ?? $limits[0]);
            if ($v < 1 || $v > $limits[1]) {
                throw new ConfigException('database.' . $key . ' is outside its supported range');
            }
            $out[$key] = $v;
        }
        if ($out['batch_size'] * $out['max_post_bytes'] > 8388608) {
            throw new ConfigException('database batch_size * max_post_bytes must not exceed 8MB');
        }
        $out['post_types'] = array_values((array)($raw['post_types'] ?? ['post','page']));
        if (!$out['post_types'] || count($out['post_types']) > 20) {
            throw new ConfigException('database.post_types needs 1-20 post types');
        }
        foreach ($out['post_types'] as $v) {
            if (!is_string($v) || !preg_match('/^[a-zA-Z0-9_-]{1,32}$/', $v)) {
                throw new ConfigException('invalid database post type');
            }
        }
        return $out;
    }
}
