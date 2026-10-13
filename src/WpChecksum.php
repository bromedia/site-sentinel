<?php
declare(strict_types=1);

namespace Sentinel;

final class WpChecksum
{
    public const VERIFIED = 'match';
    public const MISMATCH = 'mismatch';
    public const EXTRA = 'extra';
    public const UNKNOWN = 'unknown';

    private $http;
    private $config;
    private $cacheDir;
    /** @var array<string,string> */
    private $notes = [];
    private $coreLoaded = false;
    /** @var array<string,string>|null */
    private $core = null;
    /** @var array<string,?array> */
    private $plugins = [];

    public function __construct(HttpClient $http, Config $config, string $cacheDir)
    {
        $this->http = $http;
        $this->config = $config;
        $this->cacheDir = rtrim($cacheDir, '/');
    }

    /** @return string[] */
    public function notes(): array
    {
        return array_values($this->notes);
    }

    public function isCorePath(string $rel): bool
    {
        $core = $this->coreMap();
        if ($core !== null) {
            return isset($core[$rel]);
        }
        return strpos($rel, 'wp-admin/') === 0 || strpos($rel, 'wp-includes/') === 0;
    }

    public function verify(string $rel): string
    {
        $abs = $this->config->abs($rel);
        $core = $this->coreMap();
        if ($core !== null && isset($core[$rel])) {
            $md5 = @md5_file($abs);
            if ($md5 === false) {
                return self::UNKNOWN;
            }
            return $md5 === $core[$rel] ? self::VERIFIED : self::MISMATCH;
        }
        if (strpos($rel, 'wp-content/plugins/') === 0) {
            return $this->verifyPlugin($rel, $abs);
        }
        if ($core !== null && (strpos($rel, 'wp-admin/') === 0 || strpos($rel, 'wp-includes/') === 0)) {
            return self::EXTRA;
        }
        return self::UNKNOWN;
    }

    private function verifyPlugin(string $rel, string $abs): string
    {
        if (!preg_match('#^wp-content/plugins/([^/]+)/(.+)$#', $rel, $m)) {
            return self::UNKNOWN;
        }
        $slug = $m[1];
        $file = $m[2];
        if (!preg_match('/^[A-Za-z0-9._-]+$/', $slug)) {
            return self::UNKNOWN;
        }
        $version = VersionTracker::dirVersion($this->config, 'wp-content/plugins/' . $slug);
        if ($version === null || !preg_match('/^[A-Za-z0-9._+-]+$/', $version)) {
            return self::UNKNOWN;
        }
        $map = $this->pluginMap($slug, $version);
        if ($map === null) {
            return self::UNKNOWN;
        }
        if (!isset($map[$file])) {
            return self::EXTRA;
        }
        foreach (['sha256', 'md5'] as $algo) {
            if (isset($map[$file][$algo])) {
                $h = @hash_file($algo, $abs);
                if ($h === false) {
                    return self::UNKNOWN;
                }
                return in_array($h, $map[$file][$algo], true) ? self::VERIFIED : self::MISMATCH;
            }
        }
        return self::UNKNOWN;
    }

    /** @return array<string,string>|null */
    private function coreMap(): ?array
    {
        if ($this->coreLoaded) {
            return $this->core;
        }
        $this->coreLoaded = true;
        $info = $this->wpVersion();
        if ($info === null) {
            $this->note('WordPress version could not be read; core checksum verification skipped');
            return null;
        }
        [$ver, $locale] = $info;
        $cache = $this->cacheFile('wp-core-' . $ver . '-' . $locale . '.json');
        $map = $this->readCache($cache);
        if ($map === null) {
            $r = $this->http->request('GET', 'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode($ver) . '&locale=' . rawurlencode($locale));
            if ($r['status'] !== 200) {
                $this->note('WordPress core checksums unavailable (' . $this->why($r['status']) . '); core verification skipped');
                return null;
            }
            $j = json_decode($r['body'], true);
            if (!is_array($j) || !isset($j['checksums']) || !is_array($j['checksums'])) {
                $this->note("No official checksums published for WordPress $ver ($locale); core verification skipped");
                return null;
            }
            $map = [];
            foreach ($j['checksums'] as $f => $h) {
                if (is_string($h)) {
                    $map[(string)$f] = strtolower($h);
                }
            }
            $this->writeCache($cache, $map);
        }
        $this->core = $map;
        return $map;
    }

    /** @return array<string,array<string,string[]>>|null file => algo => accepted hashes */
    private function pluginMap(string $slug, string $version): ?array
    {
        $key = $slug . '@' . $version;
        if (array_key_exists($key, $this->plugins)) {
            return $this->plugins[$key];
        }
        $this->plugins[$key] = null;
        $cache = $this->cacheFile('wp-plugin-' . $slug . '-' . $version . '.json');
        $map = $this->readCache($cache);
        if ($map === null) {
            $r = $this->http->request('GET', 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode($slug) . '/' . rawurlencode($version) . '.json');
            if ($r['status'] === 404) {
                return null; // not in the repository: premium or custom plugin
            }
            if ($r['status'] !== 200) {
                $this->note("Checksums for plugin '$slug' unavailable (" . $this->why($r['status']) . '); verification skipped');
                return null;
            }
            $j = json_decode($r['body'], true);
            $map = [];
            if (is_array($j) && isset($j['files']) && is_array($j['files'])) {
                foreach ($j['files'] as $file => $hashes) {
                    if (!is_array($hashes)) {
                        continue;
                    }
                    foreach (['sha256', 'md5'] as $algo) {
                        if (isset($hashes[$algo])) {
                            $map[(string)$file][$algo] = array_values(array_map('strtolower', array_map('strval', (array)$hashes[$algo])));
                        }
                    }
                }
            }
            if (!$map) {
                $this->note("Checksum data for plugin '$slug' had an unexpected format; verification skipped");
                return null;
            }
            $this->writeCache($cache, $map);
        }
        $this->plugins[$key] = $map;
        return $map;
    }

    /** @return array{0:string,1:string}|null */
    private function wpVersion(): ?array
    {
        $src = @file_get_contents($this->config->abs('wp-includes/version.php'));
        if ($src === false || !preg_match('/\$wp_version\s*=\s*\'([^\']+)\'/', $src, $m) || !preg_match('/^[A-Za-z0-9.\-]+$/', $m[1])) {
            return null;
        }
        $locale = 'en_US';
        if (preg_match('/\$wp_local_package\s*=\s*\'([A-Za-z_]+)\'/', $src, $l)) {
            $locale = $l[1];
        }
        return [$m[1], $locale];
    }

    private function why(int $status): string
    {
        return $status === 0 ? 'network error' : 'HTTP ' . $status;
    }

    private function note(string $msg): void
    {
        $this->notes[$msg] = $msg;
    }

    private function cacheFile(string $name): string
    {
        return $this->cacheDir . '/' . preg_replace('/[^A-Za-z0-9._@-]/', '_', $name);
    }

    private function readCache(string $file): ?array
    {
        $j = is_file($file) ? json_decode((string)file_get_contents($file), true) : null;
        return is_array($j) && $j ? $j : null;
    }

    private function writeCache(string $file, array $map): void
    {
        if (!is_dir($this->cacheDir)) {
            @mkdir($this->cacheDir, 0700, true);
        }
        @file_put_contents($file, json_encode($map), LOCK_EX);
    }
}
