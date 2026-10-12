<?php
declare(strict_types=1);

namespace Sentinel;

final class ConfigException extends \RuntimeException
{
}

final class Config
{
    public const PROFILES = ['wordpress', 'generic'];
    public const CHANNEL_TYPES = ['email', 'ntfy', 'telegram', 'webhook', 'file'];
    /** Extensions a web server may run as PHP; anywhere in a file name's extension chain they make it code. */
    public const PHP_EXT = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps'];

    public $siteName = '';
    public $profile = 'generic';
    public $siteRoot = '';
    public $stateDir = '';
    public $watch = ['.'];
    public $exclude = [];
    public $codeExtensions = [];
    public $sensitive = [];
    public $uploadsDir = '';
    public $tempRoot = false;
    public $channels = [];
    public $budgetSeconds = 50;
    public $budgetMemoryMb = 128;
    public $maxScanBytes = 2097152;
    public $remindHours = 24;
    public $wpChecksums = true;
    public $heartbeatUrl = '';
    public $rulesUrl = '';
    public $rulesPublicKey = '';
    public $allowUnsignedRules = false;
    public $clamscanPath = '';
    public $yaraPath = '';
    public $yaraRules = '';

    /** @var string[] */
    private $extraExclude = [];

    public static function load(string $file): Config
    {
        $json = @file_get_contents($file);
        if ($json === false) {
            throw new ConfigException("cannot read config file $file");
        }
        $raw = json_decode($json, true);
        if (!is_array($raw)) {
            throw new ConfigException("config file $file is not valid JSON");
        }
        return self::fromArray($raw);
    }

    public static function fromArray(array $raw): Config
    {
        $c = new Config();
        $root = (string)($raw['site_root'] ?? '');
        $real = $root !== '' ? realpath($root) : false;
        if ($real === false || !is_dir($real)) {
            throw new ConfigException('site_root must be an existing directory');
        }
        $c->siteRoot = rtrim($real, '/');
        $c->siteName = trim((string)($raw['site_name'] ?? ''));
        if ($c->siteName === '') {
            throw new ConfigException('site_name is required');
        }
        $c->stateDir = rtrim((string)($raw['state_dir'] ?? ''), '/');
        if ($c->stateDir === '') {
            throw new ConfigException('state_dir is required');
        }
        $profile = (string)($raw['profile'] ?? '');
        if ($profile === '') {
            $profile = Profile::detect($c->siteRoot);
        }
        if (!in_array($profile, self::PROFILES, true)) {
            throw new ConfigException("unknown profile '$profile'");
        }
        $c->profile = $profile;
        $d = Profile::defaults($profile);
        $c->watch = self::normalizeWatch($raw['watch'] ?? ['.']);
        $c->exclude = self::strings($raw['exclude'] ?? $d['exclude']);
        $c->codeExtensions = array_map('strtolower', self::strings($raw['code_extensions'] ?? $d['code_extensions']));
        $c->sensitive = self::strings($raw['sensitive'] ?? $d['sensitive']);
        $c->uploadsDir = trim((string)($raw['uploads_dir'] ?? $d['uploads_dir']), '/');
        $c->tempRoot = (bool)($raw['temp_root'] ?? false);
        $c->channels = self::channels($raw['channels'] ?? []);
        $c->budgetSeconds = self::int($raw, 'budget_seconds', 50);
        $c->budgetMemoryMb = self::int($raw, 'budget_memory_mb', 128);
        $c->maxScanBytes = self::int($raw, 'max_scan_bytes', 2097152);
        $c->remindHours = self::int($raw, 'remind_hours', 24);
        $c->wpChecksums = (bool)($raw['wp_checksums'] ?? true);
        $c->heartbeatUrl = self::url($raw, 'heartbeat_url');
        $c->rulesUrl = self::url($raw, 'rules_url');
        $c->rulesPublicKey = trim((string)($raw['rules_public_key'] ?? ''));
        $c->allowUnsignedRules = (bool)($raw['allow_unsigned_rules'] ?? false);
        $c->clamscanPath = trim((string)($raw['clamscan_path'] ?? ''));
        $c->yaraPath = trim((string)($raw['yara_path'] ?? ''));
        $c->yaraRules = trim((string)($raw['yara_rules'] ?? ''));
        return $c;
    }

    public function toArray(): array
    {
        return [
            'site_name' => $this->siteName,
            'profile' => $this->profile,
            'site_root' => $this->siteRoot === '' ? '/' : $this->siteRoot,
            'state_dir' => $this->stateDir,
            'watch' => $this->watch,
            'exclude' => $this->exclude,
            'code_extensions' => $this->codeExtensions,
            'sensitive' => $this->sensitive,
            'uploads_dir' => $this->uploadsDir,
            'temp_root' => $this->tempRoot,
            'channels' => $this->channels,
            'budget_seconds' => $this->budgetSeconds,
            'budget_memory_mb' => $this->budgetMemoryMb,
            'max_scan_bytes' => $this->maxScanBytes,
            'remind_hours' => $this->remindHours,
            'wp_checksums' => $this->wpChecksums,
            'heartbeat_url' => $this->heartbeatUrl,
            'rules_url' => $this->rulesUrl,
            'rules_public_key' => $this->rulesPublicKey,
            'allow_unsigned_rules' => $this->allowUnsignedRules,
            'clamscan_path' => $this->clamscanPath,
            'yara_path' => $this->yaraPath,
            'yara_rules' => $this->yaraRules,
        ];
    }

    public function abs(string $rel): string
    {
        if ($rel === '') {
            return $this->siteRoot === '' ? '/' : $this->siteRoot;
        }
        return $this->siteRoot . '/' . $rel;
    }

    /** Exclusion patterns: configured ones plus the state dir and added tool files. */
    public function exclusions(): array
    {
        $out = array_merge($this->exclude, $this->extraExclude);
        $rel = $this->relative($this->stateDir);
        if ($rel !== null && $rel !== '') {
            $out[] = '/' . $rel . '/';
        }
        return $out;
    }

    /** Excludes a file or directory (e.g. the script or config) when it lies inside the site root. */
    public function addExclusion(string $absPath): void
    {
        $real = realpath($absPath);
        $rel = $this->relative($real !== false ? $real : $absPath);
        if ($rel !== null && $rel !== '') {
            $this->extraExclude[] = '/' . $rel;
        }
    }

    public function isCodeFile(string $rel): bool
    {
        $base = strtolower(basename($rel));
        if (in_array($base, ['.htaccess', '.user.ini', 'php.ini'], true)) {
            return true;
        }
        $parts = explode('.', $base);
        array_shift($parts);
        foreach ($parts as $p) {
            if (in_array($p, self::PHP_EXT, true)) {
                return true;
            }
        }
        return $parts && in_array(end($parts), $this->codeExtensions, true);
    }

    public function isUploads(string $rel): bool
    {
        return $this->uploadsDir !== '' && ($rel === $this->uploadsDir || strpos($rel, $this->uploadsDir . '/') === 0);
    }

    private function relative(string $abs): ?string
    {
        $abs = rtrim($abs, '/');
        if ($this->siteRoot === '') {
            return ltrim($abs, '/');
        }
        if (strpos($abs, $this->siteRoot . '/') === 0) {
            return substr($abs, strlen($this->siteRoot) + 1);
        }
        return null;
    }

    private static function normalizeWatch($watch): array
    {
        $list = [];
        foreach ((array)$watch as $w) {
            $w = trim(str_replace('\\', '/', (string)$w), '/');
            $w = (string)preg_replace('#^(\./)+#', '', $w);
            if ($w === '' || $w === '.') {
                return ['.'];
            }
            if (preg_match('#(^|/)\.\.(/|$)#', $w)) {
                throw new ConfigException('watch paths must not contain ..');
            }
            $list[] = $w;
        }
        if (!$list) {
            return ['.'];
        }
        usort($list, [PathOrder::class, 'compare']);
        $out = [];
        foreach ($list as $w) {
            foreach ($out as $o) {
                if ($w === $o || strpos($w, $o . '/') === 0) {
                    continue 2;
                }
            }
            $out[] = $w;
        }
        return $out;
    }

    private static function strings($v): array
    {
        return array_values(array_map('strval', (array)$v));
    }

    private static function int(array $raw, string $key, int $default): int
    {
        $v = (int)($raw[$key] ?? $default);
        if ($v < 1) {
            throw new ConfigException("$key must be a positive integer");
        }
        return $v;
    }

    private static function url(array $raw, string $key): string
    {
        $v = trim((string)($raw[$key] ?? ''));
        if ($v !== '' && !preg_match('#^https?://#i', $v)) {
            throw new ConfigException("$key must start with http:// or https://");
        }
        return $v;
    }

    private static function channels($list): array
    {
        if (!is_array($list)) {
            throw new ConfigException('channels must be a list');
        }
        $out = [];
        foreach ($list as $i => $ch) {
            if (!is_array($ch)) {
                throw new ConfigException("channel #$i must be an object");
            }
            $type = (string)($ch['type'] ?? '');
            if (!in_array($type, self::CHANNEL_TYPES, true)) {
                throw new ConfigException("channel #$i: unknown type '$type'");
            }
            $min = strtolower((string)($ch['min_severity'] ?? 'warning'));
            if (!in_array($min, ['info', 'warning', 'critical'], true)) {
                throw new ConfigException("channel #$i: min_severity must be info, warning or critical");
            }
            $n = ['type' => $type, 'min_severity' => $min];
            switch ($type) {
                case 'email':
                    $to = array_values(array_filter(array_map('trim', array_map('strval', (array)($ch['to'] ?? [])))));
                    if (!$to) {
                        throw new ConfigException("channel #$i: email needs 'to'");
                    }
                    foreach ($to as $addr) {
                        if (!preg_match('/^[^\s@]+@[^\s@]+$/', $addr)) {
                            throw new ConfigException("channel #$i: '$addr' is not an email address");
                        }
                    }
                    $n['to'] = $to;
                    $n['from'] = trim((string)($ch['from'] ?? ''));
                    break;
                case 'ntfy':
                case 'webhook':
                    $url = trim((string)($ch['url'] ?? ''));
                    if (!preg_match('#^https?://#i', $url)) {
                        throw new ConfigException("channel #$i: $type needs an http(s) 'url'");
                    }
                    $n['url'] = $url;
                    break;
                case 'telegram':
                    $n['token'] = trim((string)($ch['token'] ?? ''));
                    $n['chat_id'] = trim((string)($ch['chat_id'] ?? ''));
                    if ($n['token'] === '' || $n['chat_id'] === '') {
                        throw new ConfigException("channel #$i: telegram needs 'token' and 'chat_id'");
                    }
                    break;
                case 'file':
                    $n['path'] = trim((string)($ch['path'] ?? ''));
                    if ($n['path'] === '' || $n['path'][0] !== '/') {
                        throw new ConfigException("channel #$i: file needs an absolute 'path'");
                    }
                    break;
            }
            $out[] = $n;
        }
        return $out;
    }
}
