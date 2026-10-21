<?php
declare(strict_types=1);

namespace Sentinel;

final class ConfigException extends \RuntimeException
{
}

final class Config
{
    /** The site_root the client package ships with, relative to sentinel.json. */
    public const PACKAGE_SITE_ROOT = '../public_html';
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
    /** Changes nothing flags are recorded without an email: everywhere (quiet_changes), or only under quiet_folders. */
    public $quietChanges = false;
    /** @var string[] */
    public $quietFolders = [];
    public $codeExtensions = [];
    public $sensitive = [];
    public $uploadsDir = '';
    public $tempRoot = false;
    public $channels = [];
    public $budgetSeconds = 50;
    public $budgetMemoryMb = 128;
    public $maxScanBytes = 2097152;
    public $remindHours = 24;
    public $updateGraceSeconds = 120;
    public $wpChecksums = true;
    /** Accept plugin/theme version bumps whose files cannot be verified against an official source (legacy behaviour). */
    public $autoAcceptUnverifiedUpdates = false;
    /** The developer's update policy (sentinel.json), which applies when settings.txt has no line for it. */
    public $autoAcceptDefault = false;
    /** Who alert recipients should contact; shown in client alerts. */
    public $contact = '';
    /** 'technical' alerts show commands; 'client' alerts are plain language with no commands. */
    public $audience = 'technical';
    /** Absolute path of settings.txt, or '' when the config has none. */
    public $settingsFile = '';
    /**
     * Why settings.txt could not be used, when the last settings that worked were used instead
     * ('' when settings.txt is fine). Run reports it; monitoring carries on meanwhile.
     */
    public $settingsProblem = '';
    /** The settings in use, as Settings::toArray() (packaged installs only). */
    public $settings = [];

    /** In the state directory: the last settings that worked, kept so a broken settings.txt never stops monitoring. */
    public const LAST_GOOD_SETTINGS = 'settings-trusted.json';
    public $heartbeatUrl = '';
    public $rulesUrl = '';
    public $rulesPublicKey = '';
    public $allowUnsignedRules = false;
    public $clamscanPath = '';
    public $clamdscanPath = '';
    public $yaraPath = '';
    public $yaraRules = '';

    /** @var string[] */
    private $extraExclude = [];
    /** The packaged site_root was missing, and public_html was found one folder further up. */
    public $siteRootFoundHigher = false;
    /** site_root as written in sentinel.json (after the one-level-up fallback), before it was resolved; '' when not loaded from a file. */
    public $siteRootSetting = '';
    /**
     * The hosting account's home: the parent of the website folder as configured, before symlinks
     * are resolved (<sentinel>/../public_html and <sentinel>/../../public_html both give the folder
     * holding public_html). '' when it cannot be told. Used to keep absolute paths out of what is sent.
     */
    public $accountHome = '';
    /** WordPress installs in subfolders (Profile::nestedWordPress), found each time the config is loaded. */
    public $nestedWordPress = [];
    /** @var string[] their uploads folders and anchored sensitive paths; never written back to the config file */
    private $nestedUploads = [];
    private $nestedSensitive = [];
    /** Whether exclude and sensitive were configured, or are the profile's defaults (not written back). */
    private $excludeConfigured = false;
    private $sensitiveConfigured = false;
    private $quietFoldersConfigured = false;
    /** @var PathFilter|null built from quiet_folders when first needed */
    private $quietFilter = null;

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
        // Relative paths are relative to the config file, not to wherever cron happens to start,
        // so a packaged folder works without anyone typing their hosting username.
        $dir = dirname($file);
        // The package ships "../public_html". If unzipping added a folder level (for example
        // ~/site-sentinel/sentinel/), the website is exactly one folder further up.
        $configured = (string)($raw['site_root'] ?? '');
        $higher = self::foundHigher($dir, $raw['site_root'] ?? null);
        if ($higher) {
            $raw['site_root'] = '../' . self::PACKAGE_SITE_ROOT;
        }
        $setting = (string)($raw['site_root'] ?? '');
        foreach (['site_root', 'state_dir', 'settings_file'] as $key) {
            if (isset($raw[$key]) && is_string($raw[$key]) && $raw[$key] !== '' && $raw[$key][0] !== '/') {
                $raw[$key] = $dir . '/' . $raw[$key];
            }
        }
        $settingsFile = (string)($raw['settings_file'] ?? '');
        $autoAcceptDefault = (bool)($raw['auto_accept_unverified_updates'] ?? false); // read as fromArray reads it
        $problem = '';
        $settings = null;
        if ($settingsFile !== '') {
            try {
                $settings = Settings::load($settingsFile);
            } catch (SettingsException $e) {
                $settings = self::lastGoodSettings($raw);
                if ($settings === null) {
                    throw new ConfigException($e->getMessage());
                }
                $problem = $e->getMessage();
            }
            $raw = self::withSettings($raw, $settings);
        }
        $c = self::fromArray($raw);
        $c->siteRootFoundHigher = $higher;
        $c->accountHome = self::accountHomeFor($dir, $configured);
        $c->siteRootSetting = $setting;
        $c->settingsProblem = $problem;
        $c->autoAcceptDefault = $autoAcceptDefault;
        $c->settings = $settings !== null ? $settings->toArray() : [];
        return $c;
    }

    /** Whether the shipped site_root is missing here while public_html is one folder further up. */
    private static function foundHigher(string $dir, $siteRoot): bool
    {
        return $siteRoot === self::PACKAGE_SITE_ROOT && !is_dir($dir . '/' . self::PACKAGE_SITE_ROOT) && is_dir($dir . '/../' . self::PACKAGE_SITE_ROOT);
    }

    /**
     * The account home for a site_root as written in the config file in $dir (with the one-level-up
     * fallback applied): the parent of that folder with "." and ".." resolved by name only, so a
     * website folder that is a link still gives the folder holding the link. '' when unknowable.
     */
    public static function accountHomeFor(string $dir, string $siteRoot): string
    {
        if (self::foundHigher($dir, $siteRoot)) {
            $siteRoot = '../' . self::PACKAGE_SITE_ROOT;
        }
        return self::parentOf($siteRoot !== '' && $siteRoot[0] !== '/' ? $dir . '/' . $siteRoot : $siteRoot);
    }

    /** The parent folder of $path by name (relative paths start at the current folder); '' for none or for the file system root. */
    private static function parentOf(string $path): string
    {
        if ($path === '') {
            return '';
        }
        if ($path[0] !== '/') {
            $cwd = getcwd();
            if ($cwd === false) {
                return '';
            }
            $path = $cwd . '/' . $path;
        }
        $parts = [];
        foreach (explode('/', $path) as $part) {
            if ($part === '..') {
                array_pop($parts);
            } elseif ($part !== '' && $part !== '.') {
                $parts[] = $part;
            }
        }
        array_pop($parts); // the website folder itself
        return $parts ? '/' . implode('/', $parts) : '';
    }

    /** The settings kept when they last worked, if the state directory has them. */
    private static function lastGoodSettings(array $raw): ?Settings
    {
        $dir = (string)($raw['state_dir'] ?? '');
        $file = $dir . '/' . self::LAST_GOOD_SETTINGS;
        if ($dir === '' || !is_file($file)) {
            return null;
        }
        $a = json_decode((string)@file_get_contents($file), true);
        return is_array($a) ? Settings::fromArray($a) : null;
    }

    /** Overlays settings.txt: recipients, names, the update policy and an optional heartbeat. */
    private static function withSettings(array $raw, Settings $s): array
    {
        $raw['channels'] = array_merge([['type' => 'email', 'to' => $s->emails, 'from' => $s->from]], (array)($raw['channels'] ?? []));
        if ($s->website !== '') {
            $raw['site_name'] = $s->website;
        }
        if ((string)($raw['site_name'] ?? '') === '') {
            $raw['site_name'] = 'your website';
        }
        if ($s->contact !== '') {
            $raw['contact'] = $s->contact;
        }
        if ($s->approveUpdates !== null) {
            $raw['auto_accept_unverified_updates'] = $s->approveUpdates;
        }
        if ($s->quietChanges !== null) { // settings.txt wins over a developer's quiet_changes in sentinel.json
            $raw['quiet_changes'] = $s->quietChanges;
        }
        if ($s->heartbeat !== '') {
            $raw['heartbeat_url'] = $s->heartbeat;
        }
        return $raw;
    }

    /**
     * The website folder as shown to its owner: for the client audience, as configured without
     * the absolute path (which contains the hosting account name), e.g. "public_html".
     */
    public function siteFolderLabel(): string
    {
        if ($this->audience !== 'client') {
            return $this->siteRoot;
        }
        $setting = $this->siteRootSetting;
        if ($setting !== '' && $setting[0] === '/') {
            $label = basename(rtrim($setting, '/')); // an absolute setting: only its last segment
        } else {
            $label = rtrim((string)preg_replace('#^(?:\.{1,2}(?:/+|$))+#', '', $setting), '/');
        }
        return $label === '' || $label === '.' || $label === '..' ? basename($this->siteRoot) : $label;
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
        $c->accountHome = self::parentOf($root);
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
        $c->excludeConfigured = isset($raw['exclude']);
        $c->sensitiveConfigured = isset($raw['sensitive']);
        $c->exclude = self::strings($raw['exclude'] ?? $d['exclude']);
        $c->quietFoldersConfigured = isset($raw['quiet_folders']);
        $c->quietFolders = self::strings($raw['quiet_folders'] ?? []);
        // Only the boolean true: a string such as "false" or "no" must not switch quiet on.
        $c->quietChanges = ($raw['quiet_changes'] ?? false) === true;
        $c->codeExtensions = array_map('strtolower', self::strings($raw['code_extensions'] ?? $d['code_extensions']));
        $c->sensitive = self::strings($raw['sensitive'] ?? $d['sensitive']);
        $c->uploadsDir = trim((string)($raw['uploads_dir'] ?? $d['uploads_dir']), '/');
        // WordPress in a subfolder gets the WordPress path rules under its folder. A configured
        // exclude or sensitive list replaces the defaults, for subfolders as for the root.
        $c->nestedWordPress = Profile::nestedWordPress($c->siteRoot, new PathFilter($c->exclude));
        $wp = Profile::defaults('wordpress');
        foreach ($c->nestedWordPress as $prefix) {
            $c->nestedUploads[] = $prefix . '/' . $wp['uploads_dir'];
            foreach ($c->excludeConfigured ? [] : $wp['exclude'] as $pattern) {
                if (($moved = Profile::under($prefix, $pattern)) !== null) {
                    $c->extraExclude[] = $moved;
                }
            }
            foreach ($c->sensitiveConfigured ? [] : $wp['sensitive'] as $pattern) {
                if (($moved = Profile::under($prefix, $pattern)) !== null) {
                    $c->nestedSensitive[] = $moved;
                }
            }
        }
        $c->tempRoot = (bool)($raw['temp_root'] ?? false);
        $c->channels = self::channels($raw['channels'] ?? []);
        $c->budgetSeconds = self::int($raw, 'budget_seconds', 50);
        $c->budgetMemoryMb = self::int($raw, 'budget_memory_mb', 128);
        $c->maxScanBytes = self::int($raw, 'max_scan_bytes', 2097152);
        $c->remindHours = self::int($raw, 'remind_hours', 24);
        $c->updateGraceSeconds = self::int($raw, 'update_grace_seconds', 120, 0);
        $c->wpChecksums = (bool)($raw['wp_checksums'] ?? true);
        $c->autoAcceptUnverifiedUpdates = (bool)($raw['auto_accept_unverified_updates'] ?? false);
        $c->autoAcceptDefault = $c->autoAcceptUnverifiedUpdates; // load() replaces it with the value before settings.txt
        $c->contact = trim((string)($raw['contact'] ?? ''));
        $c->audience = (string)($raw['audience'] ?? 'technical');
        if (!in_array($c->audience, ['technical', 'client'], true)) {
            throw new ConfigException("audience must be 'technical' or 'client'");
        }
        $c->settingsFile = (string)($raw['settings_file'] ?? '');
        $c->heartbeatUrl = self::url($raw, 'heartbeat_url');
        $c->rulesUrl = self::url($raw, 'rules_url');
        $c->rulesPublicKey = trim((string)($raw['rules_public_key'] ?? ''));
        $c->allowUnsignedRules = (bool)($raw['allow_unsigned_rules'] ?? false);
        $c->clamscanPath = trim((string)($raw['clamscan_path'] ?? ''));
        $c->clamdscanPath = trim((string)($raw['clamdscan_path'] ?? ''));
        $c->yaraPath = trim((string)($raw['yara_path'] ?? ''));
        $c->yaraRules = trim((string)($raw['yara_rules'] ?? ''));
        return $c;
    }

    public function toArray(): array
    {
        // Default exclude and sensitive lists are left out, so loading the result again derives them
        // again (with the subfolder WordPress defaults) instead of reading them as a configured list.
        return array_diff_key([
            'site_name' => $this->siteName,
            'profile' => $this->profile,
            'site_root' => $this->siteRoot === '' ? '/' : $this->siteRoot,
            'state_dir' => $this->stateDir,
            'watch' => $this->watch,
            'exclude' => $this->exclude,
            'code_extensions' => $this->codeExtensions,
            'sensitive' => $this->sensitive,
            'quiet_folders' => $this->quietFolders,
            'uploads_dir' => $this->uploadsDir,
            'temp_root' => $this->tempRoot,
            'channels' => $this->channels,
            'budget_seconds' => $this->budgetSeconds,
            'budget_memory_mb' => $this->budgetMemoryMb,
            'max_scan_bytes' => $this->maxScanBytes,
            'remind_hours' => $this->remindHours,
            'update_grace_seconds' => $this->updateGraceSeconds,
            'wp_checksums' => $this->wpChecksums,
            'auto_accept_unverified_updates' => $this->autoAcceptUnverifiedUpdates,
            'contact' => $this->contact,
            'audience' => $this->audience,
            'heartbeat_url' => $this->heartbeatUrl,
            'rules_url' => $this->rulesUrl,
            'rules_public_key' => $this->rulesPublicKey,
            'allow_unsigned_rules' => $this->allowUnsignedRules,
            'clamscan_path' => $this->clamscanPath,
            'clamdscan_path' => $this->clamdscanPath,
            'yara_path' => $this->yaraPath,
            'yara_rules' => $this->yaraRules,
        ], array_filter([
            'exclude' => !$this->excludeConfigured,
            'sensitive' => !$this->sensitiveConfigured,
            'quiet_folders' => !$this->quietFoldersConfigured,
        ]));
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

    /** Every WordPress install watched: '' for the website folder itself, then those in subfolders. */
    public function wordpressInstalls(): array
    {
        return array_merge($this->profile === 'wordpress' ? [''] : [], $this->nestedWordPress);
    }

    /**
     * Whether a change at this path is recorded without an email unless something flags it.
     * quiet_folders patterns are anchored at the website folder: "app/" is <site>/app/ only, not a
     * folder called app inside a theme or a plugin called app (anyone who can write files could
     * create those).
     */
    public function isQuiet(string $rel): bool
    {
        if ($this->quietChanges) {
            return true;
        }
        if (!$this->quietFolders) {
            return false;
        }
        if ($this->quietFilter === null) {
            $this->quietFilter = new PathFilter(array_map(function (string $p): string {
                $p = trim($p);
                return $p === '' ? '' : '/' . ltrim($p, '/');
            }, $this->quietFolders));
        }
        return $this->quietFilter->matches($rel);
    }

    /** Files WordPress itself ships in wp-content, relative to an install. */
    private const CORE_IN_WP_CONTENT = ['wp-content/index.php', 'wp-content/plugins/index.php', 'wp-content/themes/index.php', 'wp-content/plugins/hello.php'];

    /**
     * WordPress core of any install: its wp-admin and wp-includes, the core files directly in its
     * folder (index.php, xmlrpc.php, wp-*.php), and the few files WordPress ships in wp-content
     * (the index.php placeholders and hello.php). wp-config.php is not core: it is already sensitive.
     */
    public function isCorePath(string $rel): bool
    {
        foreach ($this->wordpressInstalls() as $prefix) {
            if ($prefix === '') {
                $local = $rel;
            } elseif (strpos($rel, $prefix . '/') === 0) {
                $local = substr($rel, strlen($prefix) + 1);
            } else {
                continue;
            }
            if (strpos($local, 'wp-admin/') === 0 || strpos($local, 'wp-includes/') === 0 || in_array($local, self::CORE_IN_WP_CONTENT, true)) {
                return true;
            }
            if (strpos($local, '/') === false && $local !== 'wp-config.php'
                && ($local === 'index.php' || $local === 'xmlrpc.php' || preg_match('/^wp-[^\/]*\.php$/', $local) === 1)) {
                return true;
            }
        }
        return false;
    }

    public function hasWordPress(): bool
    {
        return $this->profile === 'wordpress' || $this->nestedWordPress;
    }

    /**
     * The WordPress install a path belongs to (the deepest one, so shop/dev wins over shop) and
     * the path inside that install, or null for a path outside every install.
     *
     * @return array{0:string,1:string}|null
     */
    public function wordpressInstallOf(string $rel): ?array
    {
        $best = null;
        foreach ($this->nestedWordPress as $prefix) {
            if (strpos($rel, $prefix . '/') === 0 && ($best === null || strlen($prefix) > strlen($best))) {
                $best = $prefix;
            }
        }
        if ($best !== null) {
            return [$best, substr($rel, strlen($best) + 1)];
        }
        return $this->profile === 'wordpress' ? ['', $rel] : null;
    }

    /** A path inside a WordPress install, as a path in the website folder. */
    public static function inInstall(string $prefix, string $local): string
    {
        return $prefix === '' ? $local : $prefix . '/' . $local;
    }

    public function isUploads(string $rel): bool
    {
        foreach (array_merge([$this->uploadsDir], $this->nestedUploads) as $dir) {
            if ($dir !== '' && ($rel === $dir || strpos($rel, $dir . '/') === 0)) {
                return true;
            }
        }
        return false;
    }

    /** Sensitive-file patterns: configured ones plus those of WordPress installs in subfolders. */
    public function sensitivePatterns(): array
    {
        return array_merge($this->sensitive, $this->nestedSensitive);
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

    private static function int(array $raw, string $key, int $default, int $min = 1): int
    {
        $v = (int)($raw[$key] ?? $default);
        if ($v < $min) {
            throw new ConfigException($min === 0 ? "$key must be zero or a positive integer" : "$key must be a positive integer");
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
