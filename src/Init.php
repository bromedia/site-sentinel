<?php
declare(strict_types=1);

namespace Sentinel;

final class Init
{
    private const BATCH = 200;

    /**
     * @param array<string,mixed> $o options, see Cli::parse
     * @return array{exit:int, lines:string[]}
     */
    public static function run(array $o, string $script, HttpClient $http): array
    {
        $root = (string)($o['root'] ?? '');
        if ($root === '' || !is_dir($root)) {
            return self::fail('--root=/path/to/site is required and must be an existing directory');
        }
        $dir = dirname($script);
        $configFile = (string)($o['config'] ?? $dir . '/sentinel.json');
        $stateDir = (string)($o['state'] ?? $dir . '/sentinel-state');
        $force = !empty($o['force']);
        $cron = Cron::lines($script, $configFile);
        if (is_file($configFile) && !$force) {
            return self::fail("$configFile already exists; use --force to overwrite it");
        }

        $channels = [];
        if (!empty($o['email'])) {
            $channels[] = ['type' => 'email', 'to' => array_map('trim', explode(',', (string)$o['email']))];
        }
        if (!empty($o['ntfy'])) {
            $channels[] = ['type' => 'ntfy', 'url' => (string)$o['ntfy']];
        }
        if (!empty($o['webhook'])) {
            $channels[] = ['type' => 'webhook', 'url' => (string)$o['webhook']];
        }
        if (!empty($o['file'])) {
            $channels[] = ['type' => 'file', 'path' => (string)$o['file']];
        }
        if (!$channels) {
            return self::fail('at least one alert channel is required: --email=a@b.c[,d@e.f], --ntfy=URL, --webhook=URL or --file=/abs/path/alerts.log');
        }

        $real = (string)realpath($root);
        $raw = [
            'site_name' => (string)($o['name'] ?? trim((string)gethostname() . ' ' . basename($real))),
            'site_root' => $root,
            'state_dir' => $stateDir,
            'channels' => $channels,
            'wp_checksums' => empty($o['no-wp-checksums']),
        ];
        if (!empty($o['profile'])) {
            $raw['profile'] = (string)$o['profile'];
        }
        try {
            $config = Config::fromArray($raw);
        } catch (ConfigException $e) {
            return self::fail($e->getMessage());
        }

        $config->addExclusion($script);
        $config->addExclusion($configFile);
        $state = new State($config->stateDir);
        $rulesFile = $state->path('rules.json');
        $rules = is_file($rulesFile) ? Rules::load($rulesFile) : Rules::builtin();
        $wpOn = $config->profile === 'wordpress';
        $wp = $wpOn && $config->wpChecksums ? new WpChecksum($http, $config, $state->path('cache')) : null;
        $analyzer = new Analyzer(
            $config,
            new PatternScanner($rules, $config->maxScanBytes),
            new LocationScanner($config),
            $wp,
            ExternalScanner::fromConfig($config)
        );

        $differ = new Differ($config);
        $findings = [];
        $notes = [];
        $tmp = $state->path('baseline.init');
        $symlinkDirs = [];
        $records = (function () use ($config, $differ, $analyzer, &$findings, &$notes, &$symlinkDirs) {
            $batch = [];
            foreach ((new Walker($config))->walk() as $meta) {
                [$rec, $unreadable] = $differ->record($meta);
                if (($rec['mode'] & 0170000) === 0120000 && is_dir($config->abs($rec['path']))) {
                    $target = @readlink($config->abs($rec['path']));
                    $symlinkDirs[] = [$rec['path'], $target === false ? '?' : $target];
                }
                if ($analyzer->wantsAnalysis($rec)) {
                    $batch[] = ['type' => 'new', 'path' => $rec['path'], 'old' => null, 'new' => $rec, 'stealth' => false, 'content_same' => false, 'unreadable' => $unreadable];
                    if (count($batch) >= self::BATCH) {
                        self::flush($analyzer, $batch, $findings, $notes);
                    }
                }
                yield $rec;
            }
            self::flush($analyzer, $batch, $findings, $notes);
        })();
        $count = Baseline::write($tmp, $records);

        $lines = [];
        if ($findings && !$force) {
            @unlink($tmp);
            $lines[] = 'The site already contains files that look malicious, so no baseline was created';
            $lines[] = '(a baseline taken now would treat them as known-good):';
            foreach ($findings as $f) {
                $lines[] = '  ' . Finding::label($f->severity) . ' ' . $f->path . ' ' . $f->rule . ': ' . $f->message;
            }
            $lines[] = 'Clean the site, then run init again. To accept the risk and baseline anyway, add --force.';
            return ['exit' => 1, 'lines' => $lines];
        }
        // The config is written only once the scan has passed, so a refused init leaves nothing behind.
        $json = json_encode($config->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false || file_put_contents($configFile, $json . "\n") === false) {
            @unlink($tmp);
            return self::fail("cannot write $configFile");
        }
        @chmod($configFile, 0600);
        if (!rename($tmp, $state->path('baseline.txt'))) {
            @unlink($tmp);
            return self::fail('cannot install the baseline');
        }

        if ($wpOn) {
            $state->writeJson('versions.json', VersionTracker::read($config));
        }
        $selfFiles = self::selfFiles($script, $configFile, $state);
        (new SelfCheck($state, $selfFiles))->record();
        (new AlertLog($state))->clear();
        @unlink($state->path('resume.json'));
        $state->writeJson('status.json', []);

        $lines[] = sprintf('Created %s (profile %s) and a baseline of %d file(s).', $configFile, $config->profile, $count);
        foreach ($findings as $f) {
            $lines[] = 'WARNING: baselined despite ' . Finding::label($f->severity) . ' ' . $f->path . ' (' . $f->rule . ')';
        }
        foreach (array_unique($notes) as $n) {
            $lines[] = 'note: ' . $n;
        }
        foreach ($symlinkDirs as [$path, $target]) {
            $lines[] = sprintf("note: '%s' is a symlink to a directory (%s). Sentinel does not follow symlinks, so nothing inside it is monitored: set up a second config with site_root set to the target.", $path, $target);
        }
        $lines[] = '';
        $lines[] = 'Add these lines to the crontab of the account that owns the site (crontab -e, or cPanel > Cron Jobs):';
        $lines = array_merge($lines, $cron);
        $lines[] = '';
        $lines[] = 'Next: run "php ' . $script . ' test-alert --config=' . $configFile . '" to confirm alerts arrive.';
        $lines[] = 'Recommended: set heartbeat_url in the config to a healthchecks.io-style URL so you are told if Sentinel stops running.';
        $lines[] = 'Run doctor for hosting checks and scan history. Cron keeps stderr visible; configure cron email or capture/rotate it in a private log.';
        return ['exit' => 0, 'lines' => $lines];
    }

    /** @return array<string,string> */
    public static function selfFiles(string $script, string $configFile, State $state): array
    {
        $s = realpath($script);
        $c = realpath($configFile);
        return [
            'script' => $s !== false ? $s : $script,
            'config' => $c !== false ? $c : $configFile,
            'rules' => $state->path('rules.json'),
        ];
    }

    private static function flush(Analyzer $analyzer, array &$batch, array &$findings, array &$notes): void
    {
        if (!$batch) {
            return;
        }
        $r = $analyzer->analyze($batch, [], [], true);
        foreach ($r['findings'] as $f) {
            $findings[] = $f;
        }
        foreach ($r['notes'] as $n) {
            $notes[] = $n;
        }
        $batch = [];
    }

    private static function fail(string $msg): array
    {
        return ['exit' => 2, 'lines' => [$msg]];
    }
}
