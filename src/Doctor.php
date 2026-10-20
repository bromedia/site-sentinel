<?php

declare(strict_types=1);

namespace Sentinel;

final class Doctor
{
    /** Read-only local diagnostics: no scans, baseline changes, network calls or test alerts. */
    public static function run(Config $c, string $script, string $configFile): array
    {
        $lines = ['Site Sentinel ' . VERSION . ' diagnostics for ' . $c->siteName];
        $exit = 0;
        $add = function (int $level, string $message) use (&$lines, &$exit): void {
            $lines[] = ['OK', 'WARN', 'ERROR'][$level] . ': ' . $message;
            $exit = max($exit, $level);
        };
        $add(0, 'PHP ' . PHP_VERSION . ' CLI: ' . PHP_BINARY);
        $add(is_readable($c->siteRoot) ? 0 : 2, 'site root: ' . $c->siteRoot);
        $add(is_dir($c->stateDir) && is_writable($c->stateDir) ? 0 : 2, 'writable state directory: ' . $c->stateDir);
        foreach (['script' => $script, 'configuration' => $configFile, 'state directory' => $c->stateDir] as $label => $path) {
            $real = realpath($path);
            $path = $real !== false ? $real : $path;
            $inside = $c->siteRoot === '' || $path === $c->siteRoot || strpos($path, $c->siteRoot . '/') === 0;
            $add($inside ? 1 : 0, $label . ($inside ? ' is inside the site root; move it outside the public web directory' : ' is outside the site root'));
        }
        $baseline = $c->stateDir . '/baseline.txt';
        if (!is_readable($baseline)) {
            $add(2, 'baseline missing or unreadable; run init before scheduling scans');
        } else {
            try {
                // Validate the header/first record without walking a potentially large baseline.
                $records = Baseline::read($baseline);
                $records->valid();
                $add(0, 'baseline is readable (this is not a full integrity scan)');
            } catch (\Throwable $e) {
                $add(2, 'baseline is invalid: ' . $e->getMessage());
            }
        }
        $add($c->channels ? 0 : 2, count($c->channels) . ' alert channel(s); run test-alert to verify delivery');
        $needsHttp = $c->wpChecksums || $c->heartbeatUrl !== '' || $c->rulesUrl !== '';
        foreach ($c->channels as $ch) {
            $needsHttp = $needsHttp || in_array($ch['type'], ['ntfy', 'telegram', 'webhook'], true);
            if ($ch['type'] === 'email') {
                $add(function_exists('mail') ? 0 : 2, 'email uses PHP mail(), independently of WordPress SMTP plugins');
            }
        }
        $add($c->heartbeatUrl !== '' ? 0 : 1, $c->heartbeatUrl !== '' ? 'external heartbeat configured (run availability, not proof of a complete scan)' : 'no external heartbeat; you will not be alerted if Sentinel stops running');
        if ($needsHttp) {
            $network = function_exists('curl_init') || (bool)ini_get('allow_url_fopen');
            $add($network ? 0 : 2, $network ? 'HTTP transport available; outbound connectivity has not been tested' : 'HTTP unavailable; enable PHP curl or allow_url_fopen for checksums and remote services');
        }
        if ($c->profile === 'wordpress') {
            $add($c->wpChecksums ? 0 : 1, $c->wpChecksums ? 'WordPress.org checksum verification enabled' : 'WordPress.org checksum verification disabled');
            if (!is_file($c->abs('wp-config.php')) && is_file(dirname($c->siteRoot) . '/wp-config.php')) {
                $add(1, 'wp-config.php is above the site root and is not monitored');
            }
            if ($c->uploadsDir !== '' && is_link($c->abs($c->uploadsDir))) {
                $add(1, 'uploads directory is a symlink and is not followed; monitor its target with a separate config');
            }
        }
        $lines[] = 'Watch: ' . implode(', ', $c->watch);
        $lines[] = 'Excluded (not scanned): ' . implode(', ', $c->exclusions());
        $lines[] = 'Shared scan budget: ' . $c->budgetSeconds . 's / ' . $c->budgetMemoryMb . 'MB. Individual file I/O, checkpointing and alerts can overrun.';
        $add($c->autoAcceptUnverifiedUpdates ? 1 : 0, $c->autoAcceptUnverifiedUpdates ? 'legacy unverified-update auto-acceptance enabled' : 'unverified updates require scoped review (strict default)');
        if ($c->database['enabled']) {
            $add(function_exists('mysqli_init') && defined('MYSQLI_OPT_READ_TIMEOUT') ? 0 : 2, 'database monitoring requires mysqli with read-timeout support');
            $add(is_readable($c->stateDir . '/database-baseline.json') ? 0 : 2, 'review administrators/options and run db-init');
            try {
                DatabaseCredentials::load($c);
                $add(0, 'database credentials readable without PHP execution (values hidden)');
            } catch (\Throwable $e) {
                $add(2, 'database credential source unreadable; use literals or a private credentials_file');
            }
        } else {
            $lines[] = 'Database monitoring disabled (opt-in).';
        }

        $file = $c->stateDir . '/status.json';
        $status = is_readable($file) ? json_decode((string)file_get_contents($file), true) : [];
        if (!is_array($status)) {
            $add(1, 'scan history is unreadable; run check and full to refresh it');
            $status = [];
        }
        foreach ($c->database['enabled'] ? ['check', 'full', 'database'] : ['check', 'full'] as $mode) {
            $entry = $status[$mode] ?? [];
            $last = (int)($entry['last_run'] ?? 0);
            $complete = (int)($entry['last_complete'] ?? 0);
            $lines[] = $mode . ': last processed run ' . self::when($last) . '; last complete traversal ' . self::when($complete);
            if (!empty($entry['last_error'])) {
                $add(1, $mode . ' last attempt failed; inspect cron stderr or the error alert');
            }
            if ($last > 0 && empty($entry['complete'])) {
                $add(1, $mode . ' has a partial scan pending; ' . ($mode === 'full' && !$c->continueFull ? 'run full to resume' : 'the next check continues it'));
            }
        }
        return ['exit' => $exit, 'lines' => $lines];
    }

    private static function when(int $timestamp): string
    {
        return $timestamp > 0 ? gmdate('Y-m-d H:i:s', $timestamp) . ' UTC' : 'not recorded';
    }
}
