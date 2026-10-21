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
        $add(0, 'PHP ' . PHP_VERSION . ' (' . PHP_SAPI . '): ' . PHP_BINARY);
        $add(is_readable($c->siteRoot) ? 0 : 2, 'site root: ' . $c->siteRoot);
        if ($c->siteRootFoundHigher) {
            $add(1, 'site root found one folder further up than sentinel.json says (' . Config::PACKAGE_SITE_ROOT . '): the sentinel folder is inside an extra folder; check that the cron command points at ' . $script);
        }
        if (is_dir($c->stateDir)) {
            $add(is_writable($c->stateDir) ? 0 : 2, 'writable state directory: ' . $c->stateDir);
        } elseif (is_dir(dirname($c->stateDir)) && is_writable(dirname($c->stateDir))) {
            // A fresh install: the first run creates it.
            $add(0, 'state directory does not exist yet; the first run creates it: ' . $c->stateDir);
        } else {
            $add(2, 'state directory does not exist and cannot be created (its parent folder is missing or not writable): ' . $c->stateDir);
        }
        foreach (['script' => $script, 'configuration' => $configFile, 'state directory' => $c->stateDir] as $label => $path) {
            $real = realpath($path);
            $path = $real !== false ? $real : $path;
            $inside = $c->siteRoot === '' || $path === $c->siteRoot || strpos($path, $c->siteRoot . '/') === 0;
            $add($inside ? 1 : 0, $label . ($inside ? ' is inside the site root; move it outside the public web directory' : ' is outside the site root'));
        }
        $baseline = $c->stateDir . '/baseline.txt';
        if (!is_file($baseline) && Run::setupPending($script, $c->stateDir)) {
            $add(1, 'not set up yet: ' . Run::MARKER . ' is present, so the next scheduled run sets Sentinel up');
        } elseif (!is_readable($baseline)) {
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
        $add(0, ExternalScanner::fromConfig($c)->describeClamav());
        $needsHttp = $c->wpChecksums || $c->heartbeatUrl !== '' || $c->rulesUrl !== '';
        foreach ($c->channels as $ch) {
            $needsHttp = $needsHttp || in_array($ch['type'], ['ntfy', 'telegram', 'webhook'], true);
            if ($ch['type'] === 'email') {
                $add(function_exists('mail') ? 0 : 2, 'email uses PHP mail(), independently of WordPress SMTP plugins');
            }
        }
        $add($c->heartbeatUrl !== '' ? 0 : 1, $c->heartbeatUrl !== '' ? 'external heartbeat configured (run availability, not proof of a complete scan)' : 'no external heartbeat (optional, recommended): nothing outside this server would notice if Sentinel stopped running');
        if ($needsHttp) {
            $network = function_exists('curl_init') || (bool)ini_get('allow_url_fopen');
            $add($network ? 0 : 2, $network ? 'HTTP transport available; outbound connectivity has not been tested' : 'HTTP unavailable; enable PHP curl or allow_url_fopen for checksums and remote services');
        }
        if ($c->hasWordPress()) {
            $add($c->wpChecksums ? 0 : 1, $c->wpChecksums ? 'WordPress.org checksum verification enabled' : 'WordPress.org checksum verification disabled');
        }
        if ($c->profile === 'wordpress') {
            if (!is_file($c->abs('wp-config.php')) && is_file(dirname($c->siteRoot) . '/wp-config.php')) {
                $add(1, 'wp-config.php is above the site root and is not monitored');
            }
            if ($c->uploadsDir !== '' && is_link($c->abs($c->uploadsDir))) {
                $add(1, 'uploads directory is a symlink and is not followed; monitor its target with a separate config');
            }
        }
        if ($c->nestedWordPress) {
            $lines[] = 'WordPress in subfolders: ' . implode(', ', $c->nestedWordPress) . '. Each is checked like WordPress in the website folder: its own core checksums and plugin or theme updates, and the WordPress rules for its uploads, wp-config.php and cache folders.';
        }
        $lines[] = 'Watch: ' . implode(', ', $c->watch);
        $lines[] = 'Excluded (not scanned): ' . implode(', ', $c->exclusions());
        $lines[] = 'Scan budget: ' . $c->budgetSeconds . 's / ' . $c->budgetMemoryMb . 'MB for file comparison; analysis and initialisation can take longer.';
        $lines[] = 'No database checks are performed.';
        $dismissed = is_readable($c->stateDir . '/' . Dismissals::FILE) ? json_decode((string)file_get_contents($c->stateDir . '/' . Dismissals::FILE), true) : [];
        $n = is_array($dismissed) ? count((array)($dismissed['dismissals'] ?? [])) : 0;
        $lines[] = $n > 0 ? $n . ' dismissed finding(s); review them with: php sentinel.php dismiss --list' : 'No dismissed findings.';
        $record = is_readable($c->stateDir . '/selfcheck.json') ? json_decode((string)file_get_contents($c->stateDir . '/selfcheck.json'), true) : [];
        $dfile = $c->stateDir . '/' . Dismissals::FILE;
        if ($n > 0 && (!is_array($record) || (string)@hash_file('sha256', $dfile) !== (string)($record['dismissals'] ?? ''))) {
            $add(1, 'dismissals.json was changed outside the dismiss command, so its entries are not applied; review them with dismiss --list');
        }

        $file = $c->stateDir . '/status.json';
        $status = is_readable($file) ? json_decode((string)file_get_contents($file), true) : [];
        if (!is_array($status)) {
            $add(1, 'scan history is unreadable; run check and full to refresh it');
            $status = [];
        }
        foreach (['check', 'full'] as $mode) {
            $entry = $status[$mode] ?? [];
            $last = (int)($entry['last_run'] ?? 0);
            $complete = (int)($entry['last_complete'] ?? 0);
            $lines[] = $mode . ': last processed run ' . self::when($last) . '; last complete traversal ' . self::when($complete);
            if ($last > 0 && empty($entry['complete'])) {
                $add(1, $mode . ' has a partial scan pending; run ' . $mode . ' again to resume (check does not resume full)');
            }
        }
        return ['exit' => $exit, 'lines' => $lines];
    }

    private static function when(int $timestamp): string
    {
        return $timestamp > 0 ? gmdate('Y-m-d H:i:s', $timestamp) . ' UTC' : 'not recorded';
    }
}
