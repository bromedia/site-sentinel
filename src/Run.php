<?php
declare(strict_types=1);

namespace Sentinel;

/**
 * The single scheduled command for packaged installs ("run"), for hosts where the owner can add
 * one cron job but has no terminal: it finishes setting up on its first run, then checks on every
 * run and does a full scan when one is due. It prints nothing when all is well, because hosting
 * panels email whatever a cron job prints.
 */
final class Run
{
    /** Shipped in the package; its presence is the only thing that allows a first-run setup. */
    public const MARKER = 'SETUP-PENDING.txt';
    /** A full scan is due once the last complete one is this old (cron may run only every few hours). */
    public const FULL_EVERY = 72000;

    /**
     * @param Channel[] $channels
     * @param array<string,string> $selfFiles
     * @return array{exit:int, lines:string[]}
     */
    public static function execute(Config $config, State $state, HttpClient $http, array $channels, array $selfFiles, string $script, string $configFile, ?callable $clock = null, ?callable $mailer = null): array
    {
        $clock = $clock ?? function (): int {
            return time();
        };
        $marker = dirname($script) . '/' . self::MARKER;
        if (!is_file($state->path('baseline.txt'))) {
            if (is_file($marker)) {
                return self::firstRun($config, $state, $http, $channels, $selfFiles, $script, $configFile, $marker, $clock);
            }
            // No marker: never re-baseline on its own. A missing baseline on an installed site is
            // reported as an error by the monitor below.
        } elseif (is_file($marker)) {
            @unlink($marker); // e.g. the package was extracted again over a working install
        }

        $lines = isset($selfFiles['settings']) ? self::settingsChanged($config, $state, $channels, $selfFiles, $mailer) : [];
        $monitor = new Monitor($config, $state, $http, $channels, $selfFiles, $clock);
        $r = $monitor->run('check');
        if ($r['exit'] !== 2 && self::fullDue($state, $clock())) {
            $f = $monitor->run('full');
            $r = ['exit' => max($r['exit'], $f['exit']), 'lines' => array_merge($r['lines'], $f['lines'])];
        }
        $r['lines'] = $r['exit'] === 0 ? $lines : array_merge($lines, $r['lines']);
        return $r;
    }

    public static function fullDue(State $state, int $now): bool
    {
        if (isset($state->readJson('resume.json')['full'])) {
            return true; // finish a partial full scan before starting over
        }
        $full = (array)($state->readJson('status.json')['full'] ?? []);
        return $now - (int)($full['last_complete'] ?? 0) >= self::FULL_EVERY;
    }

    /** @param Channel[] $channels */
    private static function firstRun(Config $config, State $state, HttpClient $http, array $channels, array $selfFiles, string $script, string $configFile, string $marker, callable $clock): array
    {
        try {
            $lock = Lock::acquire($state->path('lock'));
        } catch (\Throwable $e) {
            return ['exit' => 2, 'lines' => ['setup failed: ' . $e->getMessage()]];
        }
        if ($lock === null) {
            return ['exit' => 0, 'lines' => []];
        }
        try {
            $now = $clock();
            $who = $config->contact !== '' ? $config->contact : 'your web developer';
            $site = $config->siteName;

            $inside = [];
            foreach (['the sentinel folder' => dirname($script), 'sentinel.json' => $configFile, 'the state folder' => $config->stateDir] as $label => $path) {
                $real = realpath($path);
                $real = $real !== false ? $real : $path;
                if ($real === $config->siteRoot || strpos($real, $config->siteRoot . '/') === 0) {
                    $inside[] = $label;
                }
            }
            if ($inside) {
                $msg = 'The sentinel folder is inside the public website folder (' . $config->siteRoot . '), where its files could be downloaded by anyone. Move the whole sentinel folder next to public_html, not inside it, update the cron job to the new location, and run it again.';
                self::alertOnce($state, $channels, $now, 'setup-placement', "Site Sentinel setup could not finish on $site", "Site Sentinel was not started.\n\n$msg\n\nIf you need help, contact $who.\n");
                return ['exit' => 2, 'lines' => ['setup failed: ' . $msg]];
            }

            $scan = Init::scan($config, $state, $http);
            if ($scan['findings']) {
                @unlink($scan['tmp']);
                $body = ["Site Sentinel was not started, because the website already contains files that look like", 'hacking tools or tampering:'];
                foreach ($scan['findings'] as $f) {
                    $body[] = '  - ' . $f->path;
                }
                $body[] = '';
                $body[] = "Starting now would treat these files as normal. Please contact $who and forward this";
                $body[] = 'email. Once the files have been dealt with, setup finishes by itself on the next run.';
                $body[] = '';
                $body[] = '--';
                $body[] = 'Technical details for your web developer:';
                foreach ($scan['findings'] as $f) {
                    $body[] = '  ' . Finding::label($f->severity) . ' ' . $f->rule . ' ' . $f->path . ': ' . $f->message;
                }
                self::alertOnce($state, $channels, $now, 'setup-infected:' . sha1(implode("\n", array_map(function (Finding $f) {
                    return $f->key();
                }, $scan['findings']))), "Security alert: setup found possible hacking on $site", implode("\n", $body) . "\n");
                return ['exit' => 1, 'lines' => ['setup refused: ' . count($scan['findings']) . ' suspicious file(s); see the alert email']];
            }
            if (!Init::install($config, $state, $scan['tmp'], $selfFiles)) {
                return ['exit' => 2, 'lines' => ['setup failed: cannot install the baseline in ' . $config->stateDir]];
            }
            // The setup scan was a full one, so the next full scan is due in a day, not on the next run.
            $state->writeJson('status.json', ['full' => ['last_run' => $now, 'last_complete' => $now, 'complete' => true, 'changes' => 0, 'critical' => 0, 'warning' => 0]]);
            $state->writeJson('settings-recipients.json', self::recipients($config));
            @unlink($marker);

            $wp = $config->profile === 'wordpress';
            $body = [
                "Site Sentinel is now watching $site.",
                '',
                'What was set up',
                '  Website folder: ' . $config->siteRoot,
                '  Files recorded: ' . number_format($scan['count']),
                '  WordPress: ' . ($wp ? 'yes' . ($config->wpChecksums ? ', with official checksum checks' : '') : 'not detected'),
                '  Plugin and theme updates: ' . ($config->autoAcceptUnverifiedUpdates ? 'approved automatically' : 'each one reported for review'),
                '  Alerts go to: ' . implode(', ', self::recipients($config)),
                '',
                'What happens now',
                '  The website is checked each time the scheduled job runs, with a deeper scan once a day.',
                "  You will only hear from Site Sentinel when something needs attention.",
                '',
                "If you ever receive an alert, contact $who.",
                '',
                'This email is also the test that alerts reach you: if it landed in spam, mark it as not spam.',
            ];
            $notes = array_merge($scan['notes'], array_map(function ($l) {
                return sprintf("'%s' is a symlink to a directory (%s) and is not monitored.", $l[0], $l[1]);
            }, $scan['symlinkDirs']));
            if ($notes) {
                $body[] = '';
                $body[] = '--';
                $body[] = 'Notes for your web developer:';
                foreach ($notes as $n) {
                    $body[] = '  - ' . $n;
                }
            }
            $r = (new Alerter($channels))->send("Site Sentinel is now protecting $site", implode("\n", $body) . "\n", Finding::CRITICAL);
            $lines = [sprintf('setup complete: %d file(s) recorded for %s', $scan['count'], $site)];
            foreach ($r['results'] as $l) {
                $lines[] = 'alert ' . $l;
            }
            return ['exit' => $r['ok'] ? 0 : 2, 'lines' => $lines];
        } finally {
            $lock->release();
        }
    }

    /**
     * settings.txt is meant to be edited by the owner, so a change is not treated as tampering. It
     * is announced to the previous and the new recipients alike, so alerts cannot be redirected
     * quietly, and then trusted.
     *
     * @return string[] output lines
     */
    private static function settingsChanged(Config $config, State $state, array $channels, array $selfFiles, ?callable $mailer): array
    {
        $check = new SelfCheck($state, $selfFiles);
        if ($check->isTrusted('settings')) {
            return [];
        }
        $before = array_values(array_filter((array)$state->readJson('settings-recipients.json'), 'is_string'));
        $after = self::recipients($config);
        $site = $config->siteName;
        $who = $config->contact !== '' ? $config->contact : 'your web developer';
        $body = [
            "The Site Sentinel settings for $site were changed.",
            '',
            '  Alerts went to: ' . ($before ? implode(', ', $before) : '(unknown)'),
            '  Alerts now go to: ' . implode(', ', $after),
            '  Plugin and theme updates: ' . ($config->autoAcceptUnverifiedUpdates ? 'approved automatically' : 'each one reported for review'),
            '',
            "If you made this change, there is nothing to do. If you did not, contact $who.",
        ];
        $notify = $channels;
        $removed = array_values(array_diff(array_map('strtolower', $before), array_map('strtolower', $after)));
        if ($removed) {
            $notify[] = new Channel(new EmailNotifier($removed, '', $mailer), Finding::INFO);
        }
        $r = (new Alerter($notify))->send("Site Sentinel settings changed for $site", implode("\n", $body) . "\n", Finding::CRITICAL);
        $check->trust('settings');
        $state->writeJson('settings-recipients.json', $after);
        return array_map(function ($l) {
            return 'settings notice ' . $l;
        }, $r['results']);
    }

    /** @return string[] */
    private static function recipients(Config $config): array
    {
        $out = [];
        foreach ($config->channels as $ch) {
            if ($ch['type'] === 'email') {
                foreach ((array)$ch['to'] as $to) {
                    $out[] = (string)$to;
                }
            }
        }
        return array_values(array_unique($out));
    }

    /** Sends a setup problem once a day at most, not on every scheduled run. */
    private static function alertOnce(State $state, array $channels, int $now, string $key, string $subject, string $body): void
    {
        $f = new Finding(Finding::CRITICAL, 'sentinel', 'setup', $subject, sha1($key));
        $log = new AlertLog($state);
        if (!$log->due([$f], $now, 86400)) {
            $log->commit([$f], [], $now);
            return;
        }
        $r = (new Alerter($channels))->send($subject, $body, Finding::CRITICAL);
        $log->commit([$f], $r['ok'] ? [$f] : [], $now);
    }
}
