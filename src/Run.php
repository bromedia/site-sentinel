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
    /** Written only by a completed setup: if any is present, the site has been set up before. */
    private const INSTALLED = ['selfcheck.json', 'status.json', 'versions.json', 'settings-recipients.json', Config::LAST_GOOD_SETTINGS];

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
            if (self::wasInstalled($state)) {
                // Set up before, yet the record of the website's files is gone. Setting up again
                // would accept whatever is on disk now, so this is reported instead.
                return self::recordsMissing($config, $state, $channels, $mailer, $clock());
            }
            if (is_file($marker)) {
                return self::firstRun($config, $state, $http, $channels, $selfFiles, $script, $configFile, $marker, $clock, $mailer);
            }
            // No marker: never set up on its own. A missing baseline is reported by the monitor below.
        } elseif (is_file($marker)) {
            @unlink($marker); // e.g. the package was extracted again over a working install
        }

        $lines = [];
        if ($config->settingsProblem !== '') {
            $lines = self::settingsProblem($config, $state, $channels, $mailer, $clock());
        } elseif (isset($selfFiles['settings'])) {
            $lines = self::settingsChanged($config, $state, $channels, $selfFiles, $mailer);
        }
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

    private static function wasInstalled(State $state): bool
    {
        foreach (self::INSTALLED as $f) {
            if (file_exists($state->path($f))) {
                return true;
            }
        }
        return false;
    }

    /** @param Channel[] $channels */
    private static function firstRun(Config $config, State $state, HttpClient $http, array $channels, array $selfFiles, string $script, string $configFile, string $marker, callable $clock, ?callable $mailer): array
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
            $who = self::who($config->contact);
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
                $msg = self::placementMessage($config->siteRoot);
                self::alertOnce($state, $channels, $now, 'setup-placement', "Site Sentinel setup could not finish on $site", "Site Sentinel was not started.\n\n$msg\n\nIf you need help, contact $who.\n");
                return ['exit' => 2, 'lines' => ['setup failed: ' . $msg]];
            }

            $scan = Init::scan($config, $state, $http, $selfFiles);
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
                $body[] = '  If a file is harmless, remove it or add its path to "exclude" in sentinel.json;';
                $body[] = '  setup then finishes on the next run. Excluded files are never monitored.';
                self::alertOnce($state, $channels, $now, 'setup-infected:' . sha1(implode("\n", array_map(function (Finding $f) {
                    return $f->key();
                }, $scan['findings']))), "Security alert: setup found possible hacking on $site", self::text($body));
                return ['exit' => 1, 'lines' => ['setup refused: ' . count($scan['findings']) . ' suspicious file(s); see the alert email']];
            }
            if (!Init::install($config, $state, $scan['tmp'], $selfFiles)) {
                return ['exit' => 2, 'lines' => ['setup failed: cannot install the baseline in ' . $config->stateDir]];
            }
            // The setup scan was a full one, so the next full scan is due in a day, not on the next run.
            $state->writeJson('status.json', ['full' => ['last_run' => $now, 'last_complete' => $now, 'complete' => true, 'changes' => 0, 'critical' => 0, 'warning' => 0]]);
            self::rememberSettings($config, $state);
            @unlink($marker);

            if ($config->profile !== 'wordpress') {
                $wpLine = 'not detected';
            } elseif (!$config->wpChecksums) {
                $wpLine = 'yes';
            } elseif ($scan['core_verified'] === false) {
                $wpLine = "yes, but the official WordPress checksums could not be downloaded, so WordPress's own files were recorded without being compared to the official copies. Please ask $who to look into this.";
            } else {
                $wpLine = 'yes, checked against the official WordPress checksums';
            }
            $body = [
                "Site Sentinel is now watching $site.",
                '',
                'What was set up',
                '  Website folder: ' . $config->siteRoot,
                '  Files recorded: ' . number_format($scan['count']),
                '  WordPress: ' . $wpLine,
                '  Plugin and theme updates: ' . self::policy($config->autoAcceptUnverifiedUpdates),
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
            if ($config->heartbeatUrl === '') {
                $notes[] = 'No heartbeat is set, so nothing outside this server notices if Sentinel stops running. Add a "heartbeat =" line to settings.txt.';
            }
            if ($notes) {
                $body[] = '';
                $body[] = '--';
                $body[] = 'Notes for your web developer:';
                foreach ($notes as $n) {
                    $body[] = '  - ' . $n;
                }
            }
            $r = (new Alerter($channels))->send("Site Sentinel is now protecting $site", self::text($body), Finding::CRITICAL);
            $lines = [sprintf('setup complete: %d file(s) recorded for %s', $scan['count'], $site)];
            foreach ($r['results'] as $l) {
                $lines[] = 'alert ' . $l;
            }
            return ['exit' => $r['ok'] ? 0 : 2, 'lines' => $lines];
        } finally {
            $lock->release();
        }
    }

    /** Where the sentinel folder must not be, in words a site owner can act on. */
    public static function placementMessage(string $webRoot): string
    {
        return 'The sentinel folder is inside the public website folder (' . $webRoot . '), where its files could be downloaded by anyone. Move the whole sentinel folder to your home folder, next to public_html rather than inside it, update the cron job to the new location, and run it again.';
    }

    /**
     * settings.txt is meant to be edited by the owner, so a change is not treated as tampering.
     * It is announced, old value next to new, to the previous and the new recipients, in the
     * previous settings' words (site name, contact), and only trusted once that announcement
     * has gone out. Until then, alerts also go to whoever the change removed.
     *
     * This protects against mistakes and casual redirection. Anyone who can write Sentinel's
     * state folder can also edit what it remembers, which is why a heartbeat is recommended.
     *
     * @param Channel[] $channels extended in place while a change has not been announced
     * @return string[] output lines
     */
    private static function settingsChanged(Config $config, State $state, array &$channels, array $selfFiles, ?callable $mailer): array
    {
        $check = new SelfCheck($state, $selfFiles);
        if ($check->isTrusted('settings')) {
            return [];
        }
        try {
            $lock = Lock::acquire($state->path('lock'));
        } catch (\Throwable $e) {
            return [];
        }
        if ($lock === null) {
            return []; // another run is handling it
        }
        try {
            if ($check->isTrusted('settings')) {
                return [];
            }
            $old = self::lastSettings($state);
            $before = $old !== null ? (array)$old['emails'] : array_values(array_filter((array)$state->readJson('settings-recipients.json'), 'is_string'));
            $after = self::recipients($config);
            $new = $config->settings;
            $site = $old !== null && (string)$old['website'] !== '' ? (string)$old['website'] : $config->siteName;
            $who = self::who($old !== null ? (string)$old['contact'] : $config->contact);

            $body = ["The Site Sentinel settings for $site were changed:", ''];
            $labels = [
                'emails' => 'Alerts go to',
                'website' => 'Website name',
                'contact' => 'Contact named in alerts',
                'approve_updates' => 'Plugin and theme updates',
                'heartbeat' => 'Heartbeat',
                'from' => 'Alerts are sent from',
            ];
            $show = function (string $k, $v) use ($config): string {
                if ($k === 'emails') {
                    return $v ? implode(', ', (array)$v) : '(nobody)';
                }
                if ($k === 'approve_updates') {
                    return self::policy($v === null ? $config->autoAcceptUnverifiedUpdates : (bool)$v);
                }
                return (string)$v !== '' ? (string)$v : '(not set)';
            };
            if ($old === null) {
                $body[] = "  Sentinel has no record of the previous settings (the record may have been deleted).";
                $body[] = '  Alerts went to: ' . ($before ? implode(', ', $before) : '(unknown)');
                foreach ($labels as $k => $label) {
                    $body[] = "  $label: " . $show($k, $new[$k] ?? null);
                }
            } else {
                foreach ($labels as $k => $label) {
                    $was = $old[$k] ?? null;
                    $now = $new[$k] ?? null;
                    $same = $k === 'emails'
                        ? array_map('strtolower', (array)$was) == array_map('strtolower', (array)$now)
                        : $show($k, $was) === $show($k, $now);
                    if (!$same) {
                        $body[] = "  $label: " . $show($k, $now) . ' (was: ' . $show($k, $was) . ')';
                    }
                }
                if (count($body) === 2) {
                    $body[] = '  (only comments or formatting changed)';
                }
            }
            $body[] = '';
            $body[] = "If you made this change, there is nothing to do. If you did not, contact $who straight away:";
            $body[] = 'someone may be trying to redirect the security alerts for your website.';

            $notify = $channels;
            $removed = array_values(array_diff(array_map('strtolower', $before), array_map('strtolower', $after)));
            if ($removed) {
                $notify[] = new Channel(new EmailNotifier($removed, (string)($new['from'] ?? ''), $mailer), Finding::INFO);
            }
            $r = (new Alerter($notify))->send("Site Sentinel settings changed for $site", self::text($body), Finding::CRITICAL);
            $delivered = $r['attempted'] > 0 && strpos(implode("\n", $r['results']), 'FAILED') === false;
            if ($delivered) {
                $check->trust('settings');
                self::rememberSettings($config, $state);
            } elseif ($removed) {
                // Not announced yet: retried on the next run, and meanwhile nobody is cut off.
                $channels[] = new Channel(new EmailNotifier($removed, (string)($new['from'] ?? ''), $mailer), Finding::WARNING);
            }
            return array_map(function ($l) {
                return 'settings notice ' . $l;
            }, $r['results']);
        } finally {
            $lock->release();
        }
    }

    /**
     * settings.txt cannot be used, so the last settings that worked are in use (Config::load).
     * Said once a day to the people those settings alert, and to any valid address in the file.
     *
     * @param Channel[] $channels
     * @return string[]
     */
    private static function settingsProblem(Config $config, State $state, array $channels, ?callable $mailer, int $now): array
    {
        $inUse = self::recipients($config);
        $extra = array_values(array_diff(
            array_map('strtolower', Settings::emailsLeniently($config->settingsFile)),
            array_map('strtolower', $inUse)
        ));
        if ($extra) {
            $channels[] = new Channel(new EmailNotifier($extra, (string)($config->settings['from'] ?? ''), $mailer), Finding::INFO);
        }
        $site = $config->siteName;
        $body = [
            "settings.txt for $site has a problem, so Site Sentinel is still using the last settings that",
            'worked. The website is still being monitored, and alerts still go to: ' . implode(', ', $inUse),
            '',
            'The problem:',
            '  ' . $config->settingsProblem,
            '',
            'Please correct settings.txt, or contact ' . self::who($config->contact) . '. Until it is corrected,',
            'changes made in settings.txt have no effect.',
        ];
        self::alertOnce($state, $channels, $now, 'settings-problem:' . $config->settingsProblem, "Site Sentinel settings problem on $site", self::text($body));
        return ['settings problem: ' . $config->settingsProblem . ' (using the last settings that worked)'];
    }

    /** @param Channel[] $channels */
    private static function recordsMissing(Config $config, State $state, array $channels, ?callable $mailer, int $now): array
    {
        $old = self::lastSettings($state);
        $extra = $old !== null ? array_values(array_diff(array_map('strtolower', (array)$old['emails']), array_map('strtolower', self::recipients($config)))) : [];
        if ($extra) {
            $channels[] = new Channel(new EmailNotifier($extra, (string)($config->settings['from'] ?? ''), $mailer), Finding::INFO);
        }
        $site = $config->siteName;
        $body = [
            "Site Sentinel's record of the files of $site is missing, although it was set up before,",
            'so it cannot check the website. Someone who can change the website\'s files may have removed it.',
            '',
            'Please contact ' . self::who($old !== null ? (string)$old['contact'] : $config->contact) . ' and forward this email.',
            '',
            '--',
            'Technical details for your web developer:',
            '  ' . $state->path('baseline.txt') . ' is missing, but the state folder shows an earlier setup.',
            '  Sentinel will not set itself up again over an earlier install. To start from scratch, check',
            '  the site, delete the whole state folder and create ' . self::MARKER . ' next to sentinel.php.',
        ];
        self::alertOnce($state, $channels, $now, 'records-missing', "Security alert: Site Sentinel's records were removed on $site", self::text($body));
        return ['exit' => 2, 'lines' => ['error: the baseline is missing on a site that was set up before; see the alert email']];
    }

    /** What is remembered once settings are in use and announced. */
    private static function rememberSettings(Config $config, State $state): void
    {
        $state->writeJson('settings-recipients.json', self::recipients($config));
        if ($config->settings) {
            $state->writeJson(Config::LAST_GOOD_SETTINGS, $config->settings);
        }
    }

    /** @return array<string,mixed>|null */
    private static function lastSettings(State $state): ?array
    {
        $a = $state->readJson(Config::LAST_GOOD_SETTINGS);
        $s = $a ? Settings::fromArray($a) : null;
        return $s !== null ? $s->toArray() : null;
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

    private static function who(string $contact): string
    {
        return $contact !== '' ? $contact : 'your web developer';
    }

    private static function policy(bool $auto): string
    {
        return $auto ? 'approved automatically' : 'each one reported for review';
    }

    /** @param string[] $lines */
    private static function text(array $lines): string
    {
        return implode("\n", array_map([Finding::class, 'line'], $lines)) . "\n";
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
        $r = (new Alerter($channels))->send($subject, Finding::shown($body), Finding::CRITICAL);
        $log->commit([$f], $r['ok'] ? [$f] : [], $now);
    }
}
