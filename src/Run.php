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
    /** The welcome email, kept until it has gone out: it is also the owner's test that alerts arrive. */
    private const WELCOME = 'welcome-pending.json';
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

        $welcome = self::sendWelcome($config, $state, $channels);
        $lines = $welcome['lines'];
        if ($config->settingsProblem !== '') {
            $lines = array_merge($lines, self::settingsProblem($config, $state, $channels, $mailer, $clock()));
        } elseif (isset($selfFiles['settings'])) {
            $lines = array_merge($lines, self::settingsChanged($config, $state, $channels, $selfFiles, $mailer));
        }
        $monitor = new Monitor($config, $state, $http, $channels, $selfFiles, $clock);
        $r = $monitor->run('check');
        if ($r['exit'] !== 2 && self::fullDue($state, $clock())) {
            $f = $monitor->run('full');
            $r = ['exit' => max($r['exit'], $f['exit']), 'lines' => array_merge($r['lines'], $f['lines'])];
        }
        $r['lines'] = $r['exit'] === 0 ? $lines : array_merge($lines, $r['lines']);
        if (!$welcome['ok']) {
            $r['exit'] = 2; // email is not getting through
        }
        return $r;
    }

    /**
     * Sends the welcome email if it is still waiting, and forgets it once it has gone out.
     *
     * @param Channel[] $channels
     * @return array{ok:bool, lines:string[]}
     */
    private static function sendWelcome(Config $config, State $state, array $channels): array
    {
        $w = $state->readJson(self::WELCOME);
        if (!isset($w['subject'], $w['body'])) {
            return ['ok' => true, 'lines' => []];
        }
        $body = (string)$w['body'];
        $attachment = null;
        if (isset($w['report'])) {
            // The report was saved at setup; every try (the first included) re-reads that copy.
            try {
                $file = (string)$w['report'];
                if (dirname($file) !== $state->path('reports')) {
                    throw new \RuntimeException('not a saved report');
                }
                $attachment = Report::attachment($file, Report::displayPath($state->dir(), basename($file)));
                if (isset($w['body_attached'])) {
                    $attachment['body'] = (string)$w['body_attached'];
                }
            } catch (\Throwable $e) {
                // The welcome is also the test that alerts arrive: it goes out anyway, and says so.
                $body = self::withNote($body, 'The full report could not be attached.');
            }
        }
        $r = (new Alerter($channels, self::scrubber($config, $state)))->send((string)$w['subject'], $body, Finding::CRITICAL, $attachment);
        $ok = $r['attempted'] > 0 && strpos(implode("\n", $r['results']), 'FAILED') === false;
        if ($ok) {
            @unlink($state->path(self::WELCOME));
        }
        return ['ok' => $ok, 'lines' => array_map(function ($l) {
            return 'welcome ' . $l;
        }, $r['results'])];
    }

    public static function fullDue(State $state, int $now): bool
    {
        if (isset($state->readJson('resume.json')['full'])) {
            return true; // finish a partial full scan before starting over
        }
        $full = (array)($state->readJson('status.json')['full'] ?? []);
        return $now - (int)($full['last_complete'] ?? 0) >= self::FULL_EVERY;
    }

    /** Whether the next run sets Sentinel up: the marker is there and nothing shows an earlier install. Reads only. */
    public static function setupPending(string $script, string $stateDir): bool
    {
        if (!is_file(dirname($script) . '/' . self::MARKER) || is_file($stateDir . '/baseline.txt')) {
            return false;
        }
        foreach (self::INSTALLED as $f) {
            if (file_exists($stateDir . '/' . $f)) {
                return false;
            }
        }
        return true;
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
                // The email names the folder as the owner knows it, never by its absolute path.
                $shown = self::placementMessage($config->siteFolderLabel());
                self::alertOnce($config, $state, $channels, $now, 'setup-placement', "Site Sentinel setup could not finish on $site", self::text(self::withFooter(['Site Sentinel was not started.', '', $shown, '', "Please forward this email to $who."], $config->contact)));
                return ['exit' => 2, 'lines' => ['setup failed: ' . $msg]];
            }

            $scan = Init::scan($config, $state, $http, $selfFiles);
            // Files that look like hacking are left out of the record, so every later run examines
            // them again as new files and keeps reporting them until they are dealt with. Refusing
            // the whole setup instead would leave the rest of the website unwatched meanwhile.
            $flagged = [];
            foreach ($scan['findings'] as $f) {
                $flagged[$f->path] = null;
            }
            if ($flagged) {
                try {
                    Baseline::applyUpdates($scan['tmp'], $flagged, $scan['tmp']);
                } catch (\Throwable $e) {
                    @unlink($scan['tmp']);
                    return ['exit' => 2, 'lines' => ['setup failed: ' . $e->getMessage()]];
                }
            }
            $untrusted = array_map(function ($path) use ($config) {
                return Analyzer::groupOf((string)$path, $config->nestedWordPress);
            }, array_keys($flagged));
            if (!Init::install($config, $state, $scan['tmp'], $selfFiles, $untrusted)) {
                return ['exit' => 2, 'lines' => ['setup failed: cannot install the baseline in ' . $config->stateDir]];
            }
            // Remembered like any detection, so rewriting a flagged file until nothing matches does
            // not make it go quiet before someone has reviewed it.
            $detections = new Detections($state);
            foreach ($scan['findings'] as $f) {
                if (Detections::tracked($config, $f->path) && !in_array($f->rule, Digest::MONITORING, true)) {
                    $earlier = $detections->all()[$f->path] ?? [];
                    $rules = array_values(array_merge((array)($earlier['rules'] ?? []), [$f->rule]));
                    $detections->record($f->path, $f->hash, $rules, max((int)($earlier['severity'] ?? 0), $f->severity), $now);
                }
            }
            $detections->save();
            // The setup scan was a full one, so the next full scan is due in a day, not on the next run.
            $state->writeJson('status.json', ['full' => ['last_run' => $now, 'last_complete' => $now, 'complete' => true, 'changes' => 0, 'critical' => 0, 'warning' => 0]]);
            self::rememberSettings($config, $state);
            @unlink($marker);

            $recorded = max(0, $scan['count'] - count($flagged));
            $notes = array_merge($scan['notes'], array_map(function ($l) {
                return sprintf("'%s' is a symlink to a directory (%s) and is not monitored.", $l[0], $l[1]);
            }, $scan['symlinkDirs']));
            if ($config->heartbeatUrl === '') {
                $notes[] = 'Optional: no heartbeat is set. A "heartbeat =" line in settings.txt lets an outside service (for example healthchecks.io) warn you if Sentinel ever stops running; nothing on this server can notice that.';
            }
            // Kept until it has gone out, and retried on later runs; the setup itself is not redone.
            $subject = $flagged ? "Security alert: Site Sentinel is now protecting $site and found possible hacking" : "Site Sentinel is now protecting $site";
            $pending = ['subject' => $subject, 'body' => self::welcomeBody($config, $scan, array_keys($flagged), $recorded, $who, $notes, '')];
            if ($flagged) {
                // The full record of what was found goes with the email, and stays on the server.
                try {
                    $pending['report'] = Report::write(
                        $state->path('reports'),
                        ['site' => $site, 'root' => $config->siteRoot, 'home' => $config->accountHome, 'folders' => [dirname(dirname($state->dir()))], 'ts' => $now, 'version' => VERSION, 'mode' => 'setup', 'complete' => true, 'nested' => $config->nestedWordPress],
                        $scan['findings'],
                        array_map(function (Finding $f): string {
                            return $f->key();
                        }, $scan['findings']),
                        [],
                        [],
                        $notes
                    );
                    // Sent instead of 'body' by a try that really attaches the report: it says so.
                    $pending['body_attached'] = self::welcomeBody($config, $scan, array_keys($flagged), $recorded, $who, $notes, basename($pending['report']));
                } catch (\Throwable $e) {
                    // Setup and the welcome do not depend on the report.
                    $pending['body'] = self::withNote($pending['body'], 'The full report could not be saved: ' . self::plainReason($config, $state, $e));
                }
            }
            $state->writeJson(self::WELCOME, $pending);
            $w = self::sendWelcome($config, $state, $channels);
            // Recorded as reported, so "dismiss <id>" works from this email and the daily reminders
            // start from now. If the email did not go out, the next check alerts them itself.
            (new AlertLog($state))->commit($scan['findings'], $w['ok'] ? $scan['findings'] : [], $now);
            $line = sprintf('setup complete: %d file(s) recorded for %s', $recorded, $site);
            if ($flagged) {
                $line .= sprintf('; %d suspicious file(s) left out and reported, see the alert email', count($flagged));
            }
            $lines = array_merge([$line], $w['lines']);
            return ['exit' => $w['ok'] ? ($flagged ? 1 : 0) : 2, 'lines' => $lines];
        } finally {
            $lock->release();
        }
    }

    /**
     * The welcome email. $attached is the report's file name when this version goes out with the
     * report attached (it then says so above the footer), and '' otherwise.
     *
     * @param string[] $flagged
     * @param string[] $notes
     */
    private static function welcomeBody(Config $config, array $scan, array $flagged, int $recorded, string $who, array $notes, string $attached): string
    {
        $site = $config->siteName;
        $body = ["Site Sentinel is now watching $site.", ''];
        if ($flagged) {
            $body = [
                "Site Sentinel is now watching $site, but the website already contains files that look like",
                'hacking tools or tampering:',
            ];
            $body = array_merge($body, Digest::capped(array_map(function ($path) {
                return '  - ' . $path;
            }, $flagged), $attached));
            $body[] = '';
            $body[] = 'These files were not recorded as normal, so Site Sentinel keeps reporting them until they';
            $body[] = "have been dealt with. Please forward this email to $who today.";
            $body[] = 'The rest of the website is being watched from now on.';
            $body[] = '';
        }
        $body = array_merge($body, [
            'What was set up',
            '  Website folder: ' . $config->siteFolderLabel(),
            '  Files recorded: ' . number_format($recorded),
            '  WordPress: ' . self::wordpressLine($config, $scan, $who),
        ], $config->hasWordPress() ? ['  Plugin and theme updates: ' . self::policy($config->autoAcceptUnverifiedUpdates)] : [], [
            '  Changed files: ' . ($config->quietChanges ? 'recorded quietly unless they look like hacking' : 'you are told about every change that cannot be verified'),
        ], $config->quietFolders ? ['  Recorded quietly in: ' . implode(', ', $config->quietFolders)] : [], [
            '  Alerts go to: ' . implode(', ', self::recipients($config)),
            '',
            'What happens now',
            '  The website is checked each time the scheduled job runs, with a deeper scan once a day.',
            "  You will only hear from Site Sentinel when something needs attention.",
            '',
            "If you ever receive an alert, forward it to $who.",
            '',
            'This email is also the test that alerts reach you: if it landed in spam, mark it as not spam.',
        ]);
        if ($attached !== '') {
            $body[] = '';
            $body[] = Digest::attachedNote($attached);
        }
        $developer = [];
        if ($flagged) {
            $developer[] = '--';
            $developer[] = 'Technical details for your web developer:';
            foreach ($scan['findings'] as $f) {
                $developer[] = '  ' . Finding::label($f->severity) . ' ' . $f->rule . ' ' . $f->path . ': ' . $f->message . (Dismissals::dismissable($f) ? ' [id ' . $f->id() . ']' : '');
            }
            $developer[] = '  These files are not in the baseline and are reported again on later runs. Clean or';
            $developer[] = '  remove a file, or if it is harmless, dismiss it by its id; then accept --path=<file>.';
        }
        if ($notes) {
            if ($developer) {
                $developer[] = '';
            }
            $developer[] = '--';
            $developer[] = 'Notes for your web developer:';
            foreach ($notes as $n) {
                $developer[] = '  - ' . $n;
            }
        }
        return self::text(self::withFooter($body, $config->contact, $developer));
    }

    /**
     * The welcome email's WordPress line: every install found (the website folder and those in
     * subfolders) and whether the official checksums were actually compared, never claimed when
     * they could not be downloaded.
     */
    private static function wordpressLine(Config $config, array $scan, string $who): string
    {
        if (!$config->hasWordPress()) {
            return 'not detected';
        }
        $failed = [];
        foreach ($config->wpChecksums ? $config->wordpressInstalls() : [] as $p) {
            if (($scan['core_by_install'][$p] ?? null) === false) {
                $failed[] = $p === '' ? 'the website folder' : $p;
            }
        }
        $nested = $config->nestedWordPress;
        if (!$nested) {
            $line = 'yes';
        } elseif ($config->profile === 'wordpress') {
            $line = sprintf('yes, in the website folder and in %d subfolder%s (%s)', count($nested), count($nested) === 1 ? '' : 's', implode(', ', $nested));
        } else {
            $line = sprintf('%d site%s in subfolders (%s)', count($nested), count($nested) === 1 ? '' : 's', implode(', ', $nested));
        }
        if (!$config->wpChecksums) {
            return $line;
        }
        if ($failed) {
            $which = $nested ? ' for ' . implode(', ', $failed) : '';
            return $line . ", but the official WordPress checksums could not be downloaded$which, so WordPress's own files were recorded without being compared to the official copies. Please forward this email to $who so they can look into this.";
        }
        return $line . ($nested && count($config->wordpressInstalls()) > 1 ? ', each checked against the official WordPress checksums' : ', checked against the official WordPress checksums');
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
            $contact = $old !== null ? (string)$old['contact'] : $config->contact; // the trusted one, not the edited one
            $who = self::who($contact);

            $body = ["The Site Sentinel settings for $site were changed:", ''];
            $labels = [
                'emails' => 'Alerts go to',
                'website' => 'Website name',
                'contact' => 'Contact named in alerts',
                'approve_updates' => 'Plugin and theme updates',
                'changed_files' => 'Changed files',
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
                if ($k === 'changed_files') {
                    return $v === 'quiet' ? 'quiet' : 'tell me'; // absent (an install from before the setting) is the default, whatever the new config says
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
            $body[] = "If you made this change, there is nothing to do. If you did not, forward this email to $who straight away:";
            $body[] = 'someone may be trying to redirect the security alerts for your website.';

            $notify = $channels;
            $removed = array_values(array_diff(array_map('strtolower', $before), array_map('strtolower', $after)));
            if ($removed) {
                $notify[] = new Channel(new EmailNotifier($removed, (string)($new['from'] ?? ''), $mailer), Finding::INFO);
            }
            $r = (new Alerter($notify, self::scrubber($config, $state)))->send("Site Sentinel settings changed for $site", self::text(self::withFooter($body, $contact)), Finding::CRITICAL);
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
            'Please correct settings.txt, or forward this email to ' . self::who($config->contact) . '. Until it is corrected,',
            'changes made in settings.txt have no effect.',
        ];
        $body = self::withFooter($body, $config->contact);
        self::alertOnce($config, $state, $channels, $now, 'settings-problem:' . $config->settingsProblem, "Site Sentinel settings problem on $site", self::text($body));
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
        $contact = $old !== null ? (string)$old['contact'] : $config->contact; // the trusted one
        $body = self::withFooter([
            "Site Sentinel's record of the files of $site is missing, although it was set up before,",
            'so it cannot check the website. Someone who can change the website\'s files may have removed it.',
            '',
            'Please forward this email to ' . self::who($contact) . '.',
        ], $contact, [
            '--',
            'Technical details for your web developer:',
            '  ' . $state->path('baseline.txt') . ' is missing, but the state folder shows an earlier setup.',
            '  Sentinel will not set itself up again over an earlier install. To start from scratch, check',
            '  the site, delete the whole state folder and create ' . self::MARKER . ' next to sentinel.php.',
        ]);
        self::alertOnce($config, $state, $channels, $now, 'records-missing', "Security alert: Site Sentinel's records were removed on $site", self::text($body));
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

    /** How a body sentence refers to the contact: "the contact below" (named once, in the footer) or the web developer. */
    private static function who(string $contact): string
    {
        return Digest::whom($contact);
    }

    /**
     * Closes the owner-facing lines with the contact footer (after a blank line, directly above
     * the developer section when there is one), then adds that developer section.
     *
     * @param string[] $body
     * @param string[] $developer
     * @return string[]
     */
    private static function withFooter(array $body, string $contact, array $developer = []): array
    {
        $footer = Digest::footer($contact);
        if ($footer !== '') {
            $body[] = '';
            $body[] = $footer;
        } elseif ($developer) {
            $body[] = '';
        }
        return array_merge($body, $developer);
    }

    private static function policy(bool $auto): string
    {
        return $auto ? 'approved automatically' : 'each one reported for review';
    }

    /** The owner-facing part of a welcome gets the note, above the footer and the developer details. */
    private static function withNote(string $body, string $note): string
    {
        return Digest::withReportNote(rtrim($body, "\n"), $note, true) . "\n";
    }

    /** Why something failed, without the hosting account's absolute paths. */
    private static function plainReason(Config $config, State $state, \Throwable $e): string
    {
        $site = rtrim($config->siteRoot, '/');
        $text = str_replace([$state->dir() . '/', $state->dir(), $site . '/', $site], ['', 'state', '', '.'], $e->getMessage());
        return trim(Finding::line($text));
    }

    /** Nothing sent shows the hosting account's absolute paths (they contain its name). */
    private static function scrubber(Config $config, State $state): callable
    {
        return Report::pathScrubber($config->siteRoot, $config->accountHome, dirname(dirname($state->dir())));
    }

    /** @param string[] $lines */
    private static function text(array $lines): string
    {
        return implode("\n", array_map([Finding::class, 'line'], $lines)) . "\n";
    }

    /** Sends a setup problem once a day at most, not on every scheduled run. */
    private static function alertOnce(Config $config, State $state, array $channels, int $now, string $key, string $subject, string $body): void
    {
        $f = new Finding(Finding::CRITICAL, 'sentinel', 'setup', $subject, sha1($key));
        $log = new AlertLog($state);
        if (!$log->due([$f], $now, 86400)) {
            $log->commit([$f], [], $now);
            return;
        }
        $r = (new Alerter($channels, self::scrubber($config, $state)))->send($subject, Finding::shown($body), Finding::CRITICAL);
        $log->commit([$f], $r['ok'] ? [$f] : [], $now);
    }
}
