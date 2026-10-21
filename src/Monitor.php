<?php
declare(strict_types=1);

namespace Sentinel;

final class Monitor
{
    private static $niced = false;

    private $config;
    private $state;
    private $http;
    /** @var Channel[] */
    private $channels;
    /** @var array<string,string> */
    private $selfFiles;
    private $clock;

    /**
     * @param Channel[] $channels
     * @param array<string,string> $selfFiles label => path, tracked by SelfCheck
     */
    public function __construct(Config $config, State $state, HttpClient $http, array $channels, array $selfFiles, ?callable $clock = null)
    {
        $this->config = $config;
        $this->state = $state;
        $this->http = $http;
        $this->channels = $channels;
        $this->selfFiles = $selfFiles;
        $this->clock = $clock ?? function (): int {
            return time();
        };
    }

    /** @return array{exit:int, lines:string[]} */
    public function run(string $mode, ?Budget $budget = null): array
    {
        if (!in_array($mode, ['check', 'full'], true)) {
            throw new \InvalidArgumentException("unknown mode '$mode'");
        }
        if (!$this->channels) {
            return ['exit' => 2, 'lines' => ['no alert channels configured: add one to the config, then run test-alert']];
        }
        try {
            $lock = Lock::acquire($this->state->path('lock'));
        } catch (\Throwable $e) {
            return $this->failed($e);
        }
        if ($lock === null) {
            return ['exit' => 0, 'lines' => ['another run is in progress; skipping']];
        }
        if (!self::$niced && function_exists('proc_nice')) {
            self::$niced = true;
            @proc_nice(10);
        }
        try {
            return $this->execute($mode, $budget);
        } catch (\Throwable $e) {
            return $this->failed($e);
        } finally {
            $lock->release();
        }
    }

    private function execute(string $mode, ?Budget $budget): array
    {
        $full = $mode === 'full';
        $baselineFile = $this->state->path('baseline.txt');
        if (!is_file($baselineFile)) {
            throw new \RuntimeException('no baseline found; run "init" first');
        }
        // Check Sentinel's own files first: a rules or dismissals file changed outside Sentinel is
        // reported and not used, so a hand-placed file cannot switch detection off for this run.
        // settings.txt is edited by its owner and announced by Run, so it is not tamper-checked here.
        $tracked = $this->selfFiles;
        unset($tracked['settings']);
        $selfCheck = new SelfCheck($this->state, $tracked);
        $selfFindings = $selfCheck->check();
        $untrusted = $selfCheck->untrusted();
        $selfNotes = [];
        $rulesFile = $this->state->path('rules.json');
        if (in_array('rules', $untrusted, true)) {
            $rules = Rules::builtin();
            $selfNotes[] = 'rules.json changed outside update-rules, so the built-in rules were used; run accept --self only if you changed it deliberately';
        } else {
            $rules = is_file($rulesFile) ? Rules::load($rulesFile) : Rules::builtin();
        }
        $dismissals = null;
        if (in_array('dismissals', $untrusted, true)) {
            $selfNotes[] = 'dismissals.json changed outside the dismiss command, so no dismissals were applied; run accept --self only if you changed it deliberately';
        } else {
            $dismissals = new Dismissals($this->state);
        }
        $budget = $budget ?? Budget::forConfig($this->config);
        $resume = $this->state->readJson('resume.json');
        $startAfter = (string)($resume[$mode] ?? '');

        $wpOn = $this->config->hasWordPress();
        $wp = $wpOn && $this->config->wpChecksums ? new WpChecksum($this->http, $this->config, $this->state->path('cache')) : null;
        $detections = new Detections($this->state);
        if ($dismissals !== null) {
            foreach (array_keys($detections->all()) as $path) {
                if ($detections->dismissed((string)$path, $dismissals)) {
                    $detections->resolve((string)$path); // reviewed as harmless with "dismiss"
                }
            }
        }
        $analyzer = new Analyzer(
            $this->config,
            new PatternScanner($rules, $this->config->maxScanBytes),
            new LocationScanner($this->config),
            $wp,
            ExternalScanner::fromConfig($this->config),
            $dismissals,
            $detections->all()
        );

        $differ = new Differ($this->config);
        $d = $differ->diff($baselineFile, $startAfter, $budget, $full);
        $oldVersions = $this->state->readJson('versions.json');
        $newVersions = $wpOn ? VersionTracker::read($this->config) : [];
        $now = ($this->clock)();
        $a = $analyzer->analyze($d['changes'], $oldVersions, $newVersions, false, $now);

        $findings = $a['findings'];
        foreach ($d['unreadable'] as $dir) {
            $findings[] = new Finding(Finding::WARNING, (string)$dir, 'unreadable-dir', 'Directory could not be read');
        }
        foreach ($selfFindings as $f) {
            $findings[] = $f;
        }
        $a['notes'] = array_merge($selfNotes, $a['notes']);

        // Detections are remembered until reviewed. One reported earlier whose file changed or
        // disappeared outside this slice is said again here, keyed on what is there now.
        foreach ($a['detected'] as $path => $det) {
            if (Detections::tracked($this->config, (string)$path)) {
                $detections->record((string)$path, (string)$det['sha256'], (array)$det['rules'], (int)$det['severity'], $now);
            }
        }
        foreach (array_keys($a['resolved']) as $path) {
            $detections->resolve((string)$path);
        }
        foreach ($detections->all() as $path => $entry) {
            $path = (string)$path;
            if (isset($a['hold'][$path]) || isset($a['detected'][$path])) {
                continue;
            }
            $abs = $this->config->abs($path);
            // The official file can be back with nothing looking changed (same size and timestamp
            // as the baseline), so it would never reach the checksum check of a changed file.
            if ($wp !== null && file_exists($abs) && !$this->config->isUploads($path) && $wp->verify($path) === WpChecksum::VERIFIED) {
                $detections->resolve($path);
                continue;
            }
            if (!file_exists($abs)) {
                $findings[] = Analyzer::unresolvedFinding($path, '', $entry, 'removed');
            } elseif (($current = (string)@hash_file('sha256', $abs)) !== $entry['sha256']) {
                $findings[] = Analyzer::unresolvedFinding($path, $current, $entry, 'changed');
            }
        }

        $updates = [];
        foreach ($d['changes'] as $c) {
            if (isset($a['hold'][$c['path']])) {
                continue;
            }
            $updates[$c['path']] = in_array($c['type'], ['removed', 'dropped'], true) ? null : $c['new'];
        }
        // Saving state must not stop this run's findings from being alerted: a full disk
        // is exactly when something may be wrong. The baseline is saved first and the
        // cursor only advances after it, so a failed save means this slice is rescanned.
        try {
            if ($updates) {
                Baseline::applyUpdates($baselineFile, $updates, $baselineFile);
            }
            $detections->save();

            // What holds back a plugin's version, gathered over the whole traversal: a scan that
            // resumes across runs sees a held file in one slice and records versions in the last.
            $holdsKey = $mode . '-holds';
            $carried = $startAfter !== '' ? (array)($resume[$holdsKey] ?? []) : [];
            $versionHolds = array_fill_keys((array)($carried['update'] ?? []), true) + $a['version_holds'];
            $heldGroups = array_fill_keys((array)($carried['held'] ?? []), true);
            $heldVersionFiles = array_fill_keys((array)($carried['version_file'] ?? []), true);
            foreach (array_keys($a['hold']) as $path) {
                $g = Analyzer::groupOf((string)$path, $this->config->nestedWordPress);
                $heldGroups[$g] = true;
                if (VersionTracker::versionFile($this->config, $g) === (string)$path) {
                    $heldVersionFiles[$g] = true;
                }
            }
            if ($d['complete']) {
                unset($resume[$mode], $resume[$holdsKey]);
            } else {
                $resume[$mode] = $d['stopped_at'];
                $resume[$holdsKey] = ['update' => array_keys($versionHolds), 'held' => array_keys($heldGroups), 'version_file' => array_keys($heldVersionFiles)];
            }
            $this->state->writeJson('resume.json', $resume);
            if ($d['complete'] && $wpOn) {
                $store = [];
                foreach ($newVersions as $g => $v) {
                    // A version is recorded only once it has been accepted: not while the update
                    // waits for review or its copy, and not while the file that declares the
                    // version is itself held. Recording an unaccepted version would lose where
                    // the plugin came from (a wordpress.org release), so a later fake bump could
                    // pass as a premium update. A plugin with no recorded version yet (one with a
                    // file flagged at setup) gets none while any of its files is held, or a later
                    // bump would vouch for the flagged file. A held file does not freeze a version
                    // already recorded: later quiet edits would then pass as that update.
                    $unvouched = !isset($oldVersions[$g]) && isset($heldGroups[$g]);
                    if (!isset($versionHolds[$g]) && !isset($heldVersionFiles[$g]) && !$unvouched) {
                        $store[$g] = $v;
                    } elseif (isset($oldVersions[$g])) {
                        $store[$g] = $oldVersions[$g];
                    }
                }
                $this->state->writeJson('versions.json', $store);
            }
        } catch (\Throwable $e) {
            $findings[] = new Finding(
                Finding::CRITICAL,
                'sentinel',
                'state-write-failed',
                'Scan state could not be saved (' . $e->getMessage() . '). The previous baseline was kept and this part of the site will be scanned again; free disk space or check the state directory.',
                sha1($e->getMessage())
            );
        }

        $log = new AlertLog($this->state);
        $due = $log->due($findings, $now, $this->config->remindHours * 3600);
        $alertLines = [];
        $sent = [];
        if ($due) {
            $digest = Digest::forConfig($this->config, $now, $due, $a['info'], $a['notes']);
            // The full record goes with every alert: findings, every changed file and what became of it.
            $attachment = null;
            try {
                $file = Report::write(
                    $this->state->path('reports'),
                    [
                        'site' => $this->config->siteName,
                        'root' => $this->config->siteRoot,
                        'ts' => $now,
                        'version' => VERSION,
                        'mode' => $mode,
                        'complete' => $d['complete'],
                        'nested' => $this->config->nestedWordPress,
                    ],
                    $findings,
                    array_map(function (Finding $f): string {
                        return $f->key();
                    }, $due),
                    $d['changes'],
                    $a['outcomes'],
                    $a['notes']
                );
                $attachment = Report::attachment($file, Report::displayPath($this->state->dir(), basename($file)));
            } catch (\Throwable $e) {
                // An alert without its report beats no alert: say why, and send it anyway.
                $digest['body'] = Digest::withReportNote($digest['body'], 'The full report could not be saved: ' . $this->plainReason($e), $this->config->audience === 'client');
            }
            if ($attachment !== null && $this->config->audience === 'client') {
                // Only the email that really carries the file tells the owner it is attached; every
                // other channel, and an email sent without the file after all, uses the plain body.
                $attachment['body'] = Digest::forConfig($this->config, $now, $due, $a['info'], $a['notes'], $attachment['name'])['body'];
            }
            $r = (new Alerter($this->channels))->send($digest['subject'], $digest['body'], $digest['top'], $attachment);
            foreach ($r['results'] as $line) {
                $alertLines[] = 'alert ' . $line;
            }
            if ($r['ok']) {
                $sent = $due;
            }
        }
        $log->commit($findings, $sent, $now);

        $crit = 0;
        $warn = 0;
        foreach ($findings as $f) {
            if ($f->severity >= Finding::CRITICAL) {
                $crit++;
            } elseif ($f->severity === Finding::WARNING) {
                $warn++;
            }
        }
        $lines = [sprintf(
            '%s: %d change(s), %d critical, %d warning, %s',
            $mode,
            count($d['changes']),
            $crit,
            $warn,
            $d['complete'] ? 'scan complete' : 'partial scan, resuming after ' . $d['stopped_at']
        )];
        foreach ($findings as $f) {
            if ($f->severity >= Finding::WARNING) {
                $lines[] = Finding::line('  ' . Finding::label($f->severity) . ' ' . $f->path . ' ' . $f->rule . (Dismissals::dismissable($f) ? ' [id ' . $f->id() . ']' : ''));
            }
        }
        $lines = array_merge($lines, $alertLines);

        // Scan history for doctor: a run that processed a slice is not a complete traversal.
        $status = $this->state->readJson('status.json');
        $previous = $status[$mode] ?? [];
        $status[$mode] = [
            'last_run' => $now,
            'last_complete' => $d['complete'] ? $now : (int)($previous['last_complete'] ?? 0),
            'complete' => $d['complete'],
            'changes' => count($d['changes']),
            'critical' => $crit,
            'warning' => $warn,
        ];
        $this->state->writeJson('status.json', $status);

        if ($this->config->heartbeatUrl !== '') {
            $hb = $this->http->request('GET', $this->config->heartbeatUrl, '', [], 10);
            if ($hb['status'] < 200 || $hb['status'] >= 300) {
                $lines[] = 'heartbeat failed (' . ($hb['status'] === 0 ? 'network error' : 'HTTP ' . $hb['status']) . ')';
            }
        }
        return ['exit' => ($crit + $warn) > 0 ? 1 : 0, 'lines' => $lines];
    }

    /** The reason an exception gives, without the account's absolute paths. */
    private function plainReason(\Throwable $e): string
    {
        $text = str_replace([$this->state->dir() . '/', $this->state->dir(), rtrim($this->config->siteRoot, '/') . '/', rtrim($this->config->siteRoot, '/')], ['', 'state', '', '.'], $e->getMessage());
        return trim(Finding::line($text));
    }

    private function failed(\Throwable $e): array
    {
        return ['exit' => 2, 'lines' => array_merge(['error: ' . $e->getMessage()], $this->reportError($e->getMessage()))];
    }

    /**
     * Alerts about a tool error (deduplicated by message) so that a monitor that cannot do its job is never silent.
     *
     * @return string[] output lines describing what was sent
     */
    public function reportError(string $message, int $severity = Finding::CRITICAL): array
    {
        $lines = [];
        try {
            $now = ($this->clock)();
            $f = new Finding($severity, 'sentinel', 'run-error', $message, sha1($message));
            $log = new AlertLog($this->state);
            $due = $log->due([$f], $now, $this->config->remindHours * 3600);
            $sent = [];
            if ($due) {
                $digest = Digest::forConfig($this->config, $now, $due, [], []);
                $r = (new Alerter($this->channels))->send($digest['subject'], $digest['body'], $digest['top']);
                foreach ($r['results'] as $line) {
                    $lines[] = 'alert ' . $line;
                }
                if ($r['ok']) {
                    $sent = $due;
                }
            }
            $log->commit([$f], $sent, $now);
        } catch (\Throwable $inner) {
            $lines[] = 'could not send the error alert: ' . $inner->getMessage();
        }
        return $lines;
    }
}
