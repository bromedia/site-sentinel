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
        $rulesFile = $this->state->path('rules.json');
        $rules = is_file($rulesFile) ? Rules::load($rulesFile) : Rules::builtin();
        $budget = $budget ?? Budget::forConfig($this->config);
        $resume = $this->state->readJson('resume.json');
        $startAfter = (string)($resume[$mode] ?? '');

        $wpOn = $this->config->profile === 'wordpress';
        $wp = $wpOn && $this->config->wpChecksums ? new WpChecksum($this->http, $this->config, $this->state->path('cache')) : null;
        $analyzer = new Analyzer(
            $this->config,
            new PatternScanner($rules, $this->config->maxScanBytes),
            new LocationScanner($this->config),
            $wp,
            ExternalScanner::fromConfig($this->config)
        );

        $d = (new Differ($this->config))->diff($baselineFile, $startAfter, $budget, $full);
        $oldVersions = $this->state->readJson('versions.json');
        $newVersions = $wpOn ? VersionTracker::read($this->config) : [];
        $a = $analyzer->analyze($d['changes'], $oldVersions, $newVersions);

        $findings = $a['findings'];
        foreach ($d['unreadable'] as $dir) {
            $findings[] = new Finding(Finding::WARNING, (string)$dir, 'unreadable-dir', 'Directory could not be read');
        }
        foreach ((new SelfCheck($this->state, $this->selfFiles))->check() as $f) {
            $findings[] = $f;
        }

        $updates = [];
        foreach ($d['changes'] as $c) {
            if (isset($a['hold'][$c['path']])) {
                continue;
            }
            $updates[$c['path']] = in_array($c['type'], ['removed', 'dropped'], true) ? null : $c['new'];
        }
        if ($updates) {
            Baseline::applyUpdates($baselineFile, $updates, $baselineFile);
        }

        if ($d['complete']) {
            unset($resume[$mode]);
        } else {
            $resume[$mode] = $d['stopped_at'];
        }
        $this->state->writeJson('resume.json', $resume);
        if ($d['complete'] && $wpOn) {
            $store = [];
            foreach ($newVersions as $g => $v) {
                if (!isset($a['held_groups'][$g])) {
                    $store[$g] = $v;
                } elseif (isset($oldVersions[$g])) {
                    $store[$g] = $oldVersions[$g];
                }
            }
            $this->state->writeJson('versions.json', $store);
        }

        $now = ($this->clock)();
        $log = new AlertLog($this->state);
        $due = $log->due($findings, $now, $this->config->remindHours * 3600);
        $alertLines = [];
        $sent = [];
        if ($due) {
            $digest = Digest::build($this->config->siteName, (string)gethostname(), $now, $due, $a['info'], $a['notes']);
            $r = (new Alerter($this->channels))->send($digest['subject'], $digest['body'], $digest['top']);
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
                $lines[] = '  ' . Finding::label($f->severity) . ' ' . $f->path . ' ' . $f->rule;
            }
        }
        $lines = array_merge($lines, $alertLines);

        if ($this->config->heartbeatUrl !== '') {
            $hb = $this->http->request('GET', $this->config->heartbeatUrl, '', [], 10);
            if ($hb['status'] < 200 || $hb['status'] >= 300) {
                $lines[] = 'heartbeat failed (' . ($hb['status'] === 0 ? 'network error' : 'HTTP ' . $hb['status']) . ')';
            }
        }
        return ['exit' => ($crit + $warn) > 0 ? 1 : 0, 'lines' => $lines];
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
                $digest = Digest::build($this->config->siteName, (string)gethostname(), $now, $due, [], []);
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
