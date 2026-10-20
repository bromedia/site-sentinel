<?php

declare(strict_types=1);

namespace Sentinel;

final class DatabaseMonitor
{
    private $config;
    private $state;
    private $channels;
    private $clock;
    private $source;
    public function __construct(Config $c, State $state, array $channels, ?callable $clock = null, ?DatabaseSource $source = null)
    {
        $this->config = $c;
        $this->state = $state;
        $this->channels = $channels;
        $this->clock = $clock ?? function (): int {
            return time();
        };
        $this->source = $source;
    }
    private function source(Budget $budget): DatabaseSource
    {
        if (!$this->config->database['enabled']) {
            throw new DatabaseException('database monitoring is disabled; enable database.enabled and review its credential source');
        }
        return $this->source ?? new MysqlDatabase($this->config, $budget);
    }
    private function baseline(): array
    {
        $b = $this->state->readJson('database-baseline.json');
        if (($b['version'] ?? 0) !== 1 || !is_array($b['admins'] ?? null) || !is_array($b['options'] ?? null)) {
            throw new DatabaseException('database baseline missing/invalid; review administrators and options, then run db-init');
        }
        return $b;
    }
    public function accept(Budget $budget, string $scope = 'all', bool $initial = false, bool $force = false): array
    {
        if (!in_array($scope, ['all','admins','options'], true)) {
            return ['exit' => 2,'lines' => ['database scope must be all, admins or options']];
        }
        try {
            if ($initial && is_file($this->state->path('database-baseline.json')) && !$force) {
                throw new DatabaseException('database baseline already exists; review db-check and use db-accept --scope=admins|options');
            }
            $source = $this->source($budget);
            $snapshot = $source->snapshot();
            $b = $initial ? ['version' => 1,'admins' => [],'options' => [],'post_high_water' => $source->postStats(0)['max_id']] : $this->baseline();
            foreach (['admins','options'] as $key) {
                if ($scope === 'all' || $scope === $key) {
                    $b[$key] = $snapshot[$key];
                }
            }
            $this->state->writeJson('database-baseline.json', $b);
            return ['exit' => 0,'lines' => ['Trusted reviewed database ' . $scope . ' snapshot (' . count($snapshot['admins']) . ' privileged accounts); only hashes/IDs saved. Post content is never whitelisted.']];
        } catch (\Throwable $e) {
            return ['exit' => 2,'lines' => [self::safeError($e)]];
        }
    }
    /** Caller holds Sentinel's shared lock. */
    public function check(Budget $budget): array
    {
        $now = ($this->clock)();
        try {
            $b = $this->baseline();
            $source = $this->source($budget);
            $snapshot = $source->snapshot();
            $findings = [];
            foreach (['admins','options'] as $scope) {
                foreach (array_unique(array_merge(array_keys($b[$scope]), array_keys($snapshot[$scope]))) as $id) {
                    $was = $b[$scope][$id] ?? null;
                    $is = $snapshot[$scope][$id] ?? null;
                    if ($was === $is) {
                        continue;
                    }
                    $critical = $scope === 'admins' ? $was === null : $id !== 'admin_email';
                    $findings[] = new Finding($critical ? Finding::CRITICAL : Finding::WARNING, 'database/' . $scope . '/' . $id, $scope === 'admins' ? 'db-admin-change' : 'db-option-change', ($scope === 'admins' ? 'Privileged account ' : 'Monitored option ') . ($was === null ? 'added' : ($is === null ? 'removed' : 'changed')) . '; review before db-accept --scope=' . $scope, $is ?? 'removed');
                }
            }
            $stats = $source->postStats((int)($b['post_high_water'] ?? 0));
            if ($stats['new_count'] >= $this->config->database['new_post_threshold']) {
                $findings[] = new Finding(Finding::WARNING, 'database/posts', 'db-post-burst', $stats['new_count'] . ' new monitored posts since last database check; review unexpected bulk publishing', sha1((string)$b['post_high_water'] . ':' . $stats['max_id']));
            }
            $progress = $this->state->readJson('database-progress.json');
            $cursor = (int)($progress['post_cursor'] ?? 0);
            $complete = false;
            $scanned = 0;
            do {
                $rows = $source->posts($cursor, $this->config->database['batch_size']);
                if (!$rows) {
                    $complete = true;
                    $cursor = 0;
                    break;
                }
                foreach ($rows as $r) {
                    $id = (int)$r['id'];
                    if ($id <= $cursor) {
                        throw new DatabaseException('invalid database post cursor; progress not advanced');
                    }
                    $sample = $r['title'] . "\n" . $r['content'];
                    $hash = hash('sha256', $sample);
                    $path = 'database/posts/' . $id;
                    if (preg_match('/\b(?:online casino|casino bonus|free spins|sports betting|slot machines)\b/i', $sample)) {
                        $findings[] = new Finding(Finding::WARNING, $path, 'db-post-spam', 'Post contains a gambling/spam phrase; review manually (heuristic, not proof of malware)', $hash);
                    }
                    if (preg_match('/<script\b|<\?(?:php|=)/i', $sample)) {
                        $findings[] = new Finding(Finding::WARNING, $path, 'db-post-code', 'Post contains script/PHP-like content; legitimate embeds/examples can match', $hash);
                    }
                    if ((int)$r['bytes'] > $this->config->database['max_post_bytes']) {
                        $findings[] = new Finding(Finding::WARNING, $path, 'db-post-sampled', 'Large post sampled at beginning/end; middle was not scanned', $hash);
                    }
                    $cursor = $id;
                    $scanned++;
                }
            } while (!$budget->exceeded() && count($findings) < 200);
            $delivery = $this->deliver($findings, $now);
            if ($delivery['ok']) {
                $this->state->writeJson('database-progress.json', ['post_cursor' => $cursor]);
                $b['post_high_water'] = $stats['max_id'];
                $this->state->writeJson('database-baseline.json', $b);
            }
            $status = $this->state->readJson('status.json');
            $status['database'] = ['last_run' => $now,'last_attempt' => $now,'last_error' => '','last_complete' => $complete && $delivery['ok'] ? $now : (int)($status['database']['last_complete'] ?? 0),'complete' => $complete && $delivery['ok'],'posts_scanned' => $scanned];
            $this->state->writeJson('status.json', $status);
            $lines = ['database: ' . count($findings) . ' finding(s), ' . $scanned . ' post(s), ' . ($complete ? 'scan complete' : 'partial scan; next check resumes after post ' . $cursor)];
            foreach ($findings as $f) {
                $lines[] = '  ' . Finding::label($f->severity) . ' ' . $f->path . ' ' . $f->rule;
            }
            return ['exit' => $findings ? 1 : 0,'lines' => array_merge($lines, $delivery['lines'])];
        } catch (\Throwable $e) {
            $message = self::safeError($e);
            $status = $this->state->readJson('status.json');
            $status['database']['last_attempt'] = $now;
            $status['database']['last_error'] = $message;
            $this->state->writeJson('status.json', $status);
            $delivery = $this->deliver([new Finding(Finding::CRITICAL, 'database', 'db-run-error', $message, sha1($message))], $now);
            return ['exit' => 2,'lines' => array_merge([$message], $delivery['lines'])];
        }
    }
    private function deliver(array $findings, int $now): array
    {
        $log = new AlertLog($this->state);
        $due = $log->due($findings, $now, $this->config->remindHours * 3600);
        $sent = [];
        $lines = [];
        $ok = true;
        if ($due) {
            $digest = Digest::build($this->config->siteName, (string)gethostname(), $now, $due, [], []);
            $r = (new Alerter($this->channels))->send($digest['subject'], $digest['body'], $digest['top']);
            $ok = $r['ok'];
            $lines = $r['results'];
            if ($ok) {
                $sent = $due;
            }
        }
        $log->commit($findings, $sent, $now);
        return ['ok' => $ok,'lines' => $lines];
    }
    private static function safeError(\Throwable $e): string
    {
        return $e instanceof DatabaseException ? $e->getMessage() : 'database check failed; credentials, SQL and database content are withheld';
    }
}
