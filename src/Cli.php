<?php
declare(strict_types=1);

namespace Sentinel;

final class Cli
{
    private const USAGE = <<<'TXT'
Site Sentinel %s - file-integrity and malware monitor

Usage: php sentinel.php <command> [options]

Commands:
  init          --root=DIR and at least one of --email=A[,B] --ntfy=URL --webhook=URL --file=PATH
                [--name=NAME] [--profile=wordpress|generic] [--config=FILE] [--state=DIR]
                [--no-wp-checksums] [--force] [--restart] (repeat init to resume)
  check         quick scan of new and changed files (run every few minutes)
  full          full scan: hash everything, verify WordPress checksums (run nightly)
  accept        accept the current state as known-good [--path=REL ...] [--self]
  update-rules  download, verify and install the latest rules bundle
  test-alert    send a test alert through every configured channel
  doctor        read-only hosting/config checks and last scan history (no network or alerts)
  cron          print cron entries using this PHP executable (does not install them)
  db-init       trust a reviewed administrator/options snapshot (database.enabled required)
  db-check      check database accounts/options and budgeted post content
  db-accept     trust reviewed database changes [--scope=admins|options|all]
  version       print the version

All commands except init read --config=FILE (default: $SENTINEL_CONFIG, else sentinel.json next to this script).
Exit codes: 0 clean, 1 findings reported, 2 tool error.
TXT;

    /** @return array<string,mixed> */
    public static function parse(array $args): array
    {
        $o = [];
        foreach ($args as $a) {
            $a = (string)$a;
            if (strncmp($a, '--', 2) !== 0) {
                $o['_'][] = $a;
                continue;
            }
            $a = substr($a, 2);
            $eq = strpos($a, '=');
            if ($eq === false) {
                $o[$a] = true;
                continue;
            }
            $k = substr($a, 0, $eq);
            $v = substr($a, $eq + 1);
            if ($k === 'path') {
                $o['path'][] = $v;
            } else {
                $o[$k] = $v;
            }
        }
        return $o;
    }

    public static function main(array $argv): int
    {
        $r = self::execute(array_slice($argv, 1), (string)($argv[0] ?? 'sentinel.php'));
        foreach ($r['out'] as $line) {
            fwrite(STDOUT, $line . "\n");
        }
        foreach ($r['err'] as $line) {
            fwrite(STDERR, $line . "\n");
        }
        return $r['exit'];
    }

    /** @return array{exit:int, out:string[], err:string[]} */
    public static function execute(array $args, string $script, ?HttpClient $http = null): array
    {
        $cmd = $args ? (string)array_shift($args) : 'help';
        $opts = self::parse($args);
        if ($cmd === 'version' || $cmd === '--version') {
            return ['exit' => 0, 'out' => [VERSION], 'err' => []];
        }
        if (in_array($cmd, ['help', '--help', '-h'], true)) {
            return ['exit' => 0, 'out' => explode("\n", sprintf(self::USAGE, VERSION)), 'err' => []];
        }
        $http = $http ?? new NativeHttp();
        $real = realpath($script);
        $script = $real !== false ? $real : $script;

        try {
            if ($cmd === 'init') {
                return self::result(Init::run($opts, $script, $http));
            }
            if (!in_array($cmd, ['check', 'full', 'accept', 'update-rules', 'test-alert', 'doctor', 'cron', 'db-init', 'db-check', 'db-accept'], true)) {
                return ['exit' => 2, 'out' => [], 'err' => array_merge(["unknown command '$cmd'", ''], explode("\n", sprintf(self::USAGE, VERSION)))];
            }
            $configFile = isset($opts['config']) && is_string($opts['config'])
                ? $opts['config']
                : ((string)getenv('SENTINEL_CONFIG') !== '' ? (string)getenv('SENTINEL_CONFIG') : dirname($script) . '/sentinel.json');
            $config = Config::load($configFile);
            $config->addExclusion($script);
            $config->addExclusion($configFile);
            if ($cmd === 'doctor') {
                return self::result(Doctor::run($config, $script, $configFile));
            }
            if ($cmd === 'cron') {
                return ['exit' => 0, 'out' => Cron::lines($script, $configFile), 'err' => []];
            }
            $state = new State($config->stateDir);
            $channels = NotifierFactory::fromConfig($config, $http);
            $selfFiles = Init::selfFiles($script, $configFile, $state);
            if (in_array($cmd, ['db-init','db-check','db-accept'], true)) {
                $lock = Lock::acquire($state->path('lock'));
                if ($lock === null) { return ['exit'=>2,'out'=>[],'err'=>['another scan is in progress']]; }
                try {
                    $db = new DatabaseMonitor($config, $state, $channels);
                    $budget = Budget::forConfig($config);
                    return self::result($cmd === 'db-check' ? $db->check($budget) : $db->accept($budget, (string)($opts['scope'] ?? 'all'), $cmd === 'db-init', !empty($opts['force'])));
                } finally { $lock->release(); }
            }


            switch ($cmd) {
                case 'check':
                case 'full':
                    return self::result((new Monitor($config, $state, $http, $channels, $selfFiles))->run($cmd));
                case 'accept':
                    return self::result(Accept::run($config, $state, (array)($opts['path'] ?? []), !empty($opts['self']), $selfFiles));
                case 'update-rules':
                    if ($config->rulesUrl === '') {
                        return ['exit' => 2, 'out' => [], 'err' => ['error: rules_url is not set in the config; set it to the address of a rules.json bundle']];
                    }
                    try {
                        $lines = (new RulesUpdater($config, $state, $http, new SelfCheck($state, $selfFiles)))->update();
                        return ['exit' => 0, 'out' => $lines, 'err' => []];
                    } catch (\Throwable $e) {
                        // A rules update that cannot be trusted must not fail silently from a cron job.
                        $severity = $e instanceof RulesFetchException ? Finding::WARNING : Finding::CRITICAL;
                        $sent = (new Monitor($config, $state, $http, $channels, $selfFiles))->reportError('rules update failed: ' . $e->getMessage(), $severity);
                        return ['exit' => 2, 'out' => [], 'err' => array_merge(['error: ' . $e->getMessage()], $sent)];
                    }
                default:
                    return self::testAlert($config, $channels);
            }
        } catch (\Throwable $e) {
            return ['exit' => 2, 'out' => [], 'err' => ['error: ' . $e->getMessage()]];
        }
    }

    /** @param Channel[] $channels */
    private static function testAlert(Config $config, array $channels): array
    {
        if (!$channels) {
            return ['exit' => 2, 'out' => [], 'err' => ['no alert channels configured']];
        }
        $subject = '[Sentinel][TEST] ' . $config->siteName;
        $body = "This is a test alert from Site Sentinel.\nSite: " . $config->siteName . "\nHost: " . gethostname() . "\nTime: " . gmdate('Y-m-d H:i:s') . " UTC\n\nIf you can read this, alerts for this site will reach you.\n";
        $r = (new Alerter($channels))->send($subject, $body, Finding::CRITICAL);
        $failed = false;
        foreach ($r['results'] as $line) {
            $failed = $failed || strpos($line, 'FAILED') !== false;
        }
        return ['exit' => $failed ? 1 : 0, 'out' => $r['results'], 'err' => []];
    }

    /** @param array{exit:int, lines:string[]} $r */
    private static function result(array $r): array
    {
        return $r['exit'] === 2
            ? ['exit' => 2, 'out' => [], 'err' => $r['lines']]
            : ['exit' => $r['exit'], 'out' => $r['lines'], 'err' => []];
    }
}
