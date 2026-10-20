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
                [--no-wp-checksums] [--force]
  check         quick scan of new and changed files (run every few minutes)
  full          full scan: hash everything, verify WordPress checksums (run nightly)
  accept        accept the current state as known-good [--path=REL ...] [--self]
  dismiss       mark a reviewed false positive: dismiss <id> --reason=TEXT | --list | --remove=<id>
  run           the one scheduled job for packaged installs: first-run setup, then check, plus a
                full scan once a day; prints nothing when all is well
  update-rules  download, verify and install the latest rules bundle
  test-alert    send a test alert through every configured channel
  doctor        read-only hosting/config checks and last scan history (no network or alerts)
  cron          print cron entries using this PHP executable (does not install them)
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
        if (PHP_SAPI !== 'cli') {
            @set_time_limit(0); // some hosts run cron jobs through php-cgi, with the web time limit
        }
        $r = self::execute(array_slice($argv, 1), (string)($argv[0] ?? (isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : 'sentinel.php')));
        // STDOUT and STDERR exist only in the CLI build of PHP.
        $out = defined('STDOUT') ? STDOUT : fopen('php://stdout', 'w');
        $err = defined('STDERR') ? STDERR : fopen('php://stderr', 'w');
        foreach ($r['out'] as $line) {
            fwrite($out, $line . "\n");
        }
        foreach ($r['err'] as $line) {
            fwrite($err, $line . "\n");
        }
        return $r['exit'];
    }

    /** @return array{exit:int, out:string[], err:string[]} */
    public static function execute(array $args, string $script, ?HttpClient $http = null, ?callable $mailer = null): array
    {
        if (!$args && self::packaged($script)) {
            // A packaged install has one job; if the host's cron wrapper drops the argument, do it anyway.
            $args = ['run'];
        }
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
            if (!in_array($cmd, ['check', 'full', 'run', 'accept', 'dismiss', 'update-rules', 'test-alert', 'doctor', 'cron'], true)) {
                return ['exit' => 2, 'out' => [], 'err' => array_merge(["unknown command '$cmd'", ''], explode("\n", sprintf(self::USAGE, VERSION)))];
            }
            $configFile = isset($opts['config']) && is_string($opts['config'])
                ? $opts['config']
                : ((string)getenv('SENTINEL_CONFIG') !== '' ? (string)getenv('SENTINEL_CONFIG') : dirname($script) . '/sentinel.json');
            try {
                $config = Config::load($configFile);
            } catch (ConfigException $e) {
                if ($cmd === 'run') {
                    return self::runConfigError($e->getMessage(), $configFile, $mailer, $script);
                }
                throw $e;
            }
            $config->addExclusion($script);
            $config->addExclusion($configFile);
            if ($config->settingsFile !== '') {
                $config->addExclusion($config->settingsFile);
            }
            if ($cmd === 'doctor') {
                return self::result(Doctor::run($config, $script, $configFile));
            }
            if ($cmd === 'cron') {
                return ['exit' => 0, 'out' => Cron::lines($script, $configFile), 'err' => []];
            }
            try {
                $state = new State($config->stateDir);
            } catch (\Throwable $e) {
                if ($cmd === 'run') {
                    return self::runConfigError('the state folder cannot be created: ' . $e->getMessage(), $configFile, $mailer, $script);
                }
                throw $e;
            }
            $channels = NotifierFactory::fromConfig($config, $http, $mailer);
            $selfFiles = Init::selfFiles($script, $configFile, $state, $config->settingsFile);

            switch ($cmd) {
                case 'run':
                    return self::quiet(Run::execute($config, $state, $http, $channels, $selfFiles, $script, $configFile, null, $mailer));
                case 'check':
                case 'full':
                    return self::result((new Monitor($config, $state, $http, $channels, $selfFiles))->run($cmd));
                case 'accept':
                    return self::result(Accept::run($config, $state, (array)($opts['path'] ?? []), !empty($opts['self']), $selfFiles));
                case 'dismiss':
                    return self::result(Dismissals::run($config, $state, $opts, $selfFiles));
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

    /** Like result(), but a clean run prints nothing at all (hosting panels email any output). */
    private static function quiet(array $r): array
    {
        $out = self::result($r);
        if ($r['exit'] === 0 && !$r['lines']) {
            $out['out'] = [];
        }
        return $out;
    }

    /** Whether the script sits in a client package folder (its sentinel.json uses a settings.txt). */
    private static function packaged(string $script): bool
    {
        $raw = json_decode((string)@file_get_contents(dirname($script) . '/sentinel.json'), true);
        return is_array($raw) && (string)($raw['settings_file'] ?? '') !== '';
    }

    /**
     * "run" with a configuration that cannot be used: there is no working alert channel, so the
     * error is emailed, at most once a day per distinct error, to every address that may be
     * waiting for alerts: any valid one in settings.txt, and the ones that last worked.
     */
    private static function runConfigError(string $message, string $configFile, ?callable $mailer, string $script = ''): array
    {
        $err = ['exit' => 2, 'out' => [], 'err' => ['error: ' . $message]];
        $dir = dirname($configFile);
        $raw = json_decode((string)@file_get_contents($configFile), true);
        $raw = is_array($raw) ? $raw : [];
        $abs = function (string $p) use ($dir): string {
            return $p !== '' && $p[0] !== '/' ? $dir . '/' . $p : $p;
        };
        $settings = $abs((string)($raw['settings_file'] ?? ''));
        $stateDir = $abs((string)($raw['state_dir'] ?? 'state'));
        $to = $settings !== '' ? Settings::emailsLeniently($settings) : [];
        $last = json_decode((string)@file_get_contents($stateDir . '/' . Config::LAST_GOOD_SETTINGS), true);
        $known = is_array($last) ? Settings::fromArray($last) : null;
        foreach ($known !== null ? $known->emails : (array)json_decode((string)@file_get_contents($stateDir . '/settings-recipients.json'), true) as $a) {
            if (is_string($a) && filter_var($a, FILTER_VALIDATE_EMAIL) !== false) {
                $to[] = $a;
            }
        }
        $to = array_values(array_unique(array_map('strtolower', $to)));
        if (!$to) {
            return $err;
        }
        $seenFile = $dir . '/.last-setup-error';
        $seen = json_decode((string)@file_get_contents($seenFile), true);
        if (is_array($seen) && ($seen['hash'] ?? '') === sha1($message) && time() - (int)($seen['at'] ?? 0) < 86400) {
            return $err;
        }
        $who = $known !== null && $known->contact !== '' ? $known->contact : 'your web developer';
        $site = $known !== null && $known->website !== '' ? $known->website : 'your website';
        // A website folder that cannot be found usually means the package was extracted inside it.
        $webRoot = $script !== '' && strpos($message, 'site_root') !== false ? self::insideWebRoot(dirname($script)) : '';
        if ($webRoot !== '') {
            $subject = "Site Sentinel setup could not finish on $site";
            $body = "Site Sentinel was not started.\n\n" . Run::placementMessage($webRoot) . "\n\nIf you need help, contact $who.\n";
        } else {
            $subject = $known !== null ? "Site Sentinel has stopped monitoring $site" : 'Site Sentinel could not start';
            $body = ($known !== null ? "Site Sentinel has stopped monitoring $site" : 'Site Sentinel could not start')
                . ", because of a problem with its setup:\n\n  " . Finding::line($message) . "\n\n"
                . "Until this is fixed the website is not being monitored. Please forward this email to $who.\n";
        }
        try {
            (new EmailNotifier($to, $known !== null ? $known->from : '', $mailer))->send($subject, $body, Finding::CRITICAL);
            @file_put_contents($seenFile, json_encode(['hash' => sha1($message), 'at' => time()]));
            $err['err'][] = 'the error was emailed to ' . implode(', ', $to);
        } catch (\Throwable $e) {
            $err['err'][] = 'could not email the error: ' . $e->getMessage();
        }
        return $err;
    }

    /**
     * The website folder this folder sits inside, if any: the commonest install mistake is to
     * extract the package inside public_html, where the shipped relative paths then point nowhere.
     */
    private static function insideWebRoot(string $dir): string
    {
        $real = realpath($dir);
        $p = dirname($real !== false ? $real : $dir);
        for ($i = 0; $i < 6 && $p !== '/' && $p !== '.' && $p !== ''; $i++) {
            if (is_file($p . '/wp-config.php') || is_file($p . '/wp-load.php') || in_array(basename($p), ['public_html', 'www', 'htdocs', 'httpdocs', 'public_ssl'], true)) {
                return $p;
            }
            $p = dirname($p);
        }
        return '';
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
