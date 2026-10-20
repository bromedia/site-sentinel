<?php
declare(strict_types=1);

namespace Sentinel;

/**
 * settings.txt: the few things a site owner edits, as "name = value" lines rather than JSON,
 * so one stray character cannot break the file. Unknown names and invalid values are errors
 * that name the line, because a typo here can mean alerts going nowhere.
 */
final class Settings
{
    /** The address shipped in the template, which must be replaced. */
    public const EXAMPLE_EMAIL = 'you@example.com';

    /** @var string[] */
    public $emails = [];
    public $website = '';
    public $contact = '';
    /** @var bool|null null when the line is absent */
    public $approveUpdates = null;
    public $heartbeat = '';

    public static function load(string $file): Settings
    {
        $text = @file_get_contents($file);
        if ($text === false) {
            throw new ConfigException("cannot read the settings file $file");
        }
        return self::parse($text, basename($file));
    }

    public static function parse(string $text, string $name = 'settings.txt'): Settings
    {
        $s = new Settings();
        $errors = [];
        $text = (string)preg_replace('/^\xEF\xBB\xBF/', '', $text); // a byte-order mark from Windows editors
        foreach (preg_split('/\r\n|\r|\n/', $text) ?: [] as $i => $line) {
            $n = $i + 1;
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $eq = strpos($line, '=');
            if ($eq === false) {
                $errors[] = "line $n: expected 'name = value'";
                continue;
            }
            $key = strtolower(trim(substr($line, 0, $eq)));
            $value = trim(trim(substr($line, $eq + 1)), "\"'");
            switch ($key) {
                case 'email':
                    foreach (preg_split('/[,;\s]+/', $value, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $addr) {
                        if (strcasecmp($addr, self::EXAMPLE_EMAIL) === 0) {
                            $errors[] = "line $n: replace the example address " . self::EXAMPLE_EMAIL . ' with a real one';
                        } elseif (filter_var($addr, FILTER_VALIDATE_EMAIL) === false) {
                            $errors[] = "line $n: '$addr' is not a valid email address";
                        } elseif (!in_array(strtolower($addr), array_map('strtolower', $s->emails), true)) {
                            $s->emails[] = $addr;
                        }
                    }
                    break;
                case 'website':
                    $s->website = self::text($value);
                    break;
                case 'contact':
                    $s->contact = self::text($value);
                    break;
                case 'approve_plugin_updates_automatically':
                    $v = strtolower($value);
                    if (in_array($v, ['yes', 'true', 'on'], true)) {
                        $s->approveUpdates = true;
                    } elseif (in_array($v, ['no', 'false', 'off'], true)) {
                        $s->approveUpdates = false;
                    } else {
                        $errors[] = "line $n: approve_plugin_updates_automatically must be yes or no";
                    }
                    break;
                case 'heartbeat':
                    if ($value !== '' && !preg_match('#^https?://\S+$#i', $value)) {
                        $errors[] = "line $n: heartbeat must be an http(s) address";
                    }
                    $s->heartbeat = $value;
                    break;
                default:
                    $errors[] = "line $n: unknown setting '$key'";
            }
        }
        if (!$s->emails && !$errors) {
            $errors[] = 'add at least one "email = ..." line';
        }
        if ($errors) {
            throw new ConfigException("$name: " . implode('; ', $errors));
        }
        return $s;
    }

    /**
     * Email addresses only, ignoring every error: used to report a broken configuration to
     * whoever the owner meant to alert.
     *
     * @return string[]
     */
    public static function emailsLeniently(string $file): array
    {
        $text = (string)@file_get_contents($file);
        $out = [];
        foreach (preg_split('/\r\n|\r|\n/', $text) ?: [] as $line) {
            if (preg_match('/^\s*email\s*=(.*)$/i', $line, $m)) {
                foreach (preg_split('/[,;\s]+/', trim($m[1], " \t\"'"), -1, PREG_SPLIT_NO_EMPTY) ?: [] as $addr) {
                    if (filter_var($addr, FILTER_VALIDATE_EMAIL) !== false && strcasecmp($addr, self::EXAMPLE_EMAIL) !== 0) {
                        $out[] = $addr;
                    }
                }
            }
        }
        return array_values(array_unique($out));
    }

    private static function text(string $v): string
    {
        $v = (string)preg_replace('/[\x00-\x1F\x7F]+/', ' ', $v);
        return function_exists('mb_substr') ? mb_substr($v, 0, 200, 'UTF-8') : substr($v, 0, 200);
    }
}
