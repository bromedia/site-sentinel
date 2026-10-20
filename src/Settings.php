<?php
declare(strict_types=1);

namespace Sentinel;

/** settings.txt cannot be used as it is (missing, unreadable or invalid). */
final class SettingsException extends \RuntimeException
{
}

/**
 * settings.txt: the few things a site owner edits, as "name = value" lines rather than JSON,
 * so one stray character cannot break the file. Common ways of writing a line ("Email: ...",
 * "Jane <jane@example.org>", an address on its own) are understood; anything else is an error
 * that names the line. When the file cannot be used, a site that was already set up keeps
 * running with the last settings that worked (see Config::load), so a typo never stops
 * monitoring.
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
    /** Sender address for alert emails; '' lets PHP's mail() decide. */
    public $from = '';

    public static function load(string $file): Settings
    {
        $text = is_file($file) ? @file_get_contents($file) : false;
        if ($text === false) {
            throw new SettingsException('cannot read the settings file ' . basename($file) . ' (it is missing or unreadable)');
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
            // "name = value", also written "name: value"; an address on a line of its own is an email line.
            if (preg_match('/^([A-Za-z_ -]+?)\s*[=:]\s*(.*)$/', $line, $m)) {
                $key = strtolower(str_replace(' ', '_', trim($m[1])));
                $value = trim(trim($m[2]), "\"'");
            } elseif (strpos($line, '@') !== false && strpos($line, '=') === false) {
                $key = 'email';
                $value = $line;
            } else {
                $errors[] = "line $n: expected 'name = value'";
                continue;
            }
            switch ($key) {
                case 'email':
                case 'emails':
                case 'e-mail':
                    foreach (self::addresses($value) as $addr) {
                        if (strcasecmp($addr, self::EXAMPLE_EMAIL) === 0) {
                            $errors[] = "line $n: replace the example address " . self::EXAMPLE_EMAIL . ' with a real one';
                        } elseif (filter_var($addr, FILTER_VALIDATE_EMAIL) === false) {
                            $errors[] = "line $n: '$addr' is not a valid email address";
                        } elseif (!in_array(strtolower($addr), array_map('strtolower', $s->emails), true)) {
                            $s->emails[] = $addr;
                        }
                    }
                    break;
                case 'from':
                    if ($value !== '' && filter_var($value, FILTER_VALIDATE_EMAIL) === false) {
                        $errors[] = "line $n: from must be a single email address";
                    }
                    $s->from = $value;
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
            throw new SettingsException("$name: " . implode('; ', $errors));
        }
        return $s;
    }

    /**
     * The addresses on an email line: "a@x, b@y", "Jane Smith <jane@x>", or a mix. Words that are
     * not addresses (a name next to one) are ignored; a part with no address at all is returned
     * as it is, so it is reported as invalid.
     *
     * @return string[]
     */
    private static function addresses(string $value): array
    {
        $out = [];
        foreach (preg_split('/[,;]+/', $value, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }
            if (preg_match_all('/<([^<>\s]+)>/', $part, $m)) {
                foreach ($m[1] as $a) {
                    $out[] = $a;
                }
                continue;
            }
            $words = preg_split('/\s+/', $part, -1, PREG_SPLIT_NO_EMPTY) ?: [];
            $found = array_values(array_filter($words, function ($w) {
                return strpos($w, '@') !== false;
            }));
            foreach ($found ?: [$part] as $a) {
                $out[] = trim($a, '<>()[]"\'');
            }
        }
        return $out;
    }

    /** @return array<string,mixed> what is kept as the last settings that worked */
    public function toArray(): array
    {
        return [
            'emails' => $this->emails,
            'website' => $this->website,
            'contact' => $this->contact,
            'approve_updates' => $this->approveUpdates,
            'heartbeat' => $this->heartbeat,
            'from' => $this->from,
        ];
    }

    /** The last settings that worked, as kept by toArray(); null if they are unusable. */
    public static function fromArray(array $a): ?Settings
    {
        $s = new Settings();
        foreach ((array)($a['emails'] ?? []) as $e) {
            if (is_string($e) && filter_var($e, FILTER_VALIDATE_EMAIL) !== false) {
                $s->emails[] = $e;
            }
        }
        if (!$s->emails) {
            return null;
        }
        $s->website = self::text((string)($a['website'] ?? ''));
        $s->contact = self::text((string)($a['contact'] ?? ''));
        $s->approveUpdates = isset($a['approve_updates']) && is_bool($a['approve_updates']) ? $a['approve_updates'] : null;
        $hb = (string)($a['heartbeat'] ?? '');
        $s->heartbeat = preg_match('#^https?://\S+$#i', $hb) ? $hb : '';
        $from = (string)($a['from'] ?? '');
        $s->from = filter_var($from, FILTER_VALIDATE_EMAIL) !== false ? $from : '';
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
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            if (preg_match('/^e-?mails?\s*[=:](.*)$/i', $line, $m)) {
                $value = $m[1];
            } elseif (strpos($line, '@') !== false && strpos($line, '=') === false && strpos($line, ':') === false) {
                $value = $line;
            } else {
                continue;
            }
            foreach (self::addresses(trim($value, " \t\"'")) as $addr) {
                if (filter_var($addr, FILTER_VALIDATE_EMAIL) !== false && strcasecmp($addr, self::EXAMPLE_EMAIL) !== 0) {
                    $out[] = $addr;
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
