<?php
declare(strict_types=1);

namespace Sentinel;

final class Rules
{
    public $version = 0;
    /** @var array[] */
    public $patterns = [];
    /** @var array<string,string> sha256 => name */
    public $hashes = [];

    public static function builtin(): Rules
    {
        return self::fromArray([
            'version' => 0,
            'patterns' => [
                ['id' => 'test-marker', 'severity' => 'critical', 'regex' => '/SENTINEL-TEST-MALWARE-MARKER/', 'description' => 'Sentinel self-test marker'],
                ['id' => 'eval-decoder', 'severity' => 'critical', 'regex' => '/\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i', 'description' => 'eval of an encoded payload'],
                ['id' => 'eval-request', 'severity' => 'critical', 'regex' => '/\b(?:eval|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i', 'description' => 'eval of request data'],
                ['id' => 'exec-request', 'severity' => 'critical', 'regex' => '/\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i', 'description' => 'shell command built from request data'],
                ['id' => 'request-callable', 'severity' => 'critical', 'regex' => '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,64}\]\s*\(/', 'description' => 'request data called as a function'],
                ['id' => 'chr-chain', 'severity' => 'warning', 'regex' => '/(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){8,}/i', 'description' => 'string assembled from chr() calls (obfuscation)'],
            ],
            'hashes' => [],
        ]);
    }

    public static function fromArray(array $d): Rules
    {
        $r = new Rules();
        $r->version = (int)($d['version'] ?? 0);
        foreach ((array)($d['patterns'] ?? []) as $p) {
            $id = (string)($p['id'] ?? '');
            $sev = strtolower((string)($p['severity'] ?? ''));
            $re = (string)($p['regex'] ?? '');
            if ($id === '' || $re === '' || !in_array($sev, ['warning', 'critical'], true)) {
                throw new \InvalidArgumentException('invalid rule entry' . ($id !== '' ? " '$id'" : ''));
            }
            if (@preg_match($re, '') === false) {
                throw new \InvalidArgumentException("invalid regex in rule '$id'");
            }
            $r->patterns[] = ['id' => $id, 'severity' => $sev, 'regex' => $re, 'description' => (string)($p['description'] ?? $id)];
        }
        foreach ((array)($d['hashes'] ?? []) as $h) {
            $sha = strtolower((string)($h['sha256'] ?? ''));
            if (!preg_match('/^[a-f0-9]{64}$/', $sha)) {
                throw new \InvalidArgumentException('invalid sha256 in rules');
            }
            $r->hashes[$sha] = (string)($h['name'] ?? 'known-bad');
        }
        return $r;
    }

    public static function load(string $file): Rules
    {
        $json = @file_get_contents($file);
        $data = $json === false ? null : json_decode($json, true);
        if (!is_array($data)) {
            throw new \InvalidArgumentException("cannot read rules file $file");
        }
        return self::fromArray($data);
    }

    /** @return array[] the patterns that match $content */
    public function matchContent(string $content): array
    {
        $hits = [];
        foreach ($this->patterns as $p) {
            if (preg_match($p['regex'], $content) === 1) {
                $hits[] = $p;
            }
        }
        return $hits;
    }

    public function badHash(string $sha256): ?string
    {
        return $this->hashes[strtolower($sha256)] ?? null;
    }
}
