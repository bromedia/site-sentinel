<?php
declare(strict_types=1);

/**
 * Heuristic PHP 7.4 compatibility check. Catches the PHP 8+ constructs this
 * project forbids; it is not a full parser.
 *
 * @return string[]
 */
function compat_violations(string $code, string $label): array
{
    $out = [];
    $banTokens = [];
    foreach (['T_MATCH', 'T_ENUM', 'T_READONLY', 'T_NULLSAFE_OBJECT_OPERATOR', 'T_ATTRIBUTE'] as $name) {
        if (defined($name)) {
            $banTokens[constant($name)] = $name;
        }
    }
    $banCalls = ['str_contains', 'str_starts_with', 'str_ends_with', 'array_is_list', 'get_debug_type', 'json_validate', 'fdiv', 'fsync'];

    $tokens = token_get_all($code);
    $n = count($tokens);
    $stripped = '';
    for ($i = 0; $i < $n; $i++) {
        $tok = $tokens[$i];
        if (!is_array($tok)) {
            $stripped .= $tok;
            continue;
        }
        [$id, $text, $line] = $tok;
        if (isset($banTokens[$id])) {
            $out[] = "$label:$line uses {$banTokens[$id]} (needs PHP 8+)";
        }
        if ($id === T_STRING && in_array(strtolower($text), $banCalls, true)) {
            $j = $i + 1;
            while ($j < $n && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                $j++;
            }
            if ($j < $n && $tokens[$j] === '(') {
                $out[] = "$label:$line calls $text() (needs PHP 8+)";
            }
        }
        if ($id === T_COMMENT || $id === T_DOC_COMMENT) {
            continue;
        }
        $stripped .= $id === T_CONSTANT_ENCAPSED_STRING ? "''" : $text;
    }

    $patterns = [
        '/function\s+__construct\s*\([^)]*\b(?:public|private|protected)\b/' => 'constructor property promotion (PHP 8.0)',
        '/[(,]\s*\??[A-Za-z_\\\\][\w\\\\]*\|[\w\\\\|]+\s+&?(?:\.\.\.)?\$/' => 'union type in parameter (PHP 8.0)',
        '/\)\s*:\s*\??[A-Za-z_\\\\][\w\\\\]*\|/' => 'union type in return (PHP 8.0)',
        '/(?:\)\s*:\s*\??|[(,]\s*\??)(?:mixed|static|never)\b/' => 'mixed/static/never type (PHP 8.0+)',
        '/\bmixed\s+\$/' => 'mixed type (PHP 8.0)',
        '/catch\s*\([^)$]*\)/' => 'catch without a variable (PHP 8.0)',
    ];
    foreach ($patterns as $re => $why) {
        if (preg_match($re, $stripped, $m, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($stripped, 0, $m[0][1]), "\n") + 1;
            $out[] = "$label:~$line $why";
        }
    }
    return $out;
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    $root = dirname(__DIR__);
    $files = array_merge(glob($root . '/src/*.php') ?: [], glob($root . '/build/*.php') ?: [], glob($root . '/bin/*.php') ?: []);
    $all = [];
    foreach ($files as $f) {
        $all = array_merge($all, compat_violations((string)file_get_contents($f), basename($f)));
    }
    echo $all ? implode("\n", $all) . "\n" : "PHP 7.4 compatibility: OK\n";
    exit($all ? 1 : 0);
}
