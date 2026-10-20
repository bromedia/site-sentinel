<?php
declare(strict_types=1);

// Generates rules/builtin.json, the built-in signature set compiled into sentinel.php.
// Usage: php rules/generate.php
//
// Every rule here is original to this project and describes a technique, not a copied signature.
// Literal names of known malware families are written so this file (and the built script) never
// contains the name itself (Files[M]an matches "FilesMan"): hosting providers scan accounts for
// such strings and could otherwise quarantine Sentinel. Keep that property when adding rules.
//
// Each rule: id, severity (critical = near-certain malware; warning = suspicious, review),
// files (php | js | html | any), regex (PCRE with ~ delimiters), description.
// Every rule needs a positive sample in tests/test_signatures.php, and the whole set must stay
// silent on the false-positive corpus (see tests/corpus.php).

// Request data an attacker controls directly.
$src = '(?:\$_(?:GET|POST|REQUEST|COOKIE)\b|\$_SERVER\s*\[\s*[\'"]HTTP_|[\'"]php://input|getallheaders\s*\(\s*\))';
// Request variables only: reading the raw body (php://input) is normal in REST and XML-RPC code.
$srcVars = '(?:\$_(?:GET|POST|REQUEST|COOKIE)\b|\$_SERVER\s*\[\s*[\'"]HTTP_)';
// "( first argument" that is request data, optionally wrapped in up to three calls or a cast.
$firstArgSrc = '\(\s*(?:@\s*)?(?:\(\s*\w+\s*\)\s*)?(?:[a-z_]\w*\s*\(\s*(?:@\s*)?){0,3}' . $src;
$firstArgVars = '\(\s*(?:@\s*)?(?:\(\s*\w+\s*\)\s*)?(?:[a-z_]\w*\s*\(\s*(?:@\s*)?){0,3}' . $srcVars;
// Not a method or static call ($obj->exec(), Foo::assert()) and not part of a longer name.
$fn = '(?<![\w>:$\\\\])';

/** Splits a literal so the exact string never appears: Files[M]an. */
function lit(string $s): string
{
    $mid = intdiv(strlen($s), 2);
    return preg_quote(substr($s, 0, $mid), '~') . '[' . preg_quote($s[$mid], '~') . ']' . preg_quote(substr($s, $mid + 1), '~');
}

/** Every way of writing $name as two concatenated quoted fragments: 'sys'.'tem'. */
function splits(array $names): string
{
    $alts = [];
    foreach ($names as $name) {
        for ($k = 1; $k < strlen($name); $k++) {
            $alts[] = '(?:([\'"])' . preg_quote(substr($name, 0, $k), '~') . '\\' . '{G1}\s*\.\s*([\'"])' . preg_quote(substr($name, $k), '~') . '\\' . '{G2})';
        }
    }
    // Numbered groups differ per alternative; use one pair of named-free groups by rewriting.
    $out = [];
    $g = 1;
    foreach ($alts as $a) {
        $out[] = str_replace(['{G1}', '{G2}'], [(string)$g, (string)($g + 1)], $a);
        $g += 2;
    }
    return implode('|', $out);
}

/** Each character as itself, \xHH or \OOO, so "ev\x61l" and "\x65\x76\x61\x6c" both match. */
function escapable(string $name): string
{
    $out = '';
    foreach (str_split($name) as $ch) {
        $o = ord($ch);
        $out .= '(?:' . preg_quote($ch, '~') . '|\\\\x' . sprintf('%02x', $o) . '|\\\\' . sprintf('%03o', $o) . ')';
    }
    return $out;
}

$execNames = ['system', 'assert', 'passthru', 'shell_exec', 'popen', 'proc_open', 'pcntl_exec', 'create_function', 'move_uploaded_file'];
$decoderNames = ['base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13', 'convert_uudecode'];
$escNames = ['assert', 'system', 'passthru', 'shell_exec', 'popen', 'proc_open', 'base64_decode', 'gzinflate', 'gzuncompress', 'str_rot13', 'create_function', 'call_user_func', 'preg_replace', 'GLOBALS', 'file_put_contents', 'move_uploaded_file'];
$escAlts = implode('|', array_map('escapable', $escNames));

$rules = [
    // --- Code run straight from a web request ------------------------------------------------
    ['eval-request', 'critical', 'php', $fn . '(?:eval|assert)\s*' . $firstArgSrc, 'Runs code taken from the web request (remote code execution backdoor)'],
    ['exec-request', 'critical', 'php', $fn . '(?:system|shell_exec|passthru|exec|popen|proc_open|pcntl_exec)\s*' . $firstArgSrc, 'Runs a server command taken from the web request (command execution backdoor)'],
    ['request-callable', 'critical', 'php', '\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,64}\]\s*\(', 'Calls a function whose name comes from the web request'],
    ['callback-request', 'critical', 'php', $fn . '(?:call_user_func(?:_array)?|array_map|register_shutdown_function|register_tick_function|ob_start|forward_static_call(?:_array)?|iterator_apply)\s*' . $firstArgSrc, 'Uses request data as a callback, so the request chooses what code runs'],
    ['create-function-request', 'critical', 'php', $fn . 'create_function\s*\([^;]{0,200}?' . $src, 'Builds a function from web request data'],
    ['preg-pattern-request', 'critical', 'php', $fn . 'preg_replace(?:_callback)?\s*' . $firstArgSrc, 'Regular expression taken from the web request (code execution on old PHP)'],
    ['include-request', 'critical', 'php', '\b(?:include|require)(?:_once)?\s*\(?\s*(?:[a-z_]\w*\s*\(\s*){0,2}' . $src, 'Loads a file chosen by the web request'],
    ['write-file-request', 'critical', 'php', $fn . 'file_put_contents\s*' . $firstArgSrc, 'Writes to a file path taken from the web request'],
    ['upload-as-requested-name', 'critical', 'php', $fn . 'move_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]{1,40}\]\s*\[\s*[\'"]tmp_name[\'"]\s*\]\s*,\s*(?:\$_FILES\s*\[[^\]]{1,40}\]\s*\[\s*[\'"]name[\'"]\s*\]|' . $src . ')', 'Saves an uploaded file under the name the uploader chose (file upload backdoor)'],
    ['eval-request-variable', 'critical', 'php', '\$(\w{1,30})\s*=\s*(?:@\s*)?(?:[a-z_]\w*\s*\(\s*){0,3}(?:\$_(?:GET|POST|REQUEST|COOKIE)\b|[\'"]php://input)[^;]{0,120};\s*(?:@\s*)?(?:eval|assert|system|passthru|shell_exec|popen)\s*\(\s*(?:[a-z_]\w*\s*\(\s*){0,2}\$\1\b', 'Stores web request data and runs it on the next line'],
    ['remote-code', 'critical', 'php', '\b(?:eval|assert)\s*\(\s*(?:@\s*)?file_get_contents\s*\(\s*[\'"]https?://|\b(?:include|require)(?:_once)?\s*\(?\s*[\'"]https?://', 'Runs code downloaded from another website'],
    ['shell-download', 'critical', 'php', $fn . '(?:system|exec|shell_exec|passthru|popen)\s*\(\s*[\'"](?:wget|curl|lynx|fetch)\s', 'Downloads files with a server command'],

    // --- Obfuscated code execution -----------------------------------------------------------
    ['eval-decoder', 'critical', 'php', $fn . '(?:eval|assert)\s*\(\s*(?:@\s*)?(?:\(\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin|strrev|rawurldecode|urldecode|pack)\s*\(', 'Runs code that was hidden by encoding'],
    ['eval-decoded-variable', 'critical', 'php', '\$(\w{1,30})\s*=\s*(?:@\s*)?(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode)\s*\([^;]{0,400}\);\s*(?:@\s*)?(?:eval|assert)\s*\(\s*\$\1\b', 'Decodes hidden code and runs it on the next line'],
    ['eval-closing-tag', 'critical', 'php', '\beval\s*\(\s*([\'"])\?>\1\s*\.', 'Runs a decoded PHP payload (eval of a closing tag plus data)'],
    ['escaped-function-name', 'critical', 'php', '(["\'])(?=[^"\']{0,80}\\\\)(?:' . $escAlts . ')\1', 'Names a dangerous function with escape codes to hide it'],
    ['reversed-function-name', 'critical', 'php', '\bstrrev\s*\(\s*([\'"])(?:edoced_46esab|etalfnizg|sserpmocnuzg|tressa|metsys|cexe_llehs|urhtssap|nepop|nepo_corp|noitcnuf_etaerc|31tor_rts|stnetnoc_tup_elif|elif_dedaolpu_evom)\1', 'Builds a dangerous function name by reversing a string'],
    ['rot13-function-name', 'critical', 'php', '\bstr_rot13\s*\(\s*([\'"])(?:onfr64_qrpbqr|tmvasyngr|nffreg|flfgrz|furyy_rkrp|cnffgueh|perngr_shapgvba|cbcra)\1', 'Builds a dangerous function name with ROT13'],
    ['split-exec-name', 'critical', 'php', splits($execNames), 'Builds a code or command execution function name from pieces to hide it'],
    ['split-decoder-name', 'warning', 'php', splits($decoderNames), 'Builds a decoding function name from pieces (often used to hide payloads)'],
    ['obfuscator-variables', 'critical', 'php', '\$(?=[O0_]*0)(?=[O0_]*O)[O0_]{6,}\b', 'Variable names made only of O and 0 (a common malware obfuscator)'],
    ['globals-function-table', 'critical', 'php', '\$GLOBALS\s*\[\s*([\'"])\w{1,20}\1\s*\]\s*\[\s*\d+\s*\]\s*\(', 'Calls functions through an index into a hidden name table'],
    ['encoded-payload', 'warning', 'php', $fn . '(?:gzinflate|gzuncompress|gzdecode|str_rot13|strrev)\s*\(\s*base64_decode\s*\(\s*([\'"])[A-Za-z0-9+/=\s]{500,}\1', 'Large encoded and compressed payload'],
    // Printable characters only: binary data (fonts, PDFs) is legitimately built from chr(0), chr(5)...
    ['chr-chain', 'warning', 'php', '(?:chr\s*\(\s*(?:3[2-9]|[4-9]\d|1[01]\d|12[0-6])\s*\)\s*\.\s*){8,}', 'String assembled from chr() calls (obfuscation)'],
    ['eval-variable-chain', 'critical', 'php', $fn . '(?:eval|assert)\s*\(\s*\$\w+\s*\(\s*\$\w+\s*\(', 'Runs the result of nested variable function calls (obfuscation)'],
    ['preg-replace-eval', 'warning', 'php', $fn . 'preg_replace\s*\(\s*([\'"])([^\w\s\\\\])[^\'"]{0,200}\2[imsxuADSUXJ]{0,8}e[imsxuADSUXJ]{0,8}\1', 'Regular expression with the removed /e (execute) modifier'],

    // --- Hidden loaders --------------------------------------------------------------------------
    ['include-image', 'critical', 'php', '\b(?:include|require)(?:_once)?\s*\(?\s*([\'"])[^\'"]{0,200}\.(?:ico|png|jpe?g|gif|bmp|webp)\1', 'Runs an image file as PHP (hidden backdoor)'],
    ['include-escaped-path', 'critical', 'php', '\b(?:include|require)(?:_once)?\s*\(?\s*"(?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}){4}', 'Loads a file whose path is hidden with escape codes'],

    // --- WordPress backdoors -------------------------------------------------------------------
    ['hardcoded-user', 'critical', 'php', $fn . 'wp_create_user\s*\(\s*([\'"])[^\'"]{2,60}\1\s*,\s*([\'"])[^\'"]{4,100}\2', 'Creates a WordPress user with a password written into the code (backdoor account)'],
    ['hardcoded-user-password', 'critical', 'php', $fn . 'wp_insert_user\s*\([^;]{0,400}?[\'"]user_pass[\'"]\s*=>\s*([\'"])[^\'"$]{4,100}\1', 'Creates a WordPress user with a password written into the code (backdoor account)'],
    ['hidden-admin', 'critical', 'php', 'WHERE\s+1\s*=\s*1\s+AND\s+\{?\$wpdb->users\}?\.(?:user_login|ID)\s*!=', 'Hides a user from the WordPress user list'],
    ['hidden-plugin', 'warning', 'php', 'unset\s*\(\s*\$\w{1,30}\s*\[\s*plugin_basename\s*\(\s*__FILE__\s*\)\s*\]', 'A plugin that hides itself from the plugin list'],
    ['fake-theme-modules', 'critical', 'any', lit('wp-vcd') . '|' . lit('WP_V_CD') . '|class\.theme-' . lit('modules') . '\.php', 'Known WordPress malware family (fake theme modules)'],

    // --- Known webshells and malware families -----------------------------------------------
    ['webshell-family', 'critical', 'any', lit('FilesMan') . '|\b' . lit('wsoEx') . '\s*\(|\b' . lit('wsoLogin') . '\b|\b' . lit('WSOsetcookie') . '\b|\b' . lit('wsoHeader') . '\b|' . lit('c99shell') . '|' . lit('c99_buff_prepare') . '|' . lit('r57shell') . '|\b' . lit('b374k') . '\b|' . lit('IndoXploit'), 'Known webshell (file manager backdoor)'],
    ['reverse-shell', 'critical', 'any', '/dev/' . lit('tcp') . '/|\bbash\s+-i\s*>&|\bnc\s+-e\s+/bin/(?:ba)?sh\b|\bsh\s+-i\s+[0-9]?>&', 'Reverse shell (gives an attacker a remote command line)'],
    ['cryptominer', 'critical', 'any', lit('coinhive') . '|' . lit('CoinHive') . '\.Anonymous|' . lit('cryptonight') . '|' . lit('webminepool') . '|' . lit('crypto-loot') . '|' . lit('coinimp') . '\.com', 'Cryptocurrency miner'],

    // --- Injected JavaScript ---------------------------------------------------------------------
    ['js-eval-charcodes', 'critical', 'any', '\beval\s*\(\s*String\.fromCharCode\s*\(', 'Runs JavaScript hidden as character codes'],
    ['js-unescape-script', 'critical', 'any', 'document\.write\s*\(\s*unescape\s*\(\s*([\'"])%3[cC]%73%63', 'Writes a hidden script tag into the page'],
    ['js-encoded-script-loader', 'critical', 'any', 'atob\s*\(\s*([\'"])aHR0c[A-Za-z0-9+/=]{6,}\1[\s\S]{0,300}?createElement\s*\(\s*([\'"])script\2|createElement\s*\(\s*([\'"])script\3[\s\S]{0,300}?atob\s*\(\s*([\'"])aHR0c', 'Loads a script from an address hidden with base64'],
    ['js-long-charcodes', 'warning', 'any', 'String\.fromCharCode\s*\(\s*(?:\d{2,3}\s*,\s*){40,}', 'Long run of character codes (hidden text or script)'],
    ['script-from-ip', 'warning', 'any', '<script[^>]{0,80}src\s*=\s*\\\\?[\'"]https?://\d{1,3}(?:\.\d{1,3}){3}[:/]', 'Loads a script from a bare IP address'],

    // --- Spam and abuse ------------------------------------------------------------------------
    ['gambling-spam', 'warning', 'any', '\b(?:slot\s*' . lit('gacor') . '|' . lit('judi') . '\s*(?:slot|online|bola)|situs\s*slot|togel\s*online|' . lit('sbobet') . '|slot\s*thailand|bandar\s*(?:togel|judi))\b', 'Gambling spam text (common in hacked sites)'],
    ['hidden-pharma-spam', 'warning', 'any', '(?:' . lit('viagra') . '|' . lit('cialis') . '|' . lit('levitra') . ')[^<]{0,200}<[^>]{0,200}display\s*:\s*none|display\s*:\s*none[^>]{0,200}>[^<]{0,200}(?:' . lit('viagra') . '|' . lit('cialis') . '|' . lit('levitra') . ')', 'Hidden pharmacy spam text'],
    ['mailer-request', 'warning', 'php', $fn . 'mail\s*\(\s*\$_(?:GET|POST|REQUEST)\b', 'Sends email to an address taken straight from the web request (spam relay)'],
    ['file-op-request', 'warning', 'php', $fn . '(?:unlink|rmdir|rename|chmod|copy|readfile|scandir|fopen|touch)\s*' . $firstArgVars, 'File operation on a path taken straight from the web request'],
    ['connect-request', 'warning', 'php', $fn . '(?:fsockopen|pfsockopen|stream_socket_client|curl_init|file_get_contents)\s*' . $firstArgVars, 'Connects to an address taken straight from the web request'],
    ['extract-request', 'warning', 'php', $fn . 'extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b', 'Turns web request data into variables (often abused by backdoors)'],
    ['disable-error-log', 'warning', 'php', $fn . 'ini_set\s*\(\s*([\'"])error_log\1\s*,\s*(?:NULL|null|0|false|([\'"])\2)\s*\)', 'Switches off the PHP error log (hides activity)'],
    ['htaccess-handler-write', 'warning', 'php', $fn . 'file_put_contents\s*\([^;]{0,100}\.htaccess[^;]{0,300}(?:AddHandler|SetHandler|auto_prepend_file)', 'Writes server configuration that changes how files are executed'],

    // --- Self-test --------------------------------------------------------------------------------
    ['test-marker', 'critical', 'any', 'SENTINEL-TEST-MALWARE-MARKER', 'Sentinel self-test marker'],
];

$out = ['version' => 2026102001, 'patterns' => [], 'hashes' => []];
foreach ($rules as [$id, $sev, $files, $re, $desc]) {
    $regex = '~' . $re . '~i';
    if (@preg_match($regex, '') === false) {
        fwrite(STDERR, "invalid regex in $id: " . preg_last_error_msg() . "\n");
        exit(1);
    }
    $out['patterns'][] = ['id' => $id, 'severity' => $sev, 'files' => $files, 'regex' => $regex, 'description' => $desc, 'source' => 'Site Sentinel built-in rules (original, GPL-3.0-or-later)'];
}
$json = json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
file_put_contents(__DIR__ . '/builtin.json', $json);
echo 'wrote ' . count($out['patterns']) . " rules to rules/builtin.json\n";
