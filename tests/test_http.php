<?php
declare(strict_types=1);

use Sentinel\NativeHttp;

/** @return array{0:int,1:resource} port and process of a throw-away local web server */
function startEchoServer(): array
{
    $dir = tmpdir();
    file_put_contents($dir . '/router.php', '<?php
if (($_SERVER["REQUEST_URI"] ?? "") === "/missing") { http_response_code(404); echo "nope"; return; }
if (($_SERVER["REQUEST_URI"] ?? "") === "/moved") { header("Location: /missing", true, 302); return; }
$in = file_get_contents("php://input");
echo $_SERVER["REQUEST_METHOD"] . ":" . ($in !== "" ? $in : "empty") . ":" . ($_SERVER["HTTP_X_TEST"] ?? "-");');
    $sock = stream_socket_server('tcp://127.0.0.1:0');
    $name = stream_socket_get_name($sock, false);
    $port = (int)substr($name, (int)strrpos($name, ':') + 1);
    fclose($sock);
    $proc = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', $dir, $dir . '/router.php'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    for ($i = 0; $i < 50; $i++) {
        $c = @fsockopen('127.0.0.1', $port, $en, $es, 0.2);
        if ($c) {
            fclose($c);
            break;
        }
        usleep(100000);
    }
    return [$port, $proc];
}

t('NativeHttp performs GET and POST with headers over curl and over streams', function () {
    [$port, $proc] = startEchoServer();
    try {
        foreach ([true, false] as $preferCurl) {
            if ($preferCurl && !function_exists('curl_init')) {
                continue;
            }
            $h = new NativeHttp($preferCurl);
            $get = $h->request('GET', "http://127.0.0.1:$port/", '', ['X-Test' => 'yes'], 5);
            assertSame(['status' => 200, 'body' => 'GET:empty:yes'], $get, 'GET preferCurl=' . var_export($preferCurl, true));
            $post = $h->request('POST', "http://127.0.0.1:$port/", 'payload', [], 5);
            assertSame(['status' => 200, 'body' => 'POST:payload:-'], $post, 'POST preferCurl=' . var_export($preferCurl, true));
            assertSame(404, $h->request('GET', "http://127.0.0.1:$port/missing", '', [], 5)['status']);
            // After a followed redirect the final response's status is reported, not the 302.
            assertSame(['status' => 404, 'body' => 'nope'], $h->request('GET', "http://127.0.0.1:$port/moved", '', [], 5), 'redirect preferCurl=' . var_export($preferCurl, true));
        }
    } finally {
        proc_terminate($proc);
        proc_close($proc);
    }
});

t('Source never reads the $http_response_header variable (unreliable before PHP 8.4, deprecated in 8.5)', function () {
    foreach (glob(dirname(__DIR__) . '/src/*.php') as $file) {
        foreach (token_get_all((string)file_get_contents($file)) as $tok) {
            if (is_array($tok) && $tok[0] === T_VARIABLE && $tok[1] === '$http_response_header') {
                throw new RuntimeException(basename($file) . ' line ' . $tok[2] . ' reads $http_response_header');
            }
        }
    }
    assertTrue(true);
});

t('NativeHttp reports transport failures as status 0 and refuses non-http URLs', function () {
    $sock = stream_socket_server('tcp://127.0.0.1:0');
    $name = stream_socket_get_name($sock, false);
    $port = (int)substr($name, (int)strrpos($name, ':') + 1);
    fclose($sock); // now nothing listens on $port
    foreach ([true, false] as $preferCurl) {
        $h = new NativeHttp($preferCurl);
        assertSame(0, $h->request('GET', "http://127.0.0.1:$port/", '', [], 2)['status']);
        assertSame(0, $h->request('GET', 'file:///etc/passwd', '', [], 2)['status']);
        assertSame(0, $h->request('GET', 'ftp://example.com/x', '', [], 2)['status']);
    }
});

t('FakeHttp matches by prefix and fails otherwise', function () {
    $f = new FakeHttp();
    $f->route('https://a.example/x', 200, 'ok');
    assertSame(['status' => 200, 'body' => 'ok'], $f->request('GET', 'https://a.example/x?y=1'));
    assertSame(0, $f->request('GET', 'https://b.example/')['status']);
    assertSame(2, count($f->calls));
});
