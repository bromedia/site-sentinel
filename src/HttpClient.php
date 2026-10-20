<?php
declare(strict_types=1);

namespace Sentinel;

interface HttpClient
{
    /**
     * @param array<string,string> $headers
     * @return array{status:int, body:string} status is 0 on any transport failure
     */
    public function request(string $method, string $url, string $body = '', array $headers = [], int $timeout = 10): array;
}

final class NativeHttp implements HttpClient
{
    private $preferCurl;

    public function __construct(bool $preferCurl = true)
    {
        $this->preferCurl = $preferCurl;
    }

    public function request(string $method, string $url, string $body = '', array $headers = [], int $timeout = 10): array
    {
        if (!preg_match('#^https?://#i', $url)) {
            return ['status' => 0, 'body' => ''];
        }
        $lines = [];
        foreach ($headers as $k => $v) {
            $lines[] = str_replace(["\r", "\n", ':'], '', (string)$k) . ': ' . str_replace(["\r", "\n"], '', (string)$v);
        }
        $lines[] = 'User-Agent: site-sentinel/' . VERSION;
        if ($this->preferCurl && function_exists('curl_init')) {
            return $this->viaCurl($method, $url, $body, $lines, $timeout);
        }
        return $this->viaStream($method, $url, $body, $lines, $timeout);
    }

    private function viaCurl(string $method, string $url, string $body, array $lines, int $timeout): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
        ]);
        if ($body !== '') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $resp = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        unset($ch);
        if ($resp === false) {
            return ['status' => 0, 'body' => ''];
        }
        return ['status' => $status, 'body' => (string)$resp];
    }

    private function viaStream(string $method, string $url, string $body, array $lines, int $timeout): array
    {
        $ctx = stream_context_create(['http' => [
            'method' => $method,
            'header' => implode("\r\n", $lines),
            'content' => $body,
            'timeout' => $timeout,
            'ignore_errors' => true,
            'follow_location' => 1,
            'max_redirects' => 3,
        ]]);
        $fh = @fopen($url, 'rb', false, $ctx);
        if ($fh === false) {
            return ['status' => 0, 'body' => ''];
        }
        // Response headers come from the stream itself: the magic $http_response_header
        // variable is not reliably set on PHP < 8.4 and is deprecated from PHP 8.5.
        $meta = stream_get_meta_data($fh);
        $resp = stream_get_contents($fh);
        $timedOut = !empty(stream_get_meta_data($fh)['timed_out']);
        fclose($fh);
        if ($resp === false || $timedOut) {
            return ['status' => 0, 'body' => ''];
        }
        $status = 0;
        // With redirects followed, every response's headers are listed in order; the last status line wins.
        foreach ((array)($meta['wrapper_data'] ?? []) as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', (string)$h, $m)) {
                $status = (int)$m[1];
            }
        }
        return ['status' => $status, 'body' => $resp];
    }
}
