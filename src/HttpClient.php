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

final class BudgetHttp implements HttpClient
{
    private $inner;
    private $budget;
    public function __construct(HttpClient $inner, Budget $budget)
    {
        $this->inner = $inner;
        $this->budget = $budget;
    }
    public function request(string $method, string $url, string $body = '', array $headers = [], int $timeout = 10): array
    {
        return $this->inner->request($method, $url, $body, $headers, $this->budget->timeout($timeout));
    }
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
        $resp = @file_get_contents($url, false, $ctx);
        if ($resp === false) {
            return ['status' => 0, 'body' => ''];
        }
        $status = 0;
        // PHP 8.4+ deprecates the magic $http_response_header variable.
        $responseHeaders = function_exists('http_get_last_response_headers')
            ? (http_get_last_response_headers() ?? [])
            : ($http_response_header ?? []);
        foreach ($responseHeaders as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', (string)$h, $m)) {
                $status = (int)$m[1];
            }
        }
        return ['status' => $status, 'body' => $resp];
    }
}
