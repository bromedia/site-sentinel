<?php
declare(strict_types=1);

/** In-memory HttpClient: routes are matched by URL prefix; anything else fails like a dead network. */
final class FakeHttp implements \Sentinel\HttpClient
{
    /** @var array<string, array{0:int,1:string}> */
    public $routes = [];
    /** @var array[] */
    public $calls = [];

    public function route(string $urlPrefix, int $status, string $body): void
    {
        $this->routes[$urlPrefix] = [$status, $body];
    }

    public function request(string $method, string $url, string $body = '', array $headers = [], int $timeout = 10): array
    {
        $this->calls[] = [$method, $url, $body, $headers];
        foreach ($this->routes as $prefix => $r) {
            if (strpos($url, (string)$prefix) === 0) {
                return ['status' => $r[0], 'body' => $r[1]];
            }
        }
        return ['status' => 0, 'body' => ''];
    }
}
