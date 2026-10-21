<?php
declare(strict_types=1);

namespace Sentinel;

final class EmailNotifier implements Notifier
{
    private $to;
    private $from;
    private $mailer;

    public function __construct(array $to, string $from, ?callable $mailer = null)
    {
        $this->to = $to;
        $from = trim(str_replace(["\r", "\n"], '', $from));
        $this->from = $from !== '' ? $from : 'sentinel@' . ((string)gethostname() !== '' ? (string)gethostname() : 'localhost');
        $this->mailer = $mailer ?? function (string $to, string $subject, string $body, string $headers): bool {
            return @mail($to, $subject, $body, $headers);
        };
    }

    public function name(): string
    {
        return 'email';
    }

    public function send(string $subject, string $body, int $severity, ?array $attachment = null): void
    {
        $to = implode(', ', $this->to);
        $encoded = self::encodeSubject($subject);
        $common = 'From: ' . $this->from . "\r\n"
            . "MIME-Version: 1.0\r\n";
        $priority = 'X-Priority: ' . ($severity >= Finding::CRITICAL ? '1' : '3') . "\r\n";
        if ($attachment !== null) {
            $boundary = '=_sentinel_' . bin2hex(random_bytes(12));
            $name = (string)preg_replace('/[^A-Za-z0-9._-]/', '_', (string)$attachment['name']);
            $message = '--' . $boundary . "\r\n"
                . "Content-Type: text/plain; charset=UTF-8\r\n"
                . "Content-Transfer-Encoding: 8bit\r\n\r\n"
                . $body . "\r\n"
                . '--' . $boundary . "\r\n"
                . 'Content-Type: text/plain; charset=UTF-8; name="' . $name . "\"\r\n"
                . "Content-Transfer-Encoding: base64\r\n"
                . 'Content-Disposition: attachment; filename="' . $name . "\"\r\n\r\n"
                . chunk_split(base64_encode((string)$attachment['content']), 76, "\r\n")
                . '--' . $boundary . "--\r\n";
            $headers = $common . 'Content-Type: multipart/mixed; boundary="' . $boundary . "\"\r\n" . $priority;
            if (($this->mailer)($to, $encoded, $message, $headers)) {
                return;
            }
            // Some mail systems refuse a large message: still get the alert out, pointing at the saved report.
            $body .= "\n\nThe full report could not be attached; it is saved on the server: " . $attachment['path'];
        }
        $headers = $common . "Content-Type: text/plain; charset=UTF-8\r\n" . $priority;
        if (!($this->mailer)($to, $encoded, $body, $headers)) {
            throw new \RuntimeException('mail() reported failure');
        }
    }

    public static function encodeSubject(string $s): string
    {
        $s = trim(str_replace(["\r", "\n"], ' ', $s));
        return preg_match('/[^\x20-\x7E]/', $s) ? '=?UTF-8?B?' . base64_encode($s) . '?=' : $s;
    }
}

final class NtfyNotifier implements Notifier
{
    private $url;
    private $http;

    public function __construct(string $url, HttpClient $http)
    {
        $this->url = $url;
        $this->http = $http;
    }

    public function name(): string
    {
        return 'ntfy';
    }

    public function send(string $subject, string $body, int $severity, ?array $attachment = null): void
    {
        if ($attachment !== null) {
            $body .= "\n\n" . AttachmentNote::pointer($attachment);
        }
        $r = $this->http->request('POST', $this->url, $body, [
            'Title' => (string)preg_replace('/[^\x20-\x7E]/', '?', $subject),
            'Priority' => $severity >= Finding::CRITICAL ? 'urgent' : 'high',
            'Tags' => $severity >= Finding::CRITICAL ? 'rotating_light' : 'warning',
        ], 10);
        if ($r['status'] < 200 || $r['status'] >= 300) {
            throw new \RuntimeException('ntfy ' . ($r['status'] === 0 ? 'network error' : 'HTTP ' . $r['status']));
        }
    }
}

final class TelegramNotifier implements Notifier
{
    private $token;
    private $chatId;
    private $http;

    public function __construct(string $token, string $chatId, HttpClient $http)
    {
        $this->token = $token;
        $this->chatId = $chatId;
        $this->http = $http;
    }

    public function name(): string
    {
        return 'telegram';
    }

    public function send(string $subject, string $body, int $severity, ?array $attachment = null): void
    {
        $text = $subject . "\n\n" . $body;
        $tail = $attachment !== null ? "\n\n" . AttachmentNote::pointer($attachment) : '';
        $max = 4000 - strlen($tail);
        $text = function_exists('mb_strcut') ? mb_strcut($text, 0, $max, 'UTF-8') : substr($text, 0, $max);
        $text .= $tail;
        $r = $this->http->request(
            'POST',
            'https://api.telegram.org/bot' . $this->token . '/sendMessage',
            http_build_query(['chat_id' => $this->chatId, 'text' => $text]),
            ['Content-Type' => 'application/x-www-form-urlencoded'],
            10
        );
        if ($r['status'] < 200 || $r['status'] >= 300) {
            throw new \RuntimeException('telegram ' . ($r['status'] === 0 ? 'network error' : 'HTTP ' . $r['status']));
        }
    }
}

final class WebhookNotifier implements Notifier
{
    private $url;
    private $http;

    public function __construct(string $url, HttpClient $http)
    {
        $this->url = $url;
        $this->http = $http;
    }

    public function name(): string
    {
        return 'webhook';
    }

    public function send(string $subject, string $body, int $severity, ?array $attachment = null): void
    {
        if ($attachment !== null) {
            $body .= "\n\n" . AttachmentNote::pointer($attachment);
        }
        $json = json_encode(['subject' => $subject, 'severity' => Finding::label($severity), 'body' => $body, 'time' => gmdate('c')], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $r = $this->http->request('POST', $this->url, (string)$json, ['Content-Type' => 'application/json'], 10);
        if ($r['status'] < 200 || $r['status'] >= 300) {
            throw new \RuntimeException('webhook ' . ($r['status'] === 0 ? 'network error' : 'HTTP ' . $r['status']));
        }
    }
}

final class FileNotifier implements Notifier
{
    private $path;

    public function __construct(string $path)
    {
        $this->path = $path;
    }

    public function name(): string
    {
        return 'file';
    }

    public function send(string $subject, string $body, int $severity, ?array $attachment = null): void
    {
        if ($attachment !== null) {
            $body .= "\n\n" . AttachmentNote::pointer($attachment);
        }
        $entry = '=== ' . gmdate('c') . ' ' . $subject . " ===\n" . $body . "\n\n";
        if (@file_put_contents($this->path, $entry, FILE_APPEND | LOCK_EX) === false) {
            throw new \RuntimeException('cannot write ' . $this->path);
        }
    }
}

final class NotifierFactory
{
    /** @return Channel[] */
    public static function fromConfig(Config $c, HttpClient $http, ?callable $mailer = null): array
    {
        $out = [];
        foreach ($c->channels as $ch) {
            switch ($ch['type']) {
                case 'email':
                    $n = new EmailNotifier($ch['to'], (string)$ch['from'], $mailer);
                    break;
                case 'ntfy':
                    $n = new NtfyNotifier($ch['url'], $http);
                    break;
                case 'telegram':
                    $n = new TelegramNotifier($ch['token'], $ch['chat_id'], $http);
                    break;
                case 'webhook':
                    $n = new WebhookNotifier($ch['url'], $http);
                    break;
                default:
                    $n = new FileNotifier($ch['path']);
            }
            $out[] = new Channel($n, Finding::parseSeverity($ch['min_severity']));
        }
        return $out;
    }
}
