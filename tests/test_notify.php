<?php
declare(strict_types=1);

use Sentinel\Alerter;
use Sentinel\Channel;
use Sentinel\Digest;
use Sentinel\EmailNotifier;
use Sentinel\FileNotifier;
use Sentinel\Finding;
use Sentinel\NotifierFactory;
use Sentinel\NtfyNotifier;
use Sentinel\TelegramNotifier;
use Sentinel\WebhookNotifier;

t('Digest sorts findings, counts severities and includes notes and info', function () {
    $f = [
        new Finding(Finding::WARNING, 'b/unexplained', 'unexplained-change', '3 file(s) changed', 'h'),
        new Finding(Finding::CRITICAL, 'z.php', 'php-in-uploads', 'PHP file in the uploads directory', 'h'),
        new Finding(Finding::CRITICAL, 'a.php', 'test-marker', 'Sentinel self-test marker', 'h'),
    ];
    $d = Digest::build('Client Site', 'srv1', 1760000000, $f, ['plugin foo updated 1.0 -> 1.1'], ['checksums unavailable']);
    assertSame(Finding::CRITICAL, $d['top']);
    assertSame('[Sentinel][CRITICAL] Client Site: 2 critical, 1 warning', $d['subject']);
    $b = $d['body'];
    assertTrue(strpos($b, 'a.php') < strpos($b, 'z.php') && strpos($b, 'z.php') < strpos($b, 'b/unexplained'), 'critical first, then by path');
    assertContains('srv1', $b);
    assertContains('2025-10-09 08:53:20 UTC', $b);
    assertContains('php-in-uploads: PHP file in the uploads directory', $b);
    assertContains('What to do:', $b);
    assertContains("Notes\n  - checksums unavailable", $b);
    assertContains("Info\n  - plugin foo updated 1.0 -> 1.1", $b);
});

t('Digest of only warnings has a warning subject and a generic action for unknown rules', function () {
    $d = Digest::build('S', 'h', 0, [new Finding(Finding::WARNING, 'x', 'some-new-rule', 'm')], [], []);
    assertSame(Finding::WARNING, $d['top']);
    assertSame('[Sentinel][WARNING] S: 0 critical, 1 warning', $d['subject']);
    assertContains('What to do:', $d['body']);
});

t('Alerter filters by channel severity and reports failures (Review Focus 4)', function () {
    $all = new FakeNotifier('all');
    $crit = new FakeNotifier('crit');
    $broken = new FakeNotifier('broken');
    $broken->fail = true;
    $a = new Alerter([new Channel($all, Finding::WARNING), new Channel($crit, Finding::CRITICAL), new Channel($broken, Finding::WARNING)]);

    $r = $a->send('s', 'b', Finding::WARNING);
    assertTrue($r['ok']);
    assertSame(2, $r['attempted']);
    assertSame(0, count($crit->sent));
    assertSame(['all: sent', 'broken: FAILED - simulated failure'], $r['results']);

    $r2 = $a->send('s', 'b', Finding::CRITICAL);
    assertSame(3, $r2['attempted']);
    assertSame(1, count($crit->sent));

    $only = new Alerter([new Channel($broken, Finding::WARNING)]);
    $r3 = $only->send('s', 'b', Finding::CRITICAL);
    assertSame(false, $r3['ok'], 'every attempted channel failed');

    $none = new Alerter([new Channel($all, Finding::CRITICAL)]);
    $r4 = $none->send('s', 'b', Finding::WARNING);
    assertTrue($r4['ok'], 'nothing to attempt is not a failure');
    assertSame(0, $r4['attempted']);
});

t('EmailNotifier builds safe headers and encodes non-ASCII subjects', function () {
    $calls = [];
    $mailer = function (string $to, string $subject, string $body, string $headers) use (&$calls): bool {
        $calls[] = [$to, $subject, $body, $headers];
        return true;
    };
    $n = new EmailNotifier(['a@example.com', 'b@example.com'], "from@example.com\r\nBcc: evil@example.com", $mailer);
    $n->send("Héllo\r\nBcc: x@y.z", 'body text', Finding::CRITICAL);
    assertSame('a@example.com, b@example.com', $calls[0][0]);
    assertTrue(strpos($calls[0][1], '=?UTF-8?B?') === 0);
    assertNotContains("\n", $calls[0][1]);
    assertNotContains("\nBcc:", $calls[0][3]);
    assertContains('X-Priority: 1', $calls[0][3]);
    assertSame('Plain ASCII', EmailNotifier::encodeSubject('Plain ASCII'));

    $bad = new EmailNotifier(['a@example.com'], '', function () { return false; });
    assertThrows(RuntimeException::class, function () use ($bad) { $bad->send('s', 'b', Finding::WARNING); });
});

t('Ntfy, Telegram and Webhook notifiers post the right requests and fail on non-2xx', function () {
    $http = new FakeHttp();
    $http->route('https://ntfy.example/topic', 200, 'ok');
    (new NtfyNotifier('https://ntfy.example/topic', $http))->send('Subject é', 'the body', Finding::CRITICAL);
    [$m, $u, $body, $h] = $http->calls[0];
    assertSame(['POST', 'https://ntfy.example/topic', 'the body'], [$m, $u, $body]);
    assertSame('urgent', $h['Priority']);
    assertSame('Subject ??', $h['Title'], 'non-ASCII bytes are replaced in the header');

    $http2 = new FakeHttp();
    $http2->route('https://api.telegram.org/bot123:abc/sendMessage', 200, '{"ok":true}');
    (new TelegramNotifier('123:abc', '-100', $http2))->send('Sub', str_repeat('x', 5000), Finding::WARNING);
    parse_str($http2->calls[0][2], $form);
    assertSame('-100', $form['chat_id']);
    assertTrue(strlen($form['text']) <= 4000);
    assertContains('Sub', $form['text']);

    $http3 = new FakeHttp();
    $http3->route('https://hook.example/h', 204, '');
    (new WebhookNotifier('https://hook.example/h', $http3))->send('Sub', 'Body', Finding::WARNING);
    $payload = json_decode($http3->calls[0][2], true);
    assertSame(['subject' => 'Sub', 'severity' => 'WARNING', 'body' => 'Body'], array_intersect_key($payload, array_flip(['subject', 'severity', 'body'])));
    assertSame('application/json', $http3->calls[0][3]['Content-Type']);

    $dead = new FakeHttp();
    $dead->route('https://ntfy.example/', 500, 'boom');
    assertThrows(RuntimeException::class, function () use ($dead) {
        (new NtfyNotifier('https://ntfy.example/topic', $dead))->send('s', 'b', Finding::WARNING);
    });
    assertThrows(RuntimeException::class, function () {
        (new WebhookNotifier('https://unreachable.example/', new FakeHttp()))->send('s', 'b', Finding::WARNING);
    });
});

t('FileNotifier appends alerts to a file', function () {
    $f = tmpdir() . '/alerts.log';
    $n = new FileNotifier($f);
    $n->send('first', 'body one', Finding::WARNING);
    $n->send('second', 'body two', Finding::WARNING);
    $c = (string)file_get_contents($f);
    assertContains('first', $c);
    assertContains('body two', $c);
    assertThrows(RuntimeException::class, function () {
        (new FileNotifier('/proc/nope/alerts.log'))->send('s', 'b', Finding::WARNING);
    });
});

t('NotifierFactory builds channels from config', function () {
    $c = makeConfig(tmpdir(), ['channels' => [
        ['type' => 'email', 'to' => ['o@example.com']],
        ['type' => 'ntfy', 'url' => 'https://ntfy.sh/t', 'min_severity' => 'critical'],
        ['type' => 'telegram', 'token' => 't', 'chat_id' => '1'],
        ['type' => 'webhook', 'url' => 'https://h.example/x'],
        ['type' => 'file', 'path' => '/tmp/x.log', 'min_severity' => 'info'],
    ]]);
    $ch = NotifierFactory::fromConfig($c, new FakeHttp(), function () { return true; });
    assertSame(['email', 'ntfy', 'telegram', 'webhook', 'file'], array_map(function (Channel $x) { return $x->notifier->name(); }, $ch));
    assertSame([Finding::WARNING, Finding::CRITICAL, Finding::WARNING, Finding::WARNING, Finding::INFO], array_map(function (Channel $x) { return $x->minSeverity; }, $ch));
});

function sampleAttachment(string $content = "Sentinel report\nline two\n"): array
{
    return ['name' => 'sentinel-report-site-20251009-0853.txt', 'path' => 'sentinel/state/reports/sentinel-report-site-20251009-0853.txt', 'content' => $content];
}

t('EmailNotifier attaches the report as a well-formed multipart message', function () {
    $mail = new MailBox();
    $content = str_repeat("a long report line with some text in it\n", 40) . "caf\xC3\xA9\n";
    $n = new EmailNotifier(['a@example.com'], 'from@example.com', $mail->mailer());
    $n->send('Subject', "the alert body\nsecond line", Finding::WARNING, sampleAttachment($content));
    assertSame(1, count($mail->sent));
    $h = $mail->sent[0]['headers'];
    $b = $mail->sent[0]['body'];
    assertTrue((bool)preg_match('/^Content-Type: multipart\/mixed; boundary="([^"]+)"\r?$/m', $h, $m), 'multipart/mixed with a boundary');
    $boundary = $m[1];
    assertContains('MIME-Version: 1.0', $h);
    assertContains('From: from@example.com', $h);
    assertContains('X-Priority: 3', $h);
    assertNotContains($boundary, $content);
    assertSame(3, substr_count($b, '--' . $boundary), 'two parts and the closing marker');
    assertContains('--' . $boundary . '--', $b);
    assertContains("Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit", $b);
    assertContains("the alert body\nsecond line", $b);
    assertContains('Content-Type: text/plain; charset=UTF-8; name="sentinel-report-site-20251009-0853.txt"', $b);
    assertContains('Content-Disposition: attachment; filename="sentinel-report-site-20251009-0853.txt"', $b);
    assertContains('Content-Transfer-Encoding: base64', $b);
    foreach (explode("\r\n", substr($b, (int)strpos($b, 'base64'))) as $line) {
        assertTrue(strlen($line) <= 76 || strpos($line, '--') === 0 || strpos($line, 'Content') === 0 || $line === 'base64', 'base64 lines are at most 76 characters');
    }
    $att = $mail->attachment(0);
    assertSame('sentinel-report-site-20251009-0853.txt', $att['name']);
    assertSame($content, $att['content']);
});

t('EmailNotifier retries without the attachment when mail() refuses it', function () {
    $calls = [];
    $mailer = function (string $to, string $subject, string $body, string $headers) use (&$calls): bool {
        $calls[] = ['body' => $body, 'headers' => $headers];
        return strpos($headers, 'multipart') === false;
    };
    $n = new EmailNotifier(['a@example.com'], 'from@example.com', $mailer);
    $n->send('Subject', 'the alert body', Finding::WARNING, sampleAttachment());
    assertSame(2, count($calls));
    assertContains('multipart', $calls[0]['headers']);
    assertNotContains('multipart', $calls[1]['headers']);
    assertContains('the alert body', $calls[1]['body']);
    assertContains('The full report could not be attached; it is saved on the server: sentinel/state/reports/sentinel-report-site-20251009-0853.txt', $calls[1]['body']);

    $dead = new EmailNotifier(['a@example.com'], 'from@example.com', function () { return false; });
    assertThrows(RuntimeException::class, function () use ($dead) { $dead->send('s', 'b', Finding::WARNING, sampleAttachment()); });
});

t('EmailNotifier without an attachment sends exactly the plain message', function () {
    $calls = [];
    $mailer = function (string $to, string $subject, string $body, string $headers) use (&$calls): bool {
        $calls[] = [$to, $subject, $body, $headers];
        return true;
    };
    (new EmailNotifier(['a@example.com'], 'from@example.com', $mailer))->send('Subj', 'plain body', Finding::CRITICAL);
    assertSame(['a@example.com', 'Subj', 'plain body',
        "From: from@example.com\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nX-Priority: 1\r\n"], $calls[0]);
});

t('other channels get a pointer to the server copy', function () {
    $pointer = 'Full report saved on the server: sentinel/state/reports/sentinel-report-site-20251009-0853.txt';
    $att = sampleAttachment();

    $http = new FakeHttp();
    $http->route('https://ntfy.example/topic', 200, 'ok');
    (new NtfyNotifier('https://ntfy.example/topic', $http))->send('S', 'the body', Finding::WARNING, $att);
    assertSame("the body\n\n" . $pointer, $http->calls[0][2]);

    $http2 = new FakeHttp();
    $http2->route('https://api.telegram.org/', 200, '{"ok":true}');
    (new TelegramNotifier('123:abc', '-100', $http2))->send('S', str_repeat('x', 5000), Finding::WARNING, $att);
    parse_str($http2->calls[0][2], $form);
    assertTrue(strlen($form['text']) <= 4000);
    assertSame($pointer, substr($form['text'], -strlen($pointer)), 'the pointer survives the length cut');

    $http3 = new FakeHttp();
    $http3->route('https://hook.example/h', 204, '');
    (new WebhookNotifier('https://hook.example/h', $http3))->send('S', 'Body', Finding::WARNING, $att);
    $payload = json_decode($http3->calls[0][2], true);
    assertSame("Body\n\n" . $pointer, $payload['body']);

    $f = tmpdir() . '/alerts.log';
    (new FileNotifier($f))->send('S', 'file body', Finding::WARNING, $att);
    assertContains("file body\n\n" . $pointer . "\n", (string)file_get_contents($f));
});

t('without an attachment the other channels send exactly what they always did', function () {
    $http = new FakeHttp();
    $http->route('https://ntfy.example/topic', 200, 'ok');
    (new NtfyNotifier('https://ntfy.example/topic', $http))->send('S', 'the body', Finding::WARNING);
    assertSame('the body', $http->calls[0][2]);

    $http3 = new FakeHttp();
    $http3->route('https://hook.example/h', 204, '');
    (new WebhookNotifier('https://hook.example/h', $http3))->send('S', 'Body', Finding::WARNING);
    assertSame('Body', json_decode($http3->calls[0][2], true)['body']);

    $http2 = new FakeHttp();
    $http2->route('https://api.telegram.org/', 200, '{"ok":true}');
    (new TelegramNotifier('123:abc', '-100', $http2))->send('S', 'tb', Finding::WARNING);
    parse_str($http2->calls[0][2], $form);
    assertSame("S\n\ntb", $form['text']);

    $f = tmpdir() . '/plain.log';
    (new FileNotifier($f))->send('S', 'fb', Finding::WARNING);
    assertSame(1, preg_match('/^=== \S+ S ===\nfb\n\n$/', (string)file_get_contents($f)));
});

t('Alerter hands the attachment to every channel it sends to', function () {
    $a = new FakeNotifier('a');
    $b = new FakeNotifier('b');
    $att = sampleAttachment();
    (new Alerter([new Channel($a, Finding::WARNING), new Channel($b, Finding::CRITICAL)]))->send('s', 'b', Finding::CRITICAL, $att);
    assertSame($att, $a->sent[0]['attachment']);
    assertSame($att, $b->sent[0]['attachment']);
    (new Alerter([new Channel($a, Finding::WARNING)]))->send('s', 'b', Finding::WARNING);
    assertSame(null, $a->sent[1]['attachment']);
});

t('EmailNotifier sends the attached-wording body only with the attachment; other channels never use it', function () {
    $att = sampleAttachment() + ['body' => "the alert body\nIt is attached."];
    $mail = new MailBox();
    (new EmailNotifier(['a@example.com'], 'from@example.com', $mail->mailer()))->send('S', 'the alert body', Finding::WARNING, $att);
    assertContains("the alert body\nIt is attached.\r\n", $mail->sent[0]['body'], 'the multipart body says it is attached');

    $calls = [];
    $mailer = function (string $to, string $subject, string $body, string $headers) use (&$calls): bool {
        $calls[] = $body;
        return strpos($headers, 'multipart') === false;
    };
    (new EmailNotifier(['a@example.com'], 'from@example.com', $mailer))->send('S', 'the alert body', Finding::WARNING, $att);
    assertNotContains('It is attached.', $calls[1], 'refused with the file: the plain retry does not claim it');

    $f = tmpdir() . '/alerts.log';
    (new FileNotifier($f))->send('S', 'file body', Finding::WARNING, $att);
    assertNotContains('It is attached.', (string)file_get_contents($f));
    $http = new FakeHttp();
    $http->route('https://ntfy.example/topic', 200, 'ok');
    (new NtfyNotifier('https://ntfy.example/topic', $http))->send('S', 'the body', Finding::WARNING, $att);
    assertNotContains('It is attached.', $http->calls[0][2]);
});

t('Alerter with a scrubber cleans the subject, body and both attachment texts; without one nothing changes', function () {
    $att = ['name' => 'r.txt', 'path' => 'state/reports/r.txt', 'content' => "at /h/a/x\n", 'body' => 'attached /h/a/y'];
    $plain = new FakeNotifier('plain');
    (new Alerter([new Channel($plain, Finding::WARNING)]))->send('S /h/a/s', 'B /h/a/b', Finding::WARNING, $att);
    assertSame('S /h/a/s', $plain->sent[0]['subject']);
    assertSame('B /h/a/b', $plain->sent[0]['body']);
    assertSame($att, $plain->sent[0]['attachment'], 'byte-identical without a scrubber');

    $scrub = function (string $s): string {
        return str_replace('/h/a/', '', $s);
    };
    $n = new FakeNotifier('scrubbed');
    (new Alerter([new Channel($n, Finding::WARNING)], $scrub))->send('S /h/a/s', 'B /h/a/b', Finding::WARNING, $att);
    assertSame('S s', $n->sent[0]['subject']);
    assertSame('B b', $n->sent[0]['body']);
    assertSame(['name' => 'r.txt', 'path' => 'state/reports/r.txt', 'content' => "at x\n", 'body' => 'attached y'], $n->sent[0]['attachment']);
    (new Alerter([new Channel($n, Finding::WARNING)], $scrub))->send('S', 'B /h/a/b', Finding::WARNING);
    assertSame(null, $n->sent[1]['attachment']);
    // an attachment without the alternative body gets none invented
    (new Alerter([new Channel($n, Finding::WARNING)], $scrub))->send('S', 'B', Finding::WARNING, ['name' => 'r', 'path' => 'p', 'content' => 'c /h/a/z']);
    assertSame(['name' => 'r', 'path' => 'p', 'content' => 'c z'], $n->sent[2]['attachment']);
});

t('Alerter: a scrubber that throws or returns nothing never costs the alert; it goes out unscrubbed', function () {
    $n = new FakeNotifier();
    (new Alerter([new Channel($n, Finding::WARNING)], function (string $s): string {
        throw new RuntimeException('boom');
    }))->send('S', 'B', Finding::WARNING, ['name' => 'r', 'path' => 'p', 'content' => 'c']);
    (new Alerter([new Channel($n, Finding::WARNING)], function (string $s): string {
        return '';
    }))->send('S2', 'B2', Finding::WARNING);
    assertSame(['S', 'B', 'S2', 'B2'], [$n->sent[0]['subject'], $n->sent[0]['body'], $n->sent[1]['subject'], $n->sent[1]['body']]);
    assertSame('c', $n->sent[0]['attachment']['content']);
});

t('Report::pathScrubber is the report\'s rule: home and website folder become relative, siblings are left alone, empty values are safe', function () {
    $s = \Sentinel\Report::pathScrubber('/h/a/public_html', '/h/a');
    assertSame('sentinel/sentinel.php', $s('/h/a/sentinel/sentinel.php'));
    assertSame('index.php', $s('/h/a/public_html/index.php'));
    assertSame('.', $s('/h/a/public_html'));
    assertSame('public_html_old/x', $s('/h/a/public_html_old/x'), 'a sibling of the website folder is not mangled into the website folder');
    assertSame('see /elsewhere/x', $s('see /elsewhere/x'));
    $noRoot = \Sentinel\Report::pathScrubber('', '/h/a');
    assertSame('public_html/x', $noRoot('/h/a/public_html/x'));
    $none = \Sentinel\Report::pathScrubber('', '');
    assertSame('/h/a/x', $none('/h/a/x'));
    $slash = \Sentinel\Report::pathScrubber('/', '/');
    assertSame('/h/a/x', $slash('/h/a/x'));
});
