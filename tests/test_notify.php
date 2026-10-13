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
