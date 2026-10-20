<?php
declare(strict_types=1);

use Sentinel\Cli;
use Sentinel\Config;
use Sentinel\ConfigException;
use Sentinel\Run;
use Sentinel\Settings;

/** Captures mail() calls made through EmailNotifier. */
final class MailBox
{
    /** @var array<int,array{to:string,subject:string,body:string}> */
    public $sent = [];

    public function mailer(): callable
    {
        return function (string $to, string $subject, string $body, string $headers): bool {
            $this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];
            return true;
        };
    }

    public function subjects(): array
    {
        return array_column($this->sent, 'subject');
    }
}

/**
 * Lays the package out the way it is installed on xneelo: a home folder holding the extracted
 * "sentinel" folder and a public_html symlink to the real web root.
 *
 * @return array{0:string,1:string,2:string} [home, webRoot, sentinelDir]
 */
function packagedSite(array $siteFiles = [], string $emailLine = 'email = owner@client.example'): array
{
    $base = tmpdir();
    $home = $base . '/home/clientftp';
    $www = $base . '/www/users/clientftp';
    mkdir($home, 0755, true);
    mkdir($www, 0755, true);
    symlink($www, $home . '/public_html');
    $files = $siteFiles + [
        'index.php' => '<?php // wp',
        'wp-config.php' => "<?php define('DB_NAME', 'x');",
        'wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n",
        'wp-content/themes/Avada/style.css' => "/*\nTheme Name: Avada\nVersion: 7.11.9\n*/\n",
        'wp-content/themes/Avada/functions.php' => '<?php // functions',
    ];
    foreach ($files as $rel => $content) {
        putFile($www, $rel, $content);
    }
    $dir = $home . '/sentinel';
    mkdir($dir);
    $root = dirname(__DIR__);
    foreach (['sentinel.json', 'settings.txt', 'SETUP-PENDING.txt', '.htaccess'] as $f) {
        copy($root . '/package/' . $f, $dir . '/' . $f);
    }
    file_put_contents($dir . '/sentinel.php', '<?php // stands in for the built script');
    $settings = (string)file_get_contents($dir . '/settings.txt');
    file_put_contents($dir . '/settings.txt', str_replace('email = you@example.com', $emailLine, $settings));
    // Tests opt into the grace period explicitly; checksums need wordpress.org.
    $cfg = json_decode((string)file_get_contents($dir . '/sentinel.json'), true);
    file_put_contents($dir . '/sentinel.json', json_encode($cfg + ['update_grace_seconds' => 0, 'wp_checksums' => false]));
    return [$home, $www, $dir];
}

function runPackaged(string $dir, MailBox $mail, array $args = ['run']): array
{
    $r = Cli::execute($args, $dir . '/sentinel.php', new FakeHttp(), $mail->mailer());
    $r['text'] = implode("\n", array_merge($r['out'], $r['err']));
    return $r;
}

t('Settings: name = value lines, validated with line numbers', function () {
    $s = Settings::parse("\xEF\xBB\xBF# notes\nemail = a@b.example, c@d.example\nemail = A@B.example\nwebsite = Shop\ncontact = Bro Media\napprove_plugin_updates_automatically = no\n");
    assertSame(['a@b.example', 'c@d.example'], $s->emails);
    assertSame('Shop', $s->website);
    assertSame('Bro Media', $s->contact);
    assertSame(false, $s->approveUpdates);
    $bad = [
        "email = you@example.com\n" => 'replace the example address',
        "email = not-an-address\n" => "'not-an-address' is not a valid email",
        "email = a@b.example\ncontakt = x\n" => "line 2: unknown setting 'contakt'",
        "email = a@b.example\napprove_plugin_updates_automatically = maybe\n" => 'must be yes or no',
        "website = x\n" => 'add at least one',
        "email a@b.example\n" => "line 1: expected 'name = value'",
    ];
    foreach ($bad as $text => $expect) {
        try {
            Settings::parse($text);
            throw new RuntimeException('accepted: ' . $text);
        } catch (ConfigException $e) {
            assertContains($expect, $e->getMessage());
        }
    }
    assertSame(['ok@b.example'], Settings::emailsLeniently(putFile(tmpdir(), 's.txt', "email = you@example.com\nemail = ok@b.example\nbroken line\n")));
});

t('Config::load resolves relative paths against the config file and applies settings.txt', function () {
    [, $www, $dir] = packagedSite();
    $cwd = getcwd();
    chdir('/');
    try {
        $c = Config::load($dir . '/sentinel.json');
    } finally {
        chdir((string)$cwd);
    }
    assertSame(realpath($www), $c->siteRoot, 'public_html is followed to the real web root');
    assertSame($dir . '/state', $c->stateDir);
    assertSame('My website', $c->siteName);
    assertSame('Bro Media', $c->contact);
    assertSame('client', $c->audience);
    assertSame(true, $c->autoAcceptUnverifiedUpdates, 'the package default is visible in settings.txt');
    assertSame('wordpress', $c->profile);
    assertSame(['owner@client.example'], $c->channels[0]['to']);
});

t('run: the first run sets up, emails "now protecting", removes the marker; later clean runs print nothing', function () {
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    $r = runPackaged($dir, $mail);
    assertSame(0, $r['exit'], $r['text']);
    assertSame(['Site Sentinel is now protecting My website'], $mail->subjects());
    assertContains('Alerts go to: owner@client.example', $mail->sent[0]['body']);
    assertContains('approved automatically', $mail->sent[0]['body']);
    assertTrue(!is_file($dir . '/' . Run::MARKER));
    assertTrue(is_file($dir . '/state/baseline.txt'));
    $again = runPackaged($dir, $mail);
    assertSame(0, $again['exit']);
    assertSame([], $again['out'], 'nothing to print, so a hosting panel has nothing to email');
    assertSame(1, count($mail->sent));
});

t('run: no baseline and no marker is reported, never silently re-baselined', function () {
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    unlink($dir . '/state/baseline.txt');
    $r = runPackaged($dir, $mail);
    assertSame(2, $r['exit']);
    assertTrue(!is_file($dir . '/state/baseline.txt'));
    assertSame('Security monitoring problem on My website', end($mail->sent)['subject']);
    assertNotContains('php sentinel.php', end($mail->sent)['body'], 'client emails never show commands');
});

t('run: a marker left beside a working install is removed, not used to re-baseline', function () {
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    file_put_contents($dir . '/' . Run::MARKER, 'extracted again');
    $baseline = (string)file_get_contents($dir . '/state/baseline.txt');
    runPackaged($dir, $mail);
    assertTrue(!is_file($dir . '/' . Run::MARKER));
    assertSame($baseline, (string)file_get_contents($dir . '/state/baseline.txt'));
});

t('run: setup refuses to start inside the web root, and says so once a day, not every run', function () {
    [, $www] = packagedSite();
    $dir = $www . '/sentinel';
    mkdir($dir);
    $root = dirname(__DIR__);
    foreach (['sentinel.json', 'settings.txt', 'SETUP-PENDING.txt'] as $f) {
        copy($root . '/package/' . $f, $dir . '/' . $f);
    }
    file_put_contents($dir . '/sentinel.php', '<?php');
    file_put_contents($dir . '/settings.txt', str_replace('you@example.com', 'owner@client.example', (string)file_get_contents($dir . '/settings.txt')));
    file_put_contents($dir . '/sentinel.json', json_encode(['site_root' => '..', 'state_dir' => 'state', 'settings_file' => 'settings.txt', 'audience' => 'client']));
    $mail = new MailBox();
    $r = runPackaged($dir, $mail);
    assertSame(2, $r['exit']);
    assertContains('inside the public website folder', $r['text']);
    assertSame(["Site Sentinel setup could not finish on My website"], $mail->subjects());
    runPackaged($dir, $mail);
    assertSame(1, count($mail->sent), 'not repeated every run');
    assertTrue(!is_file($dir . '/state/baseline.txt'));
});

t('run: setup on an already infected site alerts, keeps the marker, and finishes once it is clean', function () {
    [, $www, $dir] = packagedSite(['wp-content/uploads/x.php' => '<?php eval($_POST["c"]);']);
    $mail = new MailBox();
    $r = runPackaged($dir, $mail);
    assertSame(1, $r['exit']);
    assertSame(['Security alert: setup found possible hacking on My website'], $mail->subjects());
    assertContains('wp-content/uploads/x.php', $mail->sent[0]['body']);
    assertTrue(is_file($dir . '/' . Run::MARKER));
    assertTrue(!is_file($dir . '/state/baseline.txt'));
    unlink($www . '/wp-content/uploads/x.php');
    assertSame(0, runPackaged($dir, $mail)['exit']);
    assertSame('Site Sentinel is now protecting My website', end($mail->sent)['subject']);
});

t('run: a full scan happens once a day on top of the check', function () {
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    $state = new Sentinel\State($dir . '/state');
    $status = $state->readJson('status.json');
    assertTrue(!Run::fullDue($state, time()), 'setup counts as the first full scan');
    assertTrue(Run::fullDue($state, time() + Run::FULL_EVERY));
    $status['full']['last_complete'] = time() - Run::FULL_EVERY - 1;
    $state->writeJson('status.json', $status);
    runPackaged($dir, $mail);
    assertTrue(!Run::fullDue($state, time()), 'the due full scan ran');
});

t('run: changing settings.txt is announced to old and new recipients, then trusted (not tampering)', function () {
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    file_put_contents($dir . '/settings.txt', str_replace('email = owner@client.example', 'email = office@client.example', (string)file_get_contents($dir . '/settings.txt')));
    $r = runPackaged($dir, $mail);
    $notices = array_values(array_filter($mail->sent, function ($m) {
        return strpos($m['subject'], 'settings changed') !== false;
    }));
    assertSame(['office@client.example', 'owner@client.example'], array_column($notices, 'to'), 'the old address hears about it too');
    assertContains('Alerts now go to: office@client.example', $notices[0]['body']);
    assertNotContains('self-tamper', $r['text']);
    $count = count($mail->sent);
    runPackaged($dir, $mail);
    assertSame($count, count($mail->sent), 'announced once');
});

t('run: a broken settings.txt is emailed to any valid address in it, once a day', function () {
    [, , $dir] = packagedSite([], "email = owner@client.example\ncontakt = typo");
    $mail = new MailBox();
    $r = runPackaged($dir, $mail);
    assertSame(2, $r['exit']);
    assertContains("unknown setting 'contakt'", $r['text']);
    assertSame(['Site Sentinel could not start: settings problem'], $mail->subjects());
    runPackaged($dir, $mail);
    assertSame(1, count($mail->sent));
});

t('Client alerts are plain language with the contact, no commands, technical detail at the end', function () {
    [, $www, $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    putFile($www, 'wp-content/uploads/2026/cache.php', '<?php eval($_POST["c"]);');
    putFile($www, 'wp-content/themes/Avada/extra.php', '<?php // quietly added');
    assertSame(1, runPackaged($dir, $mail)['exit']);
    $m = end($mail->sent);
    assertSame('Security alert: My website may have been hacked', $m['subject']);
    assertContains("POSSIBLE HACK", $m['body']);
    assertContains('contact Bro Media today', $m['body']);
    assertContains('WEBSITE FILES CHANGED', $m['body']);
    assertNotContains('php sentinel.php', $m['body']);
    assertContains('Technical details for your web developer', $m['body']);
    assertTrue(strpos($m['body'], 'POSSIBLE HACK') < strpos($m['body'], 'Technical details'));
});

t('build/package.php produces the sentinel folder ZIP with everything an install needs', function () {
    if (!class_exists('ZipArchive')) {
        skip('needs the zip extension');
    }
    $zipFile = tmpdir() . '/pkg.zip';
    $r = Sentinel\Proc::run([PHP_BINARY, dirname(__DIR__) . '/build/package.php', $zipFile], 120);
    assertSame(0, $r['exit'], $r['out'] . $r['err']);
    $zip = new ZipArchive();
    assertSame(true, $zip->open($zipFile));
    $names = [];
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $names[] = $zip->getNameIndex($i);
    }
    foreach (['sentinel/sentinel.php', 'sentinel/sentinel.json', 'sentinel/settings.txt', 'sentinel/SETUP-PENDING.txt', 'sentinel/.htaccess', 'sentinel/INSTALL-XNEELO.txt', 'sentinel/LICENSE.txt'] as $n) {
        assertTrue(in_array($n, $names, true), "missing $n");
    }
    assertContains('email = you@example.com', (string)$zip->getFromName('sentinel/settings.txt'));
    assertContains('sentinel.php run', (string)$zip->getFromName('sentinel/INSTALL-XNEELO.txt'));
    $zip->close();
});
