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
    /** @var array<int,array{to:string,subject:string,body:string,headers:string}> */
    public $sent = [];
    /** While true, every send fails the way mail() does when the mail system is down. */
    public $failing = false;

    public function mailer(): callable
    {
        return function (string $to, string $subject, string $body, string $headers): bool {
            if ($this->failing) {
                return false;
            }
            $this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body, 'headers' => $headers];
            return true;
        };
    }

    /**
     * The attachment of the $i-th message, decoded from its MIME, or null when it has none.
     *
     * @return array{name:string, content:string}|null
     */
    public function attachment(int $i): ?array
    {
        $m = $this->sent[$i] ?? null;
        if ($m === null || !preg_match('/boundary="([^"]+)"/', $m['headers'], $b)) {
            return null;
        }
        foreach (explode('--' . $b[1], $m['body']) as $part) {
            if (!preg_match('/Content-Disposition: attachment; filename="([^"]+)"/i', $part, $f)) {
                continue;
            }
            $pos = strpos($part, "\r\n\r\n");
            $raw = $pos === false ? '' : substr($part, $pos + 4);
            return ['name' => $f[1], 'content' => (string)base64_decode($raw)];
        }
        return null;
    }

    /** @return array<int,array{to:string,subject:string,body:string,headers:string}> */
    public function since(int $n): array
    {
        return array_slice($this->sent, $n);
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

t('Settings: changed_files accepts tell me / quiet / yes / no and rejects anything else', function () {
    $base = "email = a@b.example\n";
    assertSame(null, Settings::parse($base)->quietChanges);
    foreach (['tell me' => false, 'Quiet' => true, 'yes' => false, 'no' => true, 'QUIET' => true, 'Tell Me' => false] as $value => $quiet) {
        $s = Settings::parse($base . "changed_files = $value\n");
        assertSame($quiet, $s->quietChanges, $value);
        $back = Settings::fromArray($s->toArray());
        assertSame($quiet, $back->quietChanges, "round trip of $value");
    }
    assertSame('quiet', Settings::parse($base . "changed_files = quiet\n")->toArray()['changed_files']);
    assertSame('tell me', Settings::parse($base . "changed_files = tell me\n")->toArray()['changed_files']);
    assertSame(null, Settings::parse($base)->toArray()['changed_files']);
    assertSame(null, Settings::fromArray(['emails' => ['a@b.example']])->quietChanges);
    try {
        Settings::parse($base . "changed_files = maybe\n");
        throw new RuntimeException('accepted maybe');
    } catch (Sentinel\SettingsException $e) {
        assertContains('changed_files must be "tell me" or "quiet"', $e->getMessage());
    }
});

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
        "just some words\n" => "line 1: expected 'name = value'",
        "email = Jane Smith\n" => "'Jane Smith' is not a valid email",
        "email = jane@client\n" => "'jane@client' is not a valid email",
    ];
    foreach ($bad as $text => $expect) {
        try {
            Settings::parse($text);
            throw new RuntimeException('accepted: ' . $text);
        } catch (Sentinel\SettingsException $e) {
            assertContains($expect, $e->getMessage());
        }
    }
    // The ways people actually write an address line are understood.
    foreach ([
        "Email: jane@client.example\n",
        "email = Jane Smith <jane@client.example>\n",
        "jane@client.example\n",
        "Jane Smith <jane@client.example>\n",
        "email jane@client.example\n",
        "E-mail = jane@client.example;\n",
    ] as $text) {
        assertSame(['jane@client.example'], Settings::parse($text)->emails, $text);
    }
    assertSame(['ok@b.example', 'jane@x.example'], Settings::emailsLeniently(putFile(tmpdir(), 's2.txt', "email = ok@b.example\nJane <jane@x.example>\nwebsite: Shop\n")));
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
    assertSame('Bro Media (info@bromedia.co.za)', $c->contact);
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

t('run: a welcome email that could not be sent is retried, without setting up again', function () {
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    $mail->failing = true;
    $r = runPackaged($dir, $mail);
    assertSame(2, $r['exit'], 'a setup whose email failed is not a clean run');
    assertTrue(is_file($dir . '/state/baseline.txt'), 'the setup itself is kept');
    $baseline = (string)file_get_contents($dir . '/state/baseline.txt');
    $mail->failing = false;
    runPackaged($dir, $mail);
    assertSame(['Site Sentinel is now protecting My website'], $mail->subjects(), 'sent once mail works');
    assertSame($baseline, (string)file_get_contents($dir . '/state/baseline.txt'), 'not set up again');
    runPackaged($dir, $mail);
    assertSame(1, count($mail->sent), 'and only once');
});

t('run: setup with a flagged file sends the report with the welcome, also on a retry', function () {
    $flagged = ['wp-content/uploads/x.php' => '<?php eval($_POST["c"]);'];
    $welcomeIndex = function (MailBox $mail): int {
        foreach ($mail->sent as $i => $m) {
            if (strpos($m['subject'], 'is now protecting') !== false) {
                return $i;
            }
        }
        throw new RuntimeException('no welcome sent: ' . implode(' | ', $mail->subjects()));
    };

    // Nothing sent holds an absolute path (they contain the hosting account name): not the site
    // root (real or through the public_html link), the home folder, nor the sentinel folder.
    $noPaths = function (MailBox $mail, int $i, string $home, string $www, string $dir): void {
        $sent = $mail->sent[$i]['body'] . (string)($mail->attachment($i)['content'] ?? '');
        foreach ([$www, (string)realpath($www), $home, (string)realpath($home), $dir] as $path) {
            assertNotContains($path, $sent, 'an absolute path was sent');
        }
        assertContains('Website folder: public_html', $mail->sent[$i]['body']);
    };
    // The owner is told the report is attached, above the footer, only when it is.
    $attachedSaid = function (string $body, string $name): void {
        $sentence = "Every finding and changed file is listed in the attached report ($name).";
        assertContains($sentence, $body, 'the welcome says the report is attached');
        assertTrue(strpos($body, $sentence) < strpos($body, 'Questions about this email?'), 'above the footer');
    };

    // Delivered at once: the report lists the flagged file.
    [$home, $www, $dir] = packagedSite($flagged);
    $mail = new MailBox();
    runPackaged($dir, $mail);
    $att = $mail->attachment(0);
    assertTrue($att !== null, 'the setup email carries the report');
    assertContains('wp-content/uploads/x.php', $att['content'], 'the flagged file is listed');
    assertContains('Scan mode: setup', $att['content']);
    assertTrue(is_file($dir . '/state/reports/' . $att['name']), 'a copy is kept on the server');
    $noPaths($mail, 0, $home, $www, $dir);
    assertNotContains('could not be', $mail->sent[0]['body']);
    $attachedSaid($mail->sent[0]['body'], $att['name']);
    assertTrue(!is_file($dir . '/state/welcome-pending.json'), 'delivered, so nothing is waiting');

    // Mail down at setup: the retry carries the same report, from the server copy.
    [$home, $www, $dir] = packagedSite($flagged);
    $mail = new MailBox();
    $mail->failing = true;
    runPackaged($dir, $mail);
    $pending = json_decode((string)file_get_contents($dir . '/state/welcome-pending.json'), true);
    assertTrue(is_file((string)$pending['report']), 'the pending welcome points at the saved report');
    $mail->failing = false;
    runPackaged($dir, $mail);
    $att = $mail->attachment($welcomeIndex($mail));
    assertTrue($att !== null, 'the retried welcome carries the report');
    assertSame(basename((string)$pending['report']), $att['name']);
    assertContains('wp-content/uploads/x.php', $att['content']);
    $noPaths($mail, $welcomeIndex($mail), $home, $www, $dir);
    $attachedSaid($mail->sent[$welcomeIndex($mail)]['body'], $att['name']);

    // The server copy gone before the retry: sent without it, and says so, above the footer.
    [$home, $www, $dir] = packagedSite($flagged);
    $mail = new MailBox();
    $mail->failing = true;
    runPackaged($dir, $mail);
    $pending = json_decode((string)file_get_contents($dir . '/state/welcome-pending.json'), true);
    unlink((string)$pending['report']);
    $mail->failing = false;
    runPackaged($dir, $mail);
    $i = $welcomeIndex($mail);
    assertSame(null, $mail->attachment($i), 'nothing to attach');
    $body = $mail->sent[$i]['body'];
    assertContains('The full report could not be attached.', $body);
    assertNotContains('attached report', $body, 'nothing attached, so it does not say so');
    $noPaths($mail, $i, $home, $www, $dir);
    assertTrue(strpos($body, 'The full report could not be attached.') < strpos($body, 'Questions about this email?'), 'the note is above the footer');
    assertTrue(!is_file($dir . '/state/welcome-pending.json'), 'and it is not retried again');

    // The report cannot be saved: setup completes and the email goes out, saying why.
    [$home, $www, $dir] = packagedSite($flagged);
    mkdir($dir . '/state', 0700);
    file_put_contents($dir . '/state/reports', 'in the way');
    $mail = new MailBox();
    $r = runPackaged($dir, $mail);
    assertTrue(is_file($dir . '/state/baseline.txt'), 'setup still completes');
    assertSame(1, $r['exit']);
    assertSame(null, $mail->attachment(0));
    $body = $mail->sent[0]['body'];
    assertContains('The full report could not be saved: ', $body);
    assertNotContains('attached report', $body, 'nothing attached, so it does not say so');
    $noPaths($mail, 0, $home, $www, $dir);
    assertTrue(strpos($body, 'could not be saved') < strpos($body, 'Questions about this email?'), 'the note is above the footer');

    // A clean setup has no report.
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    assertSame(null, $mail->attachment(0));
    assertTrue(!is_dir($dir . '/state/reports'), 'no report was written');
});

t('Config: the website folder is shown to a client as configured, never as an absolute path', function () {
    [, $www, $dir] = packagedSite();
    $label = function (string $setting, string $audience) use ($www, $dir): string {
        $c = Config::fromArray(['site_root' => $www, 'state_dir' => $dir . '/state', 'audience' => $audience, 'site_name' => 'Shop']);
        $c->siteRootSetting = $setting;
        return $c->siteFolderLabel();
    };
    assertSame('public_html', $label('../public_html', 'client'));
    assertSame('public_html', $label('./../../public_html/', 'client'));
    assertSame('sites/shop', $label('../sites/shop', 'client'));
    assertSame('public_ssl', $label('/usr/home/someone/public_ssl', 'client'), 'absolute: the last segment only');
    assertSame('clientftp', $label('', 'client'), 'not loaded from a file: the folder name');
    assertSame('clientftp', $label('..', 'client'));
    assertSame(realpath($www), $label('../public_html', 'technical'), 'technical output is unchanged');
});

t('run: no baseline and no marker is reported, never silently re-baselined', function () {
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    unlink($dir . '/state/baseline.txt');
    $r = runPackaged($dir, $mail);
    assertSame(2, $r['exit']);
    assertTrue(!is_file($dir . '/state/baseline.txt'));
    assertSame("Security alert: Site Sentinel's records were removed on My website", end($mail->sent)['subject']);
    assertNotContains('php sentinel.php', end($mail->sent)['body'], 'client emails never show commands');
});

t('run: deleting the baseline and recreating the marker does not set up again over an installed site', function () {
    [, $www, $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    // Someone who can edit the files: remove the record, ask for a fresh setup, redirect the alerts.
    unlink($dir . '/state/baseline.txt');
    file_put_contents($dir . '/' . Run::MARKER, 'set me up again');
    file_put_contents($dir . '/settings.txt', str_replace('email = owner@client.example', 'email = attacker@evil.example', (string)file_get_contents($dir . '/settings.txt')));
    putFile($www, '.htaccess', "RewriteRule ^ https://spam.example/ [R=302,L]\n");
    $n = count($mail->sent);
    $r = runPackaged($dir, $mail);
    assertSame(2, $r['exit']);
    assertTrue(!is_file($dir . '/state/baseline.txt'), 'nothing was re-baselined');
    $to = array_column($mail->since($n), 'to');
    assertTrue(in_array('owner@client.example', $to, true), 'the address that was receiving alerts is told: ' . implode(', ', $to));
    assertContains("records were removed", end($mail->sent)['subject']);
});

t('run: setup ignores a rules.json nobody vouches for', function () {
    [, $www, $dir] = packagedSite(['wp-content/themes/Avada/shell.php' => '<?php eval($_POST["c"]);']);
    mkdir($dir . '/state', 0700);
    file_put_contents($dir . '/state/rules.json', json_encode(['version' => 999, 'patterns' => []]));
    $mail = new MailBox();
    $r = runPackaged($dir, $mail);
    assertSame(1, $r['exit'], 'the built-in rules still found the backdoor');
    assertSame(['Security alert: Site Sentinel is now protecting My website and found possible hacking'], $mail->subjects());
    assertNotContains('shell.php', (string)file_get_contents($dir . '/state/baseline.txt'));
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
    $mail = new MailBox();
    // The shipped sentinel.json, unmodified: its ../public_html points nowhere from inside public_html.
    $r = runPackaged($dir, $mail);
    assertSame(2, $r['exit']);
    assertSame(['Site Sentinel setup could not finish on your website'], $mail->subjects());
    assertContains('inside the public website folder', $mail->sent[0]['body']);
    assertContains('next to public_html', $mail->sent[0]['body']);
    assertNotContains($www, $mail->sent[0]['body'], 'the website folder is not shown by its absolute path');
    assertNotContains((string)realpath($www), $mail->sent[0]['body']);
    runPackaged($dir, $mail);
    assertSame(1, count($mail->sent), 'not repeated every run');
    // And a config that does reach the web root from there is refused by the setup itself.
    file_put_contents($dir . '/sentinel.json', json_encode(['site_root' => '..', 'state_dir' => 'state', 'settings_file' => 'settings.txt', 'audience' => 'client']));
    $r = runPackaged($dir, $mail);
    assertSame(2, $r['exit']);
    assertContains('inside the public website folder', $r['text']);
    assertSame('Site Sentinel setup could not finish on My website', end($mail->sent)['subject']);
    assertNotContains($www, end($mail->sent)['body'], 'nor in the email sent after the config was read');
    assertNotContains((string)realpath($www), end($mail->sent)['body']);
    assertTrue(!is_file($dir . '/state/baseline.txt'));
});

t('run: setup on an already infected site watches the rest, keeps the flagged file out of the baseline and keeps reporting it', function () {
    [, $www, $dir] = packagedSite(['wp-content/uploads/x.php' => '<?php eval($_POST["c"]);']);
    $mail = new MailBox();
    $r = runPackaged($dir, $mail);
    assertSame(1, $r['exit'], $r['text']);
    assertSame(['Security alert: Site Sentinel is now protecting My website and found possible hacking'], $mail->subjects());
    $body = $mail->sent[0]['body'];
    assertContains('  - wp-content/uploads/x.php', $body);
    assertContains('not recorded as normal', $body);
    assertContains('Files recorded: 5', $body, 'the flagged file is not counted');
    assertContains('test that alerts reach you', $body);
    assertNotContains('php sentinel.php', $body, 'client emails never show commands');
    assertTrue(strpos($body, 'not recorded as normal') < strpos($body, 'Technical details'));
    assertTrue(preg_match('/php-in-uploads wp-content\/uploads\/x\.php: .* \[id ([0-9a-f]{12})\]/', $body, $m) === 1, $body);
    assertTrue(!is_file($dir . '/' . Run::MARKER), 'setup is finished');
    $baseline = (string)file_get_contents($dir . '/state/baseline.txt');
    assertNotContains('uploads/x.php', $baseline, 'nothing flagged enters the baseline');
    assertContains('wp-content/themes/Avada/functions.php', $baseline);

    // The rest of the site is watched: a change no pattern catches is still reported, its folder
    // (with the count) in the email and the file itself by name in the attached report.
    file_put_contents($www . '/wp-content/themes/Avada/functions.php', "<?php include __DIR__ . '/cache.dat';");
    touch($www . '/wp-content/themes/Avada/functions.php', time() + 5);
    clearstatcache();
    $n = count($mail->sent);
    assertSame(1, runPackaged($dir, $mail)['exit']);
    $body = implode("\n", array_column($mail->since($n), 'body'));
    assertContains('  - 1 file changed in wp-content/themes/Avada', $body);
    assertContains('1 file(s) changed without a version change', $body);
    $att = $mail->attachment($n);
    assertTrue($att !== null, 'the report is attached');
    assertContains('wp-content/themes/Avada/functions.php', $att['content'], 'the file itself is in the report');
    runPackaged($dir, $mail, ['accept', '--path=wp-content/themes/Avada/functions.php']);

    // The flagged file is reported again once the daily reminder is due.
    $log = json_decode((string)file_get_contents($dir . '/state/alerts.json'), true);
    foreach ($log as $k => $e) {
        $log[$k]['alerted'] = (int)$e['alerted'] - 90000;
    }
    file_put_contents($dir . '/state/alerts.json', json_encode($log));
    $n = count($mail->sent);
    assertSame(1, runPackaged($dir, $mail)['exit']);
    assertContains('wp-content/uploads/x.php', implode("\n", array_column($mail->since($n), 'body')), 'still reported');

    // Reviewed as harmless: dismissed by the id from the setup email, then accepted.
    $d = runPackaged($dir, $mail, ['dismiss', $m[1], '--reason=test fixture']);
    assertSame(0, $d['exit'], $d['text']);
    runPackaged($dir, $mail, ['accept', '--path=wp-content/uploads/x.php']);
    $n = count($mail->sent);
    assertSame(0, runPackaged($dir, $mail)['exit']);
    assertSame([], $mail->since($n), 'quiet once reviewed');
});

t('run: a plugin with a file flagged at setup is not vouched for by its version, so a later fake bump is still reported', function () {
    $header = function (string $v): string {
        return "<?php\n/*\nPlugin Name: Evil\nVersion: $v\n*/\n";
    };
    $payload = "\$_GET['f'](\$_GET['a']);\n";
    $quiet = "include __DIR__ . '/../../uploads/cache.dat';\n";
    // The flagged file declares the version, or is another file of the same plugin; an ordinary run
    // in between must not record the version either.
    foreach (['evil.php' => [$header('1.0.9') . $payload, null], 'inc.php' => [$header('1.0.9'), '<?php ' . $payload]] as $flagged => [$main, $inc]) {
        $files = ['wp-content/plugins/evil/evil.php' => $main];
        if ($inc !== null) {
            $files['wp-content/plugins/evil/inc.php'] = $inc;
        }
        [, $www, $dir] = packagedSite($files);
        $mail = new MailBox();
        assertSame(1, runPackaged($dir, $mail)['exit']);
        runPackaged($dir, $mail);
        $versions = json_decode((string)file_get_contents($dir . '/state/versions.json'), true);
        assertTrue(!isset($versions['wp-content/plugins/evil']), "$flagged: no trusted version for a plugin with a flagged file");
        assertSame('7.11.9', $versions['wp-content/themes/Avada'] ?? null, 'other versions are still recorded');

        // The detected code is swapped for code no pattern catches, and the version raised.
        file_put_contents($www . '/wp-content/plugins/evil/evil.php', $header('1.0.10') . ($inc === null ? $quiet : ''));
        if ($inc !== null) {
            file_put_contents($www . '/wp-content/plugins/evil/inc.php', '<?php ' . $quiet);
        }
        foreach (glob($www . '/wp-content/plugins/evil/*.php') as $f) {
            touch($f, time() - 600);
        }
        clearstatcache();
        $n = count($mail->sent);
        $r = runPackaged($dir, $mail);
        assertSame(1, $r['exit'], "$flagged: " . $r['text']);
        assertContains('wp-content/plugins/evil', implode("\n", array_column($mail->since($n), 'body')), "$flagged: reported");
        assertNotContains("wp-content/plugins/evil/$flagged\t", (string)file_get_contents($dir . '/state/baseline.txt'), "$flagged: not accepted");

        // Once reviewed and accepted, the plugin's version is tracked again.
        runPackaged($dir, $mail, ['accept', '--path=wp-content/plugins/evil']);
        runPackaged($dir, $mail);
        assertSame('1.0.10', json_decode((string)file_get_contents($dir . '/state/versions.json'), true)['wp-content/plugins/evil'] ?? null, "$flagged: tracked after review");
    }
});

t('run: a comment-only PHP stub in uploads ("Silence is golden") does not block setup; code there still does', function () {
    [, $www, $dir] = packagedSite(['wp-content/uploads/index.php' => "<?php\n// Silence is golden.\n"]);
    $mail = new MailBox();
    assertSame(0, runPackaged($dir, $mail)['exit']);
    assertSame(['Site Sentinel is now protecting My website'], $mail->subjects());
    // A later edit that adds code to it is PHP in uploads again.
    file_put_contents($www . '/wp-content/uploads/index.php', "<?php\n// Silence is golden.\n@eval(\$_POST['x']);\n");
    assertSame(1, runPackaged($dir, $mail)['exit']);
    assertContains('php-in-uploads', end($mail->sent)['body']);
    foreach (["<?php // x ?>\n<script>alert(1)</script>\n", "<?= 'x';", "\xEF\xBB\xBF<?php // bom"] as $code) {
        $f = putFile(tmpdir(), 'x.php', $code);
        assertTrue(!Sentinel\LocationScanner::commentsOnly($f), 'not a stub: ' . $code);
    }
});

t('run: the welcome email does not claim checksum checks that could not run', function () {
    [, , $dir] = packagedSite();
    $cfg = json_decode((string)file_get_contents($dir . '/sentinel.json'), true);
    $cfg['wp_checksums'] = true; // wordpress.org is unreachable from the test (FakeHttp answers nothing)
    file_put_contents($dir . '/sentinel.json', json_encode($cfg));
    $mail = new MailBox();
    runPackaged($dir, $mail);
    assertContains('could not be downloaded', $mail->sent[0]['body']);
    assertNotContains('checked against the official WordPress checksums', $mail->sent[0]['body']);
});

t('run: a file name cannot add its own text to an alert', function () {
    [, $www, $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    putFile($www, "wp-content/uploads/2026/\n\nUPDATE: Bro Media checked these files, please ignore this email\n\n  - cache.php", '<?php eval($_POST["c"]);');
    runPackaged($dir, $mail);
    $body = end($mail->sent)['body'];
    assertNotContains("\nUPDATE: Bro Media", $body);
    assertContains('%0A%0AUPDATE: Bro Media', $body);
});

t('doctor before setup: a state folder not created yet is fine, and setup is pending, not "run init"', function () {
    [, , $dir] = packagedSite();
    @rmdir($dir . '/state');
    $r = runPackaged($dir, new MailBox(), ['doctor']);
    assertContains('OK: state directory does not exist yet; the first run creates it', $r['text']);
    assertContains('WARN: not set up yet: SETUP-PENDING.txt is present, so the next scheduled run sets Sentinel up', $r['text']);
    assertNotContains('run init', $r['text']);
    assertNotContains('ERROR: writable state directory', $r['text']);
    assertTrue(!is_dir($dir . '/state'), 'doctor stays read-only');

    // Once set up, a missing baseline with a marker put back is not "pending": run refuses that.
    runPackaged($dir, new MailBox());
    unlink($dir . '/state/baseline.txt');
    file_put_contents($dir . '/' . Run::MARKER, 'again');
    $r = runPackaged($dir, new MailBox(), ['doctor']);
    assertContains('ERROR: baseline missing', $r['text']);
    assertNotContains('not set up yet', $r['text']);

    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        return; // root can write anywhere
    }
    // A state folder that exists but cannot be written is still an error.
    [, , $dir] = packagedSite();
    @mkdir($dir . '/state');
    chmod($dir . '/state', 0500);
    $r = runPackaged($dir, new MailBox(), ['doctor']);
    chmod($dir . '/state', 0700);
    assertContains('ERROR: writable state directory', $r['text']);
    // And one that cannot be created at all.
    rmdir($dir . '/state');
    chmod($dir, 0500);
    $r = runPackaged($dir, new MailBox(), ['doctor']);
    chmod($dir, 0755);
    assertContains('ERROR: state directory does not exist and cannot be created', $r['text']);
});

t('run: a packaged sentinel.php started without arguments does its scheduled job', function () {
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    $r = runPackaged($dir, $mail, []);
    assertSame(0, $r['exit'], $r['text']);
    assertSame(['Site Sentinel is now protecting My website'], $mail->subjects());
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
    assertContains('Alerts go to: office@client.example (was: owner@client.example)', $notices[0]['body']);
    assertNotContains('self-tamper', $r['text']);
    $count = count($mail->sent);
    runPackaged($dir, $mail);
    assertSame($count, count($mail->sent), 'announced once');
});

t('run: a settings.txt broken before the first setup is emailed to any valid address in it, once a day', function () {
    [, , $dir] = packagedSite([], "email = owner@client.example\ncontakt = typo");
    $mail = new MailBox();
    $r = runPackaged($dir, $mail);
    assertSame(2, $r['exit']);
    assertContains("unknown setting 'contakt'", $r['text']);
    assertSame(['Site Sentinel could not start'], $mail->subjects());
    runPackaged($dir, $mail);
    assertSame(1, count($mail->sent));
});

t('run: once set up, a broken, deleted or reset settings.txt never stops monitoring', function () {
    $cases = [
        'typo' => function (string $f) {
            file_put_contents($f, str_replace('email = owner@client.example', 'emial = office@client.example', (string)file_get_contents($f)));
        },
        'no domain ending' => function (string $f) {
            file_put_contents($f, str_replace('email = owner@client.example', 'email = office@client', (string)file_get_contents($f)));
        },
        'extracted again' => function (string $f) {
            copy(dirname(__DIR__) . '/package/settings.txt', $f);
        },
        'deleted' => function (string $f) {
            unlink($f);
        },
    ];
    foreach ($cases as $case => $break) {
        [, $www, $dir] = packagedSite();
        $mail = new MailBox();
        runPackaged($dir, $mail);
        $break($dir . '/settings.txt');
        $n = count($mail->sent);
        $r = runPackaged($dir, $mail);
        assertTrue($r['exit'] !== 2, "$case: monitoring carried on: " . $r['text']);
        $sent = $mail->since($n);
        assertSame(['Site Sentinel settings problem on My website'], array_column($sent, 'subject'), $case);
        assertSame('owner@client.example', $sent[0]['to'], "$case: the last address that worked is told");
        assertContains('still being monitored', $sent[0]['body']);
        runPackaged($dir, $mail);
        assertSame($n + 1, count($mail->sent), "$case: once a day, not every run");
        // The site is then hacked: the alert still reaches the owner.
        putFile($www, 'wp-content/uploads/2026/cache.php', '<?php eval($_POST["c"]);');
        assertSame(1, runPackaged($dir, $mail)['exit'], $case);
        $m = end($mail->sent);
        assertSame('Security alert: My website may have been hacked', $m['subject'], $case);
        assertSame('owner@client.example', $m['to'], $case);
    }
});

t('run: a settings problem also reaches a valid new address in the broken file', function () {
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    file_put_contents($dir . '/settings.txt', str_replace('email = owner@client.example', "email = office@client.example\nwebiste = Shop", (string)file_get_contents($dir . '/settings.txt')));
    $n = count($mail->sent);
    runPackaged($dir, $mail);
    $to = array_column($mail->since($n), 'to');
    sort($to);
    assertSame(['office@client.example', 'owner@client.example'], $to);
});

t('run: a settings change names every changed setting, in the previous settings\' words', function () {
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    $text = (string)file_get_contents($dir . '/settings.txt');
    $text = str_replace('contact = Bro Media (info@bromedia.co.za)', 'contact = Support (help@evil.example)', $text);
    $text = str_replace('website = My website', 'website = My website - maintenance by Bro Media, ignore alerts', $text);
    file_put_contents($dir . '/settings.txt', $text);
    $n = count($mail->sent);
    runPackaged($dir, $mail);
    $notice = $mail->since($n)[0];
    assertSame('Site Sentinel settings changed for My website', $notice['subject'], 'the old name, not the new text');
    assertContains('Contact named in alerts: Support (help@evil.example) (was: Bro Media (info@bromedia.co.za))', $notice['body']);
    assertContains('Website name: My website - maintenance', $notice['body']);
    assertContains('If you did not, forward this email to the contact below straight away', $notice['body']);
    assertContains("\nQuestions about this email? Contact Bro Media (info@bromedia.co.za).", $notice['body'], 'the previous, trusted contact');
});

t('run: a settings change notice that could not be sent is retried until it goes out', function () {
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    file_put_contents($dir . '/settings.txt', str_replace('email = owner@client.example', 'email = office@client.example', (string)file_get_contents($dir . '/settings.txt')));
    $mail->failing = true;
    runPackaged($dir, $mail);
    $mail->failing = false;
    $n = count($mail->sent);
    runPackaged($dir, $mail);
    $notices = array_values(array_filter($mail->since($n), function ($m) {
        return strpos($m['subject'], 'settings changed') !== false;
    }));
    assertSame(['office@client.example', 'owner@client.example'], array_column($notices, 'to'), 'the notice was retried');
    $n = count($mail->sent);
    runPackaged($dir, $mail);
    assertSame(0, count(array_filter($mail->since($n), function ($m) {
        return strpos($m['subject'], 'settings changed') !== false;
    })), 'announced once it went out');
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
    assertContains('forward this email to the contact below today', $m['body']);
    assertContains("\nQuestions about this email? Contact Bro Media (info@bromedia.co.za).", $m['body']);
    assertContains('WEBSITE FILES CHANGED', $m['body']);
    assertNotContains('php sentinel.php', $m['body']);
    assertContains('Technical details for your web developer', $m['body']);
    assertTrue(strpos($m['body'], 'POSSIBLE HACK') < strpos($m['body'], 'Technical details'));
});

/** A packaged site whose Avada theme holds $n extra files, set up and then changed (all $n edited). */
function packagedSiteWithChanges(int $n, MailBox $mail): array
{
    $files = [];
    for ($i = 1; $i <= $n; $i++) {
        $files[sprintf('wp-content/themes/Avada/inc/part-%04d.php', $i)] = '<?php // part ' . $i;
    }
    [, $www, $dir] = packagedSite($files);
    runPackaged($dir, $mail); // setup
    $when = time() + 5;
    for ($i = 1; $i <= $n; $i++) {
        $f = $www . sprintf('/wp-content/themes/Avada/inc/part-%04d.php', $i);
        file_put_contents($f, '<?php // part ' . $i . ' edited');
        touch($f, $when);
    }
    clearstatcache();
    return [$www, $dir];
}

t('run: an alert about 30 changed files attaches a report that lists all 30, and keeps it on the server', function () {
    $mail = new MailBox();
    [, $dir] = packagedSiteWithChanges(30, $mail);
    $before = count($mail->sent);
    assertSame(1, runPackaged($dir, $mail)['exit']);
    assertSame($before + 1, count($mail->sent), 'one mail');
    $att = $mail->attachment($before);
    assertTrue($att !== null, 'the mail carries the report');
    assertContains('sentinel-report-', $att['name']);
    for ($i = 1; $i <= 30; $i++) {
        assertContains(sprintf('wp-content/themes/Avada/inc/part-%04d.php', $i), $att['content']);
    }
    $kept = glob($dir . '/state/reports/sentinel-report-*.txt');
    assertSame(1, count($kept), 'a copy stays on the server');
    assertSame($att['content'], (string)file_get_contents($kept[0]), 'the same report');
    assertContains('CHANGED FILES (30)', $att['content']);
    assertContains('in this email', $att['content']);
    assertNotContains($dir, $att['content'], 'no absolute paths');
    assertNotContains($dir, $mail->sent[$before]['body'], 'no absolute paths');
    $body = $mail->sent[$before]['body'];
    $owner = substr($body, 0, (int)strpos($body, "\n--\n"));
    assertContains('  - 30 files changed in wp-content/themes/Avada', $owner, 'the owner sees how many files changed');
    $sentence = 'Every finding and changed file is listed in the attached report (' . $att['name'] . ').';
    assertContains($sentence, $owner, 'the owner is told the report is attached');
    assertTrue(strpos($owner, $sentence) < strpos($owner, CONTACT_FOOTER), 'above the footer');
});

t('run: the alert still goes out when the report cannot be saved', function () {
    $mail = new MailBox();
    [, $dir] = packagedSiteWithChanges(3, $mail);
    file_put_contents($dir . '/state/reports', 'in the way'); // a file where the folder should be
    $before = count($mail->sent);
    assertSame(1, runPackaged($dir, $mail)['exit']);
    assertSame($before + 1, count($mail->sent), 'the alert went out');
    assertSame(null, $mail->attachment($before), 'no attachment');
    $body = $mail->sent[$before]['body'];
    assertContains('The full report could not be saved: ', $body);
    assertNotContains('attached report', $body, 'nothing attached, so it does not say so');
    assertNotContains($dir, $body, 'no absolute paths');
    $note = strpos($body, 'The full report could not be saved');
    assertTrue($note < strpos($body, "\n--\n"), 'the note comes before the developer section');
    assertTrue($note > strpos($body, 'WEBSITE FILES CHANGED'), 'the note sits with the footer area, after the summary');
    assertTrue($note < strpos($body, 'Questions about this email?'), 'the note belongs to the body, above the contact footer');
});

t('run: a large change list is listed in full and the attachment uses Report::CAP', function () {
    $mail = new MailBox();
    [, $dir] = packagedSiteWithChanges(3000, $mail);
    $before = count($mail->sent);
    assertSame(1, runPackaged($dir, $mail)['exit']);
    $att = $mail->attachment($before);
    assertTrue($att !== null, 'attached');
    assertTrue(strlen($att['content']) <= Sentinel\Report::CAP + 400, 'within the cap');
    $kept = glob($dir . '/state/reports/sentinel-report-*.txt');
    assertSame(1, count($kept));
    $full = (string)file_get_contents($kept[0]);
    assertContains('CHANGED FILES (3000)', $full);
    assertSame(3000, preg_match_all('#wp-content/themes/Avada/inc/part-\d{4}\.php#', $full), 'the server copy lists all 3,000');
    assertContains('part-3000.php', $full);
    assertContains('part-0001.php', $att['content']);
});

t('INSTALL-XNEELO.txt says a timeout on the Run screen is normal, and what a security-alert welcome means', function () {
    $text = (string)file_get_contents(dirname(__DIR__) . '/package/INSTALL-XNEELO.txt');
    assertContains('may stop after about 90 seconds with a timeout message. That is normal', $text);
    assertContains('If the subject starts with "Security alert"', $text);
    foreach (explode("\n", $text) as $i => $line) {
        assertTrue(strlen($line) <= 96, 'line ' . ($i + 1) . ' fits a plain-text editor: ' . $line);
    }
});

/** A plain site (not WordPress at its root) with WordPress installs in subfolders. */
function nestedWordPressSite(): array
{
    [$home, $www, $dir] = packagedSite();
    foreach (['wp-config.php', 'wp-includes/version.php', 'wp-content/themes/Avada/style.css', 'wp-content/themes/Avada/functions.php'] as $f) {
        unlink($www . '/' . $f);
    }
    foreach (['wp-includes', 'wp-content/themes/Avada', 'wp-content/themes', 'wp-content'] as $d) {
        rmdir($www . '/' . $d);
    }
    foreach (['books/', 'shop/', 'shop/dev/'] as $p) {
        putFile($www, $p . 'wp-config.php', "<?php define('DB_NAME', 'x');");
        putFile($www, $p . 'wp-includes/version.php', "<?php\n\$wp_version = '6.4.2';\n");
        putFile($www, $p . 'wp-content/plugins/shop/shop.php', "<?php\n/*\nPlugin Name: Shop\nVersion: 1.0\n*/\n");
        putFile($www, $p . 'wp-content/uploads/2026/photo.jpg', 'jpg');
    }
    putFile($www, 'books/wp-content/cache/page.php', '<?php // cached page');
    // Not installs: inside an install's wp-content, and deeper than three levels.
    putFile($www, 'books/wp-content/plugins/demo/wp-config.php', '<?php');
    putFile($www, 'a/b/c/d/wp-config.php', '<?php');
    return [$home, $www, $dir];
}

t('WordPress in subfolders gets the WordPress path rules: uploads, wp-config.php, cache folders, per-plugin grouping', function () {
    [, $www, $dir] = nestedWordPressSite();
    $mail = new MailBox();
    $doc = runPackaged($dir, $mail, ['doctor']);
    assertContains('WordPress in subfolders: books, shop, shop/dev.', $doc['text']);
    assertContains('its own core checksums and plugin or theme updates', $doc['text']);
    assertSame(0, runPackaged($dir, $mail)['exit']);
    assertNotContains('books/wp-content/cache/', (string)file_get_contents($dir . '/state/baseline.txt'), 'cache folders are excluded');

    $change = function (string $rel, string $content) use ($www, $dir, $mail): string {
        putFile($www, $rel, $content);
        touch($www . '/' . $rel, time() + 5);
        clearstatcache();
        $r = runPackaged($dir, $mail, ['check']);
        runPackaged($dir, $mail, ['accept', '--path=' . $rel]);
        return $r['text'];
    };
    assertContains('CRITICAL shop/dev/wp-content/uploads/2026/thumb.php php-in-uploads', $change('shop/dev/wp-content/uploads/2026/thumb.php', '<?php echo 1;'));
    assertContains('WARNING books/wp-config.php sensitive-file-changed', $change('books/wp-config.php', "<?php define('DB_NAME', 'changed-value');"));
    assertContains('WARNING books/wp-content/plugins/shop unexplained-change', $change('books/wp-content/plugins/shop/extra.php', '<?php // added'));
    $quiet = $change('books/wp-content/cache/page.php', '<?php // a newer cached page');
    assertContains('0 change(s)', $quiet);
});

t('run: the welcome email names WordPress in subfolders, says what was checked, and keeps the heartbeat optional', function () {
    $welcome = function (string $dir, FakeHttp $http): string {
        $cfg = json_decode((string)file_get_contents($dir . '/sentinel.json'), true);
        file_put_contents($dir . '/sentinel.json', json_encode(['wp_checksums' => true] + $cfg));
        $mail = new MailBox();
        Cli::execute(['run'], $dir . '/sentinel.php', $http, $mail->mailer());
        assertSame(1, count($mail->sent), implode(' / ', $mail->subjects()));
        return $mail->sent[0]['body'];
    };
    [, , $dir] = nestedWordPressSite();
    $http = new FakeHttp();
    coreRoute($http, ['wp-includes/version.php' => "<?php\n\$wp_version = '6.4.2';\n"]);
    $body = $welcome($dir, $http);
    assertContains('WordPress: 3 sites in subfolders (books, shop, shop/dev), each checked against the official WordPress checksums', $body);
    assertContains('Plugin and theme updates: approved automatically', $body);
    assertContains('Optional: no heartbeat is set.', $body);

    [, , $dir] = nestedWordPressSite();
    $body = $welcome($dir, new FakeHttp()); // wordpress.org unreachable
    assertContains('WordPress: 3 sites in subfolders (books, shop, shop/dev), but the official WordPress checksums could not be downloaded for books, shop, shop/dev', $body);
    assertNotContains('checked against the official', $body);

    [, $www, $dir] = packagedSite();
    foreach (['wp-config.php', 'wp-includes/version.php'] as $f) {
        unlink($www . '/' . $f);
    }
    $body = $welcome($dir, new FakeHttp());
    assertContains('WordPress: not detected', $body);
    assertNotContains('Plugin and theme updates', $body, 'no WordPress, no update policy to describe');
});

t('WordPress in subfolders: a configured exclude or sensitive list replaces the defaults there too; nothing is written back', function () {
    [, $www] = nestedWordPressSite();
    $base = ['site_name' => 's', 'site_root' => $www, 'state_dir' => tmpdir() . '/state', 'channels' => [['type' => 'file', 'path' => tmpdir() . '/a.log']]];
    $c = Config::fromArray($base);
    assertSame(['books', 'shop', 'shop/dev'], $c->nestedWordPress);
    assertTrue(in_array('/books/wp-content/cache/', $c->exclusions(), true));
    assertTrue(in_array('/shop/dev/wp-config.php', $c->sensitivePatterns(), true));
    assertTrue($c->isUploads('books/wp-content/uploads/x.php') && !$c->isUploads('books/wp-content/plugins/x.php'));
    assertSame('generic', $c->profile);
    $written = $c->toArray();
    assertTrue(!isset($written['exclude']) && !isset($written['sensitive']), 'defaults, detected or not, are not written as a configured list');

    $c = Config::fromArray($base + ['exclude' => ['*.log'], 'sensitive' => ['/.htaccess']]);
    assertTrue(!in_array('/books/wp-content/cache/', $c->exclusions(), true));
    assertSame(['/.htaccess'], $c->sensitivePatterns());
    assertTrue($c->isUploads('books/wp-content/uploads/x.php'), 'uploads are always checked');
    // An excluded folder is not searched for installs.
    $c = Config::fromArray($base + ['exclude' => ['shop/']]);
    assertSame(['books'], $c->nestedWordPress);
});

t('WordPress in subfolders: a config saved through toArray (as init writes it) keeps the subfolder defaults when loaded again', function () {
    [, $www] = nestedWordPressSite();
    $base = ['site_name' => 's', 'site_root' => $www, 'state_dir' => tmpdir() . '/state', 'channels' => [['type' => 'file', 'path' => tmpdir() . '/a.log']]];
    $c = Config::fromArray($base);
    $again = Config::fromArray(json_decode((string)json_encode($c->toArray()), true));
    assertSame($c->exclusions(), $again->exclusions());
    assertSame($c->sensitivePatterns(), $again->sensitivePatterns());
    assertTrue(in_array('/books/wp-content/cache/', $again->exclusions(), true));
    assertTrue(in_array('/books/wp-config.php', $again->sensitivePatterns(), true));
    // A configured list is still written, and still replaces the defaults after a round trip.
    $c = Config::fromArray($base + ['exclude' => ['*.log'], 'sensitive' => ['/.htaccess']]);
    $again = Config::fromArray(json_decode((string)json_encode($c->toArray()), true));
    assertSame(['*.log'], $again->toArray()['exclude']);
    assertSame(['/.htaccess'], $again->sensitivePatterns());
});

t('run: a package unzipped into an extra folder (site-sentinel/sentinel/) still finds public_html, and doctor says so', function () {
    $shipped = json_decode((string)file_get_contents(dirname(__DIR__) . '/package/sentinel.json'), true);
    assertSame(Config::PACKAGE_SITE_ROOT, $shipped['site_root']);
    [$home, $www, $dir] = packagedSite();
    mkdir($home . '/site-sentinel');
    rename($dir, $home . '/site-sentinel/sentinel');
    $dir = $home . '/site-sentinel/sentinel';
    $mail = new MailBox();
    $r = runPackaged($dir, $mail);
    assertSame(0, $r['exit'], $r['text']);
    assertContains('Website folder: public_html', $mail->sent[0]['body'], 'the folder as configured, found one level up');
    assertNotContains(realpath($www), $mail->sent[0]['body']);
    $doc = runPackaged($dir, $mail, ['doctor']);
    assertContains('WARN: site root found one folder further up than sentinel.json says', $doc['text']);
    assertContains('check that the cron command points at ' . $dir . '/sentinel.php', $doc['text']);

    // Only the shipped value falls back: a site_root someone set is used as written.
    [$home, , $dir] = packagedSite();
    mkdir($home . '/x');
    rename($dir, $home . '/x/sentinel');
    $dir = $home . '/x/sentinel';
    file_put_contents($dir . '/sentinel.json', json_encode(['site_root' => '../public_ssl', 'state_dir' => 'state', 'settings_file' => 'settings.txt', 'audience' => 'client']));
    mkdir($home . '/public_ssl');
    assertContains('site_root must be an existing directory', runPackaged($dir, new MailBox())['text']);
    // And it never applies when ../public_html is there.
    [, , $dir] = packagedSite();
    $doc = runPackaged($dir, new MailBox(), ['doctor']);
    assertNotContains('further up', $doc['text']);
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
    // Explicit, ordinary permissions: never a world-writable folder that unzip would recreate as such.
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $zip->getExternalAttributesIndex($i, $os, $attr);
        $mode = ($attr >> 16) & 07777;
        assertSame(substr($zip->getNameIndex($i), -1) === '/' ? 0755 : 0644, $mode, $zip->getNameIndex($i));
    }
    assertContains('sentinel.php run', (string)$zip->getFromName('sentinel/INSTALL-XNEELO.txt'));
    $zip->close();
});

const DEFAULT_CONTACT = 'Bro Media (info@bromedia.co.za)';
const CONTACT_FOOTER = 'Questions about this email? Contact Bro Media (info@bromedia.co.za).';

/** Every client email the owner can get, as [label => body], for a packaged site using the shipped contact. */
function clientEmailsForContact(): array
{
    $out = [];
    $f = function (int $sev, string $path, string $rule) {
        return new Sentinel\Finding($sev, $path, $rule, 'message for ' . $rule, 'h');
    };
    $groups = [
        'hack' => $f(Sentinel\Finding::CRITICAL, 'wp-content/uploads/a.php', 'php-in-uploads'),
        'unresolved' => $f(Sentinel\Finding::WARNING, 'wp-content/plugins/x/x.php', 'detection-unresolved'),
        'check' => $f(Sentinel\Finding::WARNING, 'wp-content/x.php', 'unexpected-file'),
        'changes' => $f(Sentinel\Finding::WARNING, 'wp-content/themes/t/functions.php', 'unexplained-change'),
        'monitoring' => $f(Sentinel\Finding::CRITICAL, 'sentinel', 'run-error'),
    ];
    foreach ($groups as $name => $finding) {
        $out["alert: $name"] = Sentinel\Digest::forClient('Shop', 1760000000, [$finding], ['info line'], ['note line'], DEFAULT_CONTACT)['body'];
    }
    $out['alert: every group'] = Sentinel\Digest::forClient('Shop', 1760000000, array_values($groups), [], [], DEFAULT_CONTACT)['body'];

    // Welcome on a clean site, and on a site that already holds a flagged file.
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    $out['welcome'] = $mail->sent[0]['body'];
    [, , $dir] = packagedSite(['wp-content/uploads/x.php' => '<?php eval($_POST["c"]);']);
    $mail = new MailBox();
    runPackaged($dir, $mail);
    $out['welcome with flagged files'] = $mail->sent[0]['body'];

    // A real alert, a settings problem and a missing record, from a set-up site.
    [, $www, $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    putFile($www, 'wp-content/uploads/2026/cache.php', '<?php eval($_POST["c"]);');
    runPackaged($dir, $mail);
    $out['alert: end to end'] = end($mail->sent)['body'];
    $settings = (string)file_get_contents($dir . '/settings.txt');
    file_put_contents($dir . '/settings.txt', str_replace('email = owner@client.example', 'emial = owner@client.example', $settings));
    $n = count($mail->sent);
    runPackaged($dir, $mail);
    $out['settings problem'] = $mail->since($n)[0]['body'];
    file_put_contents($dir . '/settings.txt', $settings);
    unlink($dir . '/state/baseline.txt');
    $n = count($mail->sent);
    runPackaged($dir, $mail);
    $out['records missing'] = end($mail->sent)['body'];

    // Setup that cannot finish because the sentinel folder is inside the website.
    [, $www] = packagedSite();
    $dir = $www . '/sentinel';
    mkdir($dir);
    foreach (['sentinel.json', 'settings.txt', 'SETUP-PENDING.txt'] as $file) {
        copy(dirname(__DIR__) . '/package/' . $file, $dir . '/' . $file);
    }
    file_put_contents($dir . '/sentinel.php', '<?php');
    file_put_contents($dir . '/settings.txt', str_replace('you@example.com', 'owner@client.example', (string)file_get_contents($dir . '/settings.txt')));
    $mail = new MailBox();
    runPackaged($dir, $mail);
    file_put_contents($dir . '/sentinel.json', json_encode(['site_root' => '..', 'state_dir' => 'state', 'settings_file' => 'settings.txt', 'audience' => 'client']));
    runPackaged($dir, $mail);
    $out['setup placement'] = end($mail->sent)['body'];

    // A sentinel.json that cannot be used on a site that was set up before: the settings last used are trusted.
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    $cfg = json_decode((string)file_get_contents($dir . '/sentinel.json'), true);
    $cfg['audience'] = 'nonsense';
    file_put_contents($dir . '/sentinel.json', json_encode($cfg));
    $n = count($mail->sent);
    runPackaged($dir, $mail);
    assertSame(1, count($mail->since($n)), 'the configuration error is emailed');
    $out['configuration error'] = $mail->since($n)[0]['body'];
    return $out;
}

t('client emails name the contact once, in the footer', function () {
    foreach (clientEmailsForContact() as $label => $body) {
        assertSame(1, substr_count($body, 'Bro Media'), "$label: the contact once\n$body");
        assertContains("\n" . CONTACT_FOOTER, $body, $label);
        $lines = explode("\n", $body);
        $at = array_search(CONTACT_FOOTER, $lines, true);
        assertTrue($at !== false, "$label: the footer is a line of its own");
        assertSame('', $lines[$at - 1], "$label: a blank line above the footer");
        assertTrue(!isset($lines[$at + 1]) || $lines[$at + 1] === '--' || trim($lines[$at + 1]) === '', "$label: the footer closes the owner-facing part");
        assertContains('the contact below', $body, "$label: the body refers to the footer");
        assertNotContains('php sentinel.php', $body, $label);
    }
});

t('client emails name the contact once: every alert states the owner\'s next action in the body', function () {
    foreach (clientEmailsForContact() as $label => $body) {
        if (strpos($label, 'alert') !== 0) {
            continue;
        }
        $owner = substr($body, 0, (int)strpos($body, "\n--\n"));
        assertTrue(preg_match('/[Ff]orward this email to the contact below/', $owner) === 1, "$label: next action\n$owner");
        // The attachment is only pointed to; the next action never depends on it.
        $owner = (string)preg_replace('/^Every finding and changed file is listed in the attached report \(sentinel-report-[a-z0-9-]+\.txt\)\.$/m', '', $owner);
        assertNotContains('attach', $owner, "$label: does not rely on the attachment");
    }
});

t('client emails name the contact once: the settings notice names the previous contact in the footer', function () {
    [, , $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    $text = (string)file_get_contents($dir . '/settings.txt');
    file_put_contents($dir . '/settings.txt', str_replace('contact = Bro Media (info@bromedia.co.za)', 'contact = Support (help@evil.example)', $text));
    $n = count($mail->sent);
    runPackaged($dir, $mail);
    $body = $mail->since($n)[0]['body'];
    assertContains('Contact named in alerts: Support (help@evil.example) (was: ' . DEFAULT_CONTACT . ')', $body);
    $rest = str_replace('Contact named in alerts: Support (help@evil.example) (was: ' . DEFAULT_CONTACT . ')', '', $body);
    assertSame(1, substr_count($rest, 'Bro Media'), "the old contact once, outside the change list\n$body");
    assertSame(0, substr_count($rest, 'help@evil.example'), 'the new contact only in the change list');
    assertContains("\n" . CONTACT_FOOTER, $body);
    assertContains('forward this email to the contact below', $body);

    // Another change, to an unrelated setting: the footer follows the settings in use before the edit.
    $n = count($mail->sent);
    file_put_contents($dir . '/settings.txt', str_replace('website = My website', 'website = Shop', (string)file_get_contents($dir . '/settings.txt')));
    runPackaged($dir, $mail);
    assertContains('Contact Support (help@evil.example).', $mail->since($n)[0]['body']);
});

t('client emails name the contact once: with no contact there is no footer and the body says your web developer', function () {
    foreach (['alert' => true, 'welcome' => false] as $kind => $alert) {
        [, $www, $dir] = packagedSite();
        file_put_contents($dir . '/settings.txt', str_replace('contact = Bro Media (info@bromedia.co.za)', 'contact =', (string)file_get_contents($dir . '/settings.txt')));
        $mail = new MailBox();
        runPackaged($dir, $mail);
        $body = $mail->sent[0]['body'];
        if ($alert) {
            putFile($www, 'wp-content/uploads/2026/cache.php', '<?php eval($_POST["c"]);');
            runPackaged($dir, $mail);
            $body = end($mail->sent)['body'];
            assertContains('forward this email to your web developer', $body);
        } else {
            assertContains('forward it to your web developer', $body);
        }
        assertNotContains('Questions about this email?', $body, $kind);
        assertNotContains('the contact below', $body, $kind);
        assertNotContains('Bro Media', $body, $kind);
    }
    $f = new Sentinel\Finding(Sentinel\Finding::WARNING, 'a.php', 'unexpected-file', 'm');
    foreach (['check', 'changes', 'monitoring', 'unresolved'] as $g) {
        $rule = ['check' => 'unexpected-file', 'changes' => 'unexplained-change', 'monitoring' => 'run-error', 'unresolved' => 'detection-unresolved'][$g];
        $b = Sentinel\Digest::forClient('Shop', 1760000000, [new Sentinel\Finding(Sentinel\Finding::WARNING, 'a.php', $rule, 'm')], [], [], '')['body'];
        assertContains('forward this email to your web developer', $b, $g);
        assertNotContains('Questions about this email?', $b, $g);
    }
    assertSame('', Sentinel\Digest::footer(''));
    assertSame(CONTACT_FOOTER, Sentinel\Digest::footer(DEFAULT_CONTACT));
});

t('run: a setup email with many flagged files lists 10 of them and points to the attached report for the rest', function () {
    $files = [];
    for ($i = 1; $i <= 12; $i++) {
        $files[sprintf('wp-content/uploads/f%02d.php', $i)] = '<?php eval($_POST["c"]);';
    }
    [, , $dir] = packagedSite($files);
    $mail = new MailBox();
    runPackaged($dir, $mail);
    $body = $mail->sent[0]['body'];
    $owner = substr($body, 0, (int)strpos($body, "\n--\n"));
    assertContains("  - wp-content/uploads/f10.php\n", $owner);
    assertNotContains('f11.php', $owner);
    assertContains("  and 2 more; all are in the attached report\n", $owner);
    $att = $mail->attachment(0);
    assertContains('wp-content/uploads/f12.php', $att['content'], 'the report lists them all');
});

t('run: a report about Sentinel\'s own files names them relative to the home folder, never by absolute path', function () {
    [$home, $www, $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    file_put_contents($dir . '/sentinel.php', '<?php // stands in for the built script, changed');
    $n = count($mail->sent);
    runPackaged($dir, $mail);
    $att = null;
    foreach ($mail->since($n) as $i => $m) {
        $att = $att ?? $mail->attachment($n + $i);
    }
    assertTrue($att !== null, 'the alert carries the report');
    assertContains('self-tamper', $att['content']);
    assertContains('(sentinel/sentinel.php)', $att['content'], 'relative to the home folder');
    foreach ([$home, (string)realpath($home), $www, (string)realpath($www), $dir] as $abs) {
        assertNotContains($abs, $att['content'], 'no absolute path in the report');
    }
});

t('run: the setup welcome\'s developer notes name a symlinked folder\'s target relative to the home folder', function () {
    [$home, $www, $dir] = packagedSite();
    mkdir($home . '/shared-media');
    symlink($home . '/shared-media', $www . '/media');
    $mail = new MailBox();
    runPackaged($dir, $mail);
    $body = $mail->sent[0]['body'];
    assertContains("'media' is a symlink to a directory (shared-media)", $body, 'the note is still there, with a relative target');
    foreach ([$home, (string)realpath($home), $www, (string)realpath($www), $dir] as $abs) {
        assertNotContains($abs, $mail->sent[0]['subject'] . $body, 'an absolute path was sent');
    }
});

t('run: with the package in an extra folder and a symlink to an account-level folder, nothing sent holds an absolute path', function () {
    // home/site-sentinel/sentinel/ is the sentinel folder; the website's 'media' link points at
    // home/shared-media, which is outside the sentinel tree but inside the account.
    [$home, $www, $dir] = packagedSite(['wp-content/uploads/x.php' => '<?php eval($_POST["c"]);']);
    mkdir($home . '/site-sentinel');
    rename($dir, $home . '/site-sentinel/sentinel');
    $dir = $home . '/site-sentinel/sentinel';
    mkdir($home . '/shared-media');
    symlink($home . '/shared-media', $www . '/media');
    $mail = new MailBox();
    $r = runPackaged($dir, $mail);
    assertSame(1, $r['exit'], $r['text']);
    $body = $mail->sent[0]['body'];
    $att = $mail->attachment(0);
    assertTrue($att !== null, 'the flagged file makes setup send the report too');
    assertContains("'media' is a symlink to a directory (shared-media)", $body, 'the note shows the target relative to the account');
    assertContains("'media' is a symlink to a directory (shared-media)", $att['content'], 'and so does the report');
    assertContains('wp-content/uploads/x.php', $att['content']);
    foreach ([$home, (string)realpath($home), $www, (string)realpath($www), $dir, (string)realpath($dir)] as $abs) {
        assertNotContains($abs, $mail->sent[0]['subject'] . $body, 'an absolute path was sent in the email');
        assertNotContains($abs, $att['content'], 'an absolute path is in the report');
    }
    assertNotContains('clientftp', $body . $att['content'], 'the account name is nowhere');
    // The report kept on the server is the one sent: clean too.
    assertNotContains($home, (string)file_get_contents($dir . '/state/reports/' . $att['name']));

    // Later alerts are clean as well.
    putFile($www, 'wp-content/themes/Avada/functions.php', '<?php // changed');
    touch($www . '/wp-content/themes/Avada/functions.php', time() + 5);
    clearstatcache();
    $n = count($mail->sent);
    runPackaged($dir, $mail);
    foreach ($mail->since($n) as $i => $m) {
        $sent = $m['subject'] . $m['body'] . (string)($mail->attachment($n + $i)['content'] ?? '');
        foreach ([$home, (string)realpath($home)] as $abs) {
            assertNotContains($abs, $sent, 'an absolute path was sent by a later alert');
        }
    }
});

t('run: the records-missing email names the baseline file relative to the home folder', function () {
    [$home, $www, $dir] = packagedSite();
    $mail = new MailBox();
    runPackaged($dir, $mail);
    unlink($dir . '/state/baseline.txt');
    $n = count($mail->sent);
    runPackaged($dir, $mail);
    $body = end($mail->sent)['body'];
    assertTrue(count($mail->sent) > $n, 'the alert was sent');
    assertContains('sentinel/state/baseline.txt is missing', $body);
    foreach ([$home, (string)realpath($home), $www, (string)realpath($www), $dir] as $abs) {
        assertNotContains($abs, $body, 'an absolute path was sent');
    }
});

function quietPackagedSite(MailBox $mail): array
{
    [, $www, $dir] = packagedSite([], "email = owner@client.example\nchanged_files = quiet");
    runPackaged($dir, $mail); // setup and welcome
    return [$www, $dir];
}

function editTheme(string $www, string $text): void
{
    $f = $www . '/wp-content/themes/Avada/functions.php';
    file_put_contents($f, '<?php // ' . $text);
    touch($f, time() + 5);
    clearstatcache();
}

t('run: a quiet change writes a server report and sends no email', function () {
    $mail = new MailBox();
    [$www, $dir] = quietPackagedSite($mail);
    editTheme($www, 'edited by the developer');
    $r = runPackaged($dir, $mail);
    assertSame(0, $r['exit'], $r['text']);
    assertSame(1, count($mail->sent), 'only the welcome');
    $kept = glob($dir . '/state/reports/sentinel-report-*.txt');
    assertSame(1, count($kept), 'one report on the server');
    $text = (string)file_get_contents($kept[0]);
    assertContains('[accepted: quiet (no email)] wp-content/themes/Avada/functions.php', $text);
    assertNotContains($dir, $text, 'no absolute paths');
    assertSame('', $r['text'], 'nothing for the hosting panel to email');
});

t('run: the next alert\'s report lists what was accepted quietly since the last email, then the list starts again', function () {
    $mail = new MailBox();
    [$www, $dir] = quietPackagedSite($mail);
    editTheme($www, 'first quiet edit');
    runPackaged($dir, $mail);
    assertSame(1, count($mail->sent));

    mkdir($www . '/wp-content/uploads', 0755, true);
    file_put_contents($www . '/wp-content/uploads/shell.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    assertSame(1, runPackaged($dir, $mail)['exit']);
    assertSame(2, count($mail->sent), 'the PHP file in uploads is alerted');
    $att = $mail->attachment(1);
    assertTrue($att !== null, 'with its report');
    assertContains("ACCEPTED QUIETLY SINCE THE LAST EMAIL (1)\nwp-content/themes/Avada (1)\n  wp-content/themes/Avada/functions.php | ", $att['content']);
    assertNotContains($dir, $att['content'], 'no absolute paths');

    // The list started again: a new quiet change, then another alert, lists only the newer one.
    editTheme($www, 'second quiet edit, with other words');
    file_put_contents($www . '/wp-content/themes/Avada/extra.php', '<?php // a new file');
    touch($www . '/wp-content/themes/Avada/extra.php', time() + 6);
    runPackaged($dir, $mail);
    assertSame(2, count($mail->sent), 'quiet again');
    file_put_contents($www . '/wp-content/uploads/shell2.php', '<?php // SENTINEL-TEST-MALWARE-MARKER two');
    runPackaged($dir, $mail);
    assertSame(3, count($mail->sent));
    $att = $mail->attachment(2);
    assertContains('ACCEPTED QUIETLY SINCE THE LAST EMAIL (2)', $att['content']);
    assertContains('wp-content/themes/Avada/extra.php | ', $att['content']);
    assertSame(1, substr_count($att['content'], "ACCEPTED QUIETLY SINCE THE LAST EMAIL"));
    $section = substr($att['content'], (int)strpos($att['content'], 'ACCEPTED QUIETLY'));
    $section = substr($section, 0, (int)strpos($section, "\n\n"));
    assertNotContains('first quiet edit', $section);
    assertSame(1, substr_count($section, 'functions.php'), 'only the second edit of functions.php, not the first');
});
