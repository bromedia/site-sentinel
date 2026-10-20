<?php

declare(strict_types=1);

require __DIR__ . '/lib.php';
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/helpers_config.php';
require __DIR__ . '/helpers_notify.php';
function bigBudget(): Sentinel\Budget
{
    return new Sentinel\Budget(120, PHP_INT_MAX);
}
if ((string)getenv('SENTINEL_TEST_DB_PORT') === '') {
    fwrite(STDERR, "Disposable test DB port required. Never run against production.\n");
    exit(2);
}
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$port = (int)getenv('SENTINEL_TEST_DB_PORT');
$admin = new mysqli('127.0.0.1', 'root', 'sentinel-test', '', $port);
try {
    $admin->query('CREATE DATABASE sentinel_integration CHARACTER SET utf8mb4');
    $admin->select_db('sentinel_integration');
    $admin->query('CREATE TABLE ae_users (ID BIGINT PRIMARY KEY,user_login VARCHAR(100),user_email VARCHAR(100),user_pass VARCHAR(255))');
    $admin->query('CREATE TABLE ae_usermeta (umeta_id BIGINT AUTO_INCREMENT PRIMARY KEY,user_id BIGINT,meta_key VARCHAR(100),meta_value LONGTEXT)');
    $admin->query('CREATE TABLE ae_options (option_id BIGINT AUTO_INCREMENT PRIMARY KEY,option_name VARCHAR(100),option_value LONGTEXT)');
    $admin->query('CREATE TABLE ae_posts (ID BIGINT PRIMARY KEY,post_type VARCHAR(32),post_status VARCHAR(32),post_title LONGTEXT,post_content LONGTEXT)');
    $roles = serialize(['administrator' => ['capabilities' => ['manage_options' => true]],'manager' => ['capabilities' => ['manage_options' => true]]]);
    $put = $admin->prepare('INSERT INTO ae_options (option_name,option_value) VALUES (?,?)');
    foreach (['siteurl' => 'https://example.test','default_role' => 'subscriber','ae_user_roles' => $roles] as $key => $value) {
        $put->bind_param('ss', $key, $value);
        $put->execute();
    }
    $admin->query("INSERT INTO ae_users VALUES (1,'private-login','private-email@example.test','private-password-hash'),(2,'manager','private@example.test','hash')");
    $caps = $admin->prepare("INSERT INTO ae_usermeta (user_id,meta_key,meta_value) VALUES (?,'ae_capabilities',?)");
    foreach ([1 => 'administrator',2 => 'manager'] as $id => $role) {
        $value = serialize([$role => true]);
        $caps->bind_param('is', $id, $value);
        $caps->execute();
    }
    $admin->query("INSERT INTO ae_posts VALUES (1,'post','publish','Normal','Hello'),(2,'revision','inherit','Ignored','online casino')");
    $admin->query("CREATE USER 'sentinel_reader'@'%' IDENTIFIED BY 'reader-only-test'");
    $admin->query("GRANT SELECT ON sentinel_integration.* TO 'sentinel_reader'@'%'");
    $file = putFile(tmpdir(), 'database.json', json_encode(['host' => '127.0.0.1','port' => $port,'user' => 'sentinel_reader','password' => 'reader-only-test','name' => 'sentinel_integration','table_prefix' => 'ae_']));
    $c = makeConfig(tmpdir(), ['profile' => 'wordpress','database' => ['enabled' => true,'credentials_file' => $file,'new_post_threshold' => 2,'max_post_bytes' => 32]]);
    $source = new Sentinel\MysqlDatabase($c, bigBudget());
    $s = $source->snapshot();
    assertSame([1,2], array_keys($s['admins']));
    assertSame(hash('sha256', 'https://example.test'), $s['options']['siteurl']);
    assertNotContains('private-login', json_encode($s));
    assertSame(1, count($source->posts(0, 20)));
    $state = new Sentinel\State($c->stateDir);
    $n = new FakeNotifier();
    $db = new Sentinel\DatabaseMonitor($c, $state, [new Sentinel\Channel($n, Sentinel\Finding::WARNING)], null, $source);
    assertSame(0, $db->accept(bigBudget(), 'all', true)['exit']);
    $admin->query("INSERT INTO ae_users VALUES (3,'unexpected','secret@example.test','secret-hash')");
    $id = 3;
    $value = serialize(['administrator' => true]);
    $caps->bind_param('is', $id, $value);
    $caps->execute();
    $admin->query("UPDATE ae_options SET option_value='https://changed.test' WHERE option_name='siteurl'");
    $admin->query("INSERT INTO ae_posts VALUES (3,'post','publish','Private spam title','online casino'),(4,'page','publish','Large','<script>abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz')");
    $r = $db->check(bigBudget());
    assertSame(1, $r['exit']);
    foreach (['db-admin-change','db-option-change','db-post-spam','db-post-code','db-post-burst','db-post-sampled'] as $rule) {
        assertContains($rule, implode("\n", $r['lines']));
    }
    assertSame('4', $admin->query('SELECT COUNT(*) AS n FROM ae_posts')->fetch_assoc()['n']);
    assertNotContains('Private spam title', json_encode($n->sent));
    assertNotContains('secret@example.test', json_encode($n->sent));
    $reader = new mysqli('127.0.0.1', 'sentinel_reader', 'reader-only-test', 'sentinel_integration', $port);
    $denied = false;
    try {
        $reader->query('DELETE FROM ae_posts WHERE ID=1');
    } catch (mysqli_sql_exception $e) {
        $denied = true;
    }assertTrue($denied);
    echo 'Read-only database integration passed (' . $admin->server_info . ")\n";
} finally {
    $admin->query('DROP DATABASE IF EXISTS sentinel_integration');
    $admin->query("DROP USER IF EXISTS 'sentinel_reader'@'%'");
    foreach ($GLOBALS['__tmp'] as $dir) {
        rmrf($dir);
    }
}
