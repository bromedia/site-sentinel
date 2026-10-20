<?php

declare(strict_types=1);

namespace Sentinel;

interface DatabaseSource
{
    public function snapshot(): array;
    public function posts(int $after, int $limit): array;
    public function postStats(int $after): array;
}
final class MysqlDatabase implements DatabaseSource
{
    private $db;
    private $prefix;
    private $settings;
    private $budget;
    private $maria;
    public function __construct(Config $c, Budget $budget)
    {
        if (!function_exists('mysqli_init') || !defined('MYSQLI_OPT_READ_TIMEOUT')) {
            throw new DatabaseException('database monitoring needs mysqli with read-timeout support');
        }
        $raw = DatabaseCredentials::load($c);
        $this->prefix = $raw['table_prefix'];
        $this->settings = $c->database;
        $this->budget = $budget;
        try {
            $db = mysqli_init();
            $timeout = $budget->timeout($this->settings['query_timeout_seconds']);
            $db->options(MYSQLI_OPT_CONNECT_TIMEOUT, $timeout);
            $db->options(MYSQLI_OPT_READ_TIMEOUT, $timeout);
            if (!@$db->real_connect($raw['host'], $raw['user'], $raw['password'], $raw['name'], $raw['port'], $raw['socket'] !== '' ? $raw['socket'] : null) || !$db->set_charset('utf8mb4')) {
                throw new \RuntimeException('connect failed');
            }
            $this->db = $db;
            $this->maria = stripos($db->server_info, 'MariaDB') !== false;
        } catch (\Throwable $e) {
            throw new DatabaseException('database connection failed; verify credentials, host access and mysqli (server details withheld)');
        }
    }
    private function table(string $suffix): string
    {
        return '`' . $this->prefix . $suffix . '`';
    }
    private function quote(string $s): string
    {
        return "'" . $this->db->real_escape_string($s) . "'";
    }
    /** Generated read queries only; session timeout/charset settings never change WordPress content. */
    private function select(string $sql): array
    {
        $seconds = $this->budget->timeout($this->settings['query_timeout_seconds']);
        $sql = $this->maria ? 'SET STATEMENT max_statement_time=' . $seconds . ' FOR ' . $sql : preg_replace('/^SELECT /', 'SELECT /*+ MAX_EXECUTION_TIME(' . ($seconds * 1000) . ') */ ', $sql, 1);
        try {
            $result = @$this->db->query($sql);
            if ($result === false) {
                throw new \RuntimeException('query failed');
            }
            $rows = [];
            while ($row = $result->fetch_assoc()) {
                $rows[] = $row;
            } $result->free();
            return $rows;
        } catch (\Throwable $e) {
            throw new DatabaseException('database read failed or timed out; verify SELECT access, prefix and query limits (SQL/server details withheld)');
        }
    }
    public function snapshot(): array
    {
        $names = ['siteurl','home','active_plugins','template','stylesheet','users_can_register','default_role','admin_email',$this->prefix . 'user_roles'];
        $rows = $this->select('SELECT option_name, LEFT(CAST(option_value AS BINARY),1048576) AS value, OCTET_LENGTH(option_value) AS bytes FROM ' . $this->table('options') . ' WHERE option_name IN (' . implode(',', array_map([$this,'quote'], $names)) . ') LIMIT 20');
        $options = [];
        $roles = ['administrator'];
        foreach ($rows as $r) {
            if ((int)$r['bytes'] > 1048576) {
                throw new DatabaseException('a monitored option exceeds the 1MB limit; no truncated snapshot was trusted');
            }
            $options[$r['option_name']] = hash('sha256', $r['value']);
            if ($r['option_name'] === $this->prefix . 'user_roles') {
                $map = @unserialize($r['value'], ['allowed_classes' => false]);
                if (!is_array($map)) {
                    throw new DatabaseException('WordPress roles cannot be parsed safely');
                }
                foreach ($map as $name => $role) {
                    if (is_string($name) && is_array($role) && !empty($role['capabilities']['manage_options'])) {
                        $roles[] = $name;
                    }
                }
            }
        }
        $roles = array_unique(array_merge($roles, ['manage_options']));
        if (count($roles) > 100) {
            throw new DatabaseException('too many privileged roles for bounded inspection');
        }
        $like = [];
        foreach ($roles as $role) {
            $like[] = 'm.meta_value LIKE ' . $this->quote('%' . strtr($role, ['=' => '==','%' => '=%','_' => '=_']) . '%') . " ESCAPE '='";
        }
        $rows = $this->select('SELECT u.ID,u.user_login,u.user_email,u.user_pass,LEFT(CAST(m.meta_value AS BINARY),65536) AS caps,OCTET_LENGTH(m.meta_value) AS bytes FROM ' . $this->table('users') . ' u JOIN ' . $this->table('usermeta') . ' m ON m.user_id=u.ID WHERE m.meta_key=' . $this->quote($this->prefix . 'capabilities') . ' AND (' . implode(' OR ', $like) . ') ORDER BY u.ID LIMIT ' . ($this->settings['max_admins'] + 1));
        if (count($rows) > $this->settings['max_admins']) {
            throw new DatabaseException('privileged-account candidates exceed database.max_admins; coverage incomplete');
        }
        $admins = [];
        foreach ($rows as $r) {
            if ((int)$r['bytes'] > 65536) {
                throw new DatabaseException('privileged-account capabilities exceed the read limit');
            }
            $caps = @unserialize($r['caps'], ['allowed_classes' => false]);
            if (!is_array($caps)) {
                throw new DatabaseException('privileged-account capabilities cannot be parsed safely');
            }
            foreach ($roles as $role) {
                if (!empty($caps[$role])) {
                    $id = (string)$r['ID'];
                    if (isset($admins[$id])) {
                        throw new DatabaseException('duplicate privileged capability records require review');
                    }
                    // Length prefixes avoid ambiguous concatenation and support arbitrary bytes.
                    $parts = [];
                    foreach (['user_login','user_email','user_pass','caps'] as $key) {
                        $parts[] = strlen($r[$key]) . ':' . $r[$key];
                    }
                    $admins[$id] = hash('sha256', implode('', $parts));
                    break;
                }
            }
        }
        return ['admins' => $admins,'options' => $options];
    }
    private function postFilter(): string
    {
        return 'post_type IN (' . implode(',', array_map([$this,'quote'], $this->settings['post_types'])) . ") AND post_status NOT IN ('auto-draft','inherit','trash')";
    }
    public function posts(int $after, int $limit): array
    {
        $max = $this->settings['max_post_bytes'];
        $half = (int)ceil($max / 2);
        $sample = 'CASE WHEN OCTET_LENGTH(post_content)>' . $max . ' THEN CONCAT(LEFT(CAST(post_content AS BINARY),' . $half . '),0x0a,RIGHT(CAST(post_content AS BINARY),' . $half . ')) ELSE post_content END';
        return $this->select('SELECT ID AS id,LEFT(CAST(post_title AS BINARY),4096) AS title,' . $sample . ' AS content,OCTET_LENGTH(post_content) AS bytes FROM ' . $this->table('posts') . ' WHERE ID>' . max(0, $after) . ' AND ' . $this->postFilter() . ' ORDER BY ID LIMIT ' . max(1, min($limit, $this->settings['batch_size'])));
    }
    public function postStats(int $after): array
    {
        $r = $this->select('SELECT COUNT(*) AS new_count,COALESCE(MAX(ID),0) AS max_id FROM ' . $this->table('posts') . ' WHERE ID>' . max(0, $after) . ' AND ' . $this->postFilter());
        return ['new_count' => (int)$r[0]['new_count'],'max_id' => max($after, (int)$r[0]['max_id'])];
    }
    public function __destruct()
    {
        if ($this->db !== null) {
            @$this->db->close();
        }
    }
}
