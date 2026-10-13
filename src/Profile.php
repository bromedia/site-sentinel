<?php
declare(strict_types=1);

namespace Sentinel;

final class Profile
{
    public static function detect(string $root): string
    {
        $root = rtrim($root, '/');
        if (is_file($root . '/wp-config.php') || is_file($root . '/wp-includes/version.php')) {
            return 'wordpress';
        }
        return 'generic';
    }

    /** @return array{exclude: string[], code_extensions: string[], sensitive: string[], uploads_dir: string} */
    public static function defaults(string $profile): array
    {
        $code = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'inc', 'js', 'html', 'htm', 'shtml', 'ini', 'sh', 'pl', 'py', 'cgi', 'so'];
        $common = ['*.log', 'error_log', '.git/', 'node_modules/'];
        if ($profile === 'wordpress') {
            return [
                'exclude' => array_merge($common, [
                    'wp-content/cache/', 'wp-content/upgrade/', 'wp-content/wflogs/',
                    'wp-content/backups/', 'wp-content/updraft/', 'wp-content/ai1wm-backups/',
                ]),
                'code_extensions' => $code,
                'sensitive' => [
                    '/wp-config.php', '/.htaccess', 'wp-content/mu-plugins/**',
                    '/wp-content/advanced-cache.php', '/wp-content/db.php', '/wp-content/object-cache.php', '.user.ini',
                ],
                'uploads_dir' => 'wp-content/uploads',
            ];
        }
        return [
            'exclude' => $common,
            'code_extensions' => $code,
            'sensitive' => ['/.htaccess', '.user.ini', 'php.ini'],
            'uploads_dir' => '',
        ];
    }
}
