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

    /**
     * WordPress installs in subfolders of the site, for example "shop" or "blog/dev", up to three
     * levels down. Only folders are listed, never files, and an install's own wp-admin, wp-includes
     * and wp-content are not entered, so this stays cheap however large the site is.
     *
     * @return string[] relative paths, sorted
     */
    public static function nestedWordPress(string $root, PathFilter $excluded, int $depth = 3): array
    {
        $root = rtrim($root, '/');
        $found = [];
        $level = [''];
        for ($d = 1; $d <= $depth && $level; $d++) {
            $next = [];
            foreach ($level as $rel) {
                $abs = $rel === '' ? $root : $root . '/' . $rel;
                $isWp = self::detect($abs) === 'wordpress';
                if ($isWp && $rel !== '') {
                    $found[] = $rel;
                }
                $names = @scandir($abs);
                foreach ($names === false ? [] : $names as $name) {
                    if ($name === '.' || $name === '..' || ($isWp && in_array($name, ['wp-admin', 'wp-includes', 'wp-content'], true))) {
                        continue;
                    }
                    $child = $rel === '' ? $name : $rel . '/' . $name;
                    if (is_dir($abs . '/' . $name) && !is_link($abs . '/' . $name) && !$excluded->matches($child)) {
                        $next[] = $child;
                    }
                }
            }
            $level = $next;
        }
        foreach ($level as $rel) { // the deepest level is only checked, not listed
            if (self::detect($root . '/' . $rel) === 'wordpress') {
                $found[] = $rel;
            }
        }
        sort($found);
        return $found;
    }

    /**
     * A root-anchored pattern (one with a slash, like "wp-content/cache/" or "/wp-config.php")
     * moved under a subfolder; patterns that match anywhere already cover subfolders.
     */
    public static function under(string $prefix, string $pattern): ?string
    {
        if (strpos(trim($pattern, '/'), '/') === false && $pattern[0] !== '/') {
            return null;
        }
        return '/' . $prefix . '/' . ltrim($pattern, '/');
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
                // Drop-ins WordPress loads without them being activated count as sensitive.
                'sensitive' => [
                    '/wp-config.php', '/.htaccess', 'wp-content/mu-plugins/**',
                    '/wp-content/advanced-cache.php', '/wp-content/db.php', '/wp-content/object-cache.php',
                    '/wp-content/sunrise.php', '/wp-content/maintenance.php', '/wp-content/fatal-error-handler.php',
                    '/wp-content/php-error.php', '/wp-content/db-error.php', '/wp-content/install.php', '/wp-content/blog-*.php',
                    '.user.ini',
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
