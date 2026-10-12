# Site Sentinel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `sentinel.php`, a single-file PHP CLI that monitors a web site for new, modified and removed files, flags likely malware, and alerts the site owner, on shared hosting (no root) and on a dedicated server.

**Architecture:** A baseline file (sorted, line-based) is merged against a sorted directory walk to produce changes. Pluggable scanners (WordPress checksums, pattern rules, location rules, optional ClamAV/YARA) classify new and modified files into Critical/Warning/Info. One digest per run goes to the configured channels, deduplicated by an alert log. Source lives in `src/` and a build script concatenates it into one distributable file.

**Tech Stack:** PHP 7.4+ (developed on 8.x, kept 7.4-compatible by a compat check), no Composer dependencies, plain-`php` test scripts. Optional: `sodium` (rule signatures), `curl`, `clamscan`, `yara`.

**Spec:** `docs/superpowers/specs/2026-10-12-site-sentinel-design.md`

**How to read the code blocks:** a fenced block whose first line is annotated `file=<path>` is the complete content of that file (create it, or replace it wholesale). Tasks are ordered so each one builds on the previous; every task ends with a passing test run and a commit. Every block in this plan was extracted and executed before the plan was written down: the full suite passes on PHP 8.5 (the only PHP available while planning). Two tests need the `sodium` extension and report `skip` without it, so run the suite once on a PHP that has it, and ideally once on the oldest PHP you can reach (7.4 or 8.1; ask before using the production server). The 7.4 compatibility check is a heuristic, not a real 7.4 run.

## Global Constraints

Copied from the spec; every task's requirements implicitly include these.

- Language: PHP CLI, compatible with PHP 7.4 and later (no `match`, enums, readonly, nullsafe `?->`, attributes, constructor promotion, union types, `mixed`, `str_contains`/`str_starts_with`/`str_ends_with`, `catch` without a variable). `tests/test_compat.php` enforces this.
- No required extensions beyond a default PHP CLI build. Optional: `sodium` (rule signature verification), `curl` (otherwise stream wrappers).
- No root, no daemons, no SQLite requirement.
- One distributable file, `sentinel.php`, built from a few source files.
- The tool detects and alerts only. It never deletes or modifies site files.
- Baseline: flat sorted line-based file, one line per file: path, size, mtime, permissions, hash (hash may be empty for stat-only entries). Streamed line by line so memory stays flat.
- Severity: **Critical** = scanner hit, PHP file under `uploads`, WordPress core or repo-plugin file not matching the official checksum, newly created executable in a temp directory, tool self-check failure. **Warning** = unexplained new/modified files in themes/plugins/mu-plugins, changes to `wp-config.php`/`.htaccess`, removed core files. **Info** = explained and auto-accepted changes; digest only, no push alert.
- Exit codes: 0 clean, 1 findings reported, 2 tool error.
- Config is JSON with no dependencies. State lives in a hidden directory (mode 700).
- Alerts go to the site owner; config accepts several recipients.
- All tests use temporary directories and never touch real sites or the real network.
- Commit messages end with the `Co-Authored-By` trailer the harness gives you.

## Spec clarifications decided in this plan

The spec leaves these open; the plan fixes them so no task has to guess.

1. **Info delivery:** Info lines never trigger an alert by themselves. They are appended to a digest that is sent anyway (Warning or Critical present).
2. **Unsigned rules:** without `sodium` or a configured public key, `update-rules` refuses unless `allow_unsigned_rules` is `true`. The SHA-256 fallback then protects against corruption only, not against a hijacked URL, and the command says so. (The spec's wording implied the fallback was safe by default; it is not.)
3. **No default `rules_url`:** there is no published project URL yet, so the config default is empty and `update-rules` explains how to set it. The built-in rules work without any bundle.
4. **Hash policy:** only "code files" (extension list in the profile, plus `.htaccess`, `.user.ini`, `php.ini`) are hashed and pattern-scanned. Everything else is stat-only. Files under `uploads` get location checks (PHP extension, PHP tags hidden in media).
5. **Held changes:** a Warning/Critical change is not written to the baseline, so it stays visible until `accept`. Alert dedupe prevents repeat emails; Critical findings remind every `remind_hours` (default 24).
6. **Config location:** next to the script (`sentinel.json`), state in `sentinel-state/` next to the script, unless `--config`/`--state` say otherwise. The docs tell users to place the script outside the web root.
7. **`/tmp` monitoring:** run a second config with `site_root` set to `/tmp`, `profile` `generic`, `temp_root` `true`.
8. **Offline switch:** `wp_checksums: false` disables WordPress API lookups (used by the end-to-end test and for sites without outbound HTTP).
9. **No shebang in the built file:** run it as `php sentinel.php`. Under a web server a shebang line is emitted as output before `declare(strict_types=1)` and crashes the script with a 500; without it the built-in guard answers 404 and exits.
10. **No curated rules bundle is produced by this plan.** Only the built-in rules ship. Curating a bundle from third-party sources is content work that needs a license review first (see `docs/RULES.md`, written in Task 17).

## Review Focus

Failure modes the spec implies but a skimming implementer would not test. Each has a test in the task that owns the code.

1. **Odd file names** (tab, newline, `%`, all-digit names like `123` that PHP turns into integer array keys, non-ASCII): must round-trip through the baseline and sort identically in the walker and the merge. Tests: Task 4 (baseline round-trip, `applyUpdates` with `123`), Task 5 (walker order).
2. **Payload appended past `max_scan_bytes`:** a large file with the webshell at the end must still be flagged. Test: Task 7.
3. **Tool files inside the web root:** state dir, config and the script itself must not appear in the walk or raise findings. Tests: Task 3 (exclusions), Task 5 (walker), Task 16 (init with tool files inside the root), Task 17 (end-to-end run is clean).
4. **Network failures:** an unreachable wordpress.org must yield "unknown" plus a note, never "match" (false clean) or "mismatch" (false alarm); a failing alert channel must not mark findings as alerted. Tests: Task 9 (checksums), Task 13 (alerter), Task 14 (monitor retries).
5. **Missing, corrupt or interrupted state:** `check` with no baseline must exit 2 (not treat every file as new); a corrupt baseline exits 2; a run stopped by the time budget resumes where it stopped; two overlapping runs do not both scan. Tests: Task 6 (resume, corrupt baseline), Task 12 (lock), Task 14 (missing/corrupt baseline, partial runs, overlap).

---

### Task 1: Project scaffold, test harness and PHP 7.4 compatibility check

**Files:**
- Create: `VERSION`, `.gitignore`, `build/files.php`, `build/compat.php`
- Create: `tests/lib.php`, `tests/bootstrap.php`, `tests/run.php`, `tests/test_compat.php`

**Interfaces:**
- Produces (test helpers, global namespace): `t(string $name, callable $fn)`, `skip(string $why)`, `assertTrue($v)`, `assertSame($expected, $actual)`, `assertContains($needle, $haystack)`, `assertNotContains(...)`, `assertThrows(string $class, callable $fn)`, `tmpdir(): string`, `rmrf(string $path)`, `putFile(string $root, string $rel, string $content, ?int $mtime = null): string`.
- Produces: `build/files.php` returns the ordered list of `src/` files; `tests/bootstrap.php` loads them. Later tasks append to the list.
- Produces: `compat_violations(string $code, string $label): array` in `build/compat.php`.

- [ ] **Step 1: Create the scaffold files**

```text file=VERSION
0.1.0
```

```text file=.gitignore
dist/
*.tmp
```

```php file=build/files.php
<?php
declare(strict_types=1);

// Ordered list of src/ files. Interfaces must precede their implementers.
// Each task that adds a source file appends its name here.
return [
];
```

- [ ] **Step 2: Create the test library, bootstrap and runner**

```php file=tests/lib.php
<?php
declare(strict_types=1);

final class SkipTest extends Exception
{
}

$GLOBALS['__tests'] = [];
$GLOBALS['__tmp'] = [];

function t(string $name, callable $fn): void
{
    $GLOBALS['__tests'][] = [$name, $fn];
}

function skip(string $why): void
{
    throw new SkipTest($why);
}

function assertTrue($cond, string $msg = 'expected true'): void
{
    if ($cond !== true) {
        throw new RuntimeException($msg);
    }
}

function assertSame($expected, $actual, string $msg = ''): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(($msg !== '' ? $msg . ': ' : '') . 'expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}

function assertContains(string $needle, string $haystack, string $msg = ''): void
{
    if (strpos($haystack, $needle) === false) {
        throw new RuntimeException(($msg !== '' ? $msg . ': ' : '') . 'expected to find ' . var_export($needle, true) . ' in ' . var_export($haystack, true));
    }
}

function assertNotContains(string $needle, string $haystack, string $msg = ''): void
{
    if (strpos($haystack, $needle) !== false) {
        throw new RuntimeException(($msg !== '' ? $msg . ': ' : '') . 'did not expect ' . var_export($needle, true) . ' in ' . var_export($haystack, true));
    }
}

function assertThrows(string $class, callable $fn): void
{
    try {
        $fn();
    } catch (Throwable $e) {
        if (!($e instanceof $class)) {
            throw new RuntimeException("expected $class, got " . get_class($e) . ': ' . $e->getMessage());
        }
        return;
    }
    throw new RuntimeException("expected $class to be thrown");
}

function tmpdir(): string
{
    $d = sys_get_temp_dir() . '/sentinel-test-' . bin2hex(random_bytes(6));
    mkdir($d, 0700, true);
    $GLOBALS['__tmp'][] = $d;
    return $d;
}

function rmrf(string $p): void
{
    if (is_link($p) || is_file($p)) {
        @unlink($p);
        return;
    }
    if (!is_dir($p)) {
        return;
    }
    foreach (scandir($p) as $n) {
        if ($n !== '.' && $n !== '..') {
            rmrf($p . '/' . $n);
        }
    }
    @rmdir($p);
}

function putFile(string $root, string $rel, string $content, ?int $mtime = null): string
{
    $abs = $root . '/' . $rel;
    if (!is_dir(dirname($abs))) {
        mkdir(dirname($abs), 0755, true);
    }
    file_put_contents($abs, $content);
    if ($mtime !== null) {
        touch($abs, $mtime);
    }
    return $abs;
}
```

```php file=tests/bootstrap.php
<?php
declare(strict_types=1);

define('Sentinel\VERSION', trim((string)file_get_contents(__DIR__ . '/../VERSION')));

foreach (require __DIR__ . '/../build/files.php' as $f) {
    require_once __DIR__ . '/../src/' . $f;
}
```

```php file=tests/run.php
<?php
declare(strict_types=1);

// Usage: php tests/run.php [name-substring]
error_reporting(E_ALL);
set_error_handler(function ($no, $str, $file, $line) {
    if (!(error_reporting() & $no)) {
        return false;
    }
    throw new ErrorException($str, 0, $no, $file, $line);
});

require __DIR__ . '/lib.php';
require __DIR__ . '/bootstrap.php';
foreach (glob(__DIR__ . '/helpers_*.php') as $f) {
    require $f;
}
foreach (glob(__DIR__ . '/test_*.php') as $f) {
    require $f;
}

$filter = $argv[1] ?? '';
$pass = 0;
$fail = 0;
$skipped = 0;
foreach ($GLOBALS['__tests'] as [$name, $fn]) {
    if ($filter !== '' && stripos($name, $filter) === false) {
        continue;
    }
    try {
        $fn();
        $pass++;
        echo "ok   $name\n";
    } catch (SkipTest $e) {
        $skipped++;
        echo "skip $name ({$e->getMessage()})\n";
    } catch (Throwable $e) {
        $fail++;
        echo "FAIL $name\n     " . str_replace("\n", "\n     ", $e->getMessage()) . "\n     at " . basename($e->getFile()) . ':' . $e->getLine() . "\n";
    }
}
foreach ($GLOBALS['__tmp'] as $d) {
    rmrf($d);
}
echo "\n$pass passed, $fail failed, $skipped skipped\n";
exit($fail > 0 ? 1 : 0);
```

- [ ] **Step 3: Write the failing compat test**

```php file=tests/test_compat.php
<?php
declare(strict_types=1);

require_once __DIR__ . '/../build/compat.php';

t('compat flags PHP 8-only syntax', function () {
    $bad = "<?php\n\$x = match(1) { 1 => 2 };\nif (str_contains('a', 'b')) {}\n"
        . "class A { function __construct(private int \$x) {} }\n"
        . "function f(int|string \$v): mixed {}\ntry {} catch (Exception) {}\n\$a?->b;\n";
    $v = compat_violations($bad, 'x');
    assertTrue(count($v) >= 6, "only found:\n" . implode("\n", $v));
});

t('compat accepts PHP 7.4 code', function () {
    $ok = "<?php\n\$f = fn(\$a) => \$a + 1;\nclass A { public int \$x = 1; public function __construct(int \$x) { \$this->x = \$x; } }\n"
        . "\$s = 'str_contains(match) is only a string';\n";
    assertSame([], compat_violations($ok, 'x'));
});

t('src, build and bin are PHP 7.4 clean', function () {
    $all = [];
    $files = array_merge(glob(__DIR__ . '/../src/*.php') ?: [], glob(__DIR__ . '/../build/*.php') ?: [], glob(__DIR__ . '/../bin/*.php') ?: []);
    foreach ($files as $f) {
        $all = array_merge($all, compat_violations((string)file_get_contents($f), basename($f)));
    }
    assertSame([], $all, implode("\n", $all));
});
```

- [ ] **Step 4: Run it to verify it fails**

Run: `php tests/run.php compat`
Expected: fatal error, `Failed opening required '.../build/compat.php'`.

- [ ] **Step 5: Implement the compat checker**

```php file=build/compat.php
<?php
declare(strict_types=1);

/**
 * Heuristic PHP 7.4 compatibility check. Catches the PHP 8+ constructs this
 * project forbids; it is not a full parser.
 *
 * @return string[]
 */
function compat_violations(string $code, string $label): array
{
    $out = [];
    $banTokens = [];
    foreach (['T_MATCH', 'T_ENUM', 'T_READONLY', 'T_NULLSAFE_OBJECT_OPERATOR', 'T_ATTRIBUTE'] as $name) {
        if (defined($name)) {
            $banTokens[constant($name)] = $name;
        }
    }
    $banCalls = ['str_contains', 'str_starts_with', 'str_ends_with', 'array_is_list', 'get_debug_type', 'json_validate', 'fdiv', 'fsync'];

    $tokens = token_get_all($code);
    $n = count($tokens);
    $stripped = '';
    for ($i = 0; $i < $n; $i++) {
        $tok = $tokens[$i];
        if (!is_array($tok)) {
            $stripped .= $tok;
            continue;
        }
        [$id, $text, $line] = $tok;
        if (isset($banTokens[$id])) {
            $out[] = "$label:$line uses {$banTokens[$id]} (needs PHP 8+)";
        }
        if ($id === T_STRING && in_array(strtolower($text), $banCalls, true)) {
            $j = $i + 1;
            while ($j < $n && is_array($tokens[$j]) && $tokens[$j][0] === T_WHITESPACE) {
                $j++;
            }
            if ($j < $n && $tokens[$j] === '(') {
                $out[] = "$label:$line calls $text() (needs PHP 8+)";
            }
        }
        if ($id === T_COMMENT || $id === T_DOC_COMMENT) {
            continue;
        }
        $stripped .= $id === T_CONSTANT_ENCAPSED_STRING ? "''" : $text;
    }

    $patterns = [
        '/function\s+__construct\s*\([^)]*\b(?:public|private|protected)\b/' => 'constructor property promotion (PHP 8.0)',
        '/[(,]\s*\??[A-Za-z_\\\\][\w\\\\]*\|[\w\\\\|]+\s+&?(?:\.\.\.)?\$/' => 'union type in parameter (PHP 8.0)',
        '/\)\s*:\s*\??[A-Za-z_\\\\][\w\\\\]*\|/' => 'union type in return (PHP 8.0)',
        '/(?:\)\s*:\s*\??|[(,]\s*\??)(?:mixed|static|never)\b/' => 'mixed/static/never type (PHP 8.0+)',
        '/\bmixed\s+\$/' => 'mixed type (PHP 8.0)',
        '/catch\s*\([^)$]*\)/' => 'catch without a variable (PHP 8.0)',
    ];
    foreach ($patterns as $re => $why) {
        if (preg_match($re, $stripped, $m, PREG_OFFSET_CAPTURE)) {
            $line = substr_count(substr($stripped, 0, $m[0][1]), "\n") + 1;
            $out[] = "$label:~$line $why";
        }
    }
    return $out;
}

if (PHP_SAPI === 'cli' && isset($argv[0]) && realpath($argv[0]) === __FILE__) {
    $root = dirname(__DIR__);
    $files = array_merge(glob($root . '/src/*.php') ?: [], glob($root . '/build/*.php') ?: [], glob($root . '/bin/*.php') ?: []);
    $all = [];
    foreach ($files as $f) {
        $all = array_merge($all, compat_violations((string)file_get_contents($f), basename($f)));
    }
    echo $all ? implode("\n", $all) . "\n" : "PHP 7.4 compatibility: OK\n";
    exit($all ? 1 : 0);
}
```

- [ ] **Step 6: Run the tests and verify they pass**

Run: `php tests/run.php compat`
Expected: three `ok` lines, `3 passed, 0 failed`.

- [ ] **Step 7: Commit**

```bash
git add VERSION .gitignore build tests
git commit -m "chore: test harness and PHP 7.4 compat check"
```

---

### Task 2: Path ordering and path filtering

**Files:**
- Create: `src/PathOrder.php`, `src/PathFilter.php`
- Test: `tests/test_paths.php`
- Modify: `build/files.php` (add `'PathOrder.php', 'PathFilter.php',`)

**Interfaces:**
- Produces: `Sentinel\PathOrder::compare(string $a, string $b): int` returning -1/0/1, comparing `/`-separated segments with byte order (`strcmp`). This is the single ordering used by the walker, baseline and differ.
- Produces: `Sentinel\PathFilter::__construct(array $patterns)`, `matches(string $rel): bool`. Pattern rules: trailing `/` means directory (matches the directory and everything below); `*` matches within a segment; `**` matches across segments; `**/` matches zero or more directories; `?` one character; a pattern with no `/` (after trimming) matches a basename at any depth; a pattern containing `/` or starting with `/` is anchored at the site root.

- [ ] **Step 1: Write the failing tests**

```php file=tests/test_paths.php
<?php
declare(strict_types=1);

use Sentinel\PathFilter;
use Sentinel\PathOrder;

t('PathOrder sorts segment-wise, not by raw bytes', function () {
    // Raw strcmp would put "a.txt" before "a/b" because '.' < '/'. A directory
    // walk visits a/b first, so the ordering must too.
    $paths = ['b', 'a/c/d', 'a.txt', 'a/b'];
    usort($paths, [PathOrder::class, 'compare']);
    assertSame(['a/b', 'a/c/d', 'a.txt', 'b'], $paths);
});

t('PathOrder compares equal and prefix paths', function () {
    assertSame(0, PathOrder::compare('a/b', 'a/b'));
    assertSame(-1, PathOrder::compare('a', 'a/b'));
    assertSame(1, PathOrder::compare('a/b', 'a'));
    assertSame(-1, PathOrder::compare('123', 'abc'));
});

t('PathFilter directory patterns match the directory and its children only', function () {
    $f = new PathFilter(['wp-content/cache/']);
    assertTrue($f->matches('wp-content/cache'));
    assertTrue($f->matches('wp-content/cache/a/b.php'));
    assertTrue(!$f->matches('wp-content/cached/x'));
    assertTrue(!$f->matches('x/wp-content/cache'));
});

t('PathFilter basename globs match at any depth', function () {
    $f = new PathFilter(['*.log', 'node_modules/']);
    assertTrue($f->matches('error.log'));
    assertTrue($f->matches('a/b/error.log'));
    assertTrue(!$f->matches('error.logx'));
    assertTrue($f->matches('a/node_modules/x/y.js'));
});

t('PathFilter ** and ** / semantics', function () {
    $f = new PathFilter(['wp-content/uploads/**/*.jpg', 'wp-content/mu-plugins/**']);
    assertTrue($f->matches('wp-content/uploads/a.jpg'));
    assertTrue($f->matches('wp-content/uploads/2026/10/a.jpg'));
    assertTrue(!$f->matches('wp-content/uploads/a.png'));
    assertTrue($f->matches('wp-content/mu-plugins/x/y.php'));
});

t('PathFilter leading slash anchors a single name to the root', function () {
    $f = new PathFilter(['/sentinel.php', 'a+b.txt']);
    assertTrue($f->matches('sentinel.php'));
    assertTrue(!$f->matches('sub/sentinel.php'));
    assertTrue($f->matches('x/a+b.txt'));
    assertTrue(!$f->matches('x/aab.txt'));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php PathOrder`
Expected: `Class "Sentinel\PathOrder" not found` (the files are not in `build/files.php` yet either).

- [ ] **Step 3: Implement**

```php file=src/PathOrder.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class PathOrder
{
    /** Compares two relative paths segment by segment, in byte order. */
    public static function compare(string $a, string $b): int
    {
        if ($a === $b) {
            return 0;
        }
        $pa = explode('/', $a);
        $pb = explode('/', $b);
        $n = min(count($pa), count($pb));
        for ($i = 0; $i < $n; $i++) {
            $c = strcmp($pa[$i], $pb[$i]);
            if ($c !== 0) {
                return $c < 0 ? -1 : 1;
            }
        }
        return count($pa) <=> count($pb);
    }
}
```

```php file=src/PathFilter.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class PathFilter
{
    /** @var string[] */
    private $regexes = [];

    public function __construct(array $patterns)
    {
        foreach ($patterns as $p) {
            $p = trim((string)$p);
            if ($p !== '') {
                $this->regexes[] = self::toRegex($p);
            }
        }
    }

    public function matches(string $rel): bool
    {
        foreach ($this->regexes as $re) {
            if (preg_match($re, $rel) === 1) {
                return true;
            }
        }
        return false;
    }

    private static function toRegex(string $p): string
    {
        $isDir = substr($p, -1) === '/';
        $leading = $p[0] === '/';
        $p = trim($p, '/');
        $anchored = $leading || strpos($p, '/') !== false;
        $out = '';
        $len = strlen($p);
        for ($i = 0; $i < $len; $i++) {
            $c = $p[$i];
            if ($c === '*') {
                if (substr($p, $i, 3) === '**/') {
                    $out .= '(?:.*/)?';
                    $i += 2;
                } elseif (substr($p, $i, 2) === '**') {
                    $out .= '.*';
                    $i += 1;
                } else {
                    $out .= '[^/]*';
                }
            } elseif ($c === '?') {
                $out .= '[^/]';
            } else {
                $out .= preg_quote($c, '#');
            }
        }
        $head = $anchored ? '^' : '(?:^|/)';
        $tail = $isDir ? '(?:/.*)?' : '';
        return '#' . $head . $out . $tail . '$#s';
    }
}
```

- [ ] **Step 4: Register the files and run the tests**

Edit `build/files.php`: add `'PathOrder.php',` and `'PathFilter.php',` inside the array.

Run: `php tests/run.php Path`
Expected: all `Path*` tests `ok`.

- [ ] **Step 5: Commit**

```bash
git add src build/files.php tests/test_paths.php
git commit -m "feat: path ordering and exclusion filter"
```

---

### Task 3: Profiles and configuration

**Files:**
- Create: `src/Profile.php`, `src/Config.php`
- Test: `tests/test_config.php`, `tests/helpers_config.php` (shared `makeConfig(string $root, array $extra = []): Config`)
- Modify: `build/files.php` (add `'Profile.php', 'Config.php',` after `PathFilter.php`)

**Interfaces:**
- Consumes: `PathOrder::compare`, `PathFilter`.
- Produces: `Profile::detect(string $root): string` (`'wordpress'` if `wp-config.php` or `wp-includes/version.php` exists, else `'generic'`); `Profile::defaults(string $profile): array` with keys `exclude`, `code_extensions`, `sensitive`, `uploads_dir`.
- Produces: `ConfigException extends \RuntimeException`.
- Produces: `Config` with public properties `siteName, profile, siteRoot, stateDir, watch, exclude, codeExtensions, sensitive, uploadsDir, tempRoot, channels, budgetSeconds, budgetMemoryMb, maxScanBytes, remindHours, wpChecksums, heartbeatUrl, rulesUrl, rulesPublicKey, allowUnsignedRules, clamscanPath, yaraPath, yaraRules`; static `Config::load(string $file): Config`, `Config::fromArray(array $raw): Config`; methods `toArray(): array`, `abs(string $rel): string`, `exclusions(): array`, `addExclusion(string $absPath): void`, `isCodeFile(string $rel): bool`, `isUploads(string $rel): bool`. `siteRoot` has no trailing slash (empty string for `/`). Channel entries are normalised arrays `['type'=>..., 'min_severity'=>'info|warning|critical', ...type fields]`: email has `to` (list) and `from`; ntfy/webhook have `url`; telegram has `token`, `chat_id`; file has `path`.

- [ ] **Step 1: Write the failing tests**

```php file=tests/helpers_config.php
<?php
declare(strict_types=1);

/** Builds a generic-profile Config for $root with a throw-away state dir and a file alert channel. */
function makeConfig(string $root, array $extra = []): \Sentinel\Config
{
    $state = tmpdir();
    return \Sentinel\Config::fromArray(array_merge([
        'site_name' => 'test',
        'site_root' => $root,
        'state_dir' => $state,
        'profile' => 'generic',
        'channels' => [['type' => 'file', 'path' => $state . '/alerts.log']],
    ], $extra));
}
```

```php file=tests/test_config.php
<?php
declare(strict_types=1);

use Sentinel\Config;
use Sentinel\ConfigException;
use Sentinel\PathFilter;

t('Config detects the WordPress profile and applies its defaults', function () {
    $root = tmpdir();
    putFile($root, 'wp-config.php', '<?php');
    $c = makeConfig($root, ['profile' => '']);
    assertSame('wordpress', $c->profile);
    assertSame('wp-content/uploads', $c->uploadsDir);
    assertTrue(in_array('wp-content/cache/', $c->exclude, true));
    assertTrue(in_array('php', $c->codeExtensions, true));
});

t('Config rejects bad input', function () {
    $root = tmpdir();
    assertThrows(ConfigException::class, function () {
        Config::fromArray(['site_name' => 'x', 'site_root' => '/nonexistent-dir-xyz', 'state_dir' => '/tmp/s']);
    });
    assertThrows(ConfigException::class, function () use ($root) {
        Config::fromArray(['site_name' => '', 'site_root' => $root, 'state_dir' => '/tmp/s']);
    });
    assertThrows(ConfigException::class, function () use ($root) {
        makeConfig($root, ['channels' => [['type' => 'pigeon']]]);
    });
    assertThrows(ConfigException::class, function () use ($root) {
        makeConfig($root, ['channels' => [['type' => 'email', 'to' => ['not-an-address']]]]);
    });
    assertThrows(ConfigException::class, function () use ($root) {
        makeConfig($root, ['watch' => ['../etc']]);
    });
});

t('Config normalises watch roots', function () {
    $root = tmpdir();
    assertSame(['.'], makeConfig($root, ['watch' => ['wp-content', '.']])->watch);
    assertSame(['a', 'b'], makeConfig($root, ['watch' => ['b', 'a/x', 'a', './a']])->watch);
    assertSame(['.'], makeConfig($root, ['watch' => []])->watch);
});

t('Config normalises channels', function () {
    $c = makeConfig(tmpdir(), ['channels' => [
        ['type' => 'email', 'to' => 'owner@example.com'],
        ['type' => 'ntfy', 'url' => 'https://ntfy.sh/x', 'min_severity' => 'CRITICAL'],
    ]]);
    assertSame(['owner@example.com'], $c->channels[0]['to']);
    assertSame('warning', $c->channels[0]['min_severity']);
    assertSame('critical', $c->channels[1]['min_severity']);
});

t('Config excludes its own state dir and tool files inside the site root (Review Focus 3)', function () {
    $root = tmpdir();
    $c = Config::fromArray(['site_name' => 'x', 'site_root' => $root, 'state_dir' => $root . '/.sentinel', 'profile' => 'generic']);
    $f = new PathFilter($c->exclusions());
    assertTrue($f->matches('.sentinel'));
    assertTrue($f->matches('.sentinel/baseline.txt'));
    $c->addExclusion($root . '/sentinel.php');
    $f = new PathFilter($c->exclusions());
    assertTrue($f->matches('sentinel.php'));
    assertTrue(!$f->matches('sub/sentinel.php'));
});

t('Config classifies code files and uploads paths', function () {
    $root = tmpdir();
    putFile($root, 'wp-config.php', '<?php');
    $c = makeConfig($root, ['profile' => 'wordpress']);
    assertTrue($c->isCodeFile('a/b/Shell.PHP'));
    assertTrue($c->isCodeFile('.htaccess'));
    assertTrue(!$c->isCodeFile('wp-content/uploads/a.jpg'));
    assertTrue($c->isUploads('wp-content/uploads/2026/a.jpg'));
    assertTrue(!$c->isUploads('wp-content/uploads2/a.jpg'));
});

t('Config round-trips through toArray and abs handles the root', function () {
    $root = tmpdir();
    $c = makeConfig($root, ['budget_seconds' => 7, 'rules_url' => 'https://example.com/rules.json']);
    $again = Config::fromArray($c->toArray());
    assertSame($c->toArray(), $again->toArray());
    assertSame(7, $again->budgetSeconds);
    assertSame($c->siteRoot . '/a/b', $c->abs('a/b'));
    assertSame($c->siteRoot, $c->abs(''));
});

t('Config::load reads JSON and reports unreadable or invalid files', function () {
    $root = tmpdir();
    $dir = tmpdir();
    file_put_contents($dir . '/c.json', json_encode(['site_name' => 'j', 'site_root' => $root, 'state_dir' => $dir . '/s', 'profile' => 'generic']));
    assertSame('j', Config::load($dir . '/c.json')->siteName);
    assertThrows(ConfigException::class, function () use ($dir) { Config::load($dir . '/missing.json'); });
    file_put_contents($dir . '/bad.json', '{nope');
    assertThrows(ConfigException::class, function () use ($dir) { Config::load($dir . '/bad.json'); });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php Config`
Expected: `Class "Sentinel\Config" not found`.

- [ ] **Step 3: Implement the profile**

```php file=src/Profile.php
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
```

- [ ] **Step 4: Implement the config**

```php file=src/Config.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class ConfigException extends \RuntimeException
{
}

final class Config
{
    public const PROFILES = ['wordpress', 'generic'];
    public const CHANNEL_TYPES = ['email', 'ntfy', 'telegram', 'webhook', 'file'];

    public $siteName = '';
    public $profile = 'generic';
    public $siteRoot = '';
    public $stateDir = '';
    public $watch = ['.'];
    public $exclude = [];
    public $codeExtensions = [];
    public $sensitive = [];
    public $uploadsDir = '';
    public $tempRoot = false;
    public $channels = [];
    public $budgetSeconds = 50;
    public $budgetMemoryMb = 128;
    public $maxScanBytes = 2097152;
    public $remindHours = 24;
    public $wpChecksums = true;
    public $heartbeatUrl = '';
    public $rulesUrl = '';
    public $rulesPublicKey = '';
    public $allowUnsignedRules = false;
    public $clamscanPath = '';
    public $yaraPath = '';
    public $yaraRules = '';

    /** @var string[] */
    private $extraExclude = [];

    public static function load(string $file): Config
    {
        $json = @file_get_contents($file);
        if ($json === false) {
            throw new ConfigException("cannot read config file $file");
        }
        $raw = json_decode($json, true);
        if (!is_array($raw)) {
            throw new ConfigException("config file $file is not valid JSON");
        }
        return self::fromArray($raw);
    }

    public static function fromArray(array $raw): Config
    {
        $c = new Config();
        $root = (string)($raw['site_root'] ?? '');
        $real = $root !== '' ? realpath($root) : false;
        if ($real === false || !is_dir($real)) {
            throw new ConfigException('site_root must be an existing directory');
        }
        $c->siteRoot = rtrim($real, '/');
        $c->siteName = trim((string)($raw['site_name'] ?? ''));
        if ($c->siteName === '') {
            throw new ConfigException('site_name is required');
        }
        $c->stateDir = rtrim((string)($raw['state_dir'] ?? ''), '/');
        if ($c->stateDir === '') {
            throw new ConfigException('state_dir is required');
        }
        $profile = (string)($raw['profile'] ?? '');
        if ($profile === '') {
            $profile = Profile::detect($c->siteRoot);
        }
        if (!in_array($profile, self::PROFILES, true)) {
            throw new ConfigException("unknown profile '$profile'");
        }
        $c->profile = $profile;
        $d = Profile::defaults($profile);
        $c->watch = self::normalizeWatch($raw['watch'] ?? ['.']);
        $c->exclude = self::strings($raw['exclude'] ?? $d['exclude']);
        $c->codeExtensions = array_map('strtolower', self::strings($raw['code_extensions'] ?? $d['code_extensions']));
        $c->sensitive = self::strings($raw['sensitive'] ?? $d['sensitive']);
        $c->uploadsDir = trim((string)($raw['uploads_dir'] ?? $d['uploads_dir']), '/');
        $c->tempRoot = (bool)($raw['temp_root'] ?? false);
        $c->channels = self::channels($raw['channels'] ?? []);
        $c->budgetSeconds = self::int($raw, 'budget_seconds', 50);
        $c->budgetMemoryMb = self::int($raw, 'budget_memory_mb', 128);
        $c->maxScanBytes = self::int($raw, 'max_scan_bytes', 2097152);
        $c->remindHours = self::int($raw, 'remind_hours', 24);
        $c->wpChecksums = (bool)($raw['wp_checksums'] ?? true);
        $c->heartbeatUrl = self::url($raw, 'heartbeat_url');
        $c->rulesUrl = self::url($raw, 'rules_url');
        $c->rulesPublicKey = trim((string)($raw['rules_public_key'] ?? ''));
        $c->allowUnsignedRules = (bool)($raw['allow_unsigned_rules'] ?? false);
        $c->clamscanPath = trim((string)($raw['clamscan_path'] ?? ''));
        $c->yaraPath = trim((string)($raw['yara_path'] ?? ''));
        $c->yaraRules = trim((string)($raw['yara_rules'] ?? ''));
        return $c;
    }

    public function toArray(): array
    {
        return [
            'site_name' => $this->siteName,
            'profile' => $this->profile,
            'site_root' => $this->siteRoot === '' ? '/' : $this->siteRoot,
            'state_dir' => $this->stateDir,
            'watch' => $this->watch,
            'exclude' => $this->exclude,
            'code_extensions' => $this->codeExtensions,
            'sensitive' => $this->sensitive,
            'uploads_dir' => $this->uploadsDir,
            'temp_root' => $this->tempRoot,
            'channels' => $this->channels,
            'budget_seconds' => $this->budgetSeconds,
            'budget_memory_mb' => $this->budgetMemoryMb,
            'max_scan_bytes' => $this->maxScanBytes,
            'remind_hours' => $this->remindHours,
            'wp_checksums' => $this->wpChecksums,
            'heartbeat_url' => $this->heartbeatUrl,
            'rules_url' => $this->rulesUrl,
            'rules_public_key' => $this->rulesPublicKey,
            'allow_unsigned_rules' => $this->allowUnsignedRules,
            'clamscan_path' => $this->clamscanPath,
            'yara_path' => $this->yaraPath,
            'yara_rules' => $this->yaraRules,
        ];
    }

    public function abs(string $rel): string
    {
        if ($rel === '') {
            return $this->siteRoot === '' ? '/' : $this->siteRoot;
        }
        return $this->siteRoot . '/' . $rel;
    }

    /** Exclusion patterns: configured ones plus the state dir and added tool files. */
    public function exclusions(): array
    {
        $out = array_merge($this->exclude, $this->extraExclude);
        $rel = $this->relative($this->stateDir);
        if ($rel !== null && $rel !== '') {
            $out[] = '/' . $rel . '/';
        }
        return $out;
    }

    /** Excludes a file or directory (e.g. the script or config) when it lies inside the site root. */
    public function addExclusion(string $absPath): void
    {
        $real = realpath($absPath);
        $rel = $this->relative($real !== false ? $real : $absPath);
        if ($rel !== null && $rel !== '') {
            $this->extraExclude[] = '/' . $rel;
        }
    }

    public function isCodeFile(string $rel): bool
    {
        $base = strtolower(basename($rel));
        if (in_array($base, ['.htaccess', '.user.ini', 'php.ini'], true)) {
            return true;
        }
        return in_array(strtolower(pathinfo($base, PATHINFO_EXTENSION)), $this->codeExtensions, true);
    }

    public function isUploads(string $rel): bool
    {
        return $this->uploadsDir !== '' && ($rel === $this->uploadsDir || strpos($rel, $this->uploadsDir . '/') === 0);
    }

    private function relative(string $abs): ?string
    {
        $abs = rtrim($abs, '/');
        if ($this->siteRoot === '') {
            return ltrim($abs, '/');
        }
        if (strpos($abs, $this->siteRoot . '/') === 0) {
            return substr($abs, strlen($this->siteRoot) + 1);
        }
        return null;
    }

    private static function normalizeWatch($watch): array
    {
        $list = [];
        foreach ((array)$watch as $w) {
            $w = trim(str_replace('\\', '/', (string)$w), '/');
            $w = (string)preg_replace('#^(\./)+#', '', $w);
            if ($w === '' || $w === '.') {
                return ['.'];
            }
            if (preg_match('#(^|/)\.\.(/|$)#', $w)) {
                throw new ConfigException('watch paths must not contain ..');
            }
            $list[] = $w;
        }
        if (!$list) {
            return ['.'];
        }
        usort($list, [PathOrder::class, 'compare']);
        $out = [];
        foreach ($list as $w) {
            foreach ($out as $o) {
                if ($w === $o || strpos($w, $o . '/') === 0) {
                    continue 2;
                }
            }
            $out[] = $w;
        }
        return $out;
    }

    private static function strings($v): array
    {
        return array_values(array_map('strval', (array)$v));
    }

    private static function int(array $raw, string $key, int $default): int
    {
        $v = (int)($raw[$key] ?? $default);
        if ($v < 1) {
            throw new ConfigException("$key must be a positive integer");
        }
        return $v;
    }

    private static function url(array $raw, string $key): string
    {
        $v = trim((string)($raw[$key] ?? ''));
        if ($v !== '' && !preg_match('#^https?://#i', $v)) {
            throw new ConfigException("$key must start with http:// or https://");
        }
        return $v;
    }

    private static function channels($list): array
    {
        if (!is_array($list)) {
            throw new ConfigException('channels must be a list');
        }
        $out = [];
        foreach ($list as $i => $ch) {
            if (!is_array($ch)) {
                throw new ConfigException("channel #$i must be an object");
            }
            $type = (string)($ch['type'] ?? '');
            if (!in_array($type, self::CHANNEL_TYPES, true)) {
                throw new ConfigException("channel #$i: unknown type '$type'");
            }
            $min = strtolower((string)($ch['min_severity'] ?? 'warning'));
            if (!in_array($min, ['info', 'warning', 'critical'], true)) {
                throw new ConfigException("channel #$i: min_severity must be info, warning or critical");
            }
            $n = ['type' => $type, 'min_severity' => $min];
            switch ($type) {
                case 'email':
                    $to = array_values(array_filter(array_map('trim', array_map('strval', (array)($ch['to'] ?? [])))));
                    if (!$to) {
                        throw new ConfigException("channel #$i: email needs 'to'");
                    }
                    foreach ($to as $addr) {
                        if (!preg_match('/^[^\s@]+@[^\s@]+$/', $addr)) {
                            throw new ConfigException("channel #$i: '$addr' is not an email address");
                        }
                    }
                    $n['to'] = $to;
                    $n['from'] = trim((string)($ch['from'] ?? ''));
                    break;
                case 'ntfy':
                case 'webhook':
                    $url = trim((string)($ch['url'] ?? ''));
                    if (!preg_match('#^https?://#i', $url)) {
                        throw new ConfigException("channel #$i: $type needs an http(s) 'url'");
                    }
                    $n['url'] = $url;
                    break;
                case 'telegram':
                    $n['token'] = trim((string)($ch['token'] ?? ''));
                    $n['chat_id'] = trim((string)($ch['chat_id'] ?? ''));
                    if ($n['token'] === '' || $n['chat_id'] === '') {
                        throw new ConfigException("channel #$i: telegram needs 'token' and 'chat_id'");
                    }
                    break;
                case 'file':
                    $n['path'] = trim((string)($ch['path'] ?? ''));
                    if ($n['path'] === '' || $n['path'][0] !== '/') {
                        throw new ConfigException("channel #$i: file needs an absolute 'path'");
                    }
                    break;
            }
            $out[] = $n;
        }
        return $out;
    }
}
```

- [ ] **Step 5: Register the files and run the tests**

Edit `build/files.php`: add `'Profile.php',` and `'Config.php',` after `'PathFilter.php',`.

Run: `php tests/run.php Config`
Expected: all `Config*` tests `ok`.

- [ ] **Step 6: Commit**

```bash
git add src build/files.php tests/test_config.php
git commit -m "feat: profiles and configuration"
```

---
### Task 4: Baseline file

**Files:**
- Create: `src/Baseline.php`
- Test: `tests/test_baseline.php`
- Modify: `build/files.php` (add `'Baseline.php',` after `'Config.php',`)

**Interfaces:**
- Consumes: `PathOrder::compare`.
- Produces: a *record* is `['path'=>string, 'size'=>int, 'mtime'=>int, 'mode'=>int, 'hash'=>string]`; `mode` is the full `lstat` mode (type bits included; a symlink is `($mode & 0170000) === 0120000`). `hash` is a sha256 hex string or `''`.
- Produces: `Baseline::read(string $file): \Generator` yields records in file order; a missing file yields nothing; a malformed line throws `\RuntimeException('corrupt baseline line N')`.
- Produces: `Baseline::write(string $file, iterable $records): int` writes atomically (temp file + rename, mode 0600), returns the record count. Records must already be in `PathOrder` order.
- Produces: `Baseline::applyUpdates(string $oldFile, array $updates, string $newFile): void` where `$updates` maps path => record (insert/replace) or `null` (delete); keys may be in any order and may be integers (PHP converts all-digit string keys). Output is atomic and in `PathOrder`. `$oldFile` may equal `$newFile`.
- Produces: `Baseline::encodePath`, `decodePath`, `formatLine(array $r): string`, `parseLine(string $line): ?array`.

- [ ] **Step 1: Write the failing tests**

```php file=tests/test_baseline.php
<?php
declare(strict_types=1);

use Sentinel\Baseline;
use Sentinel\PathOrder;

function brec(string $path, int $size = 1, string $hash = ''): array
{
    return ['path' => $path, 'size' => $size, 'mtime' => 1700000000, 'mode' => 0100644, 'hash' => $hash];
}

t('Baseline round-trips odd file names (Review Focus 1)', function () {
    $f = tmpdir() . '/b.txt';
    $names = ['123', "a\tb.php", "line\nbreak.php", '100%25.txt', "ünï/çode.php", 'z', "cr\rname"];
    usort($names, [PathOrder::class, 'compare']);
    $recs = [];
    foreach ($names as $i => $n) {
        $recs[] = brec((string)$n, $i, $i % 2 ? str_repeat('a', 64) : '');
    }
    assertSame(count($recs), Baseline::write($f, $recs));
    assertSame($recs, iterator_to_array(Baseline::read($f), false));
    assertSame(0600, fileperms($f) & 0777);
});

t('Baseline::read of a missing file is empty and a corrupt line throws', function () {
    $dir = tmpdir();
    assertSame([], iterator_to_array(Baseline::read($dir . '/nope.txt'), false));
    file_put_contents($dir . '/bad.txt', "good\t1\t1\t100644\t\nthis line is garbage\n");
    assertThrows(RuntimeException::class, function () use ($dir) {
        iterator_to_array(Baseline::read($dir . '/bad.txt'), false);
    });
});

t('Baseline::applyUpdates inserts, replaces and deletes in order, including all-digit paths', function () {
    $f = tmpdir() . '/b.txt';
    Baseline::write($f, [brec('a'), brec('c'), brec('e')]);
    // '123' becomes the integer key 123 in a PHP array literal.
    Baseline::applyUpdates($f, ['e' => null, 'b' => brec('b'), 'c' => brec('c', 9), '123' => brec('123'), 'z' => brec('z')], $f);
    $recs = iterator_to_array(Baseline::read($f), false);
    assertSame(['123', 'a', 'b', 'c', 'z'], array_column($recs, 'path'));
    assertSame(9, $recs[3]['size']);
});

t('Baseline::applyUpdates builds a baseline from nothing and leaves no temp file', function () {
    $dir = tmpdir();
    Baseline::applyUpdates($dir . '/b.txt', ['x' => brec('x'), 'a/b' => brec('a/b')], $dir . '/b.txt');
    assertSame(['a/b', 'x'], array_column(iterator_to_array(Baseline::read($dir . '/b.txt'), false), 'path'));
    assertSame(['b.txt'], array_values(array_diff(scandir($dir), ['.', '..'])));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php Baseline`
Expected: `Class "Sentinel\Baseline" not found`.

- [ ] **Step 3: Implement**

```php file=src/Baseline.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Baseline
{
    public static function encodePath(string $p): string
    {
        return strtr($p, ['%' => '%25', "\t" => '%09', "\n" => '%0A', "\r" => '%0D']);
    }

    public static function decodePath(string $s): string
    {
        return strtr($s, ['%09' => "\t", '%0A' => "\n", '%0D' => "\r", '%25' => '%']);
    }

    public static function formatLine(array $r): string
    {
        return self::encodePath($r['path']) . "\t" . $r['size'] . "\t" . $r['mtime'] . "\t" . decoct($r['mode']) . "\t" . $r['hash'] . "\n";
    }

    public static function parseLine(string $line): ?array
    {
        $f = explode("\t", rtrim($line, "\r\n"), 5);
        if (count($f) !== 5 || $f[0] === '' || !ctype_digit($f[1]) || !ctype_digit($f[2]) || !ctype_digit($f[3])) {
            return null;
        }
        if ($f[4] !== '' && !ctype_xdigit($f[4])) {
            return null;
        }
        return ['path' => self::decodePath($f[0]), 'size' => (int)$f[1], 'mtime' => (int)$f[2], 'mode' => (int)octdec($f[3]), 'hash' => $f[4]];
    }

    /** @return \Generator<int, array> */
    public static function read(string $file): \Generator
    {
        if (!is_file($file)) {
            return;
        }
        $fh = @fopen($file, 'rb');
        if ($fh === false) {
            throw new \RuntimeException("cannot open baseline $file");
        }
        try {
            $n = 0;
            while (($line = fgets($fh)) !== false) {
                $n++;
                $rec = self::parseLine($line);
                if ($rec === null) {
                    throw new \RuntimeException("corrupt baseline line $n");
                }
                yield $rec;
            }
        } finally {
            fclose($fh);
        }
    }

    public static function write(string $file, iterable $records): int
    {
        $tmp = $file . '.tmp';
        $fh = @fopen($tmp, 'wb');
        if ($fh === false) {
            throw new \RuntimeException("cannot write $tmp");
        }
        @chmod($tmp, 0600);
        $n = 0;
        try {
            foreach ($records as $r) {
                fwrite($fh, self::formatLine($r));
                $n++;
            }
        } catch (\Throwable $e) {
            fclose($fh);
            @unlink($tmp);
            throw $e;
        }
        fclose($fh);
        if (!rename($tmp, $file)) {
            @unlink($tmp);
            throw new \RuntimeException("cannot replace $file");
        }
        return $n;
    }

    /** @param array<int|string, ?array> $updates path => record, or null to delete */
    public static function applyUpdates(string $oldFile, array $updates, string $newFile): void
    {
        $keys = array_map('strval', array_keys($updates));
        usort($keys, [PathOrder::class, 'compare']);
        $n = count($keys);
        $i = 0;
        $tmp = $newFile . '.tmp';
        $fh = @fopen($tmp, 'wb');
        if ($fh === false) {
            throw new \RuntimeException("cannot write $tmp");
        }
        @chmod($tmp, 0600);
        try {
            foreach (self::read($oldFile) as $rec) {
                while ($i < $n && PathOrder::compare($keys[$i], $rec['path']) < 0) {
                    if ($updates[$keys[$i]] !== null) {
                        fwrite($fh, self::formatLine($updates[$keys[$i]]));
                    }
                    $i++;
                }
                if ($i < $n && $keys[$i] === $rec['path']) {
                    if ($updates[$keys[$i]] !== null) {
                        fwrite($fh, self::formatLine($updates[$keys[$i]]));
                    }
                    $i++;
                    continue;
                }
                fwrite($fh, self::formatLine($rec));
            }
            for (; $i < $n; $i++) {
                if ($updates[$keys[$i]] !== null) {
                    fwrite($fh, self::formatLine($updates[$keys[$i]]));
                }
            }
        } catch (\Throwable $e) {
            fclose($fh);
            @unlink($tmp);
            throw $e;
        }
        fclose($fh);
        if (!rename($tmp, $newFile)) {
            @unlink($tmp);
            throw new \RuntimeException("cannot replace $newFile");
        }
    }
}
```

- [ ] **Step 4: Register and run**

Edit `build/files.php`: add `'Baseline.php',`.

Run: `php tests/run.php Baseline`
Expected: 4 `ok`.

- [ ] **Step 5: Commit**

```bash
git add src/Baseline.php build/files.php tests/test_baseline.php
git commit -m "feat: baseline file reader, writer and merge"
```

---

### Task 5: Directory walker

**Files:**
- Create: `src/Walker.php`
- Test: `tests/test_walker.php`
- Modify: `build/files.php` (add `'Walker.php',` after `'Baseline.php',`)

**Interfaces:**
- Consumes: `Config` (`siteRoot`, `watch`, `exclusions()`, `abs()`), `PathFilter`, `PathOrder`.
- Produces: `Walker::__construct(Config $c)`; `walk(string $startAfter = ''): \Generator` yields metadata records (`path,size,mtime,mode,hash=''`) for every non-directory entry under the watch roots, in strict `PathOrder`, only those strictly after `$startAfter`. Symlinks are yielded (never followed) with their link mode. `unreadable(): string[]` lists directories that could not be read (valid after the generator is consumed).

- [ ] **Step 1: Write the failing tests**

```php file=tests/test_walker.php
<?php
declare(strict_types=1);

use Sentinel\Config;
use Sentinel\PathOrder;
use Sentinel\Walker;

function walkPaths(Config $c, string $after = ''): array
{
    return array_column(iterator_to_array((new Walker($c))->walk($after), false), 'path');
}

t('Walker yields files in PathOrder, skips excluded dirs and never follows symlinks', function () {
    $root = tmpdir();
    putFile($root, 'a/b.txt', '1');
    putFile($root, 'a/c/d.txt', '1');
    putFile($root, 'a.txt', '1');
    putFile($root, 'z.txt', '1');
    putFile($root, 'cache/x.php', '1');
    symlink($root . '/a', $root . '/link');
    $c = makeConfig($root, ['exclude' => ['cache/']]);
    assertSame(['a/b.txt', 'a/c/d.txt', 'a.txt', 'link', 'z.txt'], walkPaths($c));
    $recs = iterator_to_array((new Walker($c))->walk(), false);
    $link = array_values(array_filter($recs, function ($r) { return $r['path'] === 'link'; }))[0];
    assertSame(0120000, $link['mode'] & 0170000);
});

t('Walker resumes strictly after a path, pruning whole directories', function () {
    $root = tmpdir();
    putFile($root, 'a/b.txt', '1');
    putFile($root, 'a/c/d.txt', '1');
    putFile($root, 'a.txt', '1');
    putFile($root, 'z.txt', '1');
    $c = makeConfig($root);
    assertSame(['a/c/d.txt', 'a.txt', 'z.txt'], walkPaths($c, 'a/b.txt'));
    assertSame(['a.txt', 'z.txt'], walkPaths($c, 'a/c/d.txt'));
    assertSame(['z.txt'], walkPaths($c, 'a.txt'));
    assertSame([], walkPaths($c, 'z.txt'));
});

t('Walker order matches PathOrder for odd names (Review Focus 1)', function () {
    $root = tmpdir();
    $names = ['123', "a\tb.php", "line\nbreak.php", 'Zed', "ünï.php", 'a b.php', 'dir/123', 'dir.txt', 'dir/ä'];
    foreach ($names as $n) {
        putFile($root, $n, 'x');
    }
    $expected = $names;
    usort($expected, [PathOrder::class, 'compare']);
    assertSame($expected, walkPaths(makeConfig($root)));
});

t('Walker does not see the state dir, config or script inside the web root (Review Focus 3)', function () {
    $root = tmpdir();
    putFile($root, 'index.php', '<?php');
    putFile($root, '.sentinel/baseline.txt', 'x');
    putFile($root, 'sentinel.php', '<?php');
    putFile($root, 'sentinel.json', '{}');
    $c = Config::fromArray(['site_name' => 'x', 'site_root' => $root, 'state_dir' => $root . '/.sentinel', 'profile' => 'generic']);
    $c->addExclusion($root . '/sentinel.php');
    $c->addExclusion($root . '/sentinel.json');
    assertSame(['index.php'], walkPaths($c));
});

t('Walker honours watch roots and reports unreadable directories', function () {
    $root = tmpdir();
    putFile($root, 'index.php', '1');
    putFile($root, 'wp-content/a.php', '1');
    putFile($root, 'other/x.php', '1');
    assertSame(['index.php', 'wp-content/a.php'], walkPaths(makeConfig($root, ['watch' => ['wp-content', 'index.php']])));

    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        skip('root can read everything');
    }
    putFile($root, 'locked/y.php', '1');
    chmod($root . '/locked', 0000);
    $w = new Walker(makeConfig($root));
    iterator_to_array($w->walk(), false);
    chmod($root . '/locked', 0755);
    assertSame(['locked'], $w->unreadable());
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php Walker`
Expected: `Class "Sentinel\Walker" not found`.

- [ ] **Step 3: Implement**

```php file=src/Walker.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Walker
{
    private $config;
    private $filter;
    /** @var string[] */
    private $unreadable = [];

    public function __construct(Config $config)
    {
        $this->config = $config;
        $this->filter = new PathFilter($config->exclusions());
    }

    /** @return string[] */
    public function unreadable(): array
    {
        return $this->unreadable;
    }

    /** @return \Generator<int, array> */
    public function walk(string $startAfter = ''): \Generator
    {
        foreach ($this->config->watch as $w) {
            yield from $this->visit($w === '.' ? '' : $w, $startAfter);
        }
    }

    private function visit(string $rel, string $startAfter): \Generator
    {
        if ($rel !== '' && $this->filter->matches($rel)) {
            return;
        }
        $abs = $this->config->abs($rel);
        $st = @lstat($abs);
        if ($st === false) {
            return;
        }
        $isDir = ($st['mode'] & 0170000) === 0040000;
        if (!$isDir) {
            if ($rel !== '' && PathOrder::compare($rel, $startAfter) > 0) {
                yield ['path' => $rel, 'size' => (int)$st['size'], 'mtime' => (int)$st['mtime'], 'mode' => (int)$st['mode'], 'hash' => ''];
            }
            return;
        }
        // Everything below this directory sorts before $startAfter: skip it whole.
        if ($startAfter !== '' && $rel !== '' && PathOrder::compare($rel, $startAfter) < 0 && strpos($startAfter, $rel . '/') !== 0) {
            return;
        }
        $names = @scandir($abs, SCANDIR_SORT_NONE);
        if ($names === false) {
            $this->unreadable[] = $rel === '' ? '.' : $rel;
            return;
        }
        $names = array_values(array_filter($names, function ($n) {
            return $n !== '.' && $n !== '..';
        }));
        sort($names, SORT_STRING);
        foreach ($names as $n) {
            yield from $this->visit($rel === '' ? (string)$n : $rel . '/' . $n, $startAfter);
        }
    }
}
```

- [ ] **Step 4: Register and run**

Edit `build/files.php`: add `'Walker.php',`.

Run: `php tests/run.php Walker`
Expected: 5 `ok` (the unreadable-directory test reports `skip` when run as root).

- [ ] **Step 5: Commit**

```bash
git add src/Walker.php build/files.php tests/test_walker.php
git commit -m "feat: ordered, resumable directory walker"
```

---

### Task 6: Time/memory budget and the differ

**Files:**
- Create: `src/Budget.php`, `src/Differ.php`, `tests/helpers_diff.php`
- Test: `tests/test_differ.php`
- Modify: `build/files.php` (add `'Budget.php', 'Differ.php',` after `'Walker.php',`)

**Interfaces:**
- Consumes: `Config`, `Walker`, `Baseline::read`, `PathFilter`, `PathOrder`.
- Produces: `Budget::__construct(float $seconds, int $memoryBytes, ?callable $clock = null)`, `exceeded(): bool`, `static forConfig(Config $c): Budget` (memory capped at 80% of `memory_limit`), `static iniBytes(string $v): int` (0 = unlimited).
- Produces: `Differ::__construct(Config $c)`; `record(array $meta): array` returns `[record, unreadable]` — the record has `hash` filled (sha256) for code files, empty otherwise; `diff(string $baselineFile, string $startAfter, Budget $b, bool $full): array` returning `['changes'=>array, 'stopped_at'=>?string, 'complete'=>bool, 'unreadable'=>string[]]`.
- A *change* is `['type'=>'new'|'modified'|'removed'|'dropped', 'path'=>string, 'old'=>?record, 'new'=>?record, 'stealth'=>bool, 'content_same'=>bool, 'unreadable'=>bool]`. `dropped` means a baseline entry that is now excluded (silently removed, never reported). `stealth` means content changed while size, mtime and mode did not (only detected when `$full`). `content_same` means only metadata changed (a "touch").
- The differ processes at least one entry per call, then stops when the budget is exceeded; `stopped_at` is the last processed path to pass as `$startAfter` next time.
- Test helpers: `bigBudget(): Budget`, `snapshot(Config $c, string $baselineFile): void` (writes a complete baseline of the current tree), `diffByPath(Config $c, string $baselineFile, bool $full = false): array` (changes keyed by path), `bump(string $root, string $rel, string $content, int $secondsAhead = 100): void`.

- [ ] **Step 1: Write the helpers and failing tests**

```php file=tests/helpers_diff.php
<?php
declare(strict_types=1);

function bigBudget(): \Sentinel\Budget
{
    return new \Sentinel\Budget(3600.0, PHP_INT_MAX);
}

/** Writes a complete baseline of the current tree (every change accepted). */
function snapshot(\Sentinel\Config $c, string $baselineFile): void
{
    $d = (new \Sentinel\Differ($c))->diff($baselineFile, '', bigBudget(), true);
    $u = [];
    foreach ($d['changes'] as $ch) {
        $u[$ch['path']] = in_array($ch['type'], ['removed', 'dropped'], true) ? null : $ch['new'];
    }
    \Sentinel\Baseline::applyUpdates($baselineFile, $u, $baselineFile);
}

/** Full-budget diff; returns changes keyed by path. */
function diffByPath(\Sentinel\Config $c, string $baselineFile, bool $full = false): array
{
    $out = [];
    foreach ((new \Sentinel\Differ($c))->diff($baselineFile, '', bigBudget(), $full)['changes'] as $ch) {
        $out[$ch['path']] = $ch;
    }
    return $out;
}

/** Rewrites a file with a distinct mtime so stat-based detection notices. */
function bump(string $root, string $rel, string $content, int $secondsAhead = 100): void
{
    file_put_contents($root . '/' . $rel, $content);
    touch($root . '/' . $rel, time() + $secondsAhead);
}
```

```php file=tests/test_differ.php
<?php
declare(strict_types=1);

use Sentinel\Baseline;
use Sentinel\Budget;
use Sentinel\Differ;

t('Differ finds new, modified and removed files and ignores unchanged ones', function () {
    $root = tmpdir();
    putFile($root, 'a.php', '<?php // a');
    putFile($root, 'b.txt', 'b');
    putFile($root, 'c.php', '<?php // c');
    $c = makeConfig($root);
    $b = tmpdir() . '/b.txt';
    snapshot($c, $b);
    bump($root, 'a.php', '<?php // a changed');
    unlink($root . '/c.php');
    putFile($root, 'd.php', '<?php // d');
    putFile($root, 'n.txt', 'n');
    $ch = diffByPath($c, $b);
    assertSame(['a.php', 'c.php', 'd.php', 'n.txt'], array_keys($ch));
    assertSame('modified', $ch['a.php']['type']);
    assertTrue($ch['a.php']['old']['hash'] !== $ch['a.php']['new']['hash']);
    assertSame(64, strlen($ch['a.php']['new']['hash']));
    assertSame('removed', $ch['c.php']['type']);
    assertSame('new', $ch['d.php']['type']);
    assertSame(64, strlen($ch['d.php']['new']['hash']));
    assertSame('', $ch['n.txt']['new']['hash'], 'non-code files are stat-only');
});

t('Differ marks touch-only changes as content_same', function () {
    $root = tmpdir();
    putFile($root, 'a.php', '<?php // a');
    $c = makeConfig($root);
    $b = tmpdir() . '/b.txt';
    snapshot($c, $b);
    touch($root . '/a.php', time() + 500);
    $ch = diffByPath($c, $b);
    assertSame('modified', $ch['a.php']['type']);
    assertTrue($ch['a.php']['content_same']);
});

t('Differ detects same-size same-mtime edits only in full mode (stealth)', function () {
    $root = tmpdir();
    $f = putFile($root, 'a.php', 'AAAA', time() - 1000);
    $c = makeConfig($root);
    $b = tmpdir() . '/b.txt';
    snapshot($c, $b);
    $m = filemtime($f);
    file_put_contents($f, 'BBBB');
    touch($f, $m);
    clearstatcache();
    assertSame([], diffByPath($c, $b, false));
    $ch = diffByPath($c, $b, true);
    assertSame('modified', $ch['a.php']['type']);
    assertTrue($ch['a.php']['stealth']);
});

t('Differ drops baseline entries that are now excluded instead of reporting them removed', function () {
    $root = tmpdir();
    putFile($root, 'keep.php', '<?php');
    putFile($root, 'tmp/x.php', '<?php');
    $b = tmpdir() . '/b.txt';
    snapshot(makeConfig($root), $b);
    $ch = diffByPath(makeConfig($root, ['exclude' => ['tmp/']]), $b);
    assertSame(['tmp/x.php'], array_keys($ch));
    assertSame('dropped', $ch['tmp/x.php']['type']);
});

t('Differ treats a file replaced by a directory as removed plus new', function () {
    $root = tmpdir();
    putFile($root, 'x', 'file');
    $c = makeConfig($root);
    $b = tmpdir() . '/b.txt';
    snapshot($c, $b);
    unlink($root . '/x');
    putFile($root, 'x/y.php', '<?php');
    $ch = diffByPath($c, $b);
    assertSame('removed', $ch['x']['type']);
    assertSame('new', $ch['x/y.php']['type']);
});

t('Differ stops at the budget and resumes strictly after stopped_at (Review Focus 5)', function () {
    $root = tmpdir();
    foreach (['f1', 'f2', 'f3', 'f4', 'f5'] as $n) {
        putFile($root, $n . '.txt', $n);
    }
    $c = makeConfig($root);
    $b = tmpdir() . '/b.txt';
    snapshot($c, $b);
    bump($root, 'f1.txt', 'one!');
    bump($root, 'f5.txt', 'five!');
    $seen = [];
    $after = '';
    $runs = 0;
    do {
        $t = 0.0;
        // Each clock() call advances 0.6s; with a 1s budget a run handles exactly two entries.
        $budget = new Budget(1.0, PHP_INT_MAX, function () use (&$t) { $t += 0.6; return $t; });
        $d = (new Differ($c))->diff($b, $after, $budget, false);
        foreach ($d['changes'] as $ch) {
            $seen[] = $ch['path'];
        }
        $after = (string)$d['stopped_at'];
        $runs++;
    } while (!$d['complete'] && $runs < 10);
    assertSame(['f1.txt', 'f5.txt'], $seen);
    assertSame(3, $runs);
    assertSame(null, $d['stopped_at']);
});

t('Differ always makes progress even with an already-exceeded budget', function () {
    $root = tmpdir();
    putFile($root, 'a.txt', 'a');
    putFile($root, 'b.txt', 'b');
    $c = makeConfig($root);
    $d = (new Differ($c))->diff(tmpdir() . '/none.txt', '', new Budget(0.0, 1), false);
    assertSame(1, count($d['changes']));
    assertSame('a.txt', $d['stopped_at']);
});

t('Differ surfaces a corrupt baseline instead of treating everything as new (Review Focus 5)', function () {
    $root = tmpdir();
    putFile($root, 'a.txt', 'a');
    $b = tmpdir() . '/b.txt';
    file_put_contents($b, "garbage without tabs\n");
    assertThrows(RuntimeException::class, function () use ($root, $b) {
        (new Differ(makeConfig($root)))->diff($b, '', bigBudget(), false);
    });
});

t('Differ flags unreadable code files', function () {
    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        skip('root can read everything');
    }
    $root = tmpdir();
    $f = putFile($root, 'locked.php', '<?php');
    chmod($f, 0000);
    $ch = diffByPath(makeConfig($root), tmpdir() . '/none.txt');
    chmod($f, 0644);
    assertTrue($ch['locked.php']['unreadable']);
});

t('Budget::iniBytes parses memory_limit values', function () {
    assertSame(0, Budget::iniBytes('-1'));
    assertSame(0, Budget::iniBytes(''));
    assertSame(128 * 1048576, Budget::iniBytes('128M'));
    assertSame(2 * 1073741824, Budget::iniBytes('2G'));
    assertSame(512 * 1024, Budget::iniBytes('512K'));
    assertSame(1000, Budget::iniBytes('1000'));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php Differ`
Expected: `Class "Sentinel\Differ" not found` (or `Budget`).

- [ ] **Step 3: Implement the budget**

```php file=src/Budget.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Budget
{
    private $deadline;
    private $memoryBytes;
    private $clock;

    public function __construct(float $seconds, int $memoryBytes, ?callable $clock = null)
    {
        $this->clock = $clock ?? function (): float {
            return microtime(true);
        };
        $this->deadline = ($this->clock)() + $seconds;
        $this->memoryBytes = $memoryBytes;
    }

    public function exceeded(): bool
    {
        return ($this->clock)() >= $this->deadline || memory_get_usage(true) >= $this->memoryBytes;
    }

    public static function forConfig(Config $c): Budget
    {
        $limit = self::iniBytes((string)ini_get('memory_limit'));
        $cfg = $c->budgetMemoryMb * 1048576;
        $bytes = $limit > 0 ? min($cfg, (int)($limit * 0.8)) : $cfg;
        return new Budget((float)$c->budgetSeconds, $bytes);
    }

    public static function iniBytes(string $v): int
    {
        $v = trim($v);
        if ($v === '' || $v === '-1') {
            return 0;
        }
        $n = (int)$v;
        switch (strtolower(substr($v, -1))) {
            case 'g':
                return $n * 1073741824;
            case 'm':
                return $n * 1048576;
            case 'k':
                return $n * 1024;
        }
        return $n;
    }
}
```

- [ ] **Step 4: Implement the differ**

```php file=src/Differ.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Differ
{
    private $config;
    private $filter;

    public function __construct(Config $config)
    {
        $this->config = $config;
        $this->filter = new PathFilter($config->exclusions());
    }

    /**
     * Returns [record, unreadable]. Only code files are hashed.
     *
     * @return array{0: array, 1: bool}
     */
    public function record(array $meta): array
    {
        $isLink = ($meta['mode'] & 0170000) === 0120000;
        if ($isLink || !$this->config->isCodeFile($meta['path'])) {
            return [$meta, false];
        }
        $h = @hash_file('sha256', $this->config->abs($meta['path']));
        if ($h === false) {
            return [$meta, true];
        }
        $meta['hash'] = $h;
        return [$meta, false];
    }

    /**
     * Merge-compares the walk (strictly after $startAfter) with the baseline.
     *
     * @return array{changes: array, stopped_at: ?string, complete: bool, unreadable: string[]}
     */
    public function diff(string $baselineFile, string $startAfter, Budget $budget, bool $full): array
    {
        $walker = new Walker($this->config);
        $walk = $walker->walk($startAfter);
        $base = Baseline::read($baselineFile);
        while ($base->valid() && $startAfter !== '' && PathOrder::compare($base->current()['path'], $startAfter) <= 0) {
            $base->next();
        }

        $changes = [];
        $last = $startAfter;
        $processed = 0;
        $complete = true;
        while (true) {
            if ($processed > 0 && $budget->exceeded()) {
                $complete = false;
                break;
            }
            $w = $walk->valid() ? $walk->current() : null;
            $b = $base->valid() ? $base->current() : null;
            if ($w === null && $b === null) {
                break;
            }
            if ($b === null) {
                $cmp = -1;
            } elseif ($w === null) {
                $cmp = 1;
            } else {
                $cmp = PathOrder::compare($w['path'], $b['path']);
            }
            if ($cmp < 0) {
                [$rec, $unreadable] = $this->record($w);
                $changes[] = $this->change('new', $w['path'], null, $rec, ['unreadable' => $unreadable]);
                $last = $w['path'];
                $walk->next();
            } elseif ($cmp > 0) {
                $type = $this->filter->matches($b['path']) ? 'dropped' : 'removed';
                $changes[] = $this->change($type, $b['path'], $b, null);
                $last = $b['path'];
                $base->next();
            } else {
                $c = $this->compare($w, $b, $full);
                if ($c !== null) {
                    $changes[] = $c;
                }
                $last = $w['path'];
                $walk->next();
                $base->next();
            }
            $processed++;
        }
        return ['changes' => $changes, 'stopped_at' => $complete ? null : $last, 'complete' => $complete, 'unreadable' => $walker->unreadable()];
    }

    private function compare(array $w, array $b, bool $full): ?array
    {
        $statChanged = $w['size'] !== $b['size'] || $w['mtime'] !== $b['mtime'] || $w['mode'] !== $b['mode'];
        if (!$statChanged && !$full) {
            return null;
        }
        [$rec, $unreadable] = $this->record($w);
        if (!$statChanged) {
            if ($unreadable || $rec['hash'] === '' || $b['hash'] === '' || $rec['hash'] === $b['hash']) {
                return null;
            }
            return $this->change('modified', $w['path'], $b, $rec, ['stealth' => true]);
        }
        $same = $rec['hash'] !== '' && $rec['hash'] === $b['hash'];
        return $this->change('modified', $w['path'], $b, $rec, ['content_same' => $same, 'unreadable' => $unreadable]);
    }

    private function change(string $type, string $path, ?array $old, ?array $new, array $flags = []): array
    {
        return array_merge([
            'type' => $type, 'path' => $path, 'old' => $old, 'new' => $new,
            'stealth' => false, 'content_same' => false, 'unreadable' => false,
        ], $flags);
    }
}
```

- [ ] **Step 5: Register and run**

Edit `build/files.php`: add `'Budget.php', 'Differ.php',`.

Run: `php tests/run.php Differ && php tests/run.php Budget`
Expected: all `ok` (unreadable test `skip` as root).

- [ ] **Step 6: Commit**

```bash
git add src/Budget.php src/Differ.php build/files.php tests/helpers_diff.php tests/test_differ.php
git commit -m "feat: time budget and resumable baseline differ"
```

---

### Task 7: Findings, rules and the pattern and location scanners

**Files:**
- Create: `src/Finding.php`, `src/Rules.php`, `src/PatternScanner.php`, `src/LocationScanner.php`
- Test: `tests/test_scanners.php`
- Modify: `build/files.php` (add `'Finding.php', 'Rules.php', 'PatternScanner.php', 'LocationScanner.php',` after `'Differ.php',`)

**Interfaces:**
- Consumes: `Config` (`isCodeFile`, `isUploads`, `abs`, `tempRoot`, `maxScanBytes`).
- Produces: `Finding` with constants `INFO=1, WARNING=2, CRITICAL=3`; public `$severity, $path, $rule, $message, $hash`; `__construct(int $severity, string $path, string $rule, string $message, string $hash = '')`; `key(): string` (sha1 of rule, path, hash — the dedupe identity); `static label(int): string` (`INFO|WARNING|CRITICAL`); `static parseSeverity(string): int` (`info|warning|critical`, case-insensitive, default WARNING).
- Produces: `Rules` with public `$version`, `$patterns`, `$hashes`; `static builtin(): Rules`, `fromArray(array): Rules` (throws `\InvalidArgumentException` on a bad entry or regex), `load(string $file): Rules`; `matchContent(string $content): array` (matching pattern entries `['id','severity'=>'warning|critical','regex','description']`); `badHash(string $sha256): ?string`. The builtin set includes a self-test marker, `SENTINEL-TEST-MALWARE-MARKER`, so a user can verify alerts end to end.
- Produces: `PatternScanner::__construct(Rules $r, int $maxBytes)`; `scan(string $rel, string $abs, string $sha256): Finding[]` (bad-hash and pattern hits); `static headTail(string $abs, int $maxBytes): ?string` returns the whole file if it fits, else the first and last `maxBytes/2` joined by a newline (so a payload appended to a big file is still seen).
- Produces: `LocationScanner::__construct(Config $c)`; `scan(string $rel, array $record, bool $isNew): Finding[]`. Rules: PHP extension anywhere in the name chain under uploads → Critical `php-in-uploads`; new media file containing PHP tags in its first or last 64KB → Critical `php-in-media`; new `.htaccess`/`.user.ini` under uploads → Warning `config-in-uploads`; new file with an executable bit in a `tmp`/`temp` path segment (or anywhere when `tempRoot`) that is not a media file → Critical `exec-in-temp`; symlinks are ignored.

- [ ] **Step 1: Write the failing tests**

```php file=tests/test_scanners.php
<?php
declare(strict_types=1);

use Sentinel\Config;
use Sentinel\Finding;
use Sentinel\LocationScanner;
use Sentinel\PatternScanner;
use Sentinel\Rules;

function rulesOf(array $findings): array
{
    return array_map(function (Finding $f) { return $f->rule; }, $findings);
}

function lrec(string $root, string $rel): array
{
    $st = lstat($root . '/' . $rel);
    return ['path' => $rel, 'size' => (int)$st['size'], 'mtime' => (int)$st['mtime'], 'mode' => (int)$st['mode'], 'hash' => ''];
}

function wpConfig(string $root): Config
{
    putFile($root, 'wp-config.php', '<?php');
    return makeConfig($root, ['profile' => 'wordpress']);
}

t('Finding key is stable and depends on rule, path and hash', function () {
    $a = new Finding(Finding::CRITICAL, 'a.php', 'r', 'm', 'h1');
    assertSame($a->key(), (new Finding(Finding::WARNING, 'a.php', 'r', 'other message', 'h1'))->key());
    assertTrue($a->key() !== (new Finding(Finding::CRITICAL, 'a.php', 'r', 'm', 'h2'))->key());
    assertSame('CRITICAL', Finding::label(Finding::CRITICAL));
    assertSame(Finding::WARNING, Finding::parseSeverity('Warning'));
    assertSame(Finding::INFO, Finding::parseSeverity('INFO'));
});

t('Builtin rules match known-bad snippets and not ordinary code', function () {
    $r = Rules::builtin();
    $ids = function (string $code) use ($r) {
        return array_column($r->matchContent($code), 'id');
    };
    assertSame(['test-marker'], $ids('<?php // SENTINEL-TEST-MALWARE-MARKER'));
    assertSame(['eval-decoder'], $ids('<?php eval(base64_decode($payload));'));
    assertSame(['exec-request'], $ids('<?php system($_GET["c"]);'));
    assertSame(['request-callable'], $ids('<?php $_POST["f"]($x);'));
    assertSame([], $ids('<?php echo htmlspecialchars($_GET["q"]); $x = base64_decode($y);'));
});

t('Rules::fromArray validates entries and exposes bad hashes', function () {
    assertThrows(InvalidArgumentException::class, function () {
        Rules::fromArray(['patterns' => [['id' => 'x', 'severity' => 'critical', 'regex' => '/(unclosed/']]]);
    });
    assertThrows(InvalidArgumentException::class, function () {
        Rules::fromArray(['patterns' => [['id' => 'x', 'severity' => 'loud', 'regex' => '/a/']]]);
    });
    assertThrows(InvalidArgumentException::class, function () {
        Rules::fromArray(['hashes' => [['sha256' => 'nothex']]]);
    });
    $sha = hash('sha256', 'bad');
    $r = Rules::fromArray(['version' => 5, 'patterns' => [], 'hashes' => [['sha256' => strtoupper($sha), 'name' => 'Evil.A']]]);
    assertSame(5, $r->version);
    assertSame('Evil.A', $r->badHash($sha));
    assertSame(null, $r->badHash(hash('sha256', 'good')));
});

t('Rules::load reads a bundle from disk', function () {
    $f = tmpdir() . '/rules.json';
    file_put_contents($f, json_encode(['version' => 3, 'patterns' => [['id' => 'p', 'severity' => 'warning', 'regex' => '/needle/', 'description' => 'Needle']]]));
    $r = Rules::load($f);
    assertSame(3, $r->version);
    assertSame(['p'], array_column($r->matchContent('hay needle hay'), 'id'));
});

t('PatternScanner reports pattern hits and bad hashes with the file hash', function () {
    $root = tmpdir();
    $abs = putFile($root, 'a.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $sha = hash_file('sha256', $abs);
    $s = new PatternScanner(Rules::builtin(), 1048576);
    $f = $s->scan('a.php', $abs, $sha);
    assertSame(['test-marker'], rulesOf($f));
    assertSame(Finding::CRITICAL, $f[0]->severity);
    assertSame($sha, $f[0]->hash);

    $bad = Rules::fromArray(['hashes' => [['sha256' => $sha, 'name' => 'Known.Bad']]]);
    $f2 = (new PatternScanner($bad, 1048576))->scan('a.php', $abs, $sha);
    assertSame(['bad-hash'], rulesOf($f2));
    assertSame([], $s->scan('missing.php', $root . '/missing.php', ''));
});

t('PatternScanner sees a payload appended to a file larger than max_scan_bytes (Review Focus 2)', function () {
    $root = tmpdir();
    $pad = str_repeat("// padding line\n", 200000); // ~3.2MB
    $tail = putFile($root, 'tail.php', "<?php\n" . $pad . "// SENTINEL-TEST-MALWARE-MARKER\n");
    $head = putFile($root, 'head.php', "<?php // SENTINEL-TEST-MALWARE-MARKER\n" . $pad);
    $mid = putFile($root, 'mid.php', "<?php\n" . $pad . "// SENTINEL-TEST-MALWARE-MARKER\n" . $pad);
    $s = new PatternScanner(Rules::builtin(), 1048576);
    assertSame(['test-marker'], rulesOf($s->scan('tail.php', $tail, '')));
    assertSame(['test-marker'], rulesOf($s->scan('head.php', $head, '')));
    // Documented limit: the middle of a file larger than max_scan_bytes is not read.
    assertSame([], $s->scan('mid.php', $mid, ''));
});

t('LocationScanner flags PHP in uploads, including double extensions', function () {
    $root = tmpdir();
    $c = wpConfig($root);
    foreach (['wp-content/uploads/shell.php', 'wp-content/uploads/a/b.PHTML', 'wp-content/uploads/pic.php.jpg', 'wp-content/uploads/ok.jpg'] as $p) {
        putFile($root, $p, 'x');
    }
    $s = new LocationScanner($c);
    assertSame(['php-in-uploads'], rulesOf($s->scan('wp-content/uploads/shell.php', lrec($root, 'wp-content/uploads/shell.php'), true)));
    assertSame(['php-in-uploads'], rulesOf($s->scan('wp-content/uploads/a/b.PHTML', lrec($root, 'wp-content/uploads/a/b.PHTML'), true)));
    assertSame(['php-in-uploads'], rulesOf($s->scan('wp-content/uploads/pic.php.jpg', lrec($root, 'wp-content/uploads/pic.php.jpg'), true)));
    assertSame([], $s->scan('wp-content/uploads/ok.jpg', lrec($root, 'wp-content/uploads/ok.jpg'), true));
    // Same extension outside uploads is not a location finding.
    putFile($root, 'wp-content/themes/t/functions.php', '<?php');
    assertSame([], $s->scan('wp-content/themes/t/functions.php', lrec($root, 'wp-content/themes/t/functions.php'), true));
});

t('LocationScanner finds PHP hidden in new media and config files in uploads', function () {
    $root = tmpdir();
    $c = wpConfig($root);
    putFile($root, 'wp-content/uploads/head.jpg', "<?php system(\$_GET['c']); ?>\xFF\xD8");
    putFile($root, 'wp-content/uploads/tail.png', str_repeat("\x89PNG", 5000) . '<?php echo 1;');
    putFile($root, 'wp-content/uploads/.htaccess', 'AddHandler application/x-httpd-php .jpg');
    $s = new LocationScanner($c);
    assertSame(['php-in-media'], rulesOf($s->scan('wp-content/uploads/head.jpg', lrec($root, 'wp-content/uploads/head.jpg'), true)));
    assertSame(['php-in-media'], rulesOf($s->scan('wp-content/uploads/tail.png', lrec($root, 'wp-content/uploads/tail.png'), true)));
    assertSame([], $s->scan('wp-content/uploads/head.jpg', lrec($root, 'wp-content/uploads/head.jpg'), false));
    $f = $s->scan('wp-content/uploads/.htaccess', lrec($root, 'wp-content/uploads/.htaccess'), true);
    assertSame(['config-in-uploads'], rulesOf($f));
    assertSame(Finding::WARNING, $f[0]->severity);
});

t('LocationScanner flags new executables in temp paths and ignores symlinks', function () {
    $root = tmpdir();
    $c = makeConfig($root);
    $x = putFile($root, 'tmp/run', '#!/bin/sh');
    chmod($x, 0755);
    $y = putFile($root, 'bin/tool', '#!/bin/sh');
    chmod($y, 0755);
    $s = new LocationScanner($c);
    assertSame(['exec-in-temp'], rulesOf($s->scan('tmp/run', lrec($root, 'tmp/run'), true)));
    assertSame([], $s->scan('tmp/run', lrec($root, 'tmp/run'), false));
    assertSame([], $s->scan('bin/tool', lrec($root, 'bin/tool'), true));

    $t = makeConfig($root, ['temp_root' => true]);
    assertSame(['exec-in-temp'], rulesOf((new LocationScanner($t))->scan('bin/tool', lrec($root, 'bin/tool'), true)));

    symlink($x, $root . '/tmp/link');
    assertSame([], $s->scan('tmp/link', lrec($root, 'tmp/link'), true));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php Finding`
Expected: `Class "Sentinel\Finding" not found`.

- [ ] **Step 3: Implement Finding and Rules**

```php file=src/Finding.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Finding
{
    public const INFO = 1;
    public const WARNING = 2;
    public const CRITICAL = 3;

    public $severity;
    public $path;
    public $rule;
    public $message;
    public $hash;

    public function __construct(int $severity, string $path, string $rule, string $message, string $hash = '')
    {
        $this->severity = $severity;
        $this->path = $path;
        $this->rule = $rule;
        $this->message = $message;
        $this->hash = $hash;
    }

    /** Identity used for alert dedupe: the same rule on the same file content alerts once. */
    public function key(): string
    {
        return sha1($this->rule . "\0" . $this->path . "\0" . $this->hash);
    }

    public static function label(int $severity): string
    {
        if ($severity >= self::CRITICAL) {
            return 'CRITICAL';
        }
        return $severity === self::WARNING ? 'WARNING' : 'INFO';
    }

    public static function parseSeverity(string $s): int
    {
        switch (strtolower(trim($s))) {
            case 'critical':
                return self::CRITICAL;
            case 'info':
                return self::INFO;
        }
        return self::WARNING;
    }
}
```

```php file=src/Rules.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Rules
{
    public $version = 0;
    /** @var array[] */
    public $patterns = [];
    /** @var array<string,string> sha256 => name */
    public $hashes = [];

    public static function builtin(): Rules
    {
        return self::fromArray([
            'version' => 0,
            'patterns' => [
                ['id' => 'test-marker', 'severity' => 'critical', 'regex' => '/SENTINEL-TEST-MALWARE-MARKER/', 'description' => 'Sentinel self-test marker'],
                ['id' => 'eval-decoder', 'severity' => 'critical', 'regex' => '/\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i', 'description' => 'eval of an encoded payload'],
                ['id' => 'eval-request', 'severity' => 'critical', 'regex' => '/\b(?:eval|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i', 'description' => 'eval of request data'],
                ['id' => 'exec-request', 'severity' => 'critical', 'regex' => '/\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i', 'description' => 'shell command built from request data'],
                ['id' => 'request-callable', 'severity' => 'critical', 'regex' => '/\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,64}\]\s*\(/', 'description' => 'request data called as a function'],
                ['id' => 'chr-chain', 'severity' => 'warning', 'regex' => '/(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){8,}/i', 'description' => 'string assembled from chr() calls (obfuscation)'],
            ],
            'hashes' => [],
        ]);
    }

    public static function fromArray(array $d): Rules
    {
        $r = new Rules();
        $r->version = (int)($d['version'] ?? 0);
        foreach ((array)($d['patterns'] ?? []) as $p) {
            $id = (string)($p['id'] ?? '');
            $sev = strtolower((string)($p['severity'] ?? ''));
            $re = (string)($p['regex'] ?? '');
            if ($id === '' || $re === '' || !in_array($sev, ['warning', 'critical'], true)) {
                throw new \InvalidArgumentException('invalid rule entry' . ($id !== '' ? " '$id'" : ''));
            }
            if (@preg_match($re, '') === false) {
                throw new \InvalidArgumentException("invalid regex in rule '$id'");
            }
            $r->patterns[] = ['id' => $id, 'severity' => $sev, 'regex' => $re, 'description' => (string)($p['description'] ?? $id)];
        }
        foreach ((array)($d['hashes'] ?? []) as $h) {
            $sha = strtolower((string)($h['sha256'] ?? ''));
            if (!preg_match('/^[a-f0-9]{64}$/', $sha)) {
                throw new \InvalidArgumentException('invalid sha256 in rules');
            }
            $r->hashes[$sha] = (string)($h['name'] ?? 'known-bad');
        }
        return $r;
    }

    public static function load(string $file): Rules
    {
        $json = @file_get_contents($file);
        $data = $json === false ? null : json_decode($json, true);
        if (!is_array($data)) {
            throw new \InvalidArgumentException("cannot read rules file $file");
        }
        return self::fromArray($data);
    }

    /** @return array[] the patterns that match $content */
    public function matchContent(string $content): array
    {
        $hits = [];
        foreach ($this->patterns as $p) {
            if (preg_match($p['regex'], $content) === 1) {
                $hits[] = $p;
            }
        }
        return $hits;
    }

    public function badHash(string $sha256): ?string
    {
        return $this->hashes[strtolower($sha256)] ?? null;
    }
}
```

- [ ] **Step 4: Implement the scanners**

```php file=src/PatternScanner.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class PatternScanner
{
    private $rules;
    private $maxBytes;

    public function __construct(Rules $rules, int $maxBytes)
    {
        $this->rules = $rules;
        $this->maxBytes = $maxBytes;
    }

    /** @return Finding[] */
    public function scan(string $rel, string $abs, string $sha256): array
    {
        $out = [];
        if ($sha256 !== '' && ($name = $this->rules->badHash($sha256)) !== null) {
            $out[] = new Finding(Finding::CRITICAL, $rel, 'bad-hash', 'Matches a known-bad file hash: ' . $name, $sha256);
        }
        $content = self::headTail($abs, $this->maxBytes);
        if ($content === null) {
            return $out;
        }
        foreach ($this->rules->matchContent($content) as $p) {
            $sev = $p['severity'] === 'critical' ? Finding::CRITICAL : Finding::WARNING;
            $out[] = new Finding($sev, $rel, $p['id'], $p['description'], $sha256);
        }
        return $out;
    }

    /**
     * The whole file if it fits in $maxBytes, otherwise its first and last
     * half-budget joined by a newline (attackers append payloads to big files).
     */
    public static function headTail(string $abs, int $maxBytes): ?string
    {
        $size = @filesize($abs);
        $fh = $size === false ? false : @fopen($abs, 'rb');
        if ($fh === false) {
            return null;
        }
        if ($size <= $maxBytes) {
            $c = stream_get_contents($fh);
        } else {
            $half = intdiv($maxBytes, 2);
            $head = (string)fread($fh, $half);
            fseek($fh, -$half, SEEK_END);
            $c = $head . "\n" . (string)fread($fh, $half);
        }
        fclose($fh);
        return $c === false ? null : $c;
    }
}
```

```php file=src/LocationScanner.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class LocationScanner
{
    private const PHP_EXT = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phar', 'phps'];
    private const MEDIA_EXT = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'ico', 'bmp'];

    private $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /** @return Finding[] */
    public function scan(string $rel, array $record, bool $isNew): array
    {
        if (($record['mode'] & 0170000) === 0120000) {
            return [];
        }
        $out = [];
        $hash = (string)$record['hash'];
        $base = strtolower(basename($rel));
        $parts = explode('.', $base);
        array_shift($parts);
        $ext = $parts ? end($parts) : '';
        $isMedia = in_array($ext, self::MEDIA_EXT, true);

        if ($this->config->isUploads($rel)) {
            if (array_intersect($parts, self::PHP_EXT)) {
                $out[] = new Finding(Finding::CRITICAL, $rel, 'php-in-uploads', 'PHP file in the uploads directory', $hash);
            } elseif ($isNew && $isMedia && $this->hasPhpTag($this->config->abs($rel))) {
                $out[] = new Finding(Finding::CRITICAL, $rel, 'php-in-media', 'Media file containing PHP code', $hash);
            }
            if ($isNew && ($base === '.htaccess' || $base === '.user.ini')) {
                $out[] = new Finding(Finding::WARNING, $rel, 'config-in-uploads', 'Server configuration file in the uploads directory', $hash);
            }
        }

        if ($isNew && !$isMedia && ($record['mode'] & 0111) !== 0 && $this->inTemp($rel)) {
            $out[] = new Finding(Finding::CRITICAL, $rel, 'exec-in-temp', 'New executable file in a temp directory', $hash);
        }
        return $out;
    }

    private function inTemp(string $rel): bool
    {
        if ($this->config->tempRoot) {
            return true;
        }
        foreach (explode('/', dirname($rel)) as $seg) {
            if ($seg === 'tmp' || $seg === 'temp') {
                return true;
            }
        }
        return false;
    }

    private function hasPhpTag(string $abs): bool
    {
        $c = PatternScanner::headTail($abs, 131072);
        return $c !== null && (stripos($c, '<?php') !== false || strpos($c, '<?=') !== false);
    }
}
```

- [ ] **Step 5: Register and run**

Edit `build/files.php`: add `'Finding.php', 'Rules.php', 'PatternScanner.php', 'LocationScanner.php',`.

Run: `php tests/run.php Rules && php tests/run.php Scanner && php tests/run.php Finding`
Expected: all `ok`.

- [ ] **Step 6: Commit**

```bash
git add src build/files.php tests/test_scanners.php
git commit -m "feat: findings, rules bundle and pattern/location scanners"
```

---
### Task 8: HTTP client

**Files:**
- Create: `src/HttpClient.php`
- Test: `tests/test_http.php`, `tests/helpers_http.php` (shared `FakeHttp`)
- Modify: `build/files.php` (add `'HttpClient.php',` after `'LocationScanner.php',`)

**Interfaces:**
- Produces: `interface HttpClient { request(string $method, string $url, string $body = '', array $headers = [], int $timeout = 10): array }` returning `['status'=>int, 'body'=>string]`; `status` is `0` on any transport failure (DNS, TLS, timeout, non-http URL). Never throws.
- Produces: `NativeHttp implements HttpClient`, `__construct(bool $preferCurl = true)`. Uses curl when available, otherwise `file_get_contents` with a stream context. TLS verification stays on. Sends `User-Agent: site-sentinel/<VERSION>`. Follows at most 3 redirects. `$headers` is `name => value`.
- Produces (tests): `FakeHttp implements HttpClient` with `route(string $urlPrefix, int $status, string $body)`, public `$calls` (list of `[method, url, body, headers]`); an unmatched URL returns status 0.

- [ ] **Step 1: Write the fake and the failing tests**

```php file=tests/helpers_http.php
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
```

```php file=tests/test_http.php
<?php
declare(strict_types=1);

use Sentinel\NativeHttp;

/** @return array{0:int,1:resource} port and process of a throw-away local web server */
function startEchoServer(): array
{
    $dir = tmpdir();
    file_put_contents($dir . '/router.php', '<?php
if (($_SERVER["REQUEST_URI"] ?? "") === "/missing") { http_response_code(404); echo "nope"; return; }
$in = file_get_contents("php://input");
echo $_SERVER["REQUEST_METHOD"] . ":" . ($in !== "" ? $in : "empty") . ":" . ($_SERVER["HTTP_X_TEST"] ?? "-");');
    $sock = stream_socket_server('tcp://127.0.0.1:0');
    $name = stream_socket_get_name($sock, false);
    $port = (int)substr($name, (int)strrpos($name, ':') + 1);
    fclose($sock);
    $proc = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', $dir, $dir . '/router.php'], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    for ($i = 0; $i < 50; $i++) {
        $c = @fsockopen('127.0.0.1', $port, $en, $es, 0.2);
        if ($c) {
            fclose($c);
            break;
        }
        usleep(100000);
    }
    return [$port, $proc];
}

t('NativeHttp performs GET and POST with headers over curl and over streams', function () {
    [$port, $proc] = startEchoServer();
    try {
        foreach ([true, false] as $preferCurl) {
            if ($preferCurl && !function_exists('curl_init')) {
                continue;
            }
            $h = new NativeHttp($preferCurl);
            $get = $h->request('GET', "http://127.0.0.1:$port/", '', ['X-Test' => 'yes'], 5);
            assertSame(['status' => 200, 'body' => 'GET:empty:yes'], $get, 'GET preferCurl=' . var_export($preferCurl, true));
            $post = $h->request('POST', "http://127.0.0.1:$port/", 'payload', [], 5);
            assertSame(['status' => 200, 'body' => 'POST:payload:-'], $post, 'POST preferCurl=' . var_export($preferCurl, true));
            assertSame(404, $h->request('GET', "http://127.0.0.1:$port/missing", '', [], 5)['status']);
        }
    } finally {
        proc_terminate($proc);
        proc_close($proc);
    }
});

t('NativeHttp reports transport failures as status 0 and refuses non-http URLs', function () {
    $sock = stream_socket_server('tcp://127.0.0.1:0');
    $name = stream_socket_get_name($sock, false);
    $port = (int)substr($name, (int)strrpos($name, ':') + 1);
    fclose($sock); // now nothing listens on $port
    foreach ([true, false] as $preferCurl) {
        $h = new NativeHttp($preferCurl);
        assertSame(0, $h->request('GET', "http://127.0.0.1:$port/", '', [], 2)['status']);
        assertSame(0, $h->request('GET', 'file:///etc/passwd', '', [], 2)['status']);
        assertSame(0, $h->request('GET', 'ftp://example.com/x', '', [], 2)['status']);
    }
});

t('FakeHttp matches by prefix and fails otherwise', function () {
    $f = new FakeHttp();
    $f->route('https://a.example/x', 200, 'ok');
    assertSame(['status' => 200, 'body' => 'ok'], $f->request('GET', 'https://a.example/x?y=1'));
    assertSame(0, $f->request('GET', 'https://b.example/')['status']);
    assertSame(2, count($f->calls));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php Http`
Expected: `Interface "Sentinel\HttpClient" not found`.

- [ ] **Step 3: Implement**

```php file=src/HttpClient.php
<?php
declare(strict_types=1);

namespace Sentinel;

interface HttpClient
{
    /**
     * @param array<string,string> $headers
     * @return array{status:int, body:string} status is 0 on any transport failure
     */
    public function request(string $method, string $url, string $body = '', array $headers = [], int $timeout = 10): array;
}

final class NativeHttp implements HttpClient
{
    private $preferCurl;

    public function __construct(bool $preferCurl = true)
    {
        $this->preferCurl = $preferCurl;
    }

    public function request(string $method, string $url, string $body = '', array $headers = [], int $timeout = 10): array
    {
        if (!preg_match('#^https?://#i', $url)) {
            return ['status' => 0, 'body' => ''];
        }
        $lines = [];
        foreach ($headers as $k => $v) {
            $lines[] = str_replace(["\r", "\n", ':'], '', (string)$k) . ': ' . str_replace(["\r", "\n"], '', (string)$v);
        }
        $lines[] = 'User-Agent: site-sentinel/' . VERSION;
        if ($this->preferCurl && function_exists('curl_init')) {
            return $this->viaCurl($method, $url, $body, $lines, $timeout);
        }
        return $this->viaStream($method, $url, $body, $lines, $timeout);
    }

    private function viaCurl(string $method, string $url, string $body, array $lines, int $timeout): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
        ]);
        if ($body !== '') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $resp = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        unset($ch);
        if ($resp === false) {
            return ['status' => 0, 'body' => ''];
        }
        return ['status' => $status, 'body' => (string)$resp];
    }

    private function viaStream(string $method, string $url, string $body, array $lines, int $timeout): array
    {
        $ctx = stream_context_create(['http' => [
            'method' => $method,
            'header' => implode("\r\n", $lines),
            'content' => $body,
            'timeout' => $timeout,
            'ignore_errors' => true,
            'follow_location' => 1,
            'max_redirects' => 3,
        ]]);
        $resp = @file_get_contents($url, false, $ctx);
        if ($resp === false) {
            return ['status' => 0, 'body' => ''];
        }
        $status = 0;
        // PHP 8.4+ deprecates the magic $http_response_header variable.
        $responseHeaders = function_exists('http_get_last_response_headers')
            ? (http_get_last_response_headers() ?? [])
            : (get_defined_vars()['http_response_header'] ?? []);
        foreach ($responseHeaders as $h) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', (string)$h, $m)) {
                $status = (int)$m[1];
            }
        }
        return ['status' => $status, 'body' => $resp];
    }
}
```

- [ ] **Step 4: Register and run**

Edit `build/files.php`: add `'HttpClient.php',`.

Run: `php tests/run.php Http`
Expected: 3 `ok`.

- [ ] **Step 5: Commit**

```bash
git add src/HttpClient.php build/files.php tests/helpers_http.php tests/test_http.php
git commit -m "feat: HTTP client with curl and stream backends"
```

---

### Task 9: WordPress version tracking and checksum verification

**Files:**
- Create: `src/VersionTracker.php`, `src/WpChecksum.php`
- Test: `tests/test_wp.php`
- Modify: `build/files.php` (add `'VersionTracker.php', 'WpChecksum.php',` after `'HttpClient.php',`)

**Interfaces:**
- Consumes: `Config`, `HttpClient`.
- Produces: `VersionTracker::read(Config $c): array` maps group directory => version for every plugin (`wp-content/plugins/<slug>`, version from the `Version:` header of a root `.php` file that also has `Plugin Name:`) and theme (`wp-content/themes/<slug>`, `Version:` in `style.css`); directories without a version are omitted. `VersionTracker::dirVersion(Config $c, string $relDir): ?string`.
- Produces: `WpChecksum::__construct(HttpClient $http, Config $c, string $cacheDir)`; constants `VERIFIED='match'`, `MISMATCH='mismatch'`, `EXTRA='extra'`, `UNKNOWN='unknown'`; `verify(string $rel): string`; `isCorePath(string $rel): bool`; `notes(): string[]` (messages such as "WordPress core checksums unavailable ..."; deduplicated). Core data comes from `https://api.wordpress.org/core/checksums/1.0/?version=V&locale=L` (md5); plugin data from `https://downloads.wordpress.org/plugin-checksums/<slug>/<version>.json` (`sha256`/`md5` maps whose values are a string or a list). Results are cached under `$cacheDir`; a failed lookup is remembered for the rest of the run and recorded as a note. A 404 for a plugin means "not in the repository" (premium/custom) and is silent. `verify` never returns `VERIFIED` or `MISMATCH` without real data (Review Focus 4).
- Semantics: a file listed in the core map → `VERIFIED`/`MISMATCH` by md5; under `wp-admin/` or `wp-includes/` but not listed → `EXTRA`; under `wp-content/plugins/<slug>/` with a known version and repo checksums → `VERIFIED`/`MISMATCH`, or `EXTRA` if the file is not in the official package; everything else → `UNKNOWN`.

- [ ] **Step 1: Write the failing tests**

```php file=tests/test_wp.php
<?php
declare(strict_types=1);

use Sentinel\Config;
use Sentinel\VersionTracker;
use Sentinel\WpChecksum;

function wpSite(string $root, string $version = '6.4.2'): Config
{
    putFile($root, 'wp-config.php', '<?php');
    putFile($root, 'wp-includes/version.php', "<?php\n\$wp_version = '$version';\n");
    return makeConfig($root, ['profile' => 'wordpress']);
}

/** @param array<string,string> $files path => official content */
function coreRoute(FakeHttp $http, array $files, string $version = '6.4.2'): void
{
    $sums = [];
    foreach ($files as $rel => $content) {
        $sums[$rel] = md5($content);
    }
    $http->route('https://api.wordpress.org/core/checksums/1.0/?version=' . $version, 200, json_encode(['checksums' => $sums]));
}

function pluginHeader(string $version): string
{
    return "<?php\n/*\nPlugin Name: Foo\nVersion: $version\n*/\n";
}

t('VersionTracker reads plugin and theme versions and skips unversioned directories', function () {
    $root = tmpdir();
    $c = wpSite($root);
    putFile($root, 'wp-content/plugins/foo/foo.php', pluginHeader('1.2.3'));
    putFile($root, 'wp-content/plugins/foo/readme.php', "<?php // Version: 9.9.9 (not a plugin header)\n");
    putFile($root, 'wp-content/plugins/nover/nover.php', "<?php // nothing\n");
    putFile($root, 'wp-content/plugins/.hidden/x.php', pluginHeader('7'));
    putFile($root, 'wp-content/themes/twenty/style.css', "/*\nTheme Name: Twenty\nVersion: 2.0 */\n");
    assertSame([
        'wp-content/plugins/foo' => '1.2.3',
        'wp-content/themes/twenty' => '2.0',
    ], VersionTracker::read($c));
    assertSame('1.2.3', VersionTracker::dirVersion($c, 'wp-content/plugins/foo'));
    assertSame(null, VersionTracker::dirVersion($c, 'wp-content/plugins/missing'));
});

t('WpChecksum verifies core files against the official checksums and caches them', function () {
    $root = tmpdir();
    $c = wpSite($root);
    putFile($root, 'wp-includes/a.php', 'A');
    putFile($root, 'wp-includes/bad.php', 'tampered');
    putFile($root, 'wp-includes/extra.php', 'E');
    putFile($root, 'wp-content/themes/x/t.php', 'T');
    $cache = tmpdir();
    $http = new FakeHttp();
    coreRoute($http, ['wp-includes/a.php' => 'A', 'wp-includes/bad.php' => 'original']);
    $wp = new WpChecksum($http, $c, $cache);
    assertSame(WpChecksum::VERIFIED, $wp->verify('wp-includes/a.php'));
    assertSame(WpChecksum::MISMATCH, $wp->verify('wp-includes/bad.php'));
    assertSame(WpChecksum::EXTRA, $wp->verify('wp-includes/extra.php'));
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-content/themes/x/t.php'));
    assertTrue($wp->isCorePath('wp-includes/a.php'));
    assertTrue(!$wp->isCorePath('wp-content/themes/x/t.php'));
    assertSame(1, count($http->calls), 'core map fetched once');
    assertSame([], $wp->notes());

    $offline = new FakeHttp();
    $again = new WpChecksum($offline, $c, $cache);
    assertSame(WpChecksum::VERIFIED, $again->verify('wp-includes/a.php'));
    assertSame(0, count($offline->calls), 'second run uses the disk cache');
});

t('WpChecksum never claims match or mismatch when wordpress.org is unreachable (Review Focus 4)', function () {
    $root = tmpdir();
    $c = wpSite($root);
    putFile($root, 'wp-includes/a.php', 'A');
    putFile($root, 'wp-content/plugins/foo/foo.php', pluginHeader('1.0'));
    $http = new FakeHttp(); // no routes: every request fails
    $wp = new WpChecksum($http, $c, tmpdir());
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-includes/a.php'));
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-content/plugins/foo/foo.php'));
    assertTrue(count($wp->notes()) >= 2, 'expected notes, got ' . json_encode($wp->notes()));
    assertContains('unavailable', implode(' ', $wp->notes()));
    assertTrue($wp->isCorePath('wp-includes/anything.php'), 'falls back to the directory prefix');
    // Each lookup is attempted once per run, not once per file.
    $before = count($http->calls);
    $wp->verify('wp-includes/b.php');
    $wp->verify('wp-content/plugins/foo/other.php');
    assertSame($before, count($http->calls));
});

t('WpChecksum verifies repository plugins and stays silent for premium ones', function () {
    $root = tmpdir();
    $c = wpSite($root);
    putFile($root, 'wp-content/plugins/foo/foo.php', pluginHeader('1.0'));
    putFile($root, 'wp-content/plugins/foo/inc/x.php', 'X');
    putFile($root, 'wp-content/plugins/foo/inc/y.php', 'Y-tampered');
    putFile($root, 'wp-content/plugins/foo/inc/new.php', 'N');
    putFile($root, 'wp-content/plugins/premium/premium.php', pluginHeader('3.1'));
    putFile($root, 'wp-content/plugins/noheader/a.php', '<?php');
    putFile($root, 'wp-content/plugins/we ird/b.php', pluginHeader('1'));
    $http = new FakeHttp();
    coreRoute($http, ['index.php' => 'x']);
    $http->route('https://downloads.wordpress.org/plugin-checksums/foo/1.0.json', 200, json_encode([
        'plugin' => 'foo', 'version' => '1.0',
        'sha256' => ['inc/x.php' => [hash('sha256', 'X')], 'inc/y.php' => hash('sha256', 'Y')],
        'md5' => ['foo.php' => [md5(pluginHeader('1.0'))]],
    ]));
    $http->route('https://downloads.wordpress.org/plugin-checksums/premium/', 404, '{"error":"not found"}');
    $wp = new WpChecksum($http, $c, tmpdir());
    assertSame(WpChecksum::VERIFIED, $wp->verify('wp-content/plugins/foo/inc/x.php'));
    assertSame(WpChecksum::MISMATCH, $wp->verify('wp-content/plugins/foo/inc/y.php'));
    assertSame(WpChecksum::VERIFIED, $wp->verify('wp-content/plugins/foo/foo.php'));
    assertSame(WpChecksum::EXTRA, $wp->verify('wp-content/plugins/foo/inc/new.php'));
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-content/plugins/premium/premium.php'));
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-content/plugins/noheader/a.php'));
    $calls = count($http->calls);
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-content/plugins/we ird/b.php'));
    assertSame($calls, count($http->calls), 'unsafe slugs are never sent to the API');
    assertSame([], $wp->notes(), 'a 404 means "not in the repository" and is not a problem');
});

t('WpChecksum reports a missing WordPress version as a note', function () {
    $root = tmpdir();
    putFile($root, 'wp-config.php', '<?php');
    $c = makeConfig($root, ['profile' => 'wordpress']);
    $wp = new WpChecksum(new FakeHttp(), $c, tmpdir());
    assertSame(WpChecksum::UNKNOWN, $wp->verify('wp-includes/a.php'));
    assertContains('version', implode(' ', $wp->notes()));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php Wp`
Expected: `Class "Sentinel\VersionTracker" not found`.

- [ ] **Step 3: Implement the version tracker**

```php file=src/VersionTracker.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class VersionTracker
{
    /** @return array<string,string> group directory => version */
    public static function read(Config $c): array
    {
        $out = [];
        foreach (['wp-content/plugins', 'wp-content/themes'] as $dir) {
            $names = @scandir($c->abs($dir), SCANDIR_SORT_NONE);
            if ($names === false) {
                continue;
            }
            sort($names, SORT_STRING);
            foreach ($names as $n) {
                if ($n === '' || $n[0] === '.') {
                    continue;
                }
                $v = self::dirVersion($c, $dir . '/' . $n);
                if ($v !== null) {
                    $out[$dir . '/' . $n] = $v;
                }
            }
        }
        return $out;
    }

    public static function dirVersion(Config $c, string $relDir): ?string
    {
        $abs = $c->abs($relDir);
        if (!is_dir($abs)) {
            return null;
        }
        if (strpos($relDir, 'wp-content/themes/') === 0) {
            return self::header($abs . '/style.css', false);
        }
        $names = @scandir($abs, SCANDIR_SORT_NONE);
        if ($names === false) {
            return null;
        }
        sort($names, SORT_STRING);
        foreach ($names as $f) {
            if (substr($f, -4) !== '.php') {
                continue;
            }
            $v = self::header($abs . '/' . $f, true);
            if ($v !== null) {
                return $v;
            }
        }
        return null;
    }

    private static function header(string $file, bool $needPluginName): ?string
    {
        $fh = @fopen($file, 'rb');
        if ($fh === false) {
            return null;
        }
        $head = (string)fread($fh, 8192);
        fclose($fh);
        if ($needPluginName && !preg_match('/^[ \t\/*#@]*Plugin Name:/mi', $head)) {
            return null;
        }
        if (!preg_match('/^[ \t\/*#@]*Version:[ \t]*(.+)$/mi', $head, $m)) {
            return null;
        }
        $v = trim((string)preg_replace('/\s*\*\/.*$/', '', $m[1]));
        return $v === '' ? null : $v;
    }
}
```

- [ ] **Step 4: Implement the checksum verifier**

```php file=src/WpChecksum.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class WpChecksum
{
    public const VERIFIED = 'match';
    public const MISMATCH = 'mismatch';
    public const EXTRA = 'extra';
    public const UNKNOWN = 'unknown';

    private $http;
    private $config;
    private $cacheDir;
    /** @var array<string,string> */
    private $notes = [];
    private $coreLoaded = false;
    /** @var array<string,string>|null */
    private $core = null;
    /** @var array<string,?array> */
    private $plugins = [];

    public function __construct(HttpClient $http, Config $config, string $cacheDir)
    {
        $this->http = $http;
        $this->config = $config;
        $this->cacheDir = rtrim($cacheDir, '/');
    }

    /** @return string[] */
    public function notes(): array
    {
        return array_values($this->notes);
    }

    public function isCorePath(string $rel): bool
    {
        $core = $this->coreMap();
        if ($core !== null) {
            return isset($core[$rel]);
        }
        return strpos($rel, 'wp-admin/') === 0 || strpos($rel, 'wp-includes/') === 0;
    }

    public function verify(string $rel): string
    {
        $abs = $this->config->abs($rel);
        $core = $this->coreMap();
        if ($core !== null && isset($core[$rel])) {
            $md5 = @md5_file($abs);
            if ($md5 === false) {
                return self::UNKNOWN;
            }
            return $md5 === $core[$rel] ? self::VERIFIED : self::MISMATCH;
        }
        if (strpos($rel, 'wp-content/plugins/') === 0) {
            return $this->verifyPlugin($rel, $abs);
        }
        if ($core !== null && (strpos($rel, 'wp-admin/') === 0 || strpos($rel, 'wp-includes/') === 0)) {
            return self::EXTRA;
        }
        return self::UNKNOWN;
    }

    private function verifyPlugin(string $rel, string $abs): string
    {
        if (!preg_match('#^wp-content/plugins/([^/]+)/(.+)$#', $rel, $m)) {
            return self::UNKNOWN;
        }
        $slug = $m[1];
        $file = $m[2];
        if (!preg_match('/^[A-Za-z0-9._-]+$/', $slug)) {
            return self::UNKNOWN;
        }
        $version = VersionTracker::dirVersion($this->config, 'wp-content/plugins/' . $slug);
        if ($version === null || !preg_match('/^[A-Za-z0-9._+-]+$/', $version)) {
            return self::UNKNOWN;
        }
        $map = $this->pluginMap($slug, $version);
        if ($map === null) {
            return self::UNKNOWN;
        }
        if (!isset($map[$file])) {
            return self::EXTRA;
        }
        foreach (['sha256', 'md5'] as $algo) {
            if (isset($map[$file][$algo])) {
                $h = @hash_file($algo, $abs);
                if ($h === false) {
                    return self::UNKNOWN;
                }
                return in_array($h, $map[$file][$algo], true) ? self::VERIFIED : self::MISMATCH;
            }
        }
        return self::UNKNOWN;
    }

    /** @return array<string,string>|null */
    private function coreMap(): ?array
    {
        if ($this->coreLoaded) {
            return $this->core;
        }
        $this->coreLoaded = true;
        $info = $this->wpVersion();
        if ($info === null) {
            $this->note('WordPress version could not be read; core checksum verification skipped');
            return null;
        }
        [$ver, $locale] = $info;
        $cache = $this->cacheFile('wp-core-' . $ver . '-' . $locale . '.json');
        $map = $this->readCache($cache);
        if ($map === null) {
            $r = $this->http->request('GET', 'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode($ver) . '&locale=' . rawurlencode($locale));
            if ($r['status'] !== 200) {
                $this->note('WordPress core checksums unavailable (' . $this->why($r['status']) . '); core verification skipped');
                return null;
            }
            $j = json_decode($r['body'], true);
            if (!is_array($j) || !isset($j['checksums']) || !is_array($j['checksums'])) {
                $this->note("No official checksums published for WordPress $ver ($locale); core verification skipped");
                return null;
            }
            $map = [];
            foreach ($j['checksums'] as $f => $h) {
                if (is_string($h)) {
                    $map[(string)$f] = strtolower($h);
                }
            }
            $this->writeCache($cache, $map);
        }
        $this->core = $map;
        return $map;
    }

    /** @return array<string,array<string,string[]>>|null file => algo => accepted hashes */
    private function pluginMap(string $slug, string $version): ?array
    {
        $key = $slug . '@' . $version;
        if (array_key_exists($key, $this->plugins)) {
            return $this->plugins[$key];
        }
        $this->plugins[$key] = null;
        $cache = $this->cacheFile('wp-plugin-' . $slug . '-' . $version . '.json');
        $map = $this->readCache($cache);
        if ($map === null) {
            $r = $this->http->request('GET', 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode($slug) . '/' . rawurlencode($version) . '.json');
            if ($r['status'] === 404) {
                return null; // not in the repository: premium or custom plugin
            }
            if ($r['status'] !== 200) {
                $this->note("Checksums for plugin '$slug' unavailable (" . $this->why($r['status']) . '); verification skipped');
                return null;
            }
            $j = json_decode($r['body'], true);
            $map = [];
            if (is_array($j)) {
                foreach (['sha256', 'md5'] as $algo) {
                    if (isset($j[$algo]) && is_array($j[$algo])) {
                        foreach ($j[$algo] as $file => $hashes) {
                            $map[(string)$file][$algo] = array_values(array_map('strtolower', array_map('strval', (array)$hashes)));
                        }
                    }
                }
            }
            if (!$map) {
                return null;
            }
            $this->writeCache($cache, $map);
        }
        $this->plugins[$key] = $map;
        return $map;
    }

    /** @return array{0:string,1:string}|null */
    private function wpVersion(): ?array
    {
        $src = @file_get_contents($this->config->abs('wp-includes/version.php'));
        if ($src === false || !preg_match('/\$wp_version\s*=\s*\'([^\']+)\'/', $src, $m) || !preg_match('/^[A-Za-z0-9.\-]+$/', $m[1])) {
            return null;
        }
        $locale = 'en_US';
        if (preg_match('/\$wp_local_package\s*=\s*\'([A-Za-z_]+)\'/', $src, $l)) {
            $locale = $l[1];
        }
        return [$m[1], $locale];
    }

    private function why(int $status): string
    {
        return $status === 0 ? 'network error' : 'HTTP ' . $status;
    }

    private function note(string $msg): void
    {
        $this->notes[$msg] = $msg;
    }

    private function cacheFile(string $name): string
    {
        return $this->cacheDir . '/' . preg_replace('/[^A-Za-z0-9._@-]/', '_', $name);
    }

    private function readCache(string $file): ?array
    {
        $j = is_file($file) ? json_decode((string)file_get_contents($file), true) : null;
        return is_array($j) && $j ? $j : null;
    }

    private function writeCache(string $file, array $map): void
    {
        if (!is_dir($this->cacheDir)) {
            @mkdir($this->cacheDir, 0700, true);
        }
        @file_put_contents($file, json_encode($map), LOCK_EX);
    }
}
```

- [ ] **Step 5: Register and run**

Edit `build/files.php`: add `'VersionTracker.php', 'WpChecksum.php',`.

Run: `php tests/run.php Wp && php tests/run.php VersionTracker`
Expected: all `ok`.

- [ ] **Step 6: Commit**

```bash
git add src/VersionTracker.php src/WpChecksum.php build/files.php tests/test_wp.php
git commit -m "feat: WordPress version tracking and official checksum verification"
```

---

### Task 10: Process runner and optional external scanners

**Files:**
- Create: `src/Proc.php`, `src/ExternalScanner.php`
- Test: `tests/test_external.php`, `tests/helpers_tools.php` (shared `fakeTool(string $dir, string $name, string $shellScript): string`, which writes an executable `#!/bin/sh` script)
- Modify: `build/files.php` (add `'Proc.php', 'ExternalScanner.php',` after `'WpChecksum.php',`)

**Interfaces:**
- Consumes: `Config` (`clamscanPath`, `yaraPath`, `yaraRules`), `Finding`.
- Produces: `Proc::run(array $cmd, int $timeoutSeconds): array` with keys `exit` (int, -1 if it could not start or was killed), `out`, `err`, `timed_out` (bool). The command is an argument array (no shell); stdin is `/dev/null`.
- Produces: `ExternalScanner::__construct(?string $clamscan, ?string $yara, ?string $yaraRules)`; `static fromConfig(Config $c)` (explicit path from config, else first match on `PATH`; YARA is enabled only when a rules file exists); `static find(string $bin): ?string`; `enabled(): bool`; `scan(array $files): Finding[]` where `$files` is `rel => abs`; `errors(): string[]` (tool failures and timeouts from the last `scan`). Hits are Critical findings with rule `clamav:<Signature>` or `yara:<Rule>` and `path` = the relative path. ClamAV runs once per 100 files (exit 0 clean, 1 infected, else error); YARA runs per file, at most 200 files per scan. A tool that fails produces an error entry, never a finding.

- [ ] **Step 1: Write the failing tests**

```php file=tests/helpers_tools.php
<?php
declare(strict_types=1);

/** Writes an executable /bin/sh script named $name into $dir and returns its path. */
function fakeTool(string $dir, string $name, string $script): string
{
    $p = $dir . '/' . $name;
    file_put_contents($p, "#!/bin/sh\n" . $script);
    chmod($p, 0755);
    return $p;
}
```

```php file=tests/test_external.php
<?php
declare(strict_types=1);

use Sentinel\ExternalScanner;
use Sentinel\Finding;
use Sentinel\Proc;

t('Proc::run captures output, exit code and stderr', function () {
    $r = Proc::run(['/bin/sh', '-c', 'echo out; echo err >&2; exit 3'], 5);
    assertSame(3, $r['exit']);
    assertSame("out\n", $r['out']);
    assertSame("err\n", $r['err']);
    assertSame(false, $r['timed_out']);
    assertSame(-1, Proc::run(['/nonexistent/binary'], 5)['exit']);
});

t('Proc::run kills a command that exceeds the timeout', function () {
    $start = microtime(true);
    $r = Proc::run(['/bin/sleep', '10'], 1);
    assertTrue($r['timed_out']);
    assertTrue(microtime(true) - $start < 5, 'did not wait for the full sleep');
});

t('ExternalScanner reports ClamAV hits as Critical findings', function () {
    $dir = tmpdir();
    $clam = fakeTool($dir, 'clamscan', 'rc=0
for f in "$@"; do
  case "$f" in -*) continue;; esac
  if grep -q EICAR "$f"; then echo "$f: Fake.Eicar FOUND"; rc=1; fi
done
exit $rc
');
    $bad = putFile($dir, 'bad.php', 'x EICAR x');
    $good = putFile($dir, 'good.php', 'fine');
    $s = new ExternalScanner($clam, null, null);
    assertTrue($s->enabled());
    $f = $s->scan(['sub/bad.php' => $bad, 'good.php' => $good, '123' => $good]);
    assertSame(1, count($f));
    assertSame('sub/bad.php', $f[0]->path);
    assertSame('clamav:Fake.Eicar', $f[0]->rule);
    assertSame(Finding::CRITICAL, $f[0]->severity);
    assertSame([], $s->errors());
});

t('ExternalScanner reports YARA hits and skips YARA when no rules file exists', function () {
    $dir = tmpdir();
    $yara = fakeTool($dir, 'yara', 'if grep -q YARAHIT "$2"; then echo "RuleX $2"; fi
exit 0
');
    file_put_contents($dir . '/rules.yar', 'rule RuleX { condition: false }');
    $hit = putFile($dir, 'hit.php', 'YARAHIT');
    $miss = putFile($dir, 'miss.php', 'nothing');
    $s = new ExternalScanner(null, $yara, $dir . '/rules.yar');
    $f = $s->scan(['hit.php' => $hit, 'miss.php' => $miss]);
    assertSame(['yara:RuleX'], array_map(function ($x) { return $x->rule; }, $f));
    assertSame('hit.php', $f[0]->path);

    $cfg = makeConfig(tmpdir(), ['yara_path' => $yara, 'yara_rules' => $dir . '/missing.yar']);
    assertTrue(!ExternalScanner::fromConfig($cfg)->enabled());
    $cfg2 = makeConfig(tmpdir(), ['yara_path' => $yara, 'yara_rules' => $dir . '/rules.yar']);
    assertTrue(ExternalScanner::fromConfig($cfg2)->enabled());
});

t('ExternalScanner records tool failures as errors, not findings', function () {
    $dir = tmpdir();
    $clam = fakeTool($dir, 'clamscan', 'echo "ERROR: cannot load database" >&2
exit 2
');
    $f = putFile($dir, 'a.php', 'x');
    $s = new ExternalScanner($clam, null, null);
    assertSame([], $s->scan(['a.php' => $f]));
    assertTrue(count($s->errors()) === 1);
    assertContains('clamscan', $s->errors()[0]);
    assertSame([], (new ExternalScanner(null, null, null))->scan(['a.php' => $f]));
});

t('ExternalScanner::find locates executables on PATH', function () {
    assertSame('/bin/sh', realpath((string)ExternalScanner::find('sh')) === realpath('/bin/sh') ? '/bin/sh' : 'other');
    assertSame(null, ExternalScanner::find('definitely-not-a-real-binary-xyz'));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php External`
Expected: `Class "Sentinel\Proc" not found`.

- [ ] **Step 3: Implement**

```php file=src/Proc.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Proc
{
    /**
     * Runs a command (argument array, no shell) with a timeout.
     *
     * @return array{exit:int, out:string, err:string, timed_out:bool}
     */
    public static function run(array $cmd, int $timeout): array
    {
        $spec = [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $p = @proc_open($cmd, $spec, $pipes);
        if (!is_resource($p)) {
            return ['exit' => -1, 'out' => '', 'err' => 'cannot start ' . (string)($cmd[0] ?? ''), 'timed_out' => false];
        }
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);
        $out = '';
        $err = '';
        $exit = -1;
        $timedOut = false;
        $start = microtime(true);
        while (true) {
            $out .= (string)stream_get_contents($pipes[1]);
            $err .= (string)stream_get_contents($pipes[2]);
            $st = proc_get_status($p);
            if (!$st['running']) {
                $exit = (int)$st['exitcode'];
                break;
            }
            if (microtime(true) - $start > $timeout) {
                proc_terminate($p, 9);
                $timedOut = true;
                break;
            }
            usleep(20000);
        }
        $out .= (string)stream_get_contents($pipes[1]);
        $err .= (string)stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($p);
        return ['exit' => $exit, 'out' => $out, 'err' => $err, 'timed_out' => $timedOut];
    }
}
```

```php file=src/ExternalScanner.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class ExternalScanner
{
    private const CLAM_CHUNK = 100;
    private const YARA_MAX_FILES = 200;

    private $clamscan;
    private $yara;
    private $yaraRules;
    /** @var string[] */
    private $errors = [];

    public function __construct(?string $clamscan, ?string $yara, ?string $yaraRules)
    {
        $this->clamscan = $clamscan;
        $this->yara = $yara !== null && $yaraRules !== null && $yaraRules !== '' ? $yara : null;
        $this->yaraRules = $yaraRules;
    }

    public static function fromConfig(Config $c): ExternalScanner
    {
        $clam = $c->clamscanPath !== '' ? $c->clamscanPath : self::find('clamscan');
        $yara = $c->yaraPath !== '' ? $c->yaraPath : self::find('yara');
        if ($clam !== null && !is_executable($clam)) {
            $clam = null;
        }
        if ($yara !== null && (!is_executable($yara) || $c->yaraRules === '' || !is_file($c->yaraRules))) {
            $yara = null;
        }
        return new ExternalScanner($clam, $yara, $c->yaraRules);
    }

    public static function find(string $bin): ?string
    {
        foreach (explode(PATH_SEPARATOR, (string)getenv('PATH')) as $dir) {
            $p = rtrim($dir, '/') . '/' . $bin;
            if ($dir !== '' && is_file($p) && is_executable($p)) {
                return $p;
            }
        }
        return null;
    }

    public function enabled(): bool
    {
        return $this->clamscan !== null || $this->yara !== null;
    }

    /** @return string[] */
    public function errors(): array
    {
        return $this->errors;
    }

    /**
     * @param array<int|string,string> $files rel => abs
     * @return Finding[]
     */
    public function scan(array $files): array
    {
        $this->errors = [];
        if (!$files || !$this->enabled()) {
            return [];
        }
        $byAbs = [];
        foreach ($files as $rel => $abs) {
            $byAbs[$abs] = (string)$rel;
        }
        $out = [];
        if ($this->clamscan !== null) {
            foreach (array_chunk(array_keys($byAbs), self::CLAM_CHUNK) as $chunk) {
                $r = Proc::run(array_merge([$this->clamscan, '--no-summary', '--infected', '--'], $chunk), 300);
                if ($r['timed_out'] || ($r['exit'] !== 0 && $r['exit'] !== 1)) {
                    $this->errors[] = 'clamscan failed (' . ($r['timed_out'] ? 'timed out' : 'exit ' . $r['exit']) . '): ' . $this->firstLine($r['err']);
                    continue;
                }
                foreach (explode("\n", $r['out']) as $line) {
                    if (preg_match('/^(.*): (.+) FOUND$/', $line, $m) && isset($byAbs[$m[1]])) {
                        $out[] = new Finding(Finding::CRITICAL, $byAbs[$m[1]], 'clamav:' . $m[2], 'ClamAV signature match: ' . $m[2]);
                    }
                }
            }
        }
        if ($this->yara !== null) {
            $n = 0;
            foreach ($byAbs as $abs => $rel) {
                if (++$n > self::YARA_MAX_FILES) {
                    $this->errors[] = 'yara skipped ' . (count($byAbs) - self::YARA_MAX_FILES) . ' file(s): per-run limit reached';
                    break;
                }
                $r = Proc::run([$this->yara, (string)$this->yaraRules, (string)$abs], 30);
                if ($r['timed_out'] || $r['exit'] !== 0) {
                    $this->errors[] = 'yara failed on ' . $rel . ' (' . ($r['timed_out'] ? 'timed out' : 'exit ' . $r['exit']) . '): ' . $this->firstLine($r['err']);
                    continue;
                }
                foreach (explode("\n", $r['out']) as $line) {
                    if (preg_match('/^(\S+)\s+(.+)$/', $line, $m)) {
                        $out[] = new Finding(Finding::CRITICAL, $rel, 'yara:' . $m[1], 'YARA rule match: ' . $m[1]);
                    }
                }
            }
        }
        return $out;
    }

    private function firstLine(string $s): string
    {
        $s = trim($s);
        $p = strpos($s, "\n");
        return $p === false ? $s : substr($s, 0, $p);
    }
}
```

- [ ] **Step 4: Register and run**

Edit `build/files.php`: add `'Proc.php', 'ExternalScanner.php',`.

Run: `php tests/run.php External && php tests/run.php Proc`
Expected: all `ok`.

- [ ] **Step 5: Commit**

```bash
git add src/Proc.php src/ExternalScanner.php build/files.php tests/test_external.php
git commit -m "feat: process runner and optional ClamAV/YARA scanners"
```

---

### Task 11: Analyzer

**Files:**
- Create: `src/Analyzer.php`
- Test: `tests/test_analyzer.php`
- Modify: `build/files.php` (add `'Analyzer.php',` after `'ExternalScanner.php',`)

**Interfaces:**
- Consumes: changes from `Differ::diff`; `Config`, `PatternScanner`, `LocationScanner`, `?WpChecksum`, `ExternalScanner`, `Finding`, `PathFilter`.
- Produces: `Analyzer::__construct(Config $c, PatternScanner $p, LocationScanner $l, ?WpChecksum $wp, ExternalScanner $x)`.
- Produces: `analyze(array $changes, array $oldVersions, array $newVersions, bool $initial = false): array` returning `['findings'=>Finding[], 'info'=>string[], 'hold'=>array<path,true>, 'held_groups'=>array<group,true>, 'notes'=>string[]]`. `$oldVersions`/`$newVersions` are `VersionTracker::read` maps (stored vs current). `hold` lists paths whose baseline update must be withheld. In `$initial` mode only Critical findings are returned, and `hold`/`info` are empty (first-time baseline: unknown code is accepted, only clear malware blocks).
- Produces: `Analyzer::groupOf(string $rel): string` (`wp-content/plugins/<slug>` or `wp-content/themes/<slug>` for those paths, else the first path segment, or `.` for a root file); `wantsAnalysis(array $record): bool` (symlink, code file, uploads file or executable bit — used by `init` to skip stat-only files).
- Decision table per new/modified file (first match wins): symlink → Warning `symlink`; unreadable → Warning `unreadable`; official WordPress checksum `VERIFIED` → accepted silently (counted in Info) and any scanner hits are discarded; otherwise scanner hits + `checksum-mismatch` (Critical) / `unexpected-file` (Warning) + `stealth-modification` (Critical) → findings, held; touch-only (`content_same`) → accepted silently unless it became world-writable (Warning `world-writable`, held); sensitive path (profile `sensitive` globs) → Warning `sensitive-file-changed`, held; non-code file → accepted silently; code file → queued for external scanners and grouped. After external scanning, each group is explained (Info "<group> updated A -> B (N file(s))") only if both stored and current versions exist and differ; otherwise one Warning `unexplained-change` per group, files held. Removed: core file → Warning `core-file-removed` (held); sensitive → Warning `sensitive-file-removed` (held); anything else is counted in Info.

- [ ] **Step 1: Write the failing tests**

```php file=tests/test_analyzer.php
<?php
declare(strict_types=1);

use Sentinel\Analyzer;
use Sentinel\Config;
use Sentinel\ExternalScanner;
use Sentinel\Finding;
use Sentinel\LocationScanner;
use Sentinel\PatternScanner;
use Sentinel\Rules;
use Sentinel\VersionTracker;
use Sentinel\WpChecksum;

function analyzerFor(Config $c, ?WpChecksum $wp = null, ?ExternalScanner $x = null): Analyzer
{
    return new Analyzer($c, new PatternScanner(Rules::builtin(), 1048576), new LocationScanner($c), $wp, $x ?? new ExternalScanner(null, null, null));
}

/** Creates a WordPress site, snapshots it, and returns [root, config, baselineFile]. */
function wpFixture(array $files = []): array
{
    $root = tmpdir();
    putFile($root, 'wp-config.php', '<?php // config');
    putFile($root, 'wp-includes/version.php', "<?php\n\$wp_version = '6.4.2';\n");
    putFile($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n// v1\n");
    putFile($root, 'wp-content/uploads/pic.jpg', 'GIF89a');
    foreach ($files as $rel => $content) {
        putFile($root, $rel, $content);
    }
    $c = makeConfig($root, ['profile' => 'wordpress']);
    $b = tmpdir() . '/b.txt';
    snapshot($c, $b);
    return [$root, $c, $b];
}

function runAnalysis(Config $c, string $b, ?Analyzer $a = null, array $old = [], bool $initial = false, bool $full = false): array
{
    $changes = array_values(diffByPath($c, $b, $full));
    $new = VersionTracker::read($c);
    return ($a ?? analyzerFor($c))->analyze($changes, $old, $new, $initial);
}

function ruleList(array $r): array
{
    $out = array_map(function (Finding $f) { return $f->rule . '@' . $f->path; }, $r['findings']);
    sort($out);
    return $out;
}

t('Analyzer: PHP in uploads is Critical and held, a benign new image passes', function () {
    [$root, $c, $b] = wpFixture();
    putFile($root, 'wp-content/uploads/x.php', '<?php echo 1;');
    putFile($root, 'wp-content/uploads/new.jpg', 'GIF89a');
    $r = runAnalysis($c, $b);
    assertSame(['php-in-uploads@wp-content/uploads/x.php'], ruleList($r));
    assertSame(Finding::CRITICAL, $r['findings'][0]->severity);
    assertSame(['wp-content/uploads/x.php' => true], $r['hold']);
});

t('Analyzer: scanner hits in a plugin are Critical, held, and not double-reported as unexplained', function () {
    [$root, $c, $b] = wpFixture();
    $old = VersionTracker::read($c);
    putFile($root, 'wp-content/plugins/foo/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $r = runAnalysis($c, $b, null, $old);
    assertSame(['test-marker@wp-content/plugins/foo/evil.php'], ruleList($r));
    assertTrue(isset($r['hold']['wp-content/plugins/foo/evil.php']));
    assertTrue(isset($r['held_groups']['wp-content/plugins/foo']));
});

t('Analyzer: a plugin update with a version bump is explained, without one it is a Warning', function () {
    [$root, $c, $b] = wpFixture();
    $old = VersionTracker::read($c);
    assertSame(['wp-content/plugins/foo' => '1.0'], $old);

    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// v2\n");
    $r = runAnalysis($c, $b, null, $old);
    assertSame([], ruleList($r));
    assertSame([], $r['hold']);
    assertContains('wp-content/plugins/foo updated 1.0 -> 1.1', implode("\n", $r['info']));

    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n// quietly edited\n");
    $r2 = runAnalysis($c, $b, null, $old);
    assertSame(['unexplained-change@wp-content/plugins/foo'], ruleList($r2));
    assertSame(Finding::WARNING, $r2['findings'][0]->severity);
    assertTrue(isset($r2['hold']['wp-content/plugins/foo/foo.php']));
});

t('Analyzer: a brand-new plugin directory is a Warning and many files make one finding', function () {
    [$root, $c, $b] = wpFixture();
    $old = VersionTracker::read($c);
    putFile($root, 'wp-content/plugins/bar/bar.php', "<?php\n/*\nPlugin Name: Bar\nVersion: 2.0\n*/\n");
    for ($i = 0; $i < 8; $i++) {
        putFile($root, "wp-content/plugins/bar/inc/f$i.php", '<?php // ' . $i);
    }
    $r = runAnalysis($c, $b, null, $old);
    assertSame(['unexplained-change@wp-content/plugins/bar'], ruleList($r));
    assertContains('9 file(s)', $r['findings'][0]->message);
    assertContains('more', $r['findings'][0]->message);
});

t('Analyzer: official checksum match is accepted silently and beats pattern hits; mismatch and extras are flagged', function () {
    [$root, $c, $b] = wpFixture();
    $marker = '<?php // SENTINEL-TEST-MALWARE-MARKER';
    bump($root, 'wp-includes/ok.php', 'official');
    bump($root, 'wp-includes/odd.php', $marker);
    bump($root, 'wp-includes/tampered.php', 'tampered');
    bump($root, 'wp-includes/extra.php', 'extra');
    $http = new FakeHttp();
    coreRoute($http, ['wp-includes/ok.php' => 'official', 'wp-includes/odd.php' => $marker, 'wp-includes/tampered.php' => 'original']);
    $wp = new WpChecksum($http, $c, tmpdir());
    $r = runAnalysis($c, $b, analyzerFor($c, $wp));
    assertSame(['checksum-mismatch@wp-includes/tampered.php', 'unexpected-file@wp-includes/extra.php'], ruleList($r));
    assertContains('2 file(s) verified', implode("\n", $r['info']));
    $sev = [];
    foreach ($r['findings'] as $f) {
        $sev[$f->rule] = $f->severity;
    }
    ksort($sev);
    assertSame(['checksum-mismatch' => Finding::CRITICAL, 'unexpected-file' => Finding::WARNING], $sev);
});

t('Analyzer: stealth modification is Critical', function () {
    [$root, $c, $b] = wpFixture(['lib/a.php' => 'AAAA']);
    $m = filemtime($root . '/lib/a.php');
    file_put_contents($root . '/lib/a.php', 'BBBB');
    touch($root . '/lib/a.php', $m);
    clearstatcache();
    $r = runAnalysis($c, $b, null, [], false, true);
    assertSame(['stealth-modification@lib/a.php'], ruleList($r));
    assertSame(Finding::CRITICAL, $r['findings'][0]->severity);
});

t('Analyzer: initial mode keeps only Critical findings and holds nothing', function () {
    [$root, $c, $b] = wpFixture();
    $old = VersionTracker::read($c);
    putFile($root, 'wp-content/plugins/bar/bar.php', "<?php\n/*\nPlugin Name: Bar\nVersion: 2.0\n*/\n");
    putFile($root, 'wp-content/uploads/x.php', '<?php');
    $r = runAnalysis($c, $b, null, $old, true);
    assertSame(['php-in-uploads@wp-content/uploads/x.php'], ruleList($r));
    assertSame([], $r['hold']);
    assertSame([], $r['info']);
});

t('Analyzer: symlinks, sensitive files and world-writable changes are Warnings', function () {
    [$root, $c, $b] = wpFixture();
    symlink('/etc', $root . '/wp-content/etc-link');
    bump($root, 'wp-config.php', '<?php // edited');
    chmod($root . '/wp-content/plugins/foo/foo.php', 0666);
    $r = runAnalysis($c, $b, null, VersionTracker::read($c));
    assertSame(['sensitive-file-changed@wp-config.php', 'symlink@wp-content/etc-link', 'world-writable@wp-content/plugins/foo/foo.php'], ruleList($r));
    foreach ($r['findings'] as $f) {
        assertSame(Finding::WARNING, $f->severity);
    }
});

t('Analyzer: a touch-only change is silent', function () {
    [$root, $c, $b] = wpFixture();
    touch($root . '/wp-config.php', time() + 900);
    touch($root . '/wp-content/plugins/foo/foo.php', time() + 900);
    $r = runAnalysis($c, $b, null, VersionTracker::read($c));
    assertSame([], ruleList($r));
    assertSame([], $r['hold']);
});

t('Analyzer: removed core and sensitive files are Warnings, other removals are counted', function () {
    [$root, $c, $b] = wpFixture(['wp-includes/a.php' => 'A', 'notes.txt' => 'n']);
    $http = new FakeHttp();
    coreRoute($http, ['wp-includes/a.php' => 'A']);
    $wp = new WpChecksum($http, $c, tmpdir());
    unlink($root . '/wp-includes/a.php');
    unlink($root . '/wp-config.php');
    unlink($root . '/notes.txt');
    $r = runAnalysis($c, $b, analyzerFor($c, $wp));
    assertSame(['core-file-removed@wp-includes/a.php', 'sensitive-file-removed@wp-config.php'], ruleList($r));
    assertContains('1 file(s) removed', implode("\n", $r['info']));
    assertSame(2, count($r['hold']));
});

t('Analyzer: external scanner hits are Critical, held, and leave their group', function () {
    [$root, $c, $b] = wpFixture(['lib/clean.php' => 'ok']);
    $clam = fakeTool(tmpdir(), 'clamscan', 'rc=0
for f in "$@"; do
  case "$f" in -*) continue;; esac
  if grep -q EICAR "$f"; then echo "$f: Fake.Eicar FOUND"; rc=1; fi
done
exit $rc
');
    bump($root, 'lib/clean.php', 'still ok');
    putFile($root, 'lib/x.php', 'EICAR');
    $r = runAnalysis($c, $b, analyzerFor($c, null, new ExternalScanner($clam, null, null)));
    assertSame(['clamav:Fake.Eicar@lib/x.php', 'unexplained-change@lib'], ruleList($r));
    assertContains('1 file(s)', array_values(array_filter($r['findings'], function ($f) { return $f->rule === 'unexplained-change'; }))[0]->message);
});

t('Analyzer: unreadable files and initial-scan wants', function () {
    [$root, $c, $b] = wpFixture();
    $a = analyzerFor($c);
    assertTrue($a->wantsAnalysis(['path' => 'x.php', 'mode' => 0100644]));
    assertTrue($a->wantsAnalysis(['path' => 'wp-content/uploads/a.jpg', 'mode' => 0100644]));
    assertTrue($a->wantsAnalysis(['path' => 'x.txt', 'mode' => 0100755]));
    assertTrue($a->wantsAnalysis(['path' => 'x.txt', 'mode' => 0120777]));
    assertTrue(!$a->wantsAnalysis(['path' => 'readme.txt', 'mode' => 0100644]));
    assertSame('wp-content/plugins/foo', Analyzer::groupOf('wp-content/plugins/foo/inc/a.php'));
    assertSame('wp-content/themes/t', Analyzer::groupOf('wp-content/themes/t/style.css'));
    assertSame('wp-includes', Analyzer::groupOf('wp-includes/a.php'));
    assertSame('.', Analyzer::groupOf('index.php'));

    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        skip('root can read everything');
    }
    $f = putFile($root, 'lib/locked.php', '<?php');
    chmod($f, 0000);
    $r = runAnalysis($c, $b);
    chmod($f, 0644);
    assertSame(['unreadable@lib/locked.php'], ruleList($r));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php Analyzer`
Expected: `Class "Sentinel\Analyzer" not found`.

- [ ] **Step 3: Implement**

```php file=src/Analyzer.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Analyzer
{
    private $config;
    private $patterns;
    private $locations;
    private $wp;
    private $external;
    private $sensitive;

    public function __construct(Config $config, PatternScanner $patterns, LocationScanner $locations, ?WpChecksum $wp, ExternalScanner $external)
    {
        $this->config = $config;
        $this->patterns = $patterns;
        $this->locations = $locations;
        $this->wp = $wp;
        $this->external = $external;
        $this->sensitive = new PathFilter($config->sensitive);
    }

    public static function groupOf(string $rel): string
    {
        if (preg_match('#^(wp-content/(?:plugins|themes)/[^/]+)/#', $rel, $m)) {
            return $m[1];
        }
        $p = strpos($rel, '/');
        return $p === false ? '.' : substr($rel, 0, $p);
    }

    /** Whether a record needs scanning at all (everything else is stat-only). */
    public function wantsAnalysis(array $rec): bool
    {
        return ($rec['mode'] & 0170000) === 0120000
            || $this->config->isCodeFile($rec['path'])
            || $this->config->isUploads($rec['path'])
            || ($rec['mode'] & 0111) !== 0;
    }

    /**
     * @param array[] $changes from Differ::diff
     * @param array<string,string> $oldVersions stored plugin/theme versions
     * @param array<string,string> $newVersions versions currently on disk
     * @return array{findings: Finding[], info: string[], hold: array<string,bool>, held_groups: array<string,bool>, notes: string[]}
     */
    public function analyze(array $changes, array $oldVersions, array $newVersions, bool $initial = false): array
    {
        $findings = [];
        $info = [];
        $hold = [];
        $groups = [];
        $queue = [];
        $official = 0;
        $removed = 0;

        foreach ($changes as $c) {
            if ($c['type'] === 'dropped') {
                continue;
            }
            $rel = (string)$c['path'];

            if ($c['type'] === 'removed') {
                $oldHash = (string)($c['old']['hash'] ?? '');
                if ($this->wp !== null && $this->wp->isCorePath($rel)) {
                    $findings[] = new Finding(Finding::WARNING, $rel, 'core-file-removed', 'WordPress core file was removed', $oldHash);
                    $hold[$rel] = true;
                } elseif ($this->sensitive->matches($rel)) {
                    $findings[] = new Finding(Finding::WARNING, $rel, 'sensitive-file-removed', 'Sensitive file was removed', $oldHash);
                    $hold[$rel] = true;
                } else {
                    $removed++;
                }
                continue;
            }

            $rec = $c['new'];
            $isNew = $c['type'] === 'new';
            $hash = (string)$rec['hash'];

            if (($rec['mode'] & 0170000) === 0120000) {
                $findings[] = new Finding(Finding::WARNING, $rel, 'symlink', 'Symbolic link ' . ($isNew ? 'created' : 'changed'));
                $hold[$rel] = true;
                continue;
            }
            if ($c['unreadable']) {
                $findings[] = new Finding(Finding::WARNING, $rel, 'unreadable', 'File could not be read for hashing and scanning');
                $hold[$rel] = true;
                continue;
            }

            $hits = $this->locations->scan($rel, $rec, $isNew);
            if ($this->config->isCodeFile($rel)) {
                $hits = array_merge($hits, $this->patterns->scan($rel, $this->config->abs($rel), $hash));
            }

            $status = ($this->wp !== null && !$this->config->isUploads($rel)) ? $this->wp->verify($rel) : WpChecksum::UNKNOWN;
            if ($status === WpChecksum::VERIFIED) {
                $official++;
                continue;
            }
            if ($status === WpChecksum::MISMATCH) {
                $hits[] = new Finding(Finding::CRITICAL, $rel, 'checksum-mismatch', 'Differs from the official WordPress.org file', $hash);
            } elseif ($status === WpChecksum::EXTRA) {
                $hits[] = new Finding(Finding::WARNING, $rel, 'unexpected-file', 'Not part of the official package for this version', $hash);
            }
            if ($c['stealth']) {
                $hits[] = new Finding(Finding::CRITICAL, $rel, 'stealth-modification', 'Content changed but size and modification time did not', $hash);
            }
            if ($hits) {
                foreach ($hits as $h) {
                    $findings[] = $h;
                }
                $hold[$rel] = true;
                continue;
            }

            if ($c['type'] === 'modified' && $c['content_same']) {
                if (($rec['mode'] & 0002) !== 0 && (((int)($c['old']['mode'] ?? 0)) & 0002) === 0) {
                    $findings[] = new Finding(Finding::WARNING, $rel, 'world-writable', 'File became world-writable', $hash);
                    $hold[$rel] = true;
                }
                continue;
            }
            if ($this->sensitive->matches($rel)) {
                $findings[] = new Finding(Finding::WARNING, $rel, 'sensitive-file-changed', 'Sensitive file was ' . ($isNew ? 'created' : 'modified'), $hash);
                $hold[$rel] = true;
                continue;
            }
            if (!$this->config->isCodeFile($rel)) {
                continue;
            }
            $queue[$rel] = $this->config->abs($rel);
            $groups[self::groupOf($rel)][$rel] = $hash;
        }

        if ($queue) {
            foreach ($this->external->scan($queue) as $f) {
                $findings[] = $f;
                $hold[$f->path] = true;
                foreach (array_keys($groups) as $g) {
                    unset($groups[$g][$f->path]);
                }
            }
        }

        foreach ($groups as $g => $files) {
            $g = (string)$g;
            if (!$files) {
                continue;
            }
            $old = $oldVersions[$g] ?? null;
            $new = $newVersions[$g] ?? null;
            if ($old !== null && $new !== null && $old !== $new) {
                $info[] = sprintf('%s updated %s -> %s (%d file(s))', $g, $old, $new, count($files));
                continue;
            }
            $names = array_map('strval', array_keys($files));
            $sample = implode(', ', array_slice($names, 0, 5)) . (count($names) > 5 ? sprintf(' (+%d more)', count($names) - 5) : '');
            $findings[] = new Finding(
                Finding::WARNING,
                $g,
                'unexplained-change',
                sprintf('%d file(s) changed without a version change: %s', count($names), $sample),
                sha1(implode(',', $names) . '|' . implode(',', array_values($files)))
            );
            foreach ($names as $n) {
                $hold[$n] = true;
            }
        }

        $notes = $this->wp !== null ? $this->wp->notes() : [];
        $notes = array_merge($notes, $this->external->errors());

        if ($initial) {
            $crit = array_values(array_filter($findings, function (Finding $f) {
                return $f->severity >= Finding::CRITICAL;
            }));
            return ['findings' => $crit, 'info' => [], 'hold' => [], 'held_groups' => [], 'notes' => $notes];
        }

        if ($official > 0) {
            $info[] = sprintf('%d file(s) verified against official WordPress.org checksums', $official);
        }
        if ($removed > 0) {
            $info[] = sprintf('%d file(s) removed', $removed);
        }
        $heldGroups = [];
        foreach (array_keys($hold) as $p) {
            $heldGroups[self::groupOf((string)$p)] = true;
        }
        return ['findings' => $findings, 'info' => $info, 'hold' => $hold, 'held_groups' => $heldGroups, 'notes' => $notes];
    }
}
```

- [ ] **Step 4: Register and run**

Edit `build/files.php`: add `'Analyzer.php',`.

Run: `php tests/run.php Analyzer`
Expected: all `ok` (the unreadable assertion is `skip`ped as root).

- [ ] **Step 5: Commit**

```bash
git add src/Analyzer.php build/files.php tests/test_analyzer.php
git commit -m "feat: analyzer classifying changes into findings with update-aware grouping"
```

---
### Task 12: State directory, lock, alert log and self-check

**Files:**
- Create: `src/State.php`, `src/Lock.php`, `src/AlertLog.php`, `src/SelfCheck.php`
- Test: `tests/test_state.php`
- Modify: `build/files.php` (add `'State.php', 'Lock.php', 'AlertLog.php', 'SelfCheck.php',` after `'Analyzer.php',`)

**Interfaces:**
- Consumes: `Finding`.
- Produces: `State::__construct(string $dir)` (creates the directory with mode 0700, throws `\RuntimeException` if it cannot); `dir(): string`; `path(string $name): string`; `readJson(string $name): array` (missing or corrupt file gives `[]`); `writeJson(string $name, array $data): void` (atomic, mode 0600, throws on failure).
- Produces: `Lock::acquire(string $file): ?Lock` (non-blocking exclusive `flock`; `null` if another holder has it); `release(): void`. The lock is tied to the open file, so a crashed run never leaves a stale lock; a leftover file is harmless (Review Focus 5).
- Produces: `AlertLog::__construct(State $s)` (state file `alerts.json`); `due(array $findings, int $now, int $remindSeconds): Finding[]` returns the findings that need an alert now: Warning or Critical findings never alerted successfully (including ones whose earlier send failed), plus Critical findings last alerted at least `$remindSeconds` ago; Info never. `commit(array $current, array $sent, int $now): void` records every current finding as seen, marks the `$sent` ones as alerted, and forgets entries not seen for 7 days. `clear(): void`.
- Produces: `SelfCheck::__construct(State $s, array $files)` where `$files` is `label => absolute path`; `check(): Finding[]` (first ever call records and returns `[]`; afterwards a changed or missing tracked file is a Critical `self-tamper` finding; a file not yet recorded is ignored); `record(): void` stores the current hashes of the files that exist.

- [ ] **Step 1: Write the failing tests**

```php file=tests/test_state.php
<?php
declare(strict_types=1);

use Sentinel\AlertLog;
use Sentinel\Finding;
use Sentinel\Lock;
use Sentinel\SelfCheck;
use Sentinel\State;

t('State creates a private directory and round-trips JSON atomically', function () {
    $dir = tmpdir() . '/nested/state';
    $s = new State($dir);
    assertSame(0700, fileperms($dir) & 0777);
    $s->writeJson('x.json', ['a' => [1, 2], 'b' => 'ü']);
    assertSame(['a' => [1, 2], 'b' => 'ü'], $s->readJson('x.json'));
    assertSame(0600, fileperms($dir . '/x.json') & 0777);
    assertSame(['x.json'], array_values(array_diff(scandir($dir), ['.', '..'])));
    assertSame([], $s->readJson('missing.json'));
    file_put_contents($dir . '/bad.json', '{broken');
    assertSame([], $s->readJson('bad.json'));
    assertSame($dir . '/baseline.txt', $s->path('baseline.txt'));
});

t('State refuses a directory it cannot create', function () {
    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        skip('root can write anywhere');
    }
    assertThrows(RuntimeException::class, function () {
        new State('/proc/definitely/not/creatable');
    });
});

t('Lock is exclusive while held, free after release, and a leftover file is not stale (Review Focus 5)', function () {
    $f = tmpdir() . '/lock';
    $a = Lock::acquire($f);
    assertTrue($a !== null);
    assertSame(null, Lock::acquire($f));
    $a->release();
    $b = Lock::acquire($f);
    assertTrue($b !== null);
    $b->release();
    file_put_contents($f, 'left behind by a crashed run');
    $c = Lock::acquire($f);
    assertTrue($c !== null);
});

t('AlertLog alerts once, reminds Critical findings, retries failed sends and forgets old entries', function () {
    $state = new State(tmpdir());
    $crit = new Finding(Finding::CRITICAL, 'a.php', 'r', 'm', 'h');
    $warn = new Finding(Finding::WARNING, 'b.php', 'r', 'm', 'h');
    $info = new Finding(Finding::INFO, 'c.php', 'r', 'm', 'h');
    $day = 86400;

    $log = new AlertLog($state);
    assertSame([$crit, $warn], $log->due([$crit, $warn, $info], 1000, $day));
    $log->commit([$crit, $warn, $info], [$crit, $warn], 1000);

    $log = new AlertLog($state); // reloaded from disk
    assertSame([], $log->due([$crit, $warn], 1000 + 3600, $day));
    assertSame([$crit], $log->due([$crit, $warn], 1000 + $day, $day), 'only Critical reminds');

    // A send that failed leaves the finding un-alerted so the next run retries it.
    $failed = new Finding(Finding::CRITICAL, 'd.php', 'r', 'm', 'h');
    $log->commit([$failed], [], 2000);
    $log = new AlertLog($state);
    assertSame([$failed], $log->due([$failed], 2100, $day));

    // Unseen for more than 7 days: forgotten, so it alerts as new again.
    $log->commit([], [], 1000 + 8 * $day);
    $log = new AlertLog($state);
    assertSame([$warn], $log->due([$warn], 1000 + 8 * $day, $day));

    $log->clear();
    assertSame([$warn], (new AlertLog($state))->due([$warn], 5, $day));
});

t('SelfCheck records on first use, then flags changed or missing tool files', function () {
    $dir = tmpdir();
    $state = new State($dir . '/state');
    $script = putFile($dir, 'sentinel.php', '<?php // v1');
    $config = putFile($dir, 'sentinel.json', '{}');
    $files = ['script' => $script, 'config' => $config, 'rules' => $state->path('rules.json')];
    $sc = new SelfCheck($state, $files);
    assertSame([], $sc->check());
    assertSame([], $sc->check());

    file_put_contents($script, '<?php // tampered');
    $f = $sc->check();
    assertSame(1, count($f));
    assertSame('self-tamper', $f[0]->rule);
    assertSame(Finding::CRITICAL, $f[0]->severity);
    assertContains('script', $f[0]->path);

    $sc->record();
    assertSame([], $sc->check());

    unlink($config);
    $f = $sc->check();
    assertSame(1, count($f));
    assertContains('missing', $f[0]->message);

    // A rules bundle appearing for the first time is not tampering; once recorded, changing it is.
    file_put_contents($config, '{}');
    $sc->record();
    file_put_contents($state->path('rules.json'), '{"version":1}');
    assertSame([], $sc->check());
    $sc->record();
    file_put_contents($state->path('rules.json'), '{"version":2}');
    assertSame(1, count($sc->check()));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php State`
Expected: `Class "Sentinel\State" not found`.

- [ ] **Step 3: Implement**

```php file=src/State.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class State
{
    private $dir;

    public function __construct(string $dir)
    {
        $this->dir = rtrim($dir, '/');
        if (!is_dir($this->dir) && !@mkdir($this->dir, 0700, true) && !is_dir($this->dir)) {
            throw new \RuntimeException('cannot create state directory ' . $this->dir);
        }
        @chmod($this->dir, 0700);
    }

    public function dir(): string
    {
        return $this->dir;
    }

    public function path(string $name): string
    {
        return $this->dir . '/' . $name;
    }

    public function readJson(string $name): array
    {
        $f = $this->path($name);
        if (!is_file($f)) {
            return [];
        }
        $d = json_decode((string)file_get_contents($f), true);
        return is_array($d) ? $d : [];
    }

    public function writeJson(string $name, array $data): void
    {
        $f = $this->path($name);
        $tmp = $f . '.tmp';
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false || file_put_contents($tmp, $json) === false) {
            @unlink($tmp);
            throw new \RuntimeException('cannot write ' . $f);
        }
        @chmod($tmp, 0600);
        if (!rename($tmp, $f)) {
            @unlink($tmp);
            throw new \RuntimeException('cannot replace ' . $f);
        }
    }
}
```

```php file=src/Lock.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Lock
{
    private $fh;

    private function __construct($fh)
    {
        $this->fh = $fh;
    }

    public static function acquire(string $file): ?Lock
    {
        $fh = @fopen($file, 'c');
        if ($fh === false) {
            return null;
        }
        if (!flock($fh, LOCK_EX | LOCK_NB)) {
            fclose($fh);
            return null;
        }
        return new Lock($fh);
    }

    public function release(): void
    {
        if ($this->fh !== null) {
            flock($this->fh, LOCK_UN);
            fclose($this->fh);
            $this->fh = null;
        }
    }

    public function __destruct()
    {
        $this->release();
    }
}
```

```php file=src/AlertLog.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class AlertLog
{
    private const FORGET_AFTER = 604800; // 7 days

    private $state;
    /** @var array<string,array{first:int,alerted:int,seen:int,sev:int}> */
    private $entries;

    public function __construct(State $state)
    {
        $this->state = $state;
        $this->entries = $state->readJson('alerts.json');
    }

    /**
     * @param Finding[] $findings
     * @return Finding[] findings that should be alerted now
     */
    public function due(array $findings, int $now, int $remindSeconds): array
    {
        $out = [];
        foreach ($findings as $f) {
            if ($f->severity < Finding::WARNING) {
                continue;
            }
            $e = $this->entries[$f->key()] ?? null;
            if ($e === null || (int)$e['alerted'] === 0) {
                $out[] = $f;
            } elseif ($f->severity >= Finding::CRITICAL && $now - (int)$e['alerted'] >= $remindSeconds) {
                $out[] = $f;
            }
        }
        return $out;
    }

    /**
     * @param Finding[] $current every finding seen this run
     * @param Finding[] $sent the ones an alert was successfully sent for
     */
    public function commit(array $current, array $sent, int $now): void
    {
        $sentKeys = [];
        foreach ($sent as $f) {
            $sentKeys[$f->key()] = true;
        }
        foreach ($current as $f) {
            $k = $f->key();
            $e = $this->entries[$k] ?? ['first' => $now, 'alerted' => 0, 'seen' => $now, 'sev' => $f->severity];
            $e['seen'] = $now;
            if (isset($sentKeys[$k])) {
                $e['alerted'] = $now;
            }
            $this->entries[$k] = $e;
        }
        foreach ($this->entries as $k => $e) {
            if ($now - (int)$e['seen'] > self::FORGET_AFTER) {
                unset($this->entries[$k]);
            }
        }
        $this->state->writeJson('alerts.json', $this->entries);
    }

    public function clear(): void
    {
        $this->entries = [];
        $this->state->writeJson('alerts.json', []);
    }
}
```

```php file=src/SelfCheck.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class SelfCheck
{
    private $state;
    /** @var array<string,string> */
    private $files;

    /** @param array<string,string> $files label => absolute path */
    public function __construct(State $state, array $files)
    {
        $this->state = $state;
        $this->files = $files;
    }

    /** @return Finding[] */
    public function check(): array
    {
        $stored = $this->state->readJson('selfcheck.json');
        if ($stored === []) {
            $this->record();
            return [];
        }
        $out = [];
        foreach ($this->files as $label => $path) {
            $was = $stored[$label] ?? null;
            if ($was === null) {
                continue;
            }
            $now = is_file($path) ? (string)hash_file('sha256', $path) : '';
            if ($now !== $was) {
                $out[] = new Finding(
                    Finding::CRITICAL,
                    $label . ' (' . $path . ')',
                    'self-tamper',
                    $now === '' ? 'Sentinel file is missing' : 'Sentinel file changed since it was last accepted',
                    $now
                );
            }
        }
        return $out;
    }

    public function record(): void
    {
        $map = [];
        foreach ($this->files as $label => $path) {
            if (is_file($path)) {
                $map[$label] = (string)hash_file('sha256', $path);
            }
        }
        $this->state->writeJson('selfcheck.json', $map);
    }
}
```

- [ ] **Step 4: Register and run**

Edit `build/files.php`: add `'State.php', 'Lock.php', 'AlertLog.php', 'SelfCheck.php',`.

Run: `php tests/run.php State && php tests/run.php Lock && php tests/run.php AlertLog && php tests/run.php SelfCheck`
Expected: all `ok`.

- [ ] **Step 5: Commit**

```bash
git add src build/files.php tests/test_state.php
git commit -m "feat: state directory, run lock, alert dedupe log and self-check"
```

---

### Task 13: Notifiers, alerter and digest

**Files:**
- Create: `src/Notifier.php`, `src/Notifiers.php`, `src/Alerter.php`, `src/Digest.php`, `tests/helpers_notify.php`
- Test: `tests/test_notify.php`
- Modify: `build/files.php` (add `'Notifier.php', 'Notifiers.php', 'Alerter.php', 'Digest.php',` after `'SelfCheck.php',`)

**Interfaces:**
- Consumes: `Config` (`channels`), `HttpClient`, `Finding`.
- Produces: `interface Notifier { name(): string; send(string $subject, string $body, int $severity): void }` (throws `\RuntimeException` on failure); `Channel` with public `$notifier`, `$minSeverity` (int), constructor `(Notifier $n, int $min)`.
- Produces in `Notifiers.php`: `EmailNotifier(array $to, string $from, ?callable $mailer = null)` where the mailer is `fn(string $to, string $subject, string $body, string $headers): bool` (default wraps `mail()`); `static EmailNotifier::encodeSubject(string $s): string` (strips CR/LF, base64-encodes non-ASCII). `NtfyNotifier(string $url, HttpClient $h)`, `TelegramNotifier(string $token, string $chatId, HttpClient $h)`, `WebhookNotifier(string $url, HttpClient $h)`, `FileNotifier(string $path)`. Non-2xx responses throw. `NotifierFactory::fromConfig(Config $c, HttpClient $h, ?callable $mailer = null): Channel[]`.
- Produces: `Alerter::__construct(array $channels)`; `send(string $subject, string $body, int $topSeverity): array` returning `['ok'=>bool, 'results'=>string[], 'attempted'=>int]`; channels whose `minSeverity` exceeds `$topSeverity` are skipped; `ok` is true if at least one attempted channel succeeded, or if none were attempted; each failure appears as `"<name>: FAILED - <message>"`, each success as `"<name>: sent"`.
- Produces: `Digest::build(string $site, string $host, int $ts, array $findings, array $info, array $notes): array` returning `['subject'=>string, 'body'=>string, 'top'=>int]`. Findings are sorted by severity (desc), then path. Subject: `[Sentinel][<TOP>] <site>: N critical, M warning`. Body sections: header, one block per finding (path, `rule: message`, `What to do:` line), `Notes`, `Info`.
- Produces (tests): `FakeNotifier` (`$sent` list, `$fail` flag) and `FakeClock` (`public $t`, callable returning int) in `tests/helpers_notify.php`.

- [ ] **Step 1: Write the helpers and failing tests**

```php file=tests/helpers_notify.php
<?php
declare(strict_types=1);

final class FakeNotifier implements \Sentinel\Notifier
{
    /** @var array<int,array{subject:string,body:string,severity:int}> */
    public $sent = [];
    public $fail = false;
    private $name;

    public function __construct(string $name = 'fake')
    {
        $this->name = $name;
    }

    public function name(): string
    {
        return $this->name;
    }

    public function send(string $subject, string $body, int $severity): void
    {
        if ($this->fail) {
            throw new RuntimeException('simulated failure');
        }
        $this->sent[] = ['subject' => $subject, 'body' => $body, 'severity' => $severity];
    }
}

/** A controllable clock: $c->t += 86400; pass $c wherever a callable returning int is expected. */
final class FakeClock
{
    public $t = 1760000000;

    public function __invoke(): int
    {
        return $this->t;
    }
}
```

```php file=tests/test_notify.php
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
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php Digest`
Expected: `Interface "Sentinel\Notifier" not found` (raised by `helpers_notify.php`).

- [ ] **Step 3: Implement the interface, channel and notifiers**

```php file=src/Notifier.php
<?php
declare(strict_types=1);

namespace Sentinel;

interface Notifier
{
    public function name(): string;

    /** @throws \RuntimeException when the message could not be delivered */
    public function send(string $subject, string $body, int $severity): void;
}

final class Channel
{
    public $notifier;
    public $minSeverity;

    public function __construct(Notifier $notifier, int $minSeverity)
    {
        $this->notifier = $notifier;
        $this->minSeverity = $minSeverity;
    }
}
```

```php file=src/Notifiers.php
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

    public function send(string $subject, string $body, int $severity): void
    {
        $headers = 'From: ' . $this->from . "\r\n"
            . "MIME-Version: 1.0\r\n"
            . "Content-Type: text/plain; charset=UTF-8\r\n"
            . 'X-Priority: ' . ($severity >= Finding::CRITICAL ? '1' : '3') . "\r\n";
        if (!($this->mailer)(implode(', ', $this->to), self::encodeSubject($subject), $body, $headers)) {
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

    public function send(string $subject, string $body, int $severity): void
    {
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

    public function send(string $subject, string $body, int $severity): void
    {
        $text = $subject . "\n\n" . $body;
        $text = function_exists('mb_strcut') ? mb_strcut($text, 0, 4000, 'UTF-8') : substr($text, 0, 4000);
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

    public function send(string $subject, string $body, int $severity): void
    {
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

    public function send(string $subject, string $body, int $severity): void
    {
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
```

- [ ] **Step 4: Implement the alerter and digest**

```php file=src/Alerter.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Alerter
{
    /** @var Channel[] */
    private $channels;

    /** @param Channel[] $channels */
    public function __construct(array $channels)
    {
        $this->channels = $channels;
    }

    /** @return array{ok: bool, results: string[], attempted: int} */
    public function send(string $subject, string $body, int $topSeverity): array
    {
        $results = [];
        $attempted = 0;
        $succeeded = 0;
        foreach ($this->channels as $ch) {
            if ($topSeverity < $ch->minSeverity) {
                continue;
            }
            $attempted++;
            try {
                $ch->notifier->send($subject, $body, $topSeverity);
                $results[] = $ch->notifier->name() . ': sent';
                $succeeded++;
            } catch (\Throwable $e) {
                $results[] = $ch->notifier->name() . ': FAILED - ' . $e->getMessage();
            }
        }
        return ['ok' => $attempted === 0 || $succeeded > 0, 'results' => $results, 'attempted' => $attempted];
    }
}
```

```php file=src/Digest.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Digest
{
    private const COMPROMISE = 'Treat this as a possible compromise: keep a copy of the file for analysis, remove or restore it, then check recent logins, plugin/theme vulnerabilities and file permissions. Restore from a clean backup if it is confirmed.';

    private const ACTIONS = [
        'php-in-uploads' => 'PHP does not belong in uploads. Inspect the file, delete it if it is not yours, and find out how it got there (vulnerable plugin, stolen credentials).',
        'php-in-media' => 'A media file carrying PHP code is a disguised webshell. Delete it and find out how it was uploaded.',
        'checksum-mismatch' => 'Reinstall the official version of this file and find out how it was changed.',
        'unexpected-file' => 'This file is not in the official package. If you did not add it, inspect and remove it.',
        'stealth-modification' => 'Someone changed the content and reset the timestamp. Inspect the file and restore it from a clean copy.',
        'unexplained-change' => 'If you did not just deploy or update this, review the files. If you did, run: php sentinel.php accept',
        'sensitive-file-changed' => 'Review the change. If it was intentional, run: php sentinel.php accept --path=<file>',
        'sensitive-file-removed' => 'Restore the file from a backup if the removal was not intentional.',
        'core-file-removed' => 'Reinstall WordPress core files (wp core download --force --skip-content) if the removal was not intentional.',
        'symlink' => 'Symbolic links can expose other accounts or system files. Remove it unless you created it.',
        'world-writable' => 'Set sane permissions (644 for files, 755 for directories).',
        'self-tamper' => 'A Sentinel file changed. If you updated Sentinel, run: php sentinel.php accept --self. Otherwise treat as a compromise.',
        'run-error' => 'Sentinel could not complete its check, so the site is not being monitored. Fix the cause and run it again.',
        'unreadable' => 'Fix the file permissions so Sentinel can read it, or exclude it.',
        'unreadable-dir' => 'Fix the directory permissions so Sentinel can read it, or exclude it.',
        'config-in-uploads' => 'Server configuration in uploads can enable code execution. Inspect and remove it if it is not yours.',
        'exec-in-temp' => 'An executable appeared in a temp directory. Inspect it and find out which process created it.',
    ];

    /**
     * @param Finding[] $findings
     * @param string[] $info
     * @param string[] $notes
     * @return array{subject: string, body: string, top: int}
     */
    public static function build(string $site, string $host, int $ts, array $findings, array $info, array $notes): array
    {
        usort($findings, function (Finding $a, Finding $b) {
            return $b->severity <=> $a->severity ?: PathOrder::compare($a->path, $b->path);
        });
        $top = Finding::INFO;
        $crit = 0;
        $warn = 0;
        foreach ($findings as $f) {
            $top = max($top, $f->severity);
            if ($f->severity >= Finding::CRITICAL) {
                $crit++;
            } elseif ($f->severity === Finding::WARNING) {
                $warn++;
            }
        }
        $subject = sprintf('[Sentinel][%s] %s: %d critical, %d warning', Finding::label($top), $site, $crit, $warn);

        $lines = [
            "Site Sentinel alert: $site ($host)",
            'Time: ' . gmdate('Y-m-d H:i:s', $ts) . ' UTC',
            'Highest severity: ' . Finding::label($top),
            '',
        ];
        $current = null;
        foreach ($findings as $f) {
            if ($f->severity !== $current) {
                $current = $f->severity;
                $count = 0;
                foreach ($findings as $g) {
                    $count += $g->severity === $current ? 1 : 0;
                }
                $lines[] = Finding::label($current) . " ($count)";
            }
            $lines[] = '  ' . $f->path;
            $lines[] = '    ' . $f->rule . ': ' . $f->message;
            $lines[] = '    What to do: ' . self::action($f);
            $lines[] = '';
        }
        if ($notes) {
            $lines[] = 'Notes';
            foreach ($notes as $n) {
                $lines[] = '  - ' . $n;
            }
            $lines[] = '';
        }
        if ($info) {
            $lines[] = 'Info';
            foreach ($info as $i) {
                $lines[] = '  - ' . $i;
            }
            $lines[] = '';
        }
        return ['subject' => $subject, 'body' => implode("\n", $lines), 'top' => $top];
    }

    private static function action(Finding $f): string
    {
        if (isset(self::ACTIONS[$f->rule])) {
            return self::ACTIONS[$f->rule];
        }
        if ($f->severity >= Finding::CRITICAL) {
            return self::COMPROMISE;
        }
        return 'Review the file. If the change is expected, run: php sentinel.php accept --path=<file>';
    }
}
```

- [ ] **Step 5: Register and run**

Edit `build/files.php`: add `'Notifier.php', 'Notifiers.php', 'Alerter.php', 'Digest.php',`.

Run: `php tests/run.php Digest && php tests/run.php Alerter && php tests/run.php Notifier && php tests/run.php Email && php tests/run.php Ntfy && php tests/run.php FileNotifier`
Expected: all `ok`.

- [ ] **Step 6: Commit**

```bash
git add src build/files.php tests/helpers_notify.php tests/test_notify.php
git commit -m "feat: notification channels, alerter and digest"
```

---

### Task 14: Monitor (the `check` and `full` runs)

**Files:**
- Create: `src/Monitor.php`
- Test: `tests/test_monitor.php`
- Modify: `build/files.php` (add `'Monitor.php',` after `'Digest.php',`)

**Interfaces:**
- Consumes: everything above.
- Produces: `Monitor::__construct(Config $c, State $s, HttpClient $h, array $channels, array $selfFiles, ?callable $clock = null)` where `$channels` is `Channel[]`, `$selfFiles` is `label => path` for `SelfCheck`, and `$clock` returns the current unix time as int.
- Produces: `run(string $mode, ?Budget $budget = null): array` with `$mode` `'check'` or `'full'`, returning `['exit'=>0|1|2, 'lines'=>string[]]`. Exit 0 = no Warning/Critical findings, 1 = findings reported, 2 = tool error. Behaviour:
  1. No channels configured → exit 2.
  2. Lock held elsewhere → exit 0 with a "skipping" line, nothing scanned.
  3. Any exception (missing baseline, corrupt baseline, unreadable state) → exit 2 and a deduplicated Critical `run-error` alert (the same error alerts once, then reminds after `remind_hours`). A missing baseline is an error, never "everything is new".
  4. Otherwise: diff from the stored resume point for this mode, analyze, add unreadable-directory and self-check findings, apply baseline updates for non-held changes, store/clear the resume point (`resume.json`, per mode), update `versions.json` only when the scan completed (held groups keep their old version), alert on findings that are `due` (one digest including Info and notes), commit the alert log (marking findings alerted only if at least one channel succeeded), ping `heartbeat_url` (a failure only adds an output line).
  5. Output lines: a summary (`<mode>: N change(s), C critical, W warning, scan complete|partial scan, resuming after <path>`), one line per Warning/Critical finding, and alert results.
- Files used in state: `baseline.txt`, `rules.json` (optional), `resume.json`, `versions.json`, `alerts.json`, `selfcheck.json`, `lock`, `cache/`.

- [ ] **Step 1: Write the failing tests**

```php file=tests/test_monitor.php
<?php
declare(strict_types=1);

use Sentinel\Baseline;
use Sentinel\Budget;
use Sentinel\Channel;
use Sentinel\Finding;
use Sentinel\Lock;
use Sentinel\Monitor;
use Sentinel\State;
use Sentinel\VersionTracker;

/** @return array{0:string,1:\Sentinel\Config,2:State,3:Monitor,4:FakeNotifier,5:FakeHttp,6:FakeClock} */
function monitorFixture(array $files = [], array $cfg = [], array $self = []): array
{
    $root = tmpdir();
    foreach ($files as $rel => $content) {
        putFile($root, $rel, $content);
    }
    $config = makeConfig($root, $cfg);
    $state = new State($config->stateDir);
    snapshot($config, $state->path('baseline.txt'));
    $notifier = new FakeNotifier();
    $http = new FakeHttp();
    $clock = new FakeClock();
    $m = new Monitor($config, $state, $http, [new Channel($notifier, Finding::WARNING)], $self, $clock);
    return [$root, $config, $state, $m, $notifier, $http, $clock];
}

t('Monitor: a clean run exits 0 and sends nothing', function () {
    [, , , $m, $n] = monitorFixture(['index.php' => '<?php', 'a.txt' => 'a']);
    $r = $m->run('check');
    assertSame(0, $r['exit']);
    assertSame(0, count($n->sent));
    assertContains('0 change(s), 0 critical, 0 warning, scan complete', $r['lines'][0]);
});

t('Monitor: a malware hit alerts once, stays held, and reminds after remind_hours', function () {
    [$root, , , $m, $n, , $clock] = monitorFixture(['index.php' => '<?php']);
    putFile($root, 'lib/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $r = $m->run('check');
    assertSame(1, $r['exit']);
    assertSame(1, count($n->sent));
    assertContains('[Sentinel][CRITICAL]', $n->sent[0]['subject']);
    assertContains('lib/evil.php', $n->sent[0]['body']);

    $r2 = $m->run('check');
    assertSame(1, $r2['exit'], 'still reported, because it is held out of the baseline');
    assertSame(1, count($n->sent), 'but not re-alerted');

    $clock->t += 86400 + 10;
    $m->run('check');
    assertSame(2, count($n->sent), 'Critical findings remind daily');
});

t('Monitor: a failing channel does not mark findings alerted, so the next run retries (Review Focus 4)', function () {
    [$root, , , $m, $n] = monitorFixture();
    putFile($root, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $n->fail = true;
    $r = $m->run('check');
    assertSame(1, $r['exit']);
    assertSame(0, count($n->sent));
    assertContains('FAILED', implode("\n", $r['lines']));
    $n->fail = false;
    $m->run('check');
    assertSame(1, count($n->sent));
});

t('Monitor: a missing baseline is an error, not "everything is new" (Review Focus 5)', function () {
    [$root, , $state, $m, $n] = monitorFixture(['a.php' => '<?php']);
    unlink($state->path('baseline.txt'));
    $r = $m->run('check');
    assertSame(2, $r['exit']);
    assertContains('no baseline', implode("\n", $r['lines']));
    assertSame(1, count($n->sent));
    assertContains('[Sentinel][CRITICAL]', $n->sent[0]['subject']);
    assertContains('run "init" first', $n->sent[0]['body']);
    assertTrue(!is_file($state->path('baseline.txt')), 'must not invent a baseline');
    $m->run('check');
    assertSame(1, count($n->sent), 'the same error alerts once');
});

t('Monitor: a corrupt baseline is an error and is left untouched (Review Focus 5)', function () {
    [, , $state, $m, $n] = monitorFixture(['a.php' => '<?php']);
    file_put_contents($state->path('baseline.txt'), "not a baseline\n");
    $r = $m->run('check');
    assertSame(2, $r['exit']);
    assertContains('corrupt baseline', implode("\n", $r['lines']));
    assertSame("not a baseline\n", file_get_contents($state->path('baseline.txt')));
    assertSame(1, count($n->sent));
});

t('Monitor: clean changes update the baseline, code changes are held and alerted once', function () {
    [$root, , , $m, $n] = monitorFixture(['notes.txt' => 'one', 'lib/a.php' => '<?php // a']);
    bump($root, 'notes.txt', 'two');
    $r = $m->run('check');
    assertSame(0, $r['exit']);
    assertContains('1 change(s)', $r['lines'][0]);
    assertContains('0 change(s)', $m->run('check')['lines'][0], 'baseline was updated');

    bump($root, 'lib/a.php', '<?php // edited');
    $r2 = $m->run('check');
    assertSame(1, $r2['exit']);
    assertSame(1, count($n->sent));
    assertContains('unexplained-change', $n->sent[0]['body']);
    $r3 = $m->run('check');
    assertSame(1, $r3['exit']);
    assertContains('1 change(s)', $r3['lines'][0], 'held out of the baseline');
    assertSame(1, count($n->sent));
});

t('Monitor: a budget-limited scan resumes where it stopped and finishes (Review Focus 5)', function () {
    [$root, , $state, $m, $n] = monitorFixture(['f1.txt' => '1', 'f2.txt' => '2', 'f3.txt' => '3', 'f4.txt' => '4', 'f5.txt' => '5']);
    bump($root, 'f1.txt', 'one!');
    bump($root, 'f5.txt', 'five!');
    $total = 0;
    $runs = 0;
    do {
        $t = 0.0;
        $budget = new Budget(1.0, PHP_INT_MAX, function () use (&$t) { $t += 0.6; return $t; });
        $r = $m->run('check', $budget);
        $partial = strpos($r['lines'][0], 'partial scan') !== false;
        if ($partial) {
            assertContains('resuming after', $r['lines'][0]);
            assertTrue(isset($state->readJson('resume.json')['check']));
        }
        preg_match('/(\d+) change\(s\)/', $r['lines'][0], $mm);
        $total += (int)$mm[1];
        $runs++;
    } while ($partial && $runs < 10);
    assertSame(2, $total);
    assertSame(3, $runs);
    assertTrue(!isset($state->readJson('resume.json')['check']));
    assertContains('0 change(s)', $m->run('check')['lines'][0]);
    assertSame(0, count($n->sent));
});

t('Monitor: two overlapping runs do not both scan (Review Focus 5)', function () {
    [$root, , $state, $m, $n] = monitorFixture();
    putFile($root, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $lock = Lock::acquire($state->path('lock'));
    $r = $m->run('check');
    assertSame(0, $r['exit']);
    assertContains('another run is in progress', $r['lines'][0]);
    assertSame(0, count($n->sent));
    $lock->release();
    assertSame(1, $m->run('check')['exit']);
});

t('Monitor: heartbeat is pinged after a completed run but not after an error', function () {
    [, , $state, $m, , $http] = monitorFixture([], ['heartbeat_url' => 'https://hb.example/ping']);
    $http->route('https://hb.example/ping', 200, 'OK');
    $m->run('check');
    assertSame(1, count($http->calls));
    assertSame('https://hb.example/ping', $http->calls[0][1]);

    unlink($state->path('baseline.txt'));
    $m->run('check');
    assertSame(1, count($http->calls));

    [, , , $m2, , $http2] = monitorFixture([], ['heartbeat_url' => 'https://hb.example/ping']);
    $r = $m2->run('check');
    assertContains('heartbeat failed', implode("\n", $r['lines']));
});

t('Monitor: tampering with the script is a Critical finding', function () {
    $dir = tmpdir();
    $script = putFile($dir, 'sentinel.php', '<?php // v1');
    [, , , $m, $n] = monitorFixture([], [], ['script' => $script]);
    assertSame(0, $m->run('check')['exit']);
    file_put_contents($script, '<?php // evil');
    $r = $m->run('check');
    assertSame(1, $r['exit']);
    assertContains('self-tamper', $n->sent[0]['body']);
});

t('Monitor: with no channels configured it refuses to run', function () {
    $root = tmpdir();
    $config = makeConfig($root);
    $m = new Monitor($config, new State($config->stateDir), new FakeHttp(), [], []);
    $r = $m->run('check');
    assertSame(2, $r['exit']);
    assertContains('no alert channels', $r['lines'][0]);
});

t('Monitor: a WordPress plugin update is explained, silent, and advances stored versions', function () {
    $files = [
        'wp-config.php' => '<?php',
        'wp-content/plugins/foo/foo.php' => "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n// v1\n",
    ];
    [$root, $config, $state, $m, $n] = monitorFixture($files, ['profile' => 'wordpress', 'wp_checksums' => false]);
    $state->writeJson('versions.json', VersionTracker::read($config));
    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// v2\n");
    $r = $m->run('check');
    assertSame(0, $r['exit']);
    assertSame(0, count($n->sent), 'Info never alerts on its own');
    assertSame(['wp-content/plugins/foo' => '1.1'], $state->readJson('versions.json'));
    assertContains('0 change(s)', $m->run('check')['lines'][0]);

    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// quiet edit\n");
    assertSame(1, $m->run('check')['exit']);
    assertSame(1, count($n->sent));
    assertContains("Info\n", $n->sent[0]['body'] . "Info\n");
});

t('Monitor: a held plugin group keeps its old stored version', function () {
    $files = [
        'wp-config.php' => '<?php',
        'wp-content/plugins/foo/foo.php' => "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n// v1\n",
    ];
    [$root, $config, $state, $m] = monitorFixture($files, ['profile' => 'wordpress', 'wp_checksums' => false]);
    $state->writeJson('versions.json', VersionTracker::read($config));
    putFile($root, 'wp-content/plugins/foo/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    bump($root, 'wp-content/plugins/foo/foo.php', "<?php\n/*\nPlugin Name: Foo\nVersion: 1.1\n*/\n// v2\n");
    assertSame(1, $m->run('check')['exit']);
    assertSame(['wp-content/plugins/foo' => '1.0'], $state->readJson('versions.json'));
});

t('Monitor: an unreadable directory is reported', function () {
    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        skip('root can read everything');
    }
    [$root, , , $m, $n] = monitorFixture(['a.txt' => 'a']);
    putFile($root, 'locked/x.txt', 'x');
    chmod($root . '/locked', 0000);
    $r = $m->run('check');
    chmod($root . '/locked', 0755);
    assertSame(1, $r['exit']);
    assertContains('unreadable-dir', $n->sent[0]['body']);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php Monitor`
Expected: `Class "Sentinel\Monitor" not found`.

- [ ] **Step 3: Implement**

```php file=src/Monitor.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Monitor
{
    private static $niced = false;

    private $config;
    private $state;
    private $http;
    /** @var Channel[] */
    private $channels;
    /** @var array<string,string> */
    private $selfFiles;
    private $clock;

    /**
     * @param Channel[] $channels
     * @param array<string,string> $selfFiles label => path, tracked by SelfCheck
     */
    public function __construct(Config $config, State $state, HttpClient $http, array $channels, array $selfFiles, ?callable $clock = null)
    {
        $this->config = $config;
        $this->state = $state;
        $this->http = $http;
        $this->channels = $channels;
        $this->selfFiles = $selfFiles;
        $this->clock = $clock ?? function (): int {
            return time();
        };
    }

    /** @return array{exit:int, lines:string[]} */
    public function run(string $mode, ?Budget $budget = null): array
    {
        if (!in_array($mode, ['check', 'full'], true)) {
            throw new \InvalidArgumentException("unknown mode '$mode'");
        }
        if (!$this->channels) {
            return ['exit' => 2, 'lines' => ['no alert channels configured: add one to the config, then run test-alert']];
        }
        $lock = Lock::acquire($this->state->path('lock'));
        if ($lock === null) {
            return ['exit' => 0, 'lines' => ['another run is in progress; skipping']];
        }
        if (!self::$niced && function_exists('proc_nice')) {
            self::$niced = true;
            @proc_nice(10);
        }
        try {
            return $this->execute($mode, $budget);
        } catch (\Throwable $e) {
            return $this->failed($e);
        } finally {
            $lock->release();
        }
    }

    private function execute(string $mode, ?Budget $budget): array
    {
        $full = $mode === 'full';
        $baselineFile = $this->state->path('baseline.txt');
        if (!is_file($baselineFile)) {
            throw new \RuntimeException('no baseline found; run "init" first');
        }
        $rulesFile = $this->state->path('rules.json');
        $rules = is_file($rulesFile) ? Rules::load($rulesFile) : Rules::builtin();
        $budget = $budget ?? Budget::forConfig($this->config);
        $resume = $this->state->readJson('resume.json');
        $startAfter = (string)($resume[$mode] ?? '');

        $wpOn = $this->config->profile === 'wordpress';
        $wp = $wpOn && $this->config->wpChecksums ? new WpChecksum($this->http, $this->config, $this->state->path('cache')) : null;
        $analyzer = new Analyzer(
            $this->config,
            new PatternScanner($rules, $this->config->maxScanBytes),
            new LocationScanner($this->config),
            $wp,
            ExternalScanner::fromConfig($this->config)
        );

        $d = (new Differ($this->config))->diff($baselineFile, $startAfter, $budget, $full);
        $oldVersions = $this->state->readJson('versions.json');
        $newVersions = $wpOn ? VersionTracker::read($this->config) : [];
        $a = $analyzer->analyze($d['changes'], $oldVersions, $newVersions);

        $findings = $a['findings'];
        foreach ($d['unreadable'] as $dir) {
            $findings[] = new Finding(Finding::WARNING, (string)$dir, 'unreadable-dir', 'Directory could not be read');
        }
        foreach ((new SelfCheck($this->state, $this->selfFiles))->check() as $f) {
            $findings[] = $f;
        }

        $updates = [];
        foreach ($d['changes'] as $c) {
            if (isset($a['hold'][$c['path']])) {
                continue;
            }
            $updates[$c['path']] = in_array($c['type'], ['removed', 'dropped'], true) ? null : $c['new'];
        }
        if ($updates) {
            Baseline::applyUpdates($baselineFile, $updates, $baselineFile);
        }

        if ($d['complete']) {
            unset($resume[$mode]);
        } else {
            $resume[$mode] = $d['stopped_at'];
        }
        $this->state->writeJson('resume.json', $resume);
        if ($d['complete'] && $wpOn) {
            $store = [];
            foreach ($newVersions as $g => $v) {
                if (!isset($a['held_groups'][$g])) {
                    $store[$g] = $v;
                } elseif (isset($oldVersions[$g])) {
                    $store[$g] = $oldVersions[$g];
                }
            }
            $this->state->writeJson('versions.json', $store);
        }

        $now = ($this->clock)();
        $log = new AlertLog($this->state);
        $due = $log->due($findings, $now, $this->config->remindHours * 3600);
        $alertLines = [];
        $sent = [];
        if ($due) {
            $digest = Digest::build($this->config->siteName, (string)gethostname(), $now, $due, $a['info'], $a['notes']);
            $r = (new Alerter($this->channels))->send($digest['subject'], $digest['body'], $digest['top']);
            foreach ($r['results'] as $line) {
                $alertLines[] = 'alert ' . $line;
            }
            if ($r['ok']) {
                $sent = $due;
            }
        }
        $log->commit($findings, $sent, $now);

        $crit = 0;
        $warn = 0;
        foreach ($findings as $f) {
            if ($f->severity >= Finding::CRITICAL) {
                $crit++;
            } elseif ($f->severity === Finding::WARNING) {
                $warn++;
            }
        }
        $lines = [sprintf(
            '%s: %d change(s), %d critical, %d warning, %s',
            $mode,
            count($d['changes']),
            $crit,
            $warn,
            $d['complete'] ? 'scan complete' : 'partial scan, resuming after ' . $d['stopped_at']
        )];
        foreach ($findings as $f) {
            if ($f->severity >= Finding::WARNING) {
                $lines[] = '  ' . Finding::label($f->severity) . ' ' . $f->path . ' ' . $f->rule;
            }
        }
        $lines = array_merge($lines, $alertLines);

        if ($this->config->heartbeatUrl !== '') {
            $hb = $this->http->request('GET', $this->config->heartbeatUrl, '', [], 10);
            if ($hb['status'] < 200 || $hb['status'] >= 300) {
                $lines[] = 'heartbeat failed (' . ($hb['status'] === 0 ? 'network error' : 'HTTP ' . $hb['status']) . ')';
            }
        }
        return ['exit' => ($crit + $warn) > 0 ? 1 : 0, 'lines' => $lines];
    }

    private function failed(\Throwable $e): array
    {
        $msg = $e->getMessage();
        $lines = ['error: ' . $msg];
        try {
            $now = ($this->clock)();
            $f = new Finding(Finding::CRITICAL, 'sentinel', 'run-error', $msg, sha1($msg));
            $log = new AlertLog($this->state);
            $due = $log->due([$f], $now, $this->config->remindHours * 3600);
            $sent = [];
            if ($due) {
                $digest = Digest::build($this->config->siteName, (string)gethostname(), $now, $due, [], []);
                $r = (new Alerter($this->channels))->send($digest['subject'], $digest['body'], $digest['top']);
                foreach ($r['results'] as $line) {
                    $lines[] = 'alert ' . $line;
                }
                if ($r['ok']) {
                    $sent = $due;
                }
            }
            $log->commit([$f], $sent, $now);
        } catch (\Throwable $inner) {
            $lines[] = 'could not send the error alert: ' . $inner->getMessage();
        }
        return ['exit' => 2, 'lines' => $lines];
    }
}
```

- [ ] **Step 4: Register and run**

Edit `build/files.php`: add `'Monitor.php',`.

Run: `php tests/run.php Monitor`
Expected: all `ok`.

- [ ] **Step 5: Commit**

```bash
git add src/Monitor.php build/files.php tests/test_monitor.php
git commit -m "feat: monitor orchestrating check and full runs with alerting and resume"
```

---
### Task 15: Rules updater and signing tool

**Files:**
- Create: `src/RulesUpdater.php`, `bin/sign-rules.php`
- Test: `tests/test_rules_update.php`
- Modify: `build/files.php` (add `'RulesUpdater.php',` after `'Monitor.php',`)

**Interfaces:**
- Consumes: `Config` (`rulesUrl`, `rulesPublicKey`, `allowUnsignedRules`), `State`, `HttpClient`, `SelfCheck`, `Rules`.
- Produces: `RulesUpdater::__construct(Config $c, State $s, HttpClient $h, SelfCheck $self)`; `update(): string[]` returns output lines or throws `\RuntimeException`. Never installs anything unless verification passed:
  1. `rules_url` empty → throws (tells the user to set it).
  2. The bundle is fetched from `rules_url`. If `sodium` is available **and** `rules_public_key` (base64 ed25519) is set: the detached signature is fetched from `<rules_url>.sig` (base64) and verified; failure throws.
  3. Otherwise, only if `allow_unsigned_rules` is true: `<rules_url>.sha256` (`<hex>  <name>`) is compared with the bundle's SHA-256, and the output includes a warning that this protects against corruption only. If neither applies the update is refused with an explanatory message.
  4. The bundle must parse via `Rules::fromArray` (bad regexes or hashes throw).
  5. `version` lower than the installed version is refused (replay protection); equal is "already up to date"; higher is installed atomically as `<state>/rules.json` byte-for-byte (so signatures stay valid), then `SelfCheck::record()` is called so the new file is trusted.
- Produces: `bin/sign-rules.php keygen` prints a base64 public and secret key; `bin/sign-rules.php sign <rules.json> <secret-key-file>` writes `<rules.json>.sig` (base64 detached signature) and `<rules.json>.sha256`. Requires `sodium`.

- [ ] **Step 1: Write the failing tests**

```php file=tests/test_rules_update.php
<?php
declare(strict_types=1);

use Sentinel\Config;
use Sentinel\Proc;
use Sentinel\RulesUpdater;
use Sentinel\SelfCheck;
use Sentinel\State;

function rulesBundle(int $version, string $regex = '/needle/'): string
{
    return json_encode(['version' => $version, 'patterns' => [['id' => 'p' . $version, 'severity' => 'critical', 'regex' => $regex, 'description' => 'Needle']], 'hashes' => []]);
}

/** @return array{0:RulesUpdater,1:State,2:FakeHttp,3:SelfCheck} */
function updaterFor(array $cfg = []): array
{
    $config = makeConfig(tmpdir(), array_merge(['rules_url' => 'https://rules.example/rules.json'], $cfg));
    $state = new State($config->stateDir);
    $http = new FakeHttp();
    $self = new SelfCheck($state, ['rules' => $state->path('rules.json')]);
    return [new RulesUpdater($config, $state, $http, $self), $state, $http, $self];
}

function serveUnsigned(FakeHttp $http, string $bundle, ?string $sha = null): void
{
    $http->route('https://rules.example/rules.json.sha256', 200, ($sha ?? hash('sha256', $bundle)) . "  rules.json\n");
    $http->route('https://rules.example/rules.json', 200, $bundle);
}

t('RulesUpdater refuses unsigned rules by default and without a rules_url', function () {
    [$u, $state, $http] = updaterFor();
    serveUnsigned($http, rulesBundle(1));
    assertThrows(RuntimeException::class, function () use ($u) { $u->update(); });
    assertTrue(!is_file($state->path('rules.json')));
    try {
        $u->update();
    } catch (RuntimeException $e) {
        assertContains('refusing to install unsigned rules', $e->getMessage());
    }
    [$none] = updaterFor(['rules_url' => '']);
    try {
        $none->update();
        throw new Exception('expected failure');
    } catch (RuntimeException $e) {
        assertContains('rules_url', $e->getMessage());
    }
});

t('RulesUpdater installs a SHA-256-verified bundle only when allowed, and warns', function () {
    [$u, $state, $http, $self] = updaterFor(['allow_unsigned_rules' => true]);
    $bundle = rulesBundle(3);
    serveUnsigned($http, $bundle);
    $lines = $u->update();
    assertContains('WARNING', implode("\n", $lines));
    assertContains('installed rules version 3', implode("\n", $lines));
    assertSame($bundle, file_get_contents($state->path('rules.json')));
    assertSame(0600, fileperms($state->path('rules.json')) & 0777);
    $self->record();
    assertSame([], $self->check());
});

t('RulesUpdater rejects checksum mismatches, replays, bad rules and keeps the old bundle', function () {
    [$u, $state, $http] = updaterFor(['allow_unsigned_rules' => true]);
    serveUnsigned($http, rulesBundle(5));
    $u->update();
    $installed = file_get_contents($state->path('rules.json'));

    serveUnsigned($http, rulesBundle(6), str_repeat('0', 64));
    assertThrows(RuntimeException::class, function () use ($u) { $u->update(); });

    serveUnsigned($http, rulesBundle(4));
    try {
        $u->update();
        throw new Exception('expected a downgrade to be refused');
    } catch (RuntimeException $e) {
        assertContains('older than', $e->getMessage());
    }

    serveUnsigned($http, rulesBundle(7, '/(unclosed/'));
    assertThrows(Exception::class, function () use ($u) { $u->update(); });

    serveUnsigned($http, 'not json at all');
    assertThrows(Exception::class, function () use ($u) { $u->update(); });

    assertSame($installed, file_get_contents($state->path('rules.json')));

    serveUnsigned($http, rulesBundle(5));
    assertContains('already up to date', implode("\n", $u->update()));
});

t('RulesUpdater reports an unreachable rules server', function () {
    [$u] = updaterFor(['allow_unsigned_rules' => true]);
    assertThrows(RuntimeException::class, function () use ($u) { $u->update(); });
});

t('RulesUpdater verifies ed25519 signatures when sodium is available', function () {
    if (!function_exists('sodium_crypto_sign_keypair')) {
        skip('sodium extension not installed');
    }
    $kp = sodium_crypto_sign_keypair();
    $pub = base64_encode(sodium_crypto_sign_publickey($kp));
    $bundle = rulesBundle(2);
    $sig = base64_encode(sodium_crypto_sign_detached($bundle, sodium_crypto_sign_secretkey($kp)));

    [$u, $state, $http] = updaterFor(['rules_public_key' => $pub]);
    $http->route('https://rules.example/rules.json.sig', 200, $sig . "\n");
    $http->route('https://rules.example/rules.json', 200, $bundle);
    assertContains('signature verified', implode("\n", $u->update()));
    assertSame($bundle, file_get_contents($state->path('rules.json')));

    [$u2, $state2, $http2] = updaterFor(['rules_public_key' => $pub, 'allow_unsigned_rules' => true]);
    $http2->route('https://rules.example/rules.json.sig', 200, $sig);
    $http2->route('https://rules.example/rules.json', 200, rulesBundle(2, '/tampered/'));
    assertThrows(RuntimeException::class, function () use ($u2) { $u2->update(); });
    assertTrue(!is_file($state2->path('rules.json')), 'a failed signature never falls back to the weaker check');
});

t('sign-rules tool produces a signature the updater accepts', function () {
    if (!function_exists('sodium_crypto_sign_keypair')) {
        skip('sodium extension not installed');
    }
    $dir = tmpdir();
    $tool = __DIR__ . '/../bin/sign-rules.php';
    $k = Proc::run([PHP_BINARY, $tool, 'keygen'], 20);
    assertSame(0, $k['exit'], $k['err']);
    preg_match('/public key[^:]*: (\S+)/', $k['out'], $pm);
    preg_match('/secret key[^:]*: (\S+)/', $k['out'], $sm);
    file_put_contents($dir . '/secret.key', $sm[1]);
    file_put_contents($dir . '/rules.json', rulesBundle(9));
    $s = Proc::run([PHP_BINARY, $tool, 'sign', $dir . '/rules.json', $dir . '/secret.key'], 20);
    assertSame(0, $s['exit'], $s['err']);
    assertTrue(is_file($dir . '/rules.json.sig') && is_file($dir . '/rules.json.sha256'));

    [$u, $state, $http] = updaterFor(['rules_public_key' => $pm[1]]);
    $http->route('https://rules.example/rules.json.sig', 200, (string)file_get_contents($dir . '/rules.json.sig'));
    $http->route('https://rules.example/rules.json', 200, (string)file_get_contents($dir . '/rules.json'));
    assertContains('signature verified', implode("\n", $u->update()));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php RulesUpdater`
Expected: `Class "Sentinel\RulesUpdater" not found`.

- [ ] **Step 3: Implement the updater**

```php file=src/RulesUpdater.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class RulesUpdater
{
    private $config;
    private $state;
    private $http;
    private $self;

    public function __construct(Config $config, State $state, HttpClient $http, SelfCheck $self)
    {
        $this->config = $config;
        $this->state = $state;
        $this->http = $http;
        $this->self = $self;
    }

    /**
     * @return string[] output lines
     * @throws \RuntimeException when the bundle cannot be fetched, verified or installed
     */
    public function update(): array
    {
        $url = $this->config->rulesUrl;
        if ($url === '') {
            throw new \RuntimeException('rules_url is not set in the config; set it to the address of a rules.json bundle');
        }
        $bundle = $this->fetch($url, 'rules bundle');
        $lines = [];

        if (function_exists('sodium_crypto_sign_verify_detached') && $this->config->rulesPublicKey !== '') {
            $sig = base64_decode(trim($this->fetch($url . '.sig', 'rules signature')), true);
            $key = base64_decode($this->config->rulesPublicKey, true);
            if ($sig === false || $key === false
                || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES
                || strlen($key) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
                || !sodium_crypto_sign_verify_detached($sig, $bundle, $key)) {
                throw new \RuntimeException('rules signature verification FAILED; the bundle was discarded');
            }
            $lines[] = 'signature verified';
        } elseif ($this->config->allowUnsignedRules) {
            $expected = strtolower((string)strtok(trim($this->fetch($url . '.sha256', 'rules checksum')), " \t\r\n"));
            if (!hash_equals($expected, hash('sha256', $bundle))) {
                throw new \RuntimeException('rules checksum mismatch; the bundle was discarded');
            }
            $lines[] = 'WARNING: only the SHA-256 checksum was checked. That protects against corruption but NOT against a compromised rules server. Set rules_public_key and install the sodium extension for signed bundles.';
        } else {
            throw new \RuntimeException('refusing to install unsigned rules: the sodium extension and rules_public_key are required (or set allow_unsigned_rules to true to accept the weaker SHA-256 check)');
        }

        $data = json_decode($bundle, true);
        if (!is_array($data)) {
            throw new \RuntimeException('the rules bundle is not valid JSON');
        }
        $new = Rules::fromArray($data);

        $file = $this->state->path('rules.json');
        $installed = -1;
        if (is_file($file)) {
            try {
                $installed = Rules::load($file)->version;
            } catch (\Throwable $e) {
                $installed = -1;
            }
        }
        if ($new->version < $installed) {
            throw new \RuntimeException(sprintf('refusing to install rules version %d: older than the installed version %d', $new->version, $installed));
        }
        if ($new->version === $installed) {
            return array_merge($lines, [sprintf('rules already up to date (version %d)', $installed)]);
        }

        $tmp = $file . '.tmp';
        if (file_put_contents($tmp, $bundle) === false) {
            throw new \RuntimeException('cannot write ' . $tmp);
        }
        @chmod($tmp, 0600);
        if (!rename($tmp, $file)) {
            @unlink($tmp);
            throw new \RuntimeException('cannot install ' . $file);
        }
        $this->self->record();
        $lines[] = sprintf('installed rules version %d (%d pattern(s), %d known-bad hash(es))', $new->version, count($new->patterns), count($new->hashes));
        return $lines;
    }

    private function fetch(string $url, string $what): string
    {
        $r = $this->http->request('GET', $url, '', [], 30);
        if ($r['status'] !== 200) {
            throw new \RuntimeException(sprintf('could not download the %s (%s)', $what, $r['status'] === 0 ? 'network error' : 'HTTP ' . $r['status']));
        }
        return $r['body'];
    }
}
```

- [ ] **Step 4: Implement the signing tool**

```php file=bin/sign-rules.php
#!/usr/bin/env php
<?php
declare(strict_types=1);

// Maintainer tool for signing rules bundles.
//   php bin/sign-rules.php keygen
//   php bin/sign-rules.php sign rules.json secret.key
// Requires the sodium extension.

if (!function_exists('sodium_crypto_sign_keypair')) {
    fwrite(STDERR, "the sodium extension is required\n");
    exit(2);
}

$cmd = $argv[1] ?? '';
if ($cmd === 'keygen') {
    $kp = sodium_crypto_sign_keypair();
    echo 'public key (put in rules_public_key): ' . base64_encode(sodium_crypto_sign_publickey($kp)) . "\n";
    echo 'secret key (keep offline, pass to sign): ' . base64_encode(sodium_crypto_sign_secretkey($kp)) . "\n";
    exit(0);
}
if ($cmd === 'sign' && isset($argv[2], $argv[3])) {
    $data = file_get_contents($argv[2]);
    $secret = base64_decode(trim((string)file_get_contents($argv[3])), true);
    if ($data === false || $secret === false || strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
        fwrite(STDERR, "cannot read the bundle or the secret key is invalid\n");
        exit(2);
    }
    file_put_contents($argv[2] . '.sig', base64_encode(sodium_crypto_sign_detached($data, $secret)) . "\n");
    file_put_contents($argv[2] . '.sha256', hash('sha256', $data) . '  ' . basename($argv[2]) . "\n");
    echo 'wrote ' . $argv[2] . ".sig and " . $argv[2] . ".sha256\n";
    exit(0);
}
fwrite(STDERR, "usage: php bin/sign-rules.php keygen | sign <rules.json> <secret-key-file>\n");
exit(2);
```

- [ ] **Step 5: Register and run**

Edit `build/files.php`: add `'RulesUpdater.php',`.

Run: `php tests/run.php RulesUpdater && php -l bin/sign-rules.php && php build/compat.php`
Expected: tests `ok` (the two sodium tests report `skip` where the extension is missing), `No syntax errors`, `PHP 7.4 compatibility: OK`. If you have a PHP with sodium (any standard PHP 7.2+ build has it), run the suite there once so the signature path is exercised.

- [ ] **Step 6: Commit**

```bash
git add src/RulesUpdater.php bin/sign-rules.php build/files.php tests/test_rules_update.php
git commit -m "feat: verified rules updates and signing tool"
```

---

### Task 16: Init, accept and the command-line interface

**Files:**
- Create: `src/Init.php`, `src/Accept.php`, `src/Cli.php`
- Test: `tests/test_cli.php`
- Modify: `build/files.php` (add `'Init.php', 'Accept.php', 'Cli.php',` after `'RulesUpdater.php',`)

**Interfaces:**
- Consumes: everything above.
- Produces: `Init::run(array $opts, string $script, HttpClient $http): array` returning `['exit'=>int, 'lines'=>string[]]`. Options (all strings except flags): `root` (required), one or more of `email` (comma-separated), `ntfy`, `webhook`, `file` (required: at least one), `name`, `profile`, `config`, `state`, `force` (flag), `no-wp-checksums` (flag). Defaults: config `<script dir>/sentinel.json`, state `<script dir>/sentinel-state`, name `<hostname> <root basename>`. Behaviour: refuses to overwrite an existing config without `force`; writes the config (mode 0600); creates the state dir; streams a full walk into a temp baseline while analyzing code/uploads/symlink/executable files in batches of 200 with `initial = true`; if any Critical finding exists and no `force`, deletes the temp baseline, prints the findings and exits 1 (config stays); otherwise installs the baseline, stores `versions.json` (WordPress), records `SelfCheck`, clears alerts and resume state, and prints a summary plus ready-to-paste cron lines (check every 10 min, full nightly, optional weekly `update-rules`), and a heartbeat suggestion.
- Produces: `Accept::run(Config $c, State $s, array $paths, bool $self, array $selfFiles): array` (same return shape). `$self` only records the tool files. Otherwise it does a complete full-mode diff and writes every change (or only paths equal to or below one of `$paths`) into the baseline, refreshes `versions.json`, clears `resume.json` and (when no paths were given) the alert log. Missing baseline → exit 2.
- Produces: `Cli::parse(array $args): array` (`--k=v` → `k`, `--flag` → `true`, repeated `--path=` collects into a list, bare words under `_`); `Cli::execute(array $args, string $script, ?HttpClient $http = null): array` returning `['exit'=>int, 'out'=>string[], 'err'=>string[]]` for commands `init, check, full, accept, update-rules, test-alert, version, help`; `Cli::main(array $argv): int` prints and returns the exit code. Config path: `--config=`, else `$SENTINEL_CONFIG`, else `sentinel.json` next to the script. `test-alert` exits 1 if any channel fails.

- [ ] **Step 1: Write the failing tests**

```php file=tests/test_cli.php
<?php
declare(strict_types=1);

use Sentinel\Accept;
use Sentinel\Baseline;
use Sentinel\Channel;
use Sentinel\Cli;
use Sentinel\Finding;
use Sentinel\Init;
use Sentinel\Monitor;
use Sentinel\NativeHttp;
use Sentinel\SelfCheck;
use Sentinel\State;

/** @return array{0:string,1:string,2:array,3:string} site root, tool dir, init options, alerts log */
function initFixture(array $files = [], array $extra = []): array
{
    $site = tmpdir();
    $tool = tmpdir();
    foreach ($files as $rel => $content) {
        putFile($site, $rel, $content);
    }
    putFile($tool, 'sentinel.php', '<?php // the tool');
    $alerts = $tool . '/alerts.log';
    $opts = array_merge(['root' => $site, 'file' => $alerts, 'no-wp-checksums' => true], $extra);
    return [$site, $tool, $opts, $alerts];
}

t('Cli::parse understands --k=v, flags, repeated --path and bare words', function () {
    assertSame(
        ['root' => '/x', 'force' => true, 'path' => ['a', 'b'], '_' => ['word']],
        Cli::parse(['--root=/x', '--force', '--path=a', 'word', '--path=b'])
    );
});

t('Init creates config, baseline, versions and prints cron lines', function () {
    [$site, $tool, $opts] = initFixture([
        'wp-config.php' => '<?php',
        'wp-content/plugins/foo/foo.php' => "<?php\n/*\nPlugin Name: Foo\nVersion: 1.0\n*/\n",
        'index.php' => '<?php // home',
        'readme.txt' => 'hello',
    ], ['name' => 'Client A']);
    $r = Init::run($opts, $tool . '/sentinel.php', new FakeHttp());
    assertSame(0, $r['exit'], implode("\n", $r['lines']));
    $out = implode("\n", $r['lines']);
    assertContains('profile wordpress', $out);
    assertContains('*/10 * * * * php ' . $tool . '/sentinel.php check --config=' . $tool . '/sentinel.json', $out);
    assertContains(' full --config=', $out);
    assertContains('heartbeat', $out);

    assertSame(0600, fileperms($tool . '/sentinel.json') & 0777);
    $cfg = json_decode((string)file_get_contents($tool . '/sentinel.json'), true);
    assertSame('Client A', $cfg['site_name']);
    assertSame('wordpress', $cfg['profile']);
    assertSame($tool . '/sentinel-state', $cfg['state_dir']);

    $state = new State($tool . '/sentinel-state');
    $paths = array_column(iterator_to_array(Baseline::read($state->path('baseline.txt')), false), 'path');
    assertSame(['index.php', 'readme.txt', 'wp-config.php', 'wp-content/plugins/foo/foo.php'], $paths);
    assertSame(['wp-content/plugins/foo' => '1.0'], $state->readJson('versions.json'));
    assertTrue(is_file($state->path('selfcheck.json')));
});

t('Init refuses a site that already contains malware unless forced, and never overwrites a config silently', function () {
    [$site, $tool, $opts] = initFixture(['index.php' => '<?php', 'lib/evil.php' => '<?php // SENTINEL-TEST-MALWARE-MARKER']);
    $r = Init::run($opts, $tool . '/sentinel.php', new FakeHttp());
    assertSame(1, $r['exit']);
    assertContains('lib/evil.php', implode("\n", $r['lines']));
    assertContains('--force', implode("\n", $r['lines']));
    assertTrue(!is_file($tool . '/sentinel-state/baseline.txt'));
    assertTrue(!is_file($tool . '/sentinel-state/baseline.init'), 'temp baseline removed');

    $again = Init::run($opts, $tool . '/sentinel.php', new FakeHttp());
    assertSame(2, $again['exit']);
    assertContains('already exists', implode("\n", $again['lines']));

    $forced = Init::run(array_merge($opts, ['force' => true]), $tool . '/sentinel.php', new FakeHttp());
    assertSame(0, $forced['exit']);
    assertContains('WARNING', implode("\n", $forced['lines']));
    assertTrue(is_file($tool . '/sentinel-state/baseline.txt'));
});

t('Init validates its options', function () {
    [$site, $tool, $opts] = initFixture();
    $noRoot = $opts;
    unset($noRoot['root']);
    assertSame(2, Init::run($noRoot, $tool . '/sentinel.php', new FakeHttp())['exit']);
    $noChannel = $opts;
    unset($noChannel['file']);
    $r = Init::run($noChannel, $tool . '/sentinel.php', new FakeHttp());
    assertSame(2, $r['exit']);
    assertContains('alert channel', implode("\n", $r['lines']));
    $badEmail = Init::run(array_merge($noChannel, ['email' => 'nope']), $tool . '/sentinel.php', new FakeHttp());
    assertSame(2, $badEmail['exit']);
});

t('Init with tool files inside the site root leaves them out of the baseline (Review Focus 3)', function () {
    [$site, , $opts] = initFixture(['index.php' => '<?php']);
    putFile($site, 'sentinel.php', '<?php // tool');
    $r = Init::run(array_merge($opts, ['config' => $site . '/sentinel.json', 'state' => $site . '/.sentinel']), $site . '/sentinel.php', new FakeHttp());
    assertSame(0, $r['exit'], implode("\n", $r['lines']));
    $paths = array_column(iterator_to_array(Baseline::read($site . '/.sentinel/baseline.txt'), false), 'path');
    assertSame(['index.php'], $paths);
});

t('After init a check is clean, and accept makes held changes known-good', function () {
    [$site, $tool, $opts] = initFixture(['index.php' => '<?php', 'lib/a.php' => '<?php // a', 'lib/b.php' => '<?php // b']);
    Init::run($opts, $tool . '/sentinel.php', new FakeHttp());
    $config = \Sentinel\Config::load($tool . '/sentinel.json');
    $state = new State($config->stateDir);
    $notifier = new FakeNotifier();
    $selfFiles = ['script' => $tool . '/sentinel.php', 'config' => $tool . '/sentinel.json', 'rules' => $state->path('rules.json')];
    $m = new Monitor($config, $state, new FakeHttp(), [new Channel($notifier, Finding::WARNING)], $selfFiles, new FakeClock());
    assertSame(0, $m->run('check')['exit']);

    bump($site, 'lib/a.php', '<?php // a edited');
    bump($site, 'lib/b.php', '<?php // b edited');
    assertSame(1, $m->run('check')['exit']);
    assertSame(1, count($notifier->sent));

    $r = Accept::run($config, $state, ['lib/a.php'], false, $selfFiles);
    assertSame(0, $r['exit']);
    assertContains('1 change(s)', implode("\n", $r['lines']));
    $after = $m->run('check');
    assertSame(1, $after['exit']);
    assertSame(2, count($notifier->sent), 'the remaining set of changes is a new finding');
    $latest = $notifier->sent[1]['body'];
    assertContains('lib/b.php', $latest);
    assertNotContains('lib/a.php', $latest);

    $all = Accept::run($config, $state, [], false, $selfFiles);
    assertContains('1 change(s)', implode("\n", $all['lines']));
    assertSame(0, $m->run('check')['exit']);
    assertSame([], $state->readJson('alerts.json'), 'accepting everything clears the alert log');
});

t('Accept --self re-trusts the tool files and a missing baseline is an error', function () {
    [$site, $tool, $opts] = initFixture(['index.php' => '<?php']);
    Init::run($opts, $tool . '/sentinel.php', new FakeHttp());
    $config = \Sentinel\Config::load($tool . '/sentinel.json');
    $state = new State($config->stateDir);
    $selfFiles = ['script' => $tool . '/sentinel.php'];
    file_put_contents($tool . '/sentinel.php', '<?php // upgraded');
    assertSame(1, count((new SelfCheck($state, $selfFiles))->check()));
    $r = Accept::run($config, $state, [], true, $selfFiles);
    assertSame(0, $r['exit']);
    assertSame([], (new SelfCheck($state, $selfFiles))->check());

    unlink($state->path('baseline.txt'));
    assertSame(2, Accept::run($config, $state, [], false, $selfFiles)['exit']);
});

t('Cli runs commands end to end with a config file', function () {
    [$site, $tool, $opts, $alerts] = initFixture(['index.php' => '<?php']);
    $script = $tool . '/sentinel.php';

    $init = Cli::execute(['init', '--root=' . $site, '--file=' . $alerts, '--no-wp-checksums'], $script, new FakeHttp());
    assertSame(0, $init['exit'], implode("\n", $init['out']) . implode("\n", $init['err']));

    $check = Cli::execute(['check', '--config=' . $tool . '/sentinel.json'], $script, new FakeHttp());
    assertSame(0, $check['exit']);
    assertContains('0 change(s)', $check['out'][0]);

    $test = Cli::execute(['test-alert', '--config=' . $tool . '/sentinel.json'], $script, new FakeHttp());
    assertSame(0, $test['exit']);
    assertContains('file: sent', implode("\n", $test['out']));
    assertContains('TEST', (string)file_get_contents($alerts));

    putFile($site, 'evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $bad = Cli::execute(['check', '--config=' . $tool . '/sentinel.json'], $script, new FakeHttp());
    assertSame(1, $bad['exit']);
    assertContains('evil.php', implode("\n", $bad['out']));

    $upd = Cli::execute(['update-rules', '--config=' . $tool . '/sentinel.json'], $script, new FakeHttp());
    assertSame(2, $upd['exit']);
    assertContains('rules_url', implode("\n", $upd['err']));
});

t('Cli reports usage errors, missing config and versions', function () {
    $v = Cli::execute(['version'], '/x/sentinel.php');
    assertSame(0, $v['exit']);
    assertSame(\Sentinel\VERSION, $v['out'][0]);
    $h = Cli::execute(['help'], '/x/sentinel.php');
    assertSame(0, $h['exit']);
    assertContains('update-rules', implode("\n", $h['out']));
    $none = Cli::execute([], '/x/sentinel.php');
    assertSame(0, $none['exit']);
    $bad = Cli::execute(['frobnicate'], '/x/sentinel.php');
    assertSame(2, $bad['exit']);
    assertContains('unknown command', implode("\n", $bad['err']));
    $noConfig = Cli::execute(['check', '--config=/nonexistent/sentinel.json'], '/x/sentinel.php');
    assertSame(2, $noConfig['exit']);
    assertContains('cannot read config', implode("\n", $noConfig['err']));
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php Init`
Expected: `Class "Sentinel\Init" not found`.

- [ ] **Step 3: Implement init**

```php file=src/Init.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Init
{
    private const BATCH = 200;

    /**
     * @param array<string,mixed> $o options, see Cli::parse
     * @return array{exit:int, lines:string[]}
     */
    public static function run(array $o, string $script, HttpClient $http): array
    {
        $root = (string)($o['root'] ?? '');
        if ($root === '' || !is_dir($root)) {
            return self::fail('--root=/path/to/site is required and must be an existing directory');
        }
        $dir = dirname($script);
        $configFile = (string)($o['config'] ?? $dir . '/sentinel.json');
        $stateDir = (string)($o['state'] ?? $dir . '/sentinel-state');
        $force = !empty($o['force']);
        if (is_file($configFile) && !$force) {
            return self::fail("$configFile already exists; use --force to overwrite it");
        }

        $channels = [];
        if (!empty($o['email'])) {
            $channels[] = ['type' => 'email', 'to' => array_map('trim', explode(',', (string)$o['email']))];
        }
        if (!empty($o['ntfy'])) {
            $channels[] = ['type' => 'ntfy', 'url' => (string)$o['ntfy']];
        }
        if (!empty($o['webhook'])) {
            $channels[] = ['type' => 'webhook', 'url' => (string)$o['webhook']];
        }
        if (!empty($o['file'])) {
            $channels[] = ['type' => 'file', 'path' => (string)$o['file']];
        }
        if (!$channels) {
            return self::fail('at least one alert channel is required: --email=a@b.c[,d@e.f], --ntfy=URL, --webhook=URL or --file=/abs/path/alerts.log');
        }

        $real = (string)realpath($root);
        $raw = [
            'site_name' => (string)($o['name'] ?? trim((string)gethostname() . ' ' . basename($real))),
            'site_root' => $root,
            'state_dir' => $stateDir,
            'channels' => $channels,
            'wp_checksums' => empty($o['no-wp-checksums']),
        ];
        if (!empty($o['profile'])) {
            $raw['profile'] = (string)$o['profile'];
        }
        try {
            $config = Config::fromArray($raw);
        } catch (ConfigException $e) {
            return self::fail($e->getMessage());
        }

        $json = json_encode($config->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false || file_put_contents($configFile, $json . "\n") === false) {
            return self::fail("cannot write $configFile");
        }
        @chmod($configFile, 0600);

        $config->addExclusion($script);
        $config->addExclusion($configFile);
        $state = new State($config->stateDir);
        $rulesFile = $state->path('rules.json');
        $rules = is_file($rulesFile) ? Rules::load($rulesFile) : Rules::builtin();
        $wpOn = $config->profile === 'wordpress';
        $wp = $wpOn && $config->wpChecksums ? new WpChecksum($http, $config, $state->path('cache')) : null;
        $analyzer = new Analyzer(
            $config,
            new PatternScanner($rules, $config->maxScanBytes),
            new LocationScanner($config),
            $wp,
            ExternalScanner::fromConfig($config)
        );

        $differ = new Differ($config);
        $findings = [];
        $notes = [];
        $tmp = $state->path('baseline.init');
        $records = (function () use ($config, $differ, $analyzer, &$findings, &$notes) {
            $batch = [];
            foreach ((new Walker($config))->walk() as $meta) {
                [$rec, $unreadable] = $differ->record($meta);
                if ($analyzer->wantsAnalysis($rec)) {
                    $batch[] = ['type' => 'new', 'path' => $rec['path'], 'old' => null, 'new' => $rec, 'stealth' => false, 'content_same' => false, 'unreadable' => $unreadable];
                    if (count($batch) >= self::BATCH) {
                        self::flush($analyzer, $batch, $findings, $notes);
                    }
                }
                yield $rec;
            }
            self::flush($analyzer, $batch, $findings, $notes);
        })();
        $count = Baseline::write($tmp, $records);

        $lines = [];
        if ($findings && !$force) {
            @unlink($tmp);
            $lines[] = 'The site already contains files that look malicious, so no baseline was created';
            $lines[] = '(a baseline taken now would treat them as known-good):';
            foreach ($findings as $f) {
                $lines[] = '  ' . Finding::label($f->severity) . ' ' . $f->path . ' ' . $f->rule . ': ' . $f->message;
            }
            $lines[] = 'Clean the site, then run init again. To accept the risk and baseline anyway, add --force.';
            return ['exit' => 1, 'lines' => $lines];
        }
        if (!rename($tmp, $state->path('baseline.txt'))) {
            @unlink($tmp);
            return self::fail('cannot install the baseline');
        }

        if ($wpOn) {
            $state->writeJson('versions.json', VersionTracker::read($config));
        }
        $selfFiles = self::selfFiles($script, $configFile, $state);
        (new SelfCheck($state, $selfFiles))->record();
        (new AlertLog($state))->clear();
        @unlink($state->path('resume.json'));

        $lines[] = sprintf('Created %s (profile %s) and a baseline of %d file(s).', $configFile, $config->profile, $count);
        foreach ($findings as $f) {
            $lines[] = 'WARNING: baselined despite ' . Finding::label($f->severity) . ' ' . $f->path . ' (' . $f->rule . ')';
        }
        foreach (array_unique($notes) as $n) {
            $lines[] = 'note: ' . $n;
        }
        $lines[] = '';
        $lines[] = 'Add these lines to the crontab of the account that owns the site (crontab -e, or cPanel > Cron Jobs):';
        $lines[] = '*/10 * * * * php ' . $script . ' check --config=' . $configFile . ' >/dev/null 2>&1';
        $lines[] = '17 3 * * * php ' . $script . ' full --config=' . $configFile . ' >/dev/null 2>&1';
        $lines[] = '# optional, once a rules_url is configured:';
        $lines[] = '# 41 4 * * 1 php ' . $script . ' update-rules --config=' . $configFile . ' >/dev/null 2>&1';
        $lines[] = '';
        $lines[] = 'Next: run "php ' . $script . ' test-alert --config=' . $configFile . '" to confirm alerts arrive.';
        $lines[] = 'Recommended: set heartbeat_url in the config to a healthchecks.io-style URL so you are told if Sentinel stops running.';
        return ['exit' => 0, 'lines' => $lines];
    }

    /** @return array<string,string> */
    public static function selfFiles(string $script, string $configFile, State $state): array
    {
        $s = realpath($script);
        $c = realpath($configFile);
        return [
            'script' => $s !== false ? $s : $script,
            'config' => $c !== false ? $c : $configFile,
            'rules' => $state->path('rules.json'),
        ];
    }

    private static function flush(Analyzer $analyzer, array &$batch, array &$findings, array &$notes): void
    {
        if (!$batch) {
            return;
        }
        $r = $analyzer->analyze($batch, [], [], true);
        foreach ($r['findings'] as $f) {
            $findings[] = $f;
        }
        foreach ($r['notes'] as $n) {
            $notes[] = $n;
        }
        $batch = [];
    }

    private static function fail(string $msg): array
    {
        return ['exit' => 2, 'lines' => [$msg]];
    }
}
```


- [ ] **Step 4: Implement accept**

```php file=src/Accept.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Accept
{
    /**
     * @param string[] $paths relative paths to accept (a directory accepts everything below it); empty = everything
     * @param array<string,string> $selfFiles
     * @return array{exit:int, lines:string[]}
     */
    public static function run(Config $config, State $state, array $paths, bool $self, array $selfFiles): array
    {
        if ($self) {
            (new SelfCheck($state, $selfFiles))->record();
            return ['exit' => 0, 'lines' => ['recorded the current Sentinel files as trusted']];
        }
        $baselineFile = $state->path('baseline.txt');
        if (!is_file($baselineFile)) {
            return ['exit' => 2, 'lines' => ['no baseline found; run "init" first']];
        }
        $paths = array_values(array_filter(array_map(function ($p) {
            return trim((string)$p, '/');
        }, $paths), function ($p) {
            return $p !== '';
        }));

        $d = (new Differ($config))->diff($baselineFile, '', new Budget(86400.0, PHP_INT_MAX), true);
        $updates = [];
        foreach ($d['changes'] as $c) {
            if ($paths && !self::wanted((string)$c['path'], $paths)) {
                continue;
            }
            $updates[$c['path']] = in_array($c['type'], ['removed', 'dropped'], true) ? null : $c['new'];
        }
        if ($updates) {
            Baseline::applyUpdates($baselineFile, $updates, $baselineFile);
        }

        if ($config->profile === 'wordpress') {
            $current = VersionTracker::read($config);
            if (!$paths) {
                $state->writeJson('versions.json', $current);
            } else {
                $store = $state->readJson('versions.json');
                foreach ($current as $g => $v) {
                    foreach ($paths as $p) {
                        if ($p === $g || strpos($p, $g . '/') === 0 || strpos($g, $p . '/') === 0) {
                            $store[$g] = $v;
                        }
                    }
                }
                $state->writeJson('versions.json', $store);
            }
        }
        @unlink($state->path('resume.json'));
        if (!$paths) {
            (new AlertLog($state))->clear();
        }
        return ['exit' => 0, 'lines' => [sprintf('accepted %d change(s)', count($updates))]];
    }

    private static function wanted(string $path, array $paths): bool
    {
        foreach ($paths as $p) {
            if ($path === $p || strpos($path, $p . '/') === 0) {
                return true;
            }
        }
        return false;
    }
}
```

- [ ] **Step 5: Implement the CLI**

```php file=src/Cli.php
<?php
declare(strict_types=1);

namespace Sentinel;

final class Cli
{
    private const USAGE = <<<'TXT'
Site Sentinel %s - file-integrity and malware monitor

Usage: php sentinel.php <command> [options]

Commands:
  init          --root=DIR and at least one of --email=A[,B] --ntfy=URL --webhook=URL --file=PATH
                [--name=NAME] [--profile=wordpress|generic] [--config=FILE] [--state=DIR]
                [--no-wp-checksums] [--force]
  check         quick scan of new and changed files (run every few minutes)
  full          full scan: hash everything, verify WordPress checksums (run nightly)
  accept        accept the current state as known-good [--path=REL ...] [--self]
  update-rules  download, verify and install the latest rules bundle
  test-alert    send a test alert through every configured channel
  version       print the version

All commands except init read --config=FILE (default: $SENTINEL_CONFIG, else sentinel.json next to this script).
Exit codes: 0 clean, 1 findings reported, 2 tool error.
TXT;

    /** @return array<string,mixed> */
    public static function parse(array $args): array
    {
        $o = [];
        foreach ($args as $a) {
            $a = (string)$a;
            if (strncmp($a, '--', 2) !== 0) {
                $o['_'][] = $a;
                continue;
            }
            $a = substr($a, 2);
            $eq = strpos($a, '=');
            if ($eq === false) {
                $o[$a] = true;
                continue;
            }
            $k = substr($a, 0, $eq);
            $v = substr($a, $eq + 1);
            if ($k === 'path') {
                $o['path'][] = $v;
            } else {
                $o[$k] = $v;
            }
        }
        return $o;
    }

    public static function main(array $argv): int
    {
        $r = self::execute(array_slice($argv, 1), (string)($argv[0] ?? 'sentinel.php'));
        foreach ($r['out'] as $line) {
            fwrite(STDOUT, $line . "\n");
        }
        foreach ($r['err'] as $line) {
            fwrite(STDERR, $line . "\n");
        }
        return $r['exit'];
    }

    /** @return array{exit:int, out:string[], err:string[]} */
    public static function execute(array $args, string $script, ?HttpClient $http = null): array
    {
        $cmd = $args ? (string)array_shift($args) : 'help';
        $opts = self::parse($args);
        if ($cmd === 'version' || $cmd === '--version') {
            return ['exit' => 0, 'out' => [VERSION], 'err' => []];
        }
        if (in_array($cmd, ['help', '--help', '-h'], true)) {
            return ['exit' => 0, 'out' => explode("\n", sprintf(self::USAGE, VERSION)), 'err' => []];
        }
        $http = $http ?? new NativeHttp();
        $real = realpath($script);
        $script = $real !== false ? $real : $script;

        try {
            if ($cmd === 'init') {
                return self::result(Init::run($opts, $script, $http));
            }
            if (!in_array($cmd, ['check', 'full', 'accept', 'update-rules', 'test-alert'], true)) {
                return ['exit' => 2, 'out' => [], 'err' => array_merge(["unknown command '$cmd'", ''], explode("\n", sprintf(self::USAGE, VERSION)))];
            }
            $configFile = isset($opts['config']) && is_string($opts['config'])
                ? $opts['config']
                : ((string)getenv('SENTINEL_CONFIG') !== '' ? (string)getenv('SENTINEL_CONFIG') : dirname($script) . '/sentinel.json');
            $config = Config::load($configFile);
            $config->addExclusion($script);
            $config->addExclusion($configFile);
            $state = new State($config->stateDir);
            $channels = NotifierFactory::fromConfig($config, $http);
            $selfFiles = Init::selfFiles($script, $configFile, $state);

            switch ($cmd) {
                case 'check':
                case 'full':
                    return self::result((new Monitor($config, $state, $http, $channels, $selfFiles))->run($cmd));
                case 'accept':
                    return self::result(Accept::run($config, $state, (array)($opts['path'] ?? []), !empty($opts['self']), $selfFiles));
                case 'update-rules':
                    $lines = (new RulesUpdater($config, $state, $http, new SelfCheck($state, $selfFiles)))->update();
                    return ['exit' => 0, 'out' => $lines, 'err' => []];
                default:
                    return self::testAlert($config, $channels);
            }
        } catch (\Throwable $e) {
            return ['exit' => 2, 'out' => [], 'err' => ['error: ' . $e->getMessage()]];
        }
    }

    /** @param Channel[] $channels */
    private static function testAlert(Config $config, array $channels): array
    {
        if (!$channels) {
            return ['exit' => 2, 'out' => [], 'err' => ['no alert channels configured']];
        }
        $subject = '[Sentinel][TEST] ' . $config->siteName;
        $body = "This is a test alert from Site Sentinel.\nSite: " . $config->siteName . "\nHost: " . gethostname() . "\nTime: " . gmdate('Y-m-d H:i:s') . " UTC\n\nIf you can read this, alerts for this site will reach you.\n";
        $r = (new Alerter($channels))->send($subject, $body, Finding::CRITICAL);
        $failed = false;
        foreach ($r['results'] as $line) {
            $failed = $failed || strpos($line, 'FAILED') !== false;
        }
        return ['exit' => $failed ? 1 : 0, 'out' => $r['results'], 'err' => []];
    }

    /** @param array{exit:int, lines:string[]} $r */
    private static function result(array $r): array
    {
        return $r['exit'] === 2
            ? ['exit' => 2, 'out' => [], 'err' => $r['lines']]
            : ['exit' => $r['exit'], 'out' => $r['lines'], 'err' => []];
    }
}
```

Note: `Cli::result` routes tool errors (exit 2) to stderr and normal output to stdout.

- [ ] **Step 6: Register and run**

Edit `build/files.php`: add `'Init.php', 'Accept.php', 'Cli.php',`.

Run: `php tests/run.php Init && php tests/run.php Accept && php tests/run.php Cli && php tests/run.php "After init"`
Expected: all `ok`.

- [ ] **Step 7: Commit**

```bash
git add src build/files.php tests/test_cli.php
git commit -m "feat: init, accept and the command-line interface"
```

---

### Task 17: Build, end-to-end test, examples and documentation

**Files:**
- Create: `build/build.php`, `tests/test_e2e.php`, `examples/sentinel.json`, `examples/systemd/sentinel-check.service`, `examples/systemd/sentinel-check.timer`, `examples/systemd/sentinel-full.service`, `examples/systemd/sentinel-full.timer`, `README.md`, `docs/RULES.md`
- Modify: none

**Interfaces:**
- Produces: `php build/build.php [output]` writes the single distributable (default `dist/sentinel.php`; run it as `php sentinel.php`, it has no shebang on purpose): `<?php declare(strict_types=1); namespace Sentinel;`, `const VERSION`, a guard that answers 404 and exits when not run from the CLI (so the script can never be driven through a web server), every `src/` file in `build/files.php` order with its header stripped, and a final `exit(Cli::main($argv));`.
- Produces: an end-to-end test that builds the file, places the script, config and state **inside** the site root (Review Focus 3), and drives `init`, `check`, `full`, `accept` through a realistic WordPress-shaped site as a subprocess.

- [ ] **Step 1: Write the failing end-to-end tests**

```php file=tests/test_e2e.php
<?php
declare(strict_types=1);

use Sentinel\Config;
use Sentinel\NativeHttp;
use Sentinel\Proc;

function buildDist(string $target): void
{
    $r = Proc::run([PHP_BINARY, __DIR__ . '/../build/build.php', $target], 60);
    assertSame(0, $r['exit'], $r['out'] . $r['err']);
}

/** @return array{exit:int, out:string, err:string} */
function sentinel(string $dist, array $args): array
{
    $r = Proc::run(array_merge([PHP_BINARY, $dist], $args), 120);
    return ['exit' => $r['exit'], 'out' => $r['out'], 'err' => $r['err']];
}

function plugin(string $version, string $body): string
{
    return "<?php\n/*\nPlugin Name: Foo\nVersion: $version\n*/\n// $body\n";
}

t('build produces a valid single file that reports its version and usage', function () {
    $dist = tmpdir() . '/sentinel.php';
    buildDist($dist);
    $lint = Proc::run([PHP_BINARY, '-l', $dist], 30);
    assertSame(0, $lint['exit'], $lint['out'] . $lint['err']);
    assertSame(trim((string)file_get_contents(__DIR__ . '/../VERSION')), trim(sentinel($dist, ['version'])['out']));
    assertContains('update-rules', sentinel($dist, ['help'])['out']);
    // No shebang: under a web server it would be emitted as output ahead of declare(strict_types).
    assertSame('<?php', substr((string)file_get_contents($dist), 0, 5));
});

t('the built script refuses to run under a web server (answers 404, prints nothing)', function () {
    $docroot = tmpdir();
    buildDist($docroot . '/sentinel.php');
    $sock = stream_socket_server('tcp://127.0.0.1:0');
    $name = stream_socket_get_name($sock, false);
    $port = (int)substr($name, (int)strrpos($name, ':') + 1);
    fclose($sock);
    $proc = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', $docroot], [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    try {
        for ($i = 0; $i < 50; $i++) {
            $c = @fsockopen('127.0.0.1', $port, $en, $es, 0.2);
            if ($c) {
                fclose($c);
                break;
            }
            usleep(100000);
        }
        $r = (new NativeHttp())->request('GET', "http://127.0.0.1:$port/sentinel.php", '', [], 5);
        assertSame(404, $r['status']);
        assertSame('', $r['body']);
    } finally {
        proc_terminate($proc);
        proc_close($proc);
    }
});

t('end to end: a WordPress site with the tool installed inside the web root', function () {
    $site = tmpdir();
    $out = tmpdir();
    $alerts = $out . '/alerts.log';
    $dist = $site . '/sentinel.php';
    buildDist($dist);
    putFile($site, 'wp-config.php', '<?php // config');
    putFile($site, 'wp-includes/version.php', "<?php\n\$wp_version = '6.4.2';\n");
    putFile($site, 'index.php', '<?php // front controller');
    putFile($site, 'wp-content/plugins/foo/foo.php', plugin('1.0', 'v1'));
    putFile($site, 'wp-content/uploads/2026/photo.jpg', 'GIF89a');
    putFile($site, 'wp-content/cache/page.html', '<html>');
    $cfg = ['--config=' . $site . '/sentinel.json'];

    $init = sentinel($dist, ['init', '--root=' . $site, '--file=' . $alerts, '--no-wp-checksums', '--name=E2E', '--config=' . $site . '/sentinel.json', '--state=' . $site . '/.sentinel']);
    assertSame(0, $init['exit'], $init['out'] . $init['err']);
    assertContains('profile wordpress', $init['out']);
    assertContains('*/10 * * * * php', $init['out']);

    // Everything the tool put inside the web root is invisible to it.
    $clean = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(0, $clean['exit'], $clean['out'] . $clean['err']);
    assertContains('0 change(s)', $clean['out']);
    assertTrue(!is_file($alerts), 'no alert for a clean site');

    // PHP in uploads: Critical, alerted once.
    putFile($site, 'wp-content/uploads/2026/x.php', '<?php echo 1;');
    $r = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(1, $r['exit'], $r['out'] . $r['err']);
    assertContains('php-in-uploads', $r['out']);
    assertSame(1, substr_count((string)file_get_contents($alerts), 'php-in-uploads: PHP file in the uploads directory'));
    sentinel($dist, array_merge(['check'], $cfg));
    assertSame(1, substr_count((string)file_get_contents($alerts), 'php-in-uploads: PHP file in the uploads directory'), 'second run does not re-alert');

    // Malware marker in a plugin.
    putFile($site, 'wp-content/plugins/foo/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $r = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(1, $r['exit']);
    assertContains('test-marker', (string)file_get_contents($alerts));

    // Cleaning up returns the site to clean.
    unlink($site . '/wp-content/uploads/2026/x.php');
    unlink($site . '/wp-content/plugins/foo/evil.php');
    assertSame(0, sentinel($dist, array_merge(['check'], $cfg))['exit']);

    // A real plugin update (version bump) is silent.
    $before = (string)file_get_contents($alerts);
    bump($site, 'wp-content/plugins/foo/foo.php', plugin('1.1', 'v2'));
    $r = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(0, $r['exit'], $r['out'] . $r['err']);
    assertSame($before, (string)file_get_contents($alerts));

    // A quiet edit without a version change is a Warning; accept clears it.
    bump($site, 'wp-content/plugins/foo/foo.php', plugin('1.1', 'quietly changed'), 200);
    $r = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(1, $r['exit']);
    assertContains('unexplained-change', (string)file_get_contents($alerts));
    assertSame(0, sentinel($dist, array_merge(['accept'], $cfg))['exit']);
    assertSame(0, sentinel($dist, array_merge(['check'], $cfg))['exit']);
    assertSame(0, sentinel($dist, array_merge(['full'], $cfg))['exit']);

    // Replacing the script is tampering until it is accepted.
    file_put_contents($dist, "\n// modified\n", FILE_APPEND);
    $r = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(1, $r['exit']);
    assertContains('self-tamper', (string)file_get_contents($alerts));
    assertSame(0, sentinel($dist, array_merge(['accept', '--self'], $cfg))['exit']);
    assertSame(0, sentinel($dist, array_merge(['check'], $cfg))['exit']);

    // Losing the baseline is an error, never a flood of "new" files.
    unlink($site . '/.sentinel/baseline.txt');
    $r = sentinel($dist, array_merge(['check'], $cfg));
    assertSame(2, $r['exit']);
    assertContains('no baseline', $r['err']);
});

t('end to end: init refuses an infected site unless forced', function () {
    $site = tmpdir();
    $out = tmpdir();
    $dist = $out . '/sentinel.php';
    buildDist($dist);
    putFile($site, 'index.php', '<?php');
    putFile($site, 'lib/evil.php', '<?php // SENTINEL-TEST-MALWARE-MARKER');
    $args = ['init', '--root=' . $site, '--file=' . $out . '/alerts.log', '--no-wp-checksums'];
    $r = sentinel($dist, $args);
    assertSame(1, $r['exit'], $r['out'] . $r['err']);
    assertContains('lib/evil.php', $r['out']);
    assertTrue(!is_file($out . '/sentinel-state/baseline.txt'));
    $forced = sentinel($dist, array_merge($args, ['--force']));
    assertSame(0, $forced['exit'], $forced['out'] . $forced['err']);
    assertTrue(is_file($out . '/sentinel-state/baseline.txt'));
});

t('the example config loads once its paths are filled in', function () {
    $raw = json_decode((string)file_get_contents(__DIR__ . '/../examples/sentinel.json'), true);
    assertTrue(is_array($raw));
    $raw['site_root'] = tmpdir();
    $raw['state_dir'] = tmpdir();
    $c = Config::fromArray($raw);
    assertTrue(count($c->channels) >= 3);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `php tests/run.php build`
Expected: the build script is missing (`Could not open input file`) so `build produces ...` fails.

- [ ] **Step 3: Implement the build script**

```php file=build/build.php
<?php
declare(strict_types=1);

// Usage: php build/build.php [output-file]   (default: dist/sentinel.php)
$root = dirname(__DIR__);
$files = require __DIR__ . '/files.php';
$version = trim((string)file_get_contents($root . '/VERSION'));

$out = "<?php\ndeclare(strict_types=1);\n\n"
    . "// Site Sentinel " . $version . " - file-integrity and malware monitor.\n"
    . "// License: GPL-3.0-or-later. See LICENSE in the source repository. No warranty.\n\n"
    . "namespace Sentinel;\n\n"
    . 'const VERSION = ' . var_export($version, true) . ";\n\n"
    . "// Never run through a web server, even if the file is dropped into a web root.\n"
    . "if (PHP_SAPI !== 'cli') {\n    http_response_code(404);\n    exit;\n}\n";

foreach ($files as $f) {
    $src = file_get_contents($root . '/src/' . $f);
    if ($src === false) {
        fwrite(STDERR, "missing src/$f\n");
        exit(1);
    }
    $src = preg_replace('/\A<\?php\s+declare\(strict_types=1\);\s+namespace Sentinel;\s*/', '', $src, 1, $n);
    if ($n !== 1) {
        fwrite(STDERR, "src/$f must start with <?php, declare(strict_types=1); and namespace Sentinel;\n");
        exit(1);
    }
    $out .= "\n// ---- $f ----\n" . $src;
}
$out .= "\nexit(Cli::main(\$argv));\n";

$target = $argv[1] ?? $root . '/dist/sentinel.php';
if (!is_dir(dirname($target)) && !mkdir(dirname($target), 0755, true)) {
    fwrite(STDERR, "cannot create " . dirname($target) . "\n");
    exit(1);
}
file_put_contents($target, $out);
echo 'built ' . $target . ' (' . strlen($out) . ' bytes from ' . count($files) . " files)\n";
```

- [ ] **Step 4: Create the examples**

```json file=examples/sentinel.json
{
    "site_name": "Example Client",
    "profile": "wordpress",
    "site_root": "/home/example/public_html",
    "state_dir": "/home/example/sentinel-state",
    "channels": [
        { "type": "email", "to": ["owner@example.com"], "from": "sentinel@example.com" },
        { "type": "ntfy", "url": "https://ntfy.sh/replace-with-a-long-random-topic", "min_severity": "critical" },
        { "type": "webhook", "url": "https://hooks.example.com/sentinel", "min_severity": "warning" }
    ],
    "heartbeat_url": "https://hc-ping.com/replace-with-your-uuid",
    "rules_url": "",
    "rules_public_key": "",
    "allow_unsigned_rules": false,
    "wp_checksums": true,
    "budget_seconds": 50,
    "remind_hours": 24
}
```

```text file=examples/systemd/sentinel-check.service
[Unit]
Description=Site Sentinel quick check

[Service]
Type=oneshot
User=www-data
ExecStart=/usr/bin/php /opt/sentinel/sentinel.php check --config=/opt/sentinel/sentinel.json
Nice=19
IOSchedulingClass=idle
```

```text file=examples/systemd/sentinel-check.timer
[Unit]
Description=Run the Site Sentinel quick check every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
```

```text file=examples/systemd/sentinel-full.service
[Unit]
Description=Site Sentinel full scan

[Service]
Type=oneshot
User=www-data
ExecStart=/usr/bin/php /opt/sentinel/sentinel.php full --config=/opt/sentinel/sentinel.json
Nice=19
IOSchedulingClass=idle
```

```text file=examples/systemd/sentinel-full.timer
[Unit]
Description=Run the Site Sentinel full scan nightly

[Timer]
OnCalendar=*-*-* 03:17:00
Persistent=true

[Install]
WantedBy=timers.target
```

- [ ] **Step 5: Write the documentation**

````markdown file=README.md
# Site Sentinel

A small file-integrity and malware monitor for web sites. It notices new, modified and removed files, flags anything that looks like malware, and alerts the site owner. It is one PHP file that runs from cron, so it works on shared hosting without root as well as on a dedicated server.

It **detects and alerts**. It never deletes or changes your site files, and it is not a replacement for backups, updates, strong passwords or two-factor login.

## Requirements

- PHP 7.4 or newer on the command line (`php -v`). Optional: `curl`, `sodium` (signed rule updates), `clamscan`, `yara`.
- Permission to run a cron job as the account that owns the site.

## Install

1. Get `sentinel.php` (build it with `php build/build.php`, then use `dist/sentinel.php`).
2. Put it **outside the web root**, for example `/home/you/sentinel/sentinel.php`. The config and state directory are created next to it.
3. Initialise it, giving at least one place to send alerts:

   ```
   php sentinel.php init --root=/home/you/public_html --email=owner@example.com
   ```

   `init` detects WordPress, scans the site once and refuses to create a baseline if it already finds malware (a baseline taken on an infected site would treat the malware as normal). Clean the site and run it again, or add `--force` if you accept that.
4. Paste the cron lines it prints into the crontab (`crontab -e`, or cPanel > Cron Jobs).
5. Check alerts arrive: `php sentinel.php test-alert`.
6. Recommended: set `heartbeat_url` in `sentinel.json` to a healthchecks.io-style URL. Sentinel pings it after every completed run, so you are told if it stops running or is deleted.

## Commands

| Command | Purpose |
|---|---|
| `init` | Create the config and baseline, print cron lines. |
| `check` | Quick scan (stat-only walk, then scan only new or changed files). Run every 5-10 minutes. |
| `full` | Nightly scan: hash every code file, verify WordPress core and plugin checksums. |
| `accept` | Mark the current state as known-good: everything, or `--path=wp-content/plugins/foo` (repeatable). `--self` re-trusts the Sentinel files after you upgrade them. |
| `update-rules` | Download, verify and install the latest rules bundle. |
| `test-alert` | Send a test alert through every channel. |

Exit codes: `0` clean, `1` findings reported, `2` tool error.

## What it reports

- **Critical:** known malware patterns or hashes (built in, plus anything from ClamAV/YARA if installed), PHP files in `wp-content/uploads` (including `shell.php.jpg`), PHP code hidden inside images, a WordPress core or repository-plugin file that does not match wordpress.org's official checksum, an executable newly created in a `tmp` directory, content changed while size and timestamp were left alone, and any change to Sentinel's own files.
- **Warning:** new or modified code that is not explained by an update, changes to `wp-config.php`, `.htaccess` or `mu-plugins`, new symlinks, files that became world-writable, removed core files.
- **Info:** things that were explained and accepted automatically (a plugin updated from 1.0 to 1.1, files verified against official checksums). Info appears in the next alert that is sent anyway; it never sends one by itself.

Each problem alerts once, and Critical problems remind you every `remind_hours` (default 24) until fixed or accepted. Held changes stay out of the baseline, so they keep showing in `check` output until you run `accept`.

### WordPress updates

Core and repository plugins are verified against wordpress.org checksums, so updates are recognised without help. Premium or custom plugins and themes are grouped by directory: a version bump with clean files is a quiet Info line; changes without a version change are one Warning per plugin. For other sites (`generic` profile) changes are Warnings until you `accept`; run `php sentinel.php accept` after each deploy, for example as the last line of your deploy script.

## Configuration

`init` writes `sentinel.json`. The commonly edited keys:

| Key | Meaning |
|---|---|
| `site_name` | Appears in alert subjects. |
| `channels` | List of `email` (`to`, optional `from`), `ntfy` (`url`), `telegram` (`token`, `chat_id`), `webhook` (`url`), `file` (`path`). Each takes an optional `min_severity` (`info`, `warning` default, `critical`). |
| `watch` | Directories (relative to `site_root`) to monitor. Default `["."]`. |
| `exclude` | Patterns to skip: `dir/` for a directory, `*.log`, `**` for any depth. A pattern with a `/` is anchored at the site root. |
| `sensitive` | Files that raise a Warning on any change. |
| `uploads_dir` | Where PHP must never appear. Set automatically for WordPress. |
| `budget_seconds`, `budget_memory_mb` | Limits per run. A scan that hits the limit stops and resumes on the next run, so it never hogs a shared host. |
| `max_scan_bytes` | For files larger than this, the first and last half are scanned (malware is often appended). |
| `wp_checksums` | Set `false` to stop contacting wordpress.org. |
| `heartbeat_url` | URL pinged after each completed run. |
| `clamscan_path`, `yara_path`, `yara_rules` | Optional external scanners; found on `PATH` automatically (YARA also needs `yara_rules`). |
| `rules_url`, `rules_public_key`, `allow_unsigned_rules` | See [docs/RULES.md](docs/RULES.md). |

See `examples/sentinel.json`. To watch a server's `/tmp`, use a second config with `"site_root": "/tmp"`, `"profile": "generic"` and `"temp_root": true`. On a dedicated server, `examples/systemd/` has timers you can use instead of cron.

## Limits you should know about

- On shared hosting an attacker who controls the account can also edit Sentinel, its config and its baseline. Sentinel watches its own files and raises Critical if they change, but that is a tripwire, not a defence. The heartbeat is what tells you the monitor itself was disabled, and alerts leave the server immediately.
- Detection is rule-based: it catches common webshells and anything that violates the file-integrity rules, not novel malware. File changes that should never happen are the more reliable signal.
- Email from shared hosts is often filtered. Add a second channel (ntfy or Telegram) at least for Critical alerts.
- `wp-config.php` kept one directory above the site root is outside the watched tree.

## Development

```
php tests/run.php            # all tests (no network, temporary directories only)
php tests/run.php Walker     # tests whose name contains "Walker"
php build/compat.php         # PHP 7.4 syntax check
php build/build.php          # produce dist/sentinel.php
```

Tests need no Composer or framework. Source is in `src/` (one class per file, listed in `build/files.php`); `build/build.php` concatenates it into the single distributable.

## License

Site Sentinel is free software, released under the GNU General Public License, version 3 or (at your option) any later version. See `LICENSE`. It comes with no warranty. Rule bundles keep the licenses of their sources (see `docs/RULES.md`).
````

````markdown file=docs/RULES.md
# Rules bundles

Sentinel ships with a small built-in rule set that works without any download. `update-rules` replaces it with a maintained bundle.

## Format

`rules.json`:

```json
{
    "version": 12,
    "patterns": [
        { "id": "eval-decoder", "severity": "critical", "regex": "/\\beval\\s*\\(\\s*base64_decode\\s*\\(/i", "description": "eval of an encoded payload", "source": "where this rule came from and its license" }
    ],
    "hashes": [
        { "sha256": "<64 hex characters>", "name": "Malware.Family" }
    ]
}
```

- `severity` is `warning` or `critical`; `regex` is a full PCRE with delimiters and flags. Keep patterns specific; a pattern that matches ordinary code will alert on every deploy.
- `version` must increase with each release. Sentinel refuses a lower version (so an old signed bundle cannot be replayed) and does nothing for an equal one.
- The file is installed byte-for-byte so the signature stays valid.

## Signing and publishing (maintainer)

```
php bin/sign-rules.php keygen                       # once; keep the secret key offline
php bin/sign-rules.php sign rules.json secret.key   # writes rules.json.sig and rules.json.sha256
```

Publish `rules.json`, `rules.json.sig` and `rules.json.sha256` side by side (for example as release assets) and give clients:

```json
"rules_url": "https://example.com/path/rules.json",
"rules_public_key": "<the public key printed by keygen>"
```

Clients with the `sodium` extension verify the ed25519 signature. Clients without it must set `"allow_unsigned_rules": true` to use the `.sha256` file instead; that only guards against corruption, not a compromised rules server, and Sentinel says so each time. Run `update-rules` weekly from cron.

## Licensing of rule sources

Sentinel is open source, but every rule you bundle keeps its own license. Before adding rules from another project (Linux Malware Detect signatures, php-malware-finder, Neo23x0 signature-base, and so on), check that its license allows redistribution and commercial use, keep its attribution, and record the origin and license in each rule's `source` field. The built-in rules in `src/Rules.php` are original to this project.
````

- [ ] **Step 6: Run the full suite and the compat check**

Run: `php tests/run.php && php build/compat.php && php build/build.php`
Expected: every test `ok` (tests that need root-less permissions or the sodium extension may `skip`), `PHP 7.4 compatibility: OK`, `built dist/sentinel.php (...)`.

- [ ] **Step 7: Run it for real once**

```bash
mkdir -p /tmp/sentinel-demo/site && cd /tmp/sentinel-demo
echo '<?php // home' > site/index.php
php /path/to/site-sentinel/dist/sentinel.php init --root=/tmp/sentinel-demo/site --file=/tmp/sentinel-demo/alerts.log --no-wp-checksums --config=/tmp/sentinel-demo/sentinel.json --state=/tmp/sentinel-demo/state
echo '<?php // SENTINEL-TEST-MALWARE-MARKER' > site/dropper.php
php /path/to/site-sentinel/dist/sentinel.php check --config=/tmp/sentinel-demo/sentinel.json; echo "exit=$?"
cat /tmp/sentinel-demo/alerts.log
rm -rf /tmp/sentinel-demo
```
Expected: `init` prints cron lines; `check` prints a CRITICAL `test-marker` line and `exit=1`; `alerts.log` holds one digest naming `dropper.php`.

- [ ] **Step 8: License (decided: GPL-3.0-or-later)**

`LICENSE` (the verbatim GNU GPL v3 text) is already in the repository. Confirm the `README.md` from Step 5 ends with the `## License` section, and that the build output header carries the notice (Step 3 adds it). Nothing else is needed; the project is free software and not sold. Rule data keeps its own licenses (see `docs/RULES.md`); note that GPL-2.0-only rule sources such as some maldet signatures are not compatible with a GPL-3.0 distribution, so check each source before bundling it.

- [ ] **Step 9: Commit**

```bash
git add build/build.php tests/test_e2e.php examples README.md docs/RULES.md
git commit -m "feat: single-file build, end-to-end tests, examples and docs"
```
