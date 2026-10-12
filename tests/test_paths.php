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
