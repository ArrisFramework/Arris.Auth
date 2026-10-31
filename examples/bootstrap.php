<?php

declare(strict_types=1);

use Arris\Auth\Auth;
use Arris\Auth\AuthConfig;
use Arris\Auth\Role;
use Arris\Auth\Session\PDOSessionHandler;

require dirname(__DIR__) . '/vendor/autoload.php';

$dataDir = __DIR__ . '/data';

if (!is_dir($dataDir) && !mkdir($dataDir, 0775, true) && !is_dir($dataDir)) {
    throw new RuntimeException('Unable to create the demo data directory');
}

$pdo = new PDO('sqlite:' . $dataDir . '/demo.sqlite');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$pdo->exec('PRAGMA foreign_keys = ON');

$schema = file_get_contents(__DIR__ . '/schema.sqlite.sql');
if ($schema === false) {
    throw new RuntimeException('Unable to read the SQLite schema');
}

$pdo->exec($schema);

$config = (new AuthConfig())
    ->setSessionName('arris_demo_session')
    ->setSessionCookie([
        'path' => '/',
        'secure' => false,
        'httponly' => true,
        'samesite' => 'Lax',
    ])
    ->setSessionHandler(new PDOSessionHandler($pdo, 'sessions'))
    ->setRememberCookieName('arris_demo_remember')
    ->setRememberTtl(60 * 60 * 24 * 30)
    ->setTokenTtl(60 * 60 * 24 * 7)
    ->setRequireVerified(true)
    ->setRejectNonNormalStatus(true)
    ->setMinPasswordLength(8);

$auth = new Auth($pdo, $config);

if ((int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn() === 0) {
    $auth->register(
        email: 'admin@example.com',
        password: 'admin-password',
        username: 'admin',
        verified: true,
        rolesMask: Role::ADMIN,
    );

    $auth->register(
        email: 'user@example.com',
        password: 'user-password',
        username: 'user',
        verified: true,
        rolesMask: Role::SUBSCRIBER,
    );
}

return [
    'pdo' => $pdo,
    'auth' => $auth,
    'config' => $config,
];
