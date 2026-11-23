<?php

declare(strict_types=1);

namespace App;

use Arris\Auth\Auth as BaseAuth;
use Arris\Auth\AuthConfig;
use Arris\Auth\Role;
use Arris\Auth\Session;
use PDO;

require dirname(__DIR__) . '/vendor/autoload.php';

final class AppRole extends Role
{
    public const BANNED = 4194304;
    public const VIEWER = Role::CONSUMER;
    public const EDITOR = Role::EDITOR;
    public const CURATOR = Role::COORDINATOR;
    public const ADMIN = Role::ADMIN;

    public static function map(): array
    {
        return [
            'BANNED' => self::BANNED,
            'VIEWER' => self::VIEWER,
            'EDITOR' => self::EDITOR,
            'CURATOR' => self::CURATOR,
            'ADMIN' => self::ADMIN,
        ];
    }
}

class Auth extends BaseAuth
{
    public readonly ?int $id;
    public readonly bool $is_logged_in;
    public readonly ?string $username;
    public readonly ?string $email;
    public readonly ?string $ipv4;

    public readonly bool $is_banned_role;
    public readonly bool $is_banned_status;
    public readonly bool $is_banned;

    public readonly bool $is_viewer;
    public readonly bool $is_editor;
    public readonly bool $is_curator;
    public readonly bool $is_admin;

    public readonly string $color;

    public function __construct(PDO $pdo, ?AuthConfig $config = null, ?string $ipv4 = null)
    {
        parent::__construct($pdo, $config);

        $user = $this->user();

        $this->id = $this->id();
        $this->is_logged_in = $this->isLoggedIn();
        $this->username = $this->username();
        $this->email = $this->email();
        $this->ipv4 = $ipv4;

        $this->is_banned_role = $this->hasRole(AppRole::BANNED);
        $this->is_banned_status = $user?->isBanned() ?? false;
        $this->is_banned = $this->is_banned_role || $this->is_banned_status;

        $this->is_viewer = $this->hasRole(AppRole::VIEWER);
        $this->is_editor = $this->hasRole(AppRole::EDITOR);
        $this->is_curator = $this->hasRole(AppRole::CURATOR);
        $this->is_admin = $this->hasRole(AppRole::ADMIN);

        $this->color = match (true) {
            $this->is_banned => 'red',
            $this->is_viewer => 'orange',
            $this->is_editor => 'green',
            $this->is_curator => 'blue',
            $this->is_admin => 'purple',
            default => 'black',
        };
    }
}

function printContext(Auth $auth): void
{
    $user = $auth->user();

    printf(
        "  id=%s logged_in=%s username=%s email=%s ipv4=%s\n"
        . "  banned_role=%s banned_status=%s banned=%s\n"
        . "  viewer=%s editor=%s curator=%s admin=%s color=%s\n"
        . "  roles=%s\n",
        \var_export($auth->id, true),
        \var_export($auth->is_logged_in, true),
        \var_export($auth->username, true),
        \var_export($auth->email, true),
        \var_export($auth->ipv4, true),
        \var_export($auth->is_banned_role, true),
        \var_export($auth->is_banned_status, true),
        \var_export($auth->is_banned, true),
        \var_export($auth->is_viewer, true),
        \var_export($auth->is_editor, true),
        \var_export($auth->is_curator, true),
        \var_export($auth->is_admin, true),
        $auth->color,
        \implode(', ', $user?->roleNames(AppRole::map()) ?? []),
    );
}

$pdo = new PDO('sqlite::memory:');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

$schema = \file_get_contents(\dirname(__DIR__) . '/_database/schema_sqlite.sql');
if ($schema === false) {
    throw new \RuntimeException('Unable to read the SQLite schema');
}

$pdo->exec($schema);

$config = (new AuthConfig())
    ->setSessionName('arris_extend_demo')
    ->setSessionCookie([
        'path' => '/',
        'secure' => false,
        'httponly' => true,
        'samesite' => 'Lax',
    ])
    ->setRequireVerified(true)
    ->setRejectNonNormalStatus(true);

Session::start($config->getSessionName(), $config->getSessionCookie());

$ipv4 = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$email = 'curator@example.com';
$password = 'correct horse battery staple';

\ob_start();

echo "request #1: anonymous\n";
$request = new Auth($pdo, $config, ipv4: $ipv4);
printContext($request);

$request->register(
    email: $email,
    password: $password,
    username: 'curator',
    verified: true,
    rolesMask: AppRole::CURATOR | AppRole::BANNED,
);
$request->login($email, $password);

echo "\nrequest #2: after login (new Http request, new App\\Auth)\n";
$request = new Auth($pdo, $config, ipv4: $ipv4);
printContext($request);

$request->logout();

echo "\nrequest #3: after logout (new Http request, new App\\Auth)\n";
$request = new Auth($pdo, $config, ipv4: $ipv4);
printContext($request);

\ob_end_flush();
