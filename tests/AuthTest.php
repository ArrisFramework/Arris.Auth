<?php

declare(strict_types=1);

namespace Tests;

use Arris\Auth\Auth;
use Arris\Auth\Exception\AccountDisabledException;
use Arris\Auth\Exception\AmbiguousUsernameException;
use Arris\Auth\Exception\EmailNotVerifiedException;
use Arris\Auth\Exception\InvalidCredentialsException;
use Arris\Auth\Exception\InvalidEmailException;
use Arris\Auth\Exception\InvalidPasswordException;
use Arris\Auth\Exception\UserAlreadyExistsException;
use Arris\Auth\Repository\TokenRepository;
use Arris\Auth\Role;
use Arris\Auth\Status;
use Arris\Auth\User;
use PDO;
use PHPUnit\Framework\TestCase;

final class AuthTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        parent::setUp();

        $_COOKIE = [];
        $_SESSION = [];
        unset(
            $_SERVER['HTTP_AUTHORIZATION'],
            $_SERVER['REDIRECT_HTTP_AUTHORIZATION'],
            $_SERVER['HTTPS'],
            $_SERVER['SERVER_PORT'],
        );

        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        $this->pdo->exec(
            'CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                username TEXT DEFAULT NULL,
                status INTEGER NOT NULL DEFAULT 0,
                verified INTEGER NOT NULL DEFAULT 0,
                resettable INTEGER NOT NULL DEFAULT 1,
                roles_mask INTEGER NOT NULL DEFAULT 0,
                registered INTEGER NOT NULL,
                last_login INTEGER DEFAULT NULL,
                force_logout INTEGER NOT NULL DEFAULT 0,
                properties TEXT DEFAULT NULL
            )'
        );

        $this->pdo->exec(
            'CREATE TABLE users_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user INTEGER NOT NULL,
                kind TEXT NOT NULL DEFAULT "api",
                selector TEXT DEFAULT NULL UNIQUE,
                token TEXT NOT NULL,
                name TEXT DEFAULT NULL,
                expires INTEGER NOT NULL DEFAULT 0,
                created INTEGER NOT NULL,
                last_used INTEGER DEFAULT NULL
            )'
        );
    }

    protected function tearDown(): void
    {
        if (\session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION = [];
            \session_destroy();
        }

        $_SESSION = [];
        $_COOKIE = [];
        \session_id('');

        parent::tearDown();
    }

    /**
     * @param array<string, mixed>|string $options
     */
    private function auth(array|string $options = []): Auth
    {
        if (\is_string($options)) {
            $options = ['mode' => $options];
        }

        $options = \array_replace_recursive([
            'session_cookie' => ['secure' => false],
        ], $options);

        return new Auth($this->pdo, $options);
    }

    private function createUser(
        string $email = 'user@example.com',
        string $password = 'correct horse battery staple',
        ?string $username = 'user',
        bool $verified = true,
        int $rolesMask = 0,
    ): int {
        return $this->auth()->register($email, $password, $username, $verified, $rolesMask);
    }

    public function testRegisterCreatesUserWithHashedPassword(): void
    {
        $auth = $this->auth();
        $id = $auth->register('user@example.com', 'correct horse battery staple', 'user');

        $row = $this->pdo->query('SELECT * FROM users WHERE id = ' . $id)->fetch();

        self::assertSame('user@example.com', $row['email']);
        self::assertSame('user', $row['username']);
        self::assertSame(1, (int) $row['verified']);
        self::assertNotSame('correct horse battery staple', $row['password']);
        self::assertTrue(\password_verify('correct horse battery staple', $row['password']));
    }

    public function testRegisterRejectsInvalidEmail(): void
    {
        $this->expectException(InvalidEmailException::class);

        $this->auth()->register('not-an-email', 'correct horse battery staple');
    }

    public function testRegisterRejectsShortPassword(): void
    {
        $this->expectException(InvalidPasswordException::class);

        $this->auth()->register('user@example.com', 'short');
    }

    public function testRegisterRejectsDuplicateEmail(): void
    {
        $this->createUser();

        $this->expectException(UserAlreadyExistsException::class);

        $this->auth()->register('user@example.com', 'correct horse battery staple');
    }

    public function testLoginCreatesSession(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();

        $user = $auth->login('user@example.com', 'correct horse battery staple');

        self::assertSame($id, $user->id);
        self::assertSame($id, (int) $_SESSION[Auth::SESSION_USER_ID]);
        self::assertTrue($auth->check());
        self::assertSame($id, $auth->id());
        self::assertFalse($auth->isRemembered());
    }

    public function testLoginRejectsWrongPassword(): void
    {
        $this->createUser();

        $this->expectException(InvalidCredentialsException::class);

        $this->auth()->login('user@example.com', 'wrong password');
    }

    public function testLoginRejectsUnverifiedUser(): void
    {
        $this->createUser(verified: false);

        $this->expectException(EmailNotVerifiedException::class);

        $this->auth()->login('user@example.com', 'correct horse battery staple');
    }

    public function testVerifyUserAllowsLogin(): void
    {
        $id = $this->createUser(verified: false);
        $auth = $this->auth();

        $auth->verifyUser($id);
        $user = $auth->login('user@example.com', 'correct horse battery staple');

        self::assertSame($id, $user->id);
    }

    public function testLoginRejectsDisabledUser(): void
    {
        $id = $this->createUser();
        $this->pdo->exec('UPDATE users SET status = ' . Status::BANNED . ' WHERE id = ' . $id);

        $this->expectException(AccountDisabledException::class);

        $this->auth()->login('user@example.com', 'correct horse battery staple');
    }

    public function testLoginWithUsername(): void
    {
        $id = $this->createUser();

        $user = $this->auth()->loginWithUsername('user', 'correct horse battery staple');

        self::assertSame($id, $user->id);
    }

    public function testLoginWithAmbiguousUsernameThrows(): void
    {
        $this->createUser('one@example.com', username: 'same');
        $this->createUser('two@example.com', username: 'same');

        $this->expectException(AmbiguousUsernameException::class);

        $this->auth()->loginWithUsername('same', 'correct horse battery staple');
    }

    public function testBearerTokenAuthenticatesUser(): void
    {
        $id = $this->createUser();
        $issuer = $this->auth();
        $token = $issuer->issueToken($id, 3600, 'cli');

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;

        $user = $this->auth(Auth::MODE_TOKEN)->user();

        self::assertInstanceOf(User::class, $user);
        self::assertSame($id, $user->id);
    }

    public function testInvalidBearerTokenReturnsNullAndDoesNotFallBackToSession(): void
    {
        $id = $this->createUser();
        $sessionAuth = $this->auth();
        $sessionAuth->login('user@example.com', 'correct horse battery staple');

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer invalid-token';

        $user = $this->auth()->user();

        self::assertNull($user);
    }

    public function testRevokedTokenIsRejected(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $token = $auth->issueToken($id);

        self::assertTrue($auth->revokeToken($token));

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;

        self::assertNull($this->auth(Auth::MODE_TOKEN)->user());
    }

    public function testExpiredTokenIsRejected(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $token = $auth->issueToken($id, 1);

        $this->pdo->exec('UPDATE users_tokens SET expires = ' . (\time() - 10));

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;

        self::assertNull($this->auth(Auth::MODE_TOKEN)->user());
    }

    public function testRevokeAllTokens(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->issueToken($id);
        $auth->issueToken($id);

        self::assertSame(2, $auth->revokeAllTokens($id));
        self::assertSame(0, $auth->revokeAllTokens($id));
    }

    public function testLogoutClearsSession(): void
    {
        $this->createUser();
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');

        $auth->logout();

        self::assertFalse($auth->check());
        self::assertArrayNotHasKey(Auth::SESSION_USER_ID, $_SESSION);
    }

    public function testLogoutEverywhereInvalidatesSessionsAndTokens(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');
        $token = $auth->issueToken($id);
        $oldForceLogout = (int) $_SESSION[Auth::SESSION_FORCE_LOGOUT];

        $auth->logoutEverywhere($id);

        $row = $this->pdo->query('SELECT force_logout FROM users WHERE id = ' . $id)->fetch();
        self::assertGreaterThan($oldForceLogout, (int) $row['force_logout']);
        self::assertNull($auth->user());

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
        self::assertNull($this->auth(Auth::MODE_TOKEN)->user());
    }

    public function testForceLogoutInvalidatesExistingSession(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');

        $this->pdo->exec('UPDATE users SET force_logout = force_logout + 1 WHERE id = ' . $id);

        self::assertNull($this->auth()->user());
    }

    public function testRememberCookieAuthenticatesUser(): void
    {
        $id = $this->createUser();
        $selector = \bin2hex(\random_bytes(12));
        $token = \bin2hex(\random_bytes(32));

        (new TokenRepository($this->pdo))->createRemember(
            $id,
            $selector,
            \hash('sha256', $token),
            \time() + 3600
        );

        $_COOKIE['arris_remember'] = $selector . '~' . $token;

        $auth = $this->auth();
        $user = $auth->user();

        self::assertInstanceOf(User::class, $user);
        self::assertSame($id, $user->id);
        self::assertTrue($auth->isRemembered());
    }

    public function testInvalidRememberCookieIsRejected(): void
    {
        $this->createUser();

        $_COOKIE['arris_remember'] = 'missing~token';

        self::assertNull($this->auth()->user());
    }

    public function testUserRoles(): void
    {
        $id = $this->createUser(rolesMask: Role::ADMIN | Role::EDITOR);
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');

        self::assertTrue($auth->hasRole(Role::ADMIN));
        self::assertTrue($auth->hasAnyRole(Role::AUTHOR, Role::EDITOR));
        self::assertTrue($auth->hasAllRoles(Role::ADMIN, Role::EDITOR));
        self::assertFalse($auth->hasRole(Role::MODERATOR));

        $user = $auth->user();
        self::assertSame($id, $user->id);
        self::assertContains('ADMIN', $user->roleNames());
        self::assertContains('EDITOR', $user->roleNames());
    }

    public function testIssueTokenForUnknownUserThrows(): void
    {
        $this->expectException(\Arris\Auth\Exception\UnknownUserException::class);

        $this->auth()->issueToken(999);
    }

    public function testLoginWithRememberCreatesRememberToken(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();

        $auth->login('user@example.com', 'correct horse battery staple', remember: true);

        $row = $this->pdo->query("SELECT * FROM users_tokens WHERE kind = 'remember'")->fetch();

        self::assertIsArray($row);
        self::assertSame($id, (int) $row['user']);
        self::assertNotSame('', (string) $row['selector']);
        self::assertSame(64, \strlen((string) $row['token']));
    }

    public function testChangePasswordKeepsCurrentSessionAndRevokesTokens(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');
        $token = $auth->issueToken($id);

        $auth->changePassword($id, 'a new correct horse battery staple');

        self::assertTrue($auth->check());
        self::assertSame($id, $auth->id());
        self::assertFalse($auth->revokeToken($token));

        $row = $this->pdo->query('SELECT password FROM users WHERE id = ' . $id)->fetch();
        self::assertTrue(\password_verify('a new correct horse battery staple', $row['password']));
    }

    public function testAdminLogoutEverywhereDoesNotClearOwnSession(): void
    {
        $adminId = $this->createUser('admin@example.com', username: 'admin');
        $otherId = $this->createUser('other@example.com', username: 'other');
        $auth = $this->auth();
        $auth->login('admin@example.com', 'correct horse battery staple');
        $otherToken = $auth->issueToken($otherId);

        $auth->logoutEverywhere($otherId);

        self::assertTrue($auth->check());
        self::assertSame($adminId, $auth->id());

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $otherToken;
        self::assertNull($this->auth(Auth::MODE_TOKEN)->user());
    }

    public function testDeleteExpiredTokens(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->issueToken($id, 1);
        $auth->issueToken($id, 3600);

        $this->pdo->exec('UPDATE users_tokens SET expires = ' . (\time() - 10) . ' WHERE id = 1');

        self::assertSame(1, $auth->deleteExpiredTokens());
    }
}
