<?php

declare(strict_types=1);

namespace Tests\Integration;

use Arris\Auth\Auth;
use Arris\Auth\AuthConfig;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Support\RecordingMailer;

/**
 * Integration checks for the MySQL schema and the real MySQL driver.
 *
 * Set ARRIS_AUTH_MYSQL_DSN (and optionally ARRIS_AUTH_MYSQL_USER /
 * ARRIS_AUTH_MYSQL_PASSWORD) to run these tests.
 */
final class MySqlIntegrationTest extends TestCase
{
    private PDO $pdo;

    protected function setUp(): void
    {
        parent::setUp();

        $dsn = \getenv('ARRIS_AUTH_MYSQL_DSN');

        if ($dsn === false || $dsn === '') {
            self::markTestSkipped('ARRIS_AUTH_MYSQL_DSN is not configured');
        }

        $_COOKIE = [];
        $_SESSION = [];
        unset(
            $_SERVER['HTTP_AUTHORIZATION'],
            $_SERVER['HTTPS'],
            $_SERVER['SERVER_PORT'],
            $_SERVER['HTTP_X_FORWARDED_PROTO'],
            $_SERVER['HTTP_X_FORWARDED_SSL'],
        );

        $this->pdo = new PDO(
            $dsn,
            \getenv('ARRIS_AUTH_MYSQL_USER') ?: null,
            \getenv('ARRIS_AUTH_MYSQL_PASSWORD') ?: null,
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ]
        );

        $this->pdo->exec(
            'DROP TABLE IF EXISTS sessions, users_tokens, users_confirmations, '
            . 'users_remembered, users_resets, users_throttling, users'
        );

        $schema = \file_get_contents(\dirname(__DIR__, 2) . '/_database/schema_mysql.sql');

        if ($schema === false) {
            throw new \RuntimeException('Unable to read the MySQL schema');
        }

        $this->pdo->exec($schema);
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

    public function testLoginBearerAndRememberFlowOnMySql(): void
    {
        $config = (new AuthConfig())
            ->setSessionName('arris_mysql_test')
            ->setSessionCookie(['secure' => false, 'path' => '/'])
            ->setRememberCookieName('arris_mysql_remember');

        $auth = new Auth($this->pdo, $config);
        $id = $auth->register('mysql@example.com', 'correct horse battery staple', 'mysql')->id;

        $auth->login('mysql@example.com', 'correct horse battery staple', remember: true);

        self::assertSame($id, $auth->id());
        self::assertFalse($auth->isRemembered());

        $token = $auth->issueToken($id, 3600, 'mysql-test');

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;

        $tokenUser = (new Auth($this->pdo, $config->setMode(Auth::MODE_TOKEN)))->user();

        self::assertNotNull($tokenUser);
        self::assertSame($id, $tokenUser->id);

        $rememberRows = (int) $this->pdo->query(
            "SELECT COUNT(*) FROM users_tokens WHERE kind = 'remember'"
        )->fetchColumn();

        self::assertSame(1, $rememberRows);
    }

    public function testConfirmationFlowOnMySql(): void
    {
        $mailer = new RecordingMailer();
        $config = (new AuthConfig())
            ->setSessionName('arris_mysql_confirmation')
            ->setSessionCookie(['secure' => false, 'path' => '/'])
            ->setUserConfirmationOptions(required: true, ttl: 60)
            ->setMailer($mailer);

        $auth = new Auth($this->pdo, $config);
        $user = $auth->register('confirm-mysql@example.com', 'correct horse battery staple', 'confirm-mysql');

        self::assertFalse($user->isVerified());
        self::assertCount(1, $mailer->activations);

        $confirmed = $auth->confirmUser($mailer->activations[0]['key']);

        self::assertTrue($confirmed->isVerified());
        self::assertSame(
            1,
            (int) $this->pdo->query('SELECT verified FROM users WHERE id = ' . $user->id)->fetchColumn()
        );
    }

    public function testSchemaContainsAuthLookupIndexes(): void
    {
        $userIndexes = \array_column(
            $this->pdo->query('SHOW INDEX FROM users')->fetchAll(),
            'Key_name'
        );
        $tokenIndexes = \array_column(
            $this->pdo->query('SHOW INDEX FROM users_tokens')->fetchAll(),
            'Key_name'
        );
        $confirmationIndexes = \array_column(
            $this->pdo->query('SHOW INDEX FROM users_confirmations')->fetchAll(),
            'Key_name'
        );

        self::assertContains('username', $userIndexes);
        self::assertContains('token', $tokenIndexes);
        self::assertContains('token', $confirmationIndexes);
    }
}
