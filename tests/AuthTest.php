<?php

declare(strict_types=1);

namespace Tests;

use Arris\Auth\Auth;
use Arris\Auth\AuthConfig;
use Arris\Auth\Exception\AccountDisabledException;
use Arris\Auth\Exception\AmbiguousUsernameException;
use Arris\Auth\Exception\ConfigurationException;
use Arris\Auth\Exception\EmailNotVerifiedException;
use Arris\Auth\Exception\InvalidCredentialsException;
use Arris\Auth\Exception\InvalidEmailException;
use Arris\Auth\Exception\InvalidPasswordException;
use Arris\Auth\Exception\NotLoggedInException;
use Arris\Auth\Exception\UserAlreadyExistsException;
use Arris\Auth\Repository\TokenRepository;
use Arris\Auth\Role;
use Arris\Auth\DTO\ConfirmationState;
use Arris\Auth\DTO\ResetState;
use Arris\Auth\DTO\Status;
use Arris\Auth\DTO\ThrottleRule;
use Arris\Auth\DTO\ThrottlingOptions;
use Arris\Auth\DTO\User;
use Arris\Auth\DTO\UserConfirmationOptions;
use Arris\Auth\DTO\UserResetOptions;
use Tests\Support\RecordingMailer;
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
            $_SERVER['HTTP_X_FORWARDED_PROTO'],
            $_SERVER['HTTP_X_FORWARDED_SSL'],
        );

        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

        $schema = \file_get_contents(\dirname(__DIR__) . '/_database/schema_sqlite.sql');

        if ($schema === false) {
            throw new \RuntimeException('Unable to read the SQLite schema');
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

    private function auth(AuthConfig|string|null $config = null, bool $throttling = false): Auth
    {
        if (\is_string($config)) {
            $config = (new AuthConfig())->setMode($config);
        }

        $config ??= new AuthConfig();
        $config->setAllowInsecureHttp(true);

        if (!$throttling) {
            $config->setThrottlingOptions(new ThrottlingOptions(enabled: false));
        }

        $config->setSessionCookie(\array_replace(['secure' => false], $config->getSessionCookie()));

        return new Auth($this->pdo, $config);
    }

    private function createUser(
        string $email = 'user@example.com',
        string $password = 'correct horse battery staple',
        ?string $username = 'user',
        bool $verified = true,
        int $rolesMask = 0,
    ): int {
        return $this->auth()->register($email, $password, $username, $verified, $rolesMask)->id;
    }

    private function confirmationAuth(RecordingMailer $mailer, ?AuthConfig $config = null): Auth
    {
        $config ??= new AuthConfig();
        $config
            ->setUserConfirmationOptions(new UserConfirmationOptions(required: true, ttl: 60))
            ->setMailer($mailer);

        return $this->auth($config);
    }

    private function resetAuth(
        RecordingMailer $mailer,
        bool $allowedAny = false,
        ?AuthConfig $config = null,
    ): Auth {
        $config ??= new AuthConfig();
        $config
            ->setUserResetOptions(new UserResetOptions(enabled: true, ttl: 60, allowedAny: $allowedAny))
            ->setMailer($mailer);

        return $this->auth($config);
    }

    public function testSchemaHasAuthLookupIndexes(): void
    {
        $userIndexes = \array_column($this->pdo->query("PRAGMA index_list('users')")->fetchAll(), 'name');
        $tokenIndexes = \array_column($this->pdo->query("PRAGMA index_list('users_tokens')")->fetchAll(), 'name');
        $confirmationIndexes = \array_column(
            $this->pdo->query("PRAGMA index_list('users_confirmations')")->fetchAll(),
            'name'
        );
        $resetIndexes = \array_column(
            $this->pdo->query("PRAGMA index_list('users_resets')")->fetchAll(),
            'name'
        );

        self::assertContains('users_username', $userIndexes);
        self::assertContains('users_tokens_token', $tokenIndexes);
        self::assertContains('users_confirmations_token', $confirmationIndexes);
        self::assertContains('users_resets_token', $resetIndexes);
    }

    public function testRegisterCreatesUserWithHashedPassword(): void
    {
        $auth = $this->auth();
        $id = $auth->register('user@example.com', 'correct horse battery staple', 'user')->id;

        $row = $this->pdo->query('SELECT * FROM users WHERE id = ' . $id)->fetch();

        self::assertSame('user@example.com', $row['email']);
        self::assertSame('user', $row['username']);
        self::assertSame(1, (int) $row['verified']);
        self::assertNotSame('correct horse battery staple', $row['password']);
        self::assertTrue(\password_verify('correct horse battery staple', $row['password']));
    }

    public function testRegisterRejectsInvalidEmailWithCustomValidator(): void
    {
        $config = (new AuthConfig())->setEMailValidator(
            static fn (string $email): bool => \filter_var($email, \FILTER_VALIDATE_EMAIL) !== false
        );

        $this->expectException(InvalidEmailException::class);

        $this->auth($config)->register('not-an-email', 'correct horse battery staple');
    }

    public function testRegisterRejectsPasswordRejectedByCustomValidator(): void
    {
        $config = (new AuthConfig())->setPasswordValidator(
            static fn (string $password): bool => \strlen($password) >= 8
        );

        $this->expectException(InvalidPasswordException::class);

        $this->auth($config)->register('user@example.com', 'short');
    }

    public function testRegisterRejectsDuplicateEmail(): void
    {
        $this->createUser();

        $this->expectException(UserAlreadyExistsException::class);

        $this->auth()->register('user@example.com', 'correct horse battery staple');
    }

    public function testRegisterReturnsUserAndCreatesVerifiedUserWithoutConfirmation(): void
    {
        $auth = $this->auth();
        $user = $auth->register('verified@example.com', 'correct horse battery staple', 'verified');

        self::assertInstanceOf(User::class, $user);
        self::assertSame('verified@example.com', $user->email);
        self::assertTrue($user->isVerified());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_confirmations')->fetchColumn());
    }

    public function testRegisterWithConfirmationCreatesPendingUserAndSendsToken(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->confirmationAuth($mailer);

        $user = $auth->register('pending@example.com', 'correct horse battery staple', 'pending');

        self::assertFalse($user->isVerified());
        self::assertSame(0, $user->verified);
        self::assertSame(0, (int) $this->pdo->query(
            'SELECT verified FROM users WHERE id = ' . $user->id
        )->fetchColumn());
        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users_confirmations')->fetchColumn());
        self::assertCount(1, $mailer->activations);
        self::assertSame('pending@example.com', $mailer->activations[0]['email']);

        $token = $mailer->activations[0]['key'];
        $storedToken = (string) $this->pdo->query('SELECT token FROM users_confirmations')->fetchColumn();

        self::assertSame(\hash('sha256', $token), $storedToken);
    }

    public function testConfirmUserVerifiesUserAndDeletesConfirmation(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->confirmationAuth($mailer);
        $user = $auth->register('confirm@example.com', 'correct horse battery staple', 'confirm');

        $confirmed = $auth->confirmUser($mailer->activations[0]['key']);

        self::assertSame($user->id, $confirmed->id);
        self::assertTrue($confirmed->isVerified());
        self::assertSame(1, (int) $this->pdo->query(
            'SELECT verified FROM users WHERE id = ' . $user->id
        )->fetchColumn());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_confirmations')->fetchColumn());
    }

    public function testConfirmUserRejectsInvalidAndExpiredTokens(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->confirmationAuth($mailer);
        $auth->register('expired@example.com', 'correct horse battery staple', 'expired');

        $token = $mailer->activations[0]['key'];

        try {
            $auth->confirmUser('invalid-token');
            self::fail('Expected InvalidConfirmationException');
        } catch (\Arris\Auth\Exception\InvalidConfirmationException) {
        }

        $this->pdo->exec('UPDATE users_confirmations SET expires = ' . (\time() - 1));

        $this->expectException(\Arris\Auth\Exception\InvalidConfirmationException::class);
        $auth->confirmUser($token);
    }

    public function testConfirmationRequiredForcesVerifiedLogin(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->confirmationAuth($mailer, (new AuthConfig())->setRequireVerified(false));
        $auth->register('required@example.com', 'correct horse battery staple', 'required');

        $this->expectException(EmailNotVerifiedException::class);
        $auth->login('required@example.com', 'correct horse battery staple');
    }

    public function testResendConfirmationInvalidatesOldToken(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->confirmationAuth($mailer);
        $auth->register('resend@example.com', 'correct horse battery staple', 'resend');

        $oldToken = $mailer->activations[0]['key'];
        $state = $auth->resendConfirmation('resend@example.com');

        self::assertInstanceOf(ConfirmationState::class, $state);
        self::assertTrue($state->isSent());
        self::assertCount(2, $mailer->activations);
        self::assertNotSame($oldToken, $mailer->activations[1]['key']);
        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users_confirmations')->fetchColumn());

        try {
            $auth->confirmUser($oldToken);
            self::fail('Expected InvalidConfirmationException');
        } catch (\Arris\Auth\Exception\InvalidConfirmationException) {
        }

        self::assertTrue($auth->confirmUser($mailer->activations[1]['key'])->isVerified());
    }

    public function testResendConfirmationStates(): void
    {
        $mailer = new RecordingMailer();
        $config = (new AuthConfig())->setMailer($mailer);
        $auth = $this->auth($config);

        self::assertSame(ConfirmationState::NOT_REQUIRED, $auth->resendConfirmation('missing@example.com')->reason);

        $pendingAuth = $this->confirmationAuth($mailer);
        self::assertSame(ConfirmationState::UNKNOWN_USER, $pendingAuth->resendConfirmation('missing@example.com')->reason);

        $user = $pendingAuth->register('already@example.com', 'correct horse battery staple', 'already');
        $pendingAuth->confirmUser($mailer->activations[0]['key']);

        self::assertSame(ConfirmationState::ALREADY_VERIFIED, $pendingAuth->resendConfirmation($user->email)->reason);
    }

    public function testMailFailureDoesNotFailRegistrationOrResend(): void
    {
        $mailer = new RecordingMailer();
        $mailer->result = false;
        $auth = $this->confirmationAuth($mailer);

        $user = $auth->register('mail-fail@example.com', 'correct horse battery staple', 'mail-fail');

        self::assertFalse($user->isVerified());
        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users_confirmations')->fetchColumn());

        $state = $auth->resendConfirmation('mail-fail@example.com');

        self::assertSame(ConfirmationState::MAIL_FAILED, $state->reason);
        self::assertFalse($state->isSent());
    }

    public function testConfirmationUsesExplicitNullMailer(): void
    {
        $config = (new AuthConfig())
            ->setUserConfirmationOptions(new UserConfirmationOptions(required: true))
            ->setMailer(new \Arris\Auth\Mailer\NullMailer());
        $auth = $this->auth($config);

        $user = $auth->register('null-mailer@example.com', 'correct horse battery staple', 'null-mailer');

        self::assertFalse($user->isVerified());
        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users_confirmations')->fetchColumn());
    }

    public function testAdminRegistrationBypassesConfirmation(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->confirmationAuth($mailer);

        $user = $auth->register('admin-created@example.com', 'correct horse battery staple', 'admin-created', verified: true);

        self::assertTrue($user->isVerified());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_confirmations')->fetchColumn());
        self::assertCount(0, $mailer->activations);
    }

    public function testVerifyUserDeletesConfirmationRows(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->confirmationAuth($mailer);
        $user = $auth->register('manual@example.com', 'correct horse battery staple', 'manual');

        $auth->verifyUser($user->id);

        self::assertSame(1, (int) $this->pdo->query(
            'SELECT verified FROM users WHERE id = ' . $user->id
        )->fetchColumn());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_confirmations')->fetchColumn());
    }

    public function testDeleteUserDeletesConfirmationRows(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->confirmationAuth($mailer);
        $user = $auth->register('delete-pending@example.com', 'correct horse battery staple', 'delete-pending');

        $auth->deleteUser($user->id);

        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_confirmations')->fetchColumn());
    }

    public function testDeleteExpiredConfirmations(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->confirmationAuth($mailer);
        $auth->register('cleanup@example.com', 'correct horse battery staple', 'cleanup');

        $this->pdo->exec('UPDATE users_confirmations SET expires = ' . (\time() - 1));

        self::assertSame(1, $auth->deleteExpiredConfirmations());
    }

    public function testRequestPasswordResetStates(): void
    {
        $mailer = new RecordingMailer();

        self::assertSame(
            ResetState::NOT_ENABLED,
            $this->auth((new AuthConfig())->setMailer($mailer))->requestPasswordReset('missing@example.com')->reason
        );

        $auth = $this->resetAuth($mailer);
        self::assertSame(ResetState::UNKNOWN_USER, $auth->requestPasswordReset('missing@example.com')->reason);

        $id = $this->createUser('not-resettable@example.com');
        $this->pdo->exec('UPDATE users SET resettable = 0 WHERE id = ' . $id);

        self::assertSame(ResetState::NOT_ALLOWED, $auth->requestPasswordReset('not-resettable@example.com')->reason);
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_resets')->fetchColumn());
    }

    public function testRequestPasswordResetSendsKeyAndStoresHash(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->resetAuth($mailer);
        $this->createUser('reset@example.com');

        $state = $auth->requestPasswordReset('reset@example.com');

        self::assertTrue($state->isSent());
        self::assertCount(1, $mailer->resets);
        self::assertSame('reset@example.com', $mailer->resets[0]['email']);

        $stored = (string) $this->pdo->query('SELECT token FROM users_resets')->fetchColumn();

        self::assertSame(\hash('sha256', $mailer->resets[0]['key']), $stored);
        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users_resets')->fetchColumn());
    }

    public function testResetPasswordChangesPasswordAndInvalidatesCredentials(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->resetAuth($mailer);
        $id = $this->createUser('change-reset@example.com');
        $token = $auth->issueToken($id);
        $auth->requestPasswordReset('change-reset@example.com');

        $user = $auth->resetPassword($mailer->resets[0]['key'], 'a new correct horse battery staple');

        self::assertSame($id, $user->id);
        self::assertFalse($auth->revokeToken($token));
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_resets')->fetchColumn());

        $row = $this->pdo->query('SELECT password, force_logout FROM users WHERE id = ' . $id)->fetch();

        self::assertTrue(\password_verify('a new correct horse battery staple', (string) $row['password']));
        self::assertFalse(\password_verify('correct horse battery staple', (string) $row['password']));
        self::assertSame(1, (int) $row['force_logout']);
    }

    public function testResetPasswordRejectsInvalidAndExpiredTokens(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->resetAuth($mailer);
        $this->createUser('invalid-reset@example.com');
        $auth->requestPasswordReset('invalid-reset@example.com');

        $token = $mailer->resets[0]['key'];

        try {
            $auth->resetPassword('invalid-token', 'a new correct horse battery staple');
            self::fail('Expected InvalidResetException');
        } catch (\Arris\Auth\Exception\InvalidResetException) {
        }

        $this->pdo->exec('UPDATE users_resets SET expires = ' . (\time() - 1));

        $this->expectException(\Arris\Auth\Exception\InvalidResetException::class);
        $auth->resetPassword($token, 'a new correct horse battery staple');
    }

    public function testResetLatestOnlyInvalidatesPreviousCode(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->resetAuth($mailer);
        $this->createUser('latest@example.com');

        $auth->requestPasswordReset('latest@example.com');
        $oldToken = $mailer->resets[0]['key'];
        $auth->requestPasswordReset('latest@example.com');
        $newToken = $mailer->resets[1]['key'];

        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users_resets')->fetchColumn());

        try {
            $auth->resetPassword($oldToken, 'a new correct horse battery staple');
            self::fail('Expected InvalidResetException');
        } catch (\Arris\Auth\Exception\InvalidResetException) {
        }

        self::assertTrue($auth->resetPassword($newToken, 'a new correct horse battery staple')->isVerified());
    }

    public function testResetAllowedAnyKeepsPreviousCodes(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->resetAuth($mailer, allowedAny: true);
        $this->createUser('any@example.com');

        $auth->requestPasswordReset('any@example.com');
        $auth->requestPasswordReset('any@example.com');

        self::assertSame(2, (int) $this->pdo->query('SELECT COUNT(*) FROM users_resets')->fetchColumn());

        $auth->resetPassword($mailer->resets[0]['key'], 'a new correct horse battery staple');

        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_resets')->fetchColumn());

        try {
            $auth->resetPassword($mailer->resets[1]['key'], 'another correct horse battery staple');
            self::fail('Expected InvalidResetException');
        } catch (\Arris\Auth\Exception\InvalidResetException) {
        }
    }

    public function testResetMailFailureReturnsStateAndKeepsToken(): void
    {
        $mailer = new RecordingMailer();
        $mailer->result = false;
        $auth = $this->resetAuth($mailer);
        $this->createUser('mail-reset@example.com');

        $state = $auth->requestPasswordReset('mail-reset@example.com');

        self::assertSame(ResetState::MAIL_FAILED, $state->reason);
        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users_resets')->fetchColumn());
        self::assertTrue($auth->resetPassword($mailer->resets[0]['key'], 'a new correct horse battery staple')->isVerified());
    }

    public function testDeleteExpiredResetsAndDeleteUserRows(): void
    {
        $mailer = new RecordingMailer();
        $auth = $this->resetAuth($mailer);
        $id = $this->createUser('cleanup-reset@example.com');
        $auth->requestPasswordReset('cleanup-reset@example.com');

        $this->pdo->exec('UPDATE users_resets SET expires = ' . (\time() - 1));
        self::assertSame(1, $auth->deleteExpiredResets());

        $auth->requestPasswordReset('cleanup-reset@example.com');
        $auth->deleteUser($id);

        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_resets')->fetchColumn());
    }

    public function testDeleteExpiredThrottling(): void
    {
        $this->pdo->exec(
            "INSERT INTO users_throttling (bucket, tokens, replenished_at, expires_at)
             VALUES ('expired-bucket', 1, " . (\time() - 10) . ", " . (\time() - 1) . ")"
        );

        self::assertSame(1, $this->auth()->deleteExpiredThrottling());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_throttling')->fetchColumn());
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

    public function testIsLoggedInAndGetUserIdAliases(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();

        self::assertFalse($auth->isLoggedIn());
        self::assertNull($auth->getUserId());

        $auth->login('user@example.com', 'correct horse battery staple');

        self::assertTrue($auth->isLoggedIn());
        self::assertSame($id, $auth->getUserId());
        self::assertSame($id, $auth->getUser()?->id);

        $auth->logout();

        self::assertFalse($auth->isLoggedIn());
        self::assertNull($auth->getUserId());
    }

    public function testConstructorResolvesRememberedUser(): void
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

        self::assertTrue($auth->isRemembered());
        self::assertSame($id, $auth->getUserId());
        self::assertTrue($auth->isLoggedIn());
    }

    public function testConstructorDoesNotDispatchToOverriddenUserMethod(): void
    {
        $_COOKIE['arris_auth'] = 'constructor-probe';

        $auth = new class($this->pdo, (new AuthConfig())->setAllowInsecureHttp(true)->setSessionCookie(['secure' => false])) extends Auth {
            public bool $ready = false;
            public int $userCalls = 0;

            public function __construct(PDO $pdo, ?AuthConfig $config = null)
            {
                parent::__construct($pdo, $config);
                $this->ready = true;
            }

            public function user(): ?User
            {
                $this->userCalls++;

                if (!$this->ready) {
                    throw new \LogicException('user() was called before the constructor completed');
                }

                return parent::user();
            }
        };

        self::assertSame(0, $auth->userCalls);
        self::assertNull($auth->user());
        self::assertSame(1, $auth->userCalls);
    }

    public function testAutoInitializeCanBeDisabled(): void
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

        $auth = $this->auth((new AuthConfig())->setAutoInitialize(false));

        self::assertFalse(\Arris\Auth\Session::isStarted());
        self::assertFalse($auth->isRemembered());

        self::assertSame($id, $auth->getUserId());
        self::assertTrue($auth->isRemembered());
    }

    public function testHttpsDetectionIgnoresForwardedHeaders(): void
    {
        $method = new \ReflectionMethod(Auth::class, 'isHttps');
        $method->setAccessible(true);
        $auth = $this->auth();

        self::assertFalse($method->invoke($auth));

        $_SERVER['HTTP_X_FORWARDED_PROTO'] = 'https';
        self::assertFalse($method->invoke($auth));

        $_SERVER['HTTP_X_FORWARDED_SSL'] = 'on';
        self::assertFalse($method->invoke($auth));

        unset($_SERVER['HTTP_X_FORWARDED_PROTO'], $_SERVER['HTTP_X_FORWARDED_SSL']);
        $_SERVER['HTTPS'] = 'on';
        self::assertTrue($method->invoke($auth));

        $_SERVER['HTTPS'] = 'off';
        $_SERVER['SERVER_PORT'] = 443;
        self::assertTrue($method->invoke($auth));
    }

    public function testUserOrFailThrowsWhenNotLoggedIn(): void
    {
        $this->expectException(NotLoggedInException::class);

        $this->auth()->userOrFail();
    }

    public function testUserOrFailReturnsCurrentUser(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');

        self::assertSame($id, $auth->userOrFail()->id);
    }

    public function testLoginUsesDummyPasswordWorkForUnknownAndAmbiguousUsers(): void
    {
        $this->createUser('one@example.com', username: 'same');
        $this->createUser('two@example.com', username: 'same');

        $auth = new class($this->pdo, (new AuthConfig())->setAllowInsecureHttp(true)->setSessionCookie(['secure' => false])) extends Auth {
            public int $dummyCalls = 0;

            protected function dummyPasswordVerify(string $password): void
            {
                $this->dummyCalls++;
            }
        };

        try {
            $auth->login('unknown@example.com', 'correct horse battery staple');
            self::fail('Expected InvalidCredentialsException');
        } catch (InvalidCredentialsException) {
        }

        self::assertSame(1, $auth->dummyCalls);

        try {
            $auth->login('one@example.com', 'wrong password');
            self::fail('Expected InvalidCredentialsException');
        } catch (InvalidCredentialsException) {
        }

        self::assertSame(1, $auth->dummyCalls);

        try {
            $auth->loginWithUsername('missing', 'correct horse battery staple');
            self::fail('Expected InvalidCredentialsException');
        } catch (InvalidCredentialsException) {
        }

        self::assertSame(2, $auth->dummyCalls);

        try {
            $auth->loginWithUsername('same', 'correct horse battery staple');
            self::fail('Expected AmbiguousUsernameException');
        } catch (AmbiguousUsernameException) {
        }

        self::assertSame(3, $auth->dummyCalls);
    }

    public function testHttpsIsRequiredByDefault(): void
    {
        unset($_SERVER['HTTPS'], $_SERVER['SERVER_PORT'], $_SERVER['HTTP_X_FORWARDED_PROTO'], $_SERVER['HTTP_X_FORWARDED_SSL']);

        $this->expectException(\Arris\Auth\Exception\ConfigurationException::class);
        new Auth(new PDO('sqlite::memory:'));
    }

    public function testAllowInsecureHttpOptOut(): void
    {
        unset($_SERVER['HTTPS'], $_SERVER['SERVER_PORT'], $_SERVER['HTTP_X_FORWARDED_PROTO'], $_SERVER['HTTP_X_FORWARDED_SSL']);

        $auth = new Auth(
            new PDO('sqlite::memory:'),
            (new AuthConfig())->setAllowInsecureHttp(true)
        );

        self::assertSame(Auth::MODE_AUTO, $auth->mode());
    }

    public function testEmptyEmailAndPasswordAreRejected(): void
    {
        try {
            $this->auth()->register('', 'correct horse battery staple');
            self::fail('Expected InvalidEmailException');
        } catch (InvalidEmailException) {
        }

        $this->expectException(InvalidPasswordException::class);
        $this->auth()->register('user@example.com', '');
    }

    public function testOneCharacterPasswordAndNonEmailStringAreAcceptedWithoutValidators(): void
    {
        $user = $this->auth()->register('not-an-email', 'x');

        self::assertSame('not-an-email', $user->email);
        self::assertTrue($user->isVerified());
    }

    public function testLoggerReceivesTokenOnlyInDebugMode(): void
    {
        $logger = new class extends \Psr\Log\AbstractLogger {
            /** @var list<array{level: mixed, message: string, context: array<string, mixed>}> */
            public array $records = [];

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                $this->records[] = [
                    'level' => $level,
                    'message' => (string) $message,
                    'context' => $context,
                ];
            }
        };

        $config = (new AuthConfig())->setLogger($logger, debug: true);
        $auth = $this->auth($config);
        $id = $auth->register('logger@example.com', 'correct horse battery staple')->id;
        $token = $auth->issueToken($id, name: 'logger-test');

        self::assertNotSame([], $logger->records);

        $tokenRecords = \array_values(\array_filter(
            $logger->records,
            static fn (array $record): bool => ($record['context']['token'] ?? null) === $token
        ));

        self::assertCount(1, $tokenRecords);
    }

    public function testLoggerOmitsTokenWhenDebugIsDisabled(): void
    {
        $logger = new class extends \Psr\Log\AbstractLogger {
            /** @var list<array<string, mixed>> */
            public array $contexts = [];

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                $this->contexts[] = $context;
            }
        };

        $config = (new AuthConfig())->setLogger($logger, debug: false);
        $auth = $this->auth($config);
        $id = $auth->register('logger-no-debug@example.com', 'correct horse battery staple')->id;
        $auth->issueToken($id, name: 'logger-test');

        foreach ($logger->contexts as $context) {
            self::assertArrayNotHasKey('token', $context);
        }
    }

    public function testLoginIsThrottledAfterLimit(): void
    {
        $this->createUser('throttle-login@example.com');

        $config = (new AuthConfig())->setThrottlingOptions(
            new ThrottlingOptions(enabled: true, login: new ThrottleRule(2, 60))
        );
        $auth = $this->auth($config, true);

        for ($i = 0; $i < 2; $i++) {
            try {
                $auth->login('throttle-login@example.com', 'wrong password');
            } catch (InvalidCredentialsException) {
            }
        }

        $this->expectException(\Arris\Auth\Exception\TooManyRequestsException::class);
        $auth->login('throttle-login@example.com', 'wrong password');
    }

    public function testRegistrationIsThrottledAfterLimit(): void
    {
        $config = (new AuthConfig())->setThrottlingOptions(
            new ThrottlingOptions(enabled: true, registration: new ThrottleRule(1, 60))
        );
        $auth = $this->auth($config, true);

        $auth->register('throttle-one@example.com', 'correct horse battery staple');

        $this->expectException(\Arris\Auth\Exception\TooManyRequestsException::class);
        $auth->register('throttle-two@example.com', 'correct horse battery staple');
    }

    public function testPasswordResetRequestIsThrottled(): void
    {
        $mailer = new RecordingMailer();
        $config = (new AuthConfig())
            ->setUserResetOptions(new UserResetOptions(enabled: true, ttl: 60))
            ->setThrottlingOptions(new ThrottlingOptions(enabled: true, reset: new ThrottleRule(1, 60)))
            ->setMailer($mailer);
        $auth = $this->auth($config, true);
        $this->createUser('throttle-reset@example.com');

        self::assertTrue($auth->requestPasswordReset('throttle-reset@example.com')->isSent());
        self::assertSame(
            ResetState::THROTTLED,
            $auth->requestPasswordReset('throttle-reset@example.com')->reason
        );
    }

    public function testConfirmationResendIsThrottled(): void
    {
        $mailer = new RecordingMailer();
        $config = (new AuthConfig())
            ->setUserConfirmationOptions(new UserConfirmationOptions(required: true, ttl: 60))
            ->setThrottlingOptions(new ThrottlingOptions(enabled: true, confirmation: new ThrottleRule(1, 60)))
            ->setMailer($mailer);
        $auth = $this->auth($config, true);

        $auth->register('throttle-confirm@example.com', 'correct horse battery staple');

        self::assertTrue($auth->resendConfirmation('throttle-confirm@example.com')->isSent());
        self::assertSame(
            ConfirmationState::THROTTLED,
            $auth->resendConfirmation('throttle-confirm@example.com')->reason
        );
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

    public function testVerifyUserThrowsForUnknownUser(): void
    {
        $this->expectException(\Arris\Auth\Exception\UnknownUserException::class);

        $this->auth()->verifyUser(999);
    }

    public function testVerifyUserInvalidatesCachedUser(): void
    {
        $config = (new AuthConfig())->setRequireVerified(false);
        $auth = $this->auth($config);
        $id = $auth->register('user@example.com', 'correct horse battery staple', 'user', verified: false)->id;
        $auth->login('user@example.com', 'correct horse battery staple');

        self::assertFalse($auth->user()?->isVerified());

        $auth->verifyUser($id);

        self::assertTrue($auth->user()?->isVerified());
    }

    public function testLoginRejectsDisabledUser(): void
    {
        $id = $this->createUser();
        $this->pdo->exec('UPDATE users SET status = ' . Status::BANNED->value . ' WHERE id = ' . $id);

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

    public function testBearerTokenIsRejectedAfterForceLogoutEvenIfRowSurvives(): void
    {
        $id = $this->createUser();
        $token = $this->auth()->issueToken($id);

        $this->pdo->exec('UPDATE users SET force_logout = force_logout + 1 WHERE id = ' . $id);

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;

        self::assertNull($this->auth(Auth::MODE_TOKEN)->user());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_tokens')->fetchColumn());
    }

    public function testIssueTokenRejectsNegativeTtlWithoutWritingRow(): void
    {
        $id = $this->createUser();
        $before = (int) $this->pdo->query('SELECT COUNT(*) FROM users_tokens')->fetchColumn();

        try {
            $this->auth()->issueToken($id, -1);
            self::fail('Expected ConfigurationException');
        } catch (ConfigurationException) {
        }

        self::assertSame($before, (int) $this->pdo->query('SELECT COUNT(*) FROM users_tokens')->fetchColumn());
    }

    public function testNewBearerTokenWorksAfterForceLogout(): void
    {
        $id = $this->createUser();
        $this->pdo->exec('UPDATE users SET force_logout = force_logout + 1 WHERE id = ' . $id);

        $token = $this->auth()->issueToken($id);

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;

        $user = $this->auth(Auth::MODE_TOKEN)->user();

        self::assertNotNull($user);
        self::assertSame($id, $user->id);
    }

    public function testRememberTokenIsRejectedAfterForceLogoutEvenIfRowSurvives(): void
    {
        $id = $this->createUser();
        $selector = \bin2hex(\random_bytes(12));
        $token = \bin2hex(\random_bytes(32));

        (new TokenRepository($this->pdo))->createRemember(
            $id,
            $selector,
            \hash('sha256', $token),
            \time() + 3600,
            0
        );

        $this->pdo->exec('UPDATE users SET force_logout = force_logout + 1 WHERE id = ' . $id);
        $_COOKIE['arris_remember'] = $selector . '~' . $token;

        self::assertNull($this->auth()->user());
    }

    public function testRecentRememberTokenWorksAfterForceLogout(): void
    {
        $id = $this->createUser();
        $this->pdo->exec('UPDATE users SET force_logout = force_logout + 1 WHERE id = ' . $id);

        $selector = \bin2hex(\random_bytes(12));
        $token = \bin2hex(\random_bytes(32));

        (new TokenRepository($this->pdo))->createRemember(
            $id,
            $selector,
            \hash('sha256', $token),
            \time() + 3600,
            1
        );

        $_COOKIE['arris_remember'] = $selector . '~' . $token;

        $user = $this->auth()->user();

        self::assertNotNull($user);
        self::assertSame($id, $user->id);
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

    public function testLazyLogoutClearsPersistedSession(): void
    {
        $this->createUser();
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');

        $sessionId = \session_id();
        \session_write_close();
        $_SESSION = [];
        $_COOKIE['arris_auth'] = $sessionId;

        $lazy = $this->auth((new AuthConfig())->setAutoInitialize(false));
        $lazy->logout();

        self::assertFalse($this->auth()->isLoggedIn());
    }

    public function testLazyChangePasswordKeepsCurrentSession(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');

        $sessionId = \session_id();
        \session_write_close();
        $_SESSION = [];
        $_COOKIE['arris_auth'] = $sessionId;

        $lazy = $this->auth((new AuthConfig())->setAutoInitialize(false));
        $lazy->changePassword($id, 'a new correct horse battery staple', true);

        $check = $this->auth();

        self::assertTrue($check->isLoggedIn());
        self::assertSame($id, $check->id());
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

    public function testChangePasswordRollsBackWhenTokenDeletionFails(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->issueToken($id);

        $this->pdo->exec("CREATE TRIGGER fail_token_delete BEFORE DELETE ON users_tokens BEGIN SELECT RAISE(ABORT, 'fail'); END");

        try {
            $auth->changePassword($id, 'a new correct horse battery staple', false);
            self::fail('Expected PDOException');
        } catch (\PDOException) {
        }

        $row = $this->pdo->query('SELECT password, force_logout FROM users WHERE id = ' . $id)->fetch();

        self::assertTrue(\password_verify('correct horse battery staple', (string) $row['password']));
        self::assertSame(0, (int) $row['force_logout']);
        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users_tokens')->fetchColumn());
    }

    public function testLogoutEverywhereRollsBackWhenTokenDeletionFails(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->issueToken($id);

        $this->pdo->exec("CREATE TRIGGER fail_token_delete BEFORE DELETE ON users_tokens BEGIN SELECT RAISE(ABORT, 'fail'); END");

        try {
            $auth->logoutEverywhere($id);
            self::fail('Expected PDOException');
        } catch (\PDOException) {
        }

        $row = $this->pdo->query('SELECT force_logout FROM users WHERE id = ' . $id)->fetch();

        self::assertSame(0, (int) $row['force_logout']);
        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users_tokens')->fetchColumn());
    }

    public function testDeleteUserRollsBackWhenUserDeletionFails(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->issueToken($id);

        $this->pdo->exec("CREATE TRIGGER fail_user_delete BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT, 'fail'); END");

        try {
            $auth->deleteUser($id);
            self::fail('Expected PDOException');
        } catch (\PDOException) {
        }

        self::assertNotFalse($this->pdo->query('SELECT id FROM users WHERE id = ' . $id)->fetch());
        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users_tokens')->fetchColumn());
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

    public function testRememberCookieIsRotatedOnUse(): void
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

        $oldCookie = $selector . '~' . $token;
        $_COOKIE['arris_remember'] = $oldCookie;

        $auth = $this->auth();

        self::assertSame($id, $auth->user()?->id);

        $newCookie = $_COOKIE['arris_remember'] ?? '';

        self::assertNotSame('', $newCookie);
        self::assertNotSame($oldCookie, $newCookie);
        self::assertSame(0, (int) $this->pdo->query(
            "SELECT COUNT(*) FROM users_tokens WHERE selector = '" . $selector . "'"
        )->fetchColumn());
        self::assertSame(1, (int) $this->pdo->query(
            "SELECT COUNT(*) FROM users_tokens WHERE kind = 'remember'"
        )->fetchColumn());

        \session_write_close();
        $_SESSION = [];
        unset($_COOKIE['arris_auth']);
        $_COOKIE['arris_remember'] = $oldCookie;

        self::assertNull($this->auth()->user());

        \session_write_close();
        $_SESSION = [];
        unset($_COOKIE['arris_auth']);
        $_COOKIE['arris_remember'] = $newCookie;

        self::assertSame($id, $this->auth()->user()?->id);
    }

    public function testInvalidRememberTokenDoesNotDeleteValidRow(): void
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

        $_COOKIE['arris_remember'] = $selector . '~wrong-token';

        self::assertNull($this->auth()->user());
        self::assertSame(1, (int) $this->pdo->query(
            "SELECT COUNT(*) FROM users_tokens WHERE kind = 'remember'"
        )->fetchColumn());
        self::assertArrayNotHasKey('arris_remember', $_COOKIE);
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
        self::assertSame('user@example.com', $auth->getEmail());
        self::assertSame('user', $auth->getUsername());
        self::assertSame([Role::ADMIN => 'ADMIN', Role::EDITOR => 'EDITOR'], $auth->getRoles());

        $user = $auth->user();
        self::assertSame($id, $user->id);
        self::assertContains('ADMIN', $user->roleNames());
        self::assertContains('EDITOR', $user->roleNames());
    }

    public function testHasRoleZeroIsFalse(): void
    {
        $this->createUser(rolesMask: Role::ADMIN);
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');

        self::assertFalse($auth->user()?->hasRole(0));
        self::assertTrue($auth->user()?->hasRole(Role::ADMIN));
    }

    public function testCustomRolesMapIsUsedByGetRolesAndRoleNamesForUser(): void
    {
        $map = ['GM' => Role::ADMIN, 'MAGE' => Role::MODERATOR];
        $config = (new AuthConfig())->setRolesMap($map);
        $auth = $this->auth($config);

        $id = $auth->register(
            'custom-roles@example.com',
            'correct horse battery staple',
            'custom-roles',
            rolesMask: Role::ADMIN | Role::MODERATOR
        )->id;
        $auth->login('custom-roles@example.com', 'correct horse battery staple');

        self::assertSame(
            [Role::ADMIN => 'GM', Role::MODERATOR => 'MAGE'],
            $auth->getRoles()
        );
        self::assertSame(['GM', 'MAGE'], $auth->roleNamesForUser($id));
        self::assertSame(
            ['GM'],
            $auth->roleNamesForUser($id, ['GM' => Role::ADMIN])
        );
    }

    public function testCustomRolesMapSupportsAliases(): void
    {
        $map = ['MAGE' => Role::MODERATOR, 'ARCHMAGE' => Role::MODERATOR];
        $auth = $this->auth((new AuthConfig())->setRolesMap($map));

        $id = $auth->register(
            'aliases@example.com',
            'correct horse battery staple',
            rolesMask: Role::MODERATOR
        )->id;

        self::assertSame(['MAGE', 'ARCHMAGE'], $auth->roleNamesForUser($id));
    }

    public function testRoleManagement(): void
    {
        $id = $this->createUser(rolesMask: Role::AUTHOR);
        $auth = $this->auth();

        self::assertSame(Role::AUTHOR, $auth->roles($id));

        self::assertSame(Role::AUTHOR | Role::EDITOR, $auth->addRole($id, Role::EDITOR));
        self::assertSame(Role::AUTHOR | Role::EDITOR, $auth->roles($id));

        self::assertSame(Role::EDITOR, $auth->removeRole($id, Role::AUTHOR));
        self::assertSame(Role::EDITOR, $auth->roles($id));

        self::assertSame(Role::ADMIN, $auth->setRole($id, Role::ADMIN));
        self::assertSame(Role::ADMIN, $auth->roles($id));

        self::assertSame(Role::ADMIN | Role::EDITOR, $auth->setRoles($id, Role::ADMIN | Role::EDITOR));
        self::assertSame(Role::ADMIN | Role::EDITOR, $auth->roles($id));
        self::assertSame(['ADMIN', 'EDITOR'], $auth->roleNamesForUser($id));
    }

    public function testRoleManagementForUnknownUserThrows(): void
    {
        $this->expectException(\Arris\Auth\Exception\UnknownUserException::class);

        $this->auth()->addRole(999, Role::ADMIN);
    }

    public function testRoleChangeInvalidatesCachedUser(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');

        self::assertFalse($auth->hasRole(Role::ADMIN));

        $auth->addRole($id, Role::ADMIN);

        self::assertTrue($auth->hasRole(Role::ADMIN));
    }

    public function testLoginInTokenModeThrows(): void
    {
        $this->createUser();

        $this->expectException(ConfigurationException::class);

        $this->auth(Auth::MODE_TOKEN)->login('user@example.com', 'correct horse battery staple');
    }

    public function testIssueTokenForUnknownUserThrows(): void
    {
        $this->expectException(\Arris\Auth\Exception\UnknownUserException::class);

        $this->auth()->issueToken(999);
    }

    public function testIssueTokenRejectsUnverifiedUser(): void
    {
        $id = $this->createUser(verified: false);

        $this->expectException(EmailNotVerifiedException::class);

        $this->auth()->issueToken($id);
    }

    public function testIssueTokenRejectsDisabledUser(): void
    {
        $id = $this->createUser();
        $this->pdo->exec('UPDATE users SET status = ' . Status::BANNED->value . ' WHERE id = ' . $id);

        $this->expectException(AccountDisabledException::class);

        $this->auth()->issueToken($id);
    }

    public function testBearerTokenIsRejectedWhenUserBecomesUnverified(): void
    {
        $id = $this->createUser();
        $token = $this->auth()->issueToken($id);

        $this->pdo->exec('UPDATE users SET verified = 0 WHERE id = ' . $id);

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;

        self::assertNull($this->auth(Auth::MODE_TOKEN)->user());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_tokens')->fetchColumn());
    }

    public function testSessionIsRejectedWhenUserBecomesUnverified(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');

        $this->pdo->exec('UPDATE users SET verified = 0 WHERE id = ' . $id);

        self::assertNull($this->auth()->user());
    }

    public function testUnverifiedUserCanUseBearerWhenVerificationIsNotRequired(): void
    {
        $config = (new AuthConfig())->setRequireVerified(false);
        $auth = $this->auth($config);
        $id = $auth->register('unverified@example.com', 'correct horse battery staple', verified: false)->id;
        $token = $auth->issueToken($id);

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;

        $user = $this->auth($config->setMode(Auth::MODE_TOKEN))->user();

        self::assertNotNull($user);
        self::assertSame($id, $user->id);
    }

    public function testLoginWithRememberCreatesRememberToken(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();

        $auth->login('user@example.com', 'correct horse battery staple', remember: true);

        $row = $this->pdo->query("SELECT * FROM users_tokens WHERE kind = 'remember'")->fetch();

        self::assertIsArray($row);
        self::assertSame($id, (int) $row['user_id']);
        self::assertNotSame('', (string) $row['selector']);
        self::assertSame(64, \strlen((string) $row['token']));
    }

    public function testLogoutAfterRememberLoginRevokesRememberTokenInSameRequest(): void
    {
        $this->createUser();
        $auth = $this->auth();

        $auth->login('user@example.com', 'correct horse battery staple', remember: true);

        self::assertArrayHasKey('arris_remember', $_COOKIE);
        self::assertSame(1, (int) $this->pdo->query("SELECT COUNT(*) FROM users_tokens WHERE kind = 'remember'")->fetchColumn());

        $auth->logout();

        self::assertArrayNotHasKey('arris_remember', $_COOKIE);
        self::assertSame(0, (int) $this->pdo->query("SELECT COUNT(*) FROM users_tokens WHERE kind = 'remember'")->fetchColumn());
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

    public function testChangePasswordThrowsForUnknownUser(): void
    {
        $this->expectException(\Arris\Auth\Exception\UnknownUserException::class);

        $this->auth()->changePassword(999, 'a new correct horse battery staple');
    }

    public function testReconfirmPassword(): void
    {
        $this->createUser();
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');

        self::assertTrue($auth->reconfirmPassword('correct horse battery staple'));
        self::assertFalse($auth->reconfirmPassword('wrong password'));
    }

    public function testReconfirmPasswordRequiresLogin(): void
    {
        $this->expectException(NotLoggedInException::class);

        $this->auth()->reconfirmPassword('correct horse battery staple');
    }

    public function testChangeOwnPasswordChecksOldPassword(): void
    {
        $this->createUser();
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');

        try {
            $auth->changeOwnPassword('wrong password', 'a new correct horse battery staple');
            self::fail('Expected InvalidPasswordException');
        } catch (InvalidPasswordException) {
        }

        $auth->changeOwnPassword('correct horse battery staple', 'a new correct horse battery staple');

        self::assertTrue($auth->check());
        self::assertTrue($auth->reconfirmPassword('a new correct horse battery staple'));
    }

    public function testDeleteUserRemovesTokensAndClearsCurrentSession(): void
    {
        $id = $this->createUser();
        $auth = $this->auth();
        $auth->login('user@example.com', 'correct horse battery staple');
        $token = $auth->issueToken($id);

        $auth->deleteUser($id);

        self::assertNull($this->pdo->query('SELECT * FROM users WHERE id = ' . $id)->fetch() ?: null);
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users_tokens')->fetchColumn());
        self::assertFalse($auth->check());
        self::assertNull($auth->id());

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
        self::assertNull($this->auth(Auth::MODE_TOKEN)->user());
    }

    public function testDeleteUserThrowsForUnknownUser(): void
    {
        $this->expectException(\Arris\Auth\Exception\UnknownUserException::class);

        $this->auth()->deleteUser(999);
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
