<?php

declare(strict_types=1);

namespace Tests;

use Arris\Auth\Auth;
use Arris\Auth\AuthConfig;
use Arris\Auth\DTO\ThrottleRule;
use Arris\Auth\DTO\ThrottlingOptions;
use Arris\Auth\DTO\UserConfirmationOptions;
use Arris\Auth\DTO\UserResetOptions;
use Arris\Auth\Exception\ConfigurationException;
use Arris\Auth\Mailer\NullMailer;
use Arris\Auth\Role;
use PDO;
use PHPUnit\Framework\TestCase;
use SessionHandlerInterface;

final class AuthConfigTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $_SERVER['HTTPS'] = 'on';
    }

    public function testDefaults(): void
    {
        $config = new AuthConfig();

        self::assertSame(Auth::MODE_AUTO, $config->getMode());
        self::assertSame('', $config->getTablePrefix());
        self::assertNull($config->getDbSchema());
        self::assertSame('arris_auth', $config->getSessionName());
        self::assertSame([], $config->getSessionCookie());
        self::assertNull($config->getSessionHandler());
        self::assertSame('arris_remember', $config->getRememberCookieName());
        self::assertSame(60 * 60 * 24 * 30, $config->getRememberTtl());
        self::assertSame(60 * 60 * 24 * 30, $config->getTokenTtl());
        self::assertTrue($config->getRequireVerified());
        self::assertTrue($config->getRejectNonNormalStatus());
        self::assertTrue($config->getUpdateLastLogin());
        self::assertSame(60, $config->getTouchTokenInterval());
        self::assertTrue($config->getAutoInitialize());
        self::assertNull($config->getRolesMap());
        self::assertFalse($config->getUserConfirmationOptions()->required);
        self::assertSame(3600, $config->getUserConfirmationOptions()->ttl);
        self::assertFalse($config->getUserResetOptions()->enabled);
        self::assertSame(3600, $config->getUserResetOptions()->ttl);
        self::assertFalse($config->getUserResetOptions()->allowedAny);
        self::assertInstanceOf(\Arris\Auth\Mailer\NativeMailer::class, $config->getMailer());
        self::assertFalse($config->getAllowInsecureHttp());
        self::assertTrue($config->getThrottlingOptions()->enabled);
        self::assertSame(5, $config->getThrottlingOptions()->login->limit);
        self::assertSame(900, $config->getThrottlingOptions()->login->window);
    }

    public function testRolesMapDefaultsToNullAndCanBeReset(): void
    {
        $config = new AuthConfig();

        self::assertNull($config->getRolesMap());

        $map = ['GM' => Role::ADMIN, 'MAGE' => Role::MODERATOR];
        $config->setRolesMap($map);

        self::assertSame($map, $config->getRolesMap());

        $config->setRolesMap(null);

        self::assertNull($config->getRolesMap());
    }

    public function testInvalidRolesMapIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setRolesMap(['INVALID' => 3]);
    }

    public function testRolesMapBitAboveUnsignedIntIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setRolesMap(['TOO_HIGH' => 1 << 32]);
    }

    public function testRolesMapRejectsEmptyName(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setRolesMap(['' => Role::ADMIN]);
    }

    public function testFluentSetters(): void
    {
        $handler = $this->handler();
        $mailer = new NullMailer();

        $config = (new AuthConfig())
            ->setMode(Auth::MODE_TOKEN)
            ->setTablePrefix('app_')
            ->setDbSchema('public')
            ->setSessionName('app_session')
            ->setSessionCookie(['secure' => true, 'samesite' => 'None'])
            ->setSessionHandler($handler)
            ->setRememberCookieName('app_remember')
            ->setRememberTtl(120)
            ->setTokenTtl(0)
            ->setRequireVerified(false)
            ->setRejectNonNormalStatus(false)
            ->setUpdateLastLogin(false)
            ->setTouchTokenInterval(0)
            ->setAutoInitialize(false)
            ->setUserConfirmationOptions(new UserConfirmationOptions(required: true, ttl: 120))
            ->setUserResetOptions(new UserResetOptions(enabled: true, ttl: 300, allowedAny: true))
            ->setMailer($mailer);

        self::assertSame(Auth::MODE_TOKEN, $config->getMode());
        self::assertSame('app_', $config->getTablePrefix());
        self::assertSame('public', $config->getDbSchema());
        self::assertSame('app_session', $config->getSessionName());
        self::assertSame(['secure' => true, 'samesite' => 'None'], $config->getSessionCookie());
        self::assertSame($handler, $config->getSessionHandler());
        self::assertSame('app_remember', $config->getRememberCookieName());
        self::assertSame(120, $config->getRememberTtl());
        self::assertSame(0, $config->getTokenTtl());
        self::assertFalse($config->getRequireVerified());
        self::assertFalse($config->getRejectNonNormalStatus());
        self::assertFalse($config->getUpdateLastLogin());
        self::assertSame(0, $config->getTouchTokenInterval());
        self::assertFalse($config->getAutoInitialize());
        self::assertTrue($config->getUserConfirmationOptions()->required);
        self::assertSame(120, $config->getUserConfirmationOptions()->ttl);
        self::assertTrue($config->getUserResetOptions()->enabled);
        self::assertSame(300, $config->getUserResetOptions()->ttl);
        self::assertTrue($config->getUserResetOptions()->allowedAny);
        self::assertSame($mailer, $config->getMailer());
    }

    public function testUserConfirmationOptionsKeepNullsAndAcceptScalars(): void
    {
        $config = (new AuthConfig())->setUserConfirmationOptions(new UserConfirmationOptions(required: true, ttl: 120));

        $config->setUserConfirmationOptions();
        self::assertTrue($config->getUserConfirmationOptions()->required);
        self::assertSame(120, $config->getUserConfirmationOptions()->ttl);

        $config->setUserConfirmationOptions();
        self::assertSame(120, $config->getUserConfirmationOptions()->ttl);

        $config->setUserConfirmationOptions(new UserConfirmationOptions(required: false));
        self::assertFalse($config->getUserConfirmationOptions()->required);

        $config->setUserConfirmationOptions(new UserConfirmationOptions(required: true));
        self::assertTrue($config->getUserConfirmationOptions()->required);

        $config->setUserConfirmationOptions(new UserConfirmationOptions(ttl: 61));
        self::assertSame(61, $config->getUserConfirmationOptions()->ttl);
    }

    public function testUserResetOptionsKeepNullsAndAcceptScalars(): void
    {
        $config = (new AuthConfig())->setUserResetOptions(new UserResetOptions(enabled: true, ttl: 120, allowedAny: true));

        $config->setUserResetOptions();
        self::assertTrue($config->getUserResetOptions()->enabled);
        self::assertSame(120, $config->getUserResetOptions()->ttl);
        self::assertTrue($config->getUserResetOptions()->allowedAny);

        $config->setUserResetOptions();
        self::assertSame(120, $config->getUserResetOptions()->ttl);

        $config->setUserResetOptions(new UserResetOptions(enabled: false, allowedAny: false));
        self::assertFalse($config->getUserResetOptions()->enabled);
        self::assertFalse($config->getUserResetOptions()->allowedAny);

        $config->setUserResetOptions(new UserResetOptions(enabled: true, allowedAny: true));
        self::assertTrue($config->getUserResetOptions()->enabled);
        self::assertTrue($config->getUserResetOptions()->allowedAny);

        $config->setUserResetOptions(new UserResetOptions(ttl: 61));
        self::assertSame(61, $config->getUserResetOptions()->ttl);
    }

    public function testOptionsDtoWithMethods(): void
    {
        $confirmation = (new UserConfirmationOptions())
            ->withRequired(true)
            ->withTtl(120);

        self::assertTrue($confirmation->required);
        self::assertSame(120, $confirmation->ttl);

        $reset = (new UserResetOptions())
            ->withEnabled(true)
            ->withTtl(300)
            ->withAllowedAny(true);

        self::assertTrue($reset->enabled);
        self::assertSame(300, $reset->ttl);
        self::assertTrue($reset->allowedAny);

        $throttling = (new ThrottlingOptions())
            ->withEnabled(false)
            ->withLogin(new ThrottleRule(2, 60));

        self::assertFalse($throttling->enabled);
        self::assertSame(2, $throttling->login->limit);
        self::assertSame(60, $throttling->login->window);
        self::assertSame(3, $throttling->registration->limit);
    }

    public function testSetOptionDispatchesToTypedSetters(): void
    {
        $rolesMap = ['GM' => Role::ADMIN];
        $mailer = new NullMailer();

        $config = (new AuthConfig())
            ->setOption('mode', Auth::MODE_SESSION)
            ->setOption('session_name', 'app_session')
            ->setOption('token_ttl', 0)
            ->setOption('auto_initialize', false)
            ->setOption('roles_map', $rolesMap)
            ->setOption('user_confirmation_required', true)
            ->setOption('user_confirmation_ttl', 120)
            ->setOption('user_reset_enabled', true)
            ->setOption('user_reset_ttl', 300)
            ->setOption('user_reset_allowed_any', true)
            ->setOption('allow_insecure_http', true)
            ->setOption('throttling_options', new ThrottlingOptions(enabled: false))
            ->setOption('mailer', $mailer);

        self::assertSame(Auth::MODE_SESSION, $config->getMode());
        self::assertSame('app_session', $config->getSessionName());
        self::assertSame(0, $config->getTokenTtl());
        self::assertFalse($config->getAutoInitialize());
        self::assertSame($rolesMap, $config->getRolesMap());
        self::assertTrue($config->getUserConfirmationOptions()->required);
        self::assertSame(120, $config->getUserConfirmationOptions()->ttl);
        self::assertTrue($config->getUserResetOptions()->enabled);
        self::assertSame(300, $config->getUserResetOptions()->ttl);
        self::assertTrue($config->getUserResetOptions()->allowedAny);
        self::assertTrue($config->getAllowInsecureHttp());
        self::assertFalse($config->getThrottlingOptions()->enabled);
        self::assertSame($mailer, $config->getMailer());
    }

    public function testInvalidModeIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setMode('invalid');
    }

    public function testUnknownOptionIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setOption('unknown', true);
    }

    public function testEmptySessionNameIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setSessionName('');
    }

    public function testUnknownSessionCookieOptionIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setSessionCookie(['unknown' => true]);
    }

    public function testInvalidSessionCookieOptionTypeIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setSessionCookie(['secure' => 'yes']);
    }

    public function testInvalidSessionCookieSameSiteIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setSessionCookie(['samesite' => 'bogus']);
    }

    public function testNegativeSessionCookieLifetimeIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setSessionCookie(['lifetime' => -1]);
    }

    public function testSameSiteNoneRequiresSecureAtConfigTime(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setSessionCookie(['secure' => false, 'samesite' => 'None']);
    }

    public function testSameSiteNoneRequiresSecureAfterAutoDetection(): void
    {
        unset(
            $_SERVER['HTTPS'],
            $_SERVER['SERVER_PORT'],
            $_SERVER['HTTP_X_FORWARDED_PROTO'],
            $_SERVER['HTTP_X_FORWARDED_SSL'],
        );

        $config = (new AuthConfig())->setAllowInsecureHttp(true)->setSessionCookie(['samesite' => 'None']);

        $this->expectException(ConfigurationException::class);

        new Auth(new PDO('sqlite::memory:'), $config);
    }

    public function testNegativeTtlIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setTokenTtl(-1);
    }

    public function testNonPositiveConfirmationTtlIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setUserConfirmationOptions(new UserConfirmationOptions(ttl: 0));
    }

    public function testNonPositiveUserResetTtlIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setUserResetOptions(new UserResetOptions(ttl: 0));
    }

    public function testAuthUsesDefaultConfigWhenNullIsPassed(): void
    {
        $auth = new Auth(new PDO('sqlite::memory:'));

        self::assertSame(Auth::MODE_AUTO, $auth->mode());
    }

    public function testAuthClonesConfig(): void
    {
        $config = (new AuthConfig())->setMode(Auth::MODE_SESSION);
        $auth = new Auth(new PDO('sqlite::memory:'), $config);

        $config->setMode(Auth::MODE_TOKEN);

        self::assertSame(Auth::MODE_SESSION, $auth->mode());
    }

    private function handler(): SessionHandlerInterface
    {
        return new class implements SessionHandlerInterface {
            public function open(string $path, string $name): bool
            {
                return true;
            }

            public function close(): bool
            {
                return true;
            }

            public function read(string $id): string|false
            {
                return '';
            }

            public function write(string $id, string $data): bool
            {
                return true;
            }

            public function destroy(string $id): bool
            {
                return true;
            }

            public function gc(int $max_lifetime): int|false
            {
                return 0;
            }
        };
    }
}
