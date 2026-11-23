<?php

declare(strict_types=1);

namespace Tests;

use Arris\Auth\Auth;
use Arris\Auth\AuthConfig;
use Arris\Auth\Exception\ConfigurationException;
use PDO;
use PHPUnit\Framework\TestCase;
use SessionHandlerInterface;

final class AuthConfigTest extends TestCase
{
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
        self::assertSame(8, $config->getMinPasswordLength());
        self::assertTrue($config->getUpdateLastLogin());
        self::assertSame(60, $config->getTouchTokenInterval());
        self::assertTrue($config->getAutoInitialize());
    }

    public function testFluentSetters(): void
    {
        $handler = $this->handler();

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
            ->setMinPasswordLength(12)
            ->setUpdateLastLogin(false)
            ->setTouchTokenInterval(0)
            ->setAutoInitialize(false);

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
        self::assertSame(12, $config->getMinPasswordLength());
        self::assertFalse($config->getUpdateLastLogin());
        self::assertSame(0, $config->getTouchTokenInterval());
        self::assertFalse($config->getAutoInitialize());
    }

    public function testSetOptionDispatchesToTypedSetters(): void
    {
        $config = (new AuthConfig())
            ->setOption('mode', Auth::MODE_SESSION)
            ->setOption('session_name', 'app_session')
            ->setOption('token_ttl', 0)
            ->setOption('min_password_length', 10)
            ->setOption('auto_initialize', false);

        self::assertSame(Auth::MODE_SESSION, $config->getMode());
        self::assertSame('app_session', $config->getSessionName());
        self::assertSame(0, $config->getTokenTtl());
        self::assertSame(10, $config->getMinPasswordLength());
        self::assertFalse($config->getAutoInitialize());
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

    public function testNegativeTtlIsRejected(): void
    {
        $this->expectException(ConfigurationException::class);

        (new AuthConfig())->setTokenTtl(-1);
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
