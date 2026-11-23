<?php

declare(strict_types=1);

namespace Tests;

use Arris\Auth\Auth;
use Arris\Auth\AuthConfig;
use Arris\Auth\Session\PDOSessionHandler;
use Arris\Auth\Session\RedisSessionHandler;
use PDO;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use Redis;
use SessionHandlerInterface;

final class SessionHandlerTest extends TestCase
{
    public function testPdoHandlerStoresReadsUpdatesAndDeletesSession(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec(
            'CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                last_activity INTEGER NOT NULL
            )'
        );

        $handler = new PDOSessionHandler($pdo, 'sessions', ttl: 60);

        self::assertSame('', $handler->read('session-id'));
        self::assertFalse($handler->validateId('session-id'));

        self::assertTrue($handler->write('session-id', 'payload'));
        self::assertSame('payload', $handler->read('session-id'));
        self::assertTrue($handler->validateId('session-id'));

        self::assertTrue($handler->write('session-id', 'updated'));
        self::assertSame('updated', $handler->read('session-id'));

        self::assertTrue($handler->updateTimestamp('session-id', 'updated'));
        self::assertTrue($handler->destroy('session-id'));
        self::assertSame('', $handler->read('session-id'));
    }

    public function testPdoHandlerExpiresAndCollectsSessions(): void
    {
        $pdo = new PDO('sqlite::memory:');
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->exec(
            'CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                last_activity INTEGER NOT NULL
            )'
        );

        $handler = new PDOSessionHandler($pdo, 'sessions', ttl: 60);
        $handler->write('session-id', 'payload');

        $pdo->exec('UPDATE sessions SET last_activity = ' . (\time() - 120));

        self::assertSame('', $handler->read('session-id'));
        self::assertFalse($handler->validateId('session-id'));
        self::assertSame(1, $handler->gc(60));
    }

    #[RunInSeparateProcess]
    public function testAuthInstallsConfiguredSessionHandlerBeforeStart(): void
    {
        $handler = new class implements SessionHandlerInterface {
            /** @var list<string> */
            public array $readIds = [];

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
                $this->readIds[] = $id;

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

        $_COOKIE['arris_auth'] = 'custom-session-id';

        $config = (new AuthConfig())
            ->setSessionName('arris_auth')
            ->setSessionHandler($handler);

        $auth = new Auth(new PDO('sqlite::memory:'), $config);

        self::assertNull($auth->user());
        self::assertContains('custom-session-id', $handler->readIds);
    }

    public function testRedisHandlerStoresReadsUpdatesAndDeletesSession(): void
    {
        if (!\class_exists(Redis::class)) {
            self::markTestSkipped('The redis extension is not available');
        }

        $redis = new Redis();

        try {
            if (!$redis->connect('127.0.0.1', 6379, 0.2) || !$redis->ping()) {
                self::markTestSkipped('Redis is not available');
            }
        } catch (\RedisException) {
            self::markTestSkipped('Redis is not available');
        }

        $prefix = 'arris:test:' . \bin2hex(\random_bytes(8)) . ':';
        $handler = new RedisSessionHandler($redis, 60, $prefix);
        $id = 'session-id';

        try {
            self::assertSame('', $handler->read($id));
            self::assertFalse($handler->validateId($id));

            self::assertTrue($handler->write($id, 'payload'));
            self::assertSame('payload', $handler->read($id));
            self::assertTrue($handler->validateId($id));

            self::assertTrue($handler->updateTimestamp($id, 'payload'));
            self::assertTrue($handler->destroy($id));
            self::assertSame('', $handler->read($id));
        } finally {
            $redis->del($prefix . $id);
        }
    }
}
