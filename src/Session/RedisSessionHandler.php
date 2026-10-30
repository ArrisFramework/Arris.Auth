<?php

declare(strict_types=1);

namespace Arris\Auth\Session;

use InvalidArgumentException;
use Redis;
use SessionHandlerInterface;
use SessionUpdateTimestampHandlerInterface;

/**
 * Stores PHP sessions in Redis.
 *
 * Requires the phpredis extension and an already connected Redis client.
 *
 *
 * Хранит PHP-сессии в Redis.
 *
 * Требует расширение phpredis и уже подключённый клиент Redis.
 */
final class RedisSessionHandler implements SessionHandlerInterface, SessionUpdateTimestampHandlerInterface
{
    /**
     * Creates a Redis-backed session handler.
     *
     * Создаёт обработчик сессий на базе Redis.
     *
     * @param Redis $redis
     * @param int $ttl
     * @param string $prefix
     * @throws InvalidArgumentException
     */
    public function __construct(
        private readonly Redis $redis,
        private readonly int $ttl = 1440,
        private readonly string $prefix = 'arris:session:',
    ) {
        if ($ttl <= 0) {
            throw new InvalidArgumentException('Session TTL must be positive');
        }
    }

    /**

     */
    /**
     * Opens the session storage. Redis is already connected, so this is a no-op.
     *
     * Открывает хранилище сессий. Redis уже подключён, поэтому ничего не делает.*
     *
     * @param string $path
     * @param string $name
     *
     * @return bool
     */
    public function open(string $path, string $name): bool
    {
        return true;
    }

    /**
     * Closes the session storage. The Redis connection is managed externally.
     *
     * Закрывает хранилище сессий. Соединение Redis управляется извне.
     *
     * @return bool
     */
    public function close(): bool
    {
        return true;
    }

    /**
     * Reads session data by ID. Returns an empty string for missing sessions.
     *
     * Читает данные сессии по ID. Возвращает пустую строку для отсутствующих сессий.
     *
     * @param string $id
     *
     * @return string|false
     * @throws \RedisException
     */
    public function read(string $id): string|false
    {
        $data = $this->redis->get($this->prefix . $id);

        return \is_string($data) ? $data : '';
    }

    /**
     * Writes session data with the configured TTL.
     *
     * Записывает данные сессии с настроенным TTL.
     *
     *
     * @param string $id
     * @param string $data
     *
     * @return bool
     * @throws \RedisException
     */
    public function write(string $id, string $data): bool
    {
        return (bool) $this->redis->setex($this->prefix . $id, $this->ttl, $data);
    }

    /**
     * Deletes a session by ID.
     *
     * Удаляет сессию по ID.
     *
     * @param string $id
     *
     * @return bool
     * @throws \RedisException
     */
    public function destroy(string $id): bool
    {
        return $this->redis->del($this->prefix . $id) > 0;
    }

    /**
     * Redis expires sessions automatically, so garbage collection is a no-op.
     *
     * Redis истекает сессии автоматически, поэтому сборка мусора ничего не делает.
     *
     * @param int $max_lifetime
     *
     * @return int|false
     */
    public function gc(int $max_lifetime): int|false
    {
        return 0;
    }

    /**
     * Returns whether a session with the given ID exists.
     *
     * Возвращает, существует ли сессия с указанным ID.
     *
     * @param string $id
     *
     * @return bool
     * @throws \RedisException
     */
    public function validateId(string $id): bool
    {
        return (bool) $this->redis->exists($this->prefix . $id);
    }

    /**
     * Refreshes the session TTL.
     *
     * Обновляет TTL сессии.
     *
     * @param string $id
     * @param string $data
     *
     * @return bool
     * @throws \RedisException
     */
    public function updateTimestamp(string $id, string $data): bool
    {
        return (bool) $this->redis->expire($this->prefix . $id, $this->ttl);
    }
}
