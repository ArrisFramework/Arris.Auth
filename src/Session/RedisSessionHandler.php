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
 */
final class RedisSessionHandler implements SessionHandlerInterface, SessionUpdateTimestampHandlerInterface
{
    /**
     * Creates a Redis-backed session handler.
     *
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
     * Opens the session storage. Redis is already connected, so this is a no-op.
     */
    public function open(string $path, string $name): bool
    {
        return true;
    }

    /**
     * Closes the session storage. The Redis connection is managed externally.
     */
    public function close(): bool
    {
        return true;
    }

    /**
     * Reads session data by ID. Returns an empty string for missing sessions.
     */
    public function read(string $id): string|false
    {
        $data = $this->redis->get($this->prefix . $id);

        return \is_string($data) ? $data : '';
    }

    /**
     * Writes session data with the configured TTL.
     */
    public function write(string $id, string $data): bool
    {
        return (bool) $this->redis->setex($this->prefix . $id, $this->ttl, $data);
    }

    /**
     * Deletes a session by ID.
     */
    public function destroy(string $id): bool
    {
        return $this->redis->del($this->prefix . $id) > 0;
    }

    /**
     * Redis expires sessions automatically, so garbage collection is a no-op.
     */
    public function gc(int $max_lifetime): int|false
    {
        return 0;
    }

    /**
     * Returns whether a session with the given ID exists.
     */
    public function validateId(string $id): bool
    {
        return (bool) $this->redis->exists($this->prefix . $id);
    }

    /**
     * Refreshes the session TTL.
     */
    public function updateTimestamp(string $id, string $data): bool
    {
        return (bool) $this->redis->expire($this->prefix . $id, $this->ttl);
    }
}
