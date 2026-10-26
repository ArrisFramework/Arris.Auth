<?php

declare(strict_types=1);

namespace Arris\Auth\Session;

use Arris\Auth\TableName;
use InvalidArgumentException;
use PDO;
use PDOException;
use SessionHandlerInterface;
use SessionUpdateTimestampHandlerInterface;

/**
 * Stores PHP sessions in a PDO table.
 *
 * The table must contain id, data and last_activity columns.
 */
final class PdoSessionHandler implements SessionHandlerInterface, SessionUpdateTimestampHandlerInterface
{
    private string $table;
    private int $ttl;

    /**
     * Creates a PDO-backed session handler.
     *
     * @param PDO $pdo
     * @param string $table table name without prefix
     * @param string|null $schema optional schema/database qualifier
     * @param string $prefix optional table prefix
     * @param int|null $ttl session lifetime in seconds; defaults to session.gc_maxlifetime
     * @throws InvalidArgumentException
     */
    public function __construct(
        private readonly PDO $pdo,
        string $table = 'sessions',
        ?string $schema = null,
        string $prefix = '',
        ?int $ttl = null,
    ) {
        if ($ttl !== null && $ttl <= 0) {
            throw new InvalidArgumentException('Session TTL must be positive');
        }

        $iniTtl = (int) \ini_get('session.gc_maxlifetime');

        $this->table = TableName::make($table, $schema, $prefix);
        $this->ttl = $ttl ?? ($iniTtl > 0 ? $iniTtl : 1440);
    }

    /**
     * Opens the session storage. PDO is already connected, so this is a no-op.
     */
    public function open(string $path, string $name): bool
    {
        return true;
    }

    /**
     * Closes the session storage. PDO is managed externally, so this is a no-op.
     */
    public function close(): bool
    {
        return true;
    }

    /**
     * Reads session data by ID. Returns an empty string for missing or expired sessions.
     */
    public function read(string $id): string|false
    {
        $statement = $this->pdo->prepare(
            "SELECT data FROM {$this->table} WHERE id = ? AND last_activity >= ? LIMIT 1"
        );
        $statement->execute([$id, \time() - $this->ttl]);

        $data = $statement->fetchColumn();

        return $data === false ? '' : (string) $data;
    }

    /**
     * Writes session data, inserting or updating the row as needed.
     */
    public function write(string $id, string $data): bool
    {
        $now = \time();
        $update = $this->pdo->prepare(
            "UPDATE {$this->table} SET data = ?, last_activity = ? WHERE id = ?"
        );
        $update->execute([$data, $now, $id]);

        if ($update->rowCount() > 0) {
            return true;
        }

        $exists = $this->pdo->prepare("SELECT 1 FROM {$this->table} WHERE id = ? LIMIT 1");
        $exists->execute([$id]);

        if ($exists->fetchColumn() !== false) {
            return true;
        }

        try {
            $insert = $this->pdo->prepare(
                "INSERT INTO {$this->table} (id, data, last_activity) VALUES (?, ?, ?)"
            );
            $insert->execute([$id, $data, $now]);
        } catch (PDOException $e) {
            if (!\in_array((string) $e->getCode(), ['23000', '23505'], true)) {
                throw $e;
            }

            $update->execute([$data, $now, $id]);
        }

        return true;
    }

    /**
     * Deletes a session by ID.
     */
    public function destroy(string $id): bool
    {
        $statement = $this->pdo->prepare("DELETE FROM {$this->table} WHERE id = ?");
        $statement->execute([$id]);

        return true;
    }

    /**
     * Deletes sessions older than the given lifetime.
     */
    public function gc(int $max_lifetime): int|false
    {
        $statement = $this->pdo->prepare(
            "DELETE FROM {$this->table} WHERE last_activity < ?"
        );
        $statement->execute([\time() - $max_lifetime]);

        return $statement->rowCount();
    }

    /**
     * Returns whether a non-expired session with the given ID exists.
     */
    public function validateId(string $id): bool
    {
        $statement = $this->pdo->prepare(
            "SELECT 1 FROM {$this->table} WHERE id = ? AND last_activity >= ? LIMIT 1"
        );
        $statement->execute([$id, \time() - $this->ttl]);

        return $statement->fetchColumn() !== false;
    }

    /**
     * Refreshes the session's last_activity timestamp.
     */
    public function updateTimestamp(string $id, string $data): bool
    {
        $now = \time();
        $statement = $this->pdo->prepare(
            "UPDATE {$this->table} SET last_activity = ? WHERE id = ? AND last_activity >= ?"
        );
        $statement->execute([$now, $id, $now - $this->ttl]);

        return $statement->rowCount() > 0 || $this->validateId($id);
    }
}
