<?php

declare(strict_types=1);

namespace Arris\Auth\Repository;

use Arris\Auth\TableName;
use PDO;

final class TokenRepository
{
    public const KIND_API = 'api';
    public const KIND_REMEMBER = 'remember';

    private string $table;

    public function __construct(
        private readonly PDO $pdo,
        ?string $schema = null,
        string $prefix = '',
    ) {
        $this->table = TableName::make('users_tokens', $schema, $prefix);
    }

    public function createApi(int $userId, string $tokenHash, int $expires, ?string $name = null): int
    {
        $statement = $this->pdo->prepare(
            "INSERT INTO {$this->table}
                (user, kind, selector, token, name, expires, created)
             VALUES (?, ?, NULL, ?, ?, ?, ?)"
        );

        $statement->execute([
            $userId,
            self::KIND_API,
            $tokenHash,
            $name,
            $expires,
            \time(),
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    public function createRemember(int $userId, string $selector, string $tokenHash, int $expires): int
    {
        $statement = $this->pdo->prepare(
            "INSERT INTO {$this->table}
                (user, kind, selector, token, name, expires, created)
             VALUES (?, ?, ?, ?, NULL, ?, ?)"
        );

        $statement->execute([
            $userId,
            self::KIND_REMEMBER,
            $selector,
            $tokenHash,
            $expires,
            \time(),
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    /**
     * @return array<string, mixed>|null
     */
    public function findApi(string $tokenHash): ?array
    {
        return $this->fetchOne(
            "SELECT * FROM {$this->table}
             WHERE kind = ? AND token = ? AND (expires = 0 OR expires > ?)
             LIMIT 1",
            [self::KIND_API, $tokenHash, \time()]
        );
    }

    /**
     * @return array<string, mixed>|null
     */
    public function findRemember(string $selector): ?array
    {
        return $this->fetchOne(
            "SELECT * FROM {$this->table}
             WHERE kind = ? AND selector = ? AND expires > ?
             LIMIT 1",
            [self::KIND_REMEMBER, $selector, \time()]
        );
    }

    public function touch(int $id): void
    {
        $statement = $this->pdo->prepare(
            "UPDATE {$this->table} SET last_used = ? WHERE id = ?"
        );
        $statement->execute([\time(), $id]);
    }

    public function delete(int $id): bool
    {
        $statement = $this->pdo->prepare("DELETE FROM {$this->table} WHERE id = ?");
        $statement->execute([$id]);

        return $statement->rowCount() > 0;
    }

    public function deleteByHash(string $tokenHash, ?string $kind = null): int
    {
        if ($kind !== null) {
            $statement = $this->pdo->prepare(
                "DELETE FROM {$this->table} WHERE token = ? AND kind = ?"
            );
            $statement->execute([$tokenHash, $kind]);

            return $statement->rowCount();
        }

        $statement = $this->pdo->prepare("DELETE FROM {$this->table} WHERE token = ?");
        $statement->execute([$tokenHash]);

        return $statement->rowCount();
    }

    public function deleteBySelector(string $selector): int
    {
        $statement = $this->pdo->prepare(
            "DELETE FROM {$this->table} WHERE selector = ?"
        );
        $statement->execute([$selector]);

        return $statement->rowCount();
    }

    public function deleteByUser(int $userId, ?string $kind = null): int
    {
        if ($kind !== null) {
            $statement = $this->pdo->prepare(
                "DELETE FROM {$this->table} WHERE user = ? AND kind = ?"
            );
            $statement->execute([$userId, $kind]);

            return $statement->rowCount();
        }

        $statement = $this->pdo->prepare(
            "DELETE FROM {$this->table} WHERE user = ?"
        );
        $statement->execute([$userId]);

        return $statement->rowCount();
    }

    public function deleteExpired(): int
    {
        $statement = $this->pdo->prepare(
            "DELETE FROM {$this->table} WHERE expires > 0 AND expires < ?"
        );
        $statement->execute([\time()]);

        return $statement->rowCount();
    }

    /**
     * @param list<int|string> $params
     * @return array<string, mixed>|null
     */
    private function fetchOne(string $sql, array $params): ?array
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($params);
        $row = $statement->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : $row;
    }
}
