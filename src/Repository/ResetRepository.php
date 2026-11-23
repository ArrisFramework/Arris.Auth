<?php

declare(strict_types=1);

namespace Arris\Auth\Repository;

use Arris\Auth\TableName;
use PDO;

final class ResetRepository
{
    private string $table;

    /**
     * Creates a repository for the users_resets table.
     *
     * Создаёт репозиторий для таблицы users_resets.
     */
    public function __construct(
        private readonly PDO $pdo,
        ?string $schema = null,
        string $prefix = '',
    ) {
        $this->table = TableName::make('users_resets', $schema, $prefix);
    }

    /**
     * Stores a password reset token hash and returns the row ID.
     *
     * Сохраняет хэш reset-токена и возвращает ID строки.
     */
    public function create(
        int $userId,
        string $selector,
        string $tokenHash,
        int $expires,
    ): int {
        $statement = $this->pdo->prepare(
            "INSERT INTO {$this->table}
                (user_id, selector, token, expires)
             VALUES (?, ?, ?, ?)"
        );

        $statement->execute([$userId, $selector, $tokenHash, $expires]);

        return (int) $this->pdo->lastInsertId();
    }

    /**
     * Finds a non-expired reset row by token hash.
     *
     * Находит неистёкшую reset-строку по хэшу токена.
     *
     * @return array<string, mixed>|null
     */
    public function findActiveByTokenHash(string $tokenHash): ?array
    {
        return $this->fetchOne(
            "SELECT * FROM {$this->table}
             WHERE token = ? AND expires > ?
             ORDER BY id DESC
             LIMIT 1",
            [$tokenHash, \time()]
        );
    }

    /**
     * Deletes all reset rows of a user.
     *
     * Удаляет все reset-строки пользователя.
     */
    public function deleteByUser(int $userId): int
    {
        $statement = $this->pdo->prepare(
            "DELETE FROM {$this->table} WHERE user_id = ?"
        );
        $statement->execute([$userId]);

        return $statement->rowCount();
    }

    /**
     * Deletes expired reset rows of a user.
     *
     * Удаляет истёкшие reset-строки пользователя.
     */
    public function deleteExpiredByUser(int $userId): int
    {
        $statement = $this->pdo->prepare(
            "DELETE FROM {$this->table} WHERE user_id = ? AND expires < ?"
        );
        $statement->execute([$userId, \time()]);

        return $statement->rowCount();
    }

    /**
     * Deletes expired reset rows.
     *
     * Удаляет истёкшие reset-строки.
     */
    public function deleteExpired(): int
    {
        $statement = $this->pdo->prepare(
            "DELETE FROM {$this->table} WHERE expires < ?"
        );
        $statement->execute([\time()]);

        return $statement->rowCount();
    }

    /**
     * Executes a query and returns the first row.
     *
     * Выполняет запрос и возвращает первую строку.
     *
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
