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

    /**
     * Creates a repository for the users_tokens table.
     *
     * Создаёт репозиторий для таблицы users_tokens.
     *
     * @param PDO $pdo
     * @param string|null $schema
     * @param string $prefix
     */
    public function __construct(
        private readonly PDO $pdo,
        ?string $schema = null,
        string $prefix = '',
    ) {
        $this->table = TableName::make('users_tokens', $schema, $prefix);
    }

    /**
     * Stores a new bearer token hash and returns the generated row ID.
     *
     * Сохраняет хэш нового bearer-токена и возвращает сгенерированный ID строки.
     *
     * @param int $userId
     * @param string $tokenHash
     * @param int $expires
     * @param string|null $name
     *
     * @return int
     */
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

    /**
     * Stores a new remember-me token and returns the generated row ID.
     *
     * Сохраняет новый remember-me токен и возвращает сгенерированный ID строки.
     *
     * @param int $userId
     * @param string $selector
     * @param string $tokenHash
     * @param int $expires
     *
     * @return int
     */
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
     * Finds a non-expired bearer token by its hash.
     *
     * Находит неистёкший bearer-токен по его хэшу.
     *
     * @param string $tokenHash
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
     * Finds a non-expired remember-me token by selector.
     *
     * Находит неистёкший remember-me токен по селектору.
     *
     * @param string $selector
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

    /**
     * Updates the token's last_used timestamp.
     *
     * Обновляет метку last_used токена.
     *
     * @param int $id
     *
     * @return void
     */
    public function touch(int $id): void
    {
        $statement = $this->pdo->prepare(
            "UPDATE {$this->table} SET last_used = ? WHERE id = ?"
        );
        $statement->execute([\time(), $id]);
    }

    /**
     * Deletes a token by ID. Returns true when a row was removed.
     *
     * Удаляет токен по ID. Возвращает true, если строка была удалена.
     *
     * @param int $id
     *
     * @return bool
     */
    public function delete(int $id): bool
    {
        $statement = $this->pdo->prepare("DELETE FROM {$this->table} WHERE id = ?");
        $statement->execute([$id]);

        return $statement->rowCount() > 0;
    }

    /**
     * Deletes tokens by hash, optionally filtered by kind.
     * Returns the number of deleted rows.
     *
     * Удаляет токены по хэшу, при необходимости с фильтром по типу. Возвращает количество удалённых строк.
     *
     * @param string $tokenHash
     * @param string|null $kind
     *
     * @return int
     */
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

    /**
     * Deletes remember-me tokens by selector.
     * Returns the number of deleted rows.
     *
     * Удаляет remember-me токены по селектору. Возвращает количество удалённых строк.
     *
     * @param string $selector
     *
     * @return int
     */
    public function deleteBySelector(string $selector): int
    {
        $statement = $this->pdo->prepare(
            "DELETE FROM {$this->table} WHERE selector = ?"
        );
        $statement->execute([$selector]);

        return $statement->rowCount();
    }

    /**
     * Deletes all tokens of a user, optionally filtered by kind.
     * Returns the number of deleted rows.
     *
     * Удаляет все токены пользователя, при необходимости с фильтром по типу. Возвращает количество удалённых строк.
     *
     * @param int $userId
     * @param string|null $kind
     *
     * @return int
     */
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

    /**
     * Deletes expired tokens and returns the number of deleted rows.
     *
     * Удаляет истёкшие токены и возвращает количество удалённых строк.
     *
     * @return int
     */
    public function deleteExpired(): int
    {
        $statement = $this->pdo->prepare(
            "DELETE FROM {$this->table} WHERE expires > 0 AND expires < ?"
        );
        $statement->execute([\time()]);

        return $statement->rowCount();
    }

    /**
     * Executes a query and returns the first row as an associative array.
     *
     * Выполняет запрос и возвращает первую строку в виде ассоциативного массива.
     *
     * @param string $sql
     * @param array $params
     *
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
