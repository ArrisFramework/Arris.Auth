<?php

declare(strict_types=1);

namespace Arris\Auth\Repository;

use Arris\Auth\TableName;
use PDO;

final class UserRepository
{
    private string $table;

    /**
     * Creates a repository for the users table.
     */
    public function __construct(
        private readonly PDO $pdo,
        ?string $schema = null,
        string $prefix = '',
    ) {
        $this->table = TableName::make('users', $schema, $prefix);
    }

    /**
     * Finds a user by primary key. Returns null when not found.
     *
     * @return array<string, mixed>|null
     */
    public function findById(int $id): ?array
    {
        return $this->fetchOne(
            "SELECT * FROM {$this->table} WHERE id = ? LIMIT 1",
            [$id]
        );
    }

    /**
     * Finds a user by email address. Returns null when not found.
     *
     * @return array<string, mixed>|null
     */
    public function findByEmail(string $email): ?array
    {
        return $this->fetchOne(
            "SELECT * FROM {$this->table} WHERE email = ? LIMIT 1",
            [$email]
        );
    }

    /**
     * Finds users by username, returning up to two rows.
     *
     * Two rows let the caller detect an ambiguous username.
     *
     * @return list<array<string, mixed>>
     */
    public function findByUsername(string $username): array
    {
        $statement = $this->pdo->prepare(
            "SELECT * FROM {$this->table} WHERE username = ? LIMIT 2"
        );
        $statement->execute([$username]);

        /** @var list<array<string, mixed>> $rows */
        $rows = $statement->fetchAll(PDO::FETCH_ASSOC);

        return $rows;
    }

    /**
     * Inserts a new user and returns the generated user ID.
     */
    public function create(
        string $email,
        string $passwordHash,
        ?string $username,
        int $status,
        int $verified,
        int $rolesMask,
    ): int {
        $statement = $this->pdo->prepare(
            "INSERT INTO {$this->table}
                (email, password, username, status, verified, resettable, roles_mask, registered, force_logout)
             VALUES (?, ?, ?, ?, ?, 1, ?, ?, 0)"
        );

        $statement->execute([
            $email,
            $passwordHash,
            $username,
            $status,
            $verified,
            $rolesMask,
            \time(),
        ]);

        return (int) $this->pdo->lastInsertId();
    }

    /**
     * Updates the user's last_login timestamp.
     */
    public function updateLastLogin(int $id): void
    {
        $statement = $this->pdo->prepare(
            "UPDATE {$this->table} SET last_login = ? WHERE id = ?"
        );
        $statement->execute([\time(), $id]);
    }

    /**
     * Replaces the user's password hash.
     */
    public function updatePassword(int $id, string $passwordHash): void
    {
        $statement = $this->pdo->prepare(
            "UPDATE {$this->table} SET password = ? WHERE id = ?"
        );
        $statement->execute([$passwordHash, $id]);
    }

    /**
     * Sets the verified flag for a user.
     */
    public function setVerified(int $id, bool $verified): void
    {
        $statement = $this->pdo->prepare(
            "UPDATE {$this->table} SET verified = ? WHERE id = ?"
        );
        $statement->execute([$verified ? 1 : 0, $id]);
    }

    /**
     * Increments force_logout and returns the new value.
     *
     * Existing sessions compare their stored counter with this value.
     */
    public function incrementForceLogout(int $id): int
    {
        $statement = $this->pdo->prepare(
            "UPDATE {$this->table} SET force_logout = force_logout + 1 WHERE id = ?"
        );
        $statement->execute([$id]);

        $row = $this->findById($id);

        return (int) ($row['force_logout'] ?? 0);
    }

    /**
     * Deletes a user by ID.
     */
    public function delete(int $id): void
    {
        $statement = $this->pdo->prepare("DELETE FROM {$this->table} WHERE id = ?");
        $statement->execute([$id]);
    }

    /**
     * Executes a query and returns the first row as an associative array.
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
