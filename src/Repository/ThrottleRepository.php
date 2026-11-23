<?php

declare(strict_types=1);

namespace Arris\Auth\Repository;

use Arris\Auth\TableName;
use PDO;
use PDOException;

final class ThrottleRepository
{
    private string $table;

    /**
     * Creates a repository for the users_throttling table.
     *
     * Создаёт репозиторий для таблицы users_throttling.
     */
    public function __construct(
        private readonly PDO $pdo,
        ?string $schema = null,
        string $prefix = '',
    ) {
        $this->table = TableName::make('users_throttling', $schema, $prefix);
    }

    /**
     * Consumes one token from a token bucket.
     *
     * Потребляет один токен из token bucket.
     *
     * @return array{allowed: bool, retry_after: int}
     */
    public function consume(string $bucket, int $limit, int $window): array
    {
        try {
            return $this->consumeOnce($bucket, $limit, $window);
        } catch (PDOException $e) {
            if (!\in_array((string) $e->getCode(), ['23000', '23505'], true)) {
                throw $e;
            }

            return $this->consumeOnce($bucket, $limit, $window);
        }
    }

    /**
     * Deletes expired buckets.
     *
     * Удаляет истёкшие bucket-строки.
     */
    public function deleteExpired(): int
    {
        $statement = $this->pdo->prepare(
            "DELETE FROM {$this->table} WHERE expires_at < ?"
        );
        $statement->execute([\time()]);

        return $statement->rowCount();
    }

    /**
     * @return array{allowed: bool, retry_after: int}
     */
    private function consumeOnce(string $bucket, int $limit, int $window): array
    {
        $ownTransaction = !$this->pdo->inTransaction();

        if ($ownTransaction) {
            $this->pdo->beginTransaction();
        }

        try {
            $driver = (string) $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
            $lock = $driver === 'mysql' ? ' FOR UPDATE' : '';

            $statement = $this->pdo->prepare(
                "SELECT tokens, replenished_at FROM {$this->table} WHERE bucket = ?{$lock}"
            );
            $statement->execute([$bucket]);
            $row = $statement->fetch(PDO::FETCH_ASSOC);

            $now = \time();
            $rate = $limit / $window;

            if ($row === false) {
                $tokens = \max(0.0, $limit - 1.0);

                $insert = $this->pdo->prepare(
                    "INSERT INTO {$this->table} (bucket, tokens, replenished_at, expires_at)
                     VALUES (?, ?, ?, ?)"
                );
                $insert->execute([$bucket, $tokens, $now, $now + $window]);

                $result = ['allowed' => true, 'retry_after' => 0];
            } else {
                $elapsed = \max(0, $now - (int) $row['replenished_at']);
                $tokens = \min((float) $limit, (float) $row['tokens'] + $elapsed * $rate);
                $retryAfter = 0;

                if ($tokens >= 1.0) {
                    $tokens -= 1.0;
                    $allowed = true;
                } else {
                    $allowed = false;
                    $retryAfter = (int) \ceil((1.0 - $tokens) / $rate);
                }

                $update = $this->pdo->prepare(
                    "UPDATE {$this->table}
                     SET tokens = ?, replenished_at = ?, expires_at = ?
                     WHERE bucket = ?"
                );
                $update->execute([$tokens, $now, $now + $window, $bucket]);

                $result = ['allowed' => $allowed, 'retry_after' => $retryAfter];
            }

            if ($ownTransaction) {
                $this->pdo->commit();
            }

            return $result;
        } catch (\Throwable $e) {
            if ($ownTransaction && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }

            throw $e;
        }
    }
}
