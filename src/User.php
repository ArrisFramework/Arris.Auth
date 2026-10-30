<?php

declare(strict_types=1);

namespace Arris\Auth;

final readonly class User
{
    /**
     * Creates a read-only user value object from explicit field values.
     *
     * Создаёт неизменяемый объект пользователя из явно заданных значений полей.
     */
    public function __construct(
        public int $id,
        public string $email,
        public ?string $username,
        public Status $status,
        public int $verified,
        public int $resettable,
        public int $rolesMask,
        public int $registered,
        public ?int $lastLogin,
        public int $forceLogout,
        public ?string $properties,
    ) {
    }

    /**
     * Creates a user object from a database row.
     *
     * Создаёт объект пользователя из строки базы данных.
     *
     * @param array<string, mixed> $row
     */
    public static function fromRow(array $row): self
    {
        return new self(
            id: (int) $row['id'],
            email: (string) $row['email'],
            username: isset($row['username']) ? (string) $row['username'] : null,
            status: Status::from((int) ($row['status'] ?? Status::NORMAL->value)),
            verified: (int) ($row['verified'] ?? 0),
            resettable: (int) ($row['resettable'] ?? 1),
            rolesMask: (int) ($row['roles_mask'] ?? 0),
            registered: (int) ($row['registered'] ?? 0),
            lastLogin: isset($row['last_login']) ? (int) $row['last_login'] : null,
            forceLogout: (int) ($row['force_logout'] ?? 0),
            properties: isset($row['properties']) ? (string) $row['properties'] : null,
        );
    }

    /**
     * Returns whether the user's email address has been verified.
     *
     * Возвращает, подтверждён ли email-адрес пользователя.
     */
    public function isVerified(): bool
    {
        return $this->verified === 1;
    }

    /**
     * Returns whether the account status is normal.
     *
     * Возвращает, является ли статус учётной записи нормальным.
     */
    public function isNormal(): bool
    {
        return $this->status === Status::NORMAL;
    }

    /**
     * Returns whether the account is archived.
     *
     * Возвращает, архивирована ли учётная запись.
     */
    public function isArchived(): bool
    {
        return $this->status === Status::ARCHIVED;
    }

    /**
     * Returns whether the account is banned.
     *
     * Возвращает, забанена ли учётная запись.
     */
    public function isBanned(): bool
    {
        return $this->status === Status::BANNED;
    }

    /**
     * Returns whether the account is locked.
     *
     * Возвращает, заблокирована ли учётная запись.
     */
    public function isLocked(): bool
    {
        return $this->status === Status::LOCKED;
    }

    /**
     * Returns whether the account is pending review.
     *
     * Возвращает, ожидает ли учётная запись проверки.
     */
    public function isPendingReview(): bool
    {
        return $this->status === Status::PENDING_REVIEW;
    }

    /**
     * Returns whether the account is suspended.
     *
     * Возвращает, приостановлена ли учётная запись.
     */
    public function isSuspended(): bool
    {
        return $this->status === Status::SUSPENDED;
    }

    /**
     * Checks whether the role bit is present in the user's role mask.
     *
     * Проверяет, присутствует ли бит роли в маске ролей пользователя.
     */
    public function hasRole(int $role): bool
    {
        return ($this->rolesMask & $role) === $role;
    }

    /**
     * Checks whether at least one of the given role bits is present.
     *
     * Проверяет, присутствует ли хотя бы один из указанных битов ролей.
     */
    public function hasAnyRole(int ...$roles): bool
    {
        foreach ($roles as $role) {
            if ($this->hasRole($role)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks whether all of the given role bits are present.
     *
     * Проверяет, присутствуют ли все указанные биты ролей.
     */
    public function hasAllRoles(int ...$roles): bool
    {
        foreach ($roles as $role) {
            if (!$this->hasRole($role)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Returns the names of all roles present in the role mask.
     * Pass a custom name => bit map to use application-specific role names.
     *
     * Возвращает имена всех ролей, присутствующих в маске ролей.
     * Передайте собственную карту name => bit, чтобы использовать имена ролей приложения.
     *
     * @param array<string, int>|null $map
     * @return list<string>
     */
    public function roleNames(?array $map = null): array
    {
        $map ??= Role::map();
        $names = [];

        foreach ($map as $name => $bit) {
            if ($this->hasRole($bit)) {
                $names[] = $name;
            }
        }

        return $names;
    }

    /**
     * Exports the user fields as an associative array.
     *
     * Экспортирует поля пользователя в виде ассоциативного массива.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'email' => $this->email,
            'username' => $this->username,
            'status' => $this->status->value,
            'verified' => $this->verified,
            'resettable' => $this->resettable,
            'roles_mask' => $this->rolesMask,
            'registered' => $this->registered,
            'last_login' => $this->lastLogin,
            'force_logout' => $this->forceLogout,
            'properties' => $this->properties,
        ];
    }
}
