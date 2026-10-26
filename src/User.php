<?php

declare(strict_types=1);

namespace Arris\Auth;

final readonly class User
{
    public function __construct(
        public int $id,
        public string $email,
        public ?string $username,
        public int $status,
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
     * @param array<string, mixed> $row
     */
    public static function fromRow(array $row): self
    {
        return new self(
            id: (int) $row['id'],
            email: (string) $row['email'],
            username: isset($row['username']) ? (string) $row['username'] : null,
            status: (int) ($row['status'] ?? Status::NORMAL),
            verified: (int) ($row['verified'] ?? 0),
            resettable: (int) ($row['resettable'] ?? 1),
            rolesMask: (int) ($row['roles_mask'] ?? 0),
            registered: (int) ($row['registered'] ?? 0),
            lastLogin: isset($row['last_login']) ? (int) $row['last_login'] : null,
            forceLogout: (int) ($row['force_logout'] ?? 0),
            properties: isset($row['properties']) ? (string) $row['properties'] : null,
        );
    }

    public function isVerified(): bool
    {
        return $this->verified === 1;
    }

    public function isNormal(): bool
    {
        return $this->status === Status::NORMAL;
    }

    public function isArchived(): bool
    {
        return $this->status === Status::ARCHIVED;
    }

    public function isBanned(): bool
    {
        return $this->status === Status::BANNED;
    }

    public function isLocked(): bool
    {
        return $this->status === Status::LOCKED;
    }

    public function isPendingReview(): bool
    {
        return $this->status === Status::PENDING_REVIEW;
    }

    public function isSuspended(): bool
    {
        return $this->status === Status::SUSPENDED;
    }

    public function hasRole(int $role): bool
    {
        return ($this->rolesMask & $role) === $role;
    }

    public function hasAnyRole(int ...$roles): bool
    {
        foreach ($roles as $role) {
            if ($this->hasRole($role)) {
                return true;
            }
        }

        return false;
    }

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
     * @return list<string>
     */
    public function roleNames(): array
    {
        $map = Role::getMap();
        $names = [];

        foreach ($map as $value => $name) {
            if ($this->hasRole((int) $value)) {
                $names[] = $name;
            }
        }

        return $names;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'email' => $this->email,
            'username' => $this->username,
            'status' => $this->status,
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
