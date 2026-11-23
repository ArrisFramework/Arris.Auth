<?php

declare(strict_types=1);

namespace Arris\Auth\DTO;

use Arris\Auth\Exception\ConfigurationException;

final readonly class UserResetOptions
{
    public function __construct(
        public bool $enabled = false,
        public int $ttl = 3600,
        public bool $allowedAny = false,
    ) {
        if ($ttl <= 0) {
            throw new ConfigurationException('User reset TTL must be positive');
        }
    }

    public function withEnabled(bool $enabled): self
    {
        return new self($enabled, $this->ttl, $this->allowedAny);
    }

    public function withTtl(int $ttl): self
    {
        return new self($this->enabled, $ttl, $this->allowedAny);
    }

    public function withAllowedAny(bool $allowedAny): self
    {
        return new self($this->enabled, $this->ttl, $allowedAny);
    }
}
