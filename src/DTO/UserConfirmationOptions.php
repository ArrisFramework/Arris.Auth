<?php

declare(strict_types=1);

namespace Arris\Auth\DTO;

use Arris\Auth\Exception\ConfigurationException;

final readonly class UserConfirmationOptions
{
    public function __construct(
        public bool $required = false,
        public int $ttl = 3600,
    ) {
        if ($ttl <= 0) {
            throw new ConfigurationException('Confirmation TTL must be positive');
        }
    }

    public function withRequired(bool $required): self
    {
        return new self($required, $this->ttl);
    }

    public function withTtl(int $ttl): self
    {
        return new self($this->required, $ttl);
    }
}
