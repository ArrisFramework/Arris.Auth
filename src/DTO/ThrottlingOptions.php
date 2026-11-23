<?php

declare(strict_types=1);

namespace Arris\Auth\DTO;

final readonly class ThrottlingOptions
{
    public ThrottleRule $login;
    public ThrottleRule $registration;
    public ThrottleRule $reset;
    public ThrottleRule $confirmation;

    public function __construct(
        public bool $enabled = true,
        ?ThrottleRule $login = null,
        ?ThrottleRule $registration = null,
        ?ThrottleRule $reset = null,
        ?ThrottleRule $confirmation = null,
    ) {
        $this->login = $login ?? new ThrottleRule(5, 900);
        $this->registration = $registration ?? new ThrottleRule(3, 3600);
        $this->reset = $reset ?? new ThrottleRule(3, 3600);
        $this->confirmation = $confirmation ?? new ThrottleRule(3, 3600);
    }

    public function withEnabled(bool $enabled): self
    {
        return new self(
            $enabled,
            $this->login,
            $this->registration,
            $this->reset,
            $this->confirmation
        );
    }

    public function withLogin(ThrottleRule $login): self
    {
        return new self($this->enabled, $login, $this->registration, $this->reset, $this->confirmation);
    }

    public function withRegistration(ThrottleRule $registration): self
    {
        return new self($this->enabled, $this->login, $registration, $this->reset, $this->confirmation);
    }

    public function withReset(ThrottleRule $reset): self
    {
        return new self($this->enabled, $this->login, $this->registration, $reset, $this->confirmation);
    }

    public function withConfirmation(ThrottleRule $confirmation): self
    {
        return new self($this->enabled, $this->login, $this->registration, $this->reset, $confirmation);
    }
}
