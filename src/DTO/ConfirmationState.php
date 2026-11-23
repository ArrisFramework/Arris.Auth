<?php

declare(strict_types=1);

namespace Arris\Auth\DTO;

final readonly class ConfirmationState
{
    public const SENT = 'sent';
    public const UNKNOWN_USER = 'unknown_user';
    public const ALREADY_VERIFIED = 'already_verified';
    public const NOT_REQUIRED = 'not_required';
    public const MAIL_FAILED = 'mail_failed';
    public const THROTTLED = 'throttled';

    private function __construct(
        public bool $sent,
        public string $reason,
        public int $retryAfter = 0,
    ) {
    }

    public static function sent(): self
    {
        return new self(true, self::SENT);
    }

    public static function unknownUser(): self
    {
        return new self(false, self::UNKNOWN_USER);
    }

    public static function alreadyVerified(): self
    {
        return new self(false, self::ALREADY_VERIFIED);
    }

    public static function notRequired(): self
    {
        return new self(false, self::NOT_REQUIRED);
    }

    public static function mailFailed(): self
    {
        return new self(false, self::MAIL_FAILED);
    }

    public static function throttled(int $retryAfter): self
    {
        return new self(false, self::THROTTLED, $retryAfter);
    }

    public function isSent(): bool
    {
        return $this->sent;
    }
}
