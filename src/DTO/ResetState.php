<?php

declare(strict_types=1);

namespace Arris\Auth\DTO;

final readonly class ResetState
{
    public const SENT = 'sent';
    public const UNKNOWN_USER = 'unknown_user';
    public const NOT_ENABLED = 'not_enabled';
    public const NOT_ALLOWED = 'not_allowed';
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

    public static function notEnabled(): self
    {
        return new self(false, self::NOT_ENABLED);
    }

    public static function notAllowed(): self
    {
        return new self(false, self::NOT_ALLOWED);
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
