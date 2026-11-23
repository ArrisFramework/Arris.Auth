<?php

declare(strict_types=1);

namespace Arris\Auth\Exception;

final class TooManyRequestsException extends AuthException
{
    public function __construct(
        public readonly int $retryAfter = 0,
        string $message = 'Too many requests',
        int $code = 0,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, $code, $previous);
    }
}
