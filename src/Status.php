<?php

declare(strict_types=1);

namespace Arris\Auth;

final class Status
{
    public const NORMAL = 0;
    public const ARCHIVED = 1;
    public const BANNED = 2;
    public const LOCKED = 3;
    public const PENDING_REVIEW = 4;
    public const SUSPENDED = 5;

    private function __construct()
    {
    }
}
