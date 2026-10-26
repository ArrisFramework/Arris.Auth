<?php

declare(strict_types=1);

namespace Arris\Auth;

enum Status: int
{
    case NORMAL = 0;
    case ARCHIVED = 1;
    case BANNED = 2;
    case LOCKED = 3;
    case PENDING_REVIEW = 4;
    case SUSPENDED = 5;
}
