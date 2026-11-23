<?php

declare(strict_types=1);

namespace Arris\Auth\DTO;

use Arris\Auth\Exception\ConfigurationException;

final readonly class ThrottleRule
{
    public function __construct(
        public int $limit,
        public int $window,
    ) {
        if ($limit <= 0) {
            throw new ConfigurationException('Throttle limit must be positive');
        }

        if ($window <= 0) {
            throw new ConfigurationException('Throttle window must be positive');
        }
    }
}
