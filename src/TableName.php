<?php

declare(strict_types=1);

namespace Arris\Auth;

final class TableName
{
    private function __construct()
    {
    }

    public static function make(string $name, ?string $schema = null, string $prefix = ''): string
    {
        $table = $prefix . $name;

        if ($schema !== null && $schema !== '') {
            return $schema . '.' . $table;
        }

        return $table;
    }
}
