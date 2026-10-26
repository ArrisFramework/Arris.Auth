<?php

declare(strict_types=1);

namespace Arris\Auth;

final class TableName
{
    /**
     * The class is static; instantiation is not allowed.
     */
    private function __construct()
    {
    }

    /**
     * Builds a qualified table name from an optional schema and table prefix.
     */
    public static function make(string $name, ?string $schema = null, string $prefix = ''): string
    {
        $table = $prefix . $name;

        if ($schema !== null && $schema !== '') {
            return $schema . '.' . $table;
        }

        return $table;
    }
}
