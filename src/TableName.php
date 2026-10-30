<?php

declare(strict_types=1);

namespace Arris\Auth;

final class TableName
{
    /**
     * The class is static; instantiation is not allowed.
     *
     * Класс статический; создание экземпляра запрещено.
     */
    private function __construct()
    {
    }

    /**
     * Builds a qualified table name from an optional schema and table prefix.
     *
     * Строит полное имя таблицы из необязательной схемы и префикса таблиц.
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
