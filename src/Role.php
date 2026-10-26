<?php

declare(strict_types=1);

namespace Arris\Auth;

final class Role
{
    public const ADMIN = 1;
    public const AUTHOR = 2;
    public const COLLABORATOR = 4;
    public const CONSULTANT = 8;
    public const CONSUMER = 16;
    public const CONTRIBUTOR = 32;
    public const COORDINATOR = 64;
    public const CREATOR = 128;
    public const DEVELOPER = 256;
    public const DIRECTOR = 512;
    public const EDITOR = 1024;
    public const EMPLOYEE = 2048;
    public const MAINTAINER = 4096;
    public const MANAGER = 8192;
    public const MODERATOR = 16384;
    public const PUBLISHER = 32768;
    public const REVIEWER = 65536;
    public const SUBSCRIBER = 131072;
    public const SUPER_ADMIN = 262144;
    public const SUPER_EDITOR = 524288;
    public const SUPER_MODERATOR = 1048576;
    public const TRANSLATOR = 2097152;

    /**
     * The class is a constant holder; instantiation is not allowed.
     */
    private function __construct()
    {
    }

    /**
     * Returns a map of role values to role names.
     *
     * @return array<int, string> role value => role name
     */
    public static function getMap(): array
    {
        return \array_flip((new \ReflectionClass(self::class))->getConstants());
    }

    /**
     * Returns all role names in declaration order.
     *
     * @return list<string>
     */
    public static function getNames(): array
    {
        return \array_keys((new \ReflectionClass(self::class))->getConstants());
    }

    /**
     * Returns all role bit values in declaration order.
     *
     * @return list<int>
     */
    public static function getValues(): array
    {
        return \array_values((new \ReflectionClass(self::class))->getConstants());
    }
}
