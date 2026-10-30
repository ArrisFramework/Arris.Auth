<?php

declare(strict_types=1);

namespace Arris\Auth;

/**
 * Base role bitmask constants.
 *
 * Applications may extend this class and override map() to define their own
 * role names or aliases while reusing the base bit values.
 *
 *
 * Базовые константы битовой маски ролей.
 *
 * Приложения могут расширять этот класс и переопределять map(), чтобы задавать свои имена ролей или алиасы,
 * переиспользуя базовые значения битов.
 */
class Role
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
     *
     * Класс является хранилищем констант; создание экземпляра запрещено.
     */
    private function __construct()
    {
    }

    /**
     * Returns role names mapped to their bit values.
     * Override this method in an application-specific subclass to define
     * custom names or aliases for the base bits.
     *
     * Возвращает имена ролей, сопоставленные с их значениями битов.
     * Переопределите этот метод в подклассе приложения, чтобы задать свои имена или алиасы для базовых битов.
     *
     * @return array<string, int>
     */
    public static function map(): array
    {
        return [
            'ADMIN' => self::ADMIN,
            'AUTHOR' => self::AUTHOR,
            'COLLABORATOR' => self::COLLABORATOR,
            'CONSULTANT' => self::CONSULTANT,
            'CONSUMER' => self::CONSUMER,
            'CONTRIBUTOR' => self::CONTRIBUTOR,
            'COORDINATOR' => self::COORDINATOR,
            'CREATOR' => self::CREATOR,
            'DEVELOPER' => self::DEVELOPER,
            'DIRECTOR' => self::DIRECTOR,
            'EDITOR' => self::EDITOR,
            'EMPLOYEE' => self::EMPLOYEE,
            'MAINTAINER' => self::MAINTAINER,
            'MANAGER' => self::MANAGER,
            'MODERATOR' => self::MODERATOR,
            'PUBLISHER' => self::PUBLISHER,
            'REVIEWER' => self::REVIEWER,
            'SUBSCRIBER' => self::SUBSCRIBER,
            'SUPER_ADMIN' => self::SUPER_ADMIN,
            'SUPER_EDITOR' => self::SUPER_EDITOR,
            'SUPER_MODERATOR' => self::SUPER_MODERATOR,
            'TRANSLATOR' => self::TRANSLATOR,
        ];
    }

    /**
     * Returns the bit value for a role name, or null when the name is unknown.
     *
     * Возвращает значение бита для имени роли или null, если имя неизвестно.
     */
    public static function id(string $name): ?int
    {
        return static::map()[$name] ?? null;
    }

    /**
     * Returns the names of all roles present in the given bitmask.
     *
     * Возвращает имена всех ролей, присутствующих в указанной битовой маске.
     *
     * @return list<string>
     */
    public static function names(int $mask): array
    {
        $names = [];

        foreach (static::map() as $name => $bit) {
            if (($mask & $bit) === $bit) {
                $names[] = $name;
            }
        }

        return $names;
    }

    /**
     * Returns role bit values mapped to role names.
     * Aliases with the same bit value collapse to a single name.
     *
     * Возвращает значения битов ролей, сопоставленные с именами ролей.
     * Алиасы с одинаковым значением бита схлопываются в одно имя.
     *
     * @return array<int, string>
     */
    public static function getMap(): array
    {
        return \array_flip(static::map());
    }

    /**
     * Returns all role names.
     *
     * Возвращает все имена ролей.
     *
     * @return list<string>
     */
    public static function getNames(): array
    {
        return \array_keys(static::map());
    }

    /**
     * Returns all role bit values.
     *
     * Возвращает все значения битов ролей.
     *
     * @return list<int>
     */
    public static function getValues(): array
    {
        return \array_values(static::map());
    }
}
