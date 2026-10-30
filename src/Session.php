<?php

declare(strict_types=1);

namespace Arris\Auth;

use Arris\Auth\Exception\ConfigurationException;
use Arris\Auth\Exception\HeadersAlreadySentException;
use SessionHandlerInterface;

final class Session
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
     * Returns whether a PHP session is currently active.
     *
     * Возвращает, активна ли сейчас PHP-сессия.
     */
    public static function isStarted(): bool
    {
        return \session_status() === \PHP_SESSION_ACTIVE;
    }

    /**
     * Starts a PHP session if it is not active yet.
     *
     * Запускает PHP-сессию, если она ещё не активна.
     *
     * @param array{path?: string, domain?: string, secure?: bool, httponly?: bool, samesite?: string|null} $cookieOptions
     * @param SessionHandlerInterface|null $handler custom session storage handler
     */
    public static function start(string $name, array $cookieOptions = [], ?SessionHandlerInterface $handler = null): void
    {
        if (self::isStarted()) {
            return;
        }

        if (\session_status() === \PHP_SESSION_DISABLED) {
            throw new ConfigurationException('PHP sessions are disabled');
        }

        if (\headers_sent($file, $line)) {
            throw new HeadersAlreadySentException("Cannot start session: headers already sent in {$file}:{$line}");
        }

        \session_name($name);
        \session_set_cookie_params([
            'lifetime' => $cookieOptions['lifetime'] ?? 0,
            'path' => $cookieOptions['path'] ?? '/',
            'domain' => $cookieOptions['domain'] ?? '',
            'secure' => $cookieOptions['secure'] ?? false,
            'httponly' => $cookieOptions['httponly'] ?? true,
            'samesite' => $cookieOptions['samesite'] ?? 'Lax',
        ]);

        if ($handler !== null) {
            \session_set_save_handler($handler, true);
        }

        \session_start();
    }

    /**
     * Reads a value from the active session.
     *
     * Читает значение из активной сессии.
     */
    public static function get(string $key, mixed $default = null): mixed
    {
        return $_SESSION[$key] ?? $default;
    }

    /**
     * Writes a value to the active session.
     *
     * Записывает значение в активную сессию.
     */
    public static function set(string $key, mixed $value): void
    {
        $_SESSION[$key] = $value;
    }

    /**
     * Removes a value from the active session.
     *
     * Удаляет значение из активной сессии.
     */
    public static function remove(string $key): void
    {
        unset($_SESSION[$key]);
    }

    /**
     * Returns the current session ID.
     *
     * Возвращает ID текущей сессии.
     */
    public static function id(): string
    {
        return \session_id();
    }

    /**
     * Regenerates the session ID to prevent session fixation.
     * Returns false when no session is active.
     *
     * Регенерирует ID сессии для предотвращения фиксации сессии.
     * Возвращает false, если активной сессии нет.
     */
    public static function regenerate(bool $deleteOldSession = true): bool
    {
        if (!self::isStarted()) {
            return false;
        }

        return \session_regenerate_id($deleteOldSession);
    }

    /**
     * Destroys the active session and deletes the session cookie.
     *
     * Уничтожает активную сессию и удаляет cookie сессии.
     *
     * @param array{path?: string, domain?: string, secure?: bool, httponly?: bool, samesite?: string|null} $cookieOptions
     */
    public static function destroy(array $cookieOptions = []): void
    {
        if (!self::isStarted()) {
            $_SESSION = [];
            return;
        }

        $_SESSION = [];

        if (\ini_get('session.use_cookies')) {
            $params = \session_get_cookie_params();
            Cookie::delete(\session_name(), [
                'path' => $params['path'] ?: '/',
                'domain' => $params['domain'] ?: '',
                'secure' => (bool) $params['secure'],
                'httponly' => (bool) $params['httponly'],
                'samesite' => $params['samesite'] ?? 'Lax',
            ]);
        }

        \session_destroy();

        if (\session_status() === \PHP_SESSION_ACTIVE) {
            \session_write_close();
        }
    }
}
