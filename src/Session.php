<?php

declare(strict_types=1);

namespace Arris\Auth;

use Arris\Auth\Exception\ConfigurationException;
use Arris\Auth\Exception\HeadersAlreadySentException;

final class Session
{
    private function __construct()
    {
    }

    public static function isStarted(): bool
    {
        return \session_status() === \PHP_SESSION_ACTIVE;
    }

    /**
     * @param array{path?: string, domain?: string, secure?: bool, httponly?: bool, samesite?: string|null} $cookieOptions
     */
    public static function start(string $name, array $cookieOptions = []): void
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

        \session_start();
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        return $_SESSION[$key] ?? $default;
    }

    public static function set(string $key, mixed $value): void
    {
        $_SESSION[$key] = $value;
    }

    public static function remove(string $key): void
    {
        unset($_SESSION[$key]);
    }

    public static function id(): string
    {
        return \session_id();
    }

    public static function regenerate(bool $deleteOldSession = true): bool
    {
        if (!self::isStarted()) {
            return false;
        }

        return \session_regenerate_id($deleteOldSession);
    }

    /**
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
