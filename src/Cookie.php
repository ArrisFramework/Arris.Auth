<?php

declare(strict_types=1);

namespace Arris\Auth;

use Arris\Auth\Exception\ConfigurationException;
use Arris\Auth\Exception\HeadersAlreadySentException;

final class Cookie
{
    /**
     * The class is static; instantiation is not allowed.
     */
    private function __construct()
    {
    }

    /**
     * Sends a cookie with the given value, expiry time and options.
     *
     * @param array{path?: string, domain?: string, secure?: bool, httponly?: bool, samesite?: string|null} $options
     */
    public static function set(string $name, string $value, int $expires, array $options = []): void
    {
        $options = self::normalize($name, $options);

        self::assertHeadersNotSent();

        \setcookie($name, $value, [
            'expires' => $expires,
            'path' => $options['path'],
            'domain' => $options['domain'],
            'secure' => $options['secure'],
            'httponly' => $options['httponly'],
            'samesite' => $options['samesite'],
        ]);
    }

    /**
     * Expires a cookie on the client and removes it from $_COOKIE.
     *
     * @param array{path?: string, domain?: string, secure?: bool, httponly?: bool, samesite?: string|null} $options
     */
    public static function delete(string $name, array $options = []): void
    {
        self::set($name, '', \time() - 3600, $options);

        unset($_COOKIE[$name]);
    }

    /**
     * Validates and normalizes cookie options, including SameSite and __Host- rules.
     *
     * @param array{path?: string, domain?: string, secure?: bool, httponly?: bool, samesite?: string|null} $options
     * @return array{path: string, domain: string, secure: bool, httponly: bool, samesite: string|null}
     */
    private static function normalize(string $name, array $options): array
    {
        $normalized = \array_replace([
            'path' => '/',
            'domain' => '',
            'secure' => false,
            'httponly' => true,
            'samesite' => 'Lax',
        ], $options);

        if ($normalized['samesite'] === '') {
            $normalized['samesite'] = null;
        }

        if (\str_starts_with($name, '__Host-')) {
            if (!$normalized['secure'] || $normalized['path'] !== '/' || $normalized['domain'] !== '') {
                throw new ConfigurationException('The __Host- cookie prefix requires secure=true, path=/ and an empty domain');
            }
        }

        if ($normalized['samesite'] !== null && !\in_array($normalized['samesite'], ['Lax', 'Strict', 'None'], true)) {
            throw new ConfigurationException('Cookie SameSite must be Lax, Strict, None or null');
        }

        if ($normalized['samesite'] === 'None' && !$normalized['secure']) {
            throw new ConfigurationException('SameSite=None requires secure=true');
        }

        return $normalized;
    }

    /**
     * Throws when headers have already been sent and a cookie cannot be written.
     *
     * @throws HeadersAlreadySentException
     */
    private static function assertHeadersNotSent(): void
    {
        if (\headers_sent($file, $line)) {
            throw new HeadersAlreadySentException("Headers already sent in {$file}:{$line}");
        }
    }
}
