<?php

declare(strict_types=1);

namespace Arris\Auth;

use Arris\Auth\Exception\ConfigurationException;
use SessionHandlerInterface;

final class AuthConfig
{
    private string $mode = Auth::MODE_AUTO;
    private string $tablePrefix = '';
    private ?string $dbSchema = null;
    private string $sessionName = 'arris_auth';

    /** @var array<string, mixed> */
    private array $sessionCookie = [];

    private ?SessionHandlerInterface $sessionHandler = null;
    private string $rememberCookieName = 'arris_remember';
    private int $rememberTtl = 60 * 60 * 24 * 30;
    private int $tokenTtl = 60 * 60 * 24 * 30;
    private bool $requireVerified = true;
    private bool $rejectNonNormalStatus = true;
    private int $minPasswordLength = 8;
    private bool $updateLastLogin = true;
    private int $touchTokenInterval = 60;
    private bool $autoInitialize = true;

    /**
     * Returns the authentication mode.
     */
    public function getMode(): string
    {
        return $this->mode;
    }

    /**
     * Sets the authentication mode: auto, session or token.
     *
     * @throws ConfigurationException
     */
    public function setMode(string $mode): self
    {
        if (!\in_array($mode, [Auth::MODE_AUTO, Auth::MODE_SESSION, Auth::MODE_TOKEN], true)) {
            throw new ConfigurationException('Auth mode must be auto, session or token');
        }

        $this->mode = $mode;

        return $this;
    }

    /**
     * Returns the table prefix.
     */
    public function getTablePrefix(): string
    {
        return $this->tablePrefix;
    }

    /**
     * Sets the table prefix.
     */
    public function setTablePrefix(string $prefix): self
    {
        $this->tablePrefix = $prefix;

        return $this;
    }

    /**
     * Returns the database schema/database qualifier.
     */
    public function getDbSchema(): ?string
    {
        return $this->dbSchema;
    }

    /**
     * Sets the database schema/database qualifier.
     */
    public function setDbSchema(?string $schema): self
    {
        $this->dbSchema = $schema;

        return $this;
    }

    /**
     * Returns the PHP session name.
     */
    public function getSessionName(): string
    {
        return $this->sessionName;
    }

    /**
     * Sets the PHP session name.
     *
     * @throws ConfigurationException
     */
    public function setSessionName(string $name): self
    {
        if ($name === '') {
            throw new ConfigurationException('Session name cannot be empty');
        }

        $this->sessionName = $name;

        return $this;
    }

    /**
     * Returns the session cookie options.
     *
     * @return array<string, mixed>
     */
    public function getSessionCookie(): array
    {
        return $this->sessionCookie;
    }

    /**
     * Sets the session cookie options.
     *
     * @param array<string, mixed> $options
     */
    public function setSessionCookie(array $options): self
    {
        $this->sessionCookie = $options;

        return $this;
    }

    /**
     * Returns the custom session handler.
     */
    public function getSessionHandler(): ?SessionHandlerInterface
    {
        return $this->sessionHandler;
    }

    /**
     * Sets the custom session handler.
     */
    public function setSessionHandler(?SessionHandlerInterface $handler): self
    {
        $this->sessionHandler = $handler;

        return $this;
    }

    /**
     * Returns the remember-me cookie name.
     */
    public function getRememberCookieName(): string
    {
        return $this->rememberCookieName;
    }

    /**
     * Sets the remember-me cookie name.
     *
     * @throws ConfigurationException
     */
    public function setRememberCookieName(string $name): self
    {
        if ($name === '') {
            throw new ConfigurationException('Remember cookie name cannot be empty');
        }

        $this->rememberCookieName = $name;

        return $this;
    }

    /**
     * Returns the remember-me token lifetime in seconds.
     */
    public function getRememberTtl(): int
    {
        return $this->rememberTtl;
    }

    /**
     * Sets the remember-me token lifetime in seconds.
     *
     * @throws ConfigurationException
     */
    public function setRememberTtl(int $seconds): self
    {
        if ($seconds < 0) {
            throw new ConfigurationException('Remember TTL cannot be negative');
        }

        $this->rememberTtl = $seconds;

        return $this;
    }

    /**
     * Returns the bearer token lifetime in seconds.
     */
    public function getTokenTtl(): int
    {
        return $this->tokenTtl;
    }

    /**
     * Sets the bearer token lifetime in seconds. Zero means no expiry.
     *
     * @throws ConfigurationException
     */
    public function setTokenTtl(int $seconds): self
    {
        if ($seconds < 0) {
            throw new ConfigurationException('Token TTL cannot be negative');
        }

        $this->tokenTtl = $seconds;

        return $this;
    }

    /**
     * Returns whether email verification is required for login.
     */
    public function getRequireVerified(): bool
    {
        return $this->requireVerified;
    }

    /**
     * Sets whether email verification is required for login.
     */
    public function setRequireVerified(bool $required): self
    {
        $this->requireVerified = $required;

        return $this;
    }

    /**
     * Returns whether users with a non-normal status are rejected.
     */
    public function getRejectNonNormalStatus(): bool
    {
        return $this->rejectNonNormalStatus;
    }

    /**
     * Sets whether users with a non-normal status are rejected.
     */
    public function setRejectNonNormalStatus(bool $reject): self
    {
        $this->rejectNonNormalStatus = $reject;

        return $this;
    }

    /**
     * Returns the minimum password length.
     */
    public function getMinPasswordLength(): int
    {
        return $this->minPasswordLength;
    }

    /**
     * Sets the minimum password length.
     *
     * @throws ConfigurationException
     */
    public function setMinPasswordLength(int $length): self
    {
        if ($length < 1) {
            throw new ConfigurationException('Minimum password length must be positive');
        }

        $this->minPasswordLength = $length;

        return $this;
    }

    /**
     * Returns whether successful logins update users.last_login.
     */
    public function getUpdateLastLogin(): bool
    {
        return $this->updateLastLogin;
    }

    /**
     * Sets whether successful logins update users.last_login.
     */
    public function setUpdateLastLogin(bool $update): self
    {
        $this->updateLastLogin = $update;

        return $this;
    }

    /**
     * Returns the token last_used update interval in seconds.
     */
    public function getTouchTokenInterval(): int
    {
        return $this->touchTokenInterval;
    }

    /**
     * Sets the token last_used update interval in seconds.
     *
     * @throws ConfigurationException
     */
    public function setTouchTokenInterval(int $seconds): self
    {
        if ($seconds < 0) {
            throw new ConfigurationException('Token touch interval cannot be negative');
        }

        $this->touchTokenInterval = $seconds;

        return $this;
    }

    /**
     * Returns whether Auth resolves the current authentication state in its constructor.
     */
    public function getAutoInitialize(): bool
    {
        return $this->autoInitialize;
    }

    /**
     * Enables or disables eager resolution of the current authentication state.
     *
     * When enabled, the Auth constructor starts the session if a session or
     * remember-me cookie is present and resolves the current user immediately.
     * Anonymous visitors do not get a new session unless they log in.
     */
    public function setAutoInitialize(bool $enabled): self
    {
        $this->autoInitialize = $enabled;

        return $this;
    }

    /**
     * Sets an option by its snake_case name.
     *
     * This is a fallback for configuration hydration; typed setters are preferred.
     *
     * @throws ConfigurationException for unknown options or invalid values
     * @throws \TypeError when the value has the wrong PHP type
     */
    public function setOption(string $name, mixed $value): self
    {
        return match ($name) {
            'mode' => $this->setMode($value),
            'table_prefix' => $this->setTablePrefix($value),
            'db_schema' => $this->setDbSchema($value),
            'session_name' => $this->setSessionName($value),
            'session_cookie' => $this->setSessionCookie($value),
            'session_handler' => $this->setSessionHandler($value),
            'remember_cookie_name' => $this->setRememberCookieName($value),
            'remember_ttl' => $this->setRememberTtl($value),
            'token_ttl' => $this->setTokenTtl($value),
            'require_verified' => $this->setRequireVerified($value),
            'reject_non_normal_status' => $this->setRejectNonNormalStatus($value),
            'min_password_length' => $this->setMinPasswordLength($value),
            'update_last_login' => $this->setUpdateLastLogin($value),
            'touch_token_interval' => $this->setTouchTokenInterval($value),
            'auto_initialize' => $this->setAutoInitialize($value),
            default => throw new ConfigurationException("Unknown auth option: {$name}"),
        };
    }
}
