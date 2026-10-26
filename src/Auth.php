<?php

declare(strict_types=1);

namespace Arris\Auth;

use Arris\Auth\Exception\AccountDisabledException;
use Arris\Auth\Exception\AmbiguousUsernameException;
use Arris\Auth\Exception\AuthException;
use Arris\Auth\Exception\ConfigurationException;
use Arris\Auth\Exception\EmailNotVerifiedException;
use Arris\Auth\Exception\InvalidCredentialsException;
use Arris\Auth\Exception\InvalidEmailException;
use Arris\Auth\Exception\InvalidPasswordException;
use Arris\Auth\Exception\UnknownUserException;
use Arris\Auth\Exception\UserAlreadyExistsException;
use Arris\Auth\Repository\TokenRepository;
use Arris\Auth\Repository\UserRepository;
use PDO;
use PDOException;

final class Auth
{
    public const MODE_AUTO = 'auto';
    public const MODE_SESSION = 'session';
    public const MODE_TOKEN = 'token';

    public const SESSION_USER_ID = 'auth_user_id';
    public const SESSION_FORCE_LOGOUT = 'auth_force_logout';
    public const SESSION_REMEMBERED = 'auth_remembered';

    private const REMEMBER_SEPARATOR = '~';

    private UserRepository $users;
    private TokenRepository $tokens;

    /** @var array<string, mixed> */
    private array $options;

    /** @var array{path: string, domain: string, secure: bool, httponly: bool, samesite: string|null, lifetime: int} */
    private array $sessionCookie;

    private ?User $cachedUser = null;
    private bool $resolved = false;
    private ?string $currentBearerToken = null;

    /**
     * Creates an authentication service for the given PDO connection.
     *
     * @param array{
     *     mode?: string,
     *     table_prefix?: string,
     *     db_schema?: string|null,
     *     session_name?: string,
     *     session_cookie?: array<string, mixed>,
     *     remember_cookie_name?: string,
     *     remember_ttl?: int,
     *     token_ttl?: int,
     *     require_verified?: bool,
     *     reject_non_normal_status?: bool,
     *     min_password_length?: int,
     *     update_last_login?: bool,
     *     touch_token_interval?: int
     * } $options
     */
    public function __construct(
        private readonly PDO $pdo,
        array $options = [],
    ) {
        $this->options = \array_replace([
            'mode' => self::MODE_AUTO,
            'table_prefix' => '',
            'db_schema' => null,
            'session_name' => 'arris_auth',
            'session_cookie' => [],
            'remember_cookie_name' => 'arris_remember',
            'remember_ttl' => 60 * 60 * 24 * 30,
            'token_ttl' => 60 * 60 * 24 * 30,
            'require_verified' => true,
            'reject_non_normal_status' => true,
            'min_password_length' => 8,
            'update_last_login' => true,
            'touch_token_interval' => 60,
        ], $options);

        if (!\in_array($this->options['mode'], [self::MODE_AUTO, self::MODE_SESSION, self::MODE_TOKEN], true)) {
            throw new ConfigurationException('Auth mode must be auto, session or token');
        }

        $this->sessionCookie = \array_replace([
            'path' => '/',
            'domain' => '',
            'secure' => $this->isHttps(),
            'httponly' => true,
            'samesite' => 'Lax',
            'lifetime' => 0,
        ], $this->options['session_cookie']);

        if ($this->sessionCookie['samesite'] === '') {
            $this->sessionCookie['samesite'] = null;
        }

        $this->users = new UserRepository(
            $this->pdo,
            $this->options['db_schema'],
            $this->options['table_prefix']
        );

        $this->tokens = new TokenRepository(
            $this->pdo,
            $this->options['db_schema'],
            $this->options['table_prefix']
        );
    }

    /**
     * Returns the underlying PDO connection.
     */
    public function pdo(): PDO
    {
        return $this->pdo;
    }

    /**
     * Returns the active authentication mode: auto, session or token.
     */
    public function mode(): string
    {
        return $this->options['mode'];
    }

    /**
     * Registers a new user account.
     *
     * Validates the email address and password, hashes the password with
     * password_hash() and returns the generated user ID.
     *
     * @throws InvalidEmailException
     * @throws InvalidPasswordException
     * @throws UserAlreadyExistsException
     * @throws AuthException
     */
    public function register(
        string $email,
        string $password,
        ?string $username = null,
        bool $verified = true,
        int $rolesMask = 0,
    ): int {
        $email = $this->validateEmail($email);
        $this->validateNewPassword($password);

        if ($this->users->findByEmail($email) !== null) {
            throw new UserAlreadyExistsException('A user with this email address already exists');
        }

        $username = $username !== null ? \trim($username) : null;
        if ($username === '') {
            $username = null;
        }

        $passwordHash = \password_hash($password, \PASSWORD_DEFAULT);
        if ($passwordHash === false) {
            throw new AuthException('Unable to hash the password');
        }

        try {
            return $this->users->create(
                $email,
                $passwordHash,
                $username,
                Status::NORMAL->value,
                $verified ? 1 : 0,
                $rolesMask
            );
        } catch (PDOException $e) {
            if (\in_array((string) $e->getCode(), ['23000', '23505'], true)) {
                throw new UserAlreadyExistsException('A user with this email address already exists', 0, $e);
            }

            throw $e;
        }
    }

    /**
     * Marks the user's email address as verified.
     */
    public function verifyUser(int $userId): void
    {
        $this->users->setVerified($userId, true);
    }

    /**
     * Authenticates a user by email and password and starts a cookie session.
     *
     * When $remember is true, a long-lived remember-me cookie is created as well.
     *
     * @throws InvalidEmailException
     * @throws InvalidCredentialsException
     * @throws EmailNotVerifiedException
     * @throws AccountDisabledException
     * @throws ConfigurationException
     */
    public function login(string $email, string $password, bool $remember = false): User
    {
        $row = $this->users->findByEmail($this->validateEmail($email));

        if ($row === null) {
            throw new InvalidCredentialsException('Invalid email address or password');
        }

        return $this->loginRow($row, $password, $remember);
    }

    /**
     * Authenticates a user by username and password and starts a cookie session.
     *
     * @throws InvalidCredentialsException
     * @throws AmbiguousUsernameException
     * @throws EmailNotVerifiedException
     * @throws AccountDisabledException
     * @throws ConfigurationException
     */
    public function loginWithUsername(string $username, string $password, bool $remember = false): User
    {
        $rows = $this->users->findByUsername(\trim($username));

        if ($rows === []) {
            throw new InvalidCredentialsException('Invalid username or password');
        }

        if (\count($rows) > 1) {
            throw new AmbiguousUsernameException('This username is ambiguous');
        }

        return $this->loginRow($rows[0], $password, $remember);
    }

    /**
     * Returns the currently authenticated user, or null.
     *
     * Depending on the mode, the user is resolved from the Authorization:
     * Bearer header first, then from the PHP session and the remember-me cookie.
     * The result is cached for the lifetime of the current request.
     */
    public function user(): ?User
    {
        if ($this->resolved) {
            return $this->cachedUser;
        }

        if ($this->options['mode'] !== self::MODE_SESSION) {
            $bearer = $this->bearerToken();

            if ($bearer !== null) {
                $this->resolved = true;
                $this->currentBearerToken = $bearer;

                return $this->cachedUser = $this->userByBearerToken($bearer);
            }
        }

        if ($this->options['mode'] === self::MODE_TOKEN) {
            $this->resolved = true;

            return null;
        }

        if (!Session::isStarted() && !$this->hasSessionCookie()) {
            if (!$this->processRememberCookie()) {
                $this->resolved = true;

                return null;
            }
        } else {
            $this->startSession();

            if (empty($_SESSION[self::SESSION_USER_ID]) && !$this->processRememberCookie()) {
                $this->resolved = true;

                return null;
            }
        }

        $userId = (int) ($_SESSION[self::SESSION_USER_ID] ?? 0);
        if ($userId <= 0) {
            $this->resolved = true;

            return null;
        }

        $row = $this->users->findById($userId);
        if ($row === null) {
            $this->clearSessionAuth();
            $this->deleteRememberCookie();
            $this->resolved = true;

            return null;
        }

        if ((int) $row['force_logout'] > (int) ($_SESSION[self::SESSION_FORCE_LOGOUT] ?? 0)) {
            $this->clearSessionAuth();
            $this->deleteRememberCookie();
            $this->resolved = true;

            return null;
        }

        if ($this->isDisabled($row)) {
            $this->clearSessionAuth();
            $this->deleteRememberCookie();
            $this->resolved = true;

            return null;
        }

        $this->resolved = true;

        return $this->cachedUser = User::fromRow($row);
    }

    /**
     * Returns whether a user is currently authenticated.
     */
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Returns the current user ID, or null when nobody is authenticated.
     */
    public function id(): ?int
    {
        return $this->user()?->id;
    }

    /**
     * Returns the current user's email address, or null.
     */
    public function email(): ?string
    {
        return $this->user()?->email;
    }

    /**
     * Returns the current user's username, or null.
     */
    public function username(): ?string
    {
        return $this->user()?->username;
    }

    /**
     * Returns whether the current session was restored from a remember-me cookie.
     */
    public function isRemembered(): bool
    {
        return Session::isStarted()
            && ($_SESSION[self::SESSION_REMEMBERED] ?? false) === true;
    }

    /**
     * Checks whether the current user has the given role bit.
     */
    public function hasRole(int $role): bool
    {
        return $this->user()?->hasRole($role) ?? false;
    }

    /**
     * Checks whether the current user has at least one of the given role bits.
     */
    public function hasAnyRole(int ...$roles): bool
    {
        return $this->user()?->hasAnyRole(...$roles) ?? false;
    }

    /**
     * Checks whether the current user has all of the given role bits.
     */
    public function hasAllRoles(int ...$roles): bool
    {
        return $this->user()?->hasAllRoles(...$roles) ?? false;
    }

    /**
     * Replaces all roles of a user with a single role bit.
     *
     * Returns the new role bitmask.
     *
     * @throws UnknownUserException
     */
    public function setRole(int $userId, int $role): int
    {
        return $this->setRoles($userId, $role);
    }

    /**
     * Replaces the user's role bitmask.
     *
     * Returns the new role bitmask.
     *
     * @throws UnknownUserException
     */
    public function setRoles(int $userId, int $rolesMask): int
    {
        $this->requireUser($userId);
        $this->users->updateRolesMask($userId, $rolesMask);
        $this->invalidateCachedUser($userId);

        return $rolesMask;
    }

    /**
     * Adds role bits to the user's role mask.
     *
     * Returns the new role bitmask.
     *
     * @throws UnknownUserException
     */
    public function addRole(int $userId, int $role): int
    {
        $row = $this->requireUser($userId);
        $rolesMask = (int) ($row['roles_mask'] ?? 0) | $role;
        $this->users->updateRolesMask($userId, $rolesMask);
        $this->invalidateCachedUser($userId);

        return $rolesMask;
    }

    /**
     * Removes role bits from the user's role mask.
     *
     * Returns the new role bitmask.
     *
     * @throws UnknownUserException
     */
    public function removeRole(int $userId, int $role): int
    {
        $row = $this->requireUser($userId);
        $rolesMask = (int) ($row['roles_mask'] ?? 0) & ~$role;
        $this->users->updateRolesMask($userId, $rolesMask);
        $this->invalidateCachedUser($userId);

        return $rolesMask;
    }

    /**
     * Returns the user's role bitmask.
     *
     * @throws UnknownUserException
     */
    public function roles(int $userId): int
    {
        return (int) ($this->requireUser($userId)['roles_mask'] ?? 0);
    }

    /**
     * Returns the role names of a user.
     *
     * @param array<string, int>|null $map
     * @return list<string>
     * @throws UnknownUserException
     */
    public function roleNamesForUser(int $userId, ?array $map = null): array
    {
        return User::fromRow($this->requireUser($userId))->roleNames($map);
    }

    /**
     * Issues a new opaque bearer token for a user.
     *
     * The plain token is returned once and is never stored. Only its SHA-256
     * hash is written to the users_tokens table.
     *
     * @throws UnknownUserException
     */
    public function issueToken(int $userId, ?int $ttl = null, ?string $name = null): string
    {
        if ($this->users->findById($userId) === null) {
            throw new UnknownUserException('Unknown user');
        }

        $token = self::randomToken(32);
        $ttl ??= (int) $this->options['token_ttl'];
        $expires = $ttl > 0 ? \time() + $ttl : 0;

        $this->tokens->createApi(
            $userId,
            self::hashToken($token),
            $expires,
            $name !== null && $name !== '' ? $name : null
        );

        return $token;
    }

    /**
     * Revokes a bearer token by its plain value.
     *
     * Returns true when a token row was deleted.
     */
    public function revokeToken(string $token): bool
    {
        return $this->tokens->deleteByHash(
            self::hashToken($token),
            TokenRepository::KIND_API
        ) > 0;
    }

    /**
     * Revokes all bearer and remember-me tokens of a user.
     *
     * Returns the number of deleted token rows.
     */
    public function revokeAllTokens(int $userId): int
    {
        return $this->tokens->deleteByUser($userId);
    }

    /**
     * Deletes expired bearer and remember-me tokens.
     *
     * Returns the number of deleted token rows.
     */
    public function deleteExpiredTokens(): int
    {
        return $this->tokens->deleteExpired();
    }

    /**
     * Logs out the current session and revokes the current bearer token, if any.
     */
    public function logout(): void
    {
        $bearer = $this->currentBearerToken ?? $this->bearerToken();

        if ($bearer !== null) {
            $this->tokens->deleteByHash(
                self::hashToken($bearer),
                TokenRepository::KIND_API
            );
        }

        $this->deleteRememberCookie();
        $this->clearSessionAuth();

        if (Session::isStarted()) {
            Session::regenerate(true);
        }

        $this->resolved = true;
        $this->cachedUser = null;
        $this->currentBearerToken = null;
    }

    /**
     * Invalidates every session and token of a user.
     *
     * Increments users.force_logout so existing sessions are rejected on their
     * next request, and deletes all users_tokens rows for the user.
     */
    public function logoutEverywhere(int $userId): void
    {
        $this->users->incrementForceLogout($userId);
        $this->tokens->deleteByUser($userId);

        if ($this->isCurrentUser($userId)) {
            $this->deleteRememberCookie();
        }

        if (Session::isStarted() && (int) ($_SESSION[self::SESSION_USER_ID] ?? 0) === $userId) {
            $this->clearSessionAuth();
            Session::regenerate(true);
        }

        if ($this->cachedUser?->id === $userId) {
            $this->resolved = true;
            $this->cachedUser = null;
            $this->currentBearerToken = null;
        }
    }

    /**
     * Updates a user's password and invalidates existing sessions and tokens.
     *
     * When $keepCurrentSession is true, the current cookie session remains valid.
     *
     * @throws InvalidPasswordException
     * @throws AuthException
     */
    public function changePassword(int $userId, string $newPassword, bool $keepCurrentSession = true): void
    {
        $this->validateNewPassword($newPassword);

        $passwordHash = \password_hash($newPassword, \PASSWORD_DEFAULT);
        if ($passwordHash === false) {
            throw new AuthException('Unable to hash the password');
        }

        $this->users->updatePassword($userId, $passwordHash);
        $forceLogout = $this->users->incrementForceLogout($userId);
        $this->tokens->deleteByUser($userId);

        if ($this->isCurrentUser($userId)) {
            $this->deleteRememberCookie();
        }

        if (Session::isStarted() && (int) ($_SESSION[self::SESSION_USER_ID] ?? 0) === $userId) {
            if ($keepCurrentSession) {
                $_SESSION[self::SESSION_FORCE_LOGOUT] = $forceLogout;
            } else {
                $this->clearSessionAuth();
                Session::regenerate(true);
            }
        }

        if ($this->cachedUser?->id === $userId) {
            $this->resolved = false;
            $this->cachedUser = null;
        }
    }

    /**
     * Authenticates a user database row and creates a session.
     *
     * @param array<string, mixed> $row
     */
    private function loginRow(array $row, string $password, bool $remember): User
    {
        if ($this->options['mode'] === self::MODE_TOKEN) {
            throw new ConfigurationException('Session login is not available in token mode; use issueToken()');
        }

        if (!\password_verify($password, (string) $row['password'])) {
            throw new InvalidCredentialsException('Invalid credentials');
        }

        if (\password_needs_rehash((string) $row['password'], \PASSWORD_DEFAULT)) {
            $newHash = \password_hash($password, \PASSWORD_DEFAULT);

            if ($newHash !== false) {
                $this->users->updatePassword((int) $row['id'], $newHash);
                $row['password'] = $newHash;
            }
        }

        if ($this->options['require_verified'] && (int) $row['verified'] !== 1) {
            throw new EmailNotVerifiedException('The email address has not been verified yet');
        }

        if ($this->isDisabled($row)) {
            throw new AccountDisabledException('This account is disabled');
        }

        $this->startSession();
        Session::regenerate(true);
        $this->setSessionUser($row, false);

        if ($remember) {
            $this->issueRememberCookie((int) $row['id']);
        }

        if ($this->options['update_last_login']) {
            $this->users->updateLastLogin((int) $row['id']);
        }

        $row['last_login'] = \time();

        $this->resolved = true;
        $this->currentBearerToken = null;

        return $this->cachedUser = User::fromRow($row);
    }

    /**
     * Resolves a user by a plain bearer token.
     *
     * Deletes the token row when the user no longer exists or is disabled.
     */
    private function userByBearerToken(string $token): ?User
    {
        $tokenRow = $this->tokens->findApi(self::hashToken($token));

        if ($tokenRow === null) {
            return null;
        }

        $userRow = $this->users->findById((int) $tokenRow['user']);

        if ($userRow === null) {
            $this->tokens->delete((int) $tokenRow['id']);

            return null;
        }

        if ($this->isDisabled($userRow)) {
            $this->tokens->delete((int) $tokenRow['id']);

            return null;
        }

        $this->touchToken($tokenRow);

        return User::fromRow($userRow);
    }

    /**
     * Tries to authenticate from the remember-me cookie.
     *
     * Returns true when a session was created.
     */
    private function processRememberCookie(): bool
    {
        $name = (string) $this->options['remember_cookie_name'];
        $value = $_COOKIE[$name] ?? null;

        if (!\is_string($value) || $value === '') {
            return false;
        }

        $parts = \explode(self::REMEMBER_SEPARATOR, $value, 2);

        if (\count($parts) !== 2 || $parts[0] === '' || $parts[1] === '') {
            $this->deleteRememberCookie();

            return false;
        }

        $tokenRow = $this->tokens->findRemember($parts[0]);

        if ($tokenRow === null || !\hash_equals((string) $tokenRow['token'], self::hashToken($parts[1]))) {
            $this->deleteRememberCookie();

            return false;
        }

        $userRow = $this->users->findById((int) $tokenRow['user']);

        if ($userRow === null || $this->isDisabled($userRow)) {
            $this->deleteRememberCookie();

            return false;
        }

        if ($this->options['require_verified'] && (int) $userRow['verified'] !== 1) {
            $this->deleteRememberCookie();

            return false;
        }

        $this->startSession();
        Session::regenerate(true);
        $this->setSessionUser($userRow, true);
        $this->tokens->touch((int) $tokenRow['id']);

        if ($this->options['update_last_login']) {
            $this->users->updateLastLogin((int) $userRow['id']);
        }

        return true;
    }

    /**
     * Stores the authenticated user's ID and force-logout counter in the session.
     *
     * @param array<string, mixed> $row
     */
    private function setSessionUser(array $row, bool $remembered): void
    {
        $_SESSION[self::SESSION_USER_ID] = (int) $row['id'];
        $_SESSION[self::SESSION_FORCE_LOGOUT] = (int) ($row['force_logout'] ?? 0);
        $_SESSION[self::SESSION_REMEMBERED] = $remembered;
    }

    /**
     * Removes authentication fields from the current session.
     *
     * Other session data is left untouched.
     */
    private function clearSessionAuth(): void
    {
        if (!isset($_SESSION) || !\is_array($_SESSION)) {
            return;
        }

        unset(
            $_SESSION[self::SESSION_USER_ID],
            $_SESSION[self::SESSION_FORCE_LOGOUT],
            $_SESSION[self::SESSION_REMEMBERED],
        );
    }

    /**
     * Creates a remember-me token row and writes the corresponding HttpOnly cookie.
     */
    private function issueRememberCookie(int $userId): void
    {
        $this->deleteRememberCookie();

        $selector = \bin2hex(\random_bytes(12));
        $token = self::randomToken(32);
        $expires = \time() + (int) $this->options['remember_ttl'];

        $this->tokens->createRemember(
            $userId,
            $selector,
            self::hashToken($token),
            $expires
        );

        Cookie::set(
            (string) $this->options['remember_cookie_name'],
            $selector . self::REMEMBER_SEPARATOR . $token,
            $expires,
            $this->rememberCookieOptions()
        );
    }

    /**
     * Returns a user row or throws when the user does not exist.
     *
     * @return array<string, mixed>
     * @throws UnknownUserException
     */
    private function requireUser(int $userId): array
    {
        $row = $this->users->findById($userId);

        if ($row === null) {
            throw new UnknownUserException('Unknown user');
        }

        return $row;
    }

    /**
     * Clears the cached user when the changed user is the current one.
     */
    private function invalidateCachedUser(int $userId): void
    {
        if ($this->cachedUser?->id === $userId) {
            $this->resolved = false;
            $this->cachedUser = null;
        }
    }

    /**
     * Checks whether the given user ID belongs to the current session or cached user.
     */
    private function isCurrentUser(int $userId): bool
    {
        if (Session::isStarted() && (int) ($_SESSION[self::SESSION_USER_ID] ?? 0) === $userId) {
            return true;
        }

        return $this->cachedUser?->id === $userId;
    }

    /**
     * Deletes the current remember-me cookie and its database row, if present.
     */
    private function deleteRememberCookie(): void
    {
        $name = (string) $this->options['remember_cookie_name'];

        if (!isset($_COOKIE[$name]) || !\is_string($_COOKIE[$name])) {
            return;
        }

        $parts = \explode(self::REMEMBER_SEPARATOR, $_COOKIE[$name], 2);

        if ($parts[0] !== '') {
            $this->tokens->deleteBySelector($parts[0]);
        }

        Cookie::delete($name, $this->rememberCookieOptions());
        unset($_COOKIE[$name]);
    }

    /**
     * Starts the PHP session with the configured name and cookie parameters.
     */
    private function startSession(): void
    {
        if (Session::isStarted()) {
            return;
        }

        Session::start((string) $this->options['session_name'], $this->sessionCookie);
    }

    /**
     * Returns whether the request contains the configured session cookie.
     */
    private function hasSessionCookie(): bool
    {
        return isset($_COOKIE[(string) $this->options['session_name']]);
    }

    /**
     * Extracts a Bearer token from the Authorization header, if present.
     */
    private function bearerToken(): ?string
    {
        $header = $_SERVER['HTTP_AUTHORIZATION']
            ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION']
            ?? null;

        if ($header === null && \function_exists('getallheaders')) {
            foreach (\getallheaders() as $name => $value) {
                if (\strcasecmp((string) $name, 'Authorization') === 0) {
                    $header = $value;
                    break;
                }
            }
        }

        if (!\is_string($header)) {
            return null;
        }

        if (!\preg_match('/^Bearer\s+(.+)$/i', \trim($header), $matches)) {
            return null;
        }

        $token = \trim($matches[1]);

        return $token !== '' ? $token : null;
    }

    /**
     * Updates the token's last_used timestamp no more often than touch_token_interval.
     *
     * @param array<string, mixed> $tokenRow
     */
    private function touchToken(array $tokenRow): void
    {
        $interval = (int) $this->options['touch_token_interval'];

        if ($interval <= 0) {
            return;
        }

        $lastUsed = isset($tokenRow['last_used']) ? (int) $tokenRow['last_used'] : 0;

        if ($lastUsed + $interval <= \time()) {
            $this->tokens->touch((int) $tokenRow['id']);
        }
    }

    /**
     * Returns whether the user status is not allowed by the current policy.
     *
     * @param array<string, mixed> $row
     */
    private function isDisabled(array $row): bool
    {
        return $this->options['reject_non_normal_status']
            && (int) ($row['status'] ?? Status::NORMAL->value) !== Status::NORMAL->value;
    }

    /**
     * Trims and validates an email address and returns the normalized address.
     *
     * @throws InvalidEmailException
     */
    private function validateEmail(string $email): string
    {
        $email = \trim($email);

        if ($email === '' || \filter_var($email, \FILTER_VALIDATE_EMAIL) === false) {
            throw new InvalidEmailException('Invalid email address');
        }

        return $email;
    }

    /**
     * Validates a new password against the configured minimum length.
     *
     * @throws InvalidPasswordException
     */
    private function validateNewPassword(string $password): void
    {
        if (\strlen($password) < (int) $this->options['min_password_length']) {
            throw new InvalidPasswordException(
                'Password must be at least ' . (int) $this->options['min_password_length'] . ' characters long'
            );
        }
    }

    /**
     * Returns cookie options shared by the session and remember-me cookies.
     *
     * @return array{path: string, domain: string, secure: bool, httponly: bool, samesite: string|null}
     */
    private function rememberCookieOptions(): array
    {
        return [
            'path' => (string) $this->sessionCookie['path'],
            'domain' => (string) $this->sessionCookie['domain'],
            'secure' => (bool) $this->sessionCookie['secure'],
            'httponly' => (bool) $this->sessionCookie['httponly'],
            'samesite' => $this->sessionCookie['samesite'],
        ];
    }

    /**
     * Detects whether the current request was made over HTTPS.
     */
    private function isHttps(): bool
    {
        return (!empty($_SERVER['HTTPS']) && \strtolower((string) $_SERVER['HTTPS']) !== 'off')
            || (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;
    }

    /**
     * Generates a URL-safe random token from cryptographically secure bytes.
     */
    private static function randomToken(int $bytes = 32): string
    {
        return \rtrim(\strtr(\base64_encode(\random_bytes($bytes)), '+/', '-_'), '=');
    }

    /**
     * Returns the SHA-256 hash used to store tokens at rest.
     */
    private static function hashToken(string $token): string
    {
        return \hash('sha256', $token);
    }
}
