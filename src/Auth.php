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
use Arris\Auth\Exception\NotLoggedInException;
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

    private AuthConfig $config;

    /** @var array{path: string, domain: string, secure: bool, httponly: bool, samesite: string|null, lifetime: int} */
    private array $sessionCookie;

    private ?User $cachedUser = null;
    private bool $resolved = false;
    private ?string $currentBearerToken = null;

    /**
     * Creates an authentication service for the given PDO connection.
     * When no configuration is passed, AuthConfig defaults are used.
     *
     * Создаёт сервис аутентификации для указанного соединения PDO.
     * Если конфигурация не передана, используются значения по умолчанию AuthConfig.
     *
     * @param PDO $pdo
     * @param AuthConfig|null $config
     */
    public function __construct(
        private readonly PDO $pdo,
        ?AuthConfig $config = null,
    ) {
        $this->config = $config !== null ? clone $config : new AuthConfig();

        $this->sessionCookie = \array_replace([
            'path' => '/',
            'domain' => '',
            'secure' => $this->isHttps(),
            'httponly' => true,
            'samesite' => 'Lax',
            'lifetime' => 0,
        ], $this->config->getSessionCookie());

        if ($this->sessionCookie['samesite'] === '') {
            $this->sessionCookie['samesite'] = null;
        }

        $this->users = new UserRepository(
            $this->pdo,
            $this->config->getDbSchema(),
            $this->config->getTablePrefix()
        );

        $this->tokens = new TokenRepository(
            $this->pdo,
            $this->config->getDbSchema(),
            $this->config->getTablePrefix()
        );

        if ($this->config->getAutoInitialize()) {
            $this->initialize();
        }
    }

    /**
     * Resolves the current authentication state eagerly.
     *
     * Mirrors the old library workflow: a present session cookie, remember-me
     * cookie or bearer token is processed immediately, so isLoggedIn() and
     * getUserId() work right after construction. Anonymous visitors do not get
     * a new session here; the session is created on login().
     *
     * Определяет текущее состояние аутентификации сразу.
     *
     * Повторяет workflow старой библиотеки: присутствующие session cookie, remember-me cookie или bearer-токен
     * обрабатываются сразу, поэтому isLoggedIn() и getUserId() работают сразу после создания объекта.
     * Анонимным посетителям новая сессия здесь не создаётся; сессия создаётся при login().
     *
     * @return void
     */
    public function initialize(): void
    {
        if ($this->resolved) {
            return;
        }

        $mode = $this->config->getMode();

        if ($mode !== self::MODE_SESSION && $this->bearerToken() !== null) {
            $this->user();

            return;
        }

        if ($mode === self::MODE_TOKEN) {
            return;
        }

        if (Session::isStarted() && !empty($_SESSION[self::SESSION_USER_ID])) {
            $this->user();

            return;
        }

        if ($this->hasSessionCookie() || $this->hasRememberCookie()) {
            $this->user();
        }
    }

    /**
     * Returns the underlying PDO connection.
     *
     * Возвращает используемое соединение PDO.
     *
     * @return PDO
     */
    public function pdo(): PDO
    {
        return $this->pdo;
    }

    /**
     * Returns the active authentication mode: auto, session or token.
     *
     * Возвращает активный режим аутентификации: auto, session или token.
     *
     * @return string
     */
    public function mode(): string
    {
        return $this->config->getMode();
    }

    /**
     * Registers a new user account.
     * Validates the email address and password, hashes the password with
     * password_hash() and returns the generated user ID.
     *
     * Регистрирует новую учётную запись пользователя.
     * Проверяет email-адрес и пароль, хэширует пароль через password_hash()
     * и возвращает сгенерированный ID пользователя.
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
     *
     * Помечает email-адрес пользователя как подтверждённый.
     *
     * @param int $userId
     * @return void
     */
    public function verifyUser(int $userId): void
    {
        $this->users->setVerified($userId, true);
    }

    /**
     * Authenticates a user by email and password and starts a cookie session.
     * When $remember is true, a long-lived remember-me cookie is created as well.
     *
     * Аутентифицирует пользователя по email и паролю и запускает cookie-сессию.
     * Если $remember равно true, дополнительно создаётся долгоживущая remember-me cookie.
     *
     * @param string $email
     * @param string $password
     * @param bool $remember
     * @return User
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
     * Аутентифицирует пользователя по имени пользователя и паролю и запускает cookie-сессию.
     *
     * @param string $username
     * @param string $password
     * @param bool $remember
     *
     * @return User
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
     * Depending on the mode, the user is resolved from the Authorization:
     * Bearer header first, then from the PHP session and the remember-me cookie.
     * The result is cached for the lifetime of the current request.
     *
     * Возвращает текущего аутентифицированного пользователя или null.
     * В зависимости от режима пользователь сначала определяется по заголовку Authorization: Bearer,
     * затем по PHP-сессии и remember-me cookie. Результат кэшируется на время текущего запроса.
     *
     * @return User|null
     */
    public function user(): ?User
    {
        if ($this->resolved) {
            return $this->cachedUser;
        }

        if ($this->config->getMode() !== self::MODE_SESSION) {
            $bearer = $this->bearerToken();

            if ($bearer !== null) {
                $this->resolved = true;
                $this->currentBearerToken = $bearer;

                return $this->cachedUser = $this->userByBearerToken($bearer);
            }
        }

        if ($this->config->getMode() === self::MODE_TOKEN) {
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
     *
     * Возвращает, аутентифицирован ли сейчас пользователь.
     *
     * @return bool
     */
    public function check(): bool
    {
        return $this->user() !== null;
    }

    /**
     * Returns whether a user is currently authenticated.
     * Compatibility alias for check(), matching the old Delight Auth API.
     *
     * Возвращает, аутентифицирован ли сейчас пользователь.
     * Совместимый алиас для check(), повторяющий старый API Delight Auth.
     *
     * @return bool
     */
    public function isLoggedIn(): bool
    {
        return $this->check();
    }

    /**
     * Returns the current user, or throws when nobody is authenticated.
     *
     * Возвращает текущего пользователя или выбрасывает исключение, если никто не аутентифицирован.
     *
     * @return User
     * @throws \Arris\Auth\Exception\NotLoggedInException
     */
    public function userOrFail(): User
    {
        $user = $this->user();

        if ($user === null) {
            throw new NotLoggedInException('Not logged in');
        }

        return $user;
    }

    /**
     * Returns the current user ID, or null when nobody is authenticated.
     *
     * Возвращает ID текущего пользователя или null, если никто не аутентифицирован.
     *
     * @return int|null
     */
    public function id(): ?int
    {
        return $this->user()?->id;
    }

    /**
     * Returns the current user ID, or null when nobody is authenticated.
     * Compatibility alias for id(), matching the old Delight Auth API.
     *
     * Возвращает ID текущего пользователя или null, если никто не аутентифицирован.
     * Совместимый алиас для id(), повторяющий старый API Delight Auth.
     *
     * @return int|null
     */
    public function getUserId(): ?int
    {
        return $this->id();
    }

    /**
     * Returns the current user's email address, or null.
     *
     * Возвращает email-адрес текущего пользователя или null.
     *
     * @return string|null
     */
    public function email(): ?string
    {
        return $this->user()?->email;
    }

    /**
     * Returns the current user's username, or null.
     *
     * Возвращает имя текущего пользователя или null.
     *
     * @return string|null
     */
    public function username(): ?string
    {
        return $this->user()?->username;
    }

    /**
     * Returns the current user, or null.
     * Compatibility alias for user(), matching the old Delight Auth API.
     *
     * Возвращает текущего пользователя или null.
     * Совместимый алиас для user(), повторяющий старый API Delight Auth.     *
     *
     * @return User|null
     */
    public function getUser(): ?User
    {
        return $this->user();
    }

    /**
     * Returns the current user's email address, or null.
     * Compatibility alias for email().
     *
     * Возвращает email-адрес текущего пользователя или null.
     * Совместимый алиас для email().
     *
     * @return string|null
     */
    public function getEmail(): ?string
    {
        return $this->email();
    }

    /**
     * Returns the current user's username, or null.
     * Compatibility alias for username().
     *
     * Возвращает имя текущего пользователя или null.
     * Совместимый алиас для username().
     *
     * @return string|null
     */
    public function getUsername(): ?string
    {
        return $this->username();
    }

    /**
     * Returns the current user's role names keyed by role bit.
     *
     * Возвращает имена ролей текущего пользователя с ключами по битам ролей.
     *
     * @return array<int, string>
     */
    public function getRoles(): array
    {
        $user = $this->user();

        if ($user === null) {
            return [];
        }

        return \array_filter(
            Role::getMap(),
            static fn (int $role): bool => $user->hasRole($role),
            \ARRAY_FILTER_USE_KEY
        );
    }

    /**
     * Returns whether the current session was restored from a remember-me cookie.
     *
     * Возвращает, была ли текущая сессия восстановлена из remember-me cookie.
     *
     * @return bool
     */
    public function isRemembered(): bool
    {
        return Session::isStarted()
            && ($_SESSION[self::SESSION_REMEMBERED] ?? false) === true;
    }

    /**
     * Checks whether the current user has the given role bit.
     *
     * Проверяет, есть ли у текущего пользователя указанный бит роли.
     *
     * @param int $role
     *
     * @return bool
     */
    public function hasRole(int $role): bool
    {
        return $this->user()?->hasRole($role) ?? false;
    }

    /**
     * Checks whether the current user has at least one of the given role bits.
     *
     * Проверяет, есть ли у текущего пользователя хотя бы один из указанных битов ролей.
     *
     * @param int ...$roles
     *
     * @return bool
     */
    public function hasAnyRole(int ...$roles): bool
    {
        return $this->user()?->hasAnyRole(...$roles) ?? false;
    }

    /**
     * Checks whether the current user has all of the given role bits.
     *
     * Проверяет, есть ли у текущего пользователя все указанные биты ролей.
     *
     * @param int ...$roles
     *
     * @return bool
     */
    public function hasAllRoles(int ...$roles): bool
    {
        return $this->user()?->hasAllRoles(...$roles) ?? false;
    }

    /**
     * Replaces all roles of a user with a single role bit.
     * Returns the new role bitmask.
     *
     * Заменяет все роли пользователя одним битом роли.
     * Возвращает новую битовую маску ролей.
     *
     * @param int $userId
     * @param int $role
     *
     * @return int
     * @throws UnknownUserException
     */
    public function setRole(int $userId, int $role): int
    {
        return $this->setRoles($userId, $role);
    }

    /**
     * Replaces the user's role bitmask.
     * Returns the new role bitmask.
     *
     * Заменяет битовую маску ролей пользователя.
     * Возвращает новую битовую маску ролей.
     *
     * @param int $userId
     * @param int $rolesMask
     *
     * @return int
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
     * Returns the new role bitmask.
     *
     * Добавляет биты ролей в маску ролей пользователя.
     * Возвращает новую битовую маску ролей.
     *
     * @param int $userId
     * @param int $role
     *
     * @return int
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
     * Returns the new role bitmask.
     *
     * Удаляет биты ролей из маски ролей пользователя.
     * Возвращает новую битовую маску ролей.
     *
     * @param int $userId
     * @param int $role
     *
     * @return int
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
     * Возвращает битовую маску ролей пользователя.
     *
     * @param int $userId
     *
     * @return int
     * @throws UnknownUserException
     */
    public function roles(int $userId): int
    {
        return (int) ($this->requireUser($userId)['roles_mask'] ?? 0);
    }

    /**
     * Returns the role names of a user.
     *
     * Возвращает имена ролей пользователя.
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
     * The plain token is returned once and is never stored. Only its SHA-256
     * hash is written to the users_tokens table.
     *
     * Выдаёт новый непрозрачный bearer-токен для пользователя.
     * Открытый токен возвращается один раз и никогда не сохраняется.
     * В таблицу users_tokens записывается только его SHA-256 хэш.
     *
     * @throws UnknownUserException
     */
    public function issueToken(int $userId, ?int $ttl = null, ?string $name = null): string
    {
        if ($this->users->findById($userId) === null) {
            throw new UnknownUserException('Unknown user');
        }

        $token = self::randomToken(32);
        $ttl ??= $this->config->getTokenTtl();
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
     * Returns true when a token row was deleted.
     *
     * Отзывает bearer-токен по его открытому значению.
     * Возвращает true, если строка токена была удалена.
     *
     * @param string $token
     *
     * @return bool
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
     * Returns the number of deleted token rows.
     *
     * Отзывает все bearer- и remember-me токены пользователя.
     * Возвращает количество удалённых строк токенов.
     *
     * @param int $userId
     *
     * @return int
     */
    public function revokeAllTokens(int $userId): int
    {
        return $this->tokens->deleteByUser($userId);
    }

    /**
     * Deletes expired bearer and remember-me tokens.
     * Returns the number of deleted token rows.
     *
     * Удаляет истёкшие bearer- и remember-me токены.
     * Возвращает количество удалённых строк токенов.
     *
     * @return int
     */
    public function deleteExpiredTokens(): int
    {
        return $this->tokens->deleteExpired();
    }

    /**
     * Logs out the current session and revokes the current bearer token, if any.
     *
     * Выполняет выход из текущей сессии и отзывает текущий bearer-токен, если он есть.
     *
     * @return void
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
     * Increments users.force_logout so existing sessions are rejected on their next request
     * and deletes all users_tokens rows for the user.
     *
     * Инвалидирует все сессии и токены пользователя.
     * Увеличивает users.force_logout, чтобы существующие сессии отклонялись при следующем запросе
     * и удаляет все строки users_tokens пользователя.
     *
     * @param int $userId
     *
     * @return void
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
     * Confirms the current user's password.
     * Useful before sensitive actions and for self-service password changes.
     *
     * Подтверждает пароль текущего пользователя.
     * Полезно перед чувствительными действиями и для самостоятельной смены пароля.
     *
     * @param string $password
     *
     * @return bool
     *
     * @throws NotLoggedInException
     */
    public function reconfirmPassword(string $password): bool
    {
        $user = $this->user();

        if ($user === null) {
            throw new NotLoggedInException('Not logged in');
        }

        $row = $this->users->findById($user->id);

        if ($row === null) {
            throw new NotLoggedInException('Not logged in');
        }

        return \password_verify($password, (string) $row['password']);
    }

    /**
     * Changes the current user's password after checking the old password.
     *
     * Меняет пароль текущего пользователя после проверки старого пароля.
     *
     * @param string $oldPassword
     * @param string $newPassword
     * @param bool $keepCurrentSession
     *
     * @return void
     *
     * @throws NotLoggedInException
     * @throws InvalidPasswordException
     * @throws AuthException
     */
    public function changeOwnPassword(
        string $oldPassword,
        string $newPassword,
        bool $keepCurrentSession = true,
    ): void {
        $userId = $this->id();

        if ($userId === null) {
            throw new NotLoggedInException('Not logged in');
        }

        if (!$this->reconfirmPassword($oldPassword)) {
            throw new InvalidPasswordException('Invalid current password');
        }

        $this->changePassword($userId, $newPassword, $keepCurrentSession);
    }

    /**
     * Deletes a user and all of their tokens.
     * When the deleted user is the current user, the local session and remember
     * cookie are cleared as well.
     *
     * Удаляет пользователя и все его токены.
     * Если удаляемый пользователь является текущим, локальная сессия и remember-cookie также очищаются.
     *
     * @param int $userId
     *
     * @return void
     *
     * @throws UnknownUserException
     */
    public function deleteUser(int $userId): void
    {
        $this->requireUser($userId);
        $this->tokens->deleteByUser($userId);
        $this->users->delete($userId);

        if ($this->isCurrentUser($userId)) {
            $this->deleteRememberCookie();
            $this->clearSessionAuth();

            if (Session::isStarted()) {
                Session::regenerate(true);
            }
        }

        if ($this->cachedUser?->id === $userId) {
            $this->resolved = true;
            $this->cachedUser = null;
            $this->currentBearerToken = null;
        }
    }

    /**
     * Updates a user's password and invalidates existing sessions and tokens.
     * When $keepCurrentSession is true, the current cookie session remains valid.
     *
     * Обновляет пароль пользователя и инвалидирует существующие сессии и токены.
     * Если $keepCurrentSession равно true, текущая cookie-сессия остаётся действительной.
     *
     * @param int $userId
     * @param string $newPassword
     * @param bool $keepCurrentSession
     *
     * @return void
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
     * Аутентифицирует строку пользователя из БД и создаёт сессию.
     *
     * @param array<string, mixed> $row
     * @param string $password
     * @param bool $remember
     *
     * @return User
     */
    private function loginRow(array $row, string $password, bool $remember): User
    {
        if ($this->config->getMode() === self::MODE_TOKEN) {
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

        if ($this->config->getRequireVerified() && (int) $row['verified'] !== 1) {
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

        if ($this->config->getUpdateLastLogin()) {
            $this->users->updateLastLogin((int) $row['id']);
        }

        $row['last_login'] = \time();

        $this->resolved = true;
        $this->currentBearerToken = null;

        return $this->cachedUser = User::fromRow($row);
    }

    /**
     * Resolves a user by a plain bearer token.
     * Deletes the token row when the user no longer exists or is disabled.
     *
     * Определяет пользователя по открытому bearer-токену.
     * Удаляет строку токена, если пользователь больше не существует или отключён.
     *
     * @param string $token
     *
     * @return User|null
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
     * Returns true when a session was created.
     *
     * Пытается аутентифицировать по remember-me cookie.
     * Возвращает true, если сессия была создана.

     * @return bool
     */
    private function processRememberCookie(): bool
    {
        $name = $this->config->getRememberCookieName();
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

        if ($this->config->getRequireVerified() && (int) $userRow['verified'] !== 1) {
            $this->deleteRememberCookie();

            return false;
        }

        $this->startSession();
        Session::regenerate(true);
        $this->setSessionUser($userRow, true);
        $this->tokens->touch((int) $tokenRow['id']);

        if ($this->config->getUpdateLastLogin()) {
            $this->users->updateLastLogin((int) $userRow['id']);
        }

        return true;
    }

    /**
     * Stores the authenticated user's ID and force-logout counter in the session.
     *
     * Сохраняет ID аутентифицированного пользователя и счётчик принудительного выхода в сессии.
     *
     * @param array<string, mixed> $row
     * @param bool $remembered
     *
     * @return void
     */
    private function setSessionUser(array $row, bool $remembered): void
    {
        $_SESSION[self::SESSION_USER_ID] = (int) $row['id'];
        $_SESSION[self::SESSION_FORCE_LOGOUT] = (int) ($row['force_logout'] ?? 0);
        $_SESSION[self::SESSION_REMEMBERED] = $remembered;
    }

    /**
     * Removes authentication fields from the current session.
     * Other session data is left untouched.
     *
     * Удаляет поля аутентификации из текущей сессии.
     * Остальные данные сессии не изменяются.
     *
     * @return void
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
     *
     * Создаёт строку remember-me токена и записывает соответствующую HttpOnly cookie.
     *
     * @param int $userId
     *
     * @return void
     * @throws \Exception
     */
    private function issueRememberCookie(int $userId): void
    {
        $this->deleteRememberCookie();

        $selector = \bin2hex(\random_bytes(12));
        $token = self::randomToken(32);
        $expires = \time() + $this->config->getRememberTtl();

        $this->tokens->createRemember(
            $userId,
            $selector,
            self::hashToken($token),
            $expires
        );

        Cookie::set(
            $this->config->getRememberCookieName(),
            $selector . self::REMEMBER_SEPARATOR . $token,
            $expires,
            $this->rememberCookieOptions()
        );
    }

    /**
     * Returns a user row or throws when the user does not exist.
     *
     * Возвращает строку пользователя или выбрасывает исключение, если пользователь не существует.
     *
     * @param int $userId
     *
     * @return array
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
     *
     * Сбрасывает кэшированного пользователя, если изменённый пользователь является текущим.
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
     *
     * Проверяет, принадлежит ли указанный ID пользователя текущей сессии или кэшированному пользователю.
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
     *
     * Удаляет текущую remember-me cookie и связанную строку в БД, если они есть.
     */
    private function deleteRememberCookie(): void
    {
        $name = $this->config->getRememberCookieName();

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
     *
     * Запускает PHP-сессию с настроенными именем и параметрами cookie.
     */
    private function startSession(): void
    {
        if (Session::isStarted()) {
            return;
        }

        Session::start(
            $this->config->getSessionName(),
            $this->sessionCookie,
            $this->config->getSessionHandler()
        );
    }

    /**
     * Returns whether the request contains the configured session cookie.
     *
     *
     * Возвращает, содержит ли запрос настроенную cookie сессии.
     */
    private function hasSessionCookie(): bool
    {
        return isset($_COOKIE[$this->config->getSessionName()]);
    }

    /**
     * Returns whether the request contains a non-empty remember-me cookie.
     *
     * Возвращает, содержит ли запрос непустую remember-me cookie.
     */
    private function hasRememberCookie(): bool
    {
        $value = $_COOKIE[$this->config->getRememberCookieName()] ?? null;

        return \is_string($value) && $value !== '';
    }

    /**
     * Extracts a Bearer token from the Authorization header, if present.
     *
     * Извлекает bearer-токен из заголовка Authorization, если он присутствует.
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
     * Обновляет метку last_used токена не чаще, чем раз в touch_token_interval.
     *
     * @param array<string, mixed> $tokenRow
     */
    private function touchToken(array $tokenRow): void
    {
        $interval = $this->config->getTouchTokenInterval();

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
     * Возвращает, запрещён ли статус пользователя текущей политикой.
     *
     * @param array<string, mixed> $row
     */
    private function isDisabled(array $row): bool
    {
        return $this->config->getRejectNonNormalStatus()
            && (int) ($row['status'] ?? Status::NORMAL->value) !== Status::NORMAL->value;
    }

    /**
     * Trims and validates an email address and returns the normalized address.
     *
     * Обрезает и проверяет email-адрес и возвращает нормализованный адрес.
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
     *
     * Проверяет новый пароль на соответствие настроенной минимальной длине.
     *
     * @throws InvalidPasswordException
     */
    private function validateNewPassword(string $password): void
    {
        if (\strlen($password) < $this->config->getMinPasswordLength()) {
            throw new InvalidPasswordException(
                'Password must be at least ' . $this->config->getMinPasswordLength() . ' characters long'
            );
        }
    }

    /**
     * Returns cookie options shared by the session and remember-me cookies.
     *
     * Возвращает параметры cookie, общие для сессионной и remember-me cookie.
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
     *
     * Определяет, был ли текущий запрос выполнен по HTTPS.
     */
    private function isHttps(): bool
    {
        return (!empty($_SERVER['HTTPS']) && \strtolower((string) $_SERVER['HTTPS']) !== 'off')
            || (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;
    }

    /**
     * Generates a URL-safe random token from cryptographically secure bytes.
     *
     * Генерирует URL-безопасный случайный токен из криптографически стойких байтов.
     */
    private static function randomToken(int $bytes = 32): string
    {
        return \rtrim(\strtr(\base64_encode(\random_bytes($bytes)), '+/', '-_'), '=');
    }

    /**
     * Returns the SHA-256 hash used to store tokens at rest.
     *
     * Возвращает SHA-256 хэш, используемый для хранения токенов.
     */
    private static function hashToken(string $token): string
    {
        return \hash('sha256', $token);
    }
}
