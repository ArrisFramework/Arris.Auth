# HOWTO — типичные сценарии Arris.Auth

Практические рецепты для `karelwintersky/arris.auth`. Предполагается, что таблицы
`users`, `users_tokens` и `users_confirmations` уже созданы по
`_database/schema_mysql.sql`.

## 0. Базовая инициализация

```php
use Arris\Auth\Auth;
use Arris\Auth\AuthConfig;
use PDO;

$pdo = new PDO('mysql:host=127.0.0.1;dbname=app;charset=utf8mb4', 'user', 'pass', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);

$config = (new AuthConfig())
    ->setTablePrefix('')
    ->setDbSchema(null)
    ->setSessionName('app_session')
    ->setSessionCookie([
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ])
    ->setRememberCookieName('app_remember')
    ->setRememberTtl(60 * 60 * 24 * 30)
    ->setRequireVerified(true);

$auth = new Auth($pdo, $config);
```

`Auth` — сервис на текущий запрос. Конфиг клонируется внутри, поэтому его можно
переиспользовать. По умолчанию `autoInitialize = true`: конструктор уже обработал
session cookie, remember-me cookie или bearer-токен.

Если нужен полностью ленивый вариант:

```php
$config->setAutoInitialize(false);
```

---

## 1. Проверка «залогинен»

```php
if ($auth->isLoggedIn()) {
    $userId = $auth->getUserId();
}

// check() — то же самое
if ($auth->check()) {
    $user = $auth->user();
}

// или сразу пользователь/исключение
use Arris\Auth\Exception\NotLoggedInException;

try {
    $user = $auth->userOrFail();
} catch (NotLoggedInException $e) {
    // не авторизован
}
```

`$auth->user()` возвращает `null`, когда пользователь не авторизован — это нормальный
результат, а не ошибка. Для проверки в middleware используйте `isLoggedIn()`/`check()`.

```php
if (!App::$auth_driver->isLoggedIn()) {
    throw new AccessDeniedException('Вы не авторизованы');
}
```

---

## 2. Пользовательская регистрация

```php
use Arris\Auth\Exception\InvalidEmailException;
use Arris\Auth\Exception\InvalidPasswordException;
use Arris\Auth\Exception\UserAlreadyExistsException;
use Arris\Auth\Exception\AuthException;

try {
    $user = $auth->register(
        email: 'user@example.com',
        password: 'correct horse battery staple',
        username: 'user',
    );

    if ($user->isVerified()) {
        $auth->login('user@example.com', 'correct horse battery staple');
        echo 'Зарегистрирован и залогинен';
    } else {
        echo 'Зарегистрирован, ожидает подтверждения email';
    }
} catch (InvalidEmailException $e) {
    echo 'Некорректный email';
} catch (InvalidPasswordException $e) {
    echo 'Слишком короткий пароль';
} catch (UserAlreadyExistsException $e) {
    echo 'Пользователь с таким email уже есть';
} catch (AuthException $e) {
    echo 'Ошибка: ' . $e->getMessage();
}
```

Сигнатура:

```php
$auth->register(
    string $email,
    string $password,
    ?string $username = null,
    ?bool $verified = null,
    int $rolesMask = 0,
): \Arris\Auth\DTO\User;
```

Поведение зависит от `AuthConfig::setUserConfirmationRequired()`:

- `false` (по умолчанию) — `verified = 1`, пользователь может логиниться сразу;
- `true` — `verified = 0`, создаётся запись в `users_confirmations` и вызывается
  `MailerInterface::sendActivation()`;
- `verified: true` — админский обход confirmation;
- `verified: false` — принудительно неверифицированный пользователь.

Пример с confirmation:

```php
use Arris\Auth\Mailer\NativeMailer;

$config = (new AuthConfig())
    ->setUserConfirmationRequired(true)
    ->setConfirmationTtl(3600)
    ->setMailer(new NativeMailer());

$auth = new Auth($pdo, $config);

$user = $auth->register('user@example.com', 'correct horse battery staple', 'user');
// $user->isVerified() === false
```

Если мэйлер не задан, используется `NullMailer` — регистрация успешна, но письмо
фактически не отправляется. Для production задайте реальный `MailerInterface`.

---

## 3. Активация пользователя

Пользователь подтверждает email токеном из письма:

```php
use Arris\Auth\Exception\InvalidConfirmationException;

try {
    $user = $auth->confirmUser($activationKey);
    echo 'Email подтверждён: ' . $user->email;
} catch (InvalidConfirmationException $e) {
    echo 'Ссылка недействительна или истекла';
}
```

`confirmUser()` сам проверяет срок действия, ставит `verified = 1`, удаляет
confirmation-записи и возвращает `User`.

Повторная отправка письма:

```php
$state = $auth->resendConfirmation('user@example.com');

if ($state->isSent()) {
    echo 'Письмо отправлено';
}
// reason: sent | unknown_user | already_verified | not_required | mail_failed
```

Админское подтверждение без токена:

```php
use Arris\Auth\Exception\UnknownUserException;

try {
    $auth->verifyUser($userId);
} catch (UnknownUserException $e) {
    echo 'Пользователь не найден';
}
```

После этого `verified = 1`, и пользователь может войти.

---

## 4. Логин

По email:

```php
use Arris\Auth\Exception\InvalidEmailException;
use Arris\Auth\Exception\InvalidCredentialsException;
use Arris\Auth\Exception\EmailNotVerifiedException;
use Arris\Auth\Exception\AccountDisabledException;
use Arris\Auth\Exception\ConfigurationException;
use Arris\Auth\Exception\AuthException;

try {
    $user = $auth->login(
        email: (string) ($_REQUEST['email'] ?? ''),
        password: (string) ($_REQUEST['password'] ?? ''),
        remember: (bool) ($_REQUEST['remember'] ?? false),
    );

    echo 'User is logged in: ' . $user->id;
} catch (InvalidEmailException $e) {
    throw new AccessDeniedException('Неправильный E-Mail');
} catch (InvalidCredentialsException $e) {
    // неизвестный email ИЛИ неверный пароль — пакет намеренно их не различает
    throw new AccessDeniedException('Неправильный E-Mail или пароль');
} catch (EmailNotVerifiedException $e) {
    throw new AccessDeniedException('E-Mail не подтвержден');
} catch (AccountDisabledException $e) {
    throw new AccessDeniedException('Аккаунт заблокирован');
} catch (ConfigurationException|AuthException $e) {
    throw new AccessDeniedException('Ошибка авторизации: ' . $e->getMessage());
}
```

По username:

```php
$user = $auth->loginWithUsername('user', $password, remember: true);
```

`remember: true` включает remember-me cookie. Время жизни задаётся заранее:

```php
$config->setRememberTtl(60 * 60 * 24 * 30);
```

`login()` создаёт/регенерирует PHP-сессию. В режиме `token` логин запрещён:

```php
// ConfigurationException: use issueToken() instead
$auth->login($email, $password);
```

`setRequireVerified(true)` и `setRejectNonNormalStatus(true)` действуют не только
на `login()`: существующая сессия, remember-cookie и bearer-токен тоже перестают
работать, если пользователю сняли `verified` или изменили `status`.

---

## 5. Логаут

Текущий пользователь:

```php
$auth->logout();
```

Что делает `logout()`:

- отзывает текущий bearer-токен, если запрос был с `Authorization: Bearer`;
- удаляет remember-me cookie и его строку в `users_tokens`;
- очищает данные авторизации в сессии;
- регенерирует session ID.

Все сессии и токены пользователя (например, после смены пароля или админом):

```php
$auth->logoutEverywhere($userId);
```

Если это текущий пользователь — его локальная сессия тоже будет очищена.
Если админ разлогинивает другого пользователя — сессия админа не затрагивается.

---

## 6. Регистрация пользователя администратором

Админ создаёт сразу активного пользователя с нужными ролями:

```php
use Arris\Auth\Role;

$user = $auth->register(
    email: 'manager@example.com',
    password: 'temporary password',
    username: 'manager',
    verified: true,                         // админский обход confirmation
    rolesMask: Role::MANAGER | Role::EDITOR, // начальные роли
);

$userId = $user->id;
```

Либо создать неверифицированного пользователя и подтвердить его отдельно:

```php
$user = $auth->register('manager@example.com', 'temporary password', 'manager', verified: false);
$auth->verifyUser($user->id);
$auth->addRole($user->id, Role::MANAGER);
$auth->addRole($user->id, Role::EDITOR);
```

Установить роли целиком:

```php
$auth->setRoles($userId, Role::MANAGER | Role::EDITOR);
```

`setRole($userId, $role)` — сахар для «ровно одна роль»:

```php
$auth->setRole($userId, Role::ADMIN);
```

После смены ролей кэш текущего пользователя инвалидируется автоматически.

Если у вас приложение использует свои названия ролей, расширьте `Role`:

```php
final class AppRole extends \Arris\Auth\Role
{
    public const GAME_MASTER = \Arris\Auth\Role::COORDINATOR;
    public const PLAYER = \Arris\Auth\Role::SUBSCRIBER;

    public static function map(): array
    {
        return [
            'GAME_MASTER' => self::GAME_MASTER,
            'PLAYER' => self::PLAYER,
        ];
    }
}
```

`AppRole::PLAYER` — обычный `int`, поэтому `hasRole(AppRole::PLAYER)` работает
без настройки. Чтобы `Auth::getRoles()` и `Auth::roleNamesForUser()` использовали
прикладные имена, передайте карту в конфиг:

```php
$config = (new AuthConfig())->setRolesMap(AppRole::map());
$auth = new Auth($pdo, $config);
```

Без `setRolesMap()` используется базовая карта `Role::map()`.

---

## 7. Проверка ролей

Для текущего пользователя:

```php
if ($auth->hasRole(Role::ADMIN)) {
    // админ
}

if ($auth->hasAnyRole(Role::ADMIN, Role::MODERATOR)) {
    // любая из ролей
}

if ($auth->hasAllRoles(Role::ADMIN, Role::EDITOR)) {
    // обе роли
}
```

Роли произвольного пользователя:

```php
$mask = $auth->roles($userId);                 // int bitmask
$names = $auth->roleNamesForUser($userId);     // ['ADMIN', 'EDITOR'] или карта из setRolesMap()

$user = $auth->user();
$names = $user->roleNames();                   // по стандартной карте Role
$names = $user->roleNames(AppRole::map());     // по карте приложения
```

`getRoles()` у текущего пользователя возвращает `bit => name` и учитывает
`setRolesMap()`:

```php
if ($auth->isLoggedIn()) {
    $roles = $auth->getRoles();
    // [1 => 'ADMIN', 1024 => 'EDITOR']
}
```

Middleware «нужна роль»:

```php
if (!$auth->isLoggedIn() || !$auth->hasRole(Role::ADMIN)) {
    throw new AccessDeniedException('Недостаточно прав');
}
```

Управление ролями:

```php
$auth->addRole($userId, Role::EDITOR);     // добавить бит
$auth->removeRole($userId, Role::EDITOR);  // убрать бит
$auth->setRole($userId, Role::MODERATOR);  // заменить маску одним битом
$auth->setRoles($userId, $mask);           // заменить маску целиком
```

---

## 8. Смена пароля

### Пользователь меняет свой пароль (со знанием старого)

```php
use Arris\Auth\Exception\InvalidPasswordException;
use Arris\Auth\Exception\NotLoggedInException;

try {
    $auth->changeOwnPassword(
        oldPassword: (string) ($_REQUEST['old_password'] ?? ''),
        newPassword: (string) ($_REQUEST['new_password'] ?? ''),
        keepCurrentSession: true,
    );
} catch (NotLoggedInException $e) {
    throw new AccessDeniedException('Вы не авторизованы');
} catch (InvalidPasswordException $e) {
    throw new AccessDeniedException('Неверный текущий пароль или новый пароль слишком короткий');
}
```

Внутри это:

```php
if (!$auth->reconfirmPassword($oldPassword)) {
    throw new InvalidPasswordException('Invalid current password');
}

$auth->changePassword($auth->id(), $newPassword);
```

`reconfirmPassword()` можно использовать и отдельно — перед удалением аккаунта,
сменой email и другими опасными действиями:

```php
if (!$auth->reconfirmPassword($password)) {
    throw new AccessDeniedException('Пароль не подтверждён');
}
```

### Админ/система сбрасывает пароль пользователю

```php
$auth->changePassword(
    userId: $userId,
    newPassword: 'new temporary password',
    keepCurrentSession: false,
);
```

Что происходит:

- пароль перехэшируется;
- увеличивается `users.force_logout`, старые сессии пользователя перестают быть валидными;
- удаляются все bearer/remember-токены пользователя;
- при `keepCurrentSession: true` текущая сессия (если это тот же пользователь) остаётся.

Для чужого пользователя `keepCurrentSession` не сохраняет его сессию — она будет
инвалидирована через `force_logout`.

Исключения: `InvalidPasswordException` (короткий новый пароль), `UnknownUserException`.

---

## 9. Удаление пользователя

```php
use Arris\Auth\Exception\UnknownUserException;

try {
    $auth->deleteUser($userId);
} catch (UnknownUserException $e) {
    echo 'Пользователь не найден';
}
```

Что делает `deleteUser()`:

- удаляет строку из `users`;
- удаляет все строки пользователя из `users_tokens` (bearer и remember);
- если удаляется текущий пользователь — очищает сессию, remember-cookie и регенерирует ID.

Пакет не каскадирует прикладные таблицы (`users_confirmations`, `users_resets`,
`users_throttling`, ваши собственные). Если они используются — удалите связанные
строки сами или настройте `ON DELETE CASCADE` во внешних ключах.

---

## 10. Bearer-токены

### Генерация

```php
use Arris\Auth\Exception\AccountDisabledException;
use Arris\Auth\Exception\EmailNotVerifiedException;
use Arris\Auth\Exception\UnknownUserException;

try {
    $token = $auth->issueToken(
        userId: $userId,
        ttl: 60 * 60 * 24 * 30, // 30 дней; null — взять token_ttl из конфига; 0 — бессрочно
        name: 'mobile app',
    );
} catch (UnknownUserException $e) {
    // пользователя нет
} catch (EmailNotVerifiedException|AccountDisabledException $e) {
    // политика requireVerified / rejectNonNormalStatus запрещает выдачу токена
}
```

`issueToken()` подчиняется тем же правилам, что и `login()`: при
`setRequireVerified(true)` токен неверифицированному пользователю не создаётся, а
пользователь со статусом не `NORMAL` получает `AccountDisabledException`.

Важно: `$token` возвращается **один раз**. В БД хранится только `sha256($token)`.
Отдайте его клиенту и не храните в открытом виде.

### Использование

Клиент:

```http
Authorization: Bearer <token>
```

Сервер:

```php
use Arris\Auth\Auth;
use Arris\Auth\AuthConfig;

$auth = new Auth($pdo, (new AuthConfig())->setMode(Auth::MODE_TOKEN));

if (!$auth->isLoggedIn()) {
    http_response_code(401);
    exit;
}

$user = $auth->userOrFail();

if (!$auth->hasRole(\Arris\Auth\Role::ADMIN)) {
    http_response_code(403);
    exit;
}
```

В режиме `auto` bearer проверяется первым, затем сессия. В режиме `token` сессия
не читается и не стартует.

### Отзыв и очистка

```php
$auth->revokeToken($token);      // отозвать один токен по plaintext-значению
$auth->revokeAllTokens($userId); // отозвать все bearer + remember токены пользователя
$auth->deleteExpiredTokens();    // удалить истёкшие токены (cron)
```

`logout()` отзывает текущий bearer-токен, если запрос пришёл с ним. Для API без
сессии используйте `revokeToken()`/`revokeAllTokens()`.

Bearer- и remember-токены хранят снимок `users.force_logout` на момент выдачи.
`logoutEverywhere()` и `changePassword()` увеличивают `force_logout`, поэтому
старые токены перестают работать даже при частичном сбое удаления строк.

Токены не привязаны к PHP-сессии и не требуют cookies. `login()` в режиме `token`
бросает `ConfigurationException` — для API выдавайте токен через `issueToken()`.

---

## 11. Полный пример middleware

```php
use Arris\Auth\Role;
use Arris\Auth\Exception\NotLoggedInException;

// 1. Только авторизованные
if (!App::$auth_driver->isLoggedIn()) {
    throw new AccessDeniedException('Вы не авторизованы');
}

// 2. Только с ролью
if (!App::$auth_driver->hasRole(Role::ADMIN)) {
    throw new AccessDeniedException('Недостаточно прав');
}

// 3. Текущий пользователь
try {
    $user = App::$auth_driver->userOrFail();
} catch (NotLoggedInException $e) {
    throw new AccessDeniedException('Вы не авторизованы');
}

echo $user->email;
echo $user->username;
```

---

## 12. Шпаргалка по исключениям

| Ситуация | Исключение |
|---|---|
| Некорректный/пустой email | `InvalidEmailException` |
| Неизвестный email или неверный пароль при `login()` | `InvalidCredentialsException` |
| Неверный старый пароль при `changeOwnPassword()` | `InvalidPasswordException` |
| Короткий пароль при регистрации/смене | `InvalidPasswordException` |
| Email не подтверждён | `EmailNotVerifiedException` |
| Аккаунт не в статусе `NORMAL` | `AccountDisabledException` |
| Пользователь не найден | `UnknownUserException` |
| Неверный/истёкший confirmation-токен | `InvalidConfirmationException` |
| Не авторизован там, где нужен пользователь | `NotLoggedInException` |
| `login()` в режиме `token` | `ConfigurationException` |
| Ошибки заголовков/cookie | `HeadersAlreadySentException` |
| Общая база | `AuthException` |

Чего в пакете пока нет: throttling (`TooManyRequestsException`), готового сценария
сброса пароля, callback `onBeforeSuccess` (`AttemptCancelledException`). Эти сценарии
приложение реализует поверх `register()`, `confirmUser()`, `verifyUser()`,
`changePassword()` и своих таблиц/лимитеров.

---

## 13. Частые ошибки

- **Ждать `null` от `login()`** — `login()` возвращает `Arris\Auth\DTO\User` или бросает исключение.
- **Считать `user() === null` ошибкой** — это штатное «не залогинен».
- **Использовать `InvalidPasswordException` для неверного пароля при логине** — теперь
  это `InvalidCredentialsException`.
- **Передавать длительность remember-me третьим аргументом** — третий аргумент `bool`.
  TTL задаётся через `AuthConfig::setRememberTtl()`.
- **Хранить plaintext bearer-токен** — храните только то, что вернули клиенту один раз;
  сервер уже хранит хэш.
- **Забыть `setRejectNonNormalStatus(false)`**, если нужно пускать `BANNED`/`LOCKED`
  пользователей — по умолчанию они не пускаются.
- **Забыть `setUserConfirmationRequired(false)`**, если регистрация должна сразу
  ставить `verified = 1`. При `true` пользователь остаётся неверифицированным до
  `confirmUser()` / `verifyUser()`.
- **Ожидать письмо без настроенного мэйлера** — по умолчанию используется
  `NullMailer`, который ничего не отправляет.
