# Arris.Auth

`karelwintersky/arris.auth` — standalone-аутентификация для PHP 8.2+:
cookie-сессии и bearer-токены в одном небольшом пакете. Без фреймворка, без DI-контейнера,
без обязательных зависимостей кроме PDO.

Пакет вырос из идей `karelwintersky/arris.delight-php-auth`, но устроен проще:
`Auth` не стартует сессию в конструкторе и не заставляет выбирать один режим на всё приложение.

## Установка

```bash
composer require karelwintersky/arris.auth
```

Для локальной разработки:

```json
{
    "repositories": [
        { "type": "path", "url": "../Arris.Auth" }
    ]
}
```

## Схема БД

Пакет использует те же таблицы `users`, `users_confirmations`, `users_remembered`,
`users_resets`, `users_throttling`, что и `arris.delight-php-auth`, плюс одну новую:

```sql
CREATE TABLE `users_tokens` (
    `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    `user` int(10) unsigned NOT NULL,
    `kind` varchar(16) NOT NULL DEFAULT 'api',     -- api | remember
    `selector` varchar(24) DEFAULT NULL,           -- только для remember
    `token` varchar(64) NOT NULL,                  -- sha256-хэш токена
    `name` varchar(100) DEFAULT NULL,
    `expires` int(10) unsigned NOT NULL DEFAULT 0, -- 0 = бессрочно
    `created` int(10) unsigned NOT NULL,
    `last_used` int(10) unsigned DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `selector` (`selector`),
    KEY `user_kind` (`user`, `kind`),
    KEY `expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

Полная схема — в `_database/schema.sql`.

### Где хранятся сессии

Строкового выбора `storage=db|redis` нет. Хранилище — это объект, реализующий
`SessionHandlerInterface`, и он передаётся в `Auth` опцией `session_handler`:

- `session_handler => null` — `Auth` не вызывает `session_set_save_handler()`;
  PHP использует глобальный `session.save_handler` (обычно `files`);
- `session_handler => new PdoSessionHandler($pdo, 'sessions')` — handler сам пишет
  сериализованные данные в таблицу `sessions` через переданный PDO;
- `session_handler => new RedisSessionHandler($redis)` — handler пишет в Redis
  через переданное подключение;
- `session_handler => $myHandler` — любой свой `SessionHandlerInterface`.

Это объект, не строка: `['session_handler' => 'redis']` не сработает.

Достаточно ли просто передать объект в опции? Да, но только пока сессия ещё не
стартовала: `Auth` лениво вызывает `session_set_save_handler($handler, true)`
непосредственно перед `session_start()`. Если сессия уже активна, опция игнорируется —
handler нужно было установить раньше вручную.

Это не изоляция на уровне объекта `Auth`: после старта handler действует глобально
в текущем PHP-запросе. Поэтому один handler на запрос; два `Auth` с разными
хранилищами в одном запросе не поддержать. Для полной изоляции нужен собственный
слой сессий.

`users_tokens` к сессиям отношения не имеет: там только bearer-токены и remember-me.
Не складывайте сессии в `users_tokens`; для DB-backed сессий используется отдельная
таблица `sessions`.

## Режимы

```php
use Arris\Auth\Auth;

$auth = new Auth($pdo);                       // auto: bearer -> session
$auth = new Auth($pdo, ['mode' => 'session']);
$auth = new Auth($pdo, ['mode' => 'token']);
```

- `auto` — если есть `Authorization: Bearer ...`, проверяется токен; иначе cookie-сессия.
  Это удобный режим по умолчанию для смешанного приложения.
- `session` — bearer-заголовок игнорируется, работает только cookie-сессия.
- `token` — сессия не читается и не стартует; только bearer.

### Сессия или токен: что применяется

| | Cookie-сессия | Bearer-токен |
|---|---|---|
| Как передаётся | cookie `arris_auth` | `Authorization: Bearer <token>` |
| Где хранится | backend PHP-сессий (files/Redis/DB/...) | `users_tokens`, только `sha256(token)` |
| Чем создать | `login()` / `loginWithUsername()` | `issueToken()` |
| Когда работает | `mode=session` или `mode=auto` | `mode=token` или `mode=auto` |
| Отзыв | `logout()`, `logoutEverywhere()` | `revokeToken()`, `revokeAllTokens()` |
| Remember me | да, `login(remember: true)` | нет |
| Нужны cookies | да | нет |
| Нужен session storage | да | нет |

В `auto` сначала проверяется Bearer, потом сессия. В `token` сессия не читается
и не стартует, а `login()` бросает `ConfigurationException` — для API используйте
`issueToken()`. Дополнительной «магии» для токенов нет: тот же `Auth`, та же таблица
`users_tokens`, только без cookie и PHP-сессии. Поэтому можно держать два экземпляра
`Auth` — один для веба, второй для API.

### Своё хранилище сессий

Пакет не вводит свой `SessionStorageInterface`: контракт — стандартный
`SessionHandlerInterface`. Handler передаётся в `Auth` и устанавливается до старта сессии:

```php
use Arris\Auth\Session\PdoSessionHandler;

$auth = new Auth($pdo, [
    'session_handler' => new PdoSessionHandler($pdo, 'sessions'),
]);
```

Для `PdoSessionHandler` нужна таблица `sessions(id, data, last_activity)` — она добавлена
в `_database/schema.sql` как опциональная. Handler также реализует
`SessionUpdateTimestampHandlerInterface`.

Redis:

```php
use Arris\Auth\Session\RedisSessionHandler;
use Redis;

$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

$auth = new Auth($pdo, [
    'session_handler' => new RedisSessionHandler($redis),
]);
```

`RedisSessionHandler` требует `ext-redis` и уже подключённый клиент. Вместо этих классов
можно передать любой свой `SessionHandlerInterface`; для тестов достаточно in-memory
реализации.

## Быстрый старт

```php
use Arris\Auth\Auth;
use Arris\Auth\Exception\AuthException;

$auth = new Auth($pdo, [
    'session_name' => 'app_session',
    'session_cookie' => [
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ],
]);

try {
    $id = $auth->register('user@example.com', 'correct horse battery staple', 'user');
    $user = $auth->login('user@example.com', 'correct horse battery staple', remember: true);
} catch (AuthException $e) {
    // InvalidCredentialsException, EmailNotVerifiedException, AccountDisabledException, ...
    throw $e;
}

if ($auth->check()) {
    echo $auth->id();
    echo $auth->user()->roleNames();
}

$auth->logout();
$auth->logoutEverywhere($auth->id());
```

### Cookie-сессия и `credentials: include`

Пакет не отправляет CORS-заголовки. Для браузерного SPA с другого origin нужно:

```php
header('Access-Control-Allow-Origin: https://app.example.com');
header('Access-Control-Allow-Credentials: true');
```

и на клиенте:

```js
fetch('https://api.example.com/me', { credentials: 'include' });
```

Для cross-site cookie нужно `SameSite=None` и `Secure`:

```php
new Auth($pdo, [
    'session_cookie' => [
        'secure' => true,
        'httponly' => true,
        'samesite' => 'None',
    ],
]);
```

### Bearer-токены

```php
$token = $auth->issueToken($userId, ttl: 60 * 60 * 24 * 30, name: 'mobile');
// отдайте $token клиенту один раз

// на API-запросе:
// Authorization: Bearer <token>
$user = (new Auth($pdo, ['mode' => 'token']))->user();

$auth->revokeToken($token);
$auth->revokeAllTokens($userId);
$auth->deleteExpiredTokens();
```

Токен — opaque, не JWT. В БД лежит только `sha256(token)`, поэтому утечка БД не даёт
готовых токенов. Плюс opaque-токенов — мгновенный отзыв и не нужен секрет для подписи.
Если нужен stateless JWT — это отдельный слой, пакет его не навязывает.

### Remember me

```php
$auth->login($email, $password, remember: true);
```

Создаётся `HttpOnly`-cookie `arris_remember` вида `selector~token`; в `users_tokens`
хранится selector и хэш токена. При следующем запросе без активной сессии пользователь
автоматически входит, а `$auth->isRemembered()` возвращает `true`.

## API

```php
$auth->register(string $email, string $password, ?string $username = null, bool $verified = true, int $rolesMask = 0): int;
$auth->verifyUser(int $userId): void;

$auth->login(string $email, string $password, bool $remember = false): User;
$auth->loginWithUsername(string $username, string $password, bool $remember = false): User;

$auth->user(): ?User;
$auth->check(): bool;
$auth->id(): ?int;
$auth->email(): ?string;
$auth->username(): ?string;
$auth->isRemembered(): bool;

$auth->hasRole(int $role): bool;
$auth->hasAnyRole(int ...$roles): bool;
$auth->hasAllRoles(int ...$roles): bool;

$auth->roles(int $userId): int;
$auth->roleNamesForUser(int $userId, ?array $map = null): array;
$auth->addRole(int $userId, int $role): int;
$auth->removeRole(int $userId, int $role): int;
$auth->setRole(int $userId, int $role): int;
$auth->setRoles(int $userId, int $rolesMask): int;

$auth->issueToken(int $userId, ?int $ttl = null, ?string $name = null): string;
$auth->revokeToken(string $token): bool;
$auth->revokeAllTokens(int $userId): int;
$auth->deleteExpiredTokens(): int;

$auth->logout(): void;
$auth->logoutEverywhere(int $userId): void;
$auth->changePassword(int $userId, string $newPassword, bool $keepCurrentSession = true): void;

$auth->mode(): string;
$auth->pdo(): PDO;
```

`User` — readonly-объект: `id`, `email`, `username`, `status`, `verified`, `resettable`,
`rolesMask`, `registered`, `lastLogin`, `forceLogout`, `properties`, плюс `isNormal()`,
`isBanned()`, `hasRole()`, `roleNames()`, `toArray()`.

Значения ролей совместимы с `arris.delight-php-auth`: `Arris\Auth\Role` — не final,
его можно расширить в приложении. `Arris\Auth\Status` — backed enum; для записи в БД
используется `Status::NORMAL->value`.

```php
final class AppRole extends \Arris\Auth\Role
{
    public const BANNED = 4194304;
    public const VIEWER = \Arris\Auth\Role::CONSUMER;
    public const GAME_MASTER = \Arris\Auth\Role::COORDINATOR;
    public const PLAYER = \Arris\Auth\Role::SUBSCRIBER;
    public const OBSERVER = \Arris\Auth\Role::MANAGER;

    public static function map(): array
    {
        return [
            'BANNED' => self::BANNED,
            'VIEWER' => self::VIEWER,
            'GAME_MASTER' => self::GAME_MASTER,
            'PLAYER' => self::PLAYER,
            'OBSERVER' => self::OBSERVER,
        ];
    }
}
```

`map()` возвращает `name => bit`; `AppRole::id('GAME_MASTER')`, `AppRole::names($mask)`
и `$user->roleNames(AppRole::map())` работают без switch и reflection. Если несколько
имён ссылаются на один бит, `getMap()` схлопнет их, а `names()` вернёт все имена.

## Опции конструктора

| Опция | По умолчанию | Смысл |
|---|---|---|
| `mode` | `auto` | `auto`, `session`, `token` |
| `table_prefix` | `''` | префикс таблиц |
| `db_schema` | `null` | schema/database qualifier |
| `session_name` | `arris_auth` | имя PHP-сессии |
| `session_cookie` | `path=/`, `secure=auto`, `httponly=true`, `samesite=Lax` | параметры cookie сессии |
| `session_handler` | `null` | `SessionHandlerInterface`; `null` — настройки PHP |
| `remember_cookie_name` | `arris_remember` | имя remember-cookie |
| `remember_ttl` | 30 дней | срок жизни remember-токена |
| `token_ttl` | 30 дней | срок жизни bearer-токена; `0` — бессрочно |
| `require_verified` | `true` | требовать `verified=1` при входе |
| `reject_non_normal_status` | `true` | не пускать пользователей со статусом не `NORMAL` |
| `min_password_length` | `8` | минимальная длина пароля при регистрации/смене |
| `update_last_login` | `true` | обновлять `users.last_login` |
| `touch_token_interval` | `60` | как часто обновлять `last_used` токена |

## Что пока не реализовано

Пакет — рабочий MVP. Таблицы `users_confirmations`, `users_resets`, `users_throttling`
оставлены в схеме для совместимости, но подтверждение email, сброс пароля и throttling
пока не реализованы. Их можно добавить отдельными методами, не меняя ядро.

## Тесты

```bash
composer install
vendor/bin/phpunit
```

Текущее состояние: 35 тестов, 94 assertions.
