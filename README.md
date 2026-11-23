# Arris.Auth

`karelwintersky/arris.auth` — standalone-аутентификация для PHP 8.2–8.4:
cookie-сессии и bearer-токены в одном небольшом пакете. Без фреймворка, без DI-контейнера,
с обязательными зависимостями только `PDO` и `psr/log`.

Пакет вырос из идей `karelwintersky/arris.delight-php-auth`, но устроен проще:
`Auth` по умолчанию, как и старая библиотека, разрешает текущую аутентификацию в
конструкторе (session cookie, remember-me cookie, bearer), но не создаёт анонимную
сессию и не заставляет выбирать один режим на всё приложение. Eager-инициализацию
можно отключить через `AuthConfig::setAutoInitialize(false)`.

Пошаговые рецепты (регистрация, активация, роли, смена пароля, удаление, токены,
middleware) — в [HOWTO.md](HOWTO.md).

## Установка

```bash
composer require karelwintersky/arris.auth
```

## Схема БД

`Auth` работает с таблицами `users`, `users_tokens`, `users_confirmations`,
`users_resets` и `users_throttling`. `users_remembered` оставлена в схеме для
совместимости с `arris.delight-php-auth`, но текущий код её не использует.

```sql
CREATE TABLE `users_tokens` (
    `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    `user_id` int(10) unsigned NOT NULL,
    `force_logout` mediumint(7) unsigned NOT NULL DEFAULT 0, -- снимок users.force_logout
    `kind` varchar(16) NOT NULL DEFAULT 'api',     -- api | remember
    `selector` varchar(24) DEFAULT NULL,           -- только для remember
    `token` varchar(64) NOT NULL,                  -- sha256-хэш токена
    `name` varchar(100) DEFAULT NULL,
    `expires` int(10) unsigned NOT NULL DEFAULT 0, -- 0 = бессрочно
    `created` int(10) unsigned NOT NULL,
    `last_used` int(10) unsigned DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `selector` (`selector`),
    KEY `token` (`token`),
    KEY `user_kind` (`user_id`, `kind`),
    KEY `expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

Для `users` также нужен индекс `KEY username (username)` — по нему работает
`loginWithUsername()`. Полная схема — в `_database/schema_mysql.sql`.

### Миграция с Delight PHP Auth

Наша схема использует `user_id` в `users_remembered` и `users_resets`; в Delight
PHP Auth там колонка `user`. `users_confirmations` уже использует `user_id` и не
переименовывается.

Полный сценарий — в `_database/migrations/from_delight_auth.sql`. Ключевые команды:

```sql
-- Delight -> Arris.Auth
ALTER TABLE `users_remembered`
    CHANGE COLUMN `user` `user_id` int(10) unsigned NOT NULL;

ALTER TABLE `users_remembered`
    DROP INDEX `user`,
    ADD KEY `user_id` (`user_id`);

ALTER TABLE `users_resets`
    CHANGE COLUMN `user` `user_id` int(10) unsigned NOT NULL;

ALTER TABLE `users_resets`
    DROP INDEX `user_expires`,
    ADD KEY `user_expires` (`user_id`, `expires`);

ALTER TABLE `users_confirmations`
    ADD KEY `token` (`token`);

ALTER TABLE `users_resets`
    ADD KEY `token` (`token`);

-- Остальное: properties, username index, InnoDB, users_tokens, sessions
-- выполняется из _database/migrations/from_delight_auth.sql
```

Полный запуск:

```bash
mysql -u app_user -p app_database < _database/migrations/from_delight_auth.sql
```

Что делает миграция:

- добавляет `users.properties` и `KEY username (username)`;
- переименовывает `user` → `user_id` в `users_remembered` и `users_resets`;
- добавляет `KEY token (token)` в `users_confirmations` и `users_resets`;
- переводит таблицы `users*` в InnoDB;
- создаёт `users_tokens` (с `force_logout` и индексами) и опциональную `sessions`.

`users_tokens` обязательна для bearer и remember-me. Без неё работает только
cookie-сессия на `users`. Если полная миграция не нужна, минимально достаточно
создать `users_tokens`; переименование `user` → `user_id` в legacy-таблицах нужно
только для совпадения схемы (код эти таблицы не использует). Для транзакционных
гарантий `users` должен быть InnoDB.

Старые remember-cookie из `users_remembered` в `users_tokens` не переносятся:
пользователи после миграции один раз войдут заново. Старые строки `users_tokens`
получат `force_logout = 0`; если у пользователя `users.force_logout > 0`, его
старые токены будут отклонены. Это безопасный fail-closed вариант. Старые
pending-подтверждения в `users_confirmations` лучше перевыпустить через
`resendConfirmation()`, а старые reset-коды — через `requestPasswordReset()`.

### Обратная миграция на Delight PHP Auth

Обратная миграция **удаляет** `users_tokens` и `sessions`, а также `users.properties`.
Сначала сделайте резервную копию. Если `users.properties` использовалась приложением,
не удаляйте колонку.

```sql
-- 1. Удалить новые таблицы (данные bearer/remember и сессий будут потеряны).
DROP TABLE IF EXISTS `sessions`;
DROP TABLE IF EXISTS `users_tokens`;

-- 2. Вернуть имена колонок и индексов Delight.
ALTER TABLE `users_remembered` DROP INDEX `user_id`;
ALTER TABLE `users_remembered`
    CHANGE COLUMN `user_id` `user` int(10) unsigned NOT NULL;
ALTER TABLE `users_remembered`
    ADD KEY `user` (`user`);

ALTER TABLE `users_resets` DROP INDEX `user_expires`;
ALTER TABLE `users_resets`
    CHANGE COLUMN `user_id` `user` int(10) unsigned NOT NULL;
ALTER TABLE `users_resets`
    ADD KEY `user_expires` (`user`, `expires`);

ALTER TABLE `users_confirmations` DROP INDEX `token`;

ALTER TABLE `users_resets` DROP INDEX `token`;

-- 3. Убрать поля/индексы, которых нет в Delight.
ALTER TABLE `users` DROP INDEX `username`;
ALTER TABLE `users` DROP COLUMN `properties`;

-- 4. Вернуть MyISAM, если это требуется старой схеме.
ALTER TABLE `users` ENGINE=MyISAM;
ALTER TABLE `users_confirmations` ENGINE=MyISAM;
ALTER TABLE `users_remembered` ENGINE=MyISAM;
ALTER TABLE `users_resets` ENGINE=MyISAM;
ALTER TABLE `users_throttling` ENGINE=MyISAM;
```

После обратной миграции старые remember-cookie из `users_remembered` снова
начнут использоваться, если они не истекли. Пользователи, вошедшие через новый
`users_tokens`, потеряют эти токены и должны войти заново.

### Где хранятся сессии

Строкового выбора `storage=db|redis` нет. Хранилище — это объект, реализующий
`SessionHandlerInterface`, и он передаётся в `AuthConfig` через `setSessionHandler()`:

- `setSessionHandler(null)` — `Auth` не вызывает `session_set_save_handler()`;
  PHP использует глобальный `session.save_handler` (обычно `files`);
- `setSessionHandler(new PDOSessionHandler($pdo, 'sessions'))` — handler сам пишет
  сериализованные данные в таблицу `sessions` через переданный PDO;
- `setSessionHandler(new RedisSessionHandler($redis))` — handler пишет в Redis
  через переданное подключение;
- `setSessionHandler($myHandler)` — любой свой `SessionHandlerInterface`.

Это объект, не строка: `setSessionHandler('redis')` не сработает.

Достаточно ли просто передать объект в конфиг? Да, но только пока сессия ещё не
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
use Arris\Auth\AuthConfig;

$auth = new Auth($pdo); // AuthConfig defaults: auto: bearer -> session

$auth = new Auth($pdo, (new AuthConfig())->setMode(Auth::MODE_SESSION));
$auth = new Auth($pdo, (new AuthConfig())->setMode(Auth::MODE_TOKEN));
```

Если второй аргумент конструктора не передан или равен `null`, `Auth` сам создаёт
`AuthConfig` с дефолтными значениями. Переданный конфиг клонируется, поэтому его
последующие изменения не влияют на уже созданный `Auth`.

- `auto` — если есть `Authorization: Bearer ...`, проверяется токен; иначе cookie-сессия.
  Если Bearer-заголовок присутствует, но токен невалиден, сессия **не** используется:
  запрос считается неаутентифицированным. Это сделано намеренно, чтобы не смешивать
  два источника личности. Это удобный режим по умолчанию для смешанного приложения.
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

### Политика доступа

`setRequireVerified(true)` и `setRejectNonNormalStatus(true)` применяются не только
к `login()`, но и к уже существующим сессиям, remember-cookie и bearer-токенам.
Если пользователю сняли `verified` или изменили `status`, доступ пропадает на
следующем запросе.

Bearer- и remember-токены хранят снимок `users.force_logout` на момент выдачи.
Поэтому `logoutEverywhere()` и `changePassword()` инвалидируют их даже в том случае,
если удаление строки токена не удалось выполнить атомарно. `issueToken()` отказывает
неверифицированным и отключённым пользователям.

Remember-токен ротируется при каждом успешном использовании: старый selector
удаляется, выдаётся новый с тем же сроком действия. Неверный токен очищает только
cookie клиента и не удаляет чужую валидную строку по selector.

### HTTPS и reverse proxy

HTTPS требуется по умолчанию. `Auth` бросает `ConfigurationException`, если запрос
не HTTPS. Для локальной разработки/CLI это надо разрешить явно:

```php
$config->setAllowInsecureHttp(true);
```

`isHttps()` доверяет только `$_SERVER['HTTPS']` и порту 443. Заголовки
`X-Forwarded-Proto` / `X-Forwarded-SSL` **не используются** — их может подделать
клиент, если приложение доступно напрямую.

### Nginx как reverse proxy

Если nginx слушает `:443`, терминирует TLS и проксирует в PHP-FPM:

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    root /var/www/app/public;
    index index.php;

    location ~ \.php$ {
        include fastcgi_params;

        # PHP должен видеть HTTPS и реальный IP клиента
        fastcgi_param HTTPS on;
        fastcgi_param REMOTE_ADDR $remote_addr;

        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }
}

server {
    listen 80;
    server_name example.com;
    return 301 https://$host$request_uri;
}
```

`fastcgi_params` обычно уже содержит `REMOTE_ADDR $remote_addr`. `X-Real-IP` и
`real_ip_header` в этой схеме не нужны: перед nginx нет другого прокси.

Если позже появится Cloudflare/LB, то только тогда:

```nginx
set_real_ip_from 10.0.0.0/8;    # адреса доверенного LB
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

и потребуется отдельный trusted-proxy слой.

`setSessionCookie(['secure' => 'auto'])` включает `Secure` для cookie. В production
лучше задать `secure => true` явно. HSTS — на уровне сервера/приложения.
`SameSite=None` требует `secure=true`.

### Recommended production configuration

- HTTPS обязателен; `setAllowInsecureHttp(true)` — только для local/dev/CLI.
- nginx: `fastcgi_param HTTPS on;` и `REMOTE_ADDR $remote_addr`.
- `setMailer(new YourSmtpOrApiMailer())` вместо `NativeMailer`/`mail()`.
- `setEMailValidator()` и `setPasswordValidator()` — политика приложения.
- `deleteExpiredThrottling()` по cron; таблица `users_throttling` растёт.
- idle/absolute session timeout — ответственность приложения.
- `ext-session` должен быть доступен в PHP.
- `psr/log` logger можно подключить через `setLogger()`.

### Сессия или bearer: что выбрать

Для браузерной админки, которую рендерит тот же бэкенд, bearer не нужен:

1. `POST /login` — бэкенд проверяет пароль, создаёт сессию и ставит HttpOnly cookie.
2. `GET /admin/` — middleware проверяет сессию и отдаёт HTML.
3. JS делает `fetch('/api/getProjects', { credentials: 'same-origin' })`; браузер сам
   прикладывает cookie, API-middleware проверяет ту же сессию.
4. `POST /logout` — бэкенд уничтожает сессию.

Для изменяющих запросов (`POST/PUT/DELETE`) нужна CSRF-защита. Bearer для same-origin
браузерной админки не даёт выигрыша в безопасности: токен в JS уязвим к XSS, а
HttpOnly session cookie — нет.

Bearer нужен клиентам без cookie: мобильное приложение, CLI, внешняя интеграция,
SPA на другом origin. Сценарий:

1. `POST /api/login` — бэкенд проверяет пароль и выдаёт непрозрачный токен.
2. Клиент хранит токен и шлёт `Authorization: Bearer <token>`.
3. Сервер хэширует токен, ищет строку в `users_tokens`, проверяет срок и статус пользователя.
4. `POST /api/logout` или `revokeToken()` удаляет строку — доступ сразу пропадает.

Логин/логаут «на фронте» — это UI. Пароль всё равно проверяет бэкенд; он же создаёт
сессию или выдаёт токен и отзывает его при логауте. Токен возвращается клиенту один раз,
в БД хранится `sha256(token)`. Обязательны HTTPS, короткий TTL и отзыв.

### Своё хранилище сессий

Пакет не вводит свой `SessionStorageInterface`: контракт — стандартный
`SessionHandlerInterface`. Handler передаётся в `Auth` и устанавливается до старта сессии:

```php
use Arris\Auth\AuthConfig;
use Arris\Auth\Session\PDOSessionHandler;

$config = (new AuthConfig())
    ->setSessionHandler(new PDOSessionHandler($pdo, 'sessions'));

$auth = new Auth($pdo, $config);
```

Для `PDOSessionHandler` нужна таблица `sessions(id, data, last_activity)` — она добавлена
в `_database/schema_mysql.sql` как опциональная. Handler также реализует
`SessionUpdateTimestampHandlerInterface`.

Redis:

```php
use Arris\Auth\AuthConfig;
use Arris\Auth\Session\RedisSessionHandler;
use Redis;

$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$redis->auth($password); // если требуется
$redis->select(3);       // Redis DB №3

$config = (new AuthConfig())
    ->setSessionHandler(new RedisSessionHandler($redis));

$auth = new Auth($pdo, $config);
```

Номер Redis DB задаётся не в `RedisSessionHandler`, а на клиенте phpredis: handler
получает уже подключённый `\Redis` и не вызывает `connect()`/`select()`. После
`select(3)` все команды этого соединения, включая `get/setex/del/exists/expire`
в handler, работают в БД №3; ключи сессий имеют вид `arris:session:<id>`.

`select()` переключает БД всего соединения. Если тот же клиент используется для
других данных, создайте отдельное соединение для сессий. При `pconnect()` вызывайте
`select()` при каждом запросе. В Redis Cluster команда `SELECT` недоступна — там
изоляция делается префиксом ключей или отдельным кластером.

`RedisSessionHandler` требует `ext-redis` и уже подключённый клиент. Вместо этих классов
можно передать любой свой `SessionHandlerInterface`; для тестов достаточно in-memory
реализации.

## Быстрый старт

```php
use Arris\Auth\Auth;
use Arris\Auth\AuthConfig;
use Arris\Auth\Exception\AuthException;

$config = (new AuthConfig())
    ->setSessionName('app_session')
    ->setSessionCookie([
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

$auth = new Auth($pdo, $config);

try {
    $registered = $auth->register('user@example.com', 'correct horse battery staple', 'user');
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

### Подтверждение email

Подтверждение включается в конфиге:

```php
use Arris\Auth\DTO\UserConfirmationOptions;
use Arris\Auth\Mailer\NativeMailer;

$config = (new AuthConfig())
    ->setUserConfirmationOptions(new UserConfirmationOptions(required: true, ttl: 3600))
    ->setMailer(new NativeMailer([
        'from' => 'noreply@example.com',
        'activation_subject' => 'Confirm your email',
        'activation_body' => 'Activation key: {activation_key}',
    ]));

$auth = new Auth($pdo, $config);

$user = $auth->register('user@example.com', 'correct horse battery staple');
// $user->isVerified() === false

// приложение получает activation key из письма и вызывает:
$user = $auth->confirmUser($activationKey);
// $user->isVerified() === true
```

- `new UserConfirmationOptions(required: false)` — регистрация сразу ставит `verified = 1`.
- `new UserConfirmationOptions(required: true)` — регистрация создаёт `verified = 0` и
  запись в `users_confirmations`, затем вызывает `MailerInterface::sendActivation()`.
- `NativeMailer` — мэйлер по умолчанию. `NullMailer` можно задать явно для
  тестов/dev: `->setMailer(new NullMailer())`.
- Ошибка отправки письма не откатывает созданного пользователя.
- `register(..., verified: true)` — админский обход confirmation.
- `register(..., verified: false)` + `verifyUser($userId)` — двухшаговый админский путь.
- `resendConfirmation($email)` возвращает `ConfirmationState` с причиной
  (`sent`, `unknown_user`, `already_verified`, `not_required`, `mail_failed`,
  `throttled`).
- `deleteExpiredConfirmations()` удаляет истёкшие записи.

`UserConfirmationOptions` — immutable DTO: меняйте через `withRequired()` /
`withTtl()` или создавайте новый объект.

`required = true` означает, что неверифицированный пользователь не может войти,
даже если `requireVerified` был выключен.

### Сброс пароля

```php
use Arris\Auth\DTO\UserResetOptions;

$config = (new AuthConfig())
    ->setUserResetOptions(new UserResetOptions(enabled: true, ttl: 3600, allowedAny: false))
    ->setMailer(new \Arris\Auth\Mailer\NativeMailer());

$auth = new Auth($pdo, $config);

$state = $auth->requestPasswordReset('user@example.com');
// ResetState: sent | unknown_user | not_enabled | not_allowed | mail_failed | throttled

$user = $auth->resetPassword($resetKey, 'new correct horse battery staple');
$auth->deleteExpiredResets();
```

- `enabled` — разрешён ли сброс пароля;
- `ttl` — время жизни reset-кода;
- `allowedAny` — принимать любой неистёкший код, а не только последний.
  При `false` новый запрос инвалидирует старые коды; при `true` старые коды
  остаются рабочими до истечения TTL;
- `requestPasswordReset()` уважает `users.resettable`; при `resettable = 0`
  возвращает `not_allowed`;
- `resetPassword()` меняет пароль, увеличивает `force_logout`, удаляет все
  reset-коды и все bearer/remember-токены пользователя;
- старые reset-коды после успешного сброса недействительны всегда;
- ошибка отправки письма не откатывает созданный reset-код, но возвращает
  `mail_failed`.

`UserResetOptions` — immutable DTO: меняйте через `withEnabled()` / `withTtl()` /
`withAllowedAny()`.

### Логирование

```php
$config->setLogger($logger, debug: false);
```

- по умолчанию — `Psr\Log\NullLogger`;
- `debug: true` разрешает логирование raw-токенов;
- без debug токены не пишутся;
- пароли не логируются никогда.

### Throttling

По умолчанию включён:

```php
use Arris\Auth\DTO\ThrottleRule;
use Arris\Auth\DTO\ThrottlingOptions;

$config->setThrottlingOptions(new ThrottlingOptions(
    enabled: true,
    login: new ThrottleRule(5, 900),
    registration: new ThrottleRule(3, 3600),
    reset: new ThrottleRule(3, 3600),
    confirmation: new ThrottleRule(3, 3600),
));
```

Лимиты:

| Действие | По умолчанию |
|---|---|
| login | 5 / 15 минут |
| registration | 3 / час |
| password reset | 3 / час |
| confirmation resend | 3 / час |

При превышении login/registration бросается `TooManyRequestsException`, reset и
confirmation возвращают `throttled` с `retryAfter`. Для тестов/dev можно явно
отключить: `new ThrottlingOptions(enabled: false)`.

`users_throttling` растёт: один bucket на действие/email/IP. Очистка — на стороне
приложения:

```php
$auth->deleteExpiredThrottling();
```

Например, cron раз в 10–15 минут. Случайная очистка внутри библиотеки не
предусмотрена — она не гарантирует своевременное удаление при низком трафике.

### Валидаторы email и пароля

Пакет проверяет только непустые значения. Формат email и политику пароля задаёт
приложение:

```php
$config
    ->setEMailValidator(static fn (string $email): bool =>
        filter_var($email, FILTER_VALIDATE_EMAIL) !== false
    )
    ->setPasswordValidator(static fn (string $password): bool =>
        strlen($password) >= 8
    );
```

Если валидатор не задан, принимается любая непустая строка.

### Проверка авторизации в middleware

`check()` и его старый алиас `isLoggedIn()` возвращают `bool` и полностью разрешают
текущее состояние: bearer-токен, PHP-сессию или remember-me cookie. `user()` при этом
может вернуть `null` — это нормальный признак «не залогинен».

```php
if (!App::$auth_driver->isLoggedIn()) {
    throw new AccessDeniedException('Вы не авторизованы');
}

// либо сразу получить пользователя или исключение NotLoggedInException:
$user = App::$auth_driver->userOrFail();
```

`getUserId()` — алиас `id()`, `getUser()` — алиас `user()`. При включённом
`auto_initialize` (по умолчанию) конструктор уже обработал cookie/токен, поэтому
`isLoggedIn()` работает сразу после `new Auth(...)`. Если сессии и cookie нет,
конструктор ничего не создаёт; новая сессия появится только при `login()`.

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
$auth = new Auth($pdo, (new AuthConfig())->setSessionCookie([
    'secure' => true,
    'httponly' => true,
    'samesite' => 'None',
]));
```

### Bearer-токены

```php
$token = $auth->issueToken($userId, ttl: 60 * 60 * 24 * 30, name: 'mobile');
// отдайте $token клиенту один раз

// на API-запросе:
// Authorization: Bearer <token>
$user = (new Auth($pdo, (new AuthConfig())->setMode(Auth::MODE_TOKEN)))->user();

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

## Демо

В `examples/` есть минимальное приложение на SQLite: вход/регистрация, remember-me,
защищённая страница, bearer-токены и JSON API. Один front controller, без фреймворка.
Схема БД берётся из `_database/schema_sqlite.sql`.

```bash
composer install
php -S localhost:8080 -t examples/public examples/public/router.php
```

Откройте <http://localhost:8080/>. Тестовые аккаунты и curl-примеры — в
[examples/README.md](examples/README.md).

## API

```php
$auth->register(string $email, string $password, ?string $username = null, ?bool $verified = null, int $rolesMask = 0): User;
$auth->verifyUser(int $userId): void;
$auth->confirmUser(string $activationKey): User;
$auth->resendConfirmation(string $email): ConfirmationState;
$auth->deleteExpiredConfirmations(): int;

$auth->requestPasswordReset(string $email): ResetState;
$auth->resetPassword(string $resetKey, string $newPassword): User;
$auth->deleteExpiredResets(): int;
$auth->deleteExpiredThrottling(): int;

$auth->login(string $email, string $password, bool $remember = false): User;
$auth->loginWithUsername(string $username, string $password, bool $remember = false): User;

$auth->initialize(): void;
$auth->user(): ?User;
$auth->userOrFail(): User;
$auth->check(): bool;
$auth->isLoggedIn(): bool;
$auth->id(): ?int;
$auth->getUserId(): ?int;
$auth->getUser(): ?User;
$auth->email(): ?string;
$auth->getEmail(): ?string;
$auth->username(): ?string;
$auth->getUsername(): ?string;
$auth->getRoles(): array;
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
$auth->reconfirmPassword(string $password): bool;
$auth->changeOwnPassword(string $oldPassword, string $newPassword, bool $keepCurrentSession = true): void;
$auth->changePassword(int $userId, string $newPassword, bool $keepCurrentSession = true): void;
$auth->deleteUser(int $userId): void;

$auth->mode(): string;
$auth->pdo(): PDO;
```

`Arris\Auth\DTO\User` — readonly-объект: `id`, `email`, `username`, `status`, `verified`, `resettable`,
`rolesMask`, `registered`, `lastLogin`, `forceLogout`, `properties`, плюс `isNormal()`,
`isBanned()`, `hasRole()`, `roleNames()`, `toArray()`.

`Arris\Auth\DTO\ConfirmationState` — результат `resendConfirmation()`: `sent`, `reason`
(`sent`, `unknown_user`, `already_verified`, `not_required`, `mail_failed`) и `isSent()`.

`Arris\Auth\DTO\ResetState` — результат `requestPasswordReset()`: `sent`, `reason`
(`sent`, `unknown_user`, `not_enabled`, `not_allowed`, `mail_failed`) и `isSent()`.

Значения ролей совместимы с `arris.delight-php-auth`: `Arris\Auth\Role` — не final,
его можно расширить в приложении. `Arris\Auth\DTO\Status` — backed enum; для записи в БД
используется `Status::NORMAL->value`.

# РОЛИ

## Расширение базовых ролей

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

`AppRole` — это синтаксический сахар: `AppRole::GAME_MASTER` остаётся обычным `int`,
поэтому `hasRole(AppRole::GAME_MASTER)` работает без дополнительной настройки.
Чтобы `Auth::getRoles()` и `Auth::roleNamesForUser()` возвращали прикладные имена,
передайте карту в конфиг:

```php
$config = (new AuthConfig())->setRolesMap(AppRole::map());
$auth = new Auth($pdo, $config);

$auth->getRoles();                 // [64 => 'GAME_MASTER', ...]
$auth->roleNamesForUser($userId);  // ['GAME_MASTER', ...]
```

`setRolesMap(null)` возвращает базовую `Role::map()`. `User::roleNames()` без
аргумента всегда использует базовую карту; для прикладных имён передайте
`$user->roleNames(AppRole::map())` или используйте `$auth->roleNamesForUser()`.

Почему `AppRole` — класс с константами, а не enum и не final-база: см. `AGENTS.md`.

## Опции AuthConfig

| Метод | По умолчанию | Смысл |
|---|---|---|
| `setMode()` | `Auth::MODE_AUTO` | `auto`, `session`, `token` |
| `setTablePrefix()` | `''` | префикс таблиц |
| `setDbSchema()` | `null` | schema/database qualifier |
| `setSessionName()` | `arris_auth` | имя PHP-сессии |
| `setSessionCookie()` | `path=/`, `secure=auto`, `httponly=true`, `samesite=Lax` | параметры cookie сессии; неизвестные ключи и неверные типы отклоняются |
| `setSessionHandler()` | `null` | `SessionHandlerInterface`; `null` — настройки PHP |
| `setRememberCookieName()` | `arris_remember` | имя remember-cookie |
| `setRememberTtl()` | 30 дней | срок жизни remember-токена |
| `setTokenTtl()` | 30 дней | срок жизни bearer-токена; `0` — бессрочно; отрицательный TTL отклоняется |
| `setRequireVerified()` | `true` | требовать `verified=1` для сессии, bearer, remember и выдачи токенов |
| `setRejectNonNormalStatus()` | `true` | не пускать пользователей со статусом не `NORMAL` |
| `setUpdateLastLogin()` | `true` | обновлять `users.last_login` |
| `setTouchTokenInterval()` | `60` | как часто обновлять `last_used` токена; `0` — отключить |
| `setAutoInitialize()` | `true` | разрешать текущую аутентификацию в конструкторе |
| `setAllowInsecureHttp()` | `false` | явно разрешить работу без HTTPS |
| `setRolesMap()` | `null` | карта `name => bit` для отображения ролей; `null` — базовая `Role::map()` |
| `setUserConfirmationOptions()` | `new UserConfirmationOptions()` | DTO `required`, `ttl` |
| `setUserResetOptions()` | `new UserResetOptions()` | DTO `enabled`, `ttl`, `allowedAny` |
| `setThrottlingOptions()` | `enabled=true`, defaults 5/15м, 3/ч | DTO с `ThrottleRule` для login/registration/reset/confirmation |
| `setMailer()` | `NativeMailer` | `MailerInterface`; `null` возвращает `NativeMailer` |
| `setLogger()` | `NullLogger` | PSR-3 logger; второй аргумент `debug` разрешает raw-токены |

`setOption(string $name, mixed $value)` — резервный способ задать любую опцию по
snake_case-имени из старого API. Внутри он вызывает те же типизированные сеттеры;
неизвестный ключ или неверное значение дают `ConfigurationException`, а неверный
PHP-тип значения — `TypeError`. Карта ролей задаётся ключом `roles_map`,
confirmation — `user_confirmation_required` / `user_confirmation_ttl` (старый
`confirmation_ttl` поддерживается как алиас), reset — `user_reset_enabled` /
`user_reset_ttl` / `user_reset_allowed_any`, throttling — `throttling_options`,
HTTPS — `allow_insecure_http`, мэйлер — `mailer`.

Опции confirmation/reset/throttling — immutable DTO:
`UserConfirmationOptions`, `UserResetOptions`, `ThrottlingOptions` + `ThrottleRule`.
Геттеры: `getUserConfirmationOptions()`, `getUserResetOptions()`,
`getThrottlingOptions()`; поля читаются через `->required`, `->ttl`, `->enabled`,
`->allowedAny`.

## Тесты

```bash
composer install
vendor/bin/phpunit
```

Текущее состояние: 133 теста, 373 assertions. Четыре MySQL-теста пропускаются, если
не задан `ARRIS_AUTH_MYSQL_DSN`; для них нужен отдельный тестовый MySQL-инстанс.

## Что пока не реализовано

Пакет остаётся MVP в части account lifecycle:

- нет lockout после серии неудачных входов (есть только token-bucket throttling);
- нет отдельного аудита/экспорта security-событий;
- кастомные `emailValidator` / `passwordValidator` вызываются, но их качество —
  ответственность приложения.

Подтверждение email реализовано через `users_confirmations`, сброс пароля — через
`users_resets`, throttling — через `users_throttling`. По умолчанию используется
`NativeMailer`; `NullMailer` можно задать явно для тестов/dev.
