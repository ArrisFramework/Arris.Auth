# Arris.Auth demo

Минимальное приложение без фреймворка: один front controller, SQLite, cookie-сессии,
remember-me и bearer-токены. Нужны PHP 8.2+, `pdo_sqlite` и установленный `vendor/`.

## Запуск

Из корня пакета:

```bash
composer install
php -S localhost:8080 -t examples/public examples/public/router.php
```

Откройте <http://localhost:8080/>.

Первый запрос сам создаёт `examples/data/demo.sqlite` и тестовых пользователей.
Чтобы сбросить демо, удалите этот файл.

## Тестовые аккаунты

| Email | Пароль | Роли |
|---|---|---|
| `admin@example.com` | `admin-password` | `ADMIN` |
| `user@example.com` | `user-password` | `SUBSCRIBER` |

## Страницы

- `GET /` — состояние текущей аутентификации и карта маршрутов.
- `GET|POST /login` — вход, опционально с remember-me.
- `GET|POST /register` — регистрация и автоматический вход.
- `POST /logout` — выход.
- `GET /admin` — защищённая страница, только для `ADMIN`.
- `POST /token` — выдать bearer-токен текущему пользователю.

## API

`/api/login` проверяет email и пароль и выдаёт opaque bearer-токен. В БД хранится
только `sha256(token)`, поэтому токен показывается один раз.

```bash
curl -s -X POST http://localhost:8080/api/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"admin-password"}'
```

Ответ:

```json
{
    "token": "<token>",
    "token_type": "Bearer",
    "expires_in": 604800,
    "user": { "id": 1, "email": "admin@example.com", "roles_mask": 1 },
    "roles": ["ADMIN"]
}
```

Защищённые запросы:

```bash
TOKEN='<token>'

curl -s http://localhost:8080/api/me \
  -H "Authorization: Bearer $TOKEN"

curl -s http://localhost:8080/api/projects \
  -H "Authorization: Bearer $TOKEN"

curl -s -X POST http://localhost:8080/api/logout \
  -H "Authorization: Bearer $TOKEN"
```

Сессионный cookie тоже подходит для `/api/me` и `/api/projects`: браузер прикладывает
`arris_demo_session` автоматически. Для запросов с другого origin нужны CORS-заголовки
и `credentials: include`, но демо их не настраивает.

## Что показывает демо

- `AuthConfig` с `PDOSessionHandler` — сессии лежат в таблице `sessions` в SQLite.
- `login()` с `remember: true` и автоматический вход по remember-cookie.
- `issueToken()` и проверка bearer-токена в том же экземпляре `Auth` (режим `auto`).
- `logout()` отзывает текущий bearer-токен и очищает сессию.
- Роли: `/admin` проверяет `hasRole(Role::ADMIN)`.
- CSRF: формы используют double-submit cookie и токен `_csrf`.

## Ограничения

Это демо, а не production-шаблон:

- нет HTTPS, поэтому cookie идут без `Secure`;
- пароль в `/api/login` проверяется в приложении через `UserRepository` и
  `password_verify()`, потому что в `Auth` пока нет отдельного метода
  «проверить credentials и выдать токен»;
- CSRF-защита — double-submit cookie без подписи;
- нет подтверждения email, сброса пароля, throttling и rate limiting;
- SQLite-схема урезана до таблиц, которые нужны демо.
