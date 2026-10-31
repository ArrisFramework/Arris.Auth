<?php

declare(strict_types=1);

use Arris\Auth\Exception\AccountDisabledException;
use Arris\Auth\Exception\AuthException;
use Arris\Auth\Exception\ConfigurationException;
use Arris\Auth\Exception\EmailNotVerifiedException;
use Arris\Auth\Exception\InvalidCredentialsException;
use Arris\Auth\Exception\InvalidEmailException;
use Arris\Auth\Exception\InvalidPasswordException;
use Arris\Auth\Exception\UserAlreadyExistsException;
use Arris\Auth\Repository\UserRepository;
use Arris\Auth\Role;
use Arris\Auth\User;

function demo_e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function demo_json(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    exit;
}

function demo_redirect(string $location): never
{
    header('Location: ' . $location, true, 302);
    exit;
}

function demo_safe_next(mixed $next): string
{
    if (!is_string($next) || $next === '' || $next[0] !== '/' || str_starts_with($next, '//')) {
        return '/';
    }

    return $next;
}

function demo_request_data(): array
{
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';

    if (stripos($contentType, 'application/json') !== false) {
        $raw = file_get_contents('php://input');
        $data = json_decode($raw !== false ? $raw : '[]', true);

        return is_array($data) ? $data : [];
    }

    return $_POST;
}

function demo_method_not_allowed(array $allowed): never
{
    header('Allow: ' . implode(', ', $allowed));
    demo_json([
        'error' => 'method_not_allowed',
        'allowed' => $allowed,
    ], 405);
}

function demo_csrf_token(): string
{
    $name = 'arris_demo_csrf';
    $token = $_COOKIE[$name] ?? '';

    if (!is_string($token) || strlen($token) < 32) {
        $token = bin2hex(random_bytes(16));

        setcookie($name, $token, [
            'expires' => 0,
            'path' => '/',
            'secure' => false,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        $_COOKIE[$name] = $token;
    }

    return $token;
}

function demo_csrf_verify(string $expected): void
{
    $sent = $_POST['_csrf'] ?? '';

    if (!is_string($sent) || $sent === '' || !hash_equals($expected, $sent)) {
        demo_abort(419, 'CSRF check failed', 'The form has expired. Reload the page and try again.');
    }
}

function demo_login_error(AuthException $exception): string
{
    return match (true) {
        $exception instanceof InvalidEmailException => 'Некорректный email.',
        $exception instanceof InvalidCredentialsException => 'Неверный email или пароль.',
        $exception instanceof EmailNotVerifiedException => 'Email не подтверждён.',
        $exception instanceof AccountDisabledException => 'Аккаунт отключён.',
        $exception instanceof ConfigurationException => 'Ошибка конфигурации: ' . $exception->getMessage(),
        default => $exception->getMessage(),
    };
}

function demo_projects(): array
{
    return [
        ['id' => 1, 'name' => 'Arris.Auth', 'status' => 'active', 'owner' => 'admin@example.com'],
        ['id' => 2, 'name' => 'Arris.Config', 'status' => 'active', 'owner' => 'admin@example.com'],
        ['id' => 3, 'name' => 'Secret Project', 'status' => 'planning', 'owner' => 'user@example.com'],
    ];
}

function demo_layout_start(string $title, ?User $user, string $csrf): void
{
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    ?>
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= demo_e($title) ?> — Arris.Auth demo</title>
    <style>
        :root { color-scheme: light dark; }
        body { font: 16px/1.5 system-ui, sans-serif; max-width: 900px; margin: 0 auto; padding: 1rem; }
        header { display: flex; flex-wrap: wrap; gap: 1rem; align-items: center; justify-content: space-between; border-bottom: 1px solid #8884; padding-bottom: .75rem; margin-bottom: 1.5rem; }
        nav { display: flex; flex-wrap: wrap; gap: .75rem; align-items: center; }
        nav form { margin: 0; }
        a { color: inherit; }
        table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
        th, td { text-align: left; border-bottom: 1px solid #8884; padding: .4rem .5rem; vertical-align: top; }
        th { font-weight: 600; }
        form.stack { display: grid; gap: .75rem; max-width: 28rem; }
        label { display: grid; gap: .25rem; }
        input, button { font: inherit; padding: .45rem .6rem; }
        button { cursor: pointer; }
        code, pre { overflow-wrap: anywhere; }
        pre { padding: 1rem; overflow-x: auto; border: 1px solid #8884; border-radius: .5rem; }
        .muted { opacity: .7; }
        .error { border: 1px solid #c33; border-radius: .5rem; padding: .75rem 1rem; }
        .ok { border: 1px solid #3a3; border-radius: .5rem; padding: .75rem 1rem; }
        .inline { display: inline; }
    </style>
</head>
<body>
<header>
    <strong><a href="/">Arris.Auth demo</a></strong>
    <nav>
        <a href="/">Главная</a>
        <?php if ($user !== null): ?>
            <?php if ($user->hasRole(Role::ADMIN)): ?>
                <a href="/admin">Админка</a>
            <?php endif; ?>
            <span class="muted"><?= demo_e($user->email) ?></span>
            <form method="post" action="/logout">
                <input type="hidden" name="_csrf" value="<?= demo_e($csrf) ?>">
                <button type="submit">Выйти</button>
            </form>
        <?php else: ?>
            <a href="/login">Вход</a>
            <a href="/register">Регистрация</a>
        <?php endif; ?>
    </nav>
</header>
<main>
    <?php
}

function demo_layout_end(): void
{
    ?>
</main>
</body>
</html>
    <?php
}

function demo_abort(int $status, string $title, string $message): never
{
    http_response_code($status);
    demo_layout_start($title, null, demo_csrf_token());
    ?>
    <h1><?= demo_e($title) ?></h1>
    <p><?= demo_e($message) ?></p>
    <p><a href="/">На главную</a></p>
    <?php
    demo_layout_end();
    exit;
}

$app = require __DIR__ . '/../bootstrap.php';

/** @var PDO $pdo */
$pdo = $app['pdo'];
/** @var Arris\Auth\Auth $auth */
$auth = $app['auth'];
/** @var Arris\Auth\AuthConfig $config */
$config = $app['config'];

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = '/' . trim($path, '/');

if ($path === '/api' || str_starts_with($path, '/api/')) {
    if ($path === '/api/login') {
        if ($method !== 'POST') {
            demo_method_not_allowed(['POST']);
        }

        $input = demo_request_data();
        $email = trim((string) ($input['email'] ?? ''));
        $password = (string) ($input['password'] ?? '');

        if ($email === '' || $password === '') {
            demo_json([
                'error' => 'invalid_credentials',
                'message' => 'Email and password are required.',
            ], 401);
        }

        $users = new UserRepository($pdo);
        $row = $users->findByEmail($email);

        if ($row === null || !password_verify($password, (string) $row['password'])) {
            demo_json([
                'error' => 'invalid_credentials',
                'message' => 'Invalid email or password.',
            ], 401);
        }

        $user = User::fromRow($row);

        if (!$user->isVerified()) {
            demo_json([
                'error' => 'email_not_verified',
                'message' => 'The email address has not been verified.',
            ], 403);
        }

        if (!$user->isNormal()) {
            demo_json([
                'error' => 'account_disabled',
                'message' => 'The account is disabled.',
            ], 403);
        }

        $users->updateLastLogin($user->id);
        $row['last_login'] = time();
        $user = User::fromRow($row);
        $token = $auth->issueToken($user->id, name: 'api login');

        demo_json([
            'token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => $config->getTokenTtl(),
            'user' => $user->toArray(),
            'roles' => $user->roleNames(),
        ], 201);
    }

    if ($path === '/api/me') {
        if ($method !== 'GET') {
            demo_method_not_allowed(['GET']);
        }

        $user = $auth->user();

        if ($user === null) {
            demo_json([
                'error' => 'unauthorized',
                'message' => 'A valid session cookie or bearer token is required.',
            ], 401);
        }

        demo_json([
            'user' => $user->toArray(),
            'roles' => $user->roleNames(),
            'remembered' => $auth->isRemembered(),
        ]);
    }

    if ($path === '/api/projects') {
        if ($method !== 'GET') {
            demo_method_not_allowed(['GET']);
        }

        $user = $auth->user();

        if ($user === null) {
            demo_json([
                'error' => 'unauthorized',
                'message' => 'A valid session cookie or bearer token is required.',
            ], 401);
        }

        demo_json([
            'projects' => demo_projects(),
            'user' => $user->toArray(),
            'roles' => $user->roleNames(),
            'is_admin' => $user->hasRole(Role::ADMIN),
        ]);
    }

    if ($path === '/api/logout') {
        if ($method !== 'POST') {
            demo_method_not_allowed(['POST']);
        }

        $user = $auth->user();

        if ($user === null) {
            demo_json([
                'error' => 'unauthorized',
                'message' => 'A valid session cookie or bearer token is required.',
            ], 401);
        }

        $auth->logout();

        demo_json(['ok' => true]);
    }

    demo_json([
        'error' => 'not_found',
        'message' => 'Unknown API endpoint.',
    ], 404);
}

$csrf = demo_csrf_token();
$currentUser = $auth->user();

if ($path === '/') {
    demo_layout_start('Главная', $currentUser, $csrf);
    ?>
    <h1>Arris.Auth demo</h1>
    <p>Небольшое приложение на одном front controller: cookie-сессии, remember-me и bearer-токены.</p>

    <p class="muted">Режим: <code><?= demo_e($auth->mode()) ?></code>. Хранилище сессий: <code>PDOSessionHandler</code> в SQLite.</p>

    <?php if ($currentUser !== null): ?>
        <div class="ok">
            Вы вошли как <strong><?= demo_e($currentUser->email) ?></strong>
            (id <?= demo_e($currentUser->id) ?>, роли: <?= demo_e(implode(', ', $currentUser->roleNames()) ?: '—') ?>).
            <?php if ($auth->isRemembered()): ?>
                Сессия восстановлена из remember-me cookie.
            <?php endif; ?>
        </div>
    <?php else: ?>
        <p>Вы не авторизованы.</p>
        <p><a href="/login">Войти</a> или <a href="/register">зарегистрироваться</a>.</p>
    <?php endif; ?>

    <h2>Тестовые аккаунты</h2>
    <table>
        <thead>
        <tr><th>Email</th><th>Пароль</th><th>Роли</th></tr>
        </thead>
        <tbody>
        <tr><td>admin@example.com</td><td>admin-password</td><td>ADMIN</td></tr>
        <tr><td>user@example.com</td><td>user-password</td><td>SUBSCRIBER</td></tr>
        </tbody>
    </table>

    <h2>Маршруты</h2>
    <table>
        <thead>
        <tr><th>Маршрут</th><th>Что делает</th></tr>
        </thead>
        <tbody>
        <tr><td><code>GET /</code></td><td>Эта страница.</td></tr>
        <tr><td><code>GET|POST /login</code></td><td>Вход по email и паролю, опционально remember-me.</td></tr>
        <tr><td><code>GET|POST /register</code></td><td>Регистрация и автоматический вход.</td></tr>
        <tr><td><code>POST /logout</code></td><td>Выход и отзыв текущего bearer-токена.</td></tr>
        <tr><td><code>GET /admin</code></td><td>Защищённая страница, только для роли ADMIN.</td></tr>
        <tr><td><code>POST /token</code></td><td>Выдать bearer-токен текущему пользователю.</td></tr>
        <tr><td><code>POST /api/login</code></td><td>Получить bearer-токен по email и паролю.</td></tr>
        <tr><td><code>GET /api/me</code></td><td>Текущий пользователь через сессию или bearer.</td></tr>
        <tr><td><code>GET /api/projects</code></td><td>Защищённый JSON-список проектов.</td></tr>
        <tr><td><code>POST /api/logout</code></td><td>Отозвать текущий bearer-токен.</td></tr>
        </tbody>
    </table>
    <?php
    demo_layout_end();
    exit;
}

if ($path === '/login') {
    $next = demo_safe_next($_GET['next'] ?? $_POST['next'] ?? null);

    if ($currentUser !== null) {
        demo_redirect($next);
    }

    $error = null;
    $email = '';

    if ($method === 'POST') {
        demo_csrf_verify($csrf);
        $email = trim((string) ($_POST['email'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $remember = !empty($_POST['remember']);

        try {
            $auth->login($email, $password, $remember);
            demo_redirect($next);
        } catch (AuthException $exception) {
            http_response_code(422);
            $error = demo_login_error($exception);
        }
    }

    demo_layout_start('Вход', $currentUser, $csrf);
    ?>
    <h1>Вход</h1>

    <?php if ($error !== null): ?>
        <p class="error"><?= demo_e($error) ?></p>
    <?php endif; ?>

    <form class="stack" method="post" action="/login">
        <input type="hidden" name="_csrf" value="<?= demo_e($csrf) ?>">
        <input type="hidden" name="next" value="<?= demo_e($next) ?>">
        <label>
            Email
            <input type="email" name="email" value="<?= demo_e($email) ?>" autocomplete="email" required>
        </label>
        <label>
            Пароль
            <input type="password" name="password" autocomplete="current-password" required>
        </label>
        <label>
            <span><input type="checkbox" name="remember" value="1"> Запомнить меня</span>
        </label>
        <button type="submit">Войти</button>
    </form>

    <p class="muted">Нет аккаунта? <a href="/register">Зарегистрироваться</a>.</p>
    <?php
    demo_layout_end();
    exit;
}

if ($path === '/register') {
    if ($currentUser !== null) {
        demo_redirect('/');
    }

    $error = null;
    $email = '';
    $username = '';

    if ($method === 'POST') {
        demo_csrf_verify($csrf);
        $email = trim((string) ($_POST['email'] ?? ''));
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $passwordConfirmation = (string) ($_POST['password_confirmation'] ?? '');

        if ($password !== $passwordConfirmation) {
            http_response_code(422);
            $error = 'Пароли не совпадают.';
        } else {
            try {
                $userId = $auth->register(
                    email: $email,
                    password: $password,
                    username: $username !== '' ? $username : null,
                    verified: true,
                    rolesMask: Role::SUBSCRIBER,
                );

                $auth->login($email, $password);
                demo_redirect('/');
            } catch (InvalidPasswordException $exception) {
                http_response_code(422);
                $error = 'Пароль слишком короткий: минимум ' . $config->getMinPasswordLength() . ' символов.';
            } catch (UserAlreadyExistsException $exception) {
                http_response_code(422);
                $error = 'Пользователь с таким email уже существует.';
            } catch (InvalidEmailException $exception) {
                http_response_code(422);
                $error = 'Некорректный email.';
            } catch (AuthException $exception) {
                http_response_code(422);
                $error = $exception->getMessage();
            }
        }
    }

    demo_layout_start('Регистрация', $currentUser, $csrf);
    ?>
    <h1>Регистрация</h1>

    <?php if ($error !== null): ?>
        <p class="error"><?= demo_e($error) ?></p>
    <?php endif; ?>

    <form class="stack" method="post" action="/register">
        <input type="hidden" name="_csrf" value="<?= demo_e($csrf) ?>">
        <label>
            Email
            <input type="email" name="email" value="<?= demo_e($email) ?>" autocomplete="email" required>
        </label>
        <label>
            Имя пользователя (необязательно)
            <input type="text" name="username" value="<?= demo_e($username) ?>" autocomplete="username">
        </label>
        <label>
            Пароль
            <input type="password" name="password" autocomplete="new-password" minlength="<?= demo_e($config->getMinPasswordLength()) ?>" required>
        </label>
        <label>
            Пароль ещё раз
            <input type="password" name="password_confirmation" autocomplete="new-password" minlength="<?= demo_e($config->getMinPasswordLength()) ?>" required>
        </label>
        <button type="submit">Зарегистрироваться</button>
    </form>
    <?php
    demo_layout_end();
    exit;
}

if ($path === '/logout') {
    if ($method !== 'POST') {
        demo_abort(405, 'Method not allowed', 'Use the logout button in the navigation.');
    }

    demo_csrf_verify($csrf);
    $auth->logout();
    demo_redirect('/');
}

if ($path === '/admin') {
    if ($currentUser === null) {
        demo_redirect('/login?next=/admin');
    }

    if (!$currentUser->hasRole(Role::ADMIN)) {
        demo_abort(403, 'Доступ запрещён', 'Для этой страницы нужна роль ADMIN.');
    }

    $users = $pdo->query(
        'SELECT id, email, username, status, verified, roles_mask, registered, last_login FROM users ORDER BY id'
    )->fetchAll();
    $sessionCount = (int) $pdo->query('SELECT COUNT(*) FROM sessions')->fetchColumn();
    $tokenCount = (int) $pdo->query('SELECT COUNT(*) FROM users_tokens')->fetchColumn();
    $projectCount = count(demo_projects());

    demo_layout_start('Админка', $currentUser, $csrf);
    ?>
    <h1>Админка</h1>
    <p>Страница доступна только текущему пользователю с ролью <code>ADMIN</code>.</p>

    <table>
        <tbody>
        <tr><th>Текущий пользователь</th><td><?= demo_e($currentUser->email) ?> (id <?= demo_e($currentUser->id) ?>)</td></tr>
        <tr><th>Роли</th><td><?= demo_e(implode(', ', $currentUser->roleNames()) ?: '—') ?></td></tr>
        <tr><th>Последний вход</th><td><?= demo_e($currentUser->lastLogin !== null ? date('Y-m-d H:i:s', $currentUser->lastLogin) : '—') ?></td></tr>
        <tr><th>Сессий в БД</th><td><?= demo_e($sessionCount) ?></td></tr>
        <tr><th>Токенов в БД</th><td><?= demo_e($tokenCount) ?></td></tr>
        <tr><th>Проектов в демо-API</th><td><?= demo_e($projectCount) ?></td></tr>
        </tbody>
    </table>

    <h2>Пользователи</h2>
    <table>
        <thead>
        <tr><th>ID</th><th>Email</th><th>Username</th><th>Роли</th><th>Verified</th><th>Registered</th><th>Last login</th></tr>
        </thead>
        <tbody>
        <?php foreach ($users as $row): ?>
            <?php
            $roles = Role::names((int) $row['roles_mask']);
            $registered = (int) $row['registered'];
            $lastLogin = $row['last_login'] !== null ? (int) $row['last_login'] : null;
            ?>
            <tr>
                <td><?= demo_e($row['id']) ?></td>
                <td><?= demo_e($row['email']) ?></td>
                <td><?= demo_e($row['username'] ?? '—') ?></td>
                <td><?= demo_e(implode(', ', $roles) ?: '—') ?></td>
                <td><?= (int) $row['verified'] === 1 ? 'yes' : 'no' ?></td>
                <td><?= demo_e($registered > 0 ? date('Y-m-d H:i:s', $registered) : '—') ?></td>
                <td><?= demo_e($lastLogin !== null ? date('Y-m-d H:i:s', $lastLogin) : '—') ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>

    <h2>Bearer-токены</h2>
    <p>Выдайте токен и используйте его в заголовке <code>Authorization: Bearer &lt;token&gt;</code>.</p>
    <form method="post" action="/token">
        <input type="hidden" name="_csrf" value="<?= demo_e($csrf) ?>">
        <button type="submit">Выдать токен для <?= demo_e($currentUser->email) ?></button>
    </form>

    <h2>curl</h2>
    <pre><code>curl -s -X POST http://localhost:8080/api/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"admin-password"}'

curl -s http://localhost:8080/api/projects \
  -H "Authorization: Bearer $TOKEN"</code></pre>
    <?php
    demo_layout_end();
    exit;
}

if ($path === '/token') {
    if ($method !== 'POST') {
        demo_abort(405, 'Method not allowed', 'Issue tokens with a POST form.');
    }

    demo_csrf_verify($csrf);

    if ($currentUser === null) {
        demo_abort(401, 'Не авторизован', 'Сначала войдите, затем выдайте токен.');
    }

    $token = $auth->issueToken($currentUser->id, name: 'demo browser');

    demo_layout_start('Bearer-токен', $currentUser, $csrf);
    ?>
    <h1>Bearer-токен</h1>
    <p class="ok">Токен показывается один раз. Скопируйте его сейчас.</p>
    <pre><code><?= demo_e($token) ?></code></pre>

    <h2>Проверка</h2>
    <pre><code>curl -s http://localhost:8080/api/me \
  -H "Authorization: Bearer <?= demo_e($token) ?>"

curl -s http://localhost:8080/api/projects \
  -H "Authorization: Bearer <?= demo_e($token) ?>"</code></pre>

    <p><a href="/admin">Назад в админку</a> · <a href="/">На главную</a></p>
    <?php
    demo_layout_end();
    exit;
}

demo_abort(404, 'Страница не найдена', 'Такого маршрута в демо нет.');
