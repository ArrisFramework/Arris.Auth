CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    username TEXT,
    status INTEGER NOT NULL DEFAULT 0,
    verified INTEGER NOT NULL DEFAULT 0,
    resettable INTEGER NOT NULL DEFAULT 1,
    roles_mask INTEGER NOT NULL DEFAULT 0,
    registered INTEGER NOT NULL,
    last_login INTEGER,
    force_logout INTEGER NOT NULL DEFAULT 0,
    properties TEXT
);

CREATE TABLE IF NOT EXISTS users_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    kind TEXT NOT NULL DEFAULT 'api',
    selector TEXT,
    token TEXT NOT NULL,
    name TEXT,
    expires INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL,
    last_used INTEGER,
    UNIQUE (selector)
);

CREATE INDEX IF NOT EXISTS users_tokens_user_kind ON users_tokens (user_id, kind);
CREATE INDEX IF NOT EXISTS users_tokens_expires ON users_tokens (expires);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    last_activity INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_last_activity ON sessions (last_activity);
