-- Arris.Auth schema for SQLite.
-- Used by the test suite and the examples.

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

CREATE INDEX IF NOT EXISTS users_username ON users (username);

CREATE TABLE IF NOT EXISTS users_confirmations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    email TEXT NOT NULL,
    selector TEXT NOT NULL,
    token TEXT NOT NULL,
    expires INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS users_confirmations_selector ON users_confirmations (selector);
CREATE INDEX IF NOT EXISTS users_confirmations_token ON users_confirmations (token);
CREATE INDEX IF NOT EXISTS users_confirmations_email_expires ON users_confirmations (email, expires);
CREATE INDEX IF NOT EXISTS users_confirmations_user_id ON users_confirmations (user_id);

CREATE TABLE IF NOT EXISTS users_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    selector TEXT NOT NULL,
    token TEXT NOT NULL,
    expires INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS users_resets_selector ON users_resets (selector);
CREATE INDEX IF NOT EXISTS users_resets_token ON users_resets (token);
CREATE INDEX IF NOT EXISTS users_resets_user_expires ON users_resets (user_id, expires);

CREATE TABLE IF NOT EXISTS users_throttling (
    bucket TEXT PRIMARY KEY,
    tokens REAL NOT NULL,
    replenished_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS users_throttling_expires_at ON users_throttling (expires_at);

CREATE TABLE IF NOT EXISTS users_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    force_logout INTEGER NOT NULL DEFAULT 0,
    kind TEXT NOT NULL DEFAULT 'api',
    selector TEXT,
    token TEXT NOT NULL,
    name TEXT,
    expires INTEGER NOT NULL DEFAULT 0,
    created INTEGER NOT NULL,
    last_used INTEGER,
    UNIQUE (selector)
);

CREATE INDEX IF NOT EXISTS users_tokens_token ON users_tokens (token);
CREATE INDEX IF NOT EXISTS users_tokens_user_kind ON users_tokens (user_id, kind);
CREATE INDEX IF NOT EXISTS users_tokens_expires ON users_tokens (expires);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    last_activity INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_last_activity ON sessions (last_activity);
