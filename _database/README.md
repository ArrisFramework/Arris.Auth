# Database schemas

- `schema_mysql.sql` — canonical MySQL/MariaDB schema. All `CREATE TABLE`
  statements are idempotent and use InnoDB.
- `schema_sqlite.sql` — SQLite schema used by the test suite and the demo.
- `migrations/0.4.0.sql` — migration from the Delight PHP Auth schema.

The migration renames `user` to `user_id` in `users_remembered` and `users_resets`,
adds `users.properties` and `users.username`, converts the `users*` tables to InnoDB,
and creates `users_tokens` and optional `sessions`.

`users_tokens` is required for bearer and remember-me authentication. Basic
cookie-session authentication only needs `users`.

Forward and reverse migration commands are documented in the main `README.md`
section "Миграция с Delight PHP Auth".
