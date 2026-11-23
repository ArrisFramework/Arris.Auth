-- Arris.Auth 0.4.0 migration from the Delight PHP Auth schema.
-- Target: MySQL/MariaDB. Run on a backup/copy first.
--
-- The reverse migration is documented in README.md.
-- users_confirmations already has user_id in Delight; only users_remembered
-- and users_resets need the `user` -> `user_id` rename.

-- 1. users: properties and the loginWithUsername() index.
ALTER TABLE `users`
    ADD COLUMN `properties` text DEFAULT NULL AFTER `force_logout`;

ALTER TABLE `users`
    ADD KEY `username` (`username`);

-- 2. Rename legacy columns and indexes to match the Arris.Auth schema.
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

-- 3. Transactional storage for auth mutations.
ALTER TABLE `users` ENGINE=InnoDB;
ALTER TABLE `users_confirmations` ENGINE=InnoDB;
ALTER TABLE `users_remembered` ENGINE=InnoDB;
ALTER TABLE `users_resets` ENGINE=InnoDB;
ALTER TABLE `users_throttling` ENGINE=InnoDB;

-- 4. Bearer and remember-me tokens.
CREATE TABLE IF NOT EXISTS `users_tokens` (
    `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    `user_id` int(10) unsigned NOT NULL,
    `force_logout` mediumint(7) unsigned NOT NULL DEFAULT 0,
    `kind` varchar(16) NOT NULL DEFAULT 'api',
    `selector` varchar(24) CHARACTER SET latin1 COLLATE latin1_general_cs DEFAULT NULL,
    `token` varchar(64) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `name` varchar(100) DEFAULT NULL,
    `expires` int(10) unsigned NOT NULL DEFAULT 0,
    `created` int(10) unsigned NOT NULL,
    `last_used` int(10) unsigned DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `selector` (`selector`),
    KEY `token` (`token`),
    KEY `user_kind` (`user_id`, `kind`),
    KEY `expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- If users_tokens already exists from an earlier 0.4 preview, add the missing
-- column and index manually:
-- ALTER TABLE `users_tokens`
--     ADD COLUMN `force_logout` mediumint(7) unsigned NOT NULL DEFAULT 0 AFTER `user_id`,
--     ADD KEY `token` (`token`);

-- 5. Optional: required only for Arris\Auth\Session\PDOSessionHandler.
CREATE TABLE IF NOT EXISTS `sessions` (
    `id` varchar(128) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `data` mediumtext NOT NULL,
    `last_activity` int(10) unsigned NOT NULL,
    PRIMARY KEY (`id`),
    KEY `last_activity` (`last_activity`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
