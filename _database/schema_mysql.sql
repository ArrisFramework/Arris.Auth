-- Arris.Auth schema for MySQL/MariaDB.
-- The users, users_confirmations, users_remembered, users_resets and
-- users_throttling tables keep the layout of karelwintersky/arris.delight-php-auth.
-- users_tokens is new: it stores bearer tokens and "remember me" tokens.

CREATE TABLE `users` (
    `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
    `email` varchar(249) NOT NULL,
    `password` varchar(255) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `username` varchar(100) DEFAULT NULL,
    `status` tinyint(2) unsigned NOT NULL DEFAULT 0,
    `verified` tinyint(1) unsigned NOT NULL DEFAULT 0,
    `resettable` tinyint(1) unsigned NOT NULL DEFAULT 1,
    `roles_mask` int(10) unsigned NOT NULL DEFAULT 0,
    `registered` int(10) unsigned NOT NULL,
    `last_login` int(10) unsigned DEFAULT NULL,
    `force_logout` mediumint(7) unsigned NOT NULL DEFAULT 0,
    `properties` text DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `users_confirmations` (
    `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
    `user_id` int(10) unsigned NOT NULL,
    `email` varchar(249) NOT NULL,
    `selector` varchar(16) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `token` varchar(255) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `expires` int(10) unsigned NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `selector` (`selector`),
    KEY `email_expires` (`email`,`expires`),
    KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `users_remembered` (
    `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    `user_id` int(10) unsigned NOT NULL,
    `selector` varchar(24) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `token` varchar(255) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `expires` int(10) unsigned NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `selector` (`selector`),
    KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `users_resets` (
    `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    `user_id` int(10) unsigned NOT NULL,
    `selector` varchar(20) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `token` varchar(255) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `expires` int(10) unsigned NOT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `selector` (`selector`),
    KEY `user_expires` (`user_id`,`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `users_throttling` (
    `bucket` varchar(44) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `tokens` float unsigned NOT NULL,
    `replenished_at` int(10) unsigned NOT NULL,
    `expires_at` int(10) unsigned NOT NULL,
    PRIMARY KEY (`bucket`),
    KEY `expires_at` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `users_tokens` (
    `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    `user_id` int(10) unsigned NOT NULL,
    `kind` varchar(16) NOT NULL DEFAULT 'api',
    `selector` varchar(24) CHARACTER SET latin1 COLLATE latin1_general_cs DEFAULT NULL,
    `token` varchar(64) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `name` varchar(100) DEFAULT NULL,
    `expires` int(10) unsigned NOT NULL DEFAULT 0,
    `created` int(10) unsigned NOT NULL,
    `last_used` int(10) unsigned DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `selector` (`selector`),
    KEY `user_kind` (`user_id`,`kind`),
    KEY `expires` (`expires`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Optional: required only for Arris\Auth\Session\PDOSessionHandler
CREATE TABLE `sessions` (
    `id` varchar(128) CHARACTER SET latin1 COLLATE latin1_general_cs NOT NULL,
    `data` mediumtext NOT NULL,
    `last_activity` int(10) unsigned NOT NULL,
    PRIMARY KEY (`id`),
    KEY `last_activity` (`last_activity`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
