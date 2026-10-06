-- Apply with a migration runner to MySQL/MariaDB. Do not run on every request.
CREATE TABLE IF NOT EXISTS oauth_clients (
    id VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    record LONGTEXT NOT NULL
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS oauth_credentials (
    type VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    id VARCHAR(191) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    record LONGTEXT NOT NULL,
    revoked TINYINT(1) NOT NULL DEFAULT 0,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (type, id),
    INDEX oauth_credentials_expiry (expires_at)
) ENGINE=InnoDB;
