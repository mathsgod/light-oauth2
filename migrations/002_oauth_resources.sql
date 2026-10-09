-- Apply before enabling OAUTH_RESOURCE_REGISTRY_ENABLED. No automatic seeding.
-- Exact resource URL is in record.id; a SHA-256 key supports long URL identities.
CREATE TABLE IF NOT EXISTS oauth_resources (
    id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    record LONGTEXT NOT NULL
) ENGINE=InnoDB;
-- Client-resource assignments are stored as record.resources in oauth_clients.
-- Existing clients with no resources field are restricted to OAUTH_RESOURCE.
