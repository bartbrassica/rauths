DROP TABLE IF EXISTS oauth_accounts;

ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;
