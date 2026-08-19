ALTER TABLE cache_write_tickets ADD COLUMN backend_create_token KEYTEXT64;
ALTER TABLE cache_write_tickets ADD COLUMN backend_create_expires_at INTEGER;
