-- OAuth device-flow refresh credentials. Refresh secrets are opaque, hashed at
-- rest, single-use, and retained after consumption so reuse can revoke the
-- complete credential family.
ALTER TABLE device_codes ADD COLUMN last_polled_at INTEGER;

CREATE TABLE refresh_token_families(
  id TEXT PRIMARY KEY,
  token_id TEXT NOT NULL REFERENCES tokens(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL,
  absolute_expires_at INTEGER NOT NULL,
  revoked_at INTEGER
);

CREATE TABLE refresh_tokens(
  hash TEXT PRIMARY KEY,
  family_id TEXT NOT NULL REFERENCES refresh_token_families(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER
);

CREATE INDEX refresh_tokens_family ON refresh_tokens(family_id);
