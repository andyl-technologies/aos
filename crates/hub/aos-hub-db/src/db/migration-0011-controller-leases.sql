-- Durable ownership for controller observation writers.
CREATE TABLE controller_leases(
  target_kind KEYTEXT32 NOT NULL,
  target_id KEYTEXT255 NOT NULL,
  lease_id KEYTEXT64 NOT NULL UNIQUE,
  generation INTEGER NOT NULL,
  owner_service_account_id INTEGER NOT NULL REFERENCES service_accounts(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  serial INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(target_kind, target_id),
  CHECK(length(target_kind) > 0),
  CHECK(length(target_id) > 0),
  CHECK(length(lease_id) > 0),
  CHECK(generation > 0),
  CHECK(expires_at > created_at),
  CHECK(serial >= 0),
  CHECK(updated_at >= created_at)
);

CREATE INDEX controller_leases_expiry_idx
ON controller_leases(expires_at);
