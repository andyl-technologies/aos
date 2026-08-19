-- Physical placement scans can outlive one controller invocation's original
-- claim window. Persist a renewable, fenced claim without rewriting the
-- operation's audit start time, and bind placement evidence to the exact
-- logical object revision it verified.
CREATE TABLE placement_scan_claims(
  operation_id KEYTEXT64 PRIMARY KEY
    REFERENCES topology_operations(operation_id) ON DELETE CASCADE,
  claim_token KEYTEXT64 NOT NULL UNIQUE,
  operation_resource_version INTEGER NOT NULL,
  heartbeat_at INTEGER NOT NULL,
  lease_expires_at INTEGER NOT NULL,
  CHECK(operation_resource_version > 0),
  CHECK(lease_expires_at > heartbeat_at)
);
CREATE INDEX placement_scan_claims_expiry_idx
ON placement_scan_claims(lease_expires_at, operation_id);
ALTER TABLE object_placements
  ADD COLUMN catalog_object_resource_version INTEGER NOT NULL DEFAULT 1;
