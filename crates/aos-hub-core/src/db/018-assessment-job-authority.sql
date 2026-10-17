-- Authenticated job provenance is private, immutable and separate from results.
-- A stored authority never extends the submitting credential's access lifetime.
CREATE TABLE assessment_scan_authorities(
  scan_id KEYTEXT128 PRIMARY KEY REFERENCES assessment_scans(scan_id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  resource_scope KEYTEXT128 NOT NULL,
  request_digest KEYTEXT128 NOT NULL,
  actor_ref KEYTEXT128 NOT NULL,
  authorization_revision INTEGER NOT NULL,
  authority_json BLOB NOT NULL,
  expires_at INTEGER NOT NULL,
  admitted_at INTEGER NOT NULL,
  CHECK(authorization_revision > 0),
  CHECK(length(authority_json) > 0 AND length(authority_json) <= 16384),
  CHECK(expires_at > admitted_at)
);

CREATE INDEX assessment_scan_authority_registry_idx
ON assessment_scan_authorities(registry_id, scan_id);
