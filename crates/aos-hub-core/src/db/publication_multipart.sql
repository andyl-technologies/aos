-- Existing deployments predate the multipart publication tables in the
-- squashed fresh-install schema. Keep this migration idempotent so a new
-- database can apply the same ordered migration list after its baseline.
CREATE TABLE IF NOT EXISTS registry_publication_multipart_uploads(
  upload_id KEYTEXT64 PRIMARY KEY,
  publication_id KEYTEXT64 NOT NULL,
  registry_id INTEGER NOT NULL,
  surface_object_id INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  active_object_slot INTEGER,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  hashed_size INTEGER NOT NULL DEFAULT 0,
  sha256_state LONGTEXT NOT NULL
    DEFAULT '6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19',
  pending_part INTEGER,
  pending_hash LONGTEXT,
  pending_token KEYTEXT64,
  pending_since INTEGER,
  completion_token KEYTEXT64,
  completion_since INTEGER,
  UNIQUE(publication_id, surface_object_id, active_object_slot),
  CHECK(state IN('active', 'completing', 'completed', 'aborted', 'failed')),
  CHECK((state IN('active', 'completing') AND active_object_slot = 1
AND finished_at IS NULL)
OR(state IN('completed', 'aborted', 'failed') AND active_object_slot IS NULL
AND finished_at IS NOT NULL)),
  CHECK(expires_at > created_at),
  FOREIGN KEY(publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id),
  FOREIGN KEY(publication_id, surface_object_id)
  REFERENCES registry_publication_objects(publication_id, surface_object_id)
);
CREATE TABLE IF NOT EXISTS registry_publication_multipart_parts(
  upload_id KEYTEXT64 NOT NULL
    REFERENCES registry_publication_multipart_uploads(upload_id),
  part_number INTEGER NOT NULL,
  placement_id INTEGER NOT NULL REFERENCES surface_placements(id),
  etag LONGTEXT NOT NULL,
  PRIMARY KEY(upload_id, part_number, placement_id),
  CHECK(part_number > 0),
  CHECK(length(etag) BETWEEN 1 AND 1024)
);
CREATE TABLE IF NOT EXISTS registry_publication_multipart_backends(
  upload_id KEYTEXT64 NOT NULL
    REFERENCES registry_publication_multipart_uploads(upload_id),
  placement_id INTEGER NOT NULL REFERENCES surface_placements(id),
  placement_resource_version INTEGER NOT NULL,
  backend_upload_id KEYTEXT1024,
  completion_etag LONGTEXT,
  state KEYTEXT16 NOT NULL,
  PRIMARY KEY(upload_id, placement_id),
  CHECK(state IN('creating', 'ready', 'uncertain')),
  CHECK((state = 'creating' AND backend_upload_id IS NULL)
    OR(state IN('ready', 'uncertain') AND backend_upload_id IS NOT NULL))
);
