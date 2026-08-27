-- Resumable, bounded admission for large registry publication manifests.
-- The publication remains preparing and therefore invisible until the complete
-- manifest has been admitted and this session is sealed.
CREATE TABLE registry_publication_manifest_sessions(
  publication_id KEYTEXT64 PRIMARY KEY REFERENCES registry_publications(publication_id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL,
  lease_token KEYTEXT64 NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  expected_object_count INTEGER NOT NULL,
  admitted_object_count INTEGER NOT NULL DEFAULT 0,
  next_chunk_index INTEGER NOT NULL DEFAULT 0,
  state KEYTEXT16 NOT NULL,
  lease_expires_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  CHECK(expected_object_count > 0),
  CHECK(admitted_object_count >= 0 AND admitted_object_count <= expected_object_count),
  CHECK(next_chunk_index >= 0),
  CHECK(state IN('accepting', 'sealed')),
  CHECK(resource_version > 0),
  CHECK((state = 'accepting' AND lease_expires_at IS NOT NULL)
     OR (state = 'sealed' AND lease_expires_at IS NULL)),
  FOREIGN KEY(publication_id, registry_id)
  REFERENCES registry_publications(publication_id, registry_id)
);
CREATE INDEX registry_publication_manifest_sessions_lease
ON registry_publication_manifest_sessions(state, lease_expires_at);

-- One immutable receipt per accepted page. The digest makes retry of a lost
-- response exact without retaining the request body a second time.
CREATE TABLE registry_publication_manifest_chunks(
  publication_id KEYTEXT64 NOT NULL REFERENCES registry_publication_manifest_sessions(publication_id) ON DELETE CASCADE,
  chunk_index INTEGER NOT NULL,
  chunk_digest KEYTEXT128 NOT NULL,
  object_count INTEGER NOT NULL,
  accepted_at INTEGER NOT NULL,
  PRIMARY KEY(publication_id, chunk_index),
  CHECK(chunk_index >= 0),
  CHECK(object_count > 0)
);
