-- Per-registry generation fence for expensive index builds. The visible
-- registry_index row remains the atomic read pointer; this head prevents two
-- provider walks from racing to replace it.
CREATE TABLE registry_index_build_heads(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  build_id KEYTEXT64 NOT NULL,
  owner_token KEYTEXT64,
  base_generation INTEGER NOT NULL,
  target_generation INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  lease_expires_at INTEGER,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  content_digest KEYTEXT128,
  error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  CHECK(base_generation >= 0),
  CHECK(target_generation = base_generation + 1),
  CHECK(state IN('building', 'published', 'no_change', 'failed')),
  CHECK(resource_version > 0),
  CHECK((state = 'building' AND owner_token IS NOT NULL
         AND lease_expires_at IS NOT NULL AND finished_at IS NULL)
     OR (state <> 'building' AND owner_token IS NULL
         AND lease_expires_at IS NULL AND finished_at IS NOT NULL))
);
CREATE INDEX registry_index_build_heads_state_lease
ON registry_index_build_heads(state, lease_expires_at);
