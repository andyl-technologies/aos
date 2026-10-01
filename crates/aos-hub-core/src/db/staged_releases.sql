-- Unpublished drafts are durable management state, never public catalog rows.
-- Every revision retains its exact inventory until its own grace period ends.
CREATE TABLE staged_releases(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  stage_id KEYTEXT128 NOT NULL,
  current_revision INTEGER NOT NULL,
  release_id KEYTEXT255 NOT NULL,
  source_branch KEYTEXT255 NOT NULL,
  source_commit TEXT NOT NULL,
  inventory_digest KEYTEXT128 NOT NULL,
  object_count INTEGER NOT NULL,
  total_bytes INTEGER NOT NULL,
  container_repository KEYTEXT255,
  state KEYTEXT32 NOT NULL,
  publication_id KEYTEXT64 UNIQUE,
  released_version KEYTEXT255,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, stage_id),
  CHECK(current_revision > 0),
  CHECK(state IN('draft', 'ready', 'releasing', 'released', 'discarded'))
);

CREATE TABLE staged_release_revisions(
  registry_id INTEGER NOT NULL,
  stage_id KEYTEXT128 NOT NULL,
  revision INTEGER NOT NULL,
  revision_json LONGTEXT NOT NULL,
  document_chunks INTEGER NOT NULL DEFAULT 0,
  document_bytes INTEGER NOT NULL DEFAULT 0,
  document_sha256 KEYTEXT64 NOT NULL DEFAULT '',
  publication_id KEYTEXT64 UNIQUE,
  retire_after INTEGER,
  PRIMARY KEY(registry_id, stage_id, revision),
  FOREIGN KEY(registry_id, stage_id) REFERENCES staged_releases(registry_id, stage_id) ON DELETE CASCADE
);

-- Provider-neutral UTF-8 pages stay below Durable SQLite's row/value limit.
CREATE TABLE staged_release_revision_chunks(
  registry_id INTEGER NOT NULL,
  stage_id KEYTEXT128 NOT NULL,
  revision INTEGER NOT NULL,
  ordinal INTEGER NOT NULL,
  payload LONGTEXT NOT NULL,
  PRIMARY KEY(registry_id, stage_id, revision, ordinal),
  FOREIGN KEY(registry_id, stage_id, revision) REFERENCES staged_release_revisions(registry_id, stage_id, revision) ON DELETE CASCADE,
  CHECK(ordinal >= 0)
);

CREATE TABLE staged_release_objects(
  registry_id INTEGER NOT NULL,
  stage_id KEYTEXT128 NOT NULL,
  revision INTEGER NOT NULL,
  object_key KEYTEXT1024 NOT NULL,
  sha256 KEYTEXT64 NOT NULL,
  media_type KEYTEXT255 NOT NULL,
  byte_size INTEGER NOT NULL,
  PRIMARY KEY(registry_id, stage_id, revision, object_key),
  FOREIGN KEY(registry_id, stage_id, revision) REFERENCES staged_release_revisions(registry_id, stage_id, revision) ON DELETE CASCADE,
  CHECK(byte_size >= 0)
);

CREATE TABLE staged_release_store_roots(
  registry_id INTEGER NOT NULL,
  stage_id KEYTEXT128 NOT NULL,
  revision INTEGER NOT NULL,
  store_path KEYTEXT255 NOT NULL,
  store_hash KEYTEXT64 NOT NULL,
  PRIMARY KEY(registry_id, stage_id, revision, store_path),
  FOREIGN KEY(registry_id, stage_id, revision) REFERENCES staged_release_revisions(registry_id, stage_id, revision) ON DELETE CASCADE
);

CREATE INDEX staged_releases_publication_idx ON staged_releases(publication_id);
CREATE INDEX staged_release_revision_retirement_idx ON staged_release_revisions(retire_after);

-- The public package projection follows verified channel metadata rather than
-- whichever maintainer branch happens to be the Git default.
CREATE TABLE registry_public_catalog_heads(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  source_commit TEXT,
  release_tag KEYTEXT255
);

CREATE INDEX staged_release_object_key_idx ON staged_release_objects(registry_id, object_key);
CREATE INDEX staged_release_object_global_key_idx ON staged_release_objects(object_key);
CREATE INDEX staged_release_object_hash_idx ON staged_release_objects(sha256);
CREATE INDEX staged_release_store_path_idx ON staged_release_store_roots(store_path);
CREATE INDEX staged_release_store_hash_idx ON staged_release_store_roots(store_hash);
