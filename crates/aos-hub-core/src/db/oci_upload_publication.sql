-- Phase 5 OCI uploads and verified publication.
--
-- Migration v20 deliberately reserved publication/upload table names before
-- their protocol was implemented. No released writer could populate those
-- placeholders. Fail closed if an operator nevertheless inserted rows rather
-- than silently discarding state that cannot satisfy the durable v21 contract.
CREATE TABLE IF NOT EXISTS oci_phase5_upgrade_guard(
  id KEYTEXT16 PRIMARY KEY,
  marker INTEGER NOT NULL CHECK(marker = 0)
);
INSERT INTO oci_phase5_upgrade_guard(id, marker) VALUES('phase5', 0)
ON CONFLICT(id) DO NOTHING;
UPDATE oci_phase5_upgrade_guard SET marker = 1
WHERE id = 'phase5'
  AND (EXISTS(SELECT 1 FROM oci_uploads)
    OR EXISTS(SELECT 1 FROM oci_publications));

-- Descriptor media type belongs to the repository link, while the
-- registry-wide stored blob is generic octet-stream content. Existing v20
-- links inherit the exact descriptor media type recorded on their blob row.
ALTER TABLE oci_repository_objects
ADD COLUMN media_type KEYTEXT128 NOT NULL DEFAULT 'application/octet-stream';
UPDATE oci_repository_objects
SET media_type = (
  SELECT stored.media_type FROM oci_blobs stored
  WHERE stored.registry_id = oci_repository_objects.registry_id
    AND stored.digest = oci_repository_objects.digest
);

-- The no-op increment is the row-level fence held by a verified publication
-- while it rechecks the exact signed release root and moves a tag.
ALTER TABLE oci_release_roots
ADD COLUMN publication_fence INTEGER NOT NULL DEFAULT 0;

-- Keep the frozen v20 placeholder tables intact. Production state uses new
-- names so every v21 statement is replayable after a MySQL implicit DDL
-- commit, and concurrent starters can only race idempotent creates.
CREATE TABLE oci_publication_sessions(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  repository_id INTEGER NOT NULL,
  writer_id KEYTEXT128 NOT NULL,
  token_id KEYTEXT128 NOT NULL,
  target_tag KEYTEXT128,
  expected_tag_version INTEGER,
  expected_tag_digest KEYTEXT128,
  root_digest KEYTEXT128 NOT NULL,
  catalog_digest KEYTEXT128 NOT NULL,
  release_tag KEYTEXT255,
  sidecar_sha256 KEYTEXT128,
  confirmation_hash KEYTEXT128 NOT NULL,
  topology_digest KEYTEXT128 NOT NULL,
  required_placement_count INTEGER NOT NULL,
  source_kind KEYTEXT16 NOT NULL,
  state KEYTEXT16 NOT NULL,
  idempotency_key KEYTEXT128 NOT NULL,
  commit_idempotency_key KEYTEXT128,
  abort_idempotency_key KEYTEXT128,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  committed_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, writer_id, idempotency_key),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  CHECK(source_kind IN('manual', 'release', 'channel')),
  CHECK((source_kind = 'manual' AND release_tag IS NULL AND sidecar_sha256 IS NULL)
     OR (source_kind IN('release', 'channel')
         AND release_tag IS NOT NULL AND sidecar_sha256 IS NOT NULL)),
  CHECK(state IN('preparing', 'committing', 'ready', 'aborted', 'failed')),
  CHECK(required_placement_count > 0),
  CHECK(expected_tag_version IS NULL OR expected_tag_version >= 1)
);
CREATE INDEX oci_publications_expiry_idx
ON oci_publication_sessions(state, expires_at);

-- Begin freezes the complete set of placements whose validated write
-- capability currently makes them mandatory for registry publication. The
-- set and every writer-critical revision are rechecked in the commit
-- transaction; a topology change therefore requires a new publication plan.
CREATE TABLE oci_publication_required_placements(
  publication_id KEYTEXT64 NOT NULL
  REFERENCES oci_publication_sessions(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  placement_resource_version INTEGER NOT NULL,
  placement_write_spec_version INTEGER NOT NULL,
  placement_observation_version INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_write_revision INTEGER NOT NULL,
  revision_fingerprint KEYTEXT128 NOT NULL,
  capability_fingerprint KEYTEXT128 NOT NULL,
  PRIMARY KEY(publication_id, placement_id),
  FOREIGN KEY(placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id) ON DELETE RESTRICT,
  CHECK(placement_resource_version >= 1),
  CHECK(placement_write_spec_version >= 1),
  CHECK(placement_observation_version >= 1),
  CHECK(binding_write_revision >= 1)
);
CREATE INDEX oci_publication_required_placements_registry_idx
ON oci_publication_required_placements(registry_id, placement_id, publication_id);

-- The complete descriptor graph is frozen before publication. Projection JSON
-- is a bounded parsed admission reference; the immutable object key identifies
-- the exact bytes whose digest was independently observed.
CREATE TABLE oci_publication_objects(
  publication_id KEYTEXT64 NOT NULL REFERENCES oci_publication_sessions(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  object_kind KEYTEXT16 NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  descriptor_json LONGTEXT NOT NULL,
  projection_json LONGTEXT,
  PRIMARY KEY(publication_id, digest),
  CHECK(byte_size >= 0),
  CHECK(object_kind IN('blob', 'manifest'))
);
CREATE INDEX oci_publication_objects_digest_idx
ON oci_publication_objects(registry_id, digest, publication_id);

-- A publication may require the same object on several placements. Every row
-- records the inventory/resource fences needed to recheck exact presence in
-- the commit transaction.
CREATE TABLE oci_publication_object_placements(
  publication_id KEYTEXT64 NOT NULL,
  digest KEYTEXT128 NOT NULL,
  registry_id INTEGER NOT NULL,
  surface_object_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  object_resource_version INTEGER NOT NULL,
  placement_resource_version INTEGER NOT NULL,
  placement_observation_version INTEGER NOT NULL,
  observed_inventory_generation INTEGER NOT NULL,
  observed_size INTEGER NOT NULL,
  observed_etag KEYTEXT512 NOT NULL,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY(publication_id, digest, placement_id),
  FOREIGN KEY(publication_id, digest)
  REFERENCES oci_publication_objects(publication_id, digest) ON DELETE CASCADE,
  CHECK(observed_size >= 0),
  CHECK(object_resource_version >= 1),
  CHECK(placement_resource_version >= 1),
  CHECK(placement_observation_version >= 1),
  CHECK(observed_inventory_generation >= 0)
);
CREATE INDEX oci_publication_object_placements_evidence_idx
ON oci_publication_object_placements(
  registry_id, surface_object_id, placement_id, publication_id
);

-- Quota is reserved before any client bytes are accepted. Reservations are
-- durable recovery owners and are either committed exactly once with a new
-- object or released exactly once on deduplication, cancellation, or expiry.
CREATE TABLE oci_quota_reservations(
  id KEYTEXT128 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  org_id INTEGER NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  owner_kind KEYTEXT16 NOT NULL,
  owner_id KEYTEXT128 NOT NULL,
  reserved_bytes INTEGER NOT NULL,
  reserved_objects INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(owner_kind, owner_id),
  CHECK(owner_kind IN('upload', 'publication', 'catalog')),
  CHECK(reserved_bytes >= 0),
  CHECK(reserved_objects >= 0),
  CHECK(state IN('pending', 'reserved', 'committed', 'released'))
);
CREATE INDEX oci_quota_reservations_registry_idx
ON oci_quota_reservations(registry_id, state, created_at);

CREATE TABLE oci_upload_sessions(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  repository_id INTEGER NOT NULL,
  publication_id KEYTEXT64 REFERENCES oci_publication_sessions(id) ON DELETE CASCADE,
  quota_reservation_id KEYTEXT128 NOT NULL
  REFERENCES oci_quota_reservations(id) ON DELETE RESTRICT,
  writer_id KEYTEXT128 NOT NULL,
  token_id KEYTEXT128 NOT NULL,
  idempotency_key KEYTEXT128 NOT NULL,
  expected_digest KEYTEXT128,
  expected_size INTEGER,
  maximum_size INTEGER NOT NULL,
  uploaded_size INTEGER NOT NULL DEFAULT 0,
  -- The first accepted PATCH freezes one exact staging placement. Canonical
  -- materialization is frozen separately when finalization is claimed. Each
  -- binding revision is immutable and pins the exact credential generation;
  -- recovery therefore remains possible after placement authority moves.
  staging_placement_id INTEGER,
  staging_placement_resource_version INTEGER,
  staging_binding_id INTEGER,
  staging_binding_write_revision INTEGER,
  final_digest KEYTEXT128,
  materialization_placement_id INTEGER,
  materialization_placement_resource_version INTEGER,
  materialization_binding_id INTEGER,
  materialization_binding_write_revision INTEGER,
  -- Portable SHA-256 continuation state. Words are stored as unsigned values
  -- in non-negative SQL integers; total_bytes includes the pending tail.
  sha256_state_version INTEGER NOT NULL,
  sha256_h0 INTEGER NOT NULL,
  sha256_h1 INTEGER NOT NULL,
  sha256_h2 INTEGER NOT NULL,
  sha256_h3 INTEGER NOT NULL,
  sha256_h4 INTEGER NOT NULL,
  sha256_h5 INTEGER NOT NULL,
  sha256_h6 INTEGER NOT NULL,
  sha256_h7 INTEGER NOT NULL,
  sha256_total_bytes INTEGER NOT NULL,
  sha256_tail_hex KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  cleanup_state KEYTEXT16 NOT NULL DEFAULT 'none',
  cleanup_finished_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, writer_id, idempotency_key),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(staging_placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id) ON DELETE RESTRICT,
  FOREIGN KEY(staging_binding_id, staging_binding_write_revision)
  REFERENCES binding_write_revisions(binding_id, revision) ON DELETE RESTRICT,
  FOREIGN KEY(materialization_placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id) ON DELETE RESTRICT,
  FOREIGN KEY(materialization_binding_id, materialization_binding_write_revision)
  REFERENCES binding_write_revisions(binding_id, revision) ON DELETE RESTRICT,
  CHECK(expected_size IS NULL OR expected_size >= 0),
  CHECK(maximum_size >= 0),
  CHECK(expected_size IS NULL OR expected_size <= maximum_size),
  CHECK(uploaded_size >= 0),
  CHECK(uploaded_size <= maximum_size),
  CHECK((staging_placement_id IS NULL AND staging_placement_resource_version IS NULL
         AND staging_binding_id IS NULL AND staging_binding_write_revision IS NULL)
     OR (staging_placement_id IS NOT NULL AND staging_placement_resource_version >= 1
         AND staging_binding_id IS NOT NULL AND staging_binding_write_revision >= 1)),
  CHECK((materialization_placement_id IS NULL
         AND materialization_placement_resource_version IS NULL
         AND materialization_binding_id IS NULL
         AND materialization_binding_write_revision IS NULL)
     OR (materialization_placement_id IS NOT NULL
         AND materialization_placement_resource_version >= 1
         AND materialization_binding_id IS NOT NULL
         AND materialization_binding_write_revision >= 1)),
  CHECK(sha256_state_version = 1),
  CHECK(sha256_h0 >= 0 AND sha256_h0 <= 4294967295),
  CHECK(sha256_h1 >= 0 AND sha256_h1 <= 4294967295),
  CHECK(sha256_h2 >= 0 AND sha256_h2 <= 4294967295),
  CHECK(sha256_h3 >= 0 AND sha256_h3 <= 4294967295),
  CHECK(sha256_h4 >= 0 AND sha256_h4 <= 4294967295),
  CHECK(sha256_h5 >= 0 AND sha256_h5 <= 4294967295),
  CHECK(sha256_h6 >= 0 AND sha256_h6 <= 4294967295),
  CHECK(sha256_h7 >= 0 AND sha256_h7 <= 4294967295),
  CHECK(sha256_total_bytes >= 0),
  CHECK(length(sha256_tail_hex) <= 126),
  CHECK(state IN('active', 'completing', 'complete', 'cancelled', 'failed')),
  CHECK(cleanup_state IN('none', 'pending', 'complete')),
  CHECK((cleanup_state = 'complete' AND cleanup_finished_at IS NOT NULL)
     OR (cleanup_state <> 'complete' AND cleanup_finished_at IS NULL))
);
CREATE INDEX oci_upload_sessions_expiry_idx ON oci_upload_sessions(state, expires_at);
CREATE INDEX oci_upload_sessions_cleanup_idx
ON oci_upload_sessions(cleanup_state, finished_at, id);

-- PATCH bodies become immutable staging objects. Appending only records a new
-- row; retries must reproduce every identity column and never overwrite one.
CREATE TABLE oci_upload_chunks(
  upload_id KEYTEXT64 NOT NULL REFERENCES oci_upload_sessions(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  byte_offset INTEGER NOT NULL,
  byte_size INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  staging_object_key KEYTEXT512 NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(upload_id, ordinal),
  UNIQUE(upload_id, byte_offset),
  UNIQUE(staging_object_key),
  CHECK(ordinal >= 0),
  CHECK(byte_offset >= 0),
  CHECK(byte_size > 0)
);

-- A registry/digest claim serializes concurrent finalization. The winner may
-- materialize the blob row; losers wait for that immutable identity and then
-- release their own quota reservation as deduplicated work.
CREATE TABLE oci_blob_claims(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  digest KEYTEXT128 NOT NULL,
  upload_id KEYTEXT64 NOT NULL UNIQUE REFERENCES oci_upload_sessions(id) ON DELETE CASCADE,
  claimed_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, digest)
);
