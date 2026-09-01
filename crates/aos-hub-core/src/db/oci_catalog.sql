-- OCI container catalog and lifecycle state (RFC-0017).
--
-- Repository names are local to one AOS registry. Immutable object bytes live
-- in the registry surface at oci/blobs/sha256/<digest>; SQL retains only
-- bounded projections, reachability, mutable tags, and lifecycle state.

-- The squashed routes table predates OCI. Keeping the new capability in a
-- side table avoids a non-portable table rebuild solely to widen the legacy
-- routes audience CHECK constraint.
CREATE TABLE route_oci_capabilities(
  -- Route ids in an already-migrated MySQL v19 database use the historical
  -- VARCHAR representation, while new byte-exact keys use VARBINARY. The
  -- topology transaction explicitly deletes this side row with its route, so
  -- avoiding a cross-version textual FK preserves forward compatibility
  -- without weakening route mutation atomicity.
  route_id KEYTEXT64 PRIMARY KEY,
  serves_web INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  CHECK(serves_web IN(0, 1))
);

CREATE TABLE oci_repositories(
  id INTEGER PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  name KEYTEXT255 NOT NULL,
  visibility KEYTEXT16 NOT NULL DEFAULT 'inherit',
  lifecycle_state KEYTEXT16 NOT NULL DEFAULT 'active',
  resource_version INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(registry_id, name),
  UNIQUE(id, registry_id),
  -- Container repositories inherit their owning AOS registry's visibility;
  -- repository-local overrides would otherwise bypass registry-scoped auth.
  CHECK(visibility = 'inherit'),
  CHECK(lifecycle_state IN('active', 'deleting', 'deleted'))
);

CREATE TABLE oci_blobs(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  digest KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  surface_object_id INTEGER NOT NULL,
  quota_bytes INTEGER NOT NULL,
  lifecycle_state KEYTEXT16 NOT NULL DEFAULT 'active',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, digest),
  UNIQUE(surface_object_id, registry_id),
  FOREIGN KEY(surface_object_id, registry_id)
  REFERENCES surface_objects(id, registry_id) ON DELETE RESTRICT,
  CHECK(byte_size >= 0),
  CHECK(quota_bytes = byte_size),
  CHECK(lifecycle_state IN('active', 'tombstoned', 'deleting'))
);
CREATE INDEX oci_blobs_surface_object_idx
ON oci_blobs(surface_object_id, registry_id);

CREATE TABLE oci_repository_objects(
  repository_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  object_kind KEYTEXT16 NOT NULL,
  linked_at INTEGER NOT NULL,
  PRIMARY KEY(repository_id, digest),
  UNIQUE(registry_id, repository_id, digest),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, digest)
  REFERENCES oci_blobs(registry_id, digest) ON DELETE RESTRICT,
  CHECK(object_kind IN('blob', 'manifest'))
);
CREATE INDEX oci_repository_objects_digest_idx
ON oci_repository_objects(registry_id, digest, repository_id);

CREATE TABLE oci_manifests(
  registry_id INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  schema_version INTEGER NOT NULL,
  artifact_type KEYTEXT128,
  subject_digest KEYTEXT128,
  config_digest KEYTEXT128,
  platform_os KEYTEXT32,
  platform_architecture KEYTEXT32,
  platform_variant KEYTEXT32,
  annotations_json LONGTEXT NOT NULL DEFAULT ('{}'),
  descriptor_count INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, digest),
  FOREIGN KEY(registry_id, digest)
  REFERENCES oci_blobs(registry_id, digest) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, subject_digest)
  REFERENCES oci_blobs(registry_id, digest) ON DELETE RESTRICT,
  FOREIGN KEY(registry_id, config_digest)
  REFERENCES oci_blobs(registry_id, digest) ON DELETE RESTRICT,
  CHECK(byte_size >= 0),
  CHECK(schema_version = 2),
  CHECK(descriptor_count >= 0 AND descriptor_count <= 1024)
);
CREATE INDEX oci_manifests_subject_idx
ON oci_manifests(registry_id, subject_digest, digest);

CREATE TABLE oci_descriptor_edges(
  registry_id INTEGER NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  edge_role KEYTEXT16 NOT NULL,
  ordinal INTEGER NOT NULL,
  target_digest KEYTEXT128 NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  platform_os KEYTEXT32,
  platform_architecture KEYTEXT32,
  platform_variant KEYTEXT32,
  annotations_json LONGTEXT NOT NULL DEFAULT ('{}'),
  PRIMARY KEY(registry_id, manifest_digest, edge_role, ordinal),
  FOREIGN KEY(registry_id, manifest_digest)
  REFERENCES oci_manifests(registry_id, digest) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, target_digest)
  REFERENCES oci_blobs(registry_id, digest) ON DELETE RESTRICT,
  CHECK(edge_role IN('config', 'layer', 'child', 'subject', 'payload')),
  CHECK(ordinal >= 0),
  CHECK(byte_size >= 0)
);
CREATE INDEX oci_descriptor_edges_target_idx
ON oci_descriptor_edges(registry_id, target_digest, manifest_digest);

CREATE TABLE oci_tags(
  repository_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  name KEYTEXT128 NOT NULL,
  digest KEYTEXT128 NOT NULL,
  source_kind KEYTEXT16 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(repository_id, name),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE RESTRICT,
  CHECK(source_kind IN('manual', 'release', 'channel'))
);
CREATE INDEX oci_tags_digest_idx
ON oci_tags(registry_id, repository_id, digest);

CREATE TABLE oci_tag_history(
  id KEYTEXT64 PRIMARY KEY,
  repository_id INTEGER NOT NULL,
  registry_id INTEGER NOT NULL,
  name KEYTEXT128 NOT NULL,
  prior_digest KEYTEXT128,
  next_digest KEYTEXT128,
  source_kind KEYTEXT16 NOT NULL,
  actor_id KEYTEXT128 NOT NULL,
  changed_at INTEGER NOT NULL,
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  CHECK(prior_digest IS NOT NULL OR next_digest IS NOT NULL),
  CHECK(source_kind IN('manual', 'release', 'channel', 'retention'))
);
CREATE INDEX oci_tag_history_repository_idx
ON oci_tag_history(repository_id, changed_at, id);

CREATE TABLE oci_release_roots(
  registry_id INTEGER NOT NULL,
  release_id INTEGER NOT NULL,
  release_tag KEYTEXT255 NOT NULL,
  repository_id INTEGER NOT NULL,
  container_name KEYTEXT128 NOT NULL,
  index_digest KEYTEXT128 NOT NULL,
  source_commit KEYTEXT128 NOT NULL,
  verified_tag_oid KEYTEXT128 NOT NULL,
  catalog_digest KEYTEXT128 NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, release_tag, repository_id, container_name),
  FOREIGN KEY(release_id, registry_id)
  REFERENCES releases(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, index_digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE RESTRICT
);
CREATE INDEX oci_release_roots_digest_idx
ON oci_release_roots(registry_id, index_digest);

CREATE TABLE oci_publications(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  repository_id INTEGER NOT NULL,
  target_tag KEYTEXT128,
  root_digest KEYTEXT128 NOT NULL,
  source_kind KEYTEXT16 NOT NULL,
  state KEYTEXT16 NOT NULL,
  idempotency_key KEYTEXT128 NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  committed_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, idempotency_key),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  CHECK(source_kind IN('manual', 'release')),
  CHECK(state IN('preparing', 'committing', 'ready', 'aborted', 'failed'))
);

CREATE TABLE oci_uploads(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  repository_id INTEGER NOT NULL,
  publication_id KEYTEXT64 REFERENCES oci_publications(id) ON DELETE CASCADE,
  expected_digest KEYTEXT128,
  expected_size INTEGER,
  uploaded_size INTEGER NOT NULL DEFAULT 0,
  sha256_state LONGTEXT NOT NULL,
  backend_upload_id KEYTEXT512,
  state KEYTEXT16 NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  CHECK(expected_size IS NULL OR expected_size >= 0),
  CHECK(uploaded_size >= 0),
  CHECK(state IN('active', 'completing', 'complete', 'cancelled', 'failed'))
);
CREATE INDEX oci_uploads_expiry_idx ON oci_uploads(state, expires_at);

CREATE TABLE oci_retention_policies(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  untagged_grace_seconds INTEGER NOT NULL,
  tag_history_limit INTEGER NOT NULL,
  retain_referrers INTEGER NOT NULL DEFAULT 1,
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  CHECK(untagged_grace_seconds >= 0),
  CHECK(tag_history_limit >= 0),
  CHECK(retain_referrers IN(0, 1))
);

CREATE TABLE oci_leases(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  lease_kind KEYTEXT16 NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(registry_id, digest)
  REFERENCES oci_blobs(registry_id, digest) ON DELETE CASCADE,
  CHECK(lease_kind IN('pull', 'upload', 'publication', 'operator'))
);
CREATE INDEX oci_leases_digest_idx
ON oci_leases(registry_id, digest, expires_at);

CREATE TABLE oci_gc_generations(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  captured_mutation_epoch INTEGER NOT NULL,
  placement_inventory_digest KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL,
  plan_digest KEYTEXT128,
  planned_bytes INTEGER NOT NULL DEFAULT 0,
  planned_objects INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  CHECK(captured_mutation_epoch >= 0),
  CHECK(planned_bytes >= 0 AND planned_objects >= 0),
  CHECK(state IN('marking', 'planned', 'applying', 'complete', 'aborted', 'failed'))
);
CREATE INDEX oci_gc_generations_registry_idx
ON oci_gc_generations(registry_id, created_at);

CREATE TABLE oci_registry_state(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  mutation_epoch INTEGER NOT NULL DEFAULT 0,
  charged_bytes INTEGER NOT NULL DEFAULT 0,
  charged_objects INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  CHECK(mutation_epoch >= 0),
  CHECK(charged_bytes >= 0 AND charged_objects >= 0)
);
