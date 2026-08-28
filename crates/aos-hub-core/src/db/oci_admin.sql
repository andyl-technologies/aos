-- Phase 6 OCI administration read models and durable mutation plans.
--
-- Repository visibility deliberately remains absent here: every OCI
-- repository inherits its owning registry's visibility and authorization
-- scope. Metadata is mutable presentation state only.
CREATE TABLE oci_repository_metadata(
  repository_id INTEGER PRIMARY KEY,
  registry_id INTEGER NOT NULL,
  description LONGTEXT NOT NULL DEFAULT (''),
  resource_version INTEGER NOT NULL DEFAULT 1,
  updated_at INTEGER NOT NULL,
  UNIQUE(registry_id, repository_id),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  CHECK(resource_version >= 1),
  CHECK(length(description) <= 4096)
);

-- Backfill one metadata/version row for every repository created before v22.
-- MySQL migration replay rewrites this to INSERT IGNORE; the other engines
-- apply the whole migration atomically.
INSERT INTO oci_repository_metadata(
  repository_id, registry_id, description, resource_version, updated_at
)
SELECT repository.id, repository.registry_id, '', 1, repository.updated_at
FROM oci_repositories repository
WHERE NOT EXISTS (
  SELECT 1 FROM oci_repository_metadata metadata
  WHERE metadata.repository_id = repository.id
);

-- v20 retained only a tag's last-update stamp. Administration distinguishes
-- creation from later signed/manual moves, so v22 backfills the immutable
-- creation stamp and all new catalog writers populate it explicitly.
ALTER TABLE oci_tags ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
UPDATE oci_tags SET created_at = updated_at WHERE created_at = 0;

-- History resource versions are per-tag monotonic transition ordinals. They
-- remain meaningful across delete/recreate cycles, unlike the live pointer's
-- optimistic version, and never expose an internal UUID as a version token.
ALTER TABLE oci_tag_history
ADD COLUMN tag_resource_version INTEGER NOT NULL DEFAULT 1;
UPDATE oci_tag_history
SET tag_resource_version = (
  SELECT ranked.transition_version FROM (
    SELECT candidate.id,
      (SELECT COUNT(*) FROM oci_tag_history prior
       WHERE prior.repository_id = candidate.repository_id
         AND prior.name = candidate.name
         AND (prior.changed_at < candidate.changed_at
           OR (prior.changed_at = candidate.changed_at
             AND prior.id <= candidate.id))) AS transition_version
    FROM oci_tag_history candidate
  ) ranked
  WHERE ranked.id = oci_tag_history.id
);

-- Keep all four retention controls distinct. The historical
-- tag_history_limit becomes the initial recent-manual-revision policy. Fail
-- closed before narrowing it to the bounded administration contract.
CREATE TABLE oci_admin_retention_upgrade_guard(
  invalid_count INTEGER NOT NULL CHECK(invalid_count = 0)
);
INSERT INTO oci_admin_retention_upgrade_guard(invalid_count)
SELECT COUNT(*) FROM oci_retention_policies
WHERE tag_history_limit < 0 OR tag_history_limit > 1000000;
ALTER TABLE oci_retention_policies
ADD COLUMN deleted_tag_history_seconds INTEGER NOT NULL DEFAULT 2592000;
ALTER TABLE oci_retention_policies
ADD COLUMN recent_manual_tag_revisions INTEGER NOT NULL DEFAULT 10;
UPDATE oci_retention_policies
SET recent_manual_tag_revisions = tag_history_limit;
DROP TABLE oci_admin_retention_upgrade_guard;

-- v20/v21 retained only the coarse Go OS/architecture/variant tuple. Preserve
-- the complete OCI selector for new admission and exact-byte reconciliation.
ALTER TABLE oci_manifests ADD COLUMN platform_os_version KEYTEXT512;
ALTER TABLE oci_manifests
ADD COLUMN platform_os_features_json LONGTEXT NOT NULL DEFAULT ('[]');
ALTER TABLE oci_descriptor_edges ADD COLUMN platform_os_version KEYTEXT512;
ALTER TABLE oci_descriptor_edges
ADD COLUMN platform_os_features_json LONGTEXT NOT NULL DEFAULT ('[]');

-- Parsed image configuration and independently verified layer measurements.
-- Exact source bytes remain in the immutable object plane; config_json is the
-- bounded exact JSON projection used for operator inspection.
CREATE TABLE oci_image_config_projections(
  registry_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  root_digest KEYTEXT128 NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  config_digest KEYTEXT128 NOT NULL,
  operating_system KEYTEXT32 NOT NULL,
  architecture KEYTEXT32 NOT NULL,
  variant KEYTEXT32,
  os_version KEYTEXT512,
  os_features_json LONGTEXT NOT NULL DEFAULT ('[]'),
  aos_system KEYTEXT64 NOT NULL,
  compressed_byte_size INTEGER NOT NULL,
  unpacked_byte_size INTEGER NOT NULL,
  layer_count INTEGER NOT NULL,
  config_json LONGTEXT NOT NULL,
  verified_at INTEGER NOT NULL,
  PRIMARY KEY(repository_id, root_digest, manifest_digest),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, manifest_digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, config_digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE RESTRICT,
  CHECK(compressed_byte_size >= 0),
  CHECK(unpacked_byte_size >= 0),
  CHECK(layer_count >= 0 AND layer_count <= 64),
  CHECK(length(config_json) <= 4194304),
  CHECK(length(os_features_json) <= 4096)
);
CREATE INDEX oci_image_config_platform_idx
ON oci_image_config_projections(
  registry_id, repository_id, root_digest,
  operating_system, architecture, variant
);

CREATE TABLE oci_release_layers(
  registry_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  root_digest KEYTEXT128 NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  ordinal INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  compressed_byte_size INTEGER NOT NULL,
  unpacked_byte_size INTEGER NOT NULL,
  diff_id KEYTEXT128 NOT NULL,
  closure_group KEYTEXT128 NOT NULL DEFAULT (''),
  verified_at INTEGER NOT NULL,
  PRIMARY KEY(repository_id, root_digest, manifest_digest, ordinal),
  UNIQUE(repository_id, root_digest, manifest_digest, digest),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE RESTRICT,
  CHECK(ordinal >= 0 AND ordinal < 64),
  CHECK(compressed_byte_size >= 0),
  CHECK(unpacked_byte_size >= 0)
);
CREATE INDEX oci_release_layers_digest_idx
ON oci_release_layers(registry_id, digest, repository_id);

-- v20/v21 did not retain config JSON, DiffIDs, or unpacked layer sizes in SQL.
-- Queue every legacy runnable root for exact-byte reconciliation by the
-- authoritative placement indexer. Readers never synthesize these fields;
-- admission deletes a row only after committing the complete projection.
CREATE TABLE oci_admin_projection_reconciliations(
  registry_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  root_digest KEYTEXT128 NOT NULL,
  manifest_digest KEYTEXT128 NOT NULL,
  config_digest KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL DEFAULT ('pending'),
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error LONGTEXT,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, repository_id, root_digest, manifest_digest),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, manifest_digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, config_digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE RESTRICT,
  CHECK(state IN('pending', 'failed')),
  CHECK(attempts >= 0)
);
CREATE INDEX oci_admin_projection_reconcile_idx
ON oci_admin_projection_reconciliations(registry_id, state, root_digest);

INSERT INTO oci_admin_projection_reconciliations(
  registry_id, repository_id, root_digest, manifest_digest, config_digest,
  state, attempts, last_error, updated_at
)
SELECT link.registry_id, link.repository_id, manifest.digest, manifest.digest,
       manifest.config_digest, 'pending', 0, NULL, manifest.created_at
FROM oci_repository_objects link
JOIN oci_manifests manifest
  ON manifest.registry_id = link.registry_id AND manifest.digest = link.digest
WHERE link.object_kind = 'manifest' AND manifest.artifact_type IS NULL
  AND manifest.config_digest IS NOT NULL
  AND NOT EXISTS (
    SELECT 1 FROM oci_admin_projection_reconciliations existing
    WHERE existing.registry_id = link.registry_id
      AND existing.repository_id = link.repository_id
      AND existing.root_digest = manifest.digest
      AND existing.manifest_digest = manifest.digest
  );

INSERT INTO oci_admin_projection_reconciliations(
  registry_id, repository_id, root_digest, manifest_digest, config_digest,
  state, attempts, last_error, updated_at
)
SELECT root.registry_id, root.repository_id, root.digest, child.digest,
       child.config_digest, 'pending', 0, NULL, child.created_at
FROM oci_repository_objects root
JOIN oci_manifests root_manifest
  ON root_manifest.registry_id = root.registry_id
 AND root_manifest.digest = root.digest
JOIN oci_descriptor_edges edge
  ON edge.registry_id = root.registry_id
 AND edge.manifest_digest = root.digest AND edge.edge_role = 'child'
JOIN oci_manifests child
  ON child.registry_id = edge.registry_id AND child.digest = edge.target_digest
WHERE root.object_kind = 'manifest' AND root_manifest.config_digest IS NULL
  AND child.artifact_type IS NULL AND child.config_digest IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM oci_repository_objects child_link
    WHERE child_link.registry_id = root.registry_id
      AND child_link.repository_id = root.repository_id
      AND child_link.digest = child.digest
  )
  AND NOT EXISTS (
    SELECT 1 FROM oci_admin_projection_reconciliations existing
    WHERE existing.registry_id = root.registry_id
      AND existing.repository_id = root.repository_id
      AND existing.root_digest = root.digest
      AND existing.manifest_digest = child.digest
  );

-- Signed source identity and its complete verified evidence set. These rows
-- are replaced atomically with the release index snapshot and never inferred
-- from tag spelling by an administration reader.
CREATE TABLE oci_release_provenance(
  registry_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  root_digest KEYTEXT128 NOT NULL,
  package_name KEYTEXT128 NOT NULL,
  release_tag KEYTEXT255 NOT NULL,
  channel_name KEYTEXT128,
  signed_release_root KEYTEXT128 NOT NULL,
  catalog_digest KEYTEXT128 NOT NULL,
  verification KEYTEXT16 NOT NULL,
  verified_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, repository_id, root_digest, release_tag),
  FOREIGN KEY(repository_id, registry_id)
  REFERENCES oci_repositories(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(registry_id, repository_id, root_digest)
  REFERENCES oci_repository_objects(registry_id, repository_id, digest)
  ON DELETE RESTRICT,
  CHECK(verification IN('verified', 'invalid'))
);

CREATE TABLE oci_release_closure_members(
  registry_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  root_digest KEYTEXT128 NOT NULL,
  release_tag KEYTEXT255 NOT NULL,
  store_path KEYTEXT512 NOT NULL,
  nar_hash KEYTEXT128 NOT NULL,
  nar_size INTEGER NOT NULL,
  layer_digest KEYTEXT128 NOT NULL,
  is_direct INTEGER NOT NULL,
  PRIMARY KEY(registry_id, repository_id, root_digest, release_tag, store_path),
  FOREIGN KEY(registry_id, repository_id, root_digest, release_tag)
  REFERENCES oci_release_provenance(
    registry_id, repository_id, root_digest, release_tag
  )
  ON DELETE CASCADE,
  CHECK(nar_size >= 0),
  CHECK(is_direct IN(0, 1))
);

CREATE TABLE oci_release_evidence(
  registry_id INTEGER NOT NULL,
  repository_id INTEGER NOT NULL,
  root_digest KEYTEXT128 NOT NULL,
  release_tag KEYTEXT255 NOT NULL,
  evidence_kind KEYTEXT32 NOT NULL,
  digest KEYTEXT128 NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  verification KEYTEXT16 NOT NULL,
  referrer_digest KEYTEXT128 NOT NULL,
  PRIMARY KEY(registry_id, repository_id, root_digest, release_tag, evidence_kind),
  FOREIGN KEY(registry_id, repository_id, root_digest, release_tag)
  REFERENCES oci_release_provenance(
    registry_id, repository_id, root_digest, release_tag
  )
  ON DELETE CASCADE,
  CHECK(verification IN('verified', 'invalid'))
);

-- Plans are system-of-record audit facts. A plan freezes canonical selector
-- and desired-state JSON plus its optimistic precondition. Applying it records
-- the winning retry key rather than deleting the review evidence.
CREATE TABLE oci_admin_mutations(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  repository_id INTEGER,
  repository_name KEYTEXT128,
  mutation_kind KEYTEXT32 NOT NULL,
  selector_json LONGTEXT NOT NULL,
  desired_json LONGTEXT NOT NULL,
  confirmation_hash KEYTEXT128 NOT NULL,
  actor_id KEYTEXT128 NOT NULL,
  idempotency_key KEYTEXT128 NOT NULL,
  apply_idempotency_key KEYTEXT128,
  expected_resource_version INTEGER,
  state KEYTEXT16 NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  applied_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, actor_id, idempotency_key),
  CHECK(mutation_kind IN(
    'repository.create', 'repository.update', 'repository.delete',
    'tag.set', 'tag.unset', 'retention.set'
  )),
  CHECK((repository_id IS NULL AND mutation_kind IN('repository.create', 'retention.set'))
     OR repository_id IS NOT NULL),
  CHECK((repository_name IS NULL AND mutation_kind = 'retention.set')
     OR repository_name IS NOT NULL),
  CHECK(expected_resource_version IS NULL OR expected_resource_version >= 1),
  CHECK(state IN('planned', 'applied', 'aborted')),
  CHECK(expires_at > created_at),
  CHECK(resource_version >= 1)
);
CREATE INDEX oci_admin_mutations_registry_idx
ON oci_admin_mutations(registry_id, created_at, id);

-- Administration list paths use deterministic, bytewise keysets. These
-- indexes keep every page bounded on SQLite, PostgreSQL, MySQL, and HubDb.
CREATE INDEX oci_repositories_admin_list_idx
ON oci_repositories(registry_id, lifecycle_state, name, id);
CREATE INDEX oci_tag_history_admin_list_idx
ON oci_tag_history(registry_id, repository_id, name, changed_at, id);
CREATE INDEX oci_publications_admin_list_idx
ON oci_publication_sessions(registry_id, created_at, id);
CREATE INDEX oci_release_roots_admin_list_idx
ON oci_release_roots(registry_id, repository_id, created_at, release_tag);
