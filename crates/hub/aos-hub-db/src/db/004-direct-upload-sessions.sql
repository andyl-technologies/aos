-- Logical upload admission belongs to Hub SQL. Provider multipart state,
-- delegated URLs, credentials, bytes and physical uncertainty remain in the
-- independent broker journal. Expiry never removes an occupied logical slot.
CREATE TABLE direct_upload_sessions(
  session_id KEYTEXT64 NOT NULL PRIMARY KEY,
  deployment_id KEYTEXT255 NOT NULL,
  principal_id KEYTEXT255 NOT NULL,
  client_operation_id KEYTEXT64 NOT NULL,
  target_kind KEYTEXT32 NOT NULL,
  cache_id INTEGER REFERENCES binary_caches(id) ON DELETE RESTRICT,
  cache_identifier KEYTEXT255,
  publication_id KEYTEXT64,
  surface_object_id INTEGER,
  oci_upload_id KEYTEXT64 REFERENCES oci_upload_sessions(id) ON DELETE RESTRICT,
  object_path KEYTEXT512,
  owner_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key) ON DELETE RESTRICT,
  intent_json LONGTEXT NOT NULL,
  admission_json LONGTEXT NOT NULL,
  logical_fingerprint KEYTEXT64 NOT NULL,
  source_sha256 KEYTEXT64 NOT NULL,
  declared_size BIGINT NOT NULL,
  part_size BIGINT NOT NULL,
  declared_dependency_phase KEYTEXT16 NOT NULL,
  final_dependency_phase KEYTEXT16,
  cache_ticket_id KEYTEXT64 REFERENCES cache_write_tickets(ticket_id) ON DELETE RESTRICT,
  state KEYTEXT16 NOT NULL,
  expires_at BIGINT NOT NULL,
  created_at BIGINT NOT NULL,
  updated_at BIGINT NOT NULL,
  resource_version BIGINT NOT NULL DEFAULT 1,
  completed_at BIGINT,
  UNIQUE(deployment_id, principal_id, client_operation_id),
  UNIQUE(session_id, deployment_id),
  FOREIGN KEY(publication_id, surface_object_id)
    REFERENCES registry_publication_objects(publication_id, surface_object_id) ON DELETE RESTRICT,
  CHECK(target_kind IN('cache_object', 'publication_object', 'oci_blob')),
  CHECK((target_kind = 'cache_object' AND cache_id IS NOT NULL AND cache_identifier IS NOT NULL
      AND publication_id IS NULL AND surface_object_id IS NULL
      AND oci_upload_id IS NULL AND object_path IS NOT NULL AND cache_ticket_id IS NOT NULL)
    OR (target_kind = 'publication_object' AND cache_id IS NULL AND cache_identifier IS NULL
      AND publication_id IS NOT NULL AND surface_object_id IS NOT NULL
      AND oci_upload_id IS NULL AND object_path IS NOT NULL AND cache_ticket_id IS NULL)
    OR (target_kind = 'oci_blob' AND cache_id IS NULL AND cache_identifier IS NULL
      AND publication_id IS NULL AND surface_object_id IS NULL
      AND oci_upload_id IS NOT NULL AND object_path IS NULL AND cache_ticket_id IS NULL)),
  CHECK(declared_size >= 0 AND declared_size <= 17179869184),
  CHECK(part_size > 0 AND part_size <= 5368709120),
  CHECK(declared_dependency_phase IN('content', 'leaf_metadata', 'visibility')),
  CHECK(final_dependency_phase IS NULL OR final_dependency_phase IN('content', 'leaf_metadata', 'visibility')),
  CHECK(state IN('admitted', 'staged_verified', 'committed', 'abort_pending', 'abort_unknown', 'aborted')),
  CHECK(expires_at > created_at AND updated_at >= created_at AND resource_version > 0),
  CHECK((state = 'committed' AND completed_at IS NOT NULL) OR (state <> 'committed' AND completed_at IS NULL))
);

-- An OCI allocation has one retained direct owner for its entire lifetime;
-- another session cannot release quota still fenced by an uncertain original.
CREATE UNIQUE INDEX direct_upload_sessions_oci_owner
  ON direct_upload_sessions(oci_upload_id);

-- Full immutable placement snapshots are typed/canonical application documents;
-- duplicated scalar pins are checked against them on every load and mutation.
CREATE TABLE direct_upload_session_placements(
  deployment_id KEYTEXT255 NOT NULL,
  session_id KEYTEXT64 NOT NULL ,
  placement_id INTEGER NOT NULL REFERENCES surface_placements(id) ON DELETE RESTRICT,
  placement_resource_version BIGINT NOT NULL,
  write_spec_version BIGINT NOT NULL,
  binding_id INTEGER NOT NULL REFERENCES bindings(id) ON DELETE RESTRICT,
  binding_resource_version BIGINT NOT NULL,
  binding_write_revision BIGINT NOT NULL,
  placement_fingerprint KEYTEXT64 NOT NULL,
  placement_json LONGTEXT NOT NULL,
  PRIMARY KEY(session_id, placement_id),
  FOREIGN KEY(session_id, deployment_id)
    REFERENCES direct_upload_sessions(session_id, deployment_id) ON DELETE RESTRICT,
  CHECK(placement_resource_version > 0 AND write_spec_version > 0
    AND binding_resource_version > 0 AND binding_write_revision > 0)
);

-- The original completion intent is frozen before closing grants or provider
-- staging. Exact replay retains its first CAS version while progress advances;
-- a fresh nonce, batch composition, or clock cannot replace semantic identity.
CREATE TABLE direct_upload_completion_intents(
  deployment_id KEYTEXT255 NOT NULL,
  session_id KEYTEXT64 NOT NULL PRIMARY KEY ,
  operation_id KEYTEXT64 NOT NULL,
  expected_resource_version BIGINT NOT NULL,
  intent_digest KEYTEXT64 NOT NULL,
  intent_json LONGTEXT NOT NULL,
  admitted_at BIGINT NOT NULL,
  FOREIGN KEY(session_id, deployment_id)
    REFERENCES direct_upload_sessions(session_id, deployment_id) ON DELETE RESTRICT,
  CHECK(expected_resource_version > 0 AND admitted_at > 0)
);

-- Abort intent retains its original CAS and operation before any provider
-- effect. Unknown outcomes cannot be replaced by a fresh operation or expiry.
CREATE TABLE direct_upload_abort_intents(
  deployment_id KEYTEXT255 NOT NULL,
  session_id KEYTEXT64 NOT NULL PRIMARY KEY,
  operation_id KEYTEXT64 NOT NULL,
  expected_resource_version BIGINT NOT NULL,
  intent_digest KEYTEXT64 NOT NULL,
  intent_json LONGTEXT NOT NULL,
  admitted_at BIGINT NOT NULL,
  terminal_receipt_digest KEYTEXT64,
  settled_at BIGINT,
  FOREIGN KEY(session_id, deployment_id)
    REFERENCES direct_upload_sessions(session_id, deployment_id) ON DELETE RESTRICT,
  CHECK(expected_resource_version > 0 AND admitted_at > 0),
  CHECK((terminal_receipt_digest IS NULL AND settled_at IS NULL)
    OR (terminal_receipt_digest IS NOT NULL AND settled_at >= admitted_at))
);

-- Verified private staging is reportable before other batches close the
-- publication graph. Retaining this proof does not publish any final key.
CREATE TABLE direct_upload_stage_receipts(
  deployment_id KEYTEXT255 NOT NULL,
  session_id KEYTEXT64 NOT NULL PRIMARY KEY ,
  operation_id KEYTEXT64 NOT NULL,
  logical_fingerprint KEYTEXT64 NOT NULL,
  evidence_digest KEYTEXT64 NOT NULL,
  evidence_json LONGTEXT NOT NULL,
  verified_at BIGINT NOT NULL,
  FOREIGN KEY(session_id, deployment_id)
    REFERENCES direct_upload_sessions(session_id, deployment_id) ON DELETE RESTRICT,
  CHECK(verified_at > 0)
);

-- Immutable first held destination observations and quota activation commit
-- together. Fresh witnesses never overwrite the original observation.
CREATE TABLE direct_upload_baselines(
  deployment_id KEYTEXT255 NOT NULL,
  session_id KEYTEXT64 NOT NULL,
  placement_id INTEGER NOT NULL REFERENCES surface_placements(id) ON DELETE RESTRICT,
  complete_operation_id KEYTEXT64 NOT NULL,
  baseline_digest KEYTEXT64 NOT NULL,
  evidence_json LONGTEXT NOT NULL,
  activated_at BIGINT NOT NULL,
  PRIMARY KEY(session_id, placement_id),
  FOREIGN KEY(session_id, deployment_id)
    REFERENCES direct_upload_sessions(session_id, deployment_id) ON DELETE RESTRICT,
  CHECK(activated_at > 0)
);

-- Only authenticated, independently verified compact completion evidence is
-- retained. The original semantic operation identity survives fresh nonces and
-- exact replay never manufactures a newer provider observation.
CREATE TABLE direct_upload_completion_receipts(
  deployment_id KEYTEXT255 NOT NULL,
  session_id KEYTEXT64 NOT NULL PRIMARY KEY ,
  operation_id KEYTEXT64 NOT NULL,
  logical_fingerprint KEYTEXT64 NOT NULL,
  evidence_digest KEYTEXT64 NOT NULL,
  evidence_json LONGTEXT NOT NULL,
  final_guards_json LONGTEXT NOT NULL,
  committed_at BIGINT NOT NULL,
  resulting_resource_version BIGINT NOT NULL,
  FOREIGN KEY(session_id, deployment_id)
    REFERENCES direct_upload_sessions(session_id, deployment_id) ON DELETE RESTRICT,
  CHECK(committed_at > 0 AND resulting_resource_version > 1)
);

-- Summary rows attest to storage-adjacent semantic inspection. Legacy exact
-- config JSON remains unchanged and is never inferred from a lossy summary.
ALTER TABLE oci_image_config_projections
  ADD COLUMN config_representation KEYTEXT32 NOT NULL DEFAULT 'exact_raw';
ALTER TABLE oci_image_config_projections
  ADD COLUMN config_source_size BIGINT;
ALTER TABLE oci_image_config_projections
  ADD COLUMN config_summary_json LONGTEXT
  CHECK((config_representation = 'exact_raw' AND config_summary_json IS NULL
      AND (config_source_size IS NULL OR (config_source_size > 0 AND config_source_size <= 4194304)))
    OR (config_representation = 'storage_summary_v1' AND config_json = ''
      AND config_source_size IS NOT NULL AND config_source_size > 0
      AND config_source_size <= 4194304 AND config_summary_json IS NOT NULL
      AND config_summary_json <> ''));

-- Principal slots may be recycled by ordinary SQL allocation. A fresh UUID
-- identifies the owner incarnation; direct session IDs commit to that UUID,
-- and the storage-side actor reservation independently retains its numeric slot.
ALTER TABLE users ADD COLUMN principal_incarnation KEYTEXT64
    CHECK(principal_incarnation IS NULL OR LENGTH(principal_incarnation) = 36);
CREATE UNIQUE INDEX users_principal_incarnation ON users(principal_incarnation);

ALTER TABLE service_accounts ADD COLUMN principal_incarnation KEYTEXT64
    CHECK(principal_incarnation IS NULL OR LENGTH(principal_incarnation) = 36);
CREATE UNIQUE INDEX service_accounts_principal_incarnation ON service_accounts(principal_incarnation);

-- Existing unpinned tokens must be reissued. Inferring this field from a later
-- principal with the same numeric ID would revive a removed owner's authority.
ALTER TABLE tokens ADD COLUMN owner_incarnation KEYTEXT64
    CHECK(owner_incarnation IS NULL OR LENGTH(owner_incarnation) = 36);

-- Old unpinned cookies require fresh authentication. A cold session load must
-- never infer its original owner from a later user occupying the same slot.
ALTER TABLE sessions ADD COLUMN owner_incarnation KEYTEXT64
    CHECK(owner_incarnation IS NULL OR LENGTH(owner_incarnation) = 36);

-- Reviewed plans keep the original principal UUID across token rotation and
-- numeric-slot recycling. Legacy unpinned plans must be replanned, not repaired.
ALTER TABLE topology_plans ADD COLUMN actor_incarnation KEYTEXT64
    CHECK(actor_incarnation IS NULL OR LENGTH(actor_incarnation) = 36);

-- Initial empty OCI POST is logical metadata only. Its original owner survives
-- lost replies and token rotation; changed target/content cannot allocate a
-- second session in another registry under the same business operation.
CREATE TABLE direct_oci_allocations(
  business_id KEYTEXT64 NOT NULL PRIMARY KEY,
  deployment_id KEYTEXT255 NOT NULL,
  principal_id KEYTEXT64 NOT NULL,
  client_operation_id KEYTEXT64 NOT NULL,
  actor_kind KEYTEXT32 NOT NULL,
  actor_id INTEGER NOT NULL,
  actor_incarnation KEYTEXT64 NOT NULL,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE RESTRICT,
  registry_stable_id KEYTEXT255 NOT NULL,
  repository_id INTEGER NOT NULL REFERENCES oci_repositories(id) ON DELETE RESTRICT,
  repository_name KEYTEXT255 NOT NULL,
  source_sha256 KEYTEXT64 NOT NULL,
  declared_size BIGINT NOT NULL,
  upload_id KEYTEXT64 NOT NULL,
  original_token_id KEYTEXT64 NOT NULL,
  created_at BIGINT NOT NULL,
  UNIQUE(deployment_id, principal_id, client_operation_id),
  CHECK(actor_kind IN('user', 'service_account') AND actor_id > 0),
  CHECK(LENGTH(actor_incarnation) = 36),
  CHECK(declared_size >= 0 AND declared_size <= 17179869184),
  CHECK(created_at > 0)
);

-- Storage-local verification is distinct from Native streamed SHA continuation.
-- Only the final direct transaction records this source identity; no bulk bytes
-- or fabricated resumable hashing state enter Native SQL.
ALTER TABLE oci_upload_sessions ADD COLUMN authenticated_source_sha256 KEYTEXT64
    CHECK(authenticated_source_sha256 IS NULL OR LENGTH(authenticated_source_sha256) = 64);
ALTER TABLE oci_upload_sessions ADD COLUMN authenticated_source_bytes BIGINT
    CHECK(authenticated_source_bytes IS NULL OR authenticated_source_bytes >= 0);
