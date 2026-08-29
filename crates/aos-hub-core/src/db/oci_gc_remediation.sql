-- Phase 7 adversarial-review remediation.
--
-- Unknown upgrade history is deliberately represented by NULL
-- `unreferenced_since`. The bounded reconciliation path stamps the first
-- authoritative observation time; it never infers an earlier deadline from
-- immutable creation time.

ALTER TABLE oci_blobs ADD COLUMN unreferenced_since INTEGER;

CREATE INDEX oci_blobs_gc_eligibility_idx
ON oci_blobs(registry_id, lifecycle_state, unreferenced_since, digest);

-- Purge is a two-stage operation. Once the fence exists every Hub writer is
-- rejected, and each provider placement must publish a complete enumeration
-- captured after this exact fence before registry identity can be removed.
CREATE TABLE oci_registry_purge_fences(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  actor_id KEYTEXT128 NOT NULL,
  idempotency_key KEYTEXT128 NOT NULL,
  registry_resource_version INTEGER NOT NULL,
  captured_mutation_epoch INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  created_at INTEGER NOT NULL,
  aborted_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, actor_id, idempotency_key),
  CHECK(registry_resource_version >= 1),
  CHECK(captured_mutation_epoch >= 0),
  CHECK(state IN('collecting', 'aborted')),
  CHECK((state = 'collecting' AND aborted_at IS NULL)
    OR (state = 'aborted' AND aborted_at IS NOT NULL)),
  CHECK(resource_version >= 1)
);

-- Beginning or aborting the durable purge/write fence is itself reviewed.
-- The applied plan remains actor/idempotency evidence after the current fence
-- is replaced or the registry is finally deleted.
CREATE TABLE oci_registry_purge_fence_plans(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  action KEYTEXT16 NOT NULL,
  actor_id KEYTEXT128 NOT NULL,
  plan_idempotency_key KEYTEXT128 NOT NULL,
  apply_idempotency_key KEYTEXT128,
  expected_resource_version INTEGER NOT NULL,
  captured_mutation_epoch INTEGER NOT NULL,
  confirmation_hash KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  applied_at INTEGER,
  finished_at INTEGER,
  last_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, actor_id, plan_idempotency_key),
  CHECK(action IN('begin', 'abort')),
  CHECK(expected_resource_version >= 1),
  CHECK(captured_mutation_epoch >= 0),
  CHECK(state IN('planned', 'applied', 'failed')),
  CHECK(expires_at > created_at),
  CHECK(resource_version >= 1)
);
CREATE INDEX oci_registry_purge_fence_plans_state_idx
ON oci_registry_purge_fence_plans(state, expires_at, id);

ALTER TABLE oci_provider_inventory_generations
ADD COLUMN purge_fence_resource_version INTEGER;

-- Untracked provider entries require a reviewed operation before physical
-- deletion or adoption. Plans freeze the complete inventory and topology
-- identity; response-loss replay is actor and request bound.
CREATE TABLE oci_untracked_repair_plans(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  placement_id INTEGER NOT NULL,
  placement_name KEYTEXT128 NOT NULL,
  placement_prefix KEYTEXT512 NOT NULL,
  placement_resource_version INTEGER NOT NULL,
  placement_write_spec_version INTEGER NOT NULL,
  placement_observation_version INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  binding_write_revision INTEGER NOT NULL,
  delete_credential_purpose KEYTEXT16,
  delete_credential_generation INTEGER,
  delete_capability_fingerprint KEYTEXT128 NOT NULL,
  delete_capability_resource_version INTEGER NOT NULL,
  inventory_generation_id KEYTEXT64 NOT NULL,
  inventory_digest KEYTEXT128 NOT NULL,
  inventory_observed_at INTEGER NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  object_digest KEYTEXT128 NOT NULL,
  observed_hash KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  strong_etag KEYTEXT512 NOT NULL,
  repair_kind KEYTEXT16 NOT NULL,
  adopt_media_type KEYTEXT128,
  actor_id KEYTEXT128 NOT NULL,
  plan_idempotency_key KEYTEXT128 NOT NULL,
  apply_idempotency_key KEYTEXT128,
  captured_mutation_epoch INTEGER NOT NULL,
  confirmation_hash KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL,
  worker_id KEYTEXT128,
  claim_token KEYTEXT64,
  lease_expires_at INTEGER,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 8,
  next_attempt_at INTEGER NOT NULL,
  response_idempotency_key KEYTEXT128,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  applied_at INTEGER,
  finished_at INTEGER,
  last_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, actor_id, plan_idempotency_key),
  UNIQUE(id, registry_id),
  FOREIGN KEY(inventory_generation_id, registry_id, placement_id)
  REFERENCES oci_provider_inventory_generations(id, registry_id, placement_id)
  ON DELETE RESTRICT,
  CHECK(byte_size >= 0),
  CHECK(placement_resource_version >= 1),
  CHECK(placement_write_spec_version >= 1),
  CHECK(placement_observation_version >= 1),
  CHECK(binding_resource_version >= 1),
  CHECK(binding_write_revision >= 1),
  CHECK(delete_capability_resource_version >= 1),
  CHECK((delete_credential_purpose IS NULL AND delete_credential_generation IS NULL)
    OR (delete_credential_purpose = 'delete' AND delete_credential_generation >= 1)),
  CHECK(repair_kind IN('delete', 'adopt')),
  CHECK((repair_kind = 'delete' AND adopt_media_type IS NULL)
    OR (repair_kind = 'adopt' AND adopt_media_type IS NOT NULL)),
  CHECK(captured_mutation_epoch >= 0),
  CHECK(state IN('planned', 'pending', 'claimed', 'confirmed_absent',
                 'adopted', 'failed', 'aborted')),
  CHECK(expires_at > created_at),
  CHECK(attempt_count >= 0 AND max_attempts >= 1),
  CHECK((state = 'claimed' AND worker_id IS NOT NULL AND claim_token IS NOT NULL
      AND lease_expires_at IS NOT NULL)
    OR (state <> 'claimed' AND worker_id IS NULL AND claim_token IS NULL
      AND lease_expires_at IS NULL)),
  CHECK(resource_version >= 1)
);
CREATE INDEX oci_untracked_repairs_state_idx
ON oci_untracked_repair_plans(state, created_at, id);

-- Applied repairs pin the immutable credential generation until the exact
-- provider response is durable. Head rotation remains possible, but retiring
-- the reviewed credential cannot strand a claimed physical action.
CREATE TABLE oci_untracked_repair_credential_holds(
  plan_id KEYTEXT64 NOT NULL
  REFERENCES oci_untracked_repair_plans(id) ON DELETE CASCADE,
  binding_id INTEGER NOT NULL,
  purpose KEYTEXT16 NOT NULL,
  generation INTEGER NOT NULL,
  PRIMARY KEY(plan_id, binding_id, purpose, generation),
  FOREIGN KEY(binding_id, purpose, generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation)
  ON DELETE RESTRICT,
  CHECK(purpose = 'delete'),
  CHECK(generation >= 1)
);

CREATE TABLE oci_untracked_repair_evidence(
  plan_id KEYTEXT64 PRIMARY KEY
  REFERENCES oci_untracked_repair_plans(id) ON DELETE CASCADE,
  outcome KEYTEXT32 NOT NULL,
  provider_request_id KEYTEXT255,
  conditional_etag KEYTEXT512,
  evidence_digest KEYTEXT128 NOT NULL,
  confirmed_at INTEGER NOT NULL,
  CHECK(outcome IN('deleted', 'already_absent', 'adopted')),
  CHECK((outcome = 'deleted' AND conditional_etag IS NOT NULL)
    OR outcome IN('already_absent', 'adopted'))
);
