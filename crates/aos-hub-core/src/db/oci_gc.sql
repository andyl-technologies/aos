-- Phase 7 transactional OCI retention and physical-deletion evidence.
--
-- The frozen v20 `oci_gc_generations` placeholder remains unused. These v23
-- tables use distinct names so MySQL can replay every implicitly committed
-- DDL statement after a crash without interpreting an incomplete old row.

CREATE TABLE oci_conditional_delete_capabilities(
  binding_id INTEGER NOT NULL,
  binding_write_revision INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  delete_credential_purpose KEYTEXT16,
  delete_credential_generation INTEGER,
  capability_fingerprint KEYTEXT128 NOT NULL,
  state KEYTEXT16 NOT NULL,
  resource_version INTEGER NOT NULL DEFAULT 1,
  observed_at INTEGER NOT NULL,
  PRIMARY KEY(binding_id, binding_write_revision),
  FOREIGN KEY(binding_id, binding_write_revision)
  REFERENCES binding_write_revisions(binding_id, revision)
  ON DELETE CASCADE,
  FOREIGN KEY(binding_id, delete_credential_purpose, delete_credential_generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation)
  ON DELETE RESTRICT,
  CHECK(binding_resource_version >= 1),
  CHECK(state IN('valid', 'invalid')),
  CHECK(resource_version >= 1),
  CHECK((delete_credential_purpose IS NULL
      AND delete_credential_generation IS NULL)
    OR (delete_credential_purpose = 'delete'
      AND delete_credential_generation >= 1))
);

-- A provider inventory enumerates every canonical oci/blobs/... key, including
-- keys that have no SQL catalog identity. Collection is generation-fenced and
-- becomes selectable only after its canonical digest and counts are sealed.
CREATE TABLE oci_provider_inventory_generations(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  placement_id INTEGER NOT NULL,
  collector_id KEYTEXT128 NOT NULL,
  collector_claim_token KEYTEXT64 NOT NULL,
  collector_lease_expires_at INTEGER,
  idempotency_key KEYTEXT128 NOT NULL,
  source_kind KEYTEXT32 NOT NULL,
  captured_mutation_epoch INTEGER NOT NULL,
  placement_resource_version INTEGER NOT NULL,
  placement_write_spec_version INTEGER NOT NULL,
  placement_observation_version INTEGER NOT NULL,
  binding_id INTEGER NOT NULL,
  binding_resource_version INTEGER NOT NULL,
  binding_write_revision INTEGER NOT NULL,
  state KEYTEXT16 NOT NULL,
  active_slot INTEGER,
  inventory_digest KEYTEXT128,
  object_count INTEGER NOT NULL DEFAULT 0,
  byte_count INTEGER NOT NULL DEFAULT 0,
  untracked_object_count INTEGER NOT NULL DEFAULT 0,
  checkpoint_ordinal INTEGER NOT NULL DEFAULT 0,
  provider_cursor KEYTEXT512,
  checkpoint_last_key KEYTEXT512,
  checkpoint_digest KEYTEXT128,
  checkpoint_page_digest KEYTEXT128,
  takeover_count INTEGER NOT NULL DEFAULT 0,
  started_at INTEGER NOT NULL,
  observed_at INTEGER,
  completed_at INTEGER,
  last_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, placement_id, collector_id, idempotency_key),
  UNIQUE(placement_id, active_slot),
  UNIQUE(id, registry_id, placement_id),
  FOREIGN KEY(placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id) ON DELETE CASCADE,
  FOREIGN KEY(binding_id, binding_write_revision)
  REFERENCES binding_write_revisions(binding_id, revision) ON DELETE RESTRICT,
  CHECK(source_kind = 'provider_enumeration_v1'),
  CHECK(captured_mutation_epoch >= 0),
  CHECK(placement_resource_version >= 1),
  CHECK(placement_write_spec_version >= 1),
  CHECK(placement_observation_version >= 1),
  CHECK(binding_resource_version >= 1),
  CHECK(state IN('collecting', 'sealing', 'complete', 'failed')),
  CHECK((state IN('collecting', 'sealing') AND active_slot = 1
      AND collector_lease_expires_at IS NOT NULL)
    OR (state IN('complete', 'failed') AND active_slot IS NULL
      AND collector_lease_expires_at IS NULL)),
  CHECK(object_count >= 0 AND byte_count >= 0),
  CHECK(checkpoint_ordinal >= 0),
  CHECK(takeover_count >= 0),
  CHECK((checkpoint_ordinal = 0 AND checkpoint_last_key IS NULL
      AND checkpoint_digest IS NULL AND checkpoint_page_digest IS NULL)
    OR (checkpoint_ordinal > 0 AND checkpoint_digest IS NOT NULL
      AND checkpoint_page_digest IS NOT NULL)),
  CHECK(untracked_object_count >= 0 AND untracked_object_count <= object_count),
  CHECK(resource_version >= 1),
  CHECK((state IN('collecting', 'sealing') AND inventory_digest IS NULL
      AND observed_at IS NULL AND completed_at IS NULL)
    OR (state = 'complete' AND inventory_digest IS NOT NULL
      AND observed_at IS NOT NULL AND completed_at IS NOT NULL)
    OR (state = 'failed' AND completed_at IS NOT NULL))
);
CREATE INDEX oci_provider_inventories_placement_idx
ON oci_provider_inventory_generations(placement_id, completed_at, id);

CREATE TABLE oci_provider_inventory_entries(
  generation_id KEYTEXT64 NOT NULL
  REFERENCES oci_provider_inventory_generations(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  object_digest KEYTEXT128 NOT NULL,
  observed_hash KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  strong_etag KEYTEXT512 NOT NULL,
  surface_object_id INTEGER,
  catalog_object_resource_version INTEGER,
  classification KEYTEXT16 NOT NULL,
  deleted_at INTEGER,
  PRIMARY KEY(generation_id, object_key),
  FOREIGN KEY(generation_id, registry_id, placement_id)
  REFERENCES oci_provider_inventory_generations(id, registry_id, placement_id)
  ON DELETE CASCADE,
  CHECK(byte_size >= 0),
  CHECK(length(strong_etag) > 0),
  CHECK(classification IN('tracked', 'untracked')),
  CHECK((classification = 'tracked' AND surface_object_id IS NOT NULL
      AND catalog_object_resource_version >= 1)
    OR (classification = 'untracked' AND surface_object_id IS NULL
      AND catalog_object_resource_version IS NULL))
);
CREATE INDEX oci_provider_inventory_entries_catalog_idx
ON oci_provider_inventory_entries(
  registry_id, object_digest, placement_id, generation_id
);
CREATE INDEX oci_provider_inventory_entries_untracked_idx
ON oci_provider_inventory_entries(
  registry_id, classification, deleted_at, generation_id
);

CREATE TABLE oci_provider_inventory_heads(
  placement_id INTEGER PRIMARY KEY,
  registry_id INTEGER NOT NULL,
  generation_id KEYTEXT64 NOT NULL UNIQUE,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(generation_id, registry_id, placement_id)
  REFERENCES oci_provider_inventory_generations(id, registry_id, placement_id)
  ON DELETE CASCADE,
  FOREIGN KEY(placement_id, registry_id)
  REFERENCES surface_placements(id, registry_id) ON DELETE CASCADE
);

CREATE TABLE oci_gc_runs(
  id KEYTEXT64 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  actor_id KEYTEXT128 NOT NULL,
  plan_idempotency_key KEYTEXT128 NOT NULL,
  apply_idempotency_key KEYTEXT128,
  state KEYTEXT16 NOT NULL,
  captured_mutation_epoch INTEGER NOT NULL,
  applied_mutation_epoch INTEGER,
  policy_resource_version INTEGER NOT NULL,
  policy_digest KEYTEXT128 NOT NULL,
  root_set_digest KEYTEXT128 NOT NULL,
  placement_inventory_digest KEYTEXT128 NOT NULL,
  topology_digest KEYTEXT128 NOT NULL,
  plan_digest KEYTEXT128 NOT NULL,
  confirmation_hash KEYTEXT128 NOT NULL,
  inventory_object_count INTEGER NOT NULL,
  inventory_byte_size INTEGER NOT NULL,
  reachable_object_count INTEGER NOT NULL,
  planned_bytes INTEGER NOT NULL,
  planned_objects INTEGER NOT NULL,
  deleted_object_count INTEGER NOT NULL DEFAULT 0,
  deleted_byte_size INTEGER NOT NULL DEFAULT 0,
  placement_action_count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  applied_at INTEGER,
  finished_at INTEGER,
  last_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(registry_id, actor_id, plan_idempotency_key),
  UNIQUE(id, registry_id),
  CHECK(state IN('planned', 'applying', 'complete', 'aborted', 'failed')),
  CHECK(captured_mutation_epoch >= 0),
  CHECK(applied_mutation_epoch IS NULL OR applied_mutation_epoch >= 0),
  CHECK(policy_resource_version >= 0),
  CHECK(inventory_object_count >= 0 AND inventory_byte_size >= 0),
  CHECK(reachable_object_count >= 0),
  CHECK(planned_bytes >= 0 AND planned_objects >= 0),
  CHECK(deleted_object_count >= 0 AND deleted_byte_size >= 0),
  CHECK(placement_action_count >= 0),
  CHECK(expires_at > created_at),
  CHECK(resource_version >= 1),
  CHECK((state = 'planned' AND applied_at IS NULL AND finished_at IS NULL)
    OR (state = 'applying' AND applied_at IS NOT NULL AND finished_at IS NULL)
    OR (state IN('complete', 'aborted', 'failed') AND finished_at IS NOT NULL))
);
CREATE INDEX oci_gc_runs_registry_idx
ON oci_gc_runs(registry_id, created_at, id);
CREATE INDEX oci_gc_runs_state_idx
ON oci_gc_runs(state, created_at, id);

CREATE TABLE oci_gc_registry_locks(
  registry_id INTEGER PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  run_id KEYTEXT64 NOT NULL UNIQUE REFERENCES oci_gc_runs(id) ON DELETE CASCADE,
  acquired_at INTEGER NOT NULL
);

CREATE TABLE oci_gc_roots(
  run_id KEYTEXT64 NOT NULL REFERENCES oci_gc_runs(id) ON DELETE CASCADE,
  root_kind KEYTEXT32 NOT NULL,
  digest KEYTEXT128 NOT NULL,
  source_id KEYTEXT512 NOT NULL,
  repository_id INTEGER,
  PRIMARY KEY(run_id, root_kind, digest, source_id),
  CHECK(root_kind IN(
    'tag', 'signed_release', 'lease', 'upload', 'publication',
    'tag_history', 'referrer'
  ))
);
CREATE INDEX oci_gc_roots_digest_idx ON oci_gc_roots(run_id, digest);

CREATE TABLE oci_gc_blockers(
  run_id KEYTEXT64 NOT NULL REFERENCES oci_gc_runs(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  blocker_kind KEYTEXT64 NOT NULL,
  digest KEYTEXT128,
  detail LONGTEXT NOT NULL,
  PRIMARY KEY(run_id, ordinal),
  CHECK(ordinal >= 0)
);

CREATE TABLE oci_gc_candidates(
  run_id KEYTEXT64 NOT NULL REFERENCES oci_gc_runs(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  media_type KEYTEXT128 NOT NULL,
  byte_size INTEGER NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  surface_object_id INTEGER NOT NULL,
  catalog_object_resource_version INTEGER NOT NULL,
  repository_count INTEGER NOT NULL,
  eligible_at INTEGER NOT NULL,
  state KEYTEXT32 NOT NULL,
  finalized_at INTEGER,
  last_error LONGTEXT,
  resource_version INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(run_id, digest),
  FOREIGN KEY(run_id, registry_id)
  REFERENCES oci_gc_runs(id, registry_id) ON DELETE CASCADE,
  CHECK(byte_size >= 0),
  CHECK(catalog_object_resource_version >= 1),
  CHECK(repository_count >= 0),
  CHECK(state IN('planned', 'deleting', 'physically_absent', 'complete', 'failed')),
  CHECK(resource_version >= 1)
);
CREATE INDEX oci_gc_candidates_state_idx ON oci_gc_candidates(run_id, state, digest);

CREATE TABLE oci_gc_candidate_repositories(
  run_id KEYTEXT64 NOT NULL,
  digest KEYTEXT128 NOT NULL,
  repository_id INTEGER NOT NULL,
  repository_name KEYTEXT255 NOT NULL,
  PRIMARY KEY(run_id, digest, repository_id),
  FOREIGN KEY(run_id, digest)
  REFERENCES oci_gc_candidates(run_id, digest) ON DELETE CASCADE
);

CREATE TABLE oci_gc_placement_snapshots(
  run_id KEYTEXT64 NOT NULL REFERENCES oci_gc_runs(id) ON DELETE CASCADE,
  registry_id INTEGER NOT NULL,
  placement_id INTEGER NOT NULL,
  placement_name KEYTEXT64 NOT NULL,
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
  delete_capability_observed_at INTEGER NOT NULL,
  inventory_generation_id KEYTEXT64 NOT NULL,
  inventory_digest KEYTEXT128 NOT NULL,
  inventory_observed_at INTEGER NOT NULL,
  PRIMARY KEY(run_id, placement_id),
  CHECK(placement_resource_version >= 1),
  CHECK(placement_write_spec_version >= 1),
  CHECK(placement_observation_version >= 1),
  CHECK(binding_resource_version >= 1),
  CHECK(binding_write_revision >= 1),
  CHECK(delete_capability_resource_version >= 1),
  CHECK((delete_credential_purpose IS NULL
      AND delete_credential_generation IS NULL)
    OR (delete_credential_purpose = 'delete'
      AND delete_credential_generation >= 1))
);

-- Applying runs temporarily pin the exact immutable delete credential. The
-- reviewed snapshot remains self-contained history after this hold is released.
CREATE TABLE oci_gc_credential_holds(
  run_id KEYTEXT64 NOT NULL REFERENCES oci_gc_runs(id) ON DELETE CASCADE,
  binding_id INTEGER NOT NULL,
  purpose KEYTEXT16 NOT NULL,
  generation INTEGER NOT NULL,
  PRIMARY KEY(run_id, binding_id, purpose, generation),
  FOREIGN KEY(binding_id, purpose, generation)
  REFERENCES binding_credential_revisions(binding_id, purpose, generation)
  ON DELETE RESTRICT,
  CHECK(purpose = 'delete'),
  CHECK(generation >= 1)
);

CREATE TABLE oci_gc_placement_actions(
  id KEYTEXT64 PRIMARY KEY,
  run_id KEYTEXT64 NOT NULL,
  registry_id INTEGER NOT NULL,
  digest KEYTEXT128 NOT NULL,
  placement_id INTEGER NOT NULL,
  object_key KEYTEXT512 NOT NULL,
  expected_hash KEYTEXT128 NOT NULL,
  expected_size INTEGER NOT NULL,
  expected_strong_etag KEYTEXT512,
  inventory_generation_id KEYTEXT64 NOT NULL,
  inventory_entry_present INTEGER NOT NULL,
  state KEYTEXT32 NOT NULL,
  worker_id KEYTEXT128,
  claim_token KEYTEXT64,
  lease_expires_at INTEGER,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 8,
  next_attempt_at INTEGER NOT NULL,
  requeue_actor_id KEYTEXT128,
  requeue_idempotency_key KEYTEXT128,
  requeue_expected_resource_version INTEGER,
  last_error LONGTEXT,
  confirmed_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  UNIQUE(run_id, digest, placement_id),
  UNIQUE(requeue_actor_id, requeue_idempotency_key),
  FOREIGN KEY(run_id, digest)
  REFERENCES oci_gc_candidates(run_id, digest) ON DELETE CASCADE,
  FOREIGN KEY(run_id, placement_id)
  REFERENCES oci_gc_placement_snapshots(run_id, placement_id) ON DELETE CASCADE,
  CHECK(expected_size >= 0),
  CHECK(inventory_entry_present IN(0, 1)),
  CHECK((inventory_entry_present = 1 AND expected_strong_etag IS NOT NULL)
    OR (inventory_entry_present = 0 AND expected_strong_etag IS NULL)),
  CHECK(state IN('pending', 'claimed', 'confirmed_absent', 'failed')),
  CHECK(attempt_count >= 0 AND max_attempts > 0),
  CHECK(resource_version >= 1),
  CHECK((requeue_actor_id IS NULL AND requeue_idempotency_key IS NULL
      AND requeue_expected_resource_version IS NULL)
    OR (requeue_actor_id IS NOT NULL AND requeue_idempotency_key IS NOT NULL
      AND requeue_expected_resource_version >= 1)),
  CHECK((state = 'claimed' AND worker_id IS NOT NULL AND claim_token IS NOT NULL
      AND lease_expires_at IS NOT NULL)
    OR (state <> 'claimed' AND worker_id IS NULL AND claim_token IS NULL
      AND lease_expires_at IS NULL)),
  CHECK((state = 'confirmed_absent' AND confirmed_at IS NOT NULL)
    OR (state <> 'confirmed_absent' AND confirmed_at IS NULL))
);
CREATE INDEX oci_gc_actions_claim_idx
ON oci_gc_placement_actions(state, next_attempt_at, run_id, id);

CREATE TABLE oci_gc_deletion_evidence(
  action_id KEYTEXT64 PRIMARY KEY
  REFERENCES oci_gc_placement_actions(id) ON DELETE CASCADE,
  response_idempotency_key KEYTEXT128 NOT NULL UNIQUE,
  outcome KEYTEXT32 NOT NULL,
  conditional_etag KEYTEXT512,
  provider_request_id KEYTEXT255,
  evidence_digest KEYTEXT128 NOT NULL,
  confirmed_at INTEGER NOT NULL,
  CHECK(outcome IN('deleted', 'already_absent')),
  CHECK(outcome <> 'deleted' OR conditional_etag IS NOT NULL)
);

-- Removing a registry's snapshot reference can leave a verified opened-file
-- lease alive. This historical owner link keeps registry purge fail closed
-- until the independent snapshot collector observes that every lease drained.
CREATE TABLE oci_gc_snapshot_lease_holds(
  run_id KEYTEXT64 NOT NULL,
  registry_id INTEGER NOT NULL,
  snapshot_digest KEYTEXT64 NOT NULL,
  retired_at INTEGER NOT NULL,
  PRIMARY KEY(run_id, snapshot_digest),
  FOREIGN KEY(run_id, registry_id)
  REFERENCES oci_gc_runs(id, registry_id) ON DELETE CASCADE,
  CHECK(length(snapshot_digest) = 64)
);
CREATE INDEX oci_gc_snapshot_lease_holds_registry_idx
ON oci_gc_snapshot_lease_holds(registry_id, snapshot_digest);
