-- Compact semantic state is authoritative in SQL in every deployment mode.
-- Raw provider responses remain on independently admitted evidence storage.
-- Canonical objects are sharded so snapshot/HubDb operations remain bounded.

CREATE TABLE assessment_objects(
  partition_key KEYTEXT128 NOT NULL,
  object_digest KEYTEXT128 NOT NULL,
  object_kind KEYTEXT64 NOT NULL,
  byte_length INTEGER NOT NULL,
  shard_count INTEGER NOT NULL,
  admitted_at INTEGER NOT NULL,
  PRIMARY KEY(partition_key, object_digest),
  CHECK(byte_length > 0 AND byte_length <= 16777216),
  CHECK(shard_count > 0 AND shard_count <= 64)
);

CREATE TABLE assessment_object_shards(
  partition_key KEYTEXT128 NOT NULL,
  object_digest KEYTEXT128 NOT NULL,
  shard_ordinal INTEGER NOT NULL,
  bytes_digest KEYTEXT128 NOT NULL,
  canonical_bytes BLOB NOT NULL,
  PRIMARY KEY(partition_key, object_digest, shard_ordinal),
  FOREIGN KEY(partition_key, object_digest) REFERENCES assessment_objects(partition_key, object_digest) ON DELETE CASCADE,
  CHECK(shard_ordinal >= 0 AND shard_ordinal < 64),
  CHECK(length(canonical_bytes) > 0 AND length(canonical_bytes) <= 262144)
);

CREATE TABLE assessment_resources(
  registry_id INTEGER NOT NULL PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  partition_key KEYTEXT128 NOT NULL,
  inventory_digest KEYTEXT128 NOT NULL,
  policy_digest KEYTEXT128 NOT NULL,
  inventory_revision INTEGER NOT NULL,
  next_generation INTEGER NOT NULL,
  authorization_revision INTEGER NOT NULL,
  resource_version INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK(inventory_revision > 0 AND next_generation > 0),
  CHECK(authorization_revision > 0 AND resource_version > 0)
);

CREATE TABLE assessment_inventory_sets(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  inventory_digest KEYTEXT128 NOT NULL,
  provenance_digest KEYTEXT128 NOT NULL,
  admission_digest KEYTEXT128 NOT NULL,
  evaluation_base_digest KEYTEXT128 NOT NULL,
  inventory_revision INTEGER NOT NULL,
  state KEYTEXT32 NOT NULL,
  expected_subject_count INTEGER NOT NULL,
  expected_identity_count INTEGER NOT NULL,
  admitted_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, inventory_digest),
  CHECK(inventory_revision > 0 AND expected_subject_count > 0 AND expected_subject_count <= 10000),
  CHECK(expected_identity_count >= 0 AND expected_identity_count <= 3200000),
  CHECK(state IN('building', 'ready', 'rejected'))
);

CREATE TABLE assessment_subjects(
  registry_id INTEGER NOT NULL,
  inventory_digest KEYTEXT128 NOT NULL,
  subject_ref KEYTEXT128 NOT NULL,
  definition_digest KEYTEXT128 NOT NULL,
  component_inventory_digest KEYTEXT128 NOT NULL,
  package_coordinate KEYTEXT1024 NOT NULL,
  package_version KEYTEXT512 NOT NULL,
  platform KEYTEXT128 NOT NULL,
  output_name KEYTEXT128 NOT NULL,
  subject_kind KEYTEXT32 NOT NULL,
  artifact_digest KEYTEXT128,
  source_content_digest KEYTEXT128,
  PRIMARY KEY(registry_id, inventory_digest, subject_ref),
  FOREIGN KEY(registry_id, inventory_digest) REFERENCES assessment_inventory_sets(registry_id, inventory_digest) ON DELETE CASCADE,
  CHECK(subject_kind IN('source', 'package-artifact', 'release', 'system-image', 'oci-image')),
  CHECK((subject_kind = 'source' AND source_content_digest IS NOT NULL AND artifact_digest IS NULL)
    OR (subject_kind <> 'source' AND artifact_digest IS NOT NULL))
);

CREATE INDEX assessment_subject_coordinate_idx
ON assessment_subjects(registry_id, package_coordinate, package_version, platform);

CREATE TABLE assessment_component_index(
  registry_id INTEGER NOT NULL,
  inventory_digest KEYTEXT128 NOT NULL,
  subject_ref KEYTEXT128 NOT NULL,
  component_ref KEYTEXT128 NOT NULL,
  component_digest KEYTEXT128 NOT NULL,
  identity_digest KEYTEXT128 NOT NULL,
  PRIMARY KEY(registry_id, inventory_digest, component_ref, identity_digest),
  FOREIGN KEY(registry_id, inventory_digest, subject_ref) REFERENCES assessment_subjects(registry_id, inventory_digest, subject_ref) ON DELETE CASCADE
);

CREATE INDEX assessment_component_identity_idx
ON assessment_component_index(identity_digest, registry_id, inventory_digest);

CREATE TABLE assessment_heads(
  registry_id INTEGER NOT NULL,
  inventory_digest KEYTEXT128 NOT NULL,
  subject_ref KEYTEXT128 NOT NULL,
  profile KEYTEXT32 NOT NULL,
  policy_digest KEYTEXT128 NOT NULL,
  desired_generation INTEGER NOT NULL,
  committed_generation INTEGER NOT NULL,
  assessment_digest KEYTEXT128,
  input_digest KEYTEXT128,
  validated_until INTEGER,
  last_scan_id KEYTEXT128,
  resource_version INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, inventory_digest, subject_ref, profile, policy_digest),
  FOREIGN KEY(registry_id, inventory_digest, subject_ref) REFERENCES assessment_subjects(registry_id, inventory_digest, subject_ref) ON DELETE CASCADE,
  CHECK(profile IN('updates', 'vulnerabilities', 'license-signals')),
  CHECK(desired_generation > 0 AND committed_generation >= 0 AND committed_generation <= desired_generation),
  CHECK(resource_version > 0),
  CHECK((committed_generation = 0 AND assessment_digest IS NULL AND input_digest IS NULL)
    OR (committed_generation > 0 AND assessment_digest IS NOT NULL AND input_digest IS NOT NULL))
);

CREATE TABLE assessment_scans(
  scan_id KEYTEXT128 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  partition_key KEYTEXT128 NOT NULL,
  request_digest KEYTEXT128 NOT NULL,
  request_json BLOB NOT NULL,
  admission_complete INTEGER NOT NULL DEFAULT 0,
  generation INTEGER NOT NULL,
  inventory_revision INTEGER NOT NULL,
  inventory_digest KEYTEXT128 NOT NULL,
  policy_digest KEYTEXT128 NOT NULL,
  authorization_revision INTEGER NOT NULL,
  actor_ref KEYTEXT128 NOT NULL,
  idempotency_key KEYTEXT128 NOT NULL,
  state KEYTEXT32 NOT NULL,
  claim_token KEYTEXT128,
  lease_expires_at INTEGER,
  attempt INTEGER NOT NULL,
  usage_json BLOB NOT NULL,
  evaluation_input_digest KEYTEXT128,
  evaluation_data_digest KEYTEXT128,
  checkpoint_digest KEYTEXT128,
  assessment_digest KEYTEXT128,
  last_error_code KEYTEXT128,
  resource_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  completed_at INTEGER,
  UNIQUE(registry_id, actor_ref, idempotency_key),
  CHECK(generation > 0 AND inventory_revision > 0 AND authorization_revision > 0 AND resource_version > 0),
  CHECK(attempt >= 0 AND attempt <= 100),
  CHECK(state IN('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelling', 'cancelled', 'superseded')),
  CHECK(admission_complete IN(0, 1)),
  CHECK(length(request_json) > 0 AND length(request_json) <= 262144),
  CHECK(length(usage_json) > 0 AND length(usage_json) <= 8192),
  CHECK((state IN('succeeded', 'partial', 'failed', 'cancelled', 'superseded') AND completed_at IS NOT NULL)
    OR (state IN('queued', 'running', 'cancelling') AND completed_at IS NULL))
);

CREATE INDEX assessment_scans_due_idx ON assessment_scans(state, lease_expires_at, created_at);
CREATE INDEX assessment_scans_resource_idx ON assessment_scans(registry_id, created_at, scan_id);

CREATE TABLE assessment_scan_targets(
  scan_id KEYTEXT128 NOT NULL REFERENCES assessment_scans(scan_id) ON DELETE CASCADE,
  subject_ref KEYTEXT128 NOT NULL,
  profile KEYTEXT32 NOT NULL,
  PRIMARY KEY(scan_id, subject_ref, profile)
);

CREATE TABLE assessment_tasks(
  scan_id KEYTEXT128 NOT NULL REFERENCES assessment_scans(scan_id) ON DELETE CASCADE,
  task_id KEYTEXT128 NOT NULL,
  operation_digest KEYTEXT128 NOT NULL,
  plan_digest KEYTEXT128,
  plan_json BLOB,
  generation INTEGER NOT NULL,
  state KEYTEXT32 NOT NULL,
  claim_token KEYTEXT128,
  attempt INTEGER NOT NULL,
  lease_expires_at INTEGER,
  reservation_id KEYTEXT128,
  result_digest KEYTEXT128,
  result_json BLOB,
  continuation_digest KEYTEXT128,
  not_before INTEGER NOT NULL,
  last_error_code KEYTEXT128,
  resource_version INTEGER NOT NULL,
  PRIMARY KEY(scan_id, task_id),
  CHECK(generation > 0 AND attempt >= 0 AND attempt <= 100 AND resource_version > 0),
  CHECK(state IN('pending', 'leased', 'waiting', 'succeeded', 'partial', 'failed', 'cancelled', 'superseded')),
  CHECK(plan_json IS NULL OR (length(plan_json) > 0 AND length(plan_json) <= 262144)),
  CHECK(result_json IS NULL OR (length(result_json) > 0 AND length(result_json) <= 262144))
);

CREATE INDEX assessment_tasks_due_idx ON assessment_tasks(state, not_before, lease_expires_at);

CREATE TABLE assessment_source_budgets(
  budget_key KEYTEXT128 PRIMARY KEY,
  window_start INTEGER NOT NULL,
  window_seconds INTEGER NOT NULL,
  allowance INTEGER NOT NULL,
  consumed INTEGER NOT NULL,
  min_interval_seconds INTEGER NOT NULL,
  next_eligible_at INTEGER NOT NULL,
  circuit_until INTEGER NOT NULL,
  failure_count INTEGER NOT NULL,
  resource_version INTEGER NOT NULL,
  CHECK(window_seconds > 0 AND allowance > 0 AND consumed >= 0 AND consumed <= allowance),
  CHECK(min_interval_seconds >= 0 AND failure_count >= 0 AND resource_version > 0)
);

CREATE TABLE assessment_budget_reservations(
  reservation_id KEYTEXT128 PRIMARY KEY,
  budget_key KEYTEXT128 NOT NULL REFERENCES assessment_source_budgets(budget_key),
  scan_id KEYTEXT128 NOT NULL,
  task_id KEYTEXT128 NOT NULL,
  attempt INTEGER NOT NULL,
  request_allowance INTEGER NOT NULL,
  deadline INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(scan_id, task_id, attempt),
  FOREIGN KEY(scan_id, task_id) REFERENCES assessment_tasks(scan_id, task_id) ON DELETE CASCADE,
  CHECK(attempt > 0 AND request_allowance > 0 AND request_allowance <= 10 AND deadline > created_at)
);

CREATE TABLE assessment_observation_heads(
  partition_key KEYTEXT128 NOT NULL,
  provider KEYTEXT128 NOT NULL,
  project_digest KEYTEXT128 NOT NULL,
  operation_digest KEYTEXT128 NOT NULL,
  observation_digest KEYTEXT128 NOT NULL,
  validated_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  coverage_state KEYTEXT32 NOT NULL,
  resource_version INTEGER NOT NULL,
  PRIMARY KEY(partition_key, provider, project_digest, operation_digest),
  CHECK(expires_at >= validated_at AND resource_version > 0),
  CHECK(coverage_state IN('complete', 'through-boundary', 'partial', 'unknown'))
);

CREATE TABLE assessment_candidate_history(
  partition_key KEYTEXT128 NOT NULL,
  project_digest KEYTEXT128 NOT NULL,
  candidate_digest KEYTEXT128 NOT NULL,
  first_observed_at INTEGER NOT NULL,
  candidate_json BLOB NOT NULL,
  PRIMARY KEY(partition_key, project_digest, candidate_digest),
  CHECK(length(candidate_json) > 0 AND length(candidate_json) <= 8192)
);

CREATE TABLE assessment_advisory_revisions(
  partition_key KEYTEXT128 NOT NULL,
  provider KEYTEXT128 NOT NULL,
  advisory_id KEYTEXT128 NOT NULL,
  record_digest KEYTEXT128 NOT NULL,
  modification_identity KEYTEXT128 NOT NULL,
  withdrawn INTEGER NOT NULL,
  admitted_at INTEGER NOT NULL,
  PRIMARY KEY(partition_key, provider, advisory_id, record_digest),
  CHECK(withdrawn IN(0, 1))
);

CREATE TABLE assessment_advisory_identity_index(
  partition_key KEYTEXT128 NOT NULL,
  identity_digest KEYTEXT128 NOT NULL,
  record_digest KEYTEXT128 NOT NULL,
  PRIMARY KEY(partition_key, identity_digest, record_digest)
);

CREATE TABLE assessment_source_checkpoints(
  partition_key KEYTEXT128 NOT NULL,
  provider KEYTEXT128 NOT NULL,
  checkpoint_digest KEYTEXT128 NOT NULL,
  snapshot_digest KEYTEXT128,
  progress_digest KEYTEXT128,
  resource_version INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(partition_key, provider),
  CHECK(resource_version > 0)
);

CREATE TABLE assessment_schedules(
  schedule_id KEYTEXT128 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  actor_ref KEYTEXT128 NOT NULL,
  configuration_json BLOB NOT NULL,
  enabled INTEGER NOT NULL,
  cadence_seconds INTEGER NOT NULL,
  next_due_at INTEGER NOT NULL,
  resource_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK(enabled IN(0, 1) AND cadence_seconds >= 60 AND resource_version > 0),
  CHECK(length(configuration_json) > 0 AND length(configuration_json) <= 262144)
);

CREATE INDEX assessment_schedule_due_idx ON assessment_schedules(enabled, next_due_at, schedule_id);

CREATE TABLE assessment_alerts(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  issue_key KEYTEXT128 NOT NULL,
  subject_ref KEYTEXT128 NOT NULL,
  profile KEYTEXT32 NOT NULL,
  context_digest KEYTEXT128 NOT NULL,
  family KEYTEXT32 NOT NULL,
  attention_state KEYTEXT32 NOT NULL,
  episode INTEGER NOT NULL,
  transition_sequence INTEGER NOT NULL,
  alert_json BLOB NOT NULL,
  assessment_digest KEYTEXT128 NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, issue_key),
  CHECK(episode > 0 AND transition_sequence > 0),
  CHECK(attention_state IN('open', 'resolved', 'retired')),
  CHECK(family IN('vulnerability', 'package-update', 'coverage', 'source-health')),
  CHECK(length(alert_json) > 0 AND length(alert_json) <= 262144)
);

CREATE INDEX assessment_alert_subject_idx ON assessment_alerts(registry_id, subject_ref, profile, attention_state);

CREATE TABLE assessment_event_sequences(
  registry_id INTEGER NOT NULL PRIMARY KEY REFERENCES registries(id) ON DELETE CASCADE,
  current_sequence INTEGER NOT NULL,
  CHECK(current_sequence >= 0)
);

CREATE TABLE assessment_events(
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  event_sequence INTEGER NOT NULL,
  event_id KEYTEXT128 NOT NULL UNIQUE,
  event_kind KEYTEXT64 NOT NULL,
  issue_key KEYTEXT128,
  episode INTEGER,
  assessment_digest KEYTEXT128,
  payload_json BLOB NOT NULL,
  occurred_at INTEGER NOT NULL,
  PRIMARY KEY(registry_id, event_sequence),
  CHECK(event_sequence > 0),
  CHECK(length(payload_json) > 0 AND length(payload_json) <= 262144)
);

CREATE TABLE assessment_subscriptions(
  subscription_id KEYTEXT128 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  configuration_json BLOB NOT NULL,
  destination_reference KEYTEXT128 NOT NULL,
  secret_version_reference KEYTEXT128,
  enabled INTEGER NOT NULL,
  resource_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  CHECK(enabled IN(0, 1) AND resource_version > 0),
  CHECK(length(configuration_json) > 0 AND length(configuration_json) <= 262144)
);

CREATE TABLE assessment_notification_outbox(
  delivery_id KEYTEXT128 PRIMARY KEY,
  registry_id INTEGER NOT NULL,
  event_sequence INTEGER NOT NULL,
  subscription_id KEYTEXT128 NOT NULL REFERENCES assessment_subscriptions(subscription_id) ON DELETE CASCADE,
  subscription_revision INTEGER NOT NULL,
  payload_digest KEYTEXT128 NOT NULL,
  state KEYTEXT32 NOT NULL,
  claim_token KEYTEXT128,
  lease_expires_at INTEGER,
  attempt INTEGER NOT NULL,
  not_before INTEGER NOT NULL,
  last_error_code KEYTEXT128,
  receipt_digest KEYTEXT128,
  resource_version INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(registry_id, event_sequence, subscription_id, subscription_revision),
  FOREIGN KEY(registry_id, event_sequence) REFERENCES assessment_events(registry_id, event_sequence) ON DELETE CASCADE,
  CHECK(state IN('pending', 'leased', 'delivered', 'dead-letter', 'revoked')),
  CHECK(attempt >= 0 AND attempt <= 20 AND resource_version > 0)
);

CREATE INDEX assessment_notification_due_idx ON assessment_notification_outbox(state, not_before, lease_expires_at);

CREATE TABLE assessment_import_receipts(
  receipt_id KEYTEXT128 PRIMARY KEY,
  registry_id INTEGER NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
  bundle_digest KEYTEXT128 NOT NULL,
  uploader_ref KEYTEXT128 NOT NULL,
  assessment_digest KEYTEXT128 NOT NULL,
  authority_class KEYTEXT32 NOT NULL,
  validation_digest KEYTEXT128 NOT NULL,
  imported_at INTEGER NOT NULL,
  CHECK(authority_class IN('reproduced', 'admitted', 'rejected'))
);
