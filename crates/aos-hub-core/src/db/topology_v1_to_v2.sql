-- Online compatibility transformer for databases stamped with topology
-- hard-cutover identity v1. Commit 7b380eaba renamed the public topology
-- vocabulary without changing its relational shape; preserve every row while
-- bringing those physical identifiers and persisted enum values to v2.

ALTER TABLE storage_bindings RENAME TO bindings;
ALTER TABLE storage_binding_credential_revisions RENAME TO binding_credential_revisions;
ALTER TABLE storage_binding_credential_heads RENAME TO binding_credential_heads;
ALTER TABLE storage_binding_consumer_scopes RENAME TO binding_consumer_scopes;
ALTER TABLE storage_binding_write_revisions RENAME TO binding_write_revisions;
ALTER TABLE storage_binding_write_state RENAME TO binding_write_state;
ALTER TABLE storage_binding_write_observations RENAME TO binding_write_observations;
ALTER TABLE storage_binding_scope_grant_pins RENAME TO binding_scope_grant_pins;

ALTER TABLE network_boundaries RENAME TO network_policies;
ALTER TABLE network_boundary_revisions RENAME TO network_policy_revisions;
ALTER TABLE network_boundary_observations RENAME TO network_policy_observations;
ALTER TABLE network_boundary_revision_lifecycle RENAME TO network_policy_revision_lifecycle;
ALTER TABLE network_boundary_defaults RENAME TO network_policy_defaults;
ALTER TABLE network_boundary_consumer_scopes RENAME TO network_policy_consumer_scopes;
ALTER TABLE network_boundary_serving_pins RENAME TO network_policy_serving_pins;

ALTER TABLE delivery_endpoints RENAME TO endpoints;
ALTER TABLE delivery_endpoint_revisions RENAME TO endpoint_revisions;
ALTER TABLE delivery_endpoint_observations RENAME TO endpoint_observations;
ALTER TABLE delivery_endpoint_generation_observations RENAME TO endpoint_generation_observations;
ALTER TABLE delivery_endpoint_route_scopes RENAME TO endpoint_route_scopes;
ALTER TABLE delivery_endpoint_scope_grant_pins RENAME TO endpoint_scope_grant_pins;

ALTER TABLE storage_gateways RENAME TO gateways;
ALTER TABLE storage_gateway_path_reservations RENAME TO gateway_path_reservations;
ALTER TABLE storage_gateway_revisions RENAME TO gateway_revisions;
ALTER TABLE storage_gateway_revision_route_scopes RENAME TO gateway_revision_route_scopes;
ALTER TABLE storage_gateway_revision_events RENAME TO gateway_revision_events;
ALTER TABLE storage_gateway_scope_grant_pins RENAME TO gateway_scope_grant_pins;

ALTER TABLE delivery_route_url_reservations RENAME TO route_url_reservations;
ALTER TABLE delivery_route_replacements RENAME TO route_replacements;
ALTER TABLE delivery_routes RENAME TO routes;
ALTER TABLE delivery_route_configurations RENAME TO route_configurations;
ALTER TABLE delivery_route_heads RENAME TO route_heads;
ALTER TABLE canonical_routes RENAME TO route_advertisements;
ALTER TABLE delivery_route_observations RENAME TO route_observations;
ALTER TABLE delivery_route_access_observations RENAME TO route_access_observations;
ALTER TABLE direct_delivery_route_evidence RENAME TO direct_route_evidence;

ALTER TABLE cache_gc_generation_placements RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE cache_gc_generation_placements RENAME COLUMN storage_binding_stable_id TO binding_stable_id;
ALTER TABLE cache_gc_generation_placements RENAME COLUMN storage_binding_resource_version TO binding_resource_version;
ALTER TABLE cache_gc_plan_actions RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE cache_inventory_placement_scans RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE cache_write_tickets RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE route_advertisements RENAME COLUMN delivery_route_id TO route_id;
ALTER TABLE consumer_cache_publication_intents RENAME COLUMN delivery_route_id TO route_id;
ALTER TABLE delivery_attestation_nonces RENAME COLUMN delivery_route_id TO route_id;
ALTER TABLE endpoint_revisions RENAME COLUMN network_boundary_id TO network_policy_id;
ALTER TABLE endpoints RENAME COLUMN network_boundary_id TO network_policy_id;
ALTER TABLE route_access_observations RENAME COLUMN delivery_route_id TO route_id;
ALTER TABLE route_configurations RENAME COLUMN delivery_route_id TO route_id;
ALTER TABLE route_heads RENAME COLUMN delivery_route_id TO route_id;
ALTER TABLE route_observations RENAME COLUMN delivery_route_id TO route_id;
ALTER TABLE routes RENAME COLUMN storage_gateway_id TO gateway_id;
ALTER TABLE routes RENAME COLUMN target_storage_binding_id TO target_binding_id;
ALTER TABLE direct_route_evidence RENAME COLUMN delivery_route_id TO route_id;
ALTER TABLE direct_route_evidence RENAME COLUMN storage_gateway_id TO gateway_id;
ALTER TABLE object_deletion_attempt_receipts RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE object_deletion_jobs RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE registry_cache_stack_entries RENAME COLUMN delivery_route_id TO route_id;
ALTER TABLE binding_consumer_scopes RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE binding_credential_heads RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE binding_credential_revisions RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE binding_scope_grant_pins RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE binding_write_observations RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE binding_write_revisions RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE binding_write_state RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE gateway_revisions RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE surface_placement_write_capabilities RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE surface_placements RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE topology_defaults RENAME COLUMN storage_binding_id TO binding_id;
ALTER TABLE topology_defaults RENAME COLUMN delivery_endpoint_id TO endpoint_id;
ALTER TABLE topology_defaults RENAME COLUMN delivery_endpoint_generation TO endpoint_generation;
ALTER TABLE topology_defaults RENAME COLUMN storage_gateway_id TO gateway_id;
ALTER TABLE topology_defaults RENAME COLUMN storage_gateway_generation TO gateway_generation;

DROP INDEX IF EXISTS storage_bindings_stable_idx;
DROP INDEX IF EXISTS storage_bindings_scope_idx;
DROP INDEX IF EXISTS delivery_routes_registry_idx;
DROP INDEX IF EXISTS delivery_routes_cache_idx;
DROP INDEX IF EXISTS bindings_stable_idx;
DROP INDEX IF EXISTS bindings_scope_idx;
DROP INDEX IF EXISTS routes_registry_idx;
DROP INDEX IF EXISTS routes_cache_idx;
CREATE UNIQUE INDEX bindings_stable_idx ON bindings(stable_id);
CREATE UNIQUE INDEX bindings_scope_idx ON bindings(id, owner_scope_key);
CREATE INDEX routes_registry_idx ON routes(registry_id, id);
CREATE INDEX routes_cache_idx ON routes(cache_id, id);

-- CHECK constraints contain literal enum values and are not rewritten by
-- SQLite's ALTER TABLE support. Rebuild the four constrained ledgers. Child
-- operation rows are copied aside before the parent is replaced, then restored
-- through the unchanged foreign keys.
CREATE TABLE _topology_operations_v1 AS SELECT * FROM topology_operations;
CREATE TABLE _operation_secondary_targets_v1 AS SELECT * FROM operation_secondary_targets;
CREATE TABLE _cache_gc_operation_jobs_v1 AS SELECT * FROM cache_gc_operation_jobs;
CREATE TABLE _cache_gc_plans_v1 AS SELECT * FROM cache_gc_plans;
CREATE TABLE _cache_object_mutation_fences_v1 AS SELECT * FROM cache_object_mutation_fences;
CREATE TABLE _domain_probe_observations_v1 AS SELECT * FROM domain_probe_observations;
CREATE TABLE _object_deletion_jobs_v1 AS SELECT * FROM object_deletion_jobs;
CREATE TABLE _topology_operation_mutations_v1 AS SELECT * FROM topology_operation_mutations;
CREATE TABLE _topology_pin_resolution_jobs_v1 AS SELECT * FROM topology_pin_resolution_jobs;
CREATE TABLE _topology_event_outbox_v1 AS SELECT * FROM topology_event_outbox;
CREATE TABLE _consumer_scope_grant_events_v1 AS SELECT * FROM consumer_scope_grant_events;

DELETE FROM topology_operations;
DROP TABLE operation_secondary_targets;
DROP TABLE topology_operations;
DROP TABLE topology_event_outbox;
DROP TABLE consumer_scope_grant_events;

CREATE TABLE topology_event_outbox(
  event_id KEYTEXT64 PRIMARY KEY,
  event_name KEYTEXT128 NOT NULL,
  owner_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE CASCADE ON UPDATE RESTRICT,
  resource_kind KEYTEXT32 NOT NULL,
  resource_stable_id KEYTEXT255 NOT NULL,
  resource_generation_key INTEGER NOT NULL DEFAULT 0,
  actor_kind KEYTEXT32 NOT NULL,
  actor_id INTEGER,
  actor_label TEXT NOT NULL,
  payload_json LONGTEXT NOT NULL,
  occurred_at INTEGER NOT NULL,
  materialized_at INTEGER,
  CHECK(resource_generation_key >= 0),
  CHECK(length(payload_json) <= 1048576),
  CHECK(actor_kind IN('user', 'service_account', 'key', 'system')),
  CHECK(resource_kind IN('organization', 'project', 'binding',
    'registry', 'binary_cache', 'placement', 'domain',
    'network_policy', 'endpoint', 'gateway', 'route',
    'placement_policy', 'retention_subscription', 'population_target',
    'cache_gc_generation', 'binding_credential', 'webhook'))
);
CREATE INDEX topology_event_outbox_pending_idx
ON topology_event_outbox(materialized_at, occurred_at, event_id);

CREATE TABLE topology_operations(
  operation_id KEYTEXT64 PRIMARY KEY,
  operation_kind KEYTEXT64 NOT NULL,
  authorization_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE CASCADE ON UPDATE RESTRICT,
  control_permission KEYTEXT32 NOT NULL,
  primary_target_kind KEYTEXT32 NOT NULL,
  primary_target_stable_id KEYTEXT255 NOT NULL,
  primary_target_generation_key INTEGER NOT NULL DEFAULT 0,
  primary_target_configuration_digest KEYTEXT128 NOT NULL DEFAULT '',
  state KEYTEXT32 NOT NULL,
  progress_current INTEGER NOT NULL DEFAULT 0,
  progress_total INTEGER,
  detail_json LONGTEXT NOT NULL DEFAULT('{}'),
  error LONGTEXT,
  created_at INTEGER NOT NULL,
  started_at INTEGER,
  finished_at INTEGER,
  resource_version INTEGER NOT NULL DEFAULT 1,
  CHECK(state IN('pending', 'running', 'succeeded', 'failed', 'cancelled')),
  CHECK(control_permission IN('read', 'publish', 'channel.advance', 'keys.manage',
    'tokens.self', 'tokens.manage', 'members.manage', 'registry.configure',
    'storage.manage', 'binding.read', 'binding.manage',
    'binding.grant', 'placement.read', 'placement.manage',
    'placement_policy.read', 'placement_policy.manage', 'domain.read',
    'domain.manage', 'network_policy.read', 'network_policy.manage',
    'network_policy.grant', 'endpoint.read',
    'endpoint.manage', 'endpoint.grant',
    'gateway.read', 'gateway.manage', 'gateway.grant',
    'route.read', 'route.manage', 'topology.reconcile', 'cache.retention.manage',
    'cache.gc.plan', 'cache.gc.execute', 'cache.lease.self',
    'validation.repair', 'audit.read', 'iam.admin')),
  CHECK(primary_target_kind IN('registry', 'binary_cache', 'placement', 'domain',
    'network_policy', 'endpoint', 'gateway', 'route',
    'placement_policy', 'retention_subscription', 'population_target',
    'cache_gc_generation', 'binding')),
  CHECK(primary_target_generation_key >= 0),
  CHECK(progress_current >= 0),
  CHECK(progress_total IS NULL OR progress_total >= progress_current),
  CHECK((state = 'pending' AND started_at IS NULL AND finished_at IS NULL)
OR(state = 'running' AND started_at IS NOT NULL AND finished_at IS NULL)
OR(state IN('succeeded', 'failed', 'cancelled')
AND started_at IS NOT NULL AND finished_at IS NOT NULL)),
  CHECK(started_at IS NULL OR started_at >= created_at),
  CHECK(finished_at IS NULL OR finished_at >= started_at),
  CHECK(state <> 'succeeded' OR error IS NULL),
  CHECK(state <> 'failed' OR error IS NOT NULL),
  UNIQUE(operation_id, primary_target_kind, primary_target_stable_id)
);
CREATE INDEX topology_operations_scope_idx
ON topology_operations(authorization_scope_key, created_at, operation_id);

CREATE TABLE operation_secondary_targets(
  operation_id KEYTEXT64 NOT NULL REFERENCES topology_operations(operation_id) ON DELETE CASCADE,
  role KEYTEXT32 NOT NULL,
  target_kind KEYTEXT32 NOT NULL,
  stable_id KEYTEXT255 NOT NULL,
  authorization_scope_key KEYTEXT64 NOT NULL REFERENCES authorization_scopes(scope_key)
    ON DELETE CASCADE ON UPDATE RESTRICT,
  control_permission KEYTEXT32 NOT NULL,
  generation_key INTEGER NOT NULL DEFAULT 0,
  configuration_digest KEYTEXT128 NOT NULL DEFAULT '',
  PRIMARY KEY(operation_id, role, target_kind, stable_id, generation_key),
  UNIQUE(operation_id, target_kind, stable_id),
  UNIQUE(operation_id, role, target_kind, stable_id),
  CHECK(role IN('source', 'destination', 'placement', 'policy', 'subscription', 'generation')),
  CHECK(target_kind IN('registry', 'binary_cache', 'placement', 'domain',
    'network_policy', 'endpoint', 'gateway', 'route',
    'placement_policy', 'retention_subscription', 'population_target',
    'cache_gc_generation', 'binding')),
  CHECK(generation_key >= 0),
  CHECK(control_permission IN('read', 'publish', 'channel.advance', 'keys.manage',
    'tokens.self', 'tokens.manage', 'members.manage', 'registry.configure',
    'storage.manage', 'binding.read', 'binding.manage',
    'binding.grant', 'placement.read', 'placement.manage',
    'placement_policy.read', 'placement_policy.manage', 'domain.read',
    'domain.manage', 'network_policy.read', 'network_policy.manage',
    'network_policy.grant', 'endpoint.read',
    'endpoint.manage', 'endpoint.grant',
    'gateway.read', 'gateway.manage', 'gateway.grant',
    'route.read', 'route.manage', 'topology.reconcile', 'cache.retention.manage',
    'cache.gc.plan', 'cache.gc.execute', 'cache.lease.self',
    'validation.repair', 'audit.read', 'iam.admin'))
);
CREATE INDEX operation_secondary_targets_resource_idx
ON operation_secondary_targets(target_kind, stable_id, operation_id);

CREATE TABLE consumer_scope_grant_events(
  event_id KEYTEXT64 PRIMARY KEY,
  resource_kind KEYTEXT32 NOT NULL,
  resource_stable_id KEYTEXT64 NOT NULL,
  resource_generation_key INTEGER NOT NULL,
  consumer_scope_key KEYTEXT64 NOT NULL,
  grant_generation INTEGER NOT NULL,
  transition KEYTEXT16 NOT NULL,
  previous_state KEYTEXT16,
  resulting_state KEYTEXT16 NOT NULL,
  actor_id KEYTEXT128 NOT NULL,
  occurred_at INTEGER NOT NULL,
  request_id KEYTEXT128 NOT NULL,
  CHECK(resource_kind IN('binding', 'network_policy', 'endpoint', 'gateway')),
  CHECK(transition IN('granted', 'revoked', 'regranted')),
  CHECK(resulting_state IN('active', 'revoked')),
  CHECK(grant_generation > 0)
);

INSERT INTO topology_event_outbox
SELECT event_id,
       replace(replace(replace(replace(replace(event_name,
         'storage_binding', 'binding'), 'network_boundary', 'network_policy'),
         'delivery_endpoint', 'endpoint'), 'storage_gateway', 'gateway'),
         'delivery_route', 'route'),
       owner_scope_key,
       replace(replace(replace(replace(replace(resource_kind,
         'storage_binding', 'binding'), 'network_boundary', 'network_policy'),
         'delivery_endpoint', 'endpoint'), 'storage_gateway', 'gateway'),
         'delivery_route', 'route'),
       resource_stable_id, resource_generation_key, actor_kind, actor_id,
       actor_label,
       replace(replace(replace(replace(replace(payload_json,
         'storage_binding', 'binding'), 'network_boundary', 'network_policy'),
         'delivery_endpoint', 'endpoint'), 'storage_gateway', 'gateway'),
         'delivery_route', 'route'),
       occurred_at, materialized_at
  FROM _topology_event_outbox_v1;

INSERT INTO topology_operations
SELECT operation_id,
       replace(replace(replace(replace(replace(operation_kind,
         'storage_binding', 'binding'), 'network_boundary', 'network_policy'),
         'delivery_endpoint', 'endpoint'), 'storage_gateway', 'gateway'),
         'delivery_route', 'route'),
       authorization_scope_key,
       replace(replace(replace(replace(control_permission,
         'storage_binding', 'binding'), 'network_boundary', 'network_policy'),
         'delivery_endpoint', 'endpoint'), 'storage_gateway', 'gateway'),
       replace(replace(replace(replace(replace(primary_target_kind,
         'storage_binding', 'binding'), 'network_boundary', 'network_policy'),
         'delivery_endpoint', 'endpoint'), 'storage_gateway', 'gateway'),
         'delivery_route', 'route'),
       primary_target_stable_id, primary_target_generation_key,
       primary_target_configuration_digest, state, progress_current,
       progress_total,
       replace(replace(replace(replace(replace(detail_json,
         'storage_binding', 'binding'), 'network_boundary', 'network_policy'),
         'delivery_endpoint', 'endpoint'), 'storage_gateway', 'gateway'),
         'delivery_route', 'route'),
       error, created_at, started_at, finished_at, resource_version
  FROM _topology_operations_v1;

INSERT INTO operation_secondary_targets
SELECT operation_id, role,
       replace(replace(replace(replace(replace(target_kind,
         'storage_binding', 'binding'), 'network_boundary', 'network_policy'),
         'delivery_endpoint', 'endpoint'), 'storage_gateway', 'gateway'),
         'delivery_route', 'route'),
       stable_id, authorization_scope_key,
       replace(replace(replace(replace(control_permission,
         'storage_binding', 'binding'), 'network_boundary', 'network_policy'),
         'delivery_endpoint', 'endpoint'), 'storage_gateway', 'gateway'),
       generation_key, configuration_digest
  FROM _operation_secondary_targets_v1;

INSERT INTO cache_gc_operation_jobs SELECT * FROM _cache_gc_operation_jobs_v1;
INSERT INTO cache_gc_plans SELECT * FROM _cache_gc_plans_v1;
INSERT INTO cache_object_mutation_fences SELECT * FROM _cache_object_mutation_fences_v1;
INSERT INTO domain_probe_observations SELECT * FROM _domain_probe_observations_v1;
INSERT INTO object_deletion_jobs SELECT * FROM _object_deletion_jobs_v1;
INSERT INTO topology_operation_mutations SELECT * FROM _topology_operation_mutations_v1;
INSERT INTO topology_pin_resolution_jobs SELECT * FROM _topology_pin_resolution_jobs_v1;

INSERT INTO consumer_scope_grant_events
SELECT event_id,
       replace(replace(replace(replace(resource_kind,
         'storage_binding', 'binding'), 'network_boundary', 'network_policy'),
         'delivery_endpoint', 'endpoint'), 'storage_gateway', 'gateway'),
       resource_stable_id, resource_generation_key, consumer_scope_key,
       grant_generation, transition, previous_state, resulting_state, actor_id,
       occurred_at, request_id
  FROM _consumer_scope_grant_events_v1;

DROP TABLE _topology_operations_v1;
DROP TABLE _operation_secondary_targets_v1;
DROP TABLE _cache_gc_operation_jobs_v1;
DROP TABLE _cache_gc_plans_v1;
DROP TABLE _cache_object_mutation_fences_v1;
DROP TABLE _domain_probe_observations_v1;
DROP TABLE _object_deletion_jobs_v1;
DROP TABLE _topology_operation_mutations_v1;
DROP TABLE _topology_pin_resolution_jobs_v1;
DROP TABLE _topology_event_outbox_v1;
DROP TABLE _consumer_scope_grant_events_v1;

-- The migration ledger, not this identity, records pending additive versions.
-- Stamp v2 in the same transaction as the rename so a later migration failure
-- resumes from the ledger instead of attempting this one-shot transform twice.
UPDATE hub_schema_identity
   SET identity = 'aos-hub/topology-hard-cutover/2'
 WHERE identity = 'aos-hub/topology-hard-cutover/1';
