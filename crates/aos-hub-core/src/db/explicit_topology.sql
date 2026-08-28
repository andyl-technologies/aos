-- Normalize the Worker attachment identity that older deployments recorded as
-- a physical bucket name even though request serving always selected the
-- REGISTRY_BUCKET runtime binding.
UPDATE bindings
   SET object_bucket = 'REGISTRY_BUCKET',
       resource_version = resource_version + 1
 WHERE kind = 'deployment_r2'
   AND object_bucket <> 'REGISTRY_BUCKET';

-- Existing organization grants are configuration that predates the explicit
-- topology API. Preserve their grant generation so live pins remain valid,
-- but adopt them as ordinary explicit grants with an auditable transition.
INSERT INTO consumer_scope_grant_events
  (event_id, resource_kind, resource_stable_id, resource_generation_key,
   consumer_scope_key, grant_generation, transition, previous_state,
   resulting_state, actor_id, occurred_at, request_id)
SELECT 'migration:b:' || grant_record.consumer_scope_key, 'binding',
       binding.stable_id, 0, grant_record.consumer_scope_key,
       grant_record.grant_generation, 'regranted', 'active', 'active',
       'system:migration', 0, 'migration:explicit-topology'
  FROM binding_consumer_scopes grant_record
  JOIN bindings binding ON binding.id = grant_record.binding_id
 WHERE grant_record.grant_kind = 'instance_default'
   AND grant_record.state = 'active'
   AND grant_record.consumer_scope_key <> binding.owner_scope_key
   AND NOT EXISTS (
       SELECT 1 FROM consumer_scope_grant_events event
        WHERE event.event_id = 'migration:b:' || grant_record.consumer_scope_key
   );

UPDATE binding_consumer_scopes
   SET grant_kind = 'explicit',
       resource_version = resource_version + 1
 WHERE grant_kind = 'instance_default'
   AND state = 'active'
   AND EXISTS (
       SELECT 1 FROM bindings binding
        WHERE binding.id = binding_consumer_scopes.binding_id
          AND binding.owner_scope_key <> binding_consumer_scopes.consumer_scope_key
   );

INSERT INTO consumer_scope_grant_events
  (event_id, resource_kind, resource_stable_id, resource_generation_key,
   consumer_scope_key, grant_generation, transition, previous_state,
   resulting_state, actor_id, occurred_at, request_id)
SELECT 'migration:n:' || grant_record.consumer_scope_key, 'network_policy',
       grant_record.boundary_id, 0, grant_record.consumer_scope_key,
       grant_record.grant_generation, 'regranted', 'active', 'active',
       'system:migration', 0, 'migration:explicit-topology'
  FROM network_policy_consumer_scopes grant_record
  JOIN network_policies policy ON policy.id = grant_record.boundary_id
 WHERE grant_record.grant_kind = 'instance_default'
   AND grant_record.state = 'active'
   AND grant_record.consumer_scope_key <> policy.owner_scope_key
   AND NOT EXISTS (
       SELECT 1 FROM consumer_scope_grant_events event
        WHERE event.event_id = 'migration:n:' || grant_record.consumer_scope_key
   );

UPDATE network_policy_consumer_scopes
   SET grant_kind = 'explicit',
       resource_version = resource_version + 1
 WHERE grant_kind = 'instance_default'
   AND state = 'active'
   AND EXISTS (
       SELECT 1 FROM network_policies policy
        WHERE policy.id = network_policy_consumer_scopes.boundary_id
          AND policy.owner_scope_key <> network_policy_consumer_scopes.consumer_scope_key
   );

-- New organization and binding creation never materialize implicit grants.

-- This migration is the online adoption boundary from the first topology
-- hard-cutover schema. Startup accepts the old identity only when this pending
-- migration is present, then verifies the new identity before serving.
UPDATE hub_schema_identity
   SET identity = 'aos-hub/topology-hard-cutover/2'
 WHERE identity = 'aos-hub/topology-hard-cutover/1';
