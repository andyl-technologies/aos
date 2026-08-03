# Data model and API

The records below are normative responsibilities, not a requirement to add a
single polymorphic `surfaces` SQL table. SQLite, D1, PostgreSQL, and MySQL must
all enforce equivalent ownership and one-of constraints.

This file defines resource responsibilities and schema. The normative
Connect-JSON service/message and CLI mapping is in
[`09-interface-contracts.md`](09-interface-contracts.md).

## Placement records

```sql
surface_placements(
  id,
  registry_id NULL,
  cache_id NULL,
  storage_binding_id,
  prefix,
  role,                 -- primary | replica | shard | archive
  state,                -- provisioning | syncing | ready | degraded | draining | offline
  completeness,         -- complete | partial | unknown
  partition_rule_json NULL,
  read_enabled,
  write_enabled,
  read_order,
  write_order,
  created_at,
  updated_at,
  CHECK exactly_one(registry_id, cache_id),
  UNIQUE(storage_binding_id, prefix)
)

placement_policies(
  id,
  registry_id NULL,
  cache_id NULL,
  kind,                 -- ordered_failover | latency_preferred | hash_partition
  config_json,
  CHECK exactly_one(registry_id, cache_id)
)

placement_policy_members(
  policy_id,
  placement_id,
  member_order,
  required,
  PRIMARY KEY(policy_id, placement_id)
)

placement_equivalences(
  id,
  placement_a_id,
  placement_b_id,
  physical_identity_fingerprint,
  confirmed_by,
  confirmed_at,
  validation_revision,
  resource_version,
  created_at,
  updated_at,
  CHECK(placement_a_id < placement_b_id),
  UNIQUE(placement_a_id, placement_b_id)
)
```

Placement equivalence handles the rare case where two logical placement
records intentionally address the same physical bytes. Confirmation records
operator provenance and a validated backend identity fingerprint. Placements
must belong to the same surface and resolve the same object keys/content; the
create path never infers equivalence from similar endpoint/bucket strings.

Existing `registry.storage_binding_id/prefix` and
`cache.storage_binding_id/prefix` migrate into one primary placement each.
The cutover migration then removes the old fields before the new runtime
starts; production code never dual-reads both representations.

## Domains and delivery routes

```sql
domains(
  id,
  org_id NULL,
  hostname UNIQUE,
  dns_provider,
  dns_state,
  tls_provider,
  tls_state,
  access_provider_json,
  verified_at NULL,
  created_at,
  updated_at
)

delivery_routes(
  id,
  domain_id,
  storage_gateway_id NULL,
  gateway_generation NULL,
  base_path,
  registry_id NULL,
  cache_id NULL,
  mode,                  -- hub_proxy | hub_redirect | direct
  access_policy_json,
  placement_id NULL,
  placement_policy_id NULL,
  serves_git,
  serves_cache,
  serves_web,
  enabled,
  created_at,
  updated_at,
  CHECK exactly_one(registry_id, cache_id),
  CHECK exactly_one(placement_id, placement_policy_id),
  UNIQUE(domain_id, base_path)
)

canonical_routes(
  registry_id NULL,
  cache_id NULL,
  audience,              -- git | nix_cache | web
  delivery_route_id,
  CHECK exactly_one(registry_id, cache_id),
  UNIQUE(registry_id, audience),
  UNIQUE(cache_id, audience)
)
```

Binding-wide direct mappings become `storage_gateways`; derived route rows
make their effect visible and queryable.

```sql
storage_gateways(
  id,
  org_id NULL,             -- NULL means instance scope
  storage_binding_id,
  domain_id,
  base_path,
  origin_path_rewrite,
  access_policy_json,
  enabled,
  desired_generation,
  observed_generation,
  reconciliation_state,
  reconciliation_error NULL,
  created_at,
  updated_at,
  UNIQUE(domain_id, base_path)
)

topology_defaults(
  id,
  scope_kind,             -- instance | organization
  org_id NULL,
  scope_key UNIQUE,       -- instance | org:<stable-id>
  storage_binding_id NULL,
  domain_id NULL,
  storage_gateway_id NULL,
  created_at,
  updated_at,
  CHECK valid_scope(scope_kind, org_id, scope_key)
)
```

`delivery_routes.storage_gateway_id` and `gateway_generation` record materialized
provenance. Reconciliation previews and then updates ordinary route rows; it
does not create invisible runtime inheritance. Organization defaults may
override instance defaults. A default is only a creation-time/user-interface
choice and never silently retargets an existing placement or route.

A gateway-derived route is necessarily `direct`, references a placement on the
gateway's binding, and records the gateway generation that produced it. The
schema enforces one instance defaults row despite SQL NULL-uniqueness
differences; every organization has at most one defaults row.

The current `frontends` table migrates as follows:

- registry/cache target -> delivery route;
- binding target -> storage gateway plus one derived route per eligible
  placement;
- `domain`/`base_path` -> normalized domain and route;
- `mode` -> delivery mode;
- `serves_*` -> route capabilities;
- `advertised` -> either canonical-route selection or no migrated meaning;
- `consumer_priority` -> explicit route/policy order after correcting its
  current direction ambiguity; and
- `is_primary` -> canonical route for the applicable audience.

The resource-level `advertise_storage_frontend` fields are removed after
derived-route review. There is no generic inheritance toggle in the new model.

## Object presence

```sql
surface_objects(
  id,
  registry_id NULL,
  cache_id NULL,
  object_key,
  content_hash NULL,
  size NULL,
  mutable_generation NULL,
  CHECK exactly_one(registry_id, cache_id),
  UNIQUE(registry_id, object_key),
  UNIQUE(cache_id, object_key)
)

object_placements(
  surface_object_id,
  placement_id,
  state,                  -- present | copying | missing | corrupt | deleting
  observed_hash NULL,
  observed_size NULL,
  etag NULL,
  observed_at,
  PRIMARY KEY(surface_object_id, placement_id)
)
```

Existing cache object metadata may remain in `cache_objects`; the essential
change is moving physical presence/refcounts to placement scope.

## Registry/cache integration records

```sql
cache_retention_subscriptions(
  id,
  cache_id,
  registry_id,
  selector_json,
  removal_grace_secs,
  exposure_acknowledged_at NULL,
  enabled,
  last_successful_revision NULL,
  last_refresh_at NULL,
  refresh_error NULL,
  UNIQUE(cache_id, registry_id)
)

cache_population_targets(
  id,
  cache_id,
  registry_id,
  trigger,                -- release | manual | continuous
  required,
  placement_policy_id NULL,
  selector_json,
  validation_gate,
  enabled,
  UNIQUE(cache_id, registry_id, trigger)
)

release_artifacts(
  release_id,
  package_name,
  package_version,
  platform,
  artifact_kind,
  store_path,
  store_hash,
  PRIMARY KEY(release_id, package_name, package_version, platform,
              artifact_kind, store_hash)
)

cache_root_reasons(
  id,
  cache_id,
  store_hash,
  source_kind,
  retention_subscription_id NULL,
  manual_retention_root_id NULL,
  retention_lease_id NULL,
  release_id NULL,
  source_ref,
  source_revision,
  expires_at NULL,
  refreshed_at,
  UNIQUE(cache_id, store_hash, source_kind, source_ref)
)

manual_retention_roots(
  id,
  cache_id,
  store_hash,
  reason,
  created_by,
  created_at,
  deleted_at NULL,
  resource_version,
  UNIQUE(cache_id, id)
)

retention_leases(
  id,
  manual_retention_root_id,
  begins_at,
  expires_at,
  renewed_from_lease_id NULL,
  renewed_by,
  renewed_at,
  resource_version
)
```

Manual-root renewal creates a new lease linked to the prior lease, preserving
who extended protection and when. Deleting a manual root is logical and
audited; the derived root reason disappears only through the same transactional
refresh and grace rules as other retention reasons.

The signed consumer stack remains in `registry.toml`. Its indexed projection
gains stable managed identity:

```sql
registry_cache_stack_entries(
  registry_id,
  stack_path,
  committed_url,
  resolved_priority,
  cache_id NULL,
  delivery_route_id NULL,
  indexed_commit,
  PRIMARY KEY(registry_id, stack_path)
)
```

The cutover transforms `cache_registry_links.roots_packages` into retention
subscriptions and then drops the table in the same maintenance operation. Its
legacy `advertised` bit has no successor: signed configuration already owns
publication.

The managed-cache system-of-record table is renamed from `caches` to
`binary_caches`. The indexed signed stack uses
`registry_cache_stack_entries`; no table uses the bare name `caches`, and no
new code uses “advertised cache” to mean a signed consumer entry.

## Priority and ordering

The topology uses three deliberately different concepts:

- Nix `nix-cache-info Priority`: lower numeric value is preferred by Nix.
- Consumer cache stack: structural list order, first member tried first.
- Placement/route selection: explicit `member_order`, lower ordinal first.

No generic `consumer_priority` field crosses these domains. UIs say “first,”
“second,” or “lower Nix priority is preferred” instead of relying on an
unqualified integer.

## Service responsibilities

This section groups operations by owner. Exact public method and plan/apply
names are normative in `09-interface-contracts.md`.

### Placements

- `CreatePlacement`, `UpdatePlacement`, `PromotePlacement`, `DrainPlacement`,
  `CancelPlacementDrain`, `DeletePlacement`
- `ListPlacements`, `GetPlacement`, `ScanPlacement`
- `GetPlacementPolicy`, `SetPlacementPolicy`, `TestPlacementPolicy`
- `ReplicatePlacement`, `RepairPlacement`, `ListObjectPresence`
- `ListPlacementEquivalences`, `ConfirmPlacementEquivalence`,
  `DeletePlacementEquivalence`

Creating or moving a placement never silently changes a delivery route or
signed consumer stack. An impact endpoint reports affected routes and
integrations before apply.

### Domains and routes

- `CreateDomain`, `UpdateDomain`, `VerifyDomain`, `ConfigureDomainDns`,
  `ConfigureDomainTls`, `ConfigureDomainAccess`, `ReconcileDomain`,
  `DeleteDomain`
- `CreateRoute`, `UpdateRoute`, `EnableRoute`, `DisableRoute`, `DeleteRoute`
- `SetCanonicalRoute`, `ProbeRoute`, `ExplainRoute`
- `CreateStorageGateway`, `UpdateStorageGateway`, `PreviewGatewayRoutes`,
  `ReconcileStorageGateway`, `EnableStorageGateway`, `DisableStorageGateway`,
  `DeleteStorageGateway`

`ExplainRoute` returns the selected access decision, placement candidates,
origin credential purpose, path rewrite, and rejection reasons without
disclosing secrets.

### Storage bindings and topology defaults

- `CreateStorageBinding`, `UpdateStorageBinding`, `DeleteStorageBinding`
- `SetStorageBindingCredential`, `RotateStorageBindingCredential`,
  `ValidateStorageBindingCredential`
- `GetInstanceDefaultStorageBinding`
- `GetInstanceTopologyDefaults`, `SetInstanceTopologyDefaults`
- `GetOrganizationTopologyDefaults`, `SetOrganizationTopologyDefaults`

The public binding record exposes capabilities and health, never credential
material. Default changes have their own impact plan and affect only future
workflows unless the operator separately plans changes to existing resources.

### Cache integrations

- `GetConsumerCacheStack`, `ValidateConsumerCacheStack`,
  `PlanConsumerCacheChange`, and `CreateConsumerCacheChangeset`
- `SetRetentionSubscription`, `RefreshRetentionSubscription`
- `SetPopulationTarget`, `RunPopulation`, `RunCoverageValidation`,
  `RunCoverageRepair`
- `ListRegistryCacheIntegrations`, `ListCacheRegistryIntegrations`, and
  `GetCacheRegistryIntegration` with direction and effect explicitly named
- `PreviewCacheIntegration` returning independent publication, retention, and
  population plans without a combined apply operation

There is no new `LinkCache` operation. The old method and its combined request
message are removed at cutover. Callers use retention methods and signed
consumer-cache changes explicitly.

### GC

- `ListRootReasons`, `ExplainRetention`, `RefreshAllRetention`
- `PlanCacheGc`, `RunCacheGc`, `ListCacheGcRuns`
- `PlanPlacementEviction`, `RunPlacementEviction`

Logical GC and placement eviction are different methods and audit event types.

## Validation transactions

Mutations that cross records use a plan/apply shape:

1. resolve current topology and version ids;
2. return semantic effects, warnings, and preconditions;
3. apply against the same versions or reject as stale; and
4. enqueue replication/probe/index work after the control-plane transaction.

Examples include surface visibility changes, domain access changes, placement
drains, canonical route changes, and enabling destructive GC.

## Complete cutover

- Every still-supported public URL is imported as an ordinary delivery route,
  not a compatibility alias.
- Every committed registry `[caches]` URL is checked before cutover. If its URL
  will change, the signed change is merged before switching traffic.
- The schema migration creates placements, domains, gateways, routes,
  integrations, and root reasons, validates them, and drops the old topology
  tables/columns in the same maintenance operation.
- Native and Worker binaries start only against the new schema and route
  index. They contain no legacy read/write branch.
- Old API messages, methods, UI handlers, CLI variants, and help text are
  removed rather than deprecated in place.
- Fresh installations use a squashed new Hub schema baseline. The one-shot
  cutover artifact is not part of the steady-state runtime.
