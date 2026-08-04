# Data model and API

The records below are normative responsibilities, not a requirement to add a
single polymorphic `surfaces` SQL table. SQLite, D1, PostgreSQL, and MySQL must
all enforce equivalent ownership and one-of constraints.

This file defines resource responsibilities and schema. The normative
Connect-JSON service/message and CLI mapping is in
[`09-interface-contracts.md`](09-interface-contracts.md).

## Binding-write capability and placement records

```sql
storage_binding_write_revisions(
  storage_binding_id,
  revision,
  write_credential_version_ref,
  writes_supported,
  conditional_writes_supported,
  revision_fingerprint,
  capability_fingerprint,
  created_at,
  PRIMARY KEY(storage_binding_id, revision),
  UNIQUE(storage_binding_id, revision_fingerprint),
  FOREIGN KEY (storage_binding_id)
    REFERENCES storage_bindings(id)
      ON DELETE CASCADE ON UPDATE RESTRICT
)

storage_binding_write_state(
  storage_binding_id PRIMARY KEY,
  current_write_revision NULL,
  resource_version,
  updated_at,
  FOREIGN KEY (storage_binding_id)
    REFERENCES storage_bindings(id)
      ON DELETE CASCADE ON UPDATE RESTRICT,
  FOREIGN KEY (storage_binding_id, current_write_revision)
    REFERENCES storage_binding_write_revisions(storage_binding_id, revision)
      ON DELETE RESTRICT ON UPDATE RESTRICT
)

storage_binding_write_observations(
  storage_binding_id,
  revision,
  state,                -- unknown | validating | valid | invalid
  validated_at NULL,
  error NULL,
  observation_version,
  PRIMARY KEY(storage_binding_id, revision),
  FOREIGN KEY (storage_binding_id, revision)
    REFERENCES storage_binding_write_revisions(storage_binding_id, revision)
      ON DELETE CASCADE ON UPDATE RESTRICT
)

surface_placements(
  id,
  registry_id NULL,
  cache_id NULL,
  name,
  storage_binding_id,
  prefix,
  kind,                 -- complete | shard | archive
  desired_state,        -- active | draining | offline
  partition_rule_json NULL,
  desired_read_enabled,
  read_order,
  write_spec_version,
  resource_version,
  created_at,
  updated_at,
  CHECK exactly_one(registry_id, cache_id),
  CHECK shard_iff_partition_rule(kind, partition_rule_json),
  CHECK archive_is_not_read_selected(kind, desired_read_enabled),
  CHECK write_spec_version > 0,
  UNIQUE(registry_id, name),
  UNIQUE(cache_id, name),
  UNIQUE(id, registry_id),
  UNIQUE(id, cache_id),
  UNIQUE(id, registry_id, write_spec_version),
  UNIQUE(id, cache_id, write_spec_version),
  UNIQUE(id, storage_binding_id, write_spec_version),
  UNIQUE(storage_binding_id, prefix)
)

surface_placement_write_capabilities(
  placement_id,
  placement_write_spec_version,
  storage_binding_id,
  binding_write_revision,
  created_at,
  PRIMARY KEY(placement_id, placement_write_spec_version,
              binding_write_revision),
  FOREIGN KEY (placement_id, storage_binding_id,
               placement_write_spec_version)
    REFERENCES surface_placements(id, storage_binding_id, write_spec_version)
      ON DELETE CASCADE ON UPDATE RESTRICT,
  FOREIGN KEY (storage_binding_id, binding_write_revision)
    REFERENCES storage_binding_write_revisions(storage_binding_id, revision)
      ON DELETE RESTRICT ON UPDATE RESTRICT
)

surface_placement_observations(
  placement_id PRIMARY KEY
    REFERENCES surface_placements(id)
      ON DELETE CASCADE ON UPDATE RESTRICT,
  state,                -- provisioning | syncing | ready | degraded | offline
  completeness,         -- complete | partial | unknown
  observed_at,
  observation_version
)

registry_placement_publication_watermarks(
  placement_id,
  registry_id,
  mutable_publication_id,
  observed_at,
  PRIMARY KEY(placement_id),
  FOREIGN KEY (placement_id, registry_id)
    REFERENCES surface_placements(id, registry_id)
      ON DELETE CASCADE ON UPDATE RESTRICT,
  FOREIGN KEY (mutable_publication_id, registry_id)
    REFERENCES registry_publications(publication_id, registry_id)
      ON DELETE RESTRICT ON UPDATE RESTRICT
)

surface_write_authorities(
  id PRIMARY KEY,
  registry_id NULL,
  cache_id NULL,
  mode,                 -- single_writer
  desired_placement_id,
  desired_write_spec_version,
  desired_binding_write_revision,
  desired_generation,
  observed_placement_id NULL,
  observed_write_spec_version NULL,
  observed_binding_write_revision NULL,
  observed_generation,
  reconciliation_state, -- pending | ready | failed
  reconciliation_error NULL,
  resource_version,
  created_at,
  updated_at,
  CHECK exactly_one(registry_id, cache_id),
  CHECK mode = 'single_writer',
  CHECK observed_authority_reference_is_all_set_or_null,
  CHECK authority_generations_are_consistent,
  CHECK desired_generation > 0,
  CHECK observed_generation >= 0,
  UNIQUE(registry_id),
  UNIQUE(cache_id),
  FOREIGN KEY (desired_placement_id, registry_id,
               desired_write_spec_version)
    REFERENCES surface_placements(id, registry_id, write_spec_version)
      ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY (desired_placement_id, cache_id,
               desired_write_spec_version)
    REFERENCES surface_placements(id, cache_id, write_spec_version)
      ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY (observed_placement_id, registry_id,
               observed_write_spec_version)
    REFERENCES surface_placements(id, registry_id, write_spec_version)
      ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY (observed_placement_id, cache_id,
               observed_write_spec_version)
    REFERENCES surface_placements(id, cache_id, write_spec_version)
      ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY (desired_placement_id, desired_write_spec_version,
               desired_binding_write_revision)
    REFERENCES surface_placement_write_capabilities(
      placement_id, placement_write_spec_version, binding_write_revision)
      ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY (observed_placement_id, observed_write_spec_version,
               observed_binding_write_revision)
    REFERENCES surface_placement_write_capabilities(
      placement_id, placement_write_spec_version, binding_write_revision)
      ON DELETE RESTRICT ON UPDATE RESTRICT
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
`cache.storage_binding_id/prefix` migrate into one complete placement and
observation each. A surface receives a ready single-writer authority only when
preflight proves that its legacy destination was intended to be writable, the
exact credential/capability revision validates, and there is one unambiguous
writer. An explicitly read-only surface remains authority-free. A declared
writable surface whose capability cannot be proven, or any surface with
ambiguous writer evidence, aborts cutover rather than being downgraded or
guessed. The migration then removes the old fields before the new runtime
starts; production code never dual-reads both representations.

### Binding write revisions and rotation

`storage_binding_write_revisions` are immutable declarations. Credential
rotation, revocation replacement, or a write/conditional-write capability
change creates a new revision and observation; only a validated revision may
become `current_write_revision`. The current pointer is a default for new plans,
not authority over existing writers. A provider-side revocation changes the
revision observation to `invalid`, immediately making every authority pinned
to it effectively write-blocked without inventing a replacement.

`revision_fingerprint` hashes the stable binding id, credential-version
reference, and canonical declared-capability encoding. It is unique within the
binding and prevents duplicate insertion of the same complete revision.
`capability_fingerprint` hashes only the canonical capability declaration and
is deliberately non-unique: it groups equivalent revisions for comparison but
does not collapse a new credential version into the old revision.

`surface_placement_write_capabilities` pins a topology write-spec version to a
binding revision. Several rows may coexist for the same placement/spec during
rotation. Desired and observed authority each reference one exact row, so the
same placement can move between binding revisions through the ordinary
authority generation CAS while its binding, prefix, kind, and lifecycle remain
unchanged.

A binding-write change returns a fan-out plan listing every desired/observed
authority on that binding and every placement missing a mapping to the new
revision. Apply creates mappings, reconciles authority rows independently, and
keeps the old revision usable until all pins move. Partial fan-out is explicit
and resumable: surfaces already moved use the new revision while the remainder
continue using the old validated one. After the current pointer and all
authority pins leave an old revision, obsolete placement-capability mappings
are deleted, then its observation/revision may be deleted and its credential
revoked. Immediate `ON DELETE RESTRICT` foreign keys serialize mapping/revision
deletion against concurrent promotion; no check-then-delete race may retire a
revision that a winning authority CAS just pinned.

### Observation ownership

Generic placement health/completeness belongs to
`surface_placement_observations`, whose placement foreign key cascades on
placement deletion. It contains no registry-only publication id. Registry
mutable-pointer progress belongs to
`registry_placement_publication_watermarks`; its non-null `registry_id` is the
discriminator, and its two composite foreign keys prove both that the
placement belongs to that registry and that the publication belongs to the
same registry. Placement deletion cascades the watermark. Publication deletion
is restricted until no watermark references it. Primary keys and referenced
identity/version columns never update.

All authority, placement-write-capability, binding-revision, and publication
foreign keys are immediate/non-deferrable on every supported backend.
Authority-to-placement and authority-to-capability actions are explicitly `ON
DELETE RESTRICT ON UPDATE RESTRICT`; placement-owned observations and
capability mappings cascade only when the already-unreferenced placement is
deleted. Correctness never depends on deferred constraint checking or cascade
order that differs between SQLite/D1, PostgreSQL, and MySQL.

### Authority constraints and derived fields

The four same-surface authority foreign keys above are branch-specific
composite keys. For a registry authority, for example,
`(desired_placement_id, registry_id, desired_write_spec_version)` references
`surface_placements(id, registry_id, write_spec_version)` while the cache
branch is null and therefore ignored under ordinary SQL `MATCH SIMPLE`; cache
authorities use the inverse pair. The observed reference uses the same shape.
This enforces same-surface authority and pins writer-critical placement state
without a polymorphic surface table. The capability foreign keys additionally
pin the exact binding write revision. Deleting a surface explicitly removes
authority before its placements so an interrupted workflow leaves a safe
read-only surface instead of silently cascading away authority.

The observed id, write-spec version, and binding revision are either all null
or all present. Observed generation never exceeds desired generation. `ready`
requires equal
desired/observed placement, write-spec version, binding revision, and
generation; `pending` and `failed` require the desired generation to be newer.
These checks make an impossible reconciliation state fail at the storage
boundary rather than only in one runtime's validation code.

`role`, `write_enabled`, and `write_order` are not stored placement columns and
are not accepted by mutation messages. Read responses derive role as follows:

- the observed authority placement is `primary`, even when degraded;
- another `complete` placement is `replica`;
- `shard` and `archive` follow placement kind; and
- a desired placement that is not yet observed carries a separate
  `promotion_pending` authority status rather than becoming a second primary.

Effective write eligibility is true only when the placement is the observed
authority, desired and observed generations match, reconciliation is `ready`,
the placement specification is active and complete, and its observation is
ready and complete. The observed placement-write-capability mapping must match
the authority's binding revision, that immutable revision must declare every
write capability required by the surface/payload, and its live observation
must be `valid`. Observation or credential failure does not move authority; it
makes effective writes fail closed. Responses expose desired and observed
authority ids, binding revisions, generations, and effective fields so callers
never infer pending or write-blocked state from role strings.

### Effective read eligibility

Read eligibility is request-relative, not a stored placement boolean. For a
route, resolved placement policy, object key, and selected registry publication
generation, `effective_read(placement, request)` is true exactly when all
applicable predicates hold:

1. `desired_state = active` and `desired_read_enabled = true`;
2. placement observation is `ready` or `degraded` and is not stale under the
   route's health policy;
3. kind is not `archive`;
4. a complete placement is observed complete for its declared whole-surface
   scope; a shard is observed complete for its declared partition, is selected
   by the route's explicit hash-partition policy, and its stable partition rule
   matches the requested key;
5. the route pins this placement or its resolved policy contains it, and the
   placement satisfies every route protocol capability;
6. the requested immutable object/payload has `present` object-presence state
   on the placement; missing, corrupt, copying, deleting, or unknown presence
   is ineligible;
7. for a registry mutable pointer, immutable presence is ready and the
   placement's same-registry publication watermark equals the publication id
   selected for this request; and
8. the binding can furnish the required read capability and scoped credential.

A shard can therefore be healthy for its partition without being presented as
a complete endpoint. A degraded placement may remain eligible only while all
object/publication predicates for the particular request are proven; unknown
evidence does not become a speculative read. The placement inventory may show
the coarser desired read-selection posture, but route selection and
`ExplainSurfaceRequest` use this complete formula in native and Worker paths.

### Atomic promotion

`PlanPromotePlacement` records the authority version, current observed
placement, candidate write-spec version, and candidate binding-write revision.
`PromotePlacement` applies only that plan. Its core mutation is one conditional
`UPDATE` of `surface_write_authorities` that:

1. matches the expected authority version and current writer;
2. rejects an authority whose previous desired generation is still pending;
3. uses a correlated candidate lookup to require the planned placement and
   write-spec version, same surface, `complete` kind, active desired state,
   ready/complete observation, and usable binding write capability; and
4. advances desired generation, resource version, and reconciliation state.

The portable statement has this shape; numbered parameters are illustrative
and the correlated surface predicate expands to the registry/cache XOR:

```sql
UPDATE surface_write_authorities
SET desired_placement_id = ?1,
    desired_write_spec_version = ?2,
    desired_binding_write_revision = ?3,
    desired_generation = desired_generation + 1,
    reconciliation_state = 'pending',
    reconciliation_error = NULL,
    resource_version = resource_version + 1,
    updated_at = ?4
WHERE id = ?5
  AND resource_version = ?6
  AND observed_placement_id = ?7
  AND desired_generation = observed_generation
  AND EXISTS (
    SELECT 1
    FROM surface_placements AS p
    JOIN surface_placement_observations AS o ON o.placement_id = p.id
    JOIN surface_placement_write_capabilities AS pc
      ON pc.placement_id = p.id
     AND pc.placement_write_spec_version = p.write_spec_version
    JOIN storage_binding_write_revisions AS br
      ON br.storage_binding_id = pc.storage_binding_id
     AND br.revision = pc.binding_write_revision
    JOIN storage_binding_write_observations AS bo
      ON bo.storage_binding_id = br.storage_binding_id
     AND bo.revision = br.revision
    WHERE p.id = ?1
      AND p.write_spec_version = ?2
      AND pc.binding_write_revision = ?3
      AND ((surface_write_authorities.registry_id IS NOT NULL
            AND p.registry_id = surface_write_authorities.registry_id)
        OR (surface_write_authorities.cache_id IS NOT NULL
            AND p.cache_id = surface_write_authorities.cache_id))
      AND p.kind = 'complete'
      AND p.desired_state = 'active'
      AND o.state = 'ready'
      AND o.completeness = 'complete'
      AND br.writes_supported = 1
      AND bo.state = 'valid'
  );
```

When Hub routing and fencing can switch synchronously, the same statement also
advances the observed placement and generation. When reconciliation is
external, a second single-row authority CAS advances the observed half only
for the exact desired generation after fencing and routing succeed. The
generation mismatch keeps Hub writes closed between those statements. A crash
therefore leaves an explicit resumable pending state, never contradictory
placement roles.

Checking and pinning `write_spec_version` is required. Without the composite
foreign key, PostgreSQL or MySQL could commit a promotion and a concurrent
drain because they update different rows.
If drain wins, promotion's pinned version is stale; if promotion wins, the
writer-critical version cannot advance until authority moves. Health and other
observations remain independently writable.

The CAS is one prepared statement in SQLite and D1 as well as native database
backends. It does not depend on interactive transactions, partial unique
indexes, triggers, multi-table updates, `UPDATE ... RETURNING`, or
backend-specific upsert behavior. It always increments versions, avoiding
MySQL no-change affected-row ambiguity. On a non-one affected count, the
service rereads authoritative rows to classify a stale, missing, ineligible,
or already-applied request without parsing backend SQL errors.

Creating a placement never grants write authority. A new surface may safely
remain read-only until an `INSERT ... SELECT` creates initial authority from a
version-matched eligible placement and a validated immutable binding-write
revision. Drain and deletion reject both desired and observed authority
placements, including both sides of a pending promotion. Observed health or
binding capability may still degrade or become invalid while authority is
pinned; effective writes then fail closed.

The public promote workflow owns both cases. Its plan records that authority
is absent and apply uses guarded `INSERT ... SELECT` for the first writer, or
records the current authority and uses the `UPDATE` above. A uniqueness race
on initial creation is classified by rereading the authority; it never falls
back to an unchecked update.

The baseline constrains `mode` to `single_writer`. A future multi-writer mode
adds immutable `surface_write_policy_revisions` and
`surface_write_policy_members`; the authority row then selects desired and
observed policy revisions with the same generation/CAS contract. It must define
payload eligibility, conditional-write support, fencing, and conflict behavior
before widening the mode constraint. It never reintroduces per-placement write
booleans or write order.

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
  object_kind,           -- immutable | mutable_pointer
  content_hash NULL,
  size NULL,
  mutable_publication_id NULL,
  lifecycle_state,       -- active | tombstoned
  tombstoned_at NULL,
  resource_version,
  CHECK exactly_one(registry_id, cache_id),
  UNIQUE(id, registry_id),
  UNIQUE(id, cache_id),
  UNIQUE(registry_id, object_key),
  UNIQUE(cache_id, object_key)
)

object_placements(
  surface_object_id,
  cache_id NULL,
  registry_id NULL,
  placement_id,
  state,                  -- present | copying | missing | corrupt | deleting
  observed_hash NULL,
  observed_size NULL,
  etag NULL,
  observed_inventory_generation,
  observed_at,
  PRIMARY KEY(surface_object_id, placement_id),
  CHECK exactly_one(registry_id, cache_id),
  FOREIGN KEY(surface_object_id, cache_id)
    REFERENCES surface_objects(id, cache_id),
  FOREIGN KEY(surface_object_id, registry_id)
    REFERENCES surface_objects(id, registry_id),
  FOREIGN KEY(placement_id, cache_id)
    REFERENCES surface_placements(id, cache_id),
  FOREIGN KEY(placement_id, registry_id)
    REFERENCES surface_placements(id, registry_id)
)
```

The Nix-domain mapping is explicit:

```sql
cache_objects(
  id,
  cache_id,
  store_hash,
  store_name,
  narinfo_surface_object_id,
  nar_surface_object_id,
  nar_hash,
  nar_size,
  file_hash,
  file_size,
  compression,
  deriver NULL,
  signature NULL,
  content_address NULL,
  lifecycle_state,       -- active | tombstoned
  published_at,
  last_access_observed_at NULL,
  last_access_source NULL,
  unreferenced_since NULL,
  tombstoned_at NULL,
  resource_version,
  UNIQUE(id, cache_id),
  UNIQUE(id, cache_id, store_hash),
  UNIQUE(cache_id, store_hash),
  UNIQUE(cache_id, narinfo_surface_object_id),
  FOREIGN KEY(narinfo_surface_object_id, cache_id)
    REFERENCES surface_objects(id, cache_id),
  FOREIGN KEY(nar_surface_object_id, cache_id)
    REFERENCES surface_objects(id, cache_id)
)

cache_object_references(
  cache_id,
  cache_object_id,
  referenced_store_hash,
  referenced_cache_object_id NULL,
  PRIMARY KEY(cache_id, cache_object_id, referenced_store_hash),
  FOREIGN KEY(cache_object_id, cache_id)
    REFERENCES cache_objects(id, cache_id),
  FOREIGN KEY(referenced_cache_object_id, cache_id, referenced_store_hash)
    REFERENCES cache_objects(id, cache_id, store_hash)
)
```

The narinfo and NAR are distinct `surface_objects`. Multiple cache objects may
reference one NAR surface object, so NAR ownership and deletion refcounts are
placement-scoped. The final schema does not use an embedded authoritative
`refs` JSON value, cache-level storage binding/prefix, or a binding/prefix NAR
refcount to decide deletion.

`referenced_cache_object_id` is populated when the referenced object is
present and remains null for a missing-reference coverage error. Carrying
`cache_id` through both composite foreign keys makes a cross-cache closure edge
structurally impossible.

## Registry/cache integration records

```sql
cache_retention_subscriptions(
  id,
  cache_id,
  registry_id,
  selector_json,
  selector_digest,
  removal_grace_secs,
  exposure_acknowledged_at NULL,
  enabled,
  last_successful_revision NULL,
  last_refresh_at NULL,
  current_refresh_id NULL,
  refresh_state,          -- stale | refreshing | fresh | failed
  refresh_error NULL,
  retired_at NULL,
  resource_version,
  UNIQUE(cache_id, registry_id),
  UNIQUE(id, cache_id, registry_id),
  FOREIGN KEY(current_refresh_id, id, cache_id, registry_id)
    REFERENCES cache_retention_refreshes(
      refresh_id, subscription_id, cache_id, registry_id)
)

cache_retention_refreshes(
  refresh_id,
  subscription_id,
  cache_id,
  registry_id,
  parent_refresh_id NULL,
  expected_parent_refresh_id NULL,
  expected_subscription_version,
  expected_cache_epoch,
  selector_digest,
  registry_source_revision,
  state,                  -- building | complete | failed
  expected_reason_count,
  actual_reason_count,
  started_at,
  activated_at NULL,
  parent_grace_until NULL,
  finished_at NULL,
  error NULL,
  PRIMARY KEY(refresh_id),
  UNIQUE(refresh_id, subscription_id, cache_id, registry_id),
  CHECK ((state = 'building' AND finished_at IS NULL AND error IS NULL)
      OR (state = 'complete' AND finished_at IS NOT NULL
          AND activated_at IS NOT NULL
          AND actual_reason_count = expected_reason_count AND error IS NULL)
      OR (state = 'failed' AND finished_at IS NOT NULL AND error IS NOT NULL)),
  FOREIGN KEY(subscription_id, cache_id, registry_id)
    REFERENCES cache_retention_subscriptions(id, cache_id, registry_id),
  FOREIGN KEY(parent_refresh_id, subscription_id, cache_id, registry_id)
    REFERENCES cache_retention_refreshes(
      refresh_id, subscription_id, cache_id, registry_id)
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
  snapshot_id,
  release_id,
  registry_id,
  package_name,
  package_version,
  platform,
  artifact_kind,
  store_path,
  store_hash,
  metadata_digest,
  PRIMARY KEY(snapshot_id, package_name, package_version, platform,
              artifact_kind, store_hash),
  FOREIGN KEY(snapshot_id, release_id, registry_id)
    REFERENCES release_artifact_snapshots(
      snapshot_id, release_id, registry_id)
)

release_artifact_snapshots(
  snapshot_id PRIMARY KEY,
  release_id,
  registry_id,
  source_commit,
  verified_tag_oid,
  verification_record_id,
  manifest_digest NULL,
  state,                  -- building | complete | failed
  complete_slot NULL,     -- 1 only for the one complete snapshot
  expected_artifact_count,
  actual_artifact_count,
  started_at,
  completed_at NULL,
  error NULL,
  resource_version,
  UNIQUE(snapshot_id, release_id, registry_id),
  CHECK ((state = 'complete' AND complete_slot = 1
          AND manifest_digest IS NOT NULL AND completed_at IS NOT NULL
          AND error IS NULL
          AND expected_artifact_count = actual_artifact_count)
      OR (state = 'building' AND complete_slot IS NULL
          AND completed_at IS NULL AND error IS NULL)
      OR (state = 'failed' AND complete_slot IS NULL
          AND completed_at IS NOT NULL AND error IS NOT NULL)),
  UNIQUE(release_id, complete_slot),
  FOREIGN KEY(release_id, registry_id) REFERENCES releases(id, registry_id)
)

releases(
  ...,
  complete_artifact_snapshot_id NULL,
  UNIQUE(id, registry_id),
  FOREIGN KEY(complete_artifact_snapshot_id, id, registry_id)
    REFERENCES release_artifact_snapshots(
      snapshot_id, release_id, registry_id)
)

cache_root_reasons(
  id,
  cache_id,
  registry_id NULL,
  store_hash,
  reason_key,
  source_kind,
  refresh_id NULL,
  retention_subscription_id NULL,
  manual_retention_root_id NULL,
  retention_lease_id NULL,
  release_id NULL,
  release_snapshot_id NULL,
  channel_id NULL,
  partition_bucket NULL,
  source_ref,
  source_revision,
  expires_at NULL,
  refreshed_at,
  UNIQUE(id, cache_id),
  UNIQUE(id, cache_id, store_hash),
  UNIQUE(refresh_id, reason_key),
  UNIQUE(manual_retention_root_id, reason_key),
  CHECK valid_root_reason_provenance(
    source_kind, registry_id, refresh_id, retention_subscription_id,
    manual_retention_root_id, retention_lease_id, release_id,
    release_snapshot_id, channel_id, partition_bucket,
    source_ref, source_revision),
  FOREIGN KEY(refresh_id, retention_subscription_id, cache_id, registry_id)
    REFERENCES cache_retention_refreshes(
      refresh_id, subscription_id, cache_id, registry_id),
  FOREIGN KEY(retention_subscription_id, cache_id, registry_id)
    REFERENCES cache_retention_subscriptions(id, cache_id, registry_id),
  FOREIGN KEY(manual_retention_root_id, cache_id)
    REFERENCES manual_retention_roots(id, cache_id),
  FOREIGN KEY(retention_lease_id, manual_retention_root_id)
    REFERENCES retention_leases(id, manual_retention_root_id),
  FOREIGN KEY(release_snapshot_id, release_id, registry_id)
    REFERENCES release_artifact_snapshots(
      snapshot_id, release_id, registry_id)
)

manual_retention_roots(
  id,
  cache_id,
  store_hash,
  protection_kind,       -- indefinite | leased
  current_lease_id NULL,
  reason,
  created_by,
  created_at,
  deleted_at NULL,
  resource_version,
  UNIQUE(id, cache_id),
  CHECK (protection_kind IN ('indefinite', 'leased')),
  CHECK (protection_kind = 'leased' OR current_lease_id IS NULL),
  FOREIGN KEY(current_lease_id, id)
    REFERENCES retention_leases(id, manual_retention_root_id)
)

retention_leases(
  id,
  manual_retention_root_id,
  begins_at,
  expires_at,
  renewed_from_lease_id NULL,
  state,                  -- active | superseded | revoked
  renewed_by,
  renewed_at,
  revoked_by NULL,
  revoked_at NULL,
  resource_version,
  UNIQUE(id, manual_retention_root_id),
  CHECK (expires_at > begins_at),
  CHECK ((state = 'revoked' AND revoked_by IS NOT NULL
          AND revoked_at IS NOT NULL)
      OR (state IN ('active', 'superseded')
          AND revoked_by IS NULL AND revoked_at IS NULL)),
  FOREIGN KEY(renewed_from_lease_id, manual_retention_root_id)
    REFERENCES retention_leases(id, manual_retention_root_id)
)

cache_gc_policies(
  cache_id PRIMARY KEY,
  unreferenced_grace_secs,
  soft_max_bytes NULL,
  soft_max_objects NULL,
  schedule_secs NULL,
  deletion_concurrency,
  retry_initial_secs,
  retry_max_secs,
  retry_max_attempts,
  tombstone_retention_secs,
  resource_version
)

cache_gc_state(
  cache_id PRIMARY KEY,
  epoch,
  epoch_owner_token,
  root_generation,
  object_graph_generation,
  inventory_generation,
  topology_generation,
  current_mark_generation_id NULL,
  destructive_enabled,
  first_sweep_acknowledgement_id NULL,
  first_sweep_acknowledgement_state NULL,
  first_sweep_acknowledged_at NULL,
  resource_version,
  CHECK ((first_sweep_acknowledgement_id IS NULL
          AND first_sweep_acknowledgement_state IS NULL
          AND first_sweep_acknowledged_at IS NULL)
      OR (first_sweep_acknowledgement_id IS NOT NULL
          AND first_sweep_acknowledgement_state = 'applied'
          AND first_sweep_acknowledged_at IS NOT NULL)),
  FOREIGN KEY(current_mark_generation_id, cache_id)
    REFERENCES cache_gc_generations(generation_id, cache_id),
  FOREIGN KEY(first_sweep_acknowledgement_id, cache_id,
              first_sweep_acknowledgement_state)
    REFERENCES cache_gc_first_sweep_acknowledgements(
      acknowledgement_id, cache_id, state)
)

cache_gc_first_sweep_acknowledgements(
  acknowledgement_id,
  cache_id,
  gc_plan_id,
  state,                    -- planned | applied | expired
  expected_cache_epoch,
  expected_gc_policy_version,
  gc_manifest_digest,
  confirmation_hash,
  created_by,
  acknowledged_by NULL,
  created_at,
  expires_at,
  acknowledged_at NULL,
  PRIMARY KEY(acknowledgement_id),
  UNIQUE(acknowledgement_id, cache_id),
  UNIQUE(acknowledgement_id, cache_id, state),
  CHECK ((state = 'planned' AND acknowledged_by IS NULL
          AND acknowledged_at IS NULL)
      OR (state = 'applied' AND acknowledged_by IS NOT NULL
          AND acknowledged_at IS NOT NULL)
      OR (state = 'expired' AND acknowledged_by IS NULL
          AND acknowledged_at IS NULL)),
  FOREIGN KEY(gc_plan_id, cache_id)
    REFERENCES cache_gc_plans(plan_id, cache_id)
)

cache_object_mutation_fences(
  cache_id,
  store_hash,
  operation_id,
  kind,                   -- upload | population | replication | repair
  state,                  -- active | completed | cancelled
  resource_version,
  PRIMARY KEY(cache_id, store_hash, operation_id),
  FOREIGN KEY(cache_id) REFERENCES binary_caches(id),
  FOREIGN KEY(operation_id, cache_id)
    REFERENCES topology_operations(operation_id, cache_id)
)
```

Acknowledgement apply is one epoch-guarded plan/apply batch. It transitions the
acknowledgement to `applied`, records the applying actor and time, and sets all
three cache-state pointer/state/time fields from that row together. The
composite foreign key makes a planned or expired acknowledgement structurally
incapable of opening the destructive gate.

The refresh `current_refresh_id` is the only registry-root entry point. Begin
captures the current pointer in both the lineage `parent_refresh_id` and the
immutable CAS input `expected_parent_refresh_id`, together with the
subscription resource version and cache epoch. Complete requires exact
reason count and provenance plus an unchanged pointer, selector, registry
source revision, subscription version, and GC epoch. Complete sets
`parent_grace_until`, advances the pointer, and increments both
`root_generation` and the epoch in one atomic batch. Failed generations never
become current. Active reasons are the current complete generation plus only
the still-graced parent lineage; retirement has its own finite grace cutoff.

Reason-kind constraints make provenance total: catalog reasons carry refresh,
subscription, registry, and indexed revision; release reasons also carry a
release and its complete snapshot; channel reasons additionally carry channel
and partition; indefinite manual reasons carry only their manual root; lease
reasons carry the root and its exact current lease. The composite foreign keys
prevent cross-cache, cross-registry, and cross-release provenance.

Manual-root renewal creates a new lease linked to the prior lease, preserving
who extended protection and when. The root pointer and lease states define the
single active chain head; historical, superseded, revoked, expired, or deleted
roots cannot contribute. Subscription refresh, manual-root mutation, and lease
issue/renew/revoke advance `root_generation`; cache object/reference
publication advances `object_graph_generation`; and a complete placement scan
advances `inventory_generation`. Every one also advances the single epoch.

`inventory_generation` advances only when one cache-wide inventory operation
has completed the logical object scan and every applicable placement scan. A
single placement finishing does not make the cache inventory complete. Active
object-mutation fences are relational apply blockers; an operation removes or
completes its fences only in the same transition that publishes object metadata
and advances `object_graph_generation`.

Every competing root, graph, inventory, cache-topology, or fence
mutation conditionally advances `cache_gc_state.epoch` in the same native
transaction or D1 atomic batch as its own rows. Object publication and GC apply
also advance `object_graph_generation`; placement/policy/authority work
advances `topology_generation`, except for an authority-only desired/observed
CAS as described below. A policy update advances the epoch and its
policy version. No mutator may update one of these domains without claiming the
state row, and GC never updates authority fields itself.

Changing only desired/observed write authority does not change logical
membership, observed physical inventory, or a GC deletion target, so its
portable single-row CAS does not update cache GC state. Reconciliation that may
publish bytes first creates an object-mutation fence; creating/completing that
fence and publishing object metadata each claim the cache epoch. Any placement
lifecycle, policy, inventory, or presence change likewise uses its ordinary
topology/graph epoch mutation. This preserves the one-statement authority
contract without allowing a writer switch to hide concurrent object work from
GC.

The GC policy contains only cache-global age, soft-cap, schedule, retry,
concurrency, and tombstone-lifecycle behavior. Release and channel retention
selectors never reappear in it.

Release indexing stages one snapshot header and its artifacts, recomputes the
canonical full-metadata digest and actual count, then publishes that same row
as the sole complete snapshot and initializes the release pointer
transactionally. `state = complete` plus matching zero counts is a valid empty
snapshot; absence of a complete header is unsafe for a release-dependent
selector. A failed later verification or index attempt remains a separate
non-complete row and cannot replace an existing complete header or artifact set. Only
`building -> complete|failed` is legal; terminal headers and their child rows
are immutable in every steady-state write method.

## GC generations, plans, and deletion work

```sql
cache_gc_generations(
  generation_id PRIMARY KEY,
  cache_id,
  state,                  -- building | complete | failed
  cutoff_at,
  expected_epoch,
  root_generation,
  object_graph_generation,
  inventory_generation,
  gc_policy_version,
  topology_version,
  root_count,
  marked_object_count,
  coverage_error_count,
  error NULL,
  created_at,
  completed_at NULL,
  UNIQUE(generation_id, cache_id)
)

cache_gc_generation_roots(
  cache_id,
  generation_id,
  root_reason_id,
  store_hash,
  PRIMARY KEY(cache_id, generation_id, root_reason_id),
  FOREIGN KEY(generation_id, cache_id)
    REFERENCES cache_gc_generations(generation_id, cache_id),
  FOREIGN KEY(root_reason_id, cache_id, store_hash)
    REFERENCES cache_root_reasons(id, cache_id, store_hash)
)

cache_gc_marks(
  cache_id,
  generation_id,
  cache_object_id,
  PRIMARY KEY(cache_id, generation_id, cache_object_id),
  FOREIGN KEY(generation_id, cache_id)
    REFERENCES cache_gc_generations(generation_id, cache_id),
  FOREIGN KEY(cache_object_id, cache_id)
    REFERENCES cache_objects(id, cache_id)
)

cache_gc_generation_coverage_errors(
  cache_id,
  generation_id,
  error_id,
  kind,                   -- missing_root | missing_reference | stale_inventory
  store_hash NULL,
  referenced_store_hash NULL,
  detail,
  PRIMARY KEY(cache_id, generation_id, error_id),
  FOREIGN KEY(generation_id, cache_id)
    REFERENCES cache_gc_generations(generation_id, cache_id)
)

cache_gc_plans(
  plan_id PRIMARY KEY,
  cache_id,
  generation_id,
  expected_epoch,
  input_versions_digest,
  confirmation_hash,
  created_by,
  created_at,
  expires_at,
  applied_at NULL,
  operation_id NULL,
  UNIQUE(plan_id, cache_id),
  FOREIGN KEY(generation_id, cache_id)
    REFERENCES cache_gc_generations(generation_id, cache_id),
  FOREIGN KEY(operation_id, cache_id)
    REFERENCES topology_operations(operation_id, cache_id)
)

cache_gc_apply_claims(
  cache_id,
  plan_id,
  claim_id,
  expected_epoch,
  manifest_digest,
  actor_scope_digest,
  confirmation_hash,
  claimed_at,
  PRIMARY KEY(cache_id, plan_id),
  UNIQUE(cache_id, expected_epoch),
  UNIQUE(claim_id, cache_id),
  UNIQUE(claim_id, plan_id, cache_id),
  FOREIGN KEY(plan_id, cache_id)
    REFERENCES cache_gc_plans(plan_id, cache_id)
)

cache_gc_apply_assertions(
  cache_id,
  plan_id,
  claim_id,
  ok,
  asserted_at,
  PRIMARY KEY(cache_id, plan_id),
  CHECK(ok = 1),
  FOREIGN KEY(claim_id, plan_id, cache_id)
    REFERENCES cache_gc_apply_claims(claim_id, plan_id, cache_id)
)

cache_gc_plan_objects(
  cache_id,
  plan_id,
  cache_object_id,
  expected_object_version,
  expected_unreferenced_since,
  eligibility_reason,     -- ttl | byte_cap | object_cap
  logical_bytes,
  PRIMARY KEY(cache_id, plan_id, cache_object_id),
  FOREIGN KEY(plan_id, cache_id)
    REFERENCES cache_gc_plans(plan_id, cache_id),
  FOREIGN KEY(cache_object_id, cache_id)
    REFERENCES cache_objects(id, cache_id)
)

cache_gc_plan_actions(
  action_id PRIMARY KEY,
  cache_id,
  plan_id,
  surface_object_id,
  placement_id,
  phase,                  -- narinfo | nar
  expected_etag NULL,
  expected_hash NULL,
  expected_size NULL,
  expected_inventory_generation,
  estimated_reclaimable_bytes,
  UNIQUE(action_id, plan_id, cache_id),
  UNIQUE(action_id, plan_id, cache_id, surface_object_id, placement_id),
  UNIQUE(plan_id, surface_object_id, placement_id),
  FOREIGN KEY(plan_id, cache_id)
    REFERENCES cache_gc_plans(plan_id, cache_id),
  FOREIGN KEY(surface_object_id, cache_id)
    REFERENCES surface_objects(id, cache_id),
  FOREIGN KEY(placement_id, cache_id)
    REFERENCES surface_placements(id, cache_id)
)

cache_gc_plan_object_actions(
  cache_id,
  plan_id,
  cache_object_id,
  action_id,
  PRIMARY KEY(cache_id, plan_id, cache_object_id, action_id),
  FOREIGN KEY(cache_id, plan_id, cache_object_id)
    REFERENCES cache_gc_plan_objects(cache_id, plan_id, cache_object_id),
  FOREIGN KEY(action_id, plan_id, cache_id)
    REFERENCES cache_gc_plan_actions(action_id, plan_id, cache_id)
)

cache_gc_action_dependencies(
  cache_id,
  plan_id,
  action_id,
  prerequisite_action_id,
  PRIMARY KEY(cache_id, plan_id, action_id, prerequisite_action_id),
  FOREIGN KEY(action_id, plan_id, cache_id)
    REFERENCES cache_gc_plan_actions(action_id, plan_id, cache_id),
  FOREIGN KEY(prerequisite_action_id, plan_id, cache_id)
    REFERENCES cache_gc_plan_actions(action_id, plan_id, cache_id)
)

object_deletion_jobs(
  job_id PRIMARY KEY,
  cache_id,
  originating_operation_id,
  surface_object_id,
  placement_id,
  phase,                  -- narinfo | nar
  expected_etag NULL,
  expected_hash NULL,
  expected_size NULL,
  expected_inventory_generation,
  state,                  -- preparing | pending | running | failed | blocked | succeeded | abandoned | cancelled
  active_slot NULL,       -- 1 for every nonterminal job
  attempt_count,
  max_attempts,
  next_attempt_at NULL,
  error_class NULL,
  error NULL,
  confirmed_reclaimed_bytes DEFAULT 0,
  leaked_bytes DEFAULT 0,
  resource_version,
  UNIQUE(job_id, cache_id),
  UNIQUE(job_id, cache_id, surface_object_id, placement_id),
  UNIQUE(surface_object_id, placement_id, active_slot),
  FOREIGN KEY(originating_operation_id, cache_id)
    REFERENCES topology_operations(operation_id, cache_id),
  FOREIGN KEY(surface_object_id, cache_id)
    REFERENCES surface_objects(id, cache_id),
  FOREIGN KEY(placement_id, cache_id)
    REFERENCES surface_placements(id, cache_id),
  CHECK ((state IN ('preparing', 'pending', 'running', 'failed', 'blocked')
          AND active_slot = 1)
      OR (state IN ('succeeded', 'abandoned', 'cancelled')
          AND active_slot IS NULL)),
  CHECK (state = 'succeeded' OR confirmed_reclaimed_bytes = 0),
  CHECK (state = 'abandoned' OR leaked_bytes = 0)
)

cache_gc_action_jobs(
  cache_id,
  plan_id,
  action_id,
  job_id,
  surface_object_id,
  placement_id,
  PRIMARY KEY(cache_id, plan_id, action_id),
  FOREIGN KEY(action_id, plan_id, cache_id, surface_object_id, placement_id)
    REFERENCES cache_gc_plan_actions(
      action_id, plan_id, cache_id, surface_object_id, placement_id),
  FOREIGN KEY(job_id, cache_id, surface_object_id, placement_id)
    REFERENCES object_deletion_jobs(
      job_id, cache_id, surface_object_id, placement_id)
)
```

`topology_plans` and `topology_operations` supply the common immutable plan and
long-operation envelopes. The GC-specific tables are relational execution
authority: workers do not derive candidates from an opaque effects JSON value.
The common operation table exposes `UNIQUE(operation_id, cache_id)` for every
cache operation so all operation foreign keys above preserve cache ownership.
A mark generation is published only after its root set, closure, input
versions, and coverage status validate.

Applying a GC plan uses the same guarded statement batch in a native transaction
or Worker D1 atomic batch. The first `INSERT ... SELECT` creates a unique apply
claim only if the epoch, unused plan, expiry, actor/scope/confirmation, every
candidate/root/presence/fence predicate, and all expected manifest counts match
in that one database snapshot. Every following epoch, tombstone, generation,
operation, and job statement is gated by that exact claim id, immutable plan
manifest, and `cache_gc_state.epoch_owner_token = claim_id` at
`epoch = expected_epoch + 1`. A missing claim or a claim that did not win the
epoch CAS can therefore authorize no destructive write. The claim has
`UNIQUE(cache_id, expected_epoch)`, so two GC plans cannot both claim one cache
epoch.

The last statement inserts one row into `cache_gc_apply_assertions`, whose
`CHECK (ok = 1)` value is computed from the claim, matching epoch owner token,
final epoch/generation,
tombstone count, deterministic operation, action/job counts, and dependency-
ready count. It always attempts one insert. A missing claim or any partial
effect inserts `ok = 0`, raises a portable constraint error, and makes D1 roll
back the entire atomic batch just as a native transaction does. The algorithm
never relies on inspecting intermediate D1 affected-row counts. A competing
apply loses the unique claim; after failure or on retry, the service rereads
the deterministic applied-plan/operation relation and returns the existing
operation only when every identity matches.

An action exists for every observed physical copy, including off-policy copies.
A shared NAR action may have several prerequisite narinfo actions through
`cache_gc_action_dependencies`; it becomes runnable only after all are
confirmed and the placement-scoped refcount from non-tombstoned narinfos is
zero. Only `succeeded` satisfies a dependency. An abandoned narinfo makes its
dependent NAR job `blocked`; the NAR cannot run and requires its own reviewed
abandonment. Failed work preserves possible presence.

The global `(surface_object_id, placement_id, active_slot)` uniqueness permits
one nonterminal delete regardless of plan. Apply reuses an existing job only
when its expected hash, ETag, inventory generation, and phase match; otherwise
the plan is stale. A success CAS records observed size as confirmed reclaimed
bytes exactly once and clears `active_slot`. Operation totals sum unique linked
jobs, so retry, crash recovery, and shared-NAR fan-in cannot double count.
`abandoned` clears the slot but records possible bytes only as leaked.
Tombstones remain until all actions are `succeeded` or explicitly `abandoned`,
then remain for the configured tombstone-retention interval.

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
  `CancelPlacementPromotion`, `CancelPlacementDrain`, `DeletePlacement`
- `GetWriteAuthority`, `ReconcileWriteAuthority`
- `ListPlacements`, `GetPlacement`, `ScanPlacement`
- `GetPlacementPolicy`, `SetPlacementPolicy`, `TestPlacementPolicy`
- `ReplicatePlacement`, `RepairPlacement`, `ListObjectPresence`
- `ListPlacementEquivalences`, `ConfirmPlacementEquivalence`,
  `DeletePlacementEquivalence`

Creating or moving a placement never silently changes a delivery route or
signed consumer stack. An impact endpoint reports affected routes and
integrations before apply. Creation accepts placement kind and desired read
state, never primary role or write enablement. Promotion is the only ordinary
operation that changes desired write authority; reconciliation is idempotent
and generation guarded. Cancellation is a reviewed, generation-guarded
reconciliation back to the still-observed writer; it never clears a pending
row without proving the candidate is fenced and the observed writer is ready.

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
- `ListStorageBindingWriteRevisions`, `GetStorageBindingWriteRevision`,
  `ReconcileStorageBindingWriteRevision`
- `GetInstanceDefaultStorageBinding`
- `GetInstanceTopologyDefaults`, `SetInstanceTopologyDefaults`
- `GetOrganizationTopologyDefaults`, `SetOrganizationTopologyDefaults`

The public binding record exposes capabilities, immutable revision references,
and health, never credential material. Rotation plans include authority fan-out
and explicit old-revision retirement. Default changes have their own impact
plan and affect only future workflows unless the operator separately plans
changes to existing resources.

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
- `GetCacheGcPlan`, `GetCacheGcRun`, `GetCacheGcDeletionJob`,
  `ListCacheGcDeletionJobs`
- `RetryCacheGcDeletionJob`, `PlanAbandonCacheGcDeletionJob`,
  `AbandonCacheGcDeletionJob`
- `PlanPlacementEviction`, `RunPlacementEviction`

Logical GC and placement eviction are different methods and audit event types.

## Validation transactions

Mutations that cross records use a plan/apply shape:

1. resolve current topology and version ids;
2. return semantic effects, warnings, and preconditions;
3. apply against the same versions or reject as stale; and
4. enqueue replication/probe/index work after the control-plane transaction.

Examples include surface visibility changes, domain access changes, placement
drains, write-authority promotion, canonical route changes, and destructive
GC. GC apply has the same portable requirement as promotion: logical
tombstoning and operation creation are one version-guarded control-plane
transition, not an interactive transaction that Worker D1 cannot reproduce.
Promotion itself remains the sole authority-row compare-and-swap described
above; GC never changes write authority.

## Complete cutover

- Every still-supported public URL is imported as an ordinary delivery route,
  not a compatibility alias.
- Every committed registry `[caches]` URL is checked before cutover. If its URL
  will change, the signed change is merged before switching traffic.
- The schema migration creates placements, domains, gateways, routes,
  observations, proven binding-write revisions, applicable write authorities,
  integrations, release snapshots, root reasons, object mappings, GC state,
  and safe initial mark inputs; validates them; and drops the old topology and
  GC tables/columns in the same maintenance operation. Explicitly read-only
  surfaces remain authority-free. A declared writable surface without one
  unambiguous validated legacy writer, or any physical-location collision,
  aborts the cutover.
- Native and Worker binaries start only against the new schema and route
  index. They contain no legacy read/write branch.
- Old API messages, methods, UI handlers, CLI variants, and help text are
  removed rather than deprecated in place.
- The final runtime contains no cache-global binding/prefix writer, DB-first
  sweep, legacy cache/registry-link root derivation, embedded authoritative
  reference JSON, synchronous dry-run GC branch, or compatibility view over
  the removed GC schema.
- Fresh installations use a squashed new Hub schema baseline. The one-shot
  cutover artifact is not part of the steady-state runtime.
- Provisional development migrations that stored primary/write fields are
  rewritten before merge rather than followed by compatibility migrations.
  Branch-local databases that ran an unreleased shape are reset; production
  never learns to read both authority models.
