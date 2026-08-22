# Data model and API

The records below are normative responsibilities, not a requirement to add a
single polymorphic `surfaces` SQL table. SQLite, Durable Object SQLite,
PostgreSQL, and MySQL must
all enforce equivalent ownership and one-of constraints.

This file defines resource responsibilities and schema. The normative
Connect-JSON service/message and CLI mapping is in
[`09-interface-contracts.md`](09-interface-contracts.md).

## Binding-write capability and placement records

```sql
bindings(
  id,
  org_id NULL,
  owner_scope_key,       -- instance | org:<stable-id>
  name,
  kind,                  -- local_fs | s3 | r2
  local_root_path NULL,
  object_bucket NULL,
  object_prefix NULL,
  endpoint_scheme NULL,  -- https
  endpoint_host_kind NULL, -- dns | ipv4 | ipv6
  endpoint_host_bytes NULL,
  endpoint_port NULL,
  signing_region NULL,
  access_mode NULL,      -- public | private; object stores only
  resource_version,
  created_at,
  updated_at,
  UNIQUE(id, owner_scope_key),
  UNIQUE(org_id, name),
  CHECK valid_binding_kind_shape,
  CHECK(kind = 'local_fs' OR endpoint_scheme = 'https')
)

binding_credential_revisions(
  binding_id,
  purpose,               -- read | write | delete | list | presign
  generation,
  secret_version_ref,
  validation_state,      -- unknown | validating | valid | invalid | retired
  validated_at NULL,
  validation_error NULL,
  credential_fingerprint,
  created_by,
  created_at,
  PRIMARY KEY(binding_id, purpose, generation),
  UNIQUE(binding_id, purpose, secret_version_ref),
  CHECK(generation > 0),
  FOREIGN KEY(binding_id) REFERENCES bindings(id)
    ON DELETE CASCADE ON UPDATE RESTRICT
)

binding_credential_heads(
  binding_id,
  purpose,
  current_generation,
  resource_version,
  updated_at,
  PRIMARY KEY(binding_id, purpose),
  FOREIGN KEY(binding_id, purpose, current_generation)
    REFERENCES binding_credential_revisions(
      binding_id, purpose, generation)
      ON DELETE RESTRICT ON UPDATE RESTRICT
)

binding_consumer_scopes(
  binding_id,
  consumer_scope_key,
  grant_generation,
  grant_kind,            -- owner | instance_default | explicit
  state,                 -- active | revoked
  granted_by,
  granted_at,
  revoked_by NULL,
  revoked_at NULL,
  resource_version,
  PRIMARY KEY(binding_id, consumer_scope_key),
  UNIQUE(binding_id, consumer_scope_key, grant_generation, state),
  CHECK(grant_generation > 0),
  CHECK((state = 'active' AND revoked_by IS NULL AND revoked_at IS NULL)
     OR (state = 'revoked' AND revoked_by IS NOT NULL
         AND revoked_at IS NOT NULL)),
  FOREIGN KEY(binding_id) REFERENCES bindings(id)
)

binding_write_revisions(
  binding_id,
  revision,
  write_credential_purpose,  -- always write
  write_credential_generation,
  write_credential_version_ref,
  writes_supported,
  conditional_writes_supported,
  revision_fingerprint,
  capability_fingerprint,
  created_at,
  PRIMARY KEY(binding_id, revision),
  UNIQUE(binding_id, revision_fingerprint),
  CHECK(write_credential_purpose = 'write'),
  FOREIGN KEY(binding_id, write_credential_purpose,
              write_credential_generation)
    REFERENCES binding_credential_revisions(
      binding_id, purpose, generation)
      ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY (binding_id)
    REFERENCES bindings(id)
      ON DELETE CASCADE ON UPDATE RESTRICT
)

binding_write_state(
  binding_id PRIMARY KEY,
  current_write_revision NULL,
  resource_version,
  updated_at,
  FOREIGN KEY (binding_id)
    REFERENCES bindings(id)
      ON DELETE CASCADE ON UPDATE RESTRICT,
  FOREIGN KEY (binding_id, current_write_revision)
    REFERENCES binding_write_revisions(binding_id, revision)
      ON DELETE RESTRICT ON UPDATE RESTRICT
)

binding_write_observations(
  binding_id,
  revision,
  state,                -- unknown | validating | valid | invalid
  validated_at NULL,
  error NULL,
  observation_version,
  PRIMARY KEY(binding_id, revision),
  FOREIGN KEY (binding_id, revision)
    REFERENCES binding_write_revisions(binding_id, revision)
      ON DELETE CASCADE ON UPDATE RESTRICT
)

surface_placements(
  id,
  registry_id NULL,
  cache_id NULL,
  consumer_scope_key,
  name,
  binding_id,
  prefix,
  kind,                 -- complete | shard | archive
  desired_state,        -- active | draining | offline
  hash_range_start NULL,
  hash_range_end NULL,
  desired_read_enabled,
  read_order,
  write_spec_version,
  resource_version,
  created_at,
  updated_at,
  CHECK exactly_one(registry_id, cache_id),
  CHECK shard_iff_hash_range_v1(kind, hash_range_start, hash_range_end),
  CHECK valid_half_open_hash_range(hash_range_start, hash_range_end),
  CHECK archive_is_not_read_selected(kind, desired_read_enabled),
  CHECK write_spec_version > 0,
  UNIQUE(registry_id, name),
  UNIQUE(cache_id, name),
  UNIQUE(id, registry_id),
  UNIQUE(id, cache_id),
  UNIQUE(id, kind),
  UNIQUE(id, registry_id, kind),
  UNIQUE(id, cache_id, kind),
  UNIQUE(id, registry_id, kind, hash_range_start, hash_range_end),
  UNIQUE(id, cache_id, kind, hash_range_start, hash_range_end),
  UNIQUE(id, binding_id),
  UNIQUE(id, binding_id, prefix),
  UNIQUE(id, registry_id, write_spec_version),
  UNIQUE(id, cache_id, write_spec_version),
  UNIQUE(id, binding_id, write_spec_version),
  UNIQUE(binding_id, prefix),
  FOREIGN KEY(registry_id, consumer_scope_key)
    REFERENCES registries(id, scope_key),
  FOREIGN KEY(cache_id, consumer_scope_key)
    REFERENCES binary_caches(id, scope_key),
  FOREIGN KEY(binding_id, consumer_scope_key)
    REFERENCES binding_consumer_scopes(
      binding_id, consumer_scope_key)
)

surface_placement_write_capabilities(
  placement_id,
  placement_write_spec_version,
  binding_id,
  binding_write_revision,
  created_at,
  PRIMARY KEY(placement_id, placement_write_spec_version,
              binding_write_revision),
  FOREIGN KEY (placement_id, binding_id,
               placement_write_spec_version)
    REFERENCES surface_placements(id, binding_id, write_spec_version)
      ON DELETE CASCADE ON UPDATE RESTRICT,
  FOREIGN KEY (binding_id, binding_write_revision)
    REFERENCES binding_write_revisions(binding_id, revision)
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
  name,
  current_revision_id NULL,
  current_revision_state NULL,
  resource_version,
  CHECK exactly_one(registry_id, cache_id),
  CHECK ((current_revision_id IS NULL AND current_revision_state IS NULL)
      OR (current_revision_id IS NOT NULL
          AND current_revision_state = 'published')),
  UNIQUE(registry_id, name),
  UNIQUE(cache_id, name),
  UNIQUE(id, registry_id),
  UNIQUE(id, cache_id),
  FOREIGN KEY(current_revision_id, id, registry_id, current_revision_state)
    REFERENCES placement_policy_revisions(
      id, policy_id, registry_id, state),
  FOREIGN KEY(current_revision_id, id, cache_id, current_revision_state)
    REFERENCES placement_policy_revisions(id, policy_id, cache_id, state)
)

placement_policy_revisions(
  id,
  policy_id,
  registry_id NULL,
  cache_id NULL,
  consumer_scope_key,
  revision,
  kind,                 -- ordered_failover | local_then_remote | hash_partition
  local_boundary_id NULL,
  local_boundary_revision NULL,
  allow_remote_fallback NULL,
  hash_rule NULL,       -- hash_range_v1
  state,                -- building | published | failed
  expected_group_count,
  expected_member_count,
  build_version,
  content_digest NULL,
  created_by,
  created_at,
  published_at NULL,
  error NULL,
  CHECK exactly_one(registry_id, cache_id),
  CHECK fields_match_policy_kind,
  CHECK ((state = 'building' AND content_digest IS NULL
          AND published_at IS NULL AND error IS NULL)
      OR (state = 'published' AND content_digest IS NOT NULL
          AND published_at IS NOT NULL AND error IS NULL)
      OR (state = 'failed' AND published_at IS NULL AND error IS NOT NULL)),
  UNIQUE(policy_id, revision),
  UNIQUE(id, policy_id, registry_id),
  UNIQUE(id, policy_id, cache_id),
  UNIQUE(id, policy_id, registry_id, state),
  UNIQUE(id, policy_id, cache_id, state),
  UNIQUE(id, registry_id),
  UNIQUE(id, cache_id),
  UNIQUE(id, registry_id, kind),
  UNIQUE(id, cache_id, kind),
  UNIQUE(id, registry_id, state),
  UNIQUE(id, cache_id, state),
  FOREIGN KEY(policy_id, registry_id)
    REFERENCES placement_policies(id, registry_id),
  FOREIGN KEY(policy_id, cache_id)
    REFERENCES placement_policies(id, cache_id),
  FOREIGN KEY(registry_id, consumer_scope_key)
    REFERENCES registries(id, scope_key),
  FOREIGN KEY(cache_id, consumer_scope_key)
    REFERENCES binary_caches(id, scope_key),
  FOREIGN KEY(local_boundary_id, local_boundary_revision)
    REFERENCES network_policy_revisions(boundary_id, revision),
  FOREIGN KEY(local_boundary_id, consumer_scope_key)
    REFERENCES network_policy_consumer_scopes(
      boundary_id, consumer_scope_key)
)

placement_policy_replica_groups(
  policy_revision_id,
  registry_id NULL,
  cache_id NULL,
  group_id,
  group_order,
  policy_kind,
  purpose,              -- ordered | local | remote | hash_range | complete_fallback
  range_start NULL,     -- inclusive u32 start in 0..65535, hash_range only
  range_end NULL,       -- exclusive u32 end in 1..65536, hash_range only
  PRIMARY KEY(policy_revision_id, group_id),
  UNIQUE(policy_revision_id, group_order),
  UNIQUE(policy_revision_id, group_id, registry_id),
  UNIQUE(policy_revision_id, group_id, cache_id),
  UNIQUE(policy_revision_id, group_id, registry_id, policy_kind, purpose),
  UNIQUE(policy_revision_id, group_id, cache_id, policy_kind, purpose),
  UNIQUE(policy_revision_id, group_id, registry_id, policy_kind, purpose,
         range_start, range_end),
  UNIQUE(policy_revision_id, group_id, cache_id, policy_kind, purpose,
         range_start, range_end),
  CHECK exactly_one(registry_id, cache_id),
  CHECK valid_group_shape,
  FOREIGN KEY(policy_revision_id, registry_id, policy_kind)
    REFERENCES placement_policy_revisions(id, registry_id, kind),
  FOREIGN KEY(policy_revision_id, cache_id, policy_kind)
    REFERENCES placement_policy_revisions(id, cache_id, kind)
)

placement_policy_complete_members(
  policy_revision_id,
  group_id,
  registry_id NULL,
  cache_id NULL,
  policy_kind,
  group_purpose,
  placement_id,
  placement_kind,       -- complete
  member_order,
  PRIMARY KEY(policy_revision_id, group_id, placement_id),
  UNIQUE(policy_revision_id, group_id, member_order),
  UNIQUE(policy_revision_id, placement_id),
  CHECK exactly_one(registry_id, cache_id),
  CHECK placement_kind = 'complete',
  CHECK valid_complete_group_member(policy_kind, group_purpose),
  FOREIGN KEY(policy_revision_id, group_id, registry_id, policy_kind,
              group_purpose)
    REFERENCES placement_policy_replica_groups(
      policy_revision_id, group_id, registry_id, policy_kind, purpose),
  FOREIGN KEY(policy_revision_id, group_id, cache_id, policy_kind,
              group_purpose)
    REFERENCES placement_policy_replica_groups(
      policy_revision_id, group_id, cache_id, policy_kind, purpose),
  FOREIGN KEY(placement_id, registry_id, placement_kind)
    REFERENCES surface_placements(id, registry_id, kind),
  FOREIGN KEY(placement_id, cache_id, placement_kind)
    REFERENCES surface_placements(id, cache_id, kind)
)

placement_policy_shard_members(
  policy_revision_id,
  group_id,
  registry_id NULL,
  cache_id NULL,
  policy_kind,          -- hash_partition
  group_purpose,        -- hash_range
  range_start,
  range_end,
  placement_id,
  placement_kind,       -- shard
  member_order,
  PRIMARY KEY(policy_revision_id, group_id, placement_id),
  UNIQUE(policy_revision_id, group_id, member_order),
  UNIQUE(policy_revision_id, placement_id),
  CHECK exactly_one(registry_id, cache_id),
  CHECK policy_kind = 'hash_partition',
  CHECK group_purpose = 'hash_range',
  CHECK placement_kind = 'shard',
  FOREIGN KEY(policy_revision_id, group_id, registry_id, policy_kind,
              group_purpose, range_start, range_end)
    REFERENCES placement_policy_replica_groups(
      policy_revision_id, group_id, registry_id, policy_kind, purpose,
      range_start, range_end),
  FOREIGN KEY(policy_revision_id, group_id, cache_id, policy_kind,
              group_purpose, range_start, range_end)
    REFERENCES placement_policy_replica_groups(
      policy_revision_id, group_id, cache_id, policy_kind, purpose,
      range_start, range_end),
  FOREIGN KEY(placement_id, registry_id, placement_kind,
              range_start, range_end)
    REFERENCES surface_placements(
      id, registry_id, kind, hash_range_start, hash_range_end),
  FOREIGN KEY(placement_id, cache_id, placement_kind,
              range_start, range_end)
    REFERENCES surface_placements(
      id, cache_id, kind, hash_range_start, hash_range_end)
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

`valid_binding_kind_shape` is a closed union. `local_fs` requires one
canonical absolute `local_root_path` and requires every object-store field and
credential head to be absent. `s3` and `r2` require bucket, canonical prefix
(empty means the bucket root), typed HTTPS endpoint origin, effective port,
signing region, and access mode, and require `local_root_path` to be null.
`public` object-store bindings have no credential heads and no write revision;
`private` bindings become usable for an operation only after its exact
purpose-specific credential revision validates. Bucket, prefix, kind, owner,
and name are immutable storage identity; changing them creates a replacement
binding and moves placements/gateways through impact plans. Update may change
only object endpoint, signing region, or access mode. Moving to `public`
requires zero credential/write pins and retires heads in the same plan.

Credential `set` is valid only when that purpose has no head and creates
generation one. Credential `rotate` requires the expected current generation
and creates its successor; it never overwrites secret references. `write` or
`presign` changes also create and validate the corresponding immutable
binding-write revision before authority can move. Secret values never enter the
database or API—only closed-grammar immutable provider references and required
SHA-256 fingerprints do. The runtime resolves the exact provider version and
must verify that digest before any use; an absent version or drift fails closed.

Policy revisions and all group/member rows are immutable. Ordered failover has
one `ordered` group. Local-then-remote has one group per configured access class
and stores the exact trusted boundary revision plus remote-fallback choice on
the revision and in its content digest.
Hash partition uses `hash_range_v1`, one replica group per non-overlapping
range, and optional ordered `complete_fallback` groups. Validation requires
complete bucket coverage or a complete fallback, permits replicas only inside
one identical range group, and checks placement kind and same-surface ownership
through the composite keys above. Routes and population targets pin an exact
revision; publishing a new current revision never changes an existing target.
Revision construction is permitted only in `building`. Every group or member
mutation first locks the revision row on transactional databases, verifies
`state = building` and the caller's expected `build_version`, performs exactly
one mutation, and increments `build_version` in the same transaction. The
implementation performs the equivalent guarded mutation and increment in one
Durable Object implementation uses an atomic batch. A final native transaction
or Durable Object atomic batch verifies exact
group/member counts, range coverage, content digest, all kind/range keys, and
the unchanged policy and build versions; its publication update is a CAS on
`state = building` and that exact `build_version`. It then marks the revision
`published` and optionally advances the policy current pointer. A stale builder
therefore cannot append to or alter published content on any backend.
Route and population foreign keys carry `state = published`, so a partial or
failed revision is structurally untargetable. Published revisions and their
groups/members are immutable.
Every revision/group/member and route target foreign key is immediate
`ON UPDATE RESTRICT ON DELETE RESTRICT`; deletion workflows first move or
remove dependents under their resource-version plans.

Placement equivalence handles the rare case where two logical placement
records intentionally address the same physical bytes. Confirmation records
operator provenance and a validated backend identity fingerprint. Placements
must belong to the same surface and resolve the same object keys/content; the
create path never infers equivalence from similar endpoint/bucket strings.

Existing `registry.binding_id/prefix` and
`cache.binding_id/prefix` migrate into one complete placement and
observation each. A surface receives a ready single-writer authority only when
preflight proves that its legacy destination was intended to be writable, the
exact credential/capability revision validates, and there is one unambiguous
writer. An explicitly read-only surface remains authority-free. A declared
writable surface whose capability cannot be proven, or any surface with
ambiguous writer evidence, aborts cutover rather than being downgraded or
guessed. The migration then removes the old fields before the new runtime
starts; production code never dual-reads both representations.

### Binding write revisions and rotation

`binding_write_revisions` are immutable declarations. Credential
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
order that differs between SQLite, Durable Object SQLite, PostgreSQL, and MySQL.

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

For a mutable registry request, the selected generation is a snapshot of the
surface's committed publication head taken before placement selection. The same
id is retained through every failover attempt; selection never reads candidate
heads independently.

1. `desired_state = active` and `desired_read_enabled = true`;
2. placement observation is `ready` or `degraded` and is not stale under the
   route's health policy;
3. kind is not `archive`;
4. a complete placement is observed complete for its declared whole-surface
   scope; a shard is observed complete for its declared partition, is selected
   by the route's explicit hash-partition policy, and its typed
   `hash_range_v1` interval contains the stored partition key's bucket;
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
    JOIN binding_write_revisions AS br
      ON br.binding_id = pc.binding_id
     AND br.revision = pc.binding_write_revision
    JOIN binding_write_observations AS bo
      ON bo.binding_id = br.binding_id
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

The CAS is one prepared statement in SQLite and Durable Object SQLite as well as native database
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

## Domains, endpoints, and routes

`registries` and `binary_caches` each expose a non-null canonical `scope_key`
(`instance` or `org:<stable-id>`) and `UNIQUE(id, scope_key)`. DNS domains,
typed endpoints, and gateways retain their owner scope, while endpoint
and gateway grant rows enumerate consumer scopes allowed to create routes.
Instance-owned Hub infrastructure may grant named organizations. An
`instance_default` grant is eagerly materialized as one exact consumer-scope
row for every existing organization and by the organization-creation
transaction for each new organization; request authorization never interprets
a wildcard. Organization-owned infrastructure grants its owner by default
and another organization only through a separately authorized
cross-organization plan. Absence of an active grant generation and its required
live target pin is structural denial.

Grant identity is durable history, not a deletable authorization fact. Binding
and boundary grants key stable resources; endpoint and gateway grants key exact
generations. The current row transitions by resource-version CAS; every
transition appends an immutable `consumer_scope_grant_events` row. Initial
grant is generation 1/`active`. Revoke keeps that generation and transitions to
`revoked` only at zero pins. Regrant increments `grant_generation`, returns to
`active`, updates `granted_by/at`, clears the current row's revoke fields, and
never makes the older revoked generation usable again; the immutable events
retain every prior cycle.

Immutable configuration history may reference the stable grant identity as
provenance. Live placements, listeners, routes, gateways, and defaults acquire
the corresponding typed scope-grant pin with the exact current grant
generation in the same transaction/batch as becoming eligible. Each pin
composite-FKs to that generation and `state = active`; revocation therefore has
one winner against pin acquisition and cannot update the grant state until its
impact plan releases every live pin. A revoked historical row never authorizes
use, and an active grant without the matching live target pin is not evidence
that a target is serving. Attach/enable/create-default/activate transitions
acquire pins; detach/disable/move/delete transitions release them atomically.

```sql
domains(
  id,
  org_id NULL,
  owner_scope_key,       -- instance | org:<stable-id>
  hostname UNIQUE,
  dns_provider,
  dns_state,
  certificate_provider,
  certificate_state,
  verified_at NULL,
  created_at,
  updated_at,
  UNIQUE(id, owner_scope_key)
)

network_policies(
  id,
  org_id NULL,
  owner_scope_key,
  name,
  kind,                  -- public | vpn | vpc | tunnel | source_allowlist |
                         -- trusted_ingress
  identity_spec_json,    -- canonical closed, non-secret typed identity
  identity_fingerprint,
  resource_version,
  created_at,
  updated_at,
  CHECK valid_boundary_identity_shape(kind, identity_spec_json),
  CHECK(kind <> 'public' OR
        (id = 'instance:public' AND owner_scope_key = 'instance'
         AND org_id IS NULL)),
  UNIQUE(owner_scope_key, name),
  UNIQUE(identity_fingerprint),
  UNIQUE(id, owner_scope_key)
)

network_policy_revisions(
  boundary_id,
  revision,
  protected_transport_required,
  trusted_ingress_kind,  -- none | mtls | signed_assertion
  trusted_ingress_configuration,
  source_allowlist_cidrs NULL,
  probe_location_configuration,
  content_digest,
  created_by,
  created_at,
  PRIMARY KEY(boundary_id, revision),
  UNIQUE(boundary_id, revision, protected_transport_required,
         trusted_ingress_kind),
  FOREIGN KEY(boundary_id) REFERENCES network_policies(id)
)

network_policy_observations(
  boundary_id,
  revision,
  state,                 -- unknown | declared | probing | verified | degraded |
                         -- failed
  protected_transport_observed,
  trusted_ingress_observed,
  observed_at,
  error NULL,
  PRIMARY KEY(boundary_id, revision),
  FOREIGN KEY(boundary_id, revision)
    REFERENCES network_policy_revisions(boundary_id, revision)
)

network_policy_revision_lifecycle(
  boundary_id,
  revision,
  state,                 -- staged | active | retiring | retired
  activation_mode,       -- overlap | coordinated | system
  consumer_version,
  activated_at NULL,
  retired_at NULL,
  resource_version,
  PRIMARY KEY(boundary_id, revision),
  UNIQUE(boundary_id, revision, state),
  FOREIGN KEY(boundary_id, revision)
    REFERENCES network_policy_revisions(boundary_id, revision)
)

network_policy_defaults(
  boundary_id PRIMARY KEY,
  revision,
  state,                 -- active
  resource_version,
  updated_at,
  UNIQUE(boundary_id, revision, state),
  CHECK(state = 'active'),
  FOREIGN KEY(boundary_id) REFERENCES network_policies(id),
  FOREIGN KEY(boundary_id, revision, state)
    REFERENCES network_policy_revision_lifecycle(
      boundary_id, revision, state)
)

network_policy_serving_pins(
  pin_id PRIMARY KEY,
  boundary_id,
  revision,
  consumer_scope_key,
  grant_generation,
  grant_state,           -- active
  usage_kind,            -- endpoint_listener | route_endpoint |
                         -- route_access | route_local_policy |
                         -- gateway_endpoint | gateway_access |
                         -- topology_default
  target_kind,           -- endpoint | route | gateway | topology_default
  target_stable_id,
  target_generation_key, -- 0 for stable target, positive exact generation
  target_configuration_digest,
  acquired_by,
  acquired_at,
  resource_version,
  UNIQUE(boundary_id, revision, usage_kind, target_kind, target_stable_id,
         target_generation_key, target_configuration_digest),
  CHECK valid_boundary_serving_pin_shape,
  CHECK(grant_state = 'active'),
  FOREIGN KEY(boundary_id, revision)
    REFERENCES network_policy_revisions(boundary_id, revision),
  FOREIGN KEY(boundary_id, consumer_scope_key, grant_generation, grant_state)
    REFERENCES network_policy_consumer_scopes(
      boundary_id, consumer_scope_key, grant_generation, state)
)

network_policy_consumer_scopes(
  boundary_id,
  consumer_scope_key,
  grant_generation,
  grant_kind,            -- owner | instance_default | explicit
  state,                 -- active | revoked
  granted_by,
  granted_at,
  revoked_by NULL,
  revoked_at NULL,
  resource_version,
  PRIMARY KEY(boundary_id, consumer_scope_key),
  UNIQUE(boundary_id, consumer_scope_key, grant_generation, state),
  CHECK(grant_generation > 0),
  CHECK((state = 'active' AND revoked_by IS NULL AND revoked_at IS NULL)
     OR (state = 'revoked' AND revoked_by IS NOT NULL
         AND revoked_at IS NOT NULL)),
  FOREIGN KEY(boundary_id) REFERENCES network_policies(id)
)

endpoints(
  id,
  org_id NULL,
  owner_scope_key,
  scheme,                -- https | http
  domain_id NULL,
  ipv4_bytes NULL,
  ipv6_bytes NULL,
  effective_port,
  network_policy_id,
  cleartext_acknowledged_at NULL,
  desired_generation NULL,
  endpoint_identity_digest UNIQUE,
  resource_version,
  created_at,
  updated_at,
  CHECK exactly_one(domain_id, ipv4_bytes, ipv6_bytes),
  CHECK canonical_ip_lengths_and_no_mapped_v6,
  CHECK valid_scheme_port_and_cleartext_posture,
  UNIQUE(id, owner_scope_key),
  UNIQUE(id, network_policy_id),
  FOREIGN KEY(domain_id, owner_scope_key)
    REFERENCES domains(id, owner_scope_key),
  FOREIGN KEY(network_policy_id, owner_scope_key)
    REFERENCES network_policy_consumer_scopes(
      boundary_id, consumer_scope_key),
  FOREIGN KEY(id, desired_generation)
    REFERENCES endpoint_revisions(endpoint_id, generation)
)

endpoint_revisions(
  endpoint_id,
  generation,
  network_policy_id,
  boundary_revision,
  ingress_kind,          -- hub | external | layer7
  listener_configuration,
  tls_configuration,
  probe_configuration,
  content_digest,
  created_by,
  created_at,
  PRIMARY KEY(endpoint_id, generation),
  UNIQUE(endpoint_id, generation, ingress_kind),
  UNIQUE(endpoint_id, generation, network_policy_id, boundary_revision),
  FOREIGN KEY(endpoint_id, network_policy_id)
    REFERENCES endpoints(id, network_policy_id),
  FOREIGN KEY(network_policy_id, boundary_revision)
    REFERENCES network_policy_revisions(boundary_id, revision)
)

endpoint_observations(
  endpoint_id PRIMARY KEY,
  observed_generation NULL,
  boundary_id,
  boundary_revision NULL,
  state,                 -- unknown | declared | probing | healthy | degraded |
                         -- failed
  listener_observed,
  tls_observed,
  observed_at,
  error NULL,
  CHECK((observed_generation IS NULL AND boundary_revision IS NULL
         AND state = 'unknown')
     OR (observed_generation IS NOT NULL AND boundary_revision IS NOT NULL)),
  FOREIGN KEY(endpoint_id, boundary_id)
    REFERENCES endpoints(id, network_policy_id),
  FOREIGN KEY(endpoint_id, observed_generation, boundary_id,
              boundary_revision)
    REFERENCES endpoint_revisions(
      endpoint_id, generation, network_policy_id, boundary_revision)
)

endpoint_route_scopes(
  endpoint_id,
  endpoint_generation,
  consumer_scope_key,
  grant_generation,
  grant_kind,            -- owner | instance_default | explicit
  state,                 -- active | revoked
  granted_by,
  granted_at,
  revoked_by NULL,
  revoked_at NULL,
  resource_version,
  PRIMARY KEY(endpoint_id, endpoint_generation, consumer_scope_key),
  UNIQUE(endpoint_id, endpoint_generation, consumer_scope_key,
         grant_generation, state),
  CHECK(grant_generation > 0),
  CHECK((state = 'active' AND revoked_by IS NULL AND revoked_at IS NULL)
     OR (state = 'revoked' AND revoked_by IS NOT NULL
         AND revoked_at IS NOT NULL)),
  FOREIGN KEY(endpoint_id, endpoint_generation)
    REFERENCES endpoint_revisions(endpoint_id, generation)
)

routes(
  id,
  url_reservation_id,
  configuration_generation NULL,
  configuration_digest NULL,
  resource_version,
  endpoint_id,
  endpoint_generation,
  endpoint_ingress_kind,
  consumer_scope_key,
  gateway_id NULL,
  gateway_generation NULL,
  target_binding_id NULL,
  gateway_client_base_path NULL,
  target_placement_prefix NULL,
  base_path,
  registry_id NULL,
  cache_id NULL,
  mode,                  -- hub_proxy | hub_redirect | direct
  access_policy_kind,    -- public | hub_auth | external_provider |
                         -- private_network
  access_boundary_id NULL,
  access_boundary_revision NULL,
  external_provider_kind NULL,
  external_provider_resource_id NULL,
  external_provider_revision NULL,
  access_policy_json,
  access_policy_digest,
  placement_id NULL,
  target_placement_kind NULL,
  placement_policy_revision_id NULL,
  placement_policy_revision_state NULL,
  serves_git,
  serves_cache,
  serves_web,
  enabled,
  created_at,
  updated_at,
  CHECK exactly_one(registry_id, cache_id),
  CHECK((configuration_generation IS NULL AND configuration_digest IS NULL
         AND enabled = false)
     OR (configuration_generation IS NOT NULL
         AND configuration_digest IS NOT NULL)),
  CHECK valid_closed_access_policy_shape,
  CHECK ((mode = 'direct'
          AND endpoint_ingress_kind IN ('external', 'layer7')
          AND placement_id IS NOT NULL
          AND target_placement_kind = 'complete'
          AND placement_policy_revision_id IS NULL
          AND placement_policy_revision_state IS NULL
          AND gateway_id IS NOT NULL
          AND gateway_generation IS NOT NULL
          AND target_binding_id IS NOT NULL
          AND gateway_client_base_path IS NOT NULL
          AND target_placement_prefix IS NOT NULL
          AND base_path = join_segments(gateway_client_base_path,
                                        target_placement_prefix))
      OR (mode IN ('hub_proxy', 'hub_redirect')
          AND endpoint_ingress_kind IN ('hub', 'layer7')
          AND exactly_one(placement_id, placement_policy_revision_id)
          AND ((placement_id IS NULL AND target_placement_kind IS NULL)
            OR (placement_id IS NOT NULL
                AND target_placement_kind = 'complete'))
          AND ((placement_policy_revision_id IS NULL
                AND placement_policy_revision_state IS NULL)
            OR (placement_policy_revision_id IS NOT NULL
                AND placement_policy_revision_state = 'published'))
          AND gateway_id IS NULL
          AND gateway_generation IS NULL
          AND target_binding_id IS NULL
          AND gateway_client_base_path IS NULL
          AND target_placement_prefix IS NULL)),
  UNIQUE(endpoint_id, base_path),
  UNIQUE(id, registry_id),
  UNIQUE(id, cache_id),
  UNIQUE(id, registry_id, configuration_generation, configuration_digest),
  UNIQUE(id, cache_id, configuration_generation, configuration_digest),
  UNIQUE(id, access_policy_digest),
  UNIQUE(id, configuration_generation, configuration_digest,
         access_policy_digest),
  UNIQUE(id, registry_id, endpoint_id, endpoint_generation, placement_id,
         gateway_id, gateway_generation),
  UNIQUE(id, cache_id, endpoint_id, endpoint_generation, placement_id,
         gateway_id, gateway_generation),
  FOREIGN KEY(endpoint_id, endpoint_generation, consumer_scope_key)
    REFERENCES endpoint_route_scopes(
      endpoint_id, endpoint_generation, consumer_scope_key),
  FOREIGN KEY(endpoint_id, endpoint_generation, endpoint_ingress_kind)
    REFERENCES endpoint_revisions(
      endpoint_id, generation, ingress_kind),
  FOREIGN KEY(access_boundary_id, access_boundary_revision)
    REFERENCES network_policy_revisions(boundary_id, revision),
  FOREIGN KEY(access_boundary_id, consumer_scope_key)
    REFERENCES network_policy_consumer_scopes(
      boundary_id, consumer_scope_key),
  FOREIGN KEY(registry_id, consumer_scope_key)
    REFERENCES registries(id, scope_key),
  FOREIGN KEY(cache_id, consumer_scope_key)
    REFERENCES binary_caches(id, scope_key),
  FOREIGN KEY(id, registry_id, configuration_generation,
              configuration_digest)
    REFERENCES route_configurations(
      route_id, registry_id, configuration_generation,
      configuration_digest),
  FOREIGN KEY(id, cache_id, configuration_generation,
              configuration_digest)
    REFERENCES route_configurations(
      route_id, cache_id, configuration_generation,
      configuration_digest),
  FOREIGN KEY(placement_id, registry_id)
    REFERENCES surface_placements(id, registry_id),
  FOREIGN KEY(placement_id, cache_id)
    REFERENCES surface_placements(id, cache_id),
  FOREIGN KEY(placement_id, target_placement_kind)
    REFERENCES surface_placements(id, kind),
  FOREIGN KEY(placement_policy_revision_id, registry_id,
              placement_policy_revision_state)
    REFERENCES placement_policy_revisions(id, registry_id, state),
  FOREIGN KEY(placement_policy_revision_id, cache_id,
              placement_policy_revision_state)
    REFERENCES placement_policy_revisions(id, cache_id, state),
  FOREIGN KEY(placement_id, target_binding_id)
    REFERENCES surface_placements(id, binding_id),
  FOREIGN KEY(placement_id, target_binding_id,
              target_placement_prefix)
    REFERENCES surface_placements(id, binding_id, prefix),
  FOREIGN KEY(gateway_id, gateway_generation, endpoint_id,
              endpoint_generation, target_binding_id,
              gateway_client_base_path, access_policy_digest)
    REFERENCES gateway_revisions(
      gateway_id, generation, endpoint_id, endpoint_generation,
      binding_id, client_base_path, access_policy_digest),
  FOREIGN KEY(gateway_id, gateway_generation, consumer_scope_key)
    REFERENCES gateway_revision_route_scopes(
      gateway_id, generation, consumer_scope_key),
  FOREIGN KEY(url_reservation_id)
    REFERENCES route_url_reservations(id)
)

route_url_reservations(
  id PRIMARY KEY,
  digest_scheme,         -- hmac_sha256_v1
  reservation_key_version,
  reservation_digest,   -- fixed 32 bytes
  created_at,
  UNIQUE(reservation_key_version, reservation_digest),
  CHECK(octet_length(reservation_digest) = 32)
  -- Deliberately no plaintext URL, host, path, owner/surface identifier, actor,
  -- or FK to live topology rows.
)

route_configurations(
  route_id,
  registry_id NULL,
  cache_id NULL,
  configuration_generation,
  configuration_digest,
  canonical_rendered_url,
  canonical_configuration_json,
  created_by,
  created_at,
  PRIMARY KEY(route_id, configuration_generation),
  UNIQUE(route_id, registry_id, configuration_generation,
         configuration_digest),
  UNIQUE(route_id, cache_id, configuration_generation,
         configuration_digest),
  CHECK exactly_one(registry_id, cache_id),
  FOREIGN KEY(route_id, registry_id)
    REFERENCES routes(id, registry_id)
      ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(route_id, cache_id)
    REFERENCES routes(id, cache_id)
      ON DELETE RESTRICT ON UPDATE RESTRICT
)

route_advertisements(
  id,
  registry_id NULL,
  cache_id NULL,
  audience,              -- git | nix_cache | web
  route_id,
  CHECK exactly_one(registry_id, cache_id),
  UNIQUE(registry_id, audience),
  UNIQUE(cache_id, audience),
  FOREIGN KEY(route_id, registry_id)
    REFERENCES routes(id, registry_id),
  FOREIGN KEY(route_id, cache_id)
    REFERENCES routes(id, cache_id)
)

cache_inventory_generations(
  cache_id,
  generation,
  owner_token,
  lease_expires_at,
  state,                 -- building | published | failed
  content_digest NULL,
  published_at NULL,
  created_at,
  PRIMARY KEY(cache_id, generation),
  UNIQUE(generation, cache_id),
  CHECK owner_token_is_nonempty,
  CHECK lease_expires_at > created_at,
  CHECK valid_immutable_inventory_generation_state
)

cache_inventory_placement_scans(
  cache_id,
  generation,
  placement_id,
  placement_resource_version,
  content_digest NULL,
  object_count NULL,
  completed_at NULL,
  selected_at,
  PRIMARY KEY(cache_id, generation, placement_id),
  FOREIGN KEY(cache_id, generation)
    REFERENCES cache_inventory_generations(cache_id, generation),
  FOREIGN KEY(placement_id, cache_id)
    REFERENCES surface_placements(id, cache_id),
  CHECK complete_or_unfinished_scan_evidence
)

cache_inventory_object_observations(
  cache_id,
  generation,
  surface_object_id,
  placement_id,
  state,
  observed_hash NULL,
  observed_size NULL,
  etag NULL,
  observed_at,
  PRIMARY KEY(cache_id, generation, surface_object_id, placement_id),
  FOREIGN KEY(cache_id, generation)
    REFERENCES cache_inventory_generations(cache_id, generation),
  FOREIGN KEY(surface_object_id, cache_id)
    REFERENCES surface_objects(id, cache_id),
  FOREIGN KEY(placement_id, cache_id)
    REFERENCES surface_placements(id, cache_id)
)

placement_delivery_manifests(
  manifest_id,
  placement_id,
  registry_id NULL,
  cache_id NULL,
  kind,                  -- registry_publication | cache_inventory
  registry_publication_id NULL,
  cache_inventory_generation NULL,
  content_digest,
  published_at,
  PRIMARY KEY(manifest_id),
  UNIQUE(manifest_id, placement_id, registry_id),
  UNIQUE(manifest_id, placement_id, cache_id),
  CHECK exactly_one(registry_id, cache_id),
  CHECK manifest_kind_fields_match_surface,
  FOREIGN KEY(placement_id, registry_id)
    REFERENCES surface_placements(id, registry_id),
  FOREIGN KEY(placement_id, cache_id)
    REFERENCES surface_placements(id, cache_id),
  FOREIGN KEY(registry_publication_id, registry_id)
    REFERENCES registry_publications(publication_id, registry_id),
  FOREIGN KEY(cache_inventory_generation, cache_id)
    REFERENCES cache_inventory_generations(generation, cache_id)
)

placement_delivery_manifest_heads(
  placement_id PRIMARY KEY,
  registry_id NULL,
  cache_id NULL,
  manifest_id,
  resource_version,
  updated_at,
  CHECK exactly_one(registry_id, cache_id),
  CHECK manifest_head_fields_match_surface,
  FOREIGN KEY(manifest_id, placement_id, registry_id)
    REFERENCES placement_delivery_manifests(
      manifest_id, placement_id, registry_id),
  FOREIGN KEY(manifest_id, placement_id, cache_id)
    REFERENCES placement_delivery_manifests(
      manifest_id, placement_id, cache_id)
)

route_observations(
  route_id PRIMARY KEY,
  registry_id NULL,
  cache_id NULL,
  configuration_generation,
  configuration_digest,
  state,                 -- unknown | probing | healthy | degraded |
                         -- unreachable | declared
  observed_at,
  error NULL,
  CHECK exactly_one(registry_id, cache_id),
  UNIQUE(route_id, registry_id),
  UNIQUE(route_id, cache_id),
  FOREIGN KEY(route_id, registry_id, configuration_generation,
              configuration_digest)
    REFERENCES routes(
      id, registry_id, configuration_generation, configuration_digest)
      ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(route_id, cache_id, configuration_generation,
              configuration_digest)
    REFERENCES routes(
      id, cache_id, configuration_generation, configuration_digest)
      ON DELETE RESTRICT ON UPDATE RESTRICT
)

direct_route_evidence(
  route_id PRIMARY KEY,
  registry_id NULL,
  cache_id NULL,
  endpoint_id,
  endpoint_generation,
  placement_id,
  gateway_id,
  gateway_generation,
  publication_manifest_id,
  observed_at,
  CHECK exactly_one(registry_id, cache_id),
  FOREIGN KEY(route_id, registry_id)
    REFERENCES route_observations(route_id, registry_id)
      ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(route_id, cache_id)
    REFERENCES route_observations(route_id, cache_id)
      ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(route_id, registry_id, endpoint_id,
              endpoint_generation, placement_id,
              gateway_id, gateway_generation)
    REFERENCES routes(
      id, registry_id, endpoint_id, endpoint_generation, placement_id,
      gateway_id, gateway_generation)
      ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(route_id, cache_id, endpoint_id,
              endpoint_generation, placement_id,
              gateway_id, gateway_generation)
    REFERENCES routes(
      id, cache_id, endpoint_id, endpoint_generation, placement_id,
      gateway_id, gateway_generation)
      ON DELETE RESTRICT ON UPDATE RESTRICT,
  FOREIGN KEY(publication_manifest_id, placement_id, registry_id)
    REFERENCES placement_delivery_manifests(
      manifest_id, placement_id, registry_id),
  FOREIGN KEY(publication_manifest_id, placement_id, cache_id)
    REFERENCES placement_delivery_manifests(
      manifest_id, placement_id, cache_id)
)

route_access_observations(
  route_id PRIMARY KEY,
  configuration_generation,
  configuration_digest,
  access_policy_digest,
  state,                 -- unknown | probing | verified | degraded | failed
  observed_at,
  error NULL,
  FOREIGN KEY(route_id, configuration_generation,
              configuration_digest, access_policy_digest)
    REFERENCES routes(
      id, configuration_generation, configuration_digest,
      access_policy_digest)
      ON DELETE RESTRICT ON UPDATE RESTRICT
)
```

`probe_configuration` is canonical JSON and is part of the immutable endpoint
generation digest. It pins one Ed25519 responder identity and names the secret
provider that owns the corresponding private seed:

```json
{"provider":"worker_secret","signerSecretRef":"edge-prod-7","publicKey":"<base64url Ed25519 public key>"}
```

The closed provider set is `native_file`, `worker_secret`, and `external`.
Native Hub serves only `native_file` identities from its operator-owned signer
manifest; Worker serves only `worker_secret` identities from its Worker secret.
An `external` endpoint is not made ready by either Hub runtime: its CDN or TLS
terminator must implement the same responder contract and deployment must gate
endpoint readiness on that provider. A secret reference and public-key pin are
generation-specific; rotation creates a new endpoint generation rather than
mutating either value in place. Signer manifests contain only endpoint identity
and private seed readiness; they do not assert certificate metadata.

Network-boundary identity is stable and scoped; changing its kind or identity
fingerprint creates a replacement boundary and a planned endpoint move.
The optional default is a separate dependent row, not nullable columns on the
boundary: this keeps the active-revision foreign key acyclic and portable
across SQLite, PostgreSQL, MySQL, and Durable Object SQLite while preserving a
single CAS-managed pointer for future plans.
Changing protection requirements, trusted-ingress verification material, or
probe posture creates an immutable `staged` boundary revision; it does not move
the `network_policy_defaults` pointer or invalidate older
pinned revisions. Activation's explicit default choice may CAS the pointer for
future plans. That plan seals the boundary resource version plus the exact
previous default revision and default-row resource version (or sealed absence);
apply never rereads a newer pointer and silently substitutes it.
Reconciliation records verification independently for each exact revision.
Effective eligibility compares the consumer's pinned ref to that revision's
own `verified` observation and an `active` or `retiring` lifecycle. A verified
observation must exactly equal both desired protected-transport and desired
trusted-ingress posture; the state label alone is insufficient. Unknown,
declared, probing, degraded,
failed, inactive, or mismatched per-revision observations fail
closed for credential-bearing HTTP, trusted local `AccessClass`, and private
redirect eligibility. A public anonymous HTTP endpoint still requires the
durable cleartext acknowledgement. Endpoint creation additionally requires an
exact `network_policy_consumer_scopes` grant for its owner scope.
Credential-bearing cleartext scheme `http` always requires
`protected_transport_observed = true` on the exact verified revision;
`protected_transport_required = false` never waives that runtime predicate.
Scheme `https` instead requires the exact endpoint generation's listener/TLS
observation to be healthy and certificate/authority checks to pass; it does not
require the public boundary to claim a second protected transport.

Migration provisions exactly one instance-owned `instance:public` boundary,
immutable revision 1, its observation, and an `instance_default` whose exact
grants are materialized for the instance and every organization. Revision 1
has `protected_transport_required = false`, trusted ingress `none`, no CIDRs,
and no private probe location; its observation is `verified` at revision 1 with
both protection/trusted-ingress observations false. Every public endpoint pins
that revision. Its lifecycle is provisioned `active` with activation mode
`system`, `consumer_version = 0`, and cannot transition or retire through a
public API. The singleton cannot be created, revised, renamed, transferred,
or deleted through public APIs; probe/reconcile may refresh only its
observation. It represents the public network realm, not protected transport;
HTTP credential eligibility still fails and HTTPS relies on its verified TLS
listener. Other boundary kinds are ordinary scoped resources.
Each provisioned public scope grant starts active at grant generation 1; live
pins are acquired only as endpoints/routes/defaults become serving.

Providers that support overlapping enforcement use a staged rollout: create
the revision in `staged`, verify it, activate it while the old revision remains
active, create new endpoint/gateway/policy revisions and grants, then CAS the
old revision to `retiring`. That transition increments `consumer_version` and
fences new serving pins, but existing pinned consumers remain eligible while
its exact observation stays verified. Plans acquire equivalent pins on the new
revision while moving live routes/listeners/gateways/defaults, release the old
pins, and retire only at zero live pins. Multiple revisions may therefore be
verified concurrently.

Immutable endpoint, gateway, policy, and route history may reference a
`staged`, `active`, `retiring`, or later `retired` revision and is retained for
audit; those foreign keys are not live-consumer counts. The authoritative live
set is `network_policy_serving_pins`. Enabling or advertising a listener,
attaching/enabling a route, activating a gateway mapping, or selecting a
topology/canonical default inserts the exact typed pin in the same native
transaction or Durable Object atomic batch as the serving transition. Pin acquisition
requires `active` plus an exact verified observation. The target kind/id,
generation, and configuration digest are derived from the guarded resource row,
not accepted as arbitrary public input. Disabling/moving that serving resource
deletes its pin in the same transition.

Every pin insert/delete locks and increments the lifecycle
`consumer_version`. `active -> retiring` locks the same row, increments the
version, and fences new pins; deleting existing pins remains legal while
retiring. `retired` is immutable and ineligible. Final retirement CASes the
exact version and requires zero serving-pin rows, not deletion of immutable
history. Pin mutation versus lifecycle transition therefore has one winner on
native databases and Durable Object SQLite without a check-then-update race. UI counts and move
plans derive only from this serving-pin relation.

For a provider that cannot overlap enforcement, update returns a coordinated
impact operation containing every consumer and version. It stages replacement
topology first, switches external enforcement, verifies/activates the new
revision, moves consumers, and retires the old revision. Between the external
switch and the guarded database transitions, affected reads fail closed; the
plan explicitly estimates and requires acknowledgement of that window. A crash
leaves a resumable operation with old or new consumers ineligible, never
silently accepted under the wrong revision.

`identity_spec_json` is the lossless canonical API projection, not arbitrary
configuration. It contains exactly one closed variant: empty `public`;
provider kind, provider account/tenant, and globally qualified resource id for
VPN/VPC/tunnel; an owner-scoped stable logical allowlist id for
`source_allowlist`; or provider kind, provider account/tenant, and globally
qualified listener id for `trusted_ingress`. Provider/account tokens are
lowercase ASCII; ids are NFC UTF-8 with no control characters. The mutable CIDR membership belongs to immutable
boundary revisions, so ordinary allowlist changes do not replace endpoints.
CIDRs mask host bits, use 4-byte IPv4 or 16-byte IPv6 network bytes plus an
unsigned prefix length, reject mapped IPv6, deduplicate, and sort by
`(family, network_bytes, prefix_length)`.

`identity_fingerprint` is SHA-256 over
`"aos-hub-network-boundary-v1\0" || kind_tag:u8 || payload`. Each string in
payload is `length:u32be || UTF-8`. Provider variants encode provider, account,
then globally qualified resource/listener id. The source-allowlist payload
encodes `owner_scope_key` then its stable logical allowlist id, so two tenants'
local `prod` ids cannot collide. Public has no payload and remains the one
global singleton.
Kind tags are public `0x00`, VPN `0x01`, VPC `0x02`, tunnel `0x03`, source
allowlist `0x04`, and trusted ingress `0x05`. Get/show/UI return the typed spec
and fingerprint so migrations can round-trip and independently verify it.

Normative fingerprint vectors are:

| Identity | SHA-256 fingerprint |
| --- | --- |
| public | `a45d7088ef1cb3f42b0f7c1284e56a781daabc736ecce73134b8e4f53078c08d` |
| source allowlist, scope `org:acme`, id `prod` | `f6d31e77254aa21beee6d7b82c8db4190092253a353a614fd809b95d10e60bf4` |
| VPC, provider `aws`, account `123456789012`, resource `arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0123456789abcdef0` | `beec20e1ae5f82f5a55a53d425d4e9a08521808d787a209b8c2a589ac39b412e` |

Boundary revision `content_digest` is SHA-256 over
`"aos-hub-network-boundary-revision-v1\0"`, the boundary fingerprint,
one-byte booleans/enums, and length-prefixed canonical trusted-ingress/probe
references. Its source-allowlist field is `count:u32be` followed by
`family:u8 || prefix_length:u8 || network_bytes` in canonical order. Thus CIDR
edits change only the immutable revision digest, never boundary identity.
Trusted-ingress configuration is a closed canonical projection: `none` is
exactly `{}`, `mtls` requires only `ca_secret_ref` and `client_sans`, and
`signed_assertion` requires only `issuer`, `audience`, and
`verification_key_secret_ref`. Missing or unknown fields are rejected.

Endpoint origin identity -- scheme, typed host, effective port, and network
boundary -- is immutable. `StageEndpointGeneration` appends a new
immutable, non-selected generation and may change only ingress, listener/TLS,
probe posture, and the pinned boundary revision. `ActivateEndpointGeneration`
selects one exact staged generation only after its boundary is active and its
source-generation consumers have moved. An origin or realm change creates a replacement
endpoint followed by planned route and gateway-revision moves. Routes, grants,
gateway revisions, and observations pin an exact endpoint generation. Hub
proxy/redirect requires `hub` or `layer7` ingress; direct requires `external`
or `layer7`; mixing Hub and direct paths on one origin requires `layer7`.

Access policy is a closed canonical value, never arbitrary provider JSON:

- `public` has no boundary, provider, or credential mechanism;
- `hub_auth` contains only typed Hub principal/client requirements;
- `external_provider` pins provider kind, stable provider resource id, observed
  provider revision, client mechanisms, and redacted verification secret refs;
  and
- `private_network` pins an exact `NetworkPolicyRevisionRef`.

The canonical encoding produces `access_policy_digest`; kind-specific columns
and checks make impossible variants unrepresentable, while JSON contains only
the closed variant's typed mechanism configuration. Direct routes must match
their immutable gateway revision's exact digest through the composite foreign
key. Hub proxy may enforce any compatible variant. Hub redirect additionally
requires a `verified` access observation proving that the presigned origin
enforces the same provider revision or boundary revision for the capability
lifetime. Endpoint boundary identity is not used as a substitute for route
access policy. A boundary/provider revision change creates a new pinned policy
value; its plan enumerates routes and gateway revisions that retain or move
from the old revision.

Domain hostname and owner scope are likewise immutable because DNS-backed
endpoint identity depends on them. DNS and certificate posture have dedicated
configuration and reconciliation operations; there is no generic domain
update. The hostname input is a DNS name only and rejects an explicit port
(including a scheme-default port) rather than allowing URL parsing to erase it.
A hostname change creates a replacement domain, replacement endpoint,
and the same planned route/gateway movement.

`endpoint_identity_digest` is SHA-256 over
`"aos-hub-delivery-endpoint-v1\0" || scheme_tag:u8 || host_kind:u8 ||
host_length:u32be || typed_host_bytes || effective_port:u16be ||
network_policy_identity_fingerprint:32`. It commits to the boundary's stable
typed identity fingerprint, never its replaceable database row id or moving
revision. Ingress is revisioned configuration, not part of request identity.
HTTPS revision TLS configuration is the exact closed projection of `provider`,
`certificate_ref`, and `require_client_certificate`; HTTP uses exactly `{}`.
Unknown or missing TLS fields are rejected before digesting or persistence.
The closed tags are `http = 0x01`, `https = 0x02`, `dns = 0x01`,
`ipv4 = 0x02`, and `ipv6 = 0x03`. DNS host bytes are lowercase IDNA A-label
UTF-8; IP host bytes are the four or sixteen network-order address octets.
The following lowercase hex SHA-256 vectors are normative:

```text
origin=https://example.com
boundary_fingerprint=0000000000000000000000000000000000000000000000000000000000000000
digest=5f4355f82aabce6be5993fd4e7a2cc8daf9517f65e7c33a853a4fbd1d2e0a845

origin=http://192.0.2.10:8080
boundary_fingerprint=1111111111111111111111111111111111111111111111111111111111111111
digest=dd2386a556c359981c96f5e1406f4b1d8a703652256d564ce2231666e70195f3

origin=https://[2001:db8::1]:8443
boundary_fingerprint=2222222222222222222222222222222222222222222222222222222222222222
digest=5d13ab476e10142123363cfb3b168c9073cb5cca41411feddd5e1f072db7d62f
```

The digest is unique, so one resolvable origin in one network realm cannot split
into ambiguous endpoint rows. Public endpoints use the fixed public-boundary
fingerprint; private addresses in different realms do not collide. Deleting and
recreating an identical boundary spec reproduces the same fingerprint and
therefore cannot bypass a URL reservation. Default ports remain in identity and
are omitted only when rendering. No row stores a URL, userinfo, query, fragment,
IPv6 zone id, or storage-origin address.

An endpoint revision grant is always an exact consumer scope. The
organization-creation workflow materializes any active instance-default grants
in the same transaction that makes the organization usable, and removing an
instance default does not silently revoke already-materialized explicit
access. CLI/API stable endpoint refs resolve to the exact desired generation in
the plan and apply rejects a changed generation. Endpoint update plans list
every old-generation grant and affected route; apply creates only the
explicitly confirmed replacement-generation grants before moving routes. Old
grants are never wildcards: every carry-forward item seals the old endpoint
generation, consumer scope, grant generation, and grant resource version, and
the owner grant is sealed the same way automatically. Revoke enumerates and
releases affected live pins
before CASing the exact durable grant generation to `revoked`.
Grant/carry-forward/revoke requires dual owner/consumer
scope authorization.

`base_path` and endpoint origin are stored only after the raw-target
normalization contract in `01-domain-model.md`; queries are never part of route
identity. Reserved control namespaces never enter this table. Direct targets
use complete-placement publication ordering and reconciled gateway manifests,
while Hub targets use per-request exact presence and publication-head checks.
Both native and Worker route code consume the same typed resolution and fixed
failure contract.

The route's endpoint identity and normalized `base_path` are immutable. Together
they select an immutable `route_url_reservations` row containing only
a keyed digest for its permanent path reservation. A change to endpoint
identity or normalized/derived base path creates a new, initially non-canonical
replacement route and a new reservation; it never updates the old identity in
place. Moving to another generation of the same endpoint identity, changing
mode, or changing a direct target is an update only when the final canonical
rendered URL remains byte-identical. A direct gateway/placement change whose
derived path differs is a replacement. The service requires the predecessor to
be an active route on the same surface, rejects cycles across active replacement
operations, and permits at most one active successor at a time; replaying the
same create plan returns that successor. The append-only audit event records the
old/new route ids and reservation digests without an FK to either live route.

The reservation input is
`"aos-hub-route-reservation-v1\0" || endpoint_identity_digest:32 ||
length:u32be || normalized_base_path_utf8 || length:u32be ||
canonical_rendered_url_utf8`. The endpoint identity digest already commits to
the NetworkPolicy identity, so identical private origins in distinct realms
do not collide while reuse in one realm does. `reservation_digest` is
HMAC-SHA-256 under a versioned instance reservation key. Creation checks the candidate against every
retained key version and inserts under the current version with a uniqueness
CAS; reservation keys are retained while any row uses their version, including
after ordinary credential rotation. Specifically, it recomputes the candidate
under each retained old key and queries that version/digest pair before it
inserts under the current key; existing rows need no alias backfill. Keyring
activation and reservation creation share one serializable version/CAS fence on
native databases and one Durable Object actor/batch. If any referenced key is unavailable,
reservation creation and key rotation fail closed until restore; they never skip
that version. Reservation keys are backed up and cannot be retired while rows of
their version exist. Any equal digest is conservatively treated as already
reserved, so a cryptographic collision can deny reuse but can never cause
identity takeover. Only the live route/configuration stores renderable host/path
text. The permanent reservation stores no tenant, surface, actor, endpoint,
host, path, or URL plaintext and has no FK to deletable topology.

`configuration_digest` covers the normalized endpoint generation, base path,
surface, mode, exact target/policy/gateway tuple, access-policy digest,
capabilities, and enabled posture. For an update whose rendered URL remains
identical, `UpdateRoute` atomically deletes its old probe/access/direct-evidence
rows, inserts the complete immutable `route_configurations` snapshot,
increments `configuration_generation`, and writes the new digest under the
route resource-version plan; old observations then cannot satisfy the composite
FK. Initial creation portably inserts a disabled route with a null current
configuration pointer, inserts its generation-one child snapshot, advances the
route pointer, and asserts the complete invariant in one native transaction or
Durable Object batch. No intermediate row may commit; no backend needs deferred FKs.
The new configuration begins `unknown` and cannot be healthy or canonically
advertised until reprobed. Route advertisement selection may retain the route id,
but setup snippets and runtime advertisement require a healthy observation for
its exact current generation/digest.

The inbound Hub route projection is fail closed across the complete security
chain. It joins the endpoint's exact desired generation to a `healthy`
observation, the endpoint boundary's exact pinned revision to `active` and
`verified` lifecycle/observation rows, and requires observed protected/trusted
posture to equal the desired revision. A `private_network` access policy also
joins its separately pinned access-boundary revision under those same exact
conditions, while other authenticated policies require the exact route access
observation to be `verified`. `degraded`, stale, mismatched, or missing rows are
not ready and are never projected as an alternate path.

`DeleteRoute` physically removes the live route after a guarded plan/apply. It
requires the route to be disabled, non-canonical, absent from every current
signed stack projection, and free of all live endpoint, gateway, boundary, and
grant pins. Apply explicitly deletes direct/access evidence, deletes the route
observation, nulls the current configuration pointer, deletes configuration
snapshots, and finally deletes the route in that dependency order in one
transaction/batch. All relevant FKs
are `ON DELETE RESTRICT`; a current signed-stack FK to a configuration therefore
makes unsafe child deletion fail even if the plan check raced. The permanent URL reservation and append-only redacted
audit events remain without FKs to endpoint, placement, gateway, boundary,
binding, or surface rows, so historical provenance does not prevent deletion of
the rest of the topology dependency graph. The signed registry commit remains
the authoritative long-term signed-history record.

A direct route becomes `healthy` only when its observation proves the exact
endpoint generation and its pinned boundary revision, gateway generation,
complete placement, and the manifest selected by
`placement_delivery_manifest_heads`. The head advances by resource-version CAS
only after a registry publication or cache inventory generation is completely
externally readable; route reconciliation compares the exact head manifest id
and corresponding generation. The registry source is its committed publication
head. The cache source is the exact published
`cache_inventory_generations` row also selected by
`cache_gc_state.inventory_generation`; an in-progress placement scan cannot
advance either head. An inventory builder owns its unpublished generation with
an unguessable `owner_token` and renews `lease_expires_at` while scanning. Every
staging, manifest, lookup, cleanup, and publication mutation matches that
owner. Starting the same successor generation while its lease is live fails.
At or after expiry, a new builder may atomically delete the abandoned
generation (cascading all private staging rows) and recreate it under a new
owner. Delayed cleanup or writes from the former owner cannot erase or
contaminate the replacement. Published generations are immutable and are never
eligible for lease takeover. An unprobeable private endpoint is `declared`,
not healthy. Hub route observations may omit the direct-only tuple and report
aggregate probe state; request-time presence/publication checks remain the
serving authority.

Binding-wide direct mappings become `gateways`; explicit user-owned
direct route rows make their use visible and queryable.

```sql
gateways(
  id PRIMARY KEY,
  org_id NULL,             -- NULL means instance scope
  owner_scope_key,         -- instance | org:<stable-id>
  enabled,
  desired_generation NULL,
  observed_generation NULL,
  reconciliation_state,
  reconciliation_error NULL,
  created_at,
  updated_at,
  UNIQUE(id, owner_scope_key),
  CHECK(observed_generation IS NULL OR desired_generation IS NOT NULL),
  FOREIGN KEY(id, desired_generation)
    REFERENCES gateway_revisions(gateway_id, generation),
  FOREIGN KEY(id, observed_generation)
    REFERENCES gateway_revisions(gateway_id, generation)
)

gateway_path_reservations(
  reservation_id PRIMARY KEY,
  gateway_id,
  endpoint_id,
  client_base_path,
  resource_version,
  created_at,
  UNIQUE(endpoint_id, client_base_path),
  UNIQUE(reservation_id, gateway_id, endpoint_id, client_base_path),
  FOREIGN KEY(gateway_id) REFERENCES gateways(id),
  FOREIGN KEY(endpoint_id) REFERENCES endpoints(id)
)

gateway_revisions(
  gateway_id,
  generation,
  org_id NULL,
  owner_scope_key,
  path_reservation_id,
  binding_id,
  endpoint_id,
  endpoint_generation,
  endpoint_ingress_kind,   -- external | layer7
  client_base_path,
  origin_prefix,
  access_policy_kind,
  access_boundary_id NULL,
  access_boundary_revision NULL,
  external_provider_kind NULL,
  external_provider_resource_id NULL,
  external_provider_revision NULL,
  access_policy_json,
  access_policy_digest,
  content_digest,
  created_by,
  created_at,
  PRIMARY KEY(gateway_id, generation),
  CHECK(endpoint_ingress_kind IN ('external', 'layer7')),
  CHECK valid_direct_access_policy_shape,
  UNIQUE(gateway_id, generation, endpoint_id, endpoint_generation,
         binding_id, client_base_path, access_policy_digest),
  UNIQUE(gateway_id, generation, owner_scope_key),
  FOREIGN KEY(gateway_id, owner_scope_key)
    REFERENCES gateways(id, owner_scope_key),
  FOREIGN KEY(binding_id, owner_scope_key)
    REFERENCES binding_consumer_scopes(
      binding_id, consumer_scope_key),
  FOREIGN KEY(endpoint_id, endpoint_generation, endpoint_ingress_kind)
    REFERENCES endpoint_revisions(
      endpoint_id, generation, ingress_kind),
  FOREIGN KEY(endpoint_id, endpoint_generation, owner_scope_key)
    REFERENCES endpoint_route_scopes(
      endpoint_id, endpoint_generation, consumer_scope_key),
  FOREIGN KEY(access_boundary_id, access_boundary_revision)
    REFERENCES network_policy_revisions(boundary_id, revision),
  FOREIGN KEY(access_boundary_id, owner_scope_key)
    REFERENCES network_policy_consumer_scopes(
      boundary_id, consumer_scope_key),
  FOREIGN KEY(path_reservation_id, gateway_id, endpoint_id, client_base_path)
    REFERENCES gateway_path_reservations(
      reservation_id, gateway_id, endpoint_id, client_base_path)
)

gateway_revision_route_scopes(
  gateway_id,
  generation,
  consumer_scope_key,
  grant_generation,
  grant_kind,              -- owner | instance_default | explicit
  state,                   -- active | revoked
  granted_by,
  granted_at,
  revoked_by NULL,
  revoked_at NULL,
  resource_version,
  PRIMARY KEY(gateway_id, generation, consumer_scope_key),
  UNIQUE(gateway_id, generation, consumer_scope_key, grant_generation, state),
  CHECK(grant_generation > 0),
  CHECK((state = 'active' AND revoked_by IS NULL AND revoked_at IS NULL)
     OR (state = 'revoked' AND revoked_by IS NOT NULL
         AND revoked_at IS NOT NULL)),
  FOREIGN KEY(gateway_id, generation)
    REFERENCES gateway_revisions(gateway_id, generation)
)

binding_scope_grant_pins(
  pin_id PRIMARY KEY,
  binding_id,
  consumer_scope_key,
  grant_generation,
  grant_state,           -- active
  target_kind,           -- placement | gateway | topology_default
  target_stable_id,
  target_generation_key,
  target_configuration_digest,
  resource_version,
  UNIQUE(binding_id, consumer_scope_key, target_kind,
         target_stable_id, target_generation_key,
         target_configuration_digest),
  CHECK(grant_state = 'active'),
  CHECK valid_scope_grant_pin_shape,
  FOREIGN KEY(binding_id, consumer_scope_key, grant_generation,
              grant_state)
    REFERENCES binding_consumer_scopes(
      binding_id, consumer_scope_key, grant_generation, state)
)

endpoint_scope_grant_pins(
  pin_id PRIMARY KEY,
  endpoint_id,
  endpoint_generation,
  consumer_scope_key,
  grant_generation,
  grant_state,           -- active
  target_kind,           -- listener | route | gateway | topology_default
  target_stable_id,
  target_generation_key,
  target_configuration_digest,
  resource_version,
  UNIQUE(endpoint_id, endpoint_generation, consumer_scope_key, target_kind,
         target_stable_id, target_generation_key,
         target_configuration_digest),
  CHECK(grant_state = 'active'),
  CHECK valid_scope_grant_pin_shape,
  FOREIGN KEY(endpoint_id, endpoint_generation, consumer_scope_key,
              grant_generation, grant_state)
    REFERENCES endpoint_route_scopes(
      endpoint_id, endpoint_generation, consumer_scope_key,
      grant_generation, state)
)

gateway_scope_grant_pins(
  pin_id PRIMARY KEY,
  gateway_id,
  generation,
  consumer_scope_key,
  grant_generation,
  grant_state,           -- active
  target_kind,           -- route | topology_default
  target_stable_id,
  target_generation_key,
  target_configuration_digest,
  resource_version,
  UNIQUE(gateway_id, generation, consumer_scope_key, target_kind,
         target_stable_id, target_generation_key,
         target_configuration_digest),
  CHECK(grant_state = 'active'),
  CHECK valid_scope_grant_pin_shape,
  FOREIGN KEY(gateway_id, generation, consumer_scope_key, grant_generation,
              grant_state)
    REFERENCES gateway_revision_route_scopes(
      gateway_id, generation, consumer_scope_key, grant_generation, state)
)

consumer_scope_grant_events(
  event_id PRIMARY KEY,
  resource_kind,         -- binding | network_policy |
                         -- endpoint | gateway
  resource_stable_id,
  resource_generation_key,
  consumer_scope_key,
  grant_generation,
  transition,            -- granted | revoked | regranted
  previous_state NULL,
  resulting_state,
  actor_id,
  occurred_at,
  request_id,
  CHECK valid_immutable_grant_event_shape
)

topology_defaults(
  id,
  scope_kind,             -- instance | organization
  org_id NULL,
  scope_key UNIQUE,       -- instance | org:<stable-id>
  binding_id NULL,
  domain_id NULL,
  endpoint_id NULL,
  endpoint_generation NULL,
  gateway_id NULL,
  gateway_generation NULL,
  created_at,
  updated_at,
  CHECK valid_scope(scope_kind, org_id, scope_key),
  CHECK paired(endpoint_id, endpoint_generation),
  CHECK paired(gateway_id, gateway_generation),
  FOREIGN KEY(binding_id, scope_key)
    REFERENCES binding_consumer_scopes(
      binding_id, consumer_scope_key),
  FOREIGN KEY(domain_id, scope_key)
    REFERENCES domains(id, owner_scope_key),
  FOREIGN KEY(endpoint_id, endpoint_generation, scope_key)
    REFERENCES endpoint_route_scopes(
      endpoint_id, endpoint_generation, consumer_scope_key),
  FOREIGN KEY(gateway_id, gateway_generation, scope_key)
    REFERENCES gateway_revision_route_scopes(
      gateway_id, generation, consumer_scope_key)
)
```

The deployment-provisioned instance binding singleton uses the same eager
exact-grant projection as instance defaults elsewhere: existing organizations
are materialized when the grant is enabled, and organization creation inserts
its exact row before topology can reference the binding. Organization bindings
grant their owner by default; cross-organization grants require a dual-scope
impact plan. Placement, gateway, and topology-default rows carry the consuming
scope and reference that exact grant, so neither a nonexistent nor a foreign
binding can enter topology. Grant revocation enumerates and removes defaults,
gateways, and placements first; absence of an active grant generation and its
required live pin is structural denial.

`routes.gateway_id` and `gateway_generation` pin immutable
user-selected provenance. Gateway reconciliation creates/configures or probes a
new immutable gateway revision and advances only its observed state. It never
mutates routes. Moving an existing route or creating routes from gateway preview
is an explicit RouteService plan/apply owned by the surface. Old revisions
remain addressable until no route pins them.
One versioned reservation owns each endpoint/base path across all gateway
identities. Revisions of its owning gateway may coexist; another gateway can
acquire the path only through a planned reservation CAS after every old route
and revision has moved or retired.
Organization defaults may
override instance defaults. A default is only a creation-time/user-interface
choice and never silently retargets an existing placement or route.
Endpoint and gateway defaults pin exact granted generations. Stable CLI/API
refs resolve those generations in the plan; apply rejects changed desired
generations. A revision update offers an explicit default-move effect rather
than making defaults follow a mutable pointer.

A gateway-backed route is necessarily `direct`, references a complete
placement on the revision's binding, and records the gateway generation that
produced it. Application validation plus the composite foreign keys enforce
complete kind, compatible scope/access posture, and exact path composition.
The schema enforces one instance defaults row despite SQL NULL-uniqueness
differences; every organization has at most one defaults row.

Endpoint, gateway-revision, route-target, and canonical-route composite foreign
keys are immediate `ON UPDATE RESTRICT ON DELETE RESTRICT`. Cross-surface and
cross-scope route targets are therefore impossible in every supported SQL
backend rather than rejected only by service code.

The current `frontends` table migrates as follows:

- registry/cache target -> route;
- binding target -> gateway plus an explicit reviewed direct route for
  each still-supported old frontend URL; no route is synthesized merely because
  a placement is eligible;
- scheme/DNS/IP/port -> typed endpoint, and `base_path` -> route;
- `mode` -> delivery mode;
- `serves_*` -> route capabilities;
- `advertised` -> either canonical-route selection or no migrated meaning;
- `consumer_priority` -> explicit route/policy order after correcting its
  current direction ambiguity; and
- `is_primary` -> route advertisement for the applicable audience.

The resource-level `advertise_storage_frontend` fields are removed after
explicit-route review. There is no generic inheritance toggle in the new model.

## Object presence

```sql
surface_objects(
  id,
  registry_id NULL,
  cache_id NULL,
  object_key,
  object_kind,           -- immutable | mutable_pointer
  partition_key NULL,    -- exact 32-byte binary hash-range key
  content_hash NULL,
  size NULL,
  mutable_publication_id NULL,
  lifecycle_state,       -- active | tombstoned
  tombstoned_at NULL,
  resource_version,
  CHECK exactly_one(registry_id, cache_id),
  CHECK ((object_kind = 'immutable' AND partition_key IS NOT NULL
          AND byte_length(partition_key) = 32)
      OR (object_kind = 'mutable_pointer' AND partition_key IS NULL)),
  UNIQUE(id, registry_id),
  UNIQUE(id, cache_id),
  UNIQUE(registry_id, object_key),
  UNIQUE(cache_id, object_key)
)

CREATE INDEX surface_objects_partition_key_idx
  ON surface_objects(partition_key);

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

Indexing computes `partition_key` once from the canonical logical identity and
encoding in `01-domain-model.md`; route code reads it and never re-derives it
from a URL. Cutover recomputes and validates every immutable key, rejects a
digest/vector mismatch, and does not enable hash policies until the backfill is
complete. Mutable pointers remain unpartitioned.

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
`refs` JSON value, cache-level binding/prefix, or a binding/prefix NAR
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
  FOREIGN KEY(cache_id) REFERENCES binary_caches(id),
  FOREIGN KEY(registry_id) REFERENCES registries(id),
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
  placement_policy_revision_id NULL,
  placement_policy_revision_state NULL,
  selector_json,
  validation_gate,
  enabled,
  UNIQUE(cache_id, registry_id, trigger),
  CHECK ((placement_policy_revision_id IS NULL
          AND placement_policy_revision_state IS NULL)
      OR (placement_policy_revision_id IS NOT NULL
          AND placement_policy_revision_state = 'published')),
  FOREIGN KEY(placement_policy_revision_id, cache_id,
              placement_policy_revision_state)
    REFERENCES placement_policy_revisions(id, cache_id, state),
  FOREIGN KEY(cache_id) REFERENCES binary_caches(id),
  FOREIGN KEY(registry_id) REFERENCES registries(id)
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
  FOREIGN KEY(cache_id, inventory_generation)
    REFERENCES cache_inventory_generations(cache_id, generation),
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
generation snapshots every non-offline placement and its resource version at
begin time. Every selected placement must publish a structurally complete
manifest, and the selected set and versions must remain unchanged through
publication. Placement manifests may differ for shards; the cache-wide digest
is the deterministic digest of ordered placement id, resource version, and
manifest digest tuples. A single placement finishing does not make the cache
inventory complete. Every `present` row carries hash and size derived from the
bytes read from that exact placement plus a backend-issued strong ETag when the
backend exposes one; the scanner never copies expected database identity into
observed evidence without verification. Building observations remain in
`cache_inventory_object_observations`; replacing live `object_placements` and
advancing the generation head are one atomic publication, so a partial scan is
never visible to GC. Active
object-mutation fences are relational apply blockers; an operation removes or
completes its fences only in the same transition that publishes object metadata
and advances `object_graph_generation`.

Every competing root, graph, inventory, cache-topology, or fence
mutation conditionally advances `cache_gc_state.epoch` in the same native
transaction or Durable Object atomic batch as its own rows. Object publication and GC apply
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
or Worker Durable Object atomic batch. The first `INSERT ... SELECT` creates a unique apply
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
effect inserts `ok = 0`, raises a portable constraint error, and makes the batch roll
back the entire atomic batch just as a native transaction does. The algorithm
never relies on inspecting intermediate affected-row counts. A competing
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
  route_id NULL,
  route_configuration_generation NULL,
  route_configuration_digest NULL,
  indexed_commit,
  PRIMARY KEY(registry_id, stack_path),
  CHECK ((cache_id IS NULL AND route_id IS NULL
          AND route_configuration_generation IS NULL
          AND route_configuration_digest IS NULL)
      OR (cache_id IS NOT NULL AND route_id IS NOT NULL
          AND route_configuration_generation IS NOT NULL
          AND route_configuration_digest IS NOT NULL)),
  FOREIGN KEY(registry_id) REFERENCES registries(id),
  FOREIGN KEY(cache_id) REFERENCES binary_caches(id),
  FOREIGN KEY(route_id, cache_id, route_configuration_generation,
              route_configuration_digest)
    REFERENCES route_configurations(
      route_id, cache_id, configuration_generation,
      configuration_digest)
)
```

For a managed entry, index validation requires `committed_url` to byte-equal
the exact immutable route configuration's `canonical_rendered_url` at
`indexed_commit`; cache identity, route identity, generation, and digest are
stored together or not at all. A later route update retains that immutable
configuration for signed-history/audit but does not rewrite the committed
stack. URL identity cannot change in an update. Its replacement workflow is:
create and probe the replacement route, enable it, commit the signed cache-stack
entry to its URL, re-index that exact replacement configuration, move canonical
selection, then disable and delete the old route. Each transition is an
independent plan/apply step with resumable state; both routes may serve during
the overlap, so clients never observe an advertised but disabled URL.

`DisableRoute` and `DeleteRoute` are blocked while any current signed stack
entry names that route, even when the URL is unchanged. An access-policy or
capability update reruns compatibility validation for every referencing stack
entry and fails if any intended client class would lose read access. A
target-only move may proceed without changing a stack entry only when its URL,
access policy, and cache-serving capability remain compatible. The entry may
retain its exact historical configuration generation because immutable history
proves the signed URL; health and serving always use the route's current exact
configuration. An external URL has all managed fields null. Cross-cache,
dangling, partially managed, or generation/digest-mismatched pairs
abort index and cutover.

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
- `GetWriteAuthority`; controller-only `ReportWriteAuthority`
- `ListPlacements`, `GetPlacement`, `PlanScanPlacement` / `ScanPlacement`
- `ListPlacementPolicies`, `GetPlacementPolicy`,
  `ListPlacementPolicyRevisions`, `GetPlacementPolicyRevision`,
  `CreatePlacementPolicy`, `RevisePlacementPolicy`,
  `TestPlacementPolicyRevision`
- `PlanReplicatePlacement` / `ReplicatePlacement`,
  `PlanRepairPlacement` / `RepairPlacement`, `ListObjectPresence`
- `ListPlacementEquivalences`, `ConfirmPlacementEquivalence`,
  `DeletePlacementEquivalence`

Creating or moving a placement never silently changes a route or
signed consumer stack. An impact endpoint reports affected routes and
integrations before apply. Creation accepts placement kind and desired read
state, never primary role or write enablement. Promotion is the only ordinary
operation that changes desired write authority; reconciliation is idempotent
and generation guarded. Cancellation is a reviewed, generation-guarded
reconciliation back to the still-observed writer; it never clears a pending
row without proving the candidate is fenced and the observed writer is ready.

### Domains, network policies, endpoints, gateways, and routes

- `CreateDomain`, `VerifyDomain`, `ConfigureDomainDns`,
  `ConfigureDomainCertificate`,
  `DeleteDomain`
- `CreateNetworkPolicy`, `ReviseNetworkPolicy`; controller-only
  `CompleteNetworkPolicyRevisionProbe`, `ReportNetworkPolicyRevision`,
  `ActivateNetworkPolicyRevision`, `RetireNetworkPolicyRevision`,
  `GrantNetworkPolicyScope`, `RevokeNetworkPolicyScope`,
  `DeleteNetworkPolicy`
- `CreateEndpoint`, `StageEndpointGeneration`,
  `ActivateEndpointGeneration`,
  `GrantEndpointScope`, `RevokeEndpointScope`,
  controller-only `CompleteEndpointProbe`, `ReportEndpoint`,
  `DeleteEndpoint`
- `CreateRoute`, `UpdateRoute`, `ReplaceRoute`, `EnableRoute`, `DisableRoute`,
  `DeleteRoute`
- `SetRouteAdvertisement`, `ExplainRoute`; controller-only `CompleteRouteProbe`
- `CreateGateway`, `UpdateGateway`, `PreviewGatewayRoutes`,
  `GrantGatewayScope`, `RevokeGatewayScope`,
  controller-only `ReportGateway`, `EnableGateway`, `DisableGateway`,
  `DeleteGateway`

`ExplainRoute` returns the normalized endpoint/realm and grant, selected access
decision, publication-head/manifest evidence, placement candidates, origin
credential purpose, path rewrite, and rejection reasons without disclosing
secrets.

Boundary creation accepts a typed identity specification; the service derives
the immutable identity fingerprint and never accepts a caller-supplied digest.
Boundary revision inputs use secret references for mTLS and signed-assertion
verification material and return only redacted references.

### Bindings and topology defaults

- `CreateBinding`, `DeleteBinding`
- `SetBindingCredential`, `RotateBindingCredential`,
  `PlanValidateBindingCredential` / `ValidateBindingCredential`
- `ListBindingWriteRevisions`, `GetBindingWriteRevision`,
  controller-only `ReportBindingWriteRevision`
- `GrantBindingScope`, `RevokeBindingScope`
- `GetInstanceTopologyDefaults`, `SetInstanceTopologyDefaults`
- `GetOrganizationTopologyDefaults`, `SetOrganizationTopologyDefaults`

The public binding record exposes capabilities, immutable revision references,
and health, never credential material. Rotation plans include authority fan-out
and explicit old-revision retirement. Default changes have their own impact
plan and affect only future workflows unless the operator separately plans
changes to existing resources.

A binding's provider identity (provider kind, filesystem root, object
bucket and prefix, endpoint, region, and access mode) is immutable. Changing
any identity field requires creating a replacement binding, migrating exact
placement pins, and deleting the unreferenced predecessor through plan/apply.

### Cache integrations

- `GetConsumerCacheStack`, `ValidateConsumerCacheStack`,
  `PlanCreateConsumerCacheChangeset`, and `CreateConsumerCacheChangeset`
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
- `PlanRunCacheGc`, `RunCacheGc`, `ListCacheGcRuns`
- `GetCacheGcPlan`, `GetCacheGcRun`, `GetCacheGcDeletionJob`,
  `ListCacheGcDeletionJobs`
- `RetryCacheGcDeletionJob`, `PlanAbandonCacheGcDeletionJob`,
  `AbandonCacheGcDeletionJob`
- `PlanRunPlacementEviction`, `RunPlacementEviction`

Logical GC and placement eviction are different methods and audit event types.

## Validation transactions

Mutations that cross records use a plan/apply shape:

1. resolve current topology and version ids;
2. return semantic effects, warnings, and preconditions;
3. apply against the same versions or reject as stale; and
4. enqueue replication/probe/index work after the control-plane transaction.

Examples include surface visibility changes, endpoint/access-policy changes,
placement drains, write-authority promotion, route advertisement changes, and
destructive GC. GC apply has the same portable requirement as promotion:
logical tombstoning and operation creation are one version-guarded control-plane
transition, not an interactive transaction unavailable to the Worker runtime.
Promotion itself remains the sole authority-row compare-and-swap described
above; GC never changes write authority.

## Complete cutover

- Every still-supported public URL is imported as an ordinary route,
  not a compatibility alias.
- Every committed registry `[caches]` URL is checked before cutover. If its URL
  will change, the signed change is merged before switching traffic.
- The schema migration creates exact storage-binding consumer grants,
  placements, DNS domains, the public and imported private network policies
  with immutable revisions/per-revision observations/lifecycle and exact
  grants, typed endpoints with exact-generation grants, gateways with
  exact-generation grants, routes, manifests and observations, proven
  binding-write revisions, applicable write authorities,
  integrations, release snapshots, root reasons, object mappings, GC state,
  and safe initial mark inputs; validates them; and drops the old topology and
  GC tables/columns in the same maintenance operation. Explicitly read-only
  surfaces remain authority-free. A declared writable surface without one
  unambiguous validated legacy writer, or any physical-location collision,
  aborts the cutover.
- Each legacy frontend URL is parsed exactly into scheme, DNS/IPv4/IPv6 host,
  effective port, ingress/network realm, and normalized path. Missing network
  identity, invalid/ambiguous URL text, or an unacknowledged cleartext secret
  path aborts migration; no opaque URL or compatibility field survives.
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
