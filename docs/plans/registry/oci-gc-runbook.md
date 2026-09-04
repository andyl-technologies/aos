# OCI container operations and garbage-collection runbook

This runbook covers the Phase 7 OCI control plane. Garbage collection is
fail-closed: incomplete or stale inventory, a changed mutation epoch, a changed
root/policy/topology digest, or a placement without a proven conditional-delete
capability blocks deletion.

All five OCI rollout gates default to false: pull, push, verified publication,
administration, and GC. Enable GC only after pull/push behavior, complete
inventories, and the provider's exact conditional-delete observation have been
validated. The GC gate controls plan, apply, and run evidence reads; disabling
it does not disable pull.

## Readiness and capability probing

Before enabling GC, verify every enabled placement has a complete inventory
whose captured registry epoch and immutable placement, binding, and write-state
versions still match. The inventory must be newer than the planner's maximum
inventory age. A provider name, bucket kind, or successful unconditional delete
is not capability evidence.

The placement controller records a successful conditional-delete capability
probe against the exact binding write revision and delete-credential
generation. Planning and action claiming fail closed if that observation is
absent, stale, or belongs to different credentials. For each provider, exercise
a harmless conditional mismatch as well as a conditional success in staging;
confirm that mismatches never delete bytes and that the recorded strong ETag or
equivalent immutable precondition is the one carried into placement actions.

## Normal review and apply

1. Read the effective retention policy and record its `resource_version`. The
   built-in policy with no stored row has version `0`.
2. Create a durable, actor-bound plan:

   ```sh
   aos hub registry container gc plan REGISTRY \
     --if-version POLICY_VERSION \
     --idempotency-key CHANGE_ID
   ```

3. Review the returned mutation epoch, root-set, inventory, topology, and plan
   digests; planned object and byte totals; placement-action count; blockers;
   expiry; and confirmation hash.
4. Inspect bounded evidence when needed:

   ```sh
   aos hub registry container gc get REGISTRY RUN_ID
   aos hub registry container gc list REGISTRY --resource candidates --run-id RUN_ID --page-size 100
   aos hub registry container gc list REGISTRY --resource blockers --run-id RUN_ID
   aos hub registry container gc list REGISTRY --resource placement-actions --run-id RUN_ID --page-size 100
   ```

5. Apply only the unchanged reviewed plan:

   ```sh
   aos hub registry container gc apply \
     --plan-id RUN_ID \
     --confirm-hash SHA256_CONFIRMATION \
     --idempotency-key CHANGE_ID \
     --yes
   ```

The generation ID is also the durable operation ID. Reusing the same apply
idempotency key returns the same operation. A different actor, expired plan,
confirmation mismatch, stale policy/root/topology/inventory/epoch, new lease or
upload, or changed placement identity must fail before an action is claimed.

## Untracked provider inventory repair

An object in a current, complete provider inventory with no matching catalog
identity is not ordinary GC input. Inspect it through the bounded current-head
inventory view:

```sh
aos hub registry container gc untracked list REGISTRY --page-size 100
```

The result includes the exact inventory generation and digest, provider object
key, observed digest/hash and size, strong ETag, and frozen placement and
binding versions. Treat that evidence as a single immutable repair target. Do
not delete the key directly, copy it into an ordinary GC action, or infer its
identity from a provider path alone.

Create and review an actor-bound repair plan, then apply only its matching
confirmation hash:

```sh
aos hub registry container gc untracked repair REGISTRY \
  --placement-id PLACEMENT_ID \
  --inventory-generation-id INVENTORY_GENERATION_ID \
  --object-key OBJECT_KEY \
  --if-version INVENTORY_EPOCH \
  --idempotency-key REPAIR_ID

aos hub registry container gc untracked repair \
  --plan-id REPAIR_PLAN_ID \
  --confirm-hash SHA256_CONFIRMATION \
  --if-version PLAN_RESOURCE_VERSION \
  --idempotency-key REPAIR_APPLY_ID \
  --yes

aos hub registry container gc untracked repair-status REPAIR_PLAN_ID
```

The default and currently supported repair is an exact conditional delete. The
plan binds the current inventory head, observed digest/hash/size/strong ETag,
placement and binding versions, delete capability, actor, expiry, and
idempotency key. Apply is rejected if any bound evidence changes. There is no
unconditional-delete or partial-adopt escape hatch; adoption requires proof of
the complete immutable catalog graph and accounting identity and is unavailable
without that proof.

Poll `repair-status` until the durable state is terminal. A successful status
includes the provider outcome, conditional ETag when one was used, evidence
digest, confirmation time, exact frozen inventory/topology identity, and the
current resource version. Preserve failed status and its sanitized error for
operator diagnosis; never replace it with an unreviewed provider delete.

After the repair operation confirms exact absence, run a new complete provider
inventory and verify the object no longer appears in the untracked list. Only a
fresh, post-repair inventory may satisfy registry-purge checks. Never reuse the
pre-repair inventory generation as proof that the provider namespace is empty.

## Registry purge fence and final deletion

Final registry deletion requires a reviewed writer fence; the Hub never creates
that fence implicitly inside `DeleteRegistry`. First verify that repositories,
catalog objects, active sessions, GC work, untracked repairs, and snapshot
references are empty. Then use the registry resource version returned by
`aos hub registry show REGISTRY` to review and acquire the fence:

```sh
aos hub registry container gc purge-fence plan REGISTRY \
  --action begin \
  --if-version REGISTRY_RESOURCE_VERSION \
  --idempotency-key PURGE_FENCE_PLAN_ID

aos hub registry container gc purge-fence apply \
  --plan-id PURGE_FENCE_PLAN_ID \
  --confirm-hash SHA256_CONFIRMATION \
  --if-version PLAN_RESOURCE_VERSION \
  --idempotency-key PURGE_FENCE_APPLY_ID \
  --yes

aos hub registry container gc purge-fence status PURGE_FENCE_PLAN_ID
```

The fence blocks new OCI writers. Wait for every placement to publish a new
complete empty inventory whose generation began after that exact fence and
whose selector matches its resource version and captured mutation epoch. The
status is ready only when all bounded logical, provider, GC, session, snapshot,
and post-fence inventory blocker counts are zero. Then use the existing
reviewed `aos hub registry delete REGISTRY --if-version
REGISTRY_RESOURCE_VERSION` workflow for final identity deletion.

If deletion must be cancelled, review an Abort plan using the current fence
resource version reported by status, then apply it with the same explicit
confirmation and plan CAS flow. Abort reopens writers and invalidates all prior
purge-readiness evidence; a later purge must acquire a new fence and collect
new post-fence inventories.

## Logical and physical phases

Apply first revalidates the reviewed state and atomically tombstones catalog
visibility. That logical transition does not claim that physical bytes are
gone. Durable placement actions then conditionally delete each frozen provider
object; workers record absence evidence and retry only within the bounded action
budget. Candidate identity and quota remain until every required placement has
confirmed absence and finalization completes. A run is `complete` only after
that physical phase and catalog finalization; `applying` means destructive work
or recovery is still outstanding.

Provider retries must preserve the frozen object key, expected digest/size,
strong conditional version, binding write revision, and credential generation.
An exhausted retry becomes a failed action for operator repair. Operators
reconcile current inventory and binding state, repair credentials or the
provider fault, then use the controller recovery path; they do not downgrade to
an unconditional delete or edit run rows.

## Metrics and alerts

Native deployments expose Prometheus text at `/metrics`. Worker deployments use
Workers Logs and provider metrics with the same state names. The native endpoint
exposes these low-cardinality OCI signals:

- `aos_hub_oci_rollout_enabled{capability=...}` for the five server-side gates;
- `aos_hub_oci_gc_runs{state=...}` for durable run states;
- `aos_hub_oci_gc_bytes{state="planned|finalized"}` for reviewed and finalized bytes;
- `aos_hub_oci_gc_failed_actions` for exhausted conditional deletes;
- `aos_hub_oci_gc_blockers` for durable planning blockers;
- `aos_hub_oci_gc_stale_inventories` for placements lacking fresh complete evidence;
- `aos_hub_oci_catalog_objects` and `aos_hub_oci_catalog_bytes` for logical,
  unique, and reused catalog identity;
- `aos_hub_oci_reuse_ratio` for the reused fraction of logical catalog bytes;
- `aos_hub_oci_provider_inventory_objects` and
  `aos_hub_oci_provider_inventory_bytes` for current complete physical heads;
- `aos_hub_oci_uploads` and `aos_hub_oci_publications` for fixed durable state
  classes, including expired uploads and stuck publications;
- `aos_hub_oci_publication_ready_latency_seconds` for ready-publication
  latency sum and count;
- `aos_hub_oci_placements` and `aos_hub_oci_inventory_age_seconds` for bounded
  placement health and freshness;
- `aos_hub_oci_inventory_events` and `aos_hub_oci_gc_recoveries` for failed
  inventory, lease takeover, and actor-bound action-requeue evidence; and
- `aos_hub_oci_digest_mismatches` for exact current-head inventory/catalog
  digest conflicts.

Labels remain bounded to capability, state, kind, statistic, and health
classes; digest, repository, registry, actor, operation ID, and provider object
keys never become labels.

Alert when any of these conditions persists beyond the deployment's normal
reconciliation interval:

- logical/physical accounting mismatch;
- publication remains nonterminal past its lease/expiry;
- placement inventory age exceeds the GC planner's maximum;
- a required placement is missing or unhealthy;
- a conditional deletion fails or exhausts retry attempts;
- a GC generation remains `applying` without action progress;
- the mutation epoch advances repeatedly during the review window;
- GC reports completion while any candidate placement action is nonterminal.

Native deployments can load the checked
[`oci-alerts.rules.yml`](../../../crates/aos-hub/monitoring/oci-alerts.rules.yml)
Prometheus rule group directly. Its alert labels are limited to fixed severity
and component values; tenant, repository, digest, actor, and operation
identities never become metric labels.

## Incident response

1. Disable `HUB_OCI_GC_ENABLED` without disabling pull. Preserve the database,
   provider inventory, Worker/native logs, generation JSON, and audit records.
2. List blockers and placement actions for the affected generation. Do not
   manually mark a failed action complete or release logical identity/quota.
3. Compare the recorded placement inventory digest and immutable binding write
   revision/credential generation with current topology. A provider type alone
   is never proof of conditional-delete support.
4. Check for active uploads, publication leases, newly moved tags, signed roots,
   referrers, and retention-policy changes after the captured mutation epoch.
5. If a conditional delete returned a precondition failure, preserve the
   `applying` generation, registry lock, and failed action. Investigate or
   restore the exact reviewed object identity, binding write revision, and
   credential generation. Never create a competing plan, retarget the action
   to current bytes or credentials, or retry it as an unconditional delete.
6. After exact repair, use a controlled maintenance window to re-enable
   `HUB_OCI_GC_ENABLED`, then requeue only that same frozen failed action with
   its current resource version and a stable operator retry key:

   ```sh
   aos hub registry container gc requeue REGISTRY RUN_ID ACTION_ID \
     --if-version ACTION_RESOURCE_VERSION \
     --idempotency-key REPAIR_ID \
     --yes
   ```

   The authenticated RegistryConfigure action is GC-gated, actor/idempotency
   bound, and never retargets the frozen object, placement, binding revision,
   or credential generation. An identity mismatch still requires escalation;
   it is not a reason to edit the action or weaken the delete precondition.
7. If bytes were deleted but catalog/quota finalization failed, preserve the
   `applying` generation and its lock while the durable controller retries the
   exact finalization fences. Do not mark the run failed, edit candidate/quota
   rows, or create a replacement plan by hand.
8. Monitor the same generation through exact action retry and finalization. If
   it fails again, disable GC and preserve its evidence. Return GC to its normal
   rollout state only after recovery completes and a later fresh plan has no
   blockers and its exact inventory, topology, root-set, policy, and
   mutation-epoch checks pass.

Registry or repository deletion remains blocked while tracked or untracked OCI
bytes exist. Purge checks also block on repository identities, catalog objects,
active upload/publication/lease rows, nonterminal GC work, stale or missing
inventories, and native snapshot references. Reconciliation, not metadata
deletion, resolves those conditions.
