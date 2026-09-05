# Hosted AOS Hub backup and recovery runbook

This runbook covers the Cloudflare Worker deployments at
`aos.staging.andyl.org` and `aos.andyl.org`. Back up the environments
independently and never place either environment's secrets in the repository.

## What is actually sharded

The current Worker does not shard relational ownership across many databases.
One named `HubDb` Durable Object (`HUB_DATABASE_INSTANCE`) contains the complete
relational SQLite system of record. Control, tenant, registry, and cache Durable
Objects are request-execution shards; they use short calls back to HubDb and do
not own relational copies. The coordinator Durable Object retains operational
leases/counters, not the registry catalog.

The complete recovery set is therefore:

| Member | Authority | Recovery treatment |
| --- | --- | --- |
| HubDb SQLite | Topology, IAM, registry/cache catalogs, publication state | Cloudflare SQLite DO PITR bookmark plus tested rebuild procedure |
| R2 surface bucket | Registry, cache, image, container, and evidence bytes | Independent object copy/inventory or replay from closed release bundles |
| KV sessions/hot state | Disposable sessions and projections | Recreate empty; users sign in again and projections warm from HubDb |
| Deferred queue | Replayable post-write work | Drain before a planned cutover; dispatch reconciliation after recovery |
| Coordinator DO | Leases/counters | Allow leases to expire; rebuild operational state |
| Operator evidence | Plans, bundles, receipts, keys, deployment records | Encrypted backup outside the Hub and repository |

Cloudflare retains SQLite Durable Object point-in-time recovery history for 30
days. A bookmark is a recovery coordinate, not a portable database export.
Cloudflare R2 redundancy protects media failure but not intentional or accidental
deletion. See the provider's
[SQLite Durable Object PITR API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)
and [R2 durability guidance](https://developers.cloudflare.com/r2/reference/durability/).

## Recovery objectives

For testing, retain daily recovery points and every pre-deployment point for 30
days; keep every closed release bundle needed to rebuild the active edge outside
Cloudflare for at least 90 days. Testing may instead be rebuilt under a new root
epoch when explicitly approved.

Main must not open until a portable HubDb logical export/import and an isolated
restore exercise are implemented. PITR is valuable rollback protection, but it
restores the same Durable Object and cannot by itself prove a clean-room restore.
Until that launch gate closes, the main registry remains empty.

## Capture a planned recovery point

1. Stop release, registry, cache, topology, IAM, and credential mutations.
2. Wait for in-flight publications to reach a terminal state and for deferred
   work to drain. Record any work that must be replayed.
3. Probe the exact deployment id and record `HUB_DATABASE_INSTANCE`.
4. Capture the current HubDb PITR bookmark through the seal-gated endpoint:

   ```sh
   bookmark_file="/var/lib/aos-release/backups/hub-bookmark-$(date -u +%Y%m%dT%H%M%SZ).json"
   bookmark_tmp="$(mktemp /var/lib/aos-release/backups/.hub-bookmark.XXXXXX)"
   (
     set -eu
     umask 077
     trap 'rm -f "$bookmark_tmp"' EXIT
     HUB_SEAL_KEY="$HUB_SEAL_KEY" \
       "$installer/bin/aos-hub" worker backup-bookmark \
         --url https://aos.andyl.org > "$bookmark_tmp"
     ln "$bookmark_tmp" "$bookmark_file"
   )
   ```

   Create the restricted parent directory first, remove `bookmark_tmp` after a
   failed capture, and use the AOS-built
   `coreutils` date when it is not already on the maintainer PATH. Run the
   equivalent command against staging with its own seal and distinct file.
   Store the JSON response verbatim; it binds the bookmark, database instance,
   deployment id, requested time, and capture time. The command fails when the
   Worker lacks either live identity instead of inventing a default.
5. Produce a sorted R2 object inventory containing key, byte size, ETag/checksum,
   and capture time. Copy the bucket into a separate backup location or prove
   that every reachable immutable object exists in a retained closed release
   bundle. Do not treat the source bucket as its own backup.
6. Back up the authoring clone, release plans and bundles, TUF metadata, Hub
   receipts, signer audit records, environment configuration inventory, and all
   private keys/secrets through the operator secret manager. Secret backups must
   be encrypted and access-controlled separately from public evidence.
7. Hash and sign the ordered backup manifest. It is complete only when every
   member above has a result and the R2 inventory reconciles with HubDb's active
   publications.

Resume writes only after the evidence is durable outside the deployment.

## Restore HubDb in place

An in-place PITR restore is destructive and is used only after an isolated
rebuild is unavailable or has demonstrated the same failure. Keep the Worker
route closed to mutations throughout the procedure.

1. Select a bookmark from signed backup evidence and verify it is within the
   provider retention window.
2. Confirm the live deployment probe and database instance exactly.
3. Schedule the restore, repeating both values as destructive confirmation:

   ```sh
   restore_file="/var/lib/aos-release/backups/hub-restore-$DEPLOYMENT_ID.json"
   restore_tmp="$(mktemp /var/lib/aos-release/backups/.hub-restore.XXXXXX)"
   (
     set -eu
     umask 077
     trap 'rm -f "$restore_tmp"' EXIT
     HUB_SEAL_KEY="$HUB_SEAL_KEY" \
       "$installer/bin/aos-hub" worker restore-bookmark \
         --url https://aos.andyl.org \
         --bookmark "$BOOKMARK" \
         --confirm-database-instance hub-v2 \
         --confirm-deployment-id "$DEPLOYMENT_ID" > "$restore_tmp"
     ln "$restore_tmp" "$restore_file"
   )
   ```

   Remove `restore_tmp` after a failed request.
4. Preserve and independently read the returned `undo_bookmark` before doing
   anything else. An absent undo bookmark or `restart_required` other than
   `true` is a failed operation.
5. Redeploy the exact recorded installer with the same Worker name and
   `--database-instance`, but a new recovery-qualified deployment id that still
   records the same source commit. Changing the deployment variable makes this
   an actual Worker update and forces a new Durable Object session. Cloudflare
   recommends an immediate `ctx.abort()` after scheduling PITR; this two-step
   procedure instead preserves the provider-issued undo bookmark outside the
   terminating request before forcing the restart. Do not roll code and data
   backward in one unreviewed step. Set, record, and probe the replacement id:

   ```sh
   recovery_deployment_id="$DEPLOYMENT_ID-pitr-$(date -u +%Y%m%dT%H%M%SZ)"
   ```

   Repeat the exact environment command in
   [`aos-hub-deployment.md`](aos-hub-deployment.md), substituting
   `--deployment-id "$recovery_deployment_id"` and changing no artifact,
   database instance, resource name, domain, or secret.
6. Verify schema identity, root login, topology/IAM invariants, registry and
   cache catalogs, publication generations, and public reads.
7. Reconcile R2 from the independent copy or retained release bundles. Run the
   bounded maintenance dispatcher to reconstruct disposable projections and
   deferred work.
8. Capture a new bookmark and operation record, then reopen writes.

If validation fails, schedule the retained undo bookmark, restart again, and
record the failed recovery attempt. Never continue serving an indeterminate
mixture of restored database state and unreconciled objects.

## Rebuild testing from scratch

For the disposable testing registry, a clean rebuild is preferred when history
or root trust is intentionally abandoned:

1. preserve public evidence and revoke all old tokens;
2. deploy the current Worker to staging and production with fresh logical data
   resources, while preserving the existing Worker name and its Durable Object
   class migration history;
3. select a new empty database instance such as `hub-v3`, fresh R2/KV/Queue
   resources, and new environment secrets;
4. bootstrap the owner and recreate explicit topology/IAM configuration;
5. advance the registry trust-root epoch as described in
   [`registry-testing.md`](registry-testing.md);
6. bootstrap and replay only verified releases into the new registry;
7. validate from a new testing image before routing consumers to it.

Deleting or reinstalling the Worker itself is not the reset mechanism. Its
class migration history is provider state. Change the logical database instance
and data resources, then deploy the existing Worker name.

## Routine restore exercise

Monthly for testing and before main launch, perform a clean-room rebuild with
new logical resource names and no production route. Restore/replay the selected
backup, validate all invariants and representative downloads, then destroy the
exercise resources. Record duration, missing dependencies, object/row counts,
digests, and operator. A bookmark capture without a successful recovery exercise
does not satisfy the backup gate.
