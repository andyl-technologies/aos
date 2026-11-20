# Hub OCI garbage collection and registry deletion

This page describes how the Hub inventories and collects the OCI blobs of a
registry, the states of an OCI GC run, and the `delete_registry` operation
that removes an emptied registry. The deletion ordering, conditional-delete
capability, and deletion jobs that these runs share with binary-cache
collection are described in
[retention-and-gc.md](retention-and-gc.md#replication-and-deletion-ordering).

## OCI blob inventory

The OCI (Open Container Initiative) provider inventory that supplies the
strong ETags for registry placement deletion enumerates only the
`oci/blobs/sha256/` namespace of a registry placement. The placement also
holds the binary cache and git objects, which a blob inventory must never
page through, so the surface listing port takes a key prefix that every
backend applies natively (an object-store list prefix or a filesystem walk
rooted at the prefix). Each listing page holds one object, and a page is
checkpointed only once that object is hashed, so a dispatch that stops in the
middle of a large blob resumes it without rehashing or skipping siblings. A
durable checkpoint cursor is meaningful only for the prefix that produced it:
it is stored with a scope tag, and a collecting generation whose cursor
predates blob-scoped listing fails closed and restarts once as a fresh
generation rather than resuming an unscoped cursor against a scoped walk.

## OCI GC runs and registry teardown

Registry deletion requires an empty catalog, but signed releases and tags are
permanent roots of ordinary collection. A reviewed *retiring* run drops the
catalog-owned roots (signed releases, tags, retained tag history) and collects
without grace.

- It fails closed, at planning and inside the apply transaction, while any
  enabled route serves the registry's OCI paths. That includes an enabled
  registry OCI namespace and an enabled instance OCI route that names the
  registry as its default.
- Once it is applying, the indexer refuses to re-project container-release
  roots for that registry.
- Every physical deletion of a retiring run uses the same inventory,
  capability, and finalization fences as an ordinary run.

An OCI GC run moves through these states:

| State | Meaning |
| --- | --- |
| `planned` | The plan has been reviewed. It holds no lock, delete credential, or tombstone, and no worker can claim its frozen placement actions. |
| `applying` | Apply has tombstoned the candidates and taken the registry GC lock. |
| `complete` | Finalization has finished. |
| `failed` | The plan failed closed while planning. |
| `aborted` | Terminal state of a plan that was never applied. |

A `planned` run becomes `aborted` in one of two equivalent ways:

- its fifteen-minute review expires and the maintenance sweep records
  `review expired before apply`; or
- a registry configurator cancels it with
  `ContainerService.CancelContainerGcRun`, which records
  `cancelled by operator before apply`.

Cancellation binds the run's resource version, fails closed for an `applying`
run, whose recovery belongs to action requeue and finalization, and returns an
already terminal run unchanged.

Only applied GC work blocks registry teardown: an `applying` run and the
unfinished placement actions of a run that was applied. Apply rejects an
expired plan, so an expired or aborted run, and the never-claimable actions
frozen by any run that was not applied, never block. Reviewed purge-fence
admission additionally counts an unexpired `planned` run, because it could
still be applied behind the fence.

The final identity deletion is a `delete_registry` topology operation. It
removes no provider objects itself. Its blockers fall into two classes:

- Operator blockers refuse the reviewed apply with `failed_precondition` and an
  exact per-class count. These are repositories, catalog objects, active OCI
  sessions or leases, active publications or uploads, retained binary-cache
  roots, staged container objects, applying GC runs, unfinished actions of
  applied GC runs, active untracked repairs, snapshot references, offline
  placements or placements without a current write revision, and provider
  objects listed by a current inventory.
- Automatic steps are performed by the operation. It abandons every `planned`
  GC run, expired or not, recording `abandoned by registry deletion
  OPERATION_ID` and the run ids in the operation detail. This is the same
  `planned` to `aborted` transition as cancellation, so the reviewed deletion
  never waits for the expiry sweep or a separate cancel. It acquires an
  operation-owned purge fence. It requests a scan of any placement that was
  never observed `ready/complete`. It collects a fresh complete inventory of
  every placement under that fence.

Missing or stale inventories are therefore never a reason to refuse deletion:
the operation proves emptiness itself, including for a registry that never
published and so never entered the scheduled inventory sweep. The deletion
transaction re-asserts every predicate. If one changed after the last readiness
evaluation, the transaction reports the changed blocker breakdown instead of an
affected-row mismatch. An operation that fails or is cancelled releases the
fence it acquired.
