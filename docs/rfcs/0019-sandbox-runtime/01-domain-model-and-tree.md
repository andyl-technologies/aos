# Sandbox objects, ancestry, delegation, and placement

## Durable object graph

The controller stores logical resources independently from node-local
realization:

```text
Project
  └─ Sandbox
       ├─ parent sandbox UID (optional)
       ├─ policy revision
       ├─ storage lineage
       ├─ named exports
       ├─ desired attachments
       ├─ snapshots
       ├─ current incarnation (optional)
       └─ child sandboxes

FilesystemView
  ├─ immutable revision or live source generation
  ├─ source descriptor
  ├─ consistency and mutation model
  ├─ presentation policy
  └─ disclosure/cache domain

Attachment
  ├─ source view UID and revision
  ├─ consumer sandbox UID and incarnation
  ├─ destination slot
  ├─ mount attributes
  └─ lease and observed realization
```

Sandbox ancestry, storage lineage, and attachment dependency are distinct
graphs:

- ancestry governs authority delegation and user-facing navigation;
- storage lineage identifies snapshots, clones, and writable deltas; and
- attachment dependency determines placement, teardown, and deletion order.

They often align but must not be inferred from one another. A child may start
from an immutable snapshot of its parent while its parent holds a read-only live
attachment to the child's workspace. That does not make either writable delta
the lower layer of the other.

## Parent and child creation

A sandbox process does not receive mount or container-administration privilege.
It calls the public sandbox API through an inherited, attenuated capability.
The controller validates the request and asks a node daemon to create the
runtime as a sibling host-managed resource.

The effective child policy is:

```text
node ceiling
  intersect project ceiling
  intersect parent delegation envelope
  intersect child request
```

Resource delegation reserves capacity from the parent envelope before child
creation. A parent may delegate a total pool to its descendants or grant a
fixed child reservation. Oversubscription is explicit advisory burst capacity,
never an accidental consequence of missing limits.

The service enforces configurable maximum depth, children per parent, total
descendants, live descendants, attachment edges, and reserved resources. Tree
limits are evaluated before any storage or runtime allocation.

## Inspection

An authorized parent can inspect descendant state through two separate
surfaces:

1. control inspection for status, processes, resource observations, mounts,
   snapshots, logs, and Git state; and
2. filesystem inspection through an explicit view capability.

The default filesystem surface is a broker-owned read-only inspection root with
one independently attached slot per descendant export:

```text
/run/aos/inspection/
├─ child-a/workspace
├─ child-a/results
└─ child-b/snapshot
```

This path is illustrative and is not part of the public API. Clients address
the slots by sandbox and export handles. The broker creates and pins the actual
destination directories before the workload starts.

Independent submounts are preferred to a single mutable FUSE tree because they
provide per-edge authorization, atomic replacement, independent failure,
bounded metadata state, and no need to invalidate an enormous shared inode
namespace.

## Placement and locality

Each attachment declares a required consistency class:

- `local-live` requires source and consumer incarnations on one node;
- `immutable-revision` may be materialized on any capable node;
- `transactional-service` uses a protocol endpoint and does not require a
  shared mount; and
- `best-effort-replica` is allowed only for data explicitly declared
  reconstructible.

Creating a local-live edge installs a scheduler affinity constraint. Migration
planning must either move the complete connected live component, convert the
edge to an immutable snapshot, or reject migration. The system never silently
changes a live view into a stale copy.

A node advertises concrete capabilities such as nspawn version, user namespace
support, new mount API operations, idmapped backing filesystems, FUSE
passthrough, ZFS pools and features, overlay behavior, KVM, and capacity. The
coordinator schedules from observed capabilities, not package version
assumptions.

## State machines

Desired sandbox lifecycle and observed realization are separate. Desired
lifecycle is `Running`, `Suspended`, `Stopped`, or `Deleted`. `Suspended`
includes the requested retention mode: memory-resident freeze or durable
snapshot-plus-stop. The observed sandbox phases are:

```text
Requested -> Preparing -> Starting -> Ready -> Freezing -> Frozen
                 |           |          |          |          |
                 v           v          v          v          v
               Error <-------+------ Stopping -> Stopped <- Hibernated
                 ^                |        |           |
                 |                +--> Deleting --> Deleted
                Lost
```

`Ready` means the runtime exists and every required attachment and policy is
installed. Executions are independent resources. A ready sandbox may have zero
or many executions. Suspend admission reasons over all active executions
without changing the meaning of sandbox readiness.

Execution phases are `Requested`, `Admitted`, `Starting`, `Running`, `Exited`,
`Canceled`, and `Failed`. `Frozen` retains the active incarnation and memory;
`Hibernated` has no active incarnation and names a durable resume snapshot.
Starting from `Stopped`, resuming `Frozen`, and reconstructing `Hibernated` are
explicit transitions whose operation records identify the target generation.
A node loss moves a memory-only frozen sandbox to `Lost`/`Blocked`; only a
separately committed durable snapshot can supply a reconstruction point.

An attachment progresses independently:

```text
Declared -> Preparing -> Attached -> Ready -> Draining -> Released
                 |          |          |
                 +----------+----------+-> Faulted
```

A view progresses through `Declared`, `Indexing`, `Available`, `Degraded`,
`Draining`, and `Released`. A view may remain available after one attachment
fails.

Every state has a machine-readable reason, observed generation, transition
time, and retry classification. Unknown resource deletion is idempotent success
at the desired-state API while audit history retains whether it previously
existed.

## Capability delegation

A controller-issued capability binds:

- issuer, grantee, project, and root authenticated subject;
- sandbox UID and incarnation where applicable;
- resource selectors and allowed operations;
- policy revision and revocation generation;
- assignment epoch when node-specific;
- maximum descendants, depth, resource reservation, and delegation operations;
- not-before and expiry times; and
- the digest of the parent delegation decision.

Capabilities are not filesystem paths, bearer lease IDs, or ambient Unix group
membership. A sandbox that may create children receives only the public
`CreateSandbox` authority constrained by its delegation envelope. It never
receives access to the node daemon, system manager, mount broker, `/dev/fuse`,
or another sandbox's namespaces.

## Deletion dependencies

Deletion computes the complete dependent graph before changing state. The
default operation refuses when the sandbox has:

- live children;
- consumers of a live export;
- unpublished writable staging;
- active executions;
- retained snapshots protected by policy; or
- capabilities whose revocation policy requires an explicit administrative
  action.

`--cascade` records a topological desired-state transaction, stops consumers
when necessary to revoke open handles, deletes descendants leaves-first,
releases attachments, and finally destroys datasets and logical records.
`--force` is not an alias for recursive file deletion; it selects an explicit
administrative revocation policy and remains auditable.
