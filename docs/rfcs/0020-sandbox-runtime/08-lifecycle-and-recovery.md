# Lifecycle, snapshots, suspension, recovery, and deletion

## Desired state and operations

Consequential mutations create durable operation resources. An operation
contains:

- operation UID and idempotency key;
- target resources and expected resource versions;
- expected sandbox incarnation and assignment epoch;
- accepted desired generation;
- ordered steps and compensation state;
- progress and bounded diagnostics; and
- terminal success or typed failure.

A rejected synchronous request has no side effects. Once accepted, a later
failure appears on the operation resource rather than as a retroactive
transport error.

Client cancellation and transport deadlines do not implicitly roll back an
accepted operation. Cancellation is admitted only before the operation's
documented commit point. Terminal outcomes distinguish `Succeeded`,
`FailedBeforeCommit`, `CanceledBeforeCommit`, `CommittedWithResidualCleanup`,
and `PermanentlyBlocked`. Residual cleanup remains a reconciled resource after
the user-visible desired state commits.

The commit point is a durable semantic record, not whichever backend syscall
happens to run first:

| Method family | Cancellation closes when | Before the commit point | At or after the commit point |
| --- | --- | --- | --- |
| Create, fork, restore | The new resource, assignment, reservations, and desired generation are atomically visible | Release proposals and prepared resources; no sandbox exists | Reconcile the new resource; reversal is an explicit delete |
| Policy or environment update | The new desired generation and complete input commitments compare-and-swap | Discard prepared policy, view, and reservation state | Reconcile that generation; reversal is another versioned update |
| View attach, replace, detach, release | The attachment or view desired generation compare-and-swaps | Release staged descriptors, workers, and pins | Finish/reconcile the mutation; reversal is a new attachment operation |
| Start, stop, suspend, resume | The desired lifecycle state and generation compare-and-swap | Preserve the prior desired state | Reconcile the committed state; an inverse transition is a new operation |
| Snapshot | The verified manifest changes from `Prepared` to `Committed` after every retention acknowledgement | Thaw as required and release prepared holds, roots, and unpublished data | Preserve the snapshot; deletion is a separate versioned operation |
| Execution create | The execution becomes `Admitted` with its incarnation, limits, reservations, and route commitment | Reject admission and release proposals | Cancellation targets the execution resource; it does not cancel admission history |
| Execution cancel | The execution's desired cancellation generation compare-and-swaps | Leave the execution admitted or running | Deliver/reconcile cancellation; an already observed exit remains the terminal result |
| Capability attenuate or renew | The new child grant or lease generation compare-and-swaps | Publish no handle or renewed lease | Preserve the new record; reversal is revocation |
| Capability revoke | The revocation generation compare-and-swaps | Leave the prior grant state | Enforce revocation to its declared stop/freeze/deny-new completion; revocation is not undone by cancel |
| Delete or cascade delete | The complete version-checked tombstone set and postorder plan commit atomically | Leave all resources live | Drain and reap to completion; cancellation cannot resurrect tombstoned resources |

Planning and read methods have no effects and are canceled with their RPC.
`CancelOperation` returns the observed commit-point state, making a race
between cancellation and commit explicit. Backend compensation after a
pre-commit failure cannot publish the proposed semantic resource.

## Creation

Creation proceeds as one reconciled transaction:

1. validate identity, ancestry, policy, and idempotency;
2. intersect authority and compute descendant and node reservations;
3. select a node, incarnation, and assignment epoch;
4. atomically persist desired state, policy, complete preconditions,
   reservations, assignment, and the accepted operation before effects;
5. acquire the ownership-authority lease and install broker plans;
6. arm the assignment guardian before payload start or shared external
   endpoint activation;
7. create or clone private storage;
8. resolve immutable base and package views;
9. create broker-owned attachment slots;
10. prepare required views and cache reservations;
11. create the pinned network namespace and install verified default-drop
    policy while its external link remains down;
12. start the runtime in that prepared namespace;
13. attach views into the observed payload namespace;
14. install execution access and raise the network link only after all hard
    policy is observed; and
15. publish the observed `Ready` generation.

Failure compensates completed effects in reverse order and leaves durable
evidence for reconciliation. A retry with the same idempotency key resumes or
returns the original result; it never creates a second sandbox.

## Execution lifecycle

An execution is independent from sandbox availability. Its states are:

```text
Requested -> Admitted -> Starting -> Running -> Exited
     |           |           |          |
     +-----------+-----------+----------+-> Failed or Canceled
```

Admission binds the sandbox incarnation, environment generation, working
directory, argv, credential projections, resource sublimits, and access route.
A sandbox may accept concurrent executions only when its profile allows them.
Suspend closes new execution admission and reasons about each existing
execution explicitly.

## Fast suspend

Fast suspend keeps the runtime and attachments allocated:

1. take the per-sandbox mutation lock;
2. close new exec, mount, package-change, and publication admission;
3. ask cooperative services to quiesce when configured;
4. drain in-flight view writes and mount replacements;
5. freeze the payload cgroup and confirm the frozen event;
6. persist the observed namespace, attachment, and lease state; and
7. report `Suspended`.

FUSE workers stay outside the frozen cgroup. Cache pins and native mounts remain
live. Fast suspend is therefore quick but retains node placement and resources.
It is not portable and is lost on node failure. After host reboot, a sandbox
whose desired state was memory-resident `Suspended` remains stopped; the
controller does not automatically run it. An explicit resume reconstructs a
new incarnation from its last durable storage state or reports that no durable
resume point exists.

## Durable hibernation

Durable hibernation is snapshot plus stop:

1. run the snapshot barrier;
2. persist the complete snapshot manifest and storage snapshots;
3. stop the runtime;
4. detach and release ephemeral views and workers;
5. release node-only reservations; and
6. leave the logical sandbox in `Suspended` with no active incarnation.

Resume chooses a node capable of the snapshot requirements, creates a new
incarnation, restores storage, reconstructs attachments from the manifest, and
boots or restores the selected backend. Open FDs, process memory, TCP sessions,
and FUSE requests are not preserved unless a future backend-local checkpoint
explicitly advertises and validates them.

Restore never treats historical policy as present authority. Before effects it
intersects the recorded request with current site, project, revocation,
disclosure, secret, endpoint, and delegation ceilings and persists a newly
resolved policy. A narrowing that changes required semantics blocks for
explicit review or fails; restore never resurrects a revoked capability.

## Snapshot consistency

A snapshot request selects one of:

- crash-consistent: freeze and storage synchronization only;
- application-quiesced: a declared guest hook succeeds before freeze; or
- backend-exact: a backend-specific checkpoint whose compatibility and
  completeness are separately validated.

The snapshot coordinator first computes the complete attachment dependency
closure. A live mutable export remains mutable even when the consumer mounted
it read-only. Obtaining a consistent revision therefore freezes/snapshots its
owner under the same barrier, converts it to a sealed revision beforehand, or
records it as external and makes the snapshot non-self-contained.

The closure includes every authorized writer of each owned dataset. The
coordinator acquires and fences all writable-export leases, quiesces/freezes or
stops every writer, or rejects the snapshot. Freezing only the nominal owner is
not a write barrier while another sandbox holds a live read-write attachment.

The snapshot coordinator:

1. acquires every affected sandbox and attachment mutation lock in canonical
   UID order;
2. blocks new writes, publications, and attachment changes;
3. drains or cancels in-flight materialization and cache publication;
4. invokes and records any guest quiesce result;
5. freezes the payload;
6. syncs owned filesystems and view metadata;
7. atomically snapshots all owned datasets where the backend supports it;
8. seals private deltas needed by the snapshot;
9. acquires durable ZFS holds, Nix GC roots, authoritative content/source
   leases, and every other required availability root;
10. writes and verifies a controller `Prepared` transaction binding exact
    snapshot GUIDs and usable retention tokens, plus a portable manifest that
    commits closure generations, content revisions, typed claims, opaque
    version hashes, and non-secret receipt digests;
11. confirms every retention authority durably acknowledged the ledger token
    committed by its receipt digest, then publishes the manifest as `Committed`
    and visible to restore;
12. releases transient pins while retaining the committed roots; and
13. thaws only the runtimes that were running before the barrier when the
    caller did not request suspension.

After any failure following a successful freeze, thaw is mandatory compensation
for every runtime that was running before the barrier, even when snapshot or
manifest cleanup also fails. A failed thaw becomes an explicit high-priority
residual operation; it is never hidden by the original snapshot error.

A ZFS snapshot does not capture mount namespace state. The manifest records
every attachment and view revision for replay.

Reconciliation may release orphan holds belonging to a never-committed
`Prepared` manifest after its fenced grace period. It may never expose a
committed manifest until every required byte has a durable availability root.
Integrity identity without retained availability is not self-containment.

Operational storage holds, content leases, Nix GC roots, service checkpoint
tokens, and secret-retention handles live in a mutable controller retention
ledger keyed by snapshot UID and receipt digest. The immutable manifest commits
only typed dependency claims, immutable versions, non-secret receipt digests,
and availability constraints. A receipt digest proves which acknowledgement
was required; it is not a credential with which a snapshot reader can release
or exercise that retention authority.

A frozen filesystem gives stable bytes, not necessarily a Git-semantic point;
it may preserve an index lock or an in-progress multi-file transaction. A Git
semantic snapshot additionally requires a successful cooperative Git quiesce
inside the repository's sandbox or a committed ref obtained through the smart
protocol.

## Self-contained snapshots

A snapshot is self-contained only if all required state is both immutable and
durably retained content or owned held snapshot storage. External writable
mounts, service databases, device state, and live remote resources are
dependency declarations, not silently captured data.

A request for a self-contained snapshot fails if any required attachment is:

- any external mutable live view, whether mounted read-only or read-write;
- a service without a declared immutable checkpoint version and durable
  controller-held retention receipt;
- a device with mutable state;
- an unsealed secret whose retention policy forbids capture; or
- a backend state component outside the selected checkpoint capability.

Non-self-contained snapshots list every dependency and required generation.
Restore refuses when a dependency cannot satisfy it.

Portable snapshots contain no secret bytes. A permitted sealed-secret
reference remains an external dependency and records issuer, opaque version,
availability/expiry constraints, and the authorization required at restore.
The usable secret handle remains in the controller ledger and is reauthorized;
it is never serialized into the portable object graph.

## Fork

Fork creates a new child sandbox from a committed snapshot manifest. It never
shares a writable upper. Native storage may use a cheap clone; logical identity
still references the immutable parent snapshot plus a private child delta.

The child receives a newly resolved attenuated policy, new capability set, new
assignment epoch, and new runtime incarnation. Snapshot authority does not
implicitly grant access to secrets or services attached to the parent.

## Recovery and reconciliation

Node restart begins with discovery, not deletion. The node daemon inventories:

- transient units and payload cgroups;
- pinned namespace and process observations;
- broker-managed mounts using mount IDs and attributes;
- ZFS datasets, snapshots, clones, holds, and quotas;
- FUSE connections and worker units;
- cache reservations, pins, temporary publications, and deleting entries; and
- desired assignment records.

It matches observations by durable sandbox UID, incarnation, generation, and
broker-controlled metadata. Names alone are not sufficient. Unknown privileged
state is quarantined for operator inspection unless its ownership can be
proven; it is not recursively deleted.

Desired active sandboxes are repaired or marked faulted. Desired absent
sandboxes are drained and removed. An attachment recorded `Ready` only after the
kernel mount is observed at the expected slot; a database row alone is not
readiness.

## View and lease recovery

Every attachment lease binds sandbox and view identity, both incarnations where
live, policy digest, assignment epoch, authority scope, and deadline. A delayed
request from an old coordinator cannot renew or release a newer attachment.
Mount Apply semantics and the successful receipt reproduce the exact lease ID
and interval together with the desired generation. The durable physical mount
recipe instead retains the resource generation it created, allowing a newly
authorized release to identify and drain that older generation without
misstating it as current desired state.

The controller's current-attachment planner samples the protected wall clock
only after rechecking desired state, authenticated Mount inventory, and live
namespace authority. Before issue time it waits; at or after exclusive expiry
it plans the same ordered detach/release drain as an explicit release tombstone.
An empty expired realization reports expiry rather than readiness. Planning is
non-authorizing and rechecks all three inputs before returning, so expiry cannot
turn stale inventory or a replaced desired generation into cleanup authority.

The attachment effect path consumes that closed decision rather than accepting
a caller-authored Mount body. It derives creation from the current desired
recipe, derives install and replacement from the exact inventoried resource,
and derives detach and release from the older physical recipe while retaining
the current desired generation and lease. Desired state, the complete inventory
snapshot, the selected action, and live namespace authority are rechecked
through catalog preparation, signed-plan binding, and immediately before
durable attempt admission. Admission changes controller history and therefore
makes the older snapshot stale by construction; the admitted live token instead
retains the exact desired generation, lease mode, and namespace authority around
dispatch. Release is catalogless because it removes only broker custody, but it
still requires current authority, an exact signed plan, durable-before-I/O
admission, and a validated success receipt.

Lease expiry begins draining. It does not delete a backing object until active
kernel/open pins are reconciled. FUSE worker failure can leave an attachment
faulted; the reconciler freezes the consumer when its required filesystem
semantics are no longer available.

An expired assignment plan authorizes only node-local containment: default-drop
its network, freeze or kill its cgroup, detach namespace-local mounts after the
payload is dead, and remove objects proven private to that node and assignment.
Releasing a shared hold, destroying or mutating shared storage, rolling back a
publication, or removing an externally reassigned endpoint requires a fresh
controller cleanup plan subordinate to current ownership authority plus a
compare-and-swap at that resource's authoritative fencing endpoint.

## Deletion

Deletion first authorizes and snapshots children, live export consumers,
snapshot descendants, published/unpublished staging, active executions, and
capability-retention requirements under a controller transaction that prevents
new dependency edges. It compare-and-swaps every participating resource
version before accepting the operation. A refused default delete changes no
desired state.

Default deletion refuses unresolved dependents. Cascading deletion records the
whole versioned post-order plan and all desired tombstones atomically before
effects begin. It:

1. revokes new admission;
2. stops consumers when hard revocation is required;
3. deletes or detaches descendants leaves-first;
4. unmounts writable layers before lowers;
5. releases FUSE registrations and view workers;
6. closes namespace, root, source, and userns descriptors;
7. proves every broker-catalogued namespace, mount, FD, hold, and clone edge is
   drained and requests exact unmount/destruction;
8. releases cache pins and reservations;
9. destroys private datasets; and
10. marks physical reap complete and writes the terminal audit event.

Lazy detach alone does not revoke open FDs, current working directories, or
mappings. Security-sensitive force deletion stops the consumer cgroup before
claiming revocation.

Inventory cannot prove that no unknown kernel FD or detached mount reference
exists. Final unmount and exact `zfs destroy` results are authoritative.
`EBUSY`, an unknown hold, or an unexpected origin dependency leaves the
tombstoned resource in `ResidualState` with data intact; it never triggers
recursive or guessed cleanup.

## Upgrade

Control and view services use rolling generations. A worker or broker upgrade
does not attempt to transfer an initialized live FUSE connection. Compatible
views drain and remount; sandboxes may be briefly frozen for an atomic switch.
The public desired state and portable tree objects survive implementation
upgrades.
