# Filesystem views, FUSE, and native realizers

## Logical view model

A filesystem view description answers five questions independently:

1. Which source and immutable revision or live generation is visible?
2. Which namespace entries and metadata are presented?
3. What consistency and mutation model applies?
4. Which authority and disclosure domain may consume physical backing?
5. Which semantic and performance features are required?

The description does not select a host mount path or prescribe FUSE. The node
chooses a compatible realizer from observed capabilities. The chosen realizer
and any degraded advisory features appear in status.

A public attachment request resolves to this semantic tuple:

```text
consumer sandbox and incarnation
expected sandbox and attachment generations
source capability and view revision or live generation
declared destination slot
closed mount attributes
lease identity and expiry
```

It never contains a host path, PID, namespace path, mount option string,
mount ID, or file descriptor.

## View modes

| Mode | Source | Consumer writes | Typical realizer |
| --- | --- | --- | --- |
| Immutable | Fixed tree revision | Rejected | Native read-only mount or FUSE |
| Live read-only | Mutable local export | Rejected | Native detached idmapped mount |
| Live read-write | Mutable local export | Direct to source | Native mount; exceptional authority |
| Private CoW | Immutable lower | Private delta | ZFS clone or one overlay layer |
| Publishable staging | Immutable lower | Private transaction | Private dataset plus verified commit |
| Service projection | Endpoint | Protocol-defined | Socket or endpoint attachment, not file permissions |

Source mutability and view mutability are not synonyms. A private CoW view has
an immutable source and a mutable namespace. A live read-only view has a
mutable source but denies consumer mutation.

`Live read-only` is not the noninterfering inspection tier. A native bind of a
live filesystem shares inode locks and exposes sockets and FIFOs even when the
mount is `ro`; a consumer can therefore block source locks or communicate with
active endpoints. It requires an explicit `live-kernel-coupled-read` grant that
discloses those semantics. Default cross-sandbox inspection uses an immutable
snapshot or filtered immutable FUSE revision, omits sockets/FIFOs/devices, and
does not share regular-file lock identity with the source.

## Native mount path

Same-node live datasets and native snapshots use the Linux descriptor-based
mount API:

1. resolve an opaque broker source handle to a pinned source descriptor;
2. resolve any allowed relative subpath with `openat2(2)` using beneath,
   no-magic-link, and no-symlink constraints;
3. clone an invisible mount with `open_tree_attr(2)`;
4. apply the target user namespace idmap and `ro`, `nosuid`, `nodev`, and
   optional `noexec` attributes before exposure;
5. enter the pinned target mount namespace in a short-lived worker;
6. pin the predeclared target slot by descriptor; and
7. attach with `move_mount(2)`.

`open_tree_attr(2)` is preferred on the AOS 6.18 kernel because it can clone and
change or remove an existing idmap in one detached operation. See the
[Linux man-pages description](https://man7.org/linux/man-pages/man2/open_tree_attr.2.html).

The default clone is non-recursive. Recursive cloning imports every source
submount and scales with mount topology rather than file count; it requires a
separate authority and hard mount-count admission.

For a live native source, read-only mount attributes prevent file mutation but
do not suppress IPC or lock operations. The policy compiler never maps ordinary
`content-read` authority to this realizer. It selects the kernel-coupled grant
above or materializes an immutable inspection revision.

Source subpaths resolve beneath catalog roots with
`RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS` and normally
`RESOLVE_NO_XDEV`. Destination slots live in a host-owned attachment-anchor
filesystem. The host side remains writable only to the broker; an idmapped
read-only view of the anchor is installed in the sandbox before the payload
starts. The broker may create new bounded slot directories on the host side at
runtime, and the shared underlying directory makes them visible without giving
the sandbox create, rename, or replacement permission. Arbitrary workload
paths are not attachment destinations. Friendly locations are immutable links
or facades to these slots where the profile permits them.

Pinning an `O_PATH` target is not enough because an attacker may have raced an
old pathname before the anchor policy took effect. The worker verifies the
slot's anchor mount ID, parent chain, inode identity, and non-writability before
publication, then verifies the final mount unique ID at the authorized path.
Any mismatch rolls back the staged generation and faults the sandbox; it does
not attach at the descriptor's new name.

Replacement prepares the new mount beneath the current mount and removes the
old top under the sandbox mutation lock. On the AOS 6.18 path the worker uses
`MOVE_MOUNT_BENEATH` and then detaches the former top; if the kernel cannot
provide the required atomic replacement semantics, the node rejects that
capability rather than accumulating an overmount stack. Existing descriptors
and mappings may continue using the old mount. Replacement is an atomic
namespace switch for new path resolution, not synchronous revocation.

The operation is not `Ready` until `listmount`/`statmount` observation verifies
the unique mount ID, root, attributes, and identity map at the target and a
post-attach check confirms the sandbox incarnation and namespace generation.
Mount, freeze, snapshot, stop, and namespace-replay operations serialize under
one per-sandbox mutation lock.

Attachment replacement has durable `Planned`, `Prepared`, `Published`,
`Verified`, `Draining`, and `Reaped` observations. Before publication, the node
persists the desired attachment generation and operation digest. Every staged
mount has a broker record binding its unique ID to sandbox, incarnation,
namespace, attachment, and view generations. After a crash, inventory
identifies the old, new, and any intermediate mount by unique ID and the
durable record; the reconciler finishes the desired publication or removes
only a proven stale generation. It never infers stack order from path text or
detaches an unowned mount.

## Generic immutable tree

The portable tree representation contains sorted directory entries and typed
nodes. It deliberately specifies:

- regular-file content descriptors and logical size;
- directories and deterministic entry ordering;
- symlink bytes and path-resolution policy;
- executable and complete permission bits;
- UID/GID under a declared portable identity model;
- timestamps and their normalization rules;
- xattrs and ACLs where the source supports them;
- hard-link identity groups;
- sparse extents and holes;
- whiteouts or deletion markers only in delta formats; and
- policy-gated treatment of devices, FIFOs, and sockets.

Digest values are algorithm tagged and domain separated. The canonical tree
commitment is independent of protobuf serialization order and independent of
the runtime index encoding.

All input is hostile even when its outer digest is trusted. Validation bounds
node count, total name bytes, name and symlink length, depth, extent count,
integer arithmetic, xattr count and size, hard-link groups, directory fanout,
and total logical content. It rejects duplicate or unsorted entries, `.` and
`..`, embedded separators in names, overlapping extents, traversal, cycles,
unsupported node types, and inconsistent content sizes.

Symlink bytes retain ordinary VFS meaning unless a view policy explicitly
normalizes or rejects them. A symlink can therefore resolve outside the mounted
subtree into another path in the consumer's own namespace. Inspection tools
default to no-follow, and consumers needing a subtree-confining interface use
descriptor-relative `openat2` resolution. FUSE alone cannot simultaneously
preserve ordinary symlinks and promise that all consumer path traversal remains
beneath the view root.

## Node-local structural index

Portable tree objects compile into a replaceable node-local index. Format V1 is
the original deterministic sequential structural format and remains accepted
by its unchanged validation rules. Format V2 retains V1 record encoding and
adds an architecture-neutral, fixed-width point-lookup section. New compilation
emits V2 under a distinct media type; version and media type must agree, so a
V2 artifact cannot be interpreted under V1 policy.

V2 lookup entries are sorted canonically by parent record ID, a full
domain-separated SHA-256 digest of the parent and byte-exact component, and
record ID. Lookup uses binary search, then compares the parent and component
bytes in every equal-digest candidate record. The digest is a performance
partition, not a uniqueness or correctness assumption. Validation reconstructs
the table from exact record starts and requires byte-for-byte equality, proving
that every non-root record appears exactly once with no extra entry, forged
offset, or alternative placement. Table lengths and bytes are covered by both
the internal payload digest and the authenticated outer descriptor.

The read-only runtime seam borrows the exact validated immutable bytes and
lazily decodes only the root or lookup candidates. It retains no heap object
per path and allocates nothing during point lookup. A separate generic Linux
boundary now opens seal-proven files and lends their mapped bytes only to a
higher-ranked scoped callback. A future filesystem worker must validate the
descriptor and cross-links once inside that callback, then may retain the
resulting `ValidatedIndex` for its complete request loop; neither the byte slice
nor a proof borrowing it can escape after unmap. The generic mapping boundary
has no dependency on the filesystem-view object model. A backend-neutral table
now lazily assigns connection-local node IDs after positive V2 lookup, while
negative lookup retains no node state. The same backend-neutral table now owns
file-open identity and lifetime transitions, but still owns no OS descriptor,
FUSE request framing, directory handle, or kernel connection authority. V1
remains validation-compatible but does not offer point lookup or inode-table
creation.

Immutable mapping proofs are distinct backend capabilities. A transient memfd
is accepted only with `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW |
F_SEAL_WRITE`; `F_SEAL_FUTURE_WRITE` is insufficient. A fully sealed `O_RDWR`
handoff is safe to read because the proven seals deny mutation, while a
write-only description is rejected. This memfd type is not durable cache
authority. A durable catalog file instead uses a separate fs-verity type. Its
publication authority supplies the exact expected fs-verity algorithm and
measurement independently of the AOS object descriptor. A future worker must
open the relative path once with beneath, no-magic-link, no-symlink, and
no-mount-crossing resolution, measure that same descriptor before mapping, and
repeat the measurement and identity check after mapping; it must never validate
and reopen.
Ordinary files, mode-bit read-only files, and descriptor hashes do not satisfy
either proof.

Both mapping paths compare the authenticated expected length with the regular
file size and a hard mapped-byte ceiling before converting the length or calling
`mmap`. The resulting mapping is shared and read-only. The descriptor and
mapping pin the admitted inode, so rename or unlink changes catalog reachability
but neither revokes existing sessions nor permits early physical reclamation.
On an fs-verity page-integrity failure, a later mapped access may terminate the
worker with `SIGBUS`. The worker does not attempt signal-handler recovery: it
validates before readiness, the supervisor treats an unexpected worker death as
attachment failure, and recovery quarantines the suspect publication before
replacement.

The runtime index contract is:

- immutable after publication;
- authenticated descriptor, expected size, and backend immutability evidence
  verified before mapping, followed by structural validation of the mapped
  bytes before readiness or serving;
- addressed by source tree commitment, exact root descriptor, closed tree-role
  feature set, and compiler ABI;
- usable directly from immutable byte backing rather than decoded into
  per-path language-runtime objects;
- bounded in mapped virtual size and validated offsets; and
- composable with the scoped file-opening and mapping layer without allowing a
  byte borrow or validation proof to outlive immutable backing.

The inode table pins root as node 1 and allocates monotonically increasing IDs
that are never reused during a connection. A validated hard-link group shares
one node ID; otherwise identity is the exact artifact-local record occurrence.
The table retains the `ValidatedIndex` proof for its lifetime, so its private
long-lived node views do not become detached validation authority. V2 record
IDs remain stable only within the exact derived artifact and compiler ABI; they
are not portable inode numbers and are not stable across recompilation. A
portable hard-link group digest is likewise not itself an `ino_t`.

Two fixed-slot open-addressed maps maintain the live node/semantic bijection.
The semantic map uses a per-connection keyed SHA-256 partition whose key must
be unpredictable to the immutable-tree producer; exact semantic comparison,
not the hash, decides equality. Live load remains at most one half and
occupied-plus-tombstone load at most three quarters. Growth or compaction
pre-admits retained old arrays plus requested replacements, observes the first
allocation's actual capacity before allocating the second, and rejects the
combined actual capacities before commit. Allocator metadata and transient
size-class over-allocation remain contained by the worker cgroup rather than
being mislabeled exact language-runtime accounting.

Lookup references have an independent aggregate ceiling. Bounded batch
`FORGET` sorts and coalesces caller-owned request scratch without allocation,
preflights every count, reverse-map removal, and resulting counter before its
first table mutation, then applies with no fallible branch. Zero, stale,
over-forget, duplicate overflow, and mixed valid/invalid batches leave inode
state unchanged.

File opens use a separate fixed-slot table with an independent live-handle
ceiling and the same aggregate modeled heap ceiling. Handle IDs are typed,
connection-scoped, monotonically increasing, and never reused. Reservation
inserts `Pending` and pins the exact live file inode before any external
backing work. A non-copyable, non-cloneable opaque token is authenticated to
the unique connection key, node, and raw handle; only that token can atomically
abort the pending entry or activate it. The public typed handle carries the
same connection brand but redacts it from diagnostics, while fixed slots retain
only the raw integer. A worker routes a raw FUSE `fh` to its authoritative
connection table and resolves it there; only an existing active slot becomes a
branded handle. Pending raw values remain non-visible. Active lookup and
release reject a handle branded by another conforming connection even when its
raw integer is identical. Directories and symlinks are rejected by this
file-open path. Active lookup exposes only portable inode attributes, not an OS
descriptor. `RELEASE` consumes an active handle exactly once; stale, double,
pending-as-active, wrong-connection, and forged-token transitions fail closed.

A node whose lookup count reaches zero remains pinned while any pending or
active open refers to it. Aborting a pending open or releasing an active open
reaps the node only when both lookup references and open pins are zero. Open
table growth and tombstone compaction pre-admit retained plus replacement slot
capacity and commit only after allocation succeeds. A zero handle ceiling
explicitly disables opens while retaining lookup/getattr service. Losing a
pending reservation token deliberately does not run implicit rollback: it
leaves a bounded fail-closed pin until connection teardown. The future FUSE
worker must abort the whole connection whenever it cannot determine whether an
open reply became visible to the kernel; guessing release versus retry could
either leak backing authority or double-release it. The implementation creates
no heap object or protobuf object per path at mount time; memory grows only
with the bounded touched set.

The index is accepted only when its exact media type, encoded length, and digest
match an authenticated `ObjectDescriptor` obtained from the sealed publication.
The source tree descriptor, exact root directory descriptor, compiler ABI, and
closed tree-role feature set must also match that publication. A checksum stored
inside the candidate detects accidental payload corruption; because an attacker
can recompute it, it is never authority for publication or mapping.

The validator returns an artifact-bound, non-cloneable proof borrowing the
exact immutable bytes and retaining their authenticated descriptor, source
cross-links, and validated hard-link counts. A detached diagnostic summary is
not authority to serve or map another byte slice. Collection counts are checked
against remaining record bytes and decoded-memory admission before allocation.
The compiler's index and per-record limits are authoritative; a caller-provided
private staging capability may narrow those limits but cannot widen them.
V2 compilation pre-admits its contiguous fixed-size lookup build storage and
finish-time sorted table under both the index-output ceiling and the aggregate
graph working-memory ceiling. Allocation is fallible, and the aggregate charge
includes live graph queues, hard-link validation state, record scratch, lookup
storage, and vector container overhead.

The derived format may change between releases and is never the canonical tree.
Its descriptor may be signed as part of sealed publication, but that signature
authorizes only the exact derived bytes and their cross-links; it does not turn
the index into the portable source commitment.

The structural index retains portable UID/GID values and canonical ACL
qualifiers. It is therefore shareable by compatible consumers within the
authorized disclosure domain and does not acquire the identity of whichever
consumer caused it to be compiled first. Identity presentation is a separate,
exact translation plan bound to the consumer user namespace, its complete
UID/GID maps, and the negotiated ACL capability profile. A worker translates
owners and every named ACL qualifier through that plan without truncation; a
gap, overlap, or overflow rejects the attachment.

The translation component commits only the maps and ACL profile that determine
output bytes. The mount broker separately binds that plan to the pinned
consumer user-namespace identity and generation; a presentation-plan digest is
not namespace authority and cannot authorize connection reuse.

Translation may be performed on demand under the touched-node memory budget.
If measurement justifies a precompiled metadata sidecar, that sidecar is a
replaceable derived cache addressed by the source tree commitment, compiler
ABI, identity-map digest, and ACL capability profile. It is never part of the
portable tree commitment and cannot be shared by incompatible presentation
connections. This separation preserves structural-index and backing-inode
sharing without allowing one sandbox's ID map to contaminate another's
metadata.

## FUSE realization

The immutable FUSE worker implements the smallest semantic surface required by
the view:

- lookup and forget;
- getattr and optional xattr reads;
- readdir, preferably `READDIRPLUS` where measured beneficial;
- readlink;
- open and release; and
- non-passthrough read only as a bounded fallback when explicitly allowed.

V1 uses one FUSE connection per attachment. A process may supervise several
connections only after proving independent queue, memory, quota, abort, lease,
and error attribution; connection sharing is not the optimization default.

The v1 mount/init contract is `allow_other + default_permissions`; omitting
either is a hard failure. The mount broker accepts a connection only when its
mount user namespace is the consumer user namespace or a verified ancestor
and every presented UID, GID, and ACL qualifier maps without truncation. Until
idmapped FUSE is proven, the worker applies the connection's exact presentation
translation plan to the portable IDs in the structural index and creates a
separate presentation connection for incompatible maps. Unmappable identity
rejects the attachment rather than becoming `nobody` or host root.

The worker negotiates `FUSE_POSIX_ACL` only for a canonical ACL feature whose
kernel behavior passed the target-userns probe; otherwise ACL-bearing views are
rejected or materialized by a compatible backend. Kernel
`default_permissions`, including supplementary-group and capability checks,
enforces the presented DAC/ACL metadata before `open` reaches passthrough. AOS
authority is still attachment-wide and evaluated before lookup: mode bits are
not a substitute for view authorization, and sandbox root may exercise only
the DAC-bypass capabilities explicitly present in its payload profile.

Node ID 1 is the root. Other 64-bit node IDs are stable within the immutable
connection and are never reused until the connection is destroyed. The worker
stores checked lookup/open reference counts keyed by the semantic identity
(hard-link group or full path) and releases only after matching `FORGET` and
handle close events. A remounted connection may assign new IDs.

Per connection, separate hard admissions cover touched node records, lookup
references, open files/directories, backing registrations, in-flight requests,
kernel-advertised `max_background`, pending user queues, and worker heap/mmap
budgets. Compiler and validator admissions occur before object-sized allocation
or semantic decode and include the encoded candidate, decoded collection
ceiling, retained tree/root/features, queued paths and ancestors, hard-link
membership, and one encoded output record. A transport adapter exposes a
bounded stream and must not first allocate the whole object; the compiler owns
that allocation and verifies exact EOF and digest. Kernel dentry/inode
residency is observed and bounded indirectly by connection lifetime and TTL
policy; it is not mislabeled worker heap.

When a touched-node or reference admission is exhausted, a new lookup returns
`ENOMEM`, the attachment reports `ResourceExhausted`, and a required attachment
loses `ViewsReady`; policy may freeze the consumer before controlled remount.
The worker cannot evict a node while the kernel retains lookup references.
`READDIRPLUS` is adaptive and disabled for adversarial or high-fanout
directories when pre-instantiation would violate the touched-set budget.

Immutable entries receive long positive and negative cache lifetimes. A view
revision never mutates behind those cache entries. Updating an environment
creates a new revision and attachment switch.

Linux FUSE backing-file passthrough is required for executable package and
large-file views unless a measured capability profile explicitly permits the
slower read path. The worker obtains an authorized immutable backing handle;
the privileged broker registers it with the FUSE connection using
`FUSE_DEV_IOC_BACKING_OPEN`; and the open reply selects that backing ID. The
kernel then performs supported read, splice, and mmap operations against the
backing file. See the
[kernel FUSE passthrough documentation](https://docs.kernel.org/filesystems/fuse/fuse-passthrough.html).

Backing registration is per FUSE connection. Concurrent opens of one logical
inode coordinate one registration and retain it until the final associated
open releases. Userspace closes redundant descriptors promptly; it does not
retain one ordinary FD per open after the kernel owns the backing reference.

Before `FUSE_DEV_IOC_BACKING_OPEN`, the broker reserves one per-connection and
node registration slot and persists a `Pending` record binding connection
generation, attachment, logical inode, backing descriptor identity, and
operation nonce. It records the returned backing ID before acknowledging the
open. The final release consumes that ID exactly once through
`FUSE_DEV_IOC_BACKING_CLOSE`, then releases the reservation. Crash in an
ambiguous pending/close window, or loss of the authoritative
connection-generation mapping, aborts and remounts that connection; the broker
does not reconstruct ownership from cache paths or ordinary process FD tables.

Shared page cache follows the backing filesystem inode. FUSE presentation
inode numbers do not create sharing. Content that arrives in chunks or a
compressed NAR is verified and assembled once into a stable immutable backing
file before passthrough.

## Identity presentation

The native path uses idmapped mounts. The FUSE path must pass a kernel
conformance spike before relying on idmapped FUSE mounts. Until the kernel and
filesystem explicitly advertise the needed behavior, AOS creates separate
FUSE presentation connections for incompatible sandbox identity maps while
sharing the mapped structural index and immutable backing files within the
authorized disclosure domain.

The FUSE daemon returns the sandbox-visible metadata compiled for that
presentation. Mount-level `nosuid` and `nodev` remain mandatory. Views
containing executable package closures require explicit execute authority and
an integrity-verified immutable revision.

## Writable views

FUSE does not implement general shared writes in v1. Private CoW views use one
overlay layer over one immutable lower, or a native ZFS clone. Overlay chains
are never constructed from logical ancestry depth.

The writable upper is private and quota controlled. A shared cache file is
never hard-linked into a writable upper where chmod, chown, truncate, xattr, or
write operations could mutate the shared inode. Copy-up uses reflink or copy
when safe; publishable outputs are re-opened without symlink traversal,
validated, hashed, and promoted into an immutable store.

Whiteouts, opaque directories, redirect metadata, and metacopy behavior are
normalized into the portable delta schema before a snapshot is described as
portable.

## Live mutable sources

A native local view provides kernel coherence for rename, unlink, mmap, locks,
and metadata changes. A remote or synthesized live FUSE view would need a
precise generation/event protocol, invalidation on every cached semantic,
overflow recovery, lock ownership, and reconnect behavior. It is therefore
outside v1.

Remote inspection uses immutable revisions. A client may request a new
snapshot and atomically switch to it, but AOS does not label that process as a
coherent live filesystem.

## Failure and revocation

An unclean FUSE worker exit faults the connection and may surface `EIO`. The
node daemon reports the affected attachments, optionally freezes their
sandboxes, starts a new worker, and performs a controlled replacement. It does
not claim transparent preservation of open file descriptors.

Once the kernel has opened a passthrough backing file, later policy changes
cannot synchronously invalidate every existing descriptor and mapping. A hard
revocation stops the consuming sandbox. Passthrough is enabled only when the
authorization is valid for at least the attachment lease.

Namespace detach stops new path resolution but is not hard revocation. An
exclusive writable export cannot be considered revoked until its consumers are
stopped or every relevant open reference has been authoritatively drained.

FUSE workers, their executables, indexes, cache roots, logs, and control sockets
must never reside inside a filesystem they serve. Backing files on FUSE are
rejected to prevent recursive stacks and deadlocks.
