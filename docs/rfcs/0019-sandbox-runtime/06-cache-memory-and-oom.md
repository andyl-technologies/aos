# Cache, memory, OOM, and capacity

## Cache layers

The view service distinguishes four forms of cached state:

1. portable tree and source metadata;
2. node-local mapped structural indexes;
3. compressed or chunked transfer objects; and
4. verified contiguous backing files used for passthrough.

Kernel page cache over backing files is an additional physical residency layer
managed by the kernel. It is observed but not represented as durable cache
truth.

The existing `aos-cache` crate remains the Nix-compatible transfer client. The
node residency engine is new because it needs mount leases, pins, reservations,
disclosure partitions, eviction races, backing-file identity, and crash
reconciliation that a remote cache client does not provide.

## Disclosure and sharing domains

A cache object belongs to one disclosure domain:

- public verified content;
- project;
- explicitly configured trust group; or
- private sandbox.

The domain controls physical on-disk reuse, backing inode reuse, page-cache
sharing, fetch coalescing, metadata caches, and access-profile learning.
Sharing a digest across domains is not allowed merely because the bytes compare
equal. Strict domains use different backing inodes and independently authorized
fetches.

Shared cache residency exposes timing and presence signals. Public and
same-project sharing accept that trade; strict isolation does not. The API and
status report the selected domain rather than presenting sharing as an
implementation accident.

Authorization precedes every cache lookup. Negative and positive cache results
are keyed by authority scope and policy revision where their observation could
otherwise disclose another principal's state.

## Immutable publication

Shared objects enter through a transaction owned by the isolated publisher:

```text
reserve -> fetch/write private temporary -> verify -> fsync
        -> atomically publish immutable -> pin or admit -> release reservation
```

Verification covers algorithm-tagged digest, exact size, expected media type,
tree relationship where applicable, and source authorization. Published
backing files are opened read-only for passthrough and cannot be mutated by a
sandbox.

The producer never renames its own inode into the committed store. It closes
writers and passes a staging descriptor; the publisher creates a new inode
beneath a root writable only by the publisher identity, copies or safely
reflinks, verifies the completed destination, fsyncs it and its parent, and
publishes without replacement. It then enables and verifies fs-verity on a
supported cache filesystem or publishes from a read-only ZFS snapshot
generation before issuing a backing handle. Source adapters, viewd, FUSE
workers, and sandboxes never receive a writable committed descriptor. The same
transaction publishes portable metadata and mmap indexes. Read-only mode bits,
rename, ownership, and the absence of a known writer alone are not treated as
immutability.

An unrestricted shared writable directory is not a cache primitive. Tools that
expect mutable caches receive one of:

- a private cache with later immutable publication;
- a project-scoped transactional cache service;
- a protocol-specific service that owns locking and atomic updates; or
- an explicitly trusted shared-write view with coherency outside this RFC's
  default guarantees.

## Reservations, pins, and residency

These concepts remain separate:

- reservation: capacity promised to an operation before allocation;
- pin: an active correctness dependency that makes an object ineligible for
  eviction;
- residency: bytes currently present and reusable after the last pin; and
- popularity: advisory evidence used to order unpinned eviction.

An attachment lease pins the minimum metadata and backing objects needed to
honor active opens. Lazy views need not reserve an unknowable complete closure;
they use a hard on-demand byte window. A request unable to reserve within that
window receives resource exhaustion before allocating or fetching.

Reservations are charged in one transaction with pin changes. Eviction cannot
select an entry between a lookup and its pin. A crash between reservation and
publication is recovered from durable operation state and temporary-file
identity.

Node residency pins are distinct from source-retention guarantees. An active
lazy view must retain or lease its immutable source revision at the
authoritative content service even when a particular node has not fetched all
of its bytes. Evicting a local un-opened object is safe only while that upstream
revision can still satisfy the view's lease.

## Admission and eviction

Admission uses high- and low-water marks plus an explicit reserve-then-evict
transaction:

1. reserve the operation's worst-case bounded bytes;
2. if the high-water mark would be crossed, freeze candidate selection;
3. select only unpinned entries within the caller's permitted partition;
4. rename candidates into a deleting state under the cache transaction;
5. recheck pins and restore any raced candidate;
6. unlink outside the metadata lock;
7. finish publication; and
8. release unused reservation.

Failure to find enough evictable space returns resource exhaustion. It never
evicts a pinned object, crosses a disclosure domain, or silently stores the
object in memory.

Eviction is not secure erasure. Confidential data uses a private encrypted
domain or memory-backed secret projection with a separately documented
destruction policy. CoW snapshots and SSD behavior preclude an overwrite claim.

## Memory model

The service accounts independently for:

- language-runtime heap;
- touched FUSE inode state;
- mapped index virtual and resident bytes;
- source manifests and compiled policy;
- request queues;
- compressed input buffers;
- decompressed buffers;
- backing-file reassembly;
- speculative prefetch;
- tmpfs and memory-backed writable layers;
- open descriptors and backing registrations;
- kernel page-cache observations;
- ZFS ARC size, hit/miss, metadata, dirty, and reclaim observations; and
- Nix builders, Git exchange, snapshot, publisher, and network-broker
  operation scopes outside the payload.

Dominant variable-sized buffers and retained objects acquire conservative byte
permits before allocation. Fetch concurrency is therefore derived from
remaining bytes, not only a task count. Parser overhead, allocator metadata,
mmap faults, and kernel page cache are not exactly predictable; strict decoder
limits and the service cgroup remain backstops. Streaming decoders use bounded
windows and never collect an entire closure of messages before index
construction.

Mapped immutable indexes are preferred to closure-sized heap graphs. Their
resident pages are reclaimable, but mapped address size, file size, and touched
working set remain bounded and reported. FUSE inode caches follow kernel lookup
references and `FORGET`; they also have an emergency ceiling that can reject new
lookups rather than OOM the node.

## Cgroup layout

```text
aos-sandboxes.slice
  └─ aos-sandbox-<incarnation>.service workload memory/CPU/PIDs/I/O

aos-view-services.slice
  ├─ view-worker-<generation>.service FUSE critical path
  ├─ view-fetch-<operation>.scope      bounded fetch/decompression
  └─ view-maintenance.service         eviction/scrub, lowest priority

aos-sandbox-operations.slice
  ├─ nix-build-<operation>.scope       project-attributed builders
  ├─ git-exchange-<operation>.scope    pack/upload/receive validation
  ├─ snapshot-<operation>.scope        bounded storage work
  └─ publish-<operation>.scope         staging/hash/seal work

aos-control.slice
  ├─ aos-sandboxd.service
  ├─ aos-viewd.service
  ├─ aos-view-publisher.service
  ├─ aos-sandbox-hostd.service
  ├─ aos-mountd.service
  └─ aos-netd.service
```

Names are illustrative node-local projections. FUSE workers are not children
of sandbox scopes because sandbox freeze or OOM must not freeze the server
handling its filesystem.

Sandbox units are flat beneath the slice. The logical ancestry tree can extend
across nodes and is not encoded as cgroup nesting. Each sandbox has
kernel-enforced hard limits; ancestor-wide limits are enforced by controller
reservations and admission plus explicit subtree operations. A future same-node
aggregate cgroup optimization cannot become the source of portable tree
semantics.

An ancestor's delegable envelope is inclusive: reserving a descendant maximum
subtracts it from the parent's remaining self/descendant budget. Admission
refuses a child if the parent cannot safely lower or reserve its own effective
limit. Each resulting sandbox cgroup enforces its assigned maximum, while the
controller ledger enforces the cross-node sum; the RFC does not mislabel that
ledger as one kernel aggregate cgroup.

Mount count is hard only because the default payload capability/seccomp
profile denies guest mount and namespace creation; nspawn's static mounts and
all dynamic broker mounts are admitted and counted. A profile that permits
guest mounts cannot advertise a hard mount-count ceiling without another
proven enforcement mechanism.

`LimitNOFILE` is per process rather than per sandbox. The hard conservative FD
envelope combines `TasksMax`, per-process `LimitNOFILE`, tighter execution
sub-limits, and service-side handle admission. FUSE passthrough backing
registrations are counted separately because kernel-held references are not
bounded by the registering process's ordinary FD limit.

Critical workers receive small explicit `MemoryMin` or equivalent protection
only after measurement. Fetch and speculative work are the first reclaim and
cancel targets. The node daemon and mount broker are bounded control services,
not unlimited OOM-immune processes.

Every out-of-payload operation receives CPU, memory, PID, I/O, network-byte,
log-byte, staging-byte, output-byte, concurrency, and deadline reservations
charged to its initiating sandbox/project. Nix builders are explicitly placed
in AOS-owned delegated operation cgroups; the design does not assume a Nix
`use-cgroups` default. Git pack generation, upload-pack/receive-pack, view
fetch/materialization, publisher hashing, and snapshot transfer follow the same
rule.

ZFS ARC is node-global and may duplicate or replace ordinary page-cache
behavior depending on the path. Nodes set and reserve a measured `zfs_arc_max`,
select dataset `primarycache` policy by workload, expose ARC pressure metrics,
and include ARC in node admission and recovery tests. A per-sandbox hard ARC
share is not claimed. Passthrough-on-ZFS profiles must measure double caching
and reclaim before enablement. Tuning and observation are pinned to the
[OpenZFS module-parameter contract](https://openzfs.github.io/openzfs-docs/Performance%20and%20Tuning/Module%20Parameters.html).

## OOM behavior

Workload OOM terminates the configured sandbox cgroup and reports a typed
execution failure. It does not release view pins until the runtime and every
open-handle dependency are reconciled.

Fetch/materialization OOM fails the operation and rolls back its reservation;
an existing mounted view may remain available for already resident content.

FUSE worker OOM faults its connection. The controller does not promise that
active opens survive. It reports affected attachments, prevents dependent
sandboxes from claiming healthy readiness, and performs freeze plus controlled
remount when policy permits.

Node-wide pressure first cancels speculative work, then evicts unpinned
residency, then refuses new admission. It must not create a positive feedback
loop in which remount attempts allocate more memory than the failed worker.

## Fairness and accounting

One physical shared object may serve many logical consumers, so physical bytes
cannot be charged wholly to whichever sandbox faulted the first page. AOS keeps:

- physical node accounting for admission and eviction;
- logical pins and reserved-byte accounting per sandbox/project;
- attributable network, decompression, staging, and publication work; and
- fair-share eviction pressure across disclosure domains.

Disk bytes, pins, registrations, and service-owned memory have hard limits.
Exact per-sandbox physical page-cache residency is an observation unless the
selected backing filesystem/kernel combination proves an enforceable charging
mechanism. In particular, phase 0 measures ZFS ARC and memcg behavior. A hard
residency profile uses a suitable backing filesystem or rejects placement; it
never reports an inferred proportional charge as enforcement.

No tenant can force another domain's recently used objects out by presenting a
large speculative prefetch. Advisory admission uses a separate probationary
queue and never evicts the proven foreground working set until policy permits.

## Cache lifecycle

Every pin carries view UID, attachment UID, sandbox incarnation, assignment
epoch, authority scope, and deadline. Reconciliation releases a leaked pin only
after proving the corresponding incarnation or attachment is absent and its
grace period expired. Expiry makes an object evictable; it does not require
immediate eviction unless the retention class says so.

Snapshot manifests contain content identities and view revisions, not a promise
that the node cache remains warm. Cache residency improves restore latency but
is never necessary for snapshot correctness.
