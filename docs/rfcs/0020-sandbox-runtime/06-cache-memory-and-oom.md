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
equal. Strict domains use different backing-filesystem cache identities and
independently authorized fetches. They prohibit cross-domain clones, reflinks,
block deduplication, and shared ZFS origin/ARC identities even when directory
inodes differ. A backend that cannot prove its page-cache/ARC key isolation
uses separate datasets, filesystems, or pools, disables data caching for that
profile, or rejects strict placement.

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
reserve -> fetch/write private inode -> verify -> close writers -> seal
        -> fsync inode -> publish no-replace -> fsync final parent
        -> commit catalog -> pin or admit -> release reservation
```

Verification covers algorithm-tagged digest, exact size, expected media type,
tree relationship where applicable, and source authorization. Published
backing files are opened read-only for passthrough and cannot be mutated by a
sandbox.

The producer never renames its own inode into the committed store. It closes
writers and passes a staging descriptor; the publisher creates a new inode
beneath a root writable only by the publisher identity, copies or safely
reflinks only within one cache-isolation domain, verifies the completed
destination, closes every writer, then
enables and verifies fs-verity while the inode still has only its private name.
Only that sealed inode is linked or renamed without replacement to the
canonical name; the catalog binds its fs-verity measurement separately to the
AOS object descriptor. The publisher fsyncs the final parent and commits
catalog state afterward. Recovery adopts a final name only after re-verifying
exact content and seal, otherwise quarantining it. A ZFS backend likewise
publishes only an already-created, held, read-only snapshot GUID. Source
adapters, viewd, FUSE
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

### Publisher authority

The content publisher is an unprivileged, domain-scoped service, not another
assignment-bound privileged broker. It must operate for a project that has no
running sandbox. The initial service scope is one configured project domain;
public publication requires a separate promotion decision and cannot be inferred
from permission to read or publish inside a project. No fictitious sandbox,
assignment epoch, or ownership lease is used to fit an existing broker plan.

A distinct versioned publisher-domain plan binds the configured publisher
principal, instance and node; project and exact cache/isolation-policy domain;
holder and authenticated channel; complete content descriptor and source
authorization commitment; policy, controller-authority and revocation
generations; root-registry generation; operation/reservation identities and
limits; request commitment; validity interval; and required features. It uses a
dedicated signature purpose and protocol/media-type registration. Existing
broker encodings remain unchanged and reject publisher messages. Local peer
credentials identify a configured channel, not project authority; a future
remote transport supplies authenticated principal and possession/channel binding.

The first authority path is online. Before admission the publisher sends the
controller a fresh challenge bound to its service incarnation and exact request.
The controller evaluates capability, policy, source authorization and reservation
state, then signs a challenge-bound decision. Canonical naming/catalog completion
requires a fresh, exact-operation completion permit for the same immutable plan.
The permit also binds the prepared artifact/seal commitment, root generation,
reservation, and live publisher incarnation. Issuance and revocation initiation
are serialized by the controller.

The holder's authenticated channel and the publisher's controller connection
are distinct. In the first service flow, the live publisher registers its
fresh challenge and exact request commitment over its own authenticated
controller connection. The holder then presents that exact request over an
independently authenticated holder-to-controller channel. The controller joins
the two records, authenticates the claimed holder/channel against the observed
holder session, and resolves the capability, cache resource, source evidence,
policy, and reservation from protected current state before deciding admission.
Publisher peer credentials cannot authenticate the holder, and forwarding a
channel hash is not proof of possession. A future delegated or remote flow
must provide an explicit authenticated delegation/attestation contract rather
than silently reinterpreting one channel binding as the other. Challenge
registration itself grants no publication authority and consumes bounded
per-publisher pending-state capacity.

Capability lookup uses the controller's sole protected journal writer. An
administrative installation binds a fresh handle to the complete validated
capability record; individual revocation retains a tombstone and never permits
that handle to be rebound. This registry is not a bearer-token validator or a
public issuance endpoint. Its caller must authorize administration, and admission
must still authenticate the holder and evaluate current policy, scope-generation,
source, and resource state. Revoking a handle denies new use; it does not cancel
an already-issued retained completion permit.

Authority reads fail closed after an ambiguous journal append or synchronization
failure, even if the previous materialized values remain available for diagnostics.
Dropping and recreating a registry facade cannot restore authority; reopening and
replaying the protected journal is required. Replay and serialization have explicit
record, entry, and aggregate bounds. Tombstones consume no additional logical
record capacity, but the service must separately retain durable transaction space
for revocation and completion before admitting new work. Namespace-local journal
records are an internal persistence format, not a portable protocol or a substitute
for failover replication and rollback protection.

Version 1 uses retained controller-owned permits, not a timed completion window:
a pre-syscall clock check cannot bound an already-entered rename or fsync.
The controller durably records the one-shot permit before issuing it. It remains
valid only for that exact authorized completion across controller loss or later
admission expiry; it cannot authorize another object, operation, incarnation,
domain, or reservation. Revocation remains pending for the outstanding effect.

Controller loss or admission expiry denies new admissions and new permits, not
the exact completion already permitted. Publisher restart cannot replay an old
permit as authority: online reconciliation must establish the old executor's
fencing/quiescence and authorize the recovery incarnation. Controller failover
must preserve outstanding permit state rather than mint conflicting authority.
Neither an abort request nor an acknowledgment frees a permit or reservation
while an old executor can still finish an in-flight effect. Private and uncertain
artifacts remain charged until authority-bound reconciliation establishes the
terminal result. A stuck executor may therefore delay revocation; the API must
not promise an unsupported bounded revocation latency.
Completion converts reserved capacity into committed residency charges rather
than freeing occupied capacity. Lost replies and receipt replay are idempotent:
they cannot create another permit or release capacity twice. A recovery decision
may finish or reconcile an existing irrevocable obligation, not manufacture a
new publication grant from revoked authority.

Canonical-name existence is internal storage state, not consumer visibility.
Readers and the mount broker still require committed catalog state and their
own current disclosure authorization; they never infer publication from a path.
The journal retains decisions and exact recovery evidence, not an `authorized`
boolean. Capability-record construction is not authentication, a producer
signature is not publication permission, and an arbitrary caller-supplied
generation is not an online controller decision.

## Reservations, pins, and residency

These concepts remain separate:

- reservation: capacity promised to an operation before allocation;
- pin: an active correctness dependency that makes an object ineligible for
  eviction;
- residency: bytes currently present and reusable after the last pin; and
- popularity: advisory evidence used to order unpinned eviction.

The expiring attachment/source authorization lease is also separate from a
kernel-reference pin. Lease expiry denies new lookup/open and starts drain, but
a passthrough registration, mmap, open file, or retained FUSE lookup holds a
non-expiring kernel pin until the reference closes or the connection/consumer
is authoritatively aborted. Unlinking an inode does not release or credit its
physical bytes while such a reference exists.

A valid attachment lease admits creation of the minimum metadata and kernel
pins needed to honor active opens; expiry does not erase pins already held.
Lazy views need not reserve an unknowable complete closure; they use a hard
on-demand byte window. A request unable to reserve within that window receives
resource exhaustion before allocating or fetching.

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
  ├─ aos-storaged.service
  ├─ aos-mountd.service
  └─ aos-netd.service

aos-assignment-guardians.slice
  └─ lease-guard-<incarnation>.service CLOCK_BOOTTIME fail-stop owner
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

### Residency enforcement profiles

The node reports and admits one explicit residency profile rather than
pretending the logical fair-share ledger changes kernel charging:

- `payload-page-cache`: ordinary backing pages follow kernel first-touch memcg
  charging and reclaim; a sandbox can be charged for a page later reused by a
  peer, so equal physical attribution is not promised;
- `domain-service-residency`: non-passthrough reads and buffers are charged to
  a disclosure-domain view-service cgroup with a hard service bound;
- `node-global-arc`: ZFS ARC is bounded and admitted at node scope, with no
  per-sandbox hard ARC share; and
- `hard-isolated-residency`: a proven separate cache identity and enforcement
  mechanism supplies the requested tenant/domain bound.

The default shared immutable passthrough profile promises node-bounded
residency plus logical per-consumer reservations, not fair physical memcg
charging. A policy requiring hard isolated residency selects the last profile
or fails placement. Passthrough scans reserve a bounded declared read-working
set or closure window before admission. ZFS profiles select and report
`primarycache=metadata` or `primarycache=all` from measurement; they never
silently rely on ARC outside the advertised profile.

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

Every authorization lease and associated kernel pin carries view UID,
attachment UID, sandbox incarnation, assignment epoch, and authority scope.
The lease has a deadline; the kernel pin does not. Reconciliation releases a
leaked kernel pin only after proving the corresponding incarnation or
attachment is absent and every open, mapping, lookup reference, and backing
registration is closed or authoritatively aborted. Lease expiry starts that
drain and makes only objects with zero kernel references evictable. Physical
space is not credited until the backing filesystem reports it reclaimable.

Snapshot manifests contain content identities and view revisions, not a promise
that the node cache remains warm. Cache residency improves restore latency but
is never necessary for snapshot correctness.
