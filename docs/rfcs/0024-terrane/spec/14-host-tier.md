# 14 — Host tier

This file owns the node-local `disk` backend: the compressed chunk cache, the
sealed object directory that kernel surfaces read through, the networkless
publisher that alone may write to it, reassembly of chunks into whole files,
admission and eviction, pins and reservations, wipe-on-release for
erasure-sensitive content, verification and quarantine, the small embedded
state store, and crash recovery. It also defines how a filesystem-backed hot
tier sits beside a block-device capacity tier.

## Overview

A host tier is a cache with three shapes of content: compressed chunks laid
out exactly as a bucket would hold them, sealed whole files keyed by object
hash that the kernel can serve directly, and cached metadata (tree nodes,
indexes, filters). The first is what the network delivers; the second is
what surfaces need; the third is what makes lookups local.

Three properties distinguish a host tier from every other store. It is the
only tier where quotas are exact, because one process owns the bytes. It is
the only tier that hands out sealed backing objects to the kernel, so its
immutability guarantees are enforced by the kernel and not by convention.
And it never stores what a tier beneath it can serve, so nested tiers on one
machine hold one copy of each chunk between them.

## Layout

A host tier's durable state is a `file://` bucket
([`13-bucket-layout.md`](13-bucket-layout.md)) extended with these
registered prefixes:

```text
<root>/
  objects/pack/<aa>/<pack-id>.pack     cached packs (whole-pack fetches)
  objects/pack/<aa>/<pack-id>.idx
  objects/index/<generation>/...            cached merged shards and filters
  chunks/<aa>/<hash>.<codec>           cached individual chunk bodies
  sealed/<aa>/<object-hash>            sealed whole files, verity-enabled
  staging/<publisher-id>/...           publisher-private, never served
  quarantine/<hash>[.<incarnation>]    failed verification, awaiting scrub
  pending-delete/<hash>                two-phase delete, first phase
  state/                               embedded KV: pins, reservations, leases
```

- **[HOST-1]** A host tier MUST keep `chunks/`, `sealed/`, `staging/`,
  `quarantine/`, and `pending-delete/` on one filesystem that supports hard
  links and an immutability seal, and MUST refuse to open on a stacked or
  network filesystem for `sealed/`. *Gate:* `gate:host-layout`.
- **[HOST-2]** Bodies under `chunks/` MUST be byte-identical to the bodies a
  pack would hold for the same hash and codec, so that a chunk cached from a
  ranged read and a chunk extracted from a whole-pack fetch are the same
  file. *Gate:* `gate:host-chunk-layout`.

## Sealed object directory

The sealed object directory holds one whole, decompressed, verified file per
object hash. It is the data-only lower layer for the EROFS surface, the
backing inode for FUSE passthrough, and the directory a `shared-dir` tier
in a sandbox or guest views read-only
([`27-surface-fuse.md`](27-surface-fuse.md),
[`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md),
[`29-surface-vm.md`](29-surface-vm.md)).

- **[HOST-3]** A file under `sealed/` MUST be immutable by a kernel-enforced
  mechanism: fs-verity where the filesystem supports it, or an equivalent
  primitive that makes the inode's contents unmodifiable by any process
  including the owner. Read-only mode bits and ownership are defense in
  depth and MUST NOT be the only mechanism. *Gate:* `gate:host-sealed-immutable`.
- **[HOST-4]** Where fs-verity is used, the tier MUST record the verity
  digest beside the object hash in `state/` and MUST re-verify that binding
  when adopting a sealed file after restart. The two digest domains are not
  assumed equal. *Gate:* `gate:host-sealed-adopt`.
- **[HOST-5]** A sealed file MUST be eligible for passthrough or data-only
  lower use only after every writer descriptor is closed, the seal is
  enabled and verified, and the file has been published under its canonical
  name. A file in `staging/` MUST NEVER be handed to a surface.
  *Gate:* `gate:host-sealed-before-serve`.

### The publisher

Only one service identity may write into `sealed/`: the publisher. It has
no network access and receives content only as descriptors passed from the
tier's fetch and reassembly paths.

- **[HOST-6]** The publisher MUST be the sole owner of `sealed/` and MUST be
  the only process with write permission to it. Fetchers, reassemblers,
  surfaces, and sandboxes MUST NOT hold a writable descriptor to any sealed
  inode or write permission on the directory.
  *Gate:* `gate:host-publisher-sole-writer`.

  Publisher descriptor handoff uses PROTO-56 to PROTO-59. The publisher also
  owns namespace effects involving sealed files during quarantine,
  retirement, restoration and recovery. The cache owns pin and eviction
  decisions, retaining their exclusion until the native operation and its
  coordinated state transition actually complete. Other roles cannot mutate
  publisher-owned directories to implement HOST-28 or HOST-32.
- **[HOST-7]** Publication MUST follow this sequence: create a new inode
  under `staging/` owned by the publisher; copy or reflink the content from
  the passed descriptor; verify the written plaintext against the claimed
  content identity as specified below; close every writer; enable and
  verify the seal on the private inode; `fsync` it; link or rename it to its
  canonical name with no-replace semantics; `fsync` the parent directory;
  and only then durably record its verified binding in `state/`. Before
  canonical insertion, a failure MUST leave no canonical name created by
  that attempt. After insertion, a failure MUST NOT acknowledge publication
  or return a backing descriptor. The publisher MUST attempt to remove only
  its own newly inserted link, checking the directory-relative inode identity
  before removal, and synchronize the parent. If cleanup cannot
  be confirmed, it MUST withhold that object from service until recovery
  independently verifies the content claim and seal, synchronizes the file
  and parent, and durably records the binding. A mismatch with an existing
  recorded binding MUST be rejected and quarantined under HOST-4/32, rather
  than silently replacing that binding. Reconstruction under HOST-31 applies
  when the binding was lost, not when a conflicting binding is present.
  A preexisting canonical inode MUST NOT be removed or replaced by this
  cleanup.
  *Gate:* `gate:host-publish-sequence`.

  For an inline chunk, verification recomputes the registered chunk identity
  over the exact plaintext and checks inline eligibility under the active
  chunk profile. For a manifest-backed object, verification first checks
  the canonical manifest against its claimed identity under OBJ-4, then
  checks the exact assembled length, every ordered chunk identity and
  length, and the manifest's required whole-file content hashes. The
  manifest identity MUST NOT be recomputed over assembled plaintext.
  A one-chunk object that is not inline retains its manifest identity.
- **[HOST-8]** A reflink from staging is acceptable only when the source
  cannot be modified by any later writer and source and destination are in
  the same disclosure domain
  ([`24-disclosure-domains.md`](24-disclosure-domains.md)).
- **[HOST-9]** If a canonical name already exists at publication time, the
  publisher MUST verify the existing inode's seal and hash and MUST discard
  its own copy; it MUST NOT replace the existing inode.
  *Gate:* `gate:host-publish-no-replace`.

## Reassembly

An object spanning several chunks is served either from its chunks (each
decompressed on demand) or from one sealed whole file. The choice is the
reassembly mode, a property on the view's root
([`08-properties.md`](08-properties.md)).

| Mode | Behavior |
| --- | --- |
| `never` | Serve from chunk bodies only; never build a sealed whole file for a multi-chunk object. |
| `smart` | Build a sealed whole file when the heuristic below says so; otherwise serve from chunks. |
| `always` | Build a sealed whole file for every multi-chunk object on first open. |

- **[HOST-10]** In `smart` mode a tier MUST reassemble an object when any
  of: its chunk uniqueness ratio (chunks referenced by no other cached
  object divided by total chunks) is at or above 0.9; its size is at or
  above 16 MiB; or it was fully read by a previous consumer on this host.
  A tier MUST NOT reassemble an object smaller than 64 KiB in any mode
  other than `always`. *Gate:* `gate:host-reassembly-heuristic`.
- **[HOST-11]** Each chunk of a reassembled object MUST live in exactly one
  place on the tier: as a body under `chunks/` or as a byte range of the
  sealed file. On reassembly the tier MUST hard-link or record the range and
  MUST remove the standalone body. On eviction of a sealed file the tier
  MUST re-extract any chunk still referenced by another cached object before
  deleting it. *Gate:* `gate:host-single-residence`.
- **[HOST-12]** Single-chunk objects MUST be sealed by decompressing the
  chunk directly to a staged file; no reassembly step exists for them.
- **[HOST-13]** Reassembly MUST verify the assembled file against its
  independently verified canonical manifest before publication, using
  HOST-7's ordered chunk, length and whole-file hash checks even when every
  input chunk was already verified. The object identity remains the hash of
  the canonical manifest under OBJ-4, rather than a hash of the assembled
  plaintext, because chunk order and the manifest are inputs too.
  *Gate:* `gate:host-reassembly-verify`.

## Admission and verification

- **[HOST-14]** Every body fetched from any lower tier MUST be verified
  before it is admitted: decompressed under the decompression-bomb cap of
  [`05-chunking.md`](05-chunking.md), hashed, and compared to its claimed
  identity. Bytes MUST be written to a temporary name, synced, and renamed
  into place after verification. A tier MUST NOT serve a body it has not
  verified, and MUST NOT serve a body once and verify later.
  *Gate:* `gate:host-verify-before-admit`.
- **[HOST-15]** A body that fails verification on admission MUST be
  discarded and the fetch retried from the next tier; a body found corrupt
  on a later read MUST be moved to `quarantine/`, reported, and refetched.
  Quarantined bytes MUST be kept until scrub confirms a good copy exists
  elsewhere or the quarantine retention expires.
  *Gate:* `gate:host-quarantine`.
- **[HOST-16]** Bystander bodies ([PACK-28]) MAY be admitted after
  verification but MUST enter the probationary queue unpinned.

## Eviction

A host tier is size-bounded. It evicts by an S3-FIFO policy with a
probationary queue, never evicts pinned content, and reserves before it
admits.

- **[HOST-17]** Eviction MUST be S3-FIFO: newly admitted content enters a
  small probationary FIFO (RECOMMENDED 10% of capacity); content read again
  while probationary is promoted to the main FIFO; content that leaves the
  probationary FIFO unread is evicted first. The main FIFO MUST reinsert
  content read since its last pass rather than evicting it.
  *Gate:* `gate:host-eviction-s3fifo`.
- **[HOST-18]** Pinned content MUST NOT be evicted. On release of a pin the
  content MUST remain protected for a release grace period (RECOMMENDED
  5 minutes) so that a consumer that immediately re-pins pays nothing.
  *Gate:* `gate:host-pin-never-evicted`.
- **[HOST-19]** Before admitting content the tier MUST reserve its size.
  If the reservation would exceed the high watermark the tier MUST evict
  down to the low watermark (RECOMMENDED 85% of capacity) first, retrying
  a bounded number of times, and MUST fail the admission with `capacity` if
  it cannot. Serving from a lower tier without admission MUST remain
  possible when admission fails. *Gate:* `gate:host-reserve-then-evict`.
- **[HOST-20]** A tier MUST account chunk bodies, sealed files, cached
  packs, and cached metadata against one capacity, with sealed files
  counted once regardless of hard-link count.
- **[HOST-21]** Cached whole packs under `objects/pack/` MUST be evictable
  as units and MUST be counted; a tier SHOULD extract still-referenced
  bodies into `chunks/` before evicting a pack.

## Pins, reservations, and quotas

- **[HOST-22]** A pin MUST name a set of object or chunk hashes, an owner
  (a lease or an exposure), and an expiry. Pins MUST be durable across a
  tier restart. Pin increments MUST be synced before the pin is
  acknowledged; decrements MAY be deferred, since a lost decrement only
  over-protects. *Gate:* `gate:host-pin-durable`.
- **[HOST-23]** Reservations and quotas on a host tier MUST be exact: the
  tier MUST distinguish synchronized allocated inode blocks, kernel charged
  and reserved quota usage, and admission holds for future allocation. It
  MUST NOT present a logical length, policy hold or kernel reservation as
  measured physical allocation. The native owner MUST measure allocation
  after synchronization at serialized admission, completion and recovery
  boundaries, retaining custody of in-flight allocation between them. Each
  inode MUST have one stable charge owner and be counted once regardless of
  links or pins. An unlinked inode retained by an operation remains charged
  until actual descriptor closure and confirmed cleanup.

  The tier MUST enforce a per-owner quota where one is set, using filesystem
  project quotas where the filesystem provides them. A privileged host
  provisions finite project hard limits and inheriting roots, including
  scratch, publication, seal metadata, state, quarantine and recovery
  allocations. Their sum MUST NOT exceed the configured tier quota-charge
  budget; project quotas MUST NOT be assumed to supply hierarchical limits.
  Project assignments MUST preserve an inode's charge owner across required
  link and rename operations, including publication, quarantine and recovery;
  changing its owner is not a recovery mechanism.
  Ordinary allocation-capable roles and their descendants MUST be prevented
  by the kernel from changing project assignments or inheritance. Inode
  ownership, absent administrative capabilities, advisory locks and periodic
  rechecks alone MUST NOT be treated as that prevention. A native role using
  process confinement MUST establish it before mutable cache operations,
  cover every thread and descendant, and deny equivalent setter entry points
  and unsupported syscall ABIs. It MUST fail startup closed when the required
  confinement cannot be established. The trusted host MUST isolate writable
  role identities from unconfined actors and descriptor or process-control
  access that could bypass this boundary. Privileged provisioning remains a
  separate host administrative operation, outside these ordinary roles.
  Where kernel queries require privilege, unprivileged roles MUST verify
  actual enforcement and usage through PROTO-60. Unknown coverage, ownership,
  domain binding or enforcement MUST fail admission closed. A reservation
  MUST cover the simultaneous source, assembly and publisher-copy lifetime;
  it is not a guarantee that allocation or sealing will succeed. This is the
  one place where exact quota enforcement is a requirement rather than a goal
  ([`08-properties.md`](08-properties.md)).
  *Gate:* `gate:host-quota-exact`.
- **[HOST-24]** A pin whose owner's lease has expired MUST be released by a
  periodic sweep and MUST NOT block eviction beyond the release grace.

## Wipe on release

Some disclosure domains require that content be unrecoverable from the
host once no consumer holds it. The `wipe` property selects the strategy.

| Strategy | Behavior on last release |
| --- | --- |
| `none` | Ordinary eviction: the file is unlinked and its bytes remain until reused. |
| `zero` | Overwrite the file's blocks with zeros before unlinking; unavailable for kernel-sealed tiers. |
| `discard` | Issue a discard (trim, unmap) for the file's extents, then unlink. |
| `volatile` | Content for this domain is held on a memory-backed filesystem and never touches persistent storage. |

- **[HOST-25]** Content in a domain with `wipe` other than `none` MUST
  bypass the eviction queues and MUST be wiped as soon as its last pin is
  released and the release grace has elapsed; it MUST NOT be retained as an
  unpinned cache entry. A tier using HOST-3's permanent kernel seal MUST reject
  `wipe=zero` during configuration validation, before opening the domain or
  admitting its content. Unlinking or replacing the sealed inode MUST NOT be
  reported as overwriting it. Zero-wipe is available only on a backend that
  can actually overwrite the protected data; it does not relax HOST-3 for
  `sealed/`. *Gate:* `gate:host-wipe-on-release`.
- **[HOST-26]** In `volatile` mode the tier MUST place `chunks/` and `sealed/`
  for that domain on a memory-backed filesystem that supports the seal
  primitive, and MUST refuse the domain if none is available.
- **[HOST-27]** Sealed files MUST NOT be shared across domains with
  different `wipe` strategies; deduplication across such domains is
  disabled ([`24-disclosure-domains.md`](24-disclosure-domains.md)).

## Two-phase delete

- **[HOST-28]** Deletion of any cached body or sealed file MUST be two
  phase: first a rename into `pending-delete/`, then unlink after a bounded
  interval. A pin or read that arrives during the interval MUST restore the
  file to its canonical name. *Gate:* `gate:host-two-phase-delete`.

  Pending names retain the registered `pending-delete/<hash>` grammar.
  Chunk bodies and sealed files use their existing claimed chunk or manifest
  digest. Pack and detached-index files use the existing domain-separated
  content digest of their exact encoded bytes. These are pending namespace
  names, not replacements for the random pack ID or canonical pack/index keys.
  Every insertion MUST use no-replace semantics. An occupied name leaves the
  losing inode canonical, under retirement exclusion until retry or recovery;
  codec variants and an inline sealed file can legitimately share a digest.

  Retirement deadlines MUST be durable leases within HOST-29's state scope
  before acknowledgment. State loss MUST reconstruct a conservative bounded
  deadline before removal; it MUST NOT treat an unknown deadline as expired.
  Recovery MUST distinguish actual sealed inodes from encoded chunk bodies
  and validate the corresponding claims. A manifest identity MUST NOT be
  reconstructed by hashing assembled plaintext.

  A pack and its detached index MUST be reconciled as one retirement unit,
  including a crash with one pending and the other canonical. Recovery uses
  their existing shared header pack ID. It MUST reconcile both namespaces
  before restoring service or completing deletion. A missing index MAY be
  reconstructed from a verified pack under PACK-15/16; a surviving index
  alone MUST NOT establish the presence or validity of missing pack bytes.

## Embedded state

A host tier keeps a small embedded key-value store under `state/` for what
cannot be reconstructed from the filesystem alone.

- **[HOST-29]** The embedded store MUST hold only pins, reservations,
  leases, verity bindings, project-quota assignments, and the chunk-to-file
  residence map for reassembled objects. It MUST NOT hold the chunk index,
  tree nodes, or anything consulted on the read path of an already-sealed
  object. Reconstruction manifests MUST remain ordinary verified immutable
  cached metadata outside `state/`; they MUST NOT be copied into the
  embedded store. *Gate:* `gate:host-state-scope`.
- **[HOST-30]** A read of a sealed object MUST NOT take a lock in the
  embedded store. A stalled embedded-store writer MUST NOT stall passthrough
  reads.
- **[HOST-31]** The embedded store MUST be rebuildable from the filesystem.
  Before publishing a manifest-backed sealed file, the tier MUST durably
  retain its verified canonical manifest in ordinary cached metadata packs
  under the existing bucket layout, syncing the pack, index and containing
  directories. That metadata MUST remain available until the dependent
  sealed file is durably retired; relocation MUST durably publish verified
  replacement metadata before retiring the previous copy. On state loss,
  the tier MUST reconstruct residence and verity bindings by scanning
  `sealed/`, `chunks/`, and these cached metadata packs, verifying manifest
  identities, ordered chunk ranges, whole-file hashes and kernel seals.
  A file whose required metadata is missing or invalid MUST NOT be adopted
  or served until the metadata is recovered and verified. Reconstruction
  MUST precede eviction, including eviction of reconstruction metadata.
  Every pin MUST be treated as released (over-evict, never under-protect a
  live consumer beyond the release grace).

## Crash recovery

- **[HOST-32]** On start a tier MUST: remove every temporary file in
  `chunks/`, `sealed/`, and `staging/`; move any unsealed file found under a
  canonical `sealed/` name to `quarantine/`; re-verify the seal and hash
  binding of every sealed file it adopts, or adopt lazily on first open and
  quarantine on mismatch; and reconcile `pending-delete/` by completing
  deletes whose interval has passed. *Gate:* `gate:host-crash-recovery`.
- **[HOST-33]** A tier MUST NOT serve any file it has not adopted under
  [HOST-32].
- **[HOST-34]** Exposures that were active before a crash are not resumed;
  their upper layers are retained under their owner's lease for the owning
  surface to recover ([`20-consistency.md`](20-consistency.md)), and their
  pins persist per [HOST-22].

## Circuit breaking and degraded operation

- **[HOST-35]** A tier MUST keep serving resident content when every lower
  tier is unavailable, and MUST fail a miss with `unavailable` after a
  bounded deadline rather than blocking indefinitely.
- **[HOST-36]** A tier MUST open a circuit breaker toward a lower tier after
  a bounded number of consecutive failures and probe it on a bounded
  interval; while open, requests MUST route to other tiers where any exist.

## Hot tier beside a capacity tier

A `blockdev` tier ([`16-blockdev-backend.md`](16-blockdev-backend.md)) has
no inodes and cannot hand out sealed files. The RECOMMENDED shape is:

```text
routed[
  disk(/var/lib/terrane/hot, capacity=small),
  blockdev(/dev/nvme0n1, /dev/nvme1n1),
  remote(...),
]
```

- **[HOST-37]** When a `disk` tier sits above a `blockdev` tier, sealed
  files for the hot set MUST be built in the `disk` tier from bodies served
  by the `blockdev` tier, and the `disk` tier MUST NOT re-cache the
  compressed bodies it can read from the `blockdev` tier below it
  ([STORE-14]'s no-duplication rule applied across local tiers).

## Interactions

- [`05-chunking.md`](05-chunking.md) supplies the decompression-bomb cap and
  codecs used on admission.
- [`08-properties.md`](08-properties.md) defines the `reassembly`, `wipe`,
  and quota properties that this tier reads from a view's root.
- [`11-store-trait.md`](11-store-trait.md) defines `disk`, `shared-dir`, and
  the `cache` combinator that applies this file's eviction rules.
- [`12-pack-format.md`](12-pack-format.md) defines the bodies cached here
  and the bystander rule.
- [`13-bucket-layout.md`](13-bucket-layout.md) is the base layout this tier
  extends.
- [`16-blockdev-backend.md`](16-blockdev-backend.md) is the capacity tier a
  hot `disk` tier fronts.
- [`20-consistency.md`](20-consistency.md) owns upper layers and lease
  recovery.
- [`24-disclosure-domains.md`](24-disclosure-domains.md) governs which
  sealed files may be shared and which must be wiped.
- [`27-surface-fuse.md`](27-surface-fuse.md),
  [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md), and
  [`29-surface-vm.md`](29-surface-vm.md) consume sealed files.

## Informative: why one sealed inode per object

Every kernel surface that avoids copying (FUSE passthrough, overlayfs
data-only lower layers, virtiofs with DAX) keys the page cache on the
backing inode. One sealed inode per object hash means every sandbox, every
guest, and every mount on the host that reads the same object shares one
set of pages, and the kernel decides eviction with full knowledge of
demand. Building that inode once, sealing it, and never letting any
consumer hold a writable descriptor is what makes sharing it across trust
boundaries safe. See [`39-decision-register.md`](39-decision-register.md)
for the decision to require a kernel-enforced seal rather than mode bits.
