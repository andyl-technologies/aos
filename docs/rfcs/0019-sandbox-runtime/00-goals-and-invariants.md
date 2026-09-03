# Goals, non-goals, terminology, and invariants

## Goals

The design provides:

- lightweight disposable and durable Linux sandboxes with a workload-visible
  experience comparable to a Git worktree;
- pluggable runtime and storage backends without reducing the security contract
  to their lowest common denominator;
- explicit parent/child lineage, bounded delegation, and tree-wide inspection;
- fast local forks and snapshots with durable restore manifests;
- dynamic mount attachment to running sandboxes;
- a reusable virtual filesystem service for Nix closures, Git trees, package
  environments, filtered sources, snapshots, and future content sources;
- shared immutable build inputs and cache objects without a shared writable
  trust boundary;
- integration with per-project AOS/Nix development environments;
- a stable local and distributed control protocol; and
- a CLI suitable for humans, CI systems, and automation.

## Non-goals

The first implementation does not:

- promise a VM-strength boundary from a shared-kernel backend;
- run a nested nspawn manager inside each sandbox;
- expose arbitrary host paths or mount option strings to sandbox clients;
- provide a globally shared writable filesystem cache;
- claim synchronous revocation of already-open file descriptors or mappings;
- provide transparent live migration while native live-view edges exist;
- provide coherent live remote POSIX filesystems;
- preserve active TCP sessions, process memory, or open FUSE requests across a
  durable hibernation operation;
- make the node-local mount-broker protocol a public multi-machine standard;
- use Git worktrees as a security boundary; or
- make the NAR, Git, OCI, or runtime mmap representation the universal AOS tree
  format.

## Terminology

**Sandbox**
: A durable logical resource with identity, ancestry, desired configuration,
  policy, storage, attachments, snapshots, and zero or one active runtime
  incarnation.

**Incarnation**
: One concrete supervisor/unit realization of a sandbox runtime. Rebuilding
  the root, restoring a snapshot, moving nodes, or controller-driven runtime
  replacement creates a new unpredictable incarnation identifier. An internal
  guest reboot remains in the incarnation but advances its namespace
  generation.

**Generation**
: A monotonically increasing revision of desired state within an incarnation.
  Mutating requests use compare-and-swap against it.

**Assignment epoch**
: A monotonically fenced coordinator decision assigning an incarnation to a
  node. A node rejects mutations from older epochs.

**Export**
: A named resource a sandbox makes eligible for separately authorized viewing,
  such as `workspace`, `results`, or an immutable snapshot. The export name is
  not a host path.

**Filesystem view**
: A versioned logical namespace with defined consistency, metadata,
  authorization, sharing, and mutation semantics.

**View revision**
: An immutable description of one filesystem view. A live source changes by
  producing observations under a live consistency contract; an immutable view
  never changes in place.

**Attachment**
: A lease-bound mapping of one view revision or live export into one declared
  destination slot in a sandbox.

**Backing object**
: An immutable regular file used to serve view content. FUSE presentation inode
  identity is distinct from backing filesystem inode identity.

**Disclosure domain**
: The principals allowed to share physical cache objects, backing inodes, and
  timing/residency effects.

**Hard policy**
: A requirement whose enforcement failure prevents the sandbox or attachment
  from becoming ready.

**Advisory policy**
: A performance or telemetry preference that may be omitted with an explicit
  observed condition.

## Invariants

### Identity and fencing

- A sandbox UID is never reused for an unrelated logical sandbox.
- Every runtime-affecting operation names sandbox UID, desired generation, and
  assignment epoch. Operations on an active runtime also name its incarnation
  and payload namespace generation; create and hibernated restore instead name
  expected absence and the resource version.
- A stale assignment epoch or generation fails without side effects.
- Runtime PIDs are observations, never durable identity.
- A pidfd and verified cgroup membership pin the current payload before any
  namespace operation.

### Authority and delegation

- Effective authority is the intersection of node, site/project, ancestor, and
  request ceilings.
- A child capability is a strict attenuation of the delegable part of its
  parent capability.
- Child expiry cannot exceed any ancestor authority expiry.
- Parent ancestry alone grants no filesystem access.
- A cache hit, warm page, existing mount, or possession of a lease ID never
  substitutes for authorization.
- Authorization occurs before lookup, pinning, fetching, materialization, or
  attachment.

### Filesystems and mounts

- Public requests contain logical resource handles and declared destination
  slots, not host paths.
- The privileged broker resolves beneath pre-opened roots and attaches only to
  predeclared sandbox slots.
- Every shared byte object is immutable after verification and publication.
- Every writable upper, workspace, and staging tree is private to one sandbox
  or one explicitly transactional producer.
- Logical lineage does not imply overlay nesting. Filesystem stack depth is
  bounded independently of sandbox ancestry depth.
- FUSE-backed files never use another FUSE mount as their passthrough backing.
- Native live views and remote immutable views advertise different consistency
  capabilities.

### Resources and failure

- Hard limits use an explicit `inherit`, finite bound, or separately authorized
  `unlimited` value. Zero is never an implicit policy sentinel.
- Memory-backed filesystems consume memory policy as well as storage policy.
- Allocation, fetch, decompression, and materialization reserve byte budgets
  before work begins.
- Shared physical residency and logical consumer accounting are separate.
- A worker OOM cannot silently convert an attachment to a different backend or
  sharing mode.
- A sandbox cannot become `Ready` until all required policy, runtime, storage,
  and attachment enforcement is observed.

### Lifecycle

- Desired state is durable before node mutation begins.
- Cleanup compensates in reverse dependency order and is followed by durable
  reconciliation.
- Snapshot manifests include runtime configuration, storage snapshots, view
  revisions, attachments, policy revision, and external-dependency status.
- Restore creates a new incarnation and invalidates prior incarnation-bound
  capabilities.
- Lazy unmount is cleanup, not security revocation. Hard revocation stops the
  consuming sandbox.
- Deletion is topological and refuses live dependents unless an explicit
  cascade policy authorizes their stop and detachment.
