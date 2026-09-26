# 27 — Surface: FUSE

This file owns the FUSE surface: the realizer that presents a view as a
filesystem through the Linux FUSE interface, serves file bytes with kernel
passthrough where the kernel supports it, and provides a private writable
upper layer for exposures that commit. It is the lazy realizer: any tree of
any size can be mounted before a single object is fetched, and only what a
consumer touches is ever transferred. It covers the worker process model,
the structural index, passthrough, inode policy, the open path, the writable
upper, redirections, the control directory, mount options, leases, and
upgrades. The EROFS realizer for fully resident trees is in
[`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md); tier
behavior the surface relies on is in [`14-host-tier.md`](14-host-tier.md).

## Model

The FUSE surface is split across two processes on purpose. The **serve**
process holds the tiered store, the repository, and the exposure's token; it
has network access and talks to remote tiers. A **worker** process holds one
FUSE connection for one exposure; it has no network access, no store
credentials, and no path to a bucket. When a consumer opens a file whose
content is not yet resident, the worker asks the serve process for a
**backing handle**, the serve process fetches, verifies, assembles, and seals
the object into the host tier's object directory, and hands back an open
descriptor. From that point the kernel reads the file directly.

The worker's view of the tree is an mmap'd **structural index** compiled from
the tree's nodes: a flat, sorted, binary-searchable table. Lookup, `readdir`,
`getattr`, and `readlink` never touch the network and never allocate per
entry. Only `open` on a non-resident file crosses the process boundary.

Bytes are served through **FUSE passthrough** on kernels that support it
(Linux 6.9 and later, `FUSE_DEV_IOC_BACKING_OPEN`): the worker registers a
backing file once per inode and the kernel performs reads, `mmap`, and
`execve` against that inode without a round trip to userspace. Because every
exposure on the host registers the same sealed object for the same content,
the page cache holds one copy per object regardless of how many mounts
present it.

## Process model

- **[FUSE-1]** Each exposure MUST be served by its own worker process holding
  exactly one FUSE connection. A worker MUST NOT hold more than one
  connection. *Gate:* `gate:fuse-worker-isolation`.
- **[FUSE-2]** A worker MUST NOT have network access, MUST NOT hold any store
  credential, and MUST NOT be able to open the host tier's object directory
  for writing. A worker obtains file content only as descriptors passed from
  the serve process. *Gate:* `gate:fuse-worker-isolation`.
- **[FUSE-3]** The worker MUST request backing handles from the serve process
  over a local socket with descriptor passing. The request carries the
  exposure id, the entry's object hash, and the lease. The serve process MUST
  verify that the object hash is reachable from the exposure's served commit
  before returning a descriptor; a request for an object outside the view
  MUST be refused. *Gate:* `gate:fuse-object-scope`.
- **[FUSE-4]** A worker MUST run outside the resource-control and freezer
  domain of the consumers it serves. Freezing a consumer MUST NOT freeze the
  worker that serves its filesystem.
- **[FUSE-5]** A worker MUST have explicit memory, descriptor, task, and
  request-queue limits. Exceeding a limit MUST fault only that worker's
  exposure. Retained per-inode state MUST be bounded by the number of inodes
  the consumer has actually touched, not by the size of the tree.
- **[FUSE-6]** The serve process MUST supervise workers. A worker that exits
  MUST cause its exposure to enter a fault status; consumers observe `EIO`
  (or `ENOTCONN` for a torn-down connection) as recorded in
  [`reference/errno-mapping.md`](reference/errno-mapping.md).

## The structural index

The index is a compiled, read-only projection of the tree used by the worker.
It is content-addressed by the root hash and the index format version, so two
exposures of the same commit share one index file.

```text
Index file layout (little-endian):
  header      magic "TRIX", u16 version, u16 flags, u32 entry_count,
              u64 root_hash_offset, u64 path_arena_offset,
              u64 target_arena_offset, u64 hash_arena_offset,
              u64 entries_offset, u64 file_length
  path arena  concatenated path bytes (no separators)
  target      concatenated symlink targets
  hash arena  32-byte content hashes, deduplicated
  entries     fixed-width records sorted by path bytes:
              u64 path_off, u32 path_len, u8 kind, u8 flags,
              u16 reserved, u64 size, u64 content_off_or_hash_idx,
              u32 target_off, u32 target_len, u32 parent_idx,
              u32 first_child_idx, u32 child_count
```

- **[FUSE-7]** The serve process MUST compile a structural index from the
  tree's nodes for every distinct root hash it serves and MUST store it in
  the host tier keyed by `(root hash, index format version)`. Compilation
  MUST NOT fetch object content. *Gate:* `gate:fuse-index-roundtrip`.
- **[FUSE-8]** Path lookup in the index MUST be a binary search over the
  sorted entry table, and directory listing MUST be a contiguous scan from
  `first_child_idx` over `child_count` entries. Neither MAY require
  per-entry heap allocation.
- **[FUSE-9]** The worker MUST map the index read-only. The serve process
  MUST seal an index file (immutable, verified) before passing it to a
  worker, using the same sealing mechanism as objects
  ([`14-host-tier.md`](14-host-tier.md)).
- **[FUSE-10]** Index files are cache entries subject to the host tier's
  eviction with a separate size cap. An index in use by a live exposure MUST
  be pinned for the exposure's lease.
- **[FUSE-11]** For an entry whose content is an inline chunk hash, the index
  MUST record that hash; for an entry whose content is a manifest, the index
  MUST record the manifest hash and the logical size. Chunk ranges for a file
  are resolved from the manifest by the serve process at open time, not
  stored in the index.
- **[FUSE-12]** A `tree` entry ([`06-tree-format.md`](06-tree-format.md))
  MUST be compiled inline into the index as if its root's entries were
  children of the entry's path. The index records the grafted root hash so
  that property lookup ([`08-properties.md`](08-properties.md)) can find the
  governing root for any path.

## Passthrough

- **[FUSE-13]** On a kernel that supports FUSE passthrough, the worker MUST
  register one backing file per inode with `FUSE_DEV_IOC_BACKING_OPEN` at
  first open, retain the returned backing id under reference count, and
  return it in `FOPEN_PASSTHROUGH` on every open of that inode. The worker
  MUST close its own descriptor immediately after registration. *Gate:*
  `gate:fuse-passthrough`.
- **[FUSE-14]** The worker MUST release the backing id when the inode is
  forgotten by the kernel, not on each file close.
- **[FUSE-15]** On a kernel without passthrough, the worker MUST fall back to
  serving reads with `pread` on the sealed object and MUST set
  `FOPEN_KEEP_CACHE`. The exposure's status MUST report the degraded feature.
- **[FUSE-16]** The exposure option `passthrough` MUST accept `auto` (use if
  available), `require` (fail the exposure if unavailable), and `off`. The
  default is `auto`.
- **[FUSE-17]** A backing file MUST be a sealed object in the host tier's
  object directory, or a sealed reassembled file, or a file the serve process
  has verified against the entry's object hash. The worker MUST NOT register
  a file that is still being written.
- **[FUSE-18]** The mount MUST be created with `max_stack_depth` such that an
  overlay mounted above it does not exceed the kernel's stacking limit, and
  backing files MUST reside on a non-stacked filesystem.

## Inode policy

- **[FUSE-19]** The worker MUST present a stable 32-bit `st_ino` for every
  inode it has ever exposed on a given connection. Inode numbers MUST be
  allocated lazily at first lookup, MUST lie in `[16, 2^32 - 2]`, and MUST
  NOT be recycled while the connection lives. This allows tools compiled
  without large-file support to operate on the tree.
- **[FUSE-20]** The internal node identity used for kernel lookups MUST be
  derived from `(governing root hash, path)` and MUST NOT depend on the order
  in which paths were first accessed.
- **[FUSE-21]** Two paths that resolve to the same entry through hard-link
  identity ([`06-tree-format.md`](06-tree-format.md)) MUST present the same
  `st_ino` and `st_nlink` equal to the number of links.
- **[FUSE-22]** Where the view's schema requires canonical attributes (for
  example a schema that fixes mode bits, ownership, and timestamps for every
  entry), the worker MUST return the canonical values and MUST ignore any
  attribute in the tree that contradicts them. Otherwise the worker MUST
  return the entry's recorded mode, ownership, and timestamps, defaulting
  absent fields to `0444` (`0555` for directories and executables), owner
  `0:0`, and timestamp `1`.
- **[FUSE-23]** Symlink targets MUST be returned exactly as recorded in the
  entry, without normalization or resolution.
- **[FUSE-24]** Extended attributes MUST NOT be served unless the exposure
  option `xattrs = true` is set, in which case the entry's recorded
  attributes in the `xattr` namespace are served read-only.
- **[FUSE-25]** Attribute and entry cache timeouts MUST be unbounded for a
  `pinned` view and MUST be zero for a `follow` view or for any view with a
  ruleset that has `on_access` rules. Negative lookups MUST be cached only
  for `pinned` views.

## The open path

The sequence for `open` of a regular file whose content is not resident:

1. The worker looks the path up in the index and obtains the object hash and
   size.
2. The worker requests a backing handle from the serve process with the
   exposure id, object hash, and lease.
3. The serve process verifies scope, resolves the manifest, and requests the
   file's chunk ranges from the tiered store at the exposure's priority.
4. The serve process assembles the object into a temporary file in the host
   tier, verifies the whole-file hash against the object's recorded content
   hash, fsyncs, seals it, and links it under the object directory.
5. The serve process returns a read-only descriptor to the worker.
6. The worker registers the descriptor as the inode's backing file (or
   retains it for `pread` fallback) and completes the open.

- **[FUSE-26]** Step 4 MUST complete, including verification and sealing,
  before step 5. A consumer MUST NOT be able to read a byte of an object that
  has not been verified. *Gate:* `gate:fuse-verify-before-serve`.
- **[FUSE-27]** If the object is already sealed in the host tier, steps 3 and
  4 MUST be skipped and the serve process MUST return a descriptor to the
  existing sealed file.
- **[FUSE-28]** An open MUST block for at most the exposure's `open_deadline`
  option (default 60 seconds) and MUST then fail with `EIO`. Content that
  arrives later MUST still be sealed and cached for subsequent opens.
- **[FUSE-29]** The worker MUST coalesce concurrent opens of the same inode
  into one backing request.
- **[FUSE-30]** The serve process SHOULD honor prefetch hints from the
  exposure's ruleset ([`31-routing-rulesets.md`](31-routing-rulesets.md)) and
  from access profiles ([`10-derived-data.md`](10-derived-data.md)) by
  fetching at a lower priority than blocking opens. A dropped prefetch MUST
  never fail an open.
- **[FUSE-31]** `read` on an open file served without passthrough MUST be
  satisfied from the sealed object by `pread` and MUST NOT re-verify bytes on
  each read.

## The writable upper

A writable FUSE exposure presents an overlayfs mount whose lower layer is the
read-only FUSE tree and whose upper layer is a private directory on the host
filesystem. All consumer writes land in the upper. Commit walks the upper.

```text
<exposure dir>/
  lower/     the FUSE mount (read-only)
  upper/     private writable layer
  work/      overlayfs work directory
  merged/    the mount the consumer sees
```

- **[FUSE-32]** A writable exposure MUST use an overlayfs upper on a
  non-stacked host filesystem. The lower layer MUST be the read-only FUSE
  mount. Consumer writes MUST NOT modify any sealed object, index, or tree.
  *Gate:* `gate:fuse-upper-isolation`.
- **[FUSE-33]** The upper MUST be subject to a per-exposure quota
  (`quota_bytes`) enforced by the host filesystem's project quota where
  available; otherwise the serve process MUST enforce it by accounting and
  return `EDQUOT` when exceeded.
- **[FUSE-34]** Commit MUST walk the upper, translate overlayfs whiteouts and
  opaque directories into entry removals, chunk and hash new or changed
  files, build the delta tree ([`07-tree-algebra.md`](07-tree-algebra.md)),
  and commit through the repository's single commit path
  ([`26-surfaces.md`](26-surfaces.md) SURF-16). Rename order, whiteout
  encoding, and overlayfs private extended attributes MUST NOT appear in the
  committed tree.
- **[FUSE-35]** After a successful commit in `periodic` or `sync` mode, the
  exposure MAY collapse the upper by replacing the lower with the new commit
  and clearing the upper. The replacement MUST be atomic for new path
  resolution (mount beneath and detach the old top); open descriptors MUST
  continue to work against the old inodes.
- **[FUSE-36]** `fsync`, `fdatasync`, and `syncfs` on the merged mount MUST
  behave as specified for the exposure's writer mode in
  [`20-consistency.md`](20-consistency.md): local durability in `manual` and
  `periodic`, commit in `sync`. A failed `sync`-mode `fsync` MUST leave the
  file marked failed until a later `fsync` succeeds.

## Redirections

Build outputs and scratch directories are write-heavy and are never
committed as part of the view. Routing them through overlayfs over FUSE costs
every write two extra filesystem layers.

- **[FUSE-37]** An exposure MAY declare `redirect` options: a list of paths
  beneath the merged mount that are bind-mounted from a private host
  directory instead of the overlay. Redirected paths MUST NOT be included in
  a commit unless the redirect is declared `commit = true`.
- **[FUSE-38]** A redirected path MUST be created in the upper as an empty
  directory before the bind so that the overlay's namespace remains
  consistent if the bind is removed.
- **[FUSE-39]** Executables that the consumer runs from within the tree
  SHOULD be served through passthrough. Where an implementation observes
  that `execve` through an overlay above the FUSE mount fails on the running
  kernel, it MUST materialize the executable into the upper at first access
  and MUST report the degraded feature in status.

## The control directory

Every FUSE exposure presents a `.terrane` directory at the root of the
merged mount. It is the consumer-side porcelain: a process inside the mount
can inspect and drive the exposure without any network access of its own.

```text
.terrane/
  commit          read: the served commit hash
  ref             read: the view selector
  status          read: exposure status (the SURF-27 record, encoded as JSON)
  dirty           read: "0" or "1"; whether the upper has uncommitted changes
  last-error      read: last commit error, empty if none
  control         write-only socket: commit, tag, fork, and job requests
```

- **[FUSE-40]** The `.terrane` directory MUST be present at the root of every
  FUSE exposure, MUST NOT be part of the tree, and MUST be excluded from
  commits, listings of the committed tree, diffs, and schema validation.
- **[FUSE-41]** Requests written to `.terrane/control` MUST be authorized
  under the exposure's token and MUST NOT allow a consumer to obtain a
  broader token. The request set is `commit`, `tag`, `fork`, `status`, and
  the tree-job interface of [`32-tree-jobs.md`](32-tree-jobs.md).
- **[FUSE-42]** The control socket MUST be usable by an unprivileged process
  in the consumer's user namespace. Its protocol is the wire protocol of
  [`18-protocol.md`](18-protocol.md) restricted to the exposure's view.

## Mount options

- **[FUSE-43]** The FUSE mount MUST be created with `nosuid` and `nodev`. A
  read-only exposure MUST be mounted `ro`. `noexec` MAY be set by policy.
- **[FUSE-44]** `allow_other` is policy: an exposure whose consumers run
  under a different user id than the worker MUST set it, and an
  implementation MUST NOT set it otherwise.
- **[FUSE-45]** The mount MUST disable POSIX locks and BSD locks on the
  read-only lower layer; lock requests MUST be satisfied by the overlay's
  upper when writable and MUST return `ENOLCK` when read-only.
- **[FUSE-46]** `default_permissions` MUST be set so that the kernel enforces
  mode bits from `getattr` rather than the worker deciding per request.

## Leases, abort, and upgrade

- **[FUSE-47]** Every exposure MUST hold a lease recorded durably by the
  serve process (not only in memory), containing the exposure id, the served
  commit, the pinned index and objects, and the deadline. A lease that is not
  renewed by its deadline MUST cause the exposure to be drained and its pins
  released.
- **[FUSE-48]** Draining an exposure MUST stop accepting new opens, wait for
  in-flight backing requests up to a bounded time, then abort the FUSE
  connection. Consumers with open descriptors observe `ENOTCONN` thereafter.
- **[FUSE-49]** An implementation MUST NOT hand an active FUSE connection to
  a replacement worker as an upgrade mechanism. Upgrades MUST drain the
  exposure and mount a new worker generation; an implementation MAY mount
  the new generation beneath the old and detach the old top so that path
  resolution switches atomically.
- **[FUSE-50]** After a crash of the serve process, exposures MUST be
  recovered from their durable leases: the index and sealed objects are
  re-verified before reuse, and a lease whose deadline passed during the
  outage is released, not resumed.

## Options

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `upper` | `none` \| `private-cow` | `none` | whether the exposure is writable |
| `passthrough` | `auto` \| `require` \| `off` | `auto` | FUSE passthrough policy |
| `quota_bytes` | integer | unlimited | upper quota |
| `open_deadline` | duration | `60s` | bound on a blocking open |
| `xattrs` | bool | `false` | serve recorded extended attributes |
| `redirect` | list of `{ path, commit }` | `[]` | bind-mounted scratch paths |
| `allow_other` | bool | policy | see FUSE-44 |
| `noexec` | bool | `false` | mount `noexec` |
| `lease` | duration | `10m` | lease renewal interval |

## Interactions

- [`14-host-tier.md`](14-host-tier.md): sealed objects, the object directory,
  pins, and eviction supply every byte the surface serves.
- [`20-consistency.md`](20-consistency.md): writer and reader modes govern
  `fsync` and ref resolution.
- [`26-surfaces.md`](26-surfaces.md): the exposure record, the single commit
  path, status.
- [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md): the
  resident realizer that replaces FUSE when a tree is fully local.
- [`31-routing-rulesets.md`](31-routing-rulesets.md): prefetch and lazy
  content classification are evaluated in the serve process on the open
  path.
- [`reference/errno-mapping.md`](reference/errno-mapping.md): the errors
  consumers observe.
