# Reference — Prior art and theory (informative)

This document surveys the systems and results that Terrane draws on, grouped
by the problem each one solves. It is informative: nothing here is a
requirement. Each section ends with what Terrane took and what it left. URLs
were current at the time of writing.

## 1. Persistent Merkle maps with structural sharing

The namespace problem is: a map from path to entry with billions of keys,
where two maps with the same content must have the same identity, where a
change touches few nodes, and where diff and three-way merge cost time
proportional to the difference.

**git tree objects.** One node per directory, entries sorted by name, node
hash over children. Sharing is per directory; a one-file change rehashes
O(depth) nodes. Diff short-circuits on equal subtree hashes. Three-way merge
(`merge-ort`) recurses only where the three hashes differ. The weakness for
Terrane's scale is that fan-out is whatever the user's directory layout is:
a flat directory of ten million files is one object rewritten on every
touch, because git has no chunking below a tree node.
<https://git-scm.com/book/en/v2/Git-Internals-Git-Objects>

**Prolly trees.** A B-tree whose node boundaries are content-defined by a
rolling hash over the entry stream, so the same key set always yields the
same node structure regardless of insertion order ("history independence").
Two trees with identical contents are byte-identical; diff walks only nodes
whose hashes differ; three-way merge is a three-cursor walk that skips shared
subtrees. The known caveat is boundary variance: a naive boundary function
can produce long runs without a split, which the Dolt implementation fixes
with a boundary probability that rises with node size.
<https://www.dolthub.com/blog/2022-06-27-prolly-chunker/>,
<https://www.dolthub.com/blog/2025-06-03-people-keep-inventing-prolly-trees/>,
<https://www.dolthub.com/blog/2025-07-03-regarding-prollyferation/>,
<https://blog.mauve.moe/posts/prolly-tree-analysis>

**Merkle Search Trees** (Auvolat and Taïani, 2019). Each key's hash decides
its layer, producing a deterministic B-tree-like structure with values at
every level. Also history-independent; designed for anti-entropy set
reconciliation. Interior values make sequential scans and bulk construction
less cache-friendly than a leaf-only design for very large ordered maps.
<https://inria.hal.science/hal-02303490/document>,
<https://joelgustafson.com/posts/2023-05-04/merklizing-the-key-value-store-for-fun-and-profit>

**Hash array mapped tries in IPLD.** Hash-keyed, so iteration order is
random. Diff is O(changed buckets), but there are no ordered range queries by
path prefix and therefore no cheap directory listing.
<https://ipld.io/specs/advanced-data-layouts/hamt/spec/>

**Conflicts as values.** The jj version-control system represents a possibly
conflicted state as an odd-length list of trees, `A + (C − B) + (E − D)`;
tree merge recurses only into subtrees whose identities differ, and an
unresolved conflict is a first-class value rather than an error.
<https://jj-vcs.github.io/jj/latest/technical/conflicts/>

**Patch theory.** Pijul models patches as morphisms with pushouts in a
category of files. Elegant, but keyed on line-level edit graphs rather than
path maps, so it does not apply to a blob-level store.
<https://pijul.org/manual/theory.html>

**What Terrane took.** A prolly tree keyed by bytewise-sorted relative path
with size-scaled boundary probability; `tree` entries for O(1) grafting
across roots; three-cursor merge; jj-style conflict values. **What it left.**
Per-directory nodes, hash-keyed maps, patch theory, and interior values.

## 2. Object-store-native metadata with no database

**S3 conditional writes.** `PutObject` and `CompleteMultipartUpload` accept
`If-None-Match: *` (create only if absent, since August 2024) and
`If-Match: <etag>` (compare-and-swap, since November 2024). Only `*` is
accepted for `If-None-Match`. Bucket policy can mandate them. A multipart
upload whose completion loses the race must be aborted or it becomes
orphaned billable storage; multipart tags are not content digests and must
be treated as opaque. Some proxies and clones drop the headers silently.
<https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html>,
<https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html>

**GCS preconditions.** `ifGenerationMatch=0` means create-if-absent; a
nonzero generation is compare-and-swap. Portable clients sometimes lose the
precondition in translation.
<https://cloud.google.com/storage/docs/request-preconditions>,
<https://www.joyfulbikeshedding.com/blog/2021-05-19-robust-distributed-locking-algorithm-based-on-google-cloud-storage.html>

**Leader election on object storage.** Lease objects created with
create-if-absent and fenced with epoch numbers give a singleton without a
coordination service.
<https://www.morling.dev/blog/leader-election-with-s3-conditional-writes/>

**SlateDB.** A log-structured store whose manifest is a numbered object
written with create-if-absent, with a writer epoch bumped on writer startup
so zombie writers are fenced at their next write. Readers poll the latest
manifest. This is the cleanest published pattern for a mutable pointer over
an immutable object set, and it is Terrane's ref protocol almost exactly.
<https://slatedb.io/rfcs/0001-manifest/>

**Iceberg and Delta.** Iceberg commits by atomically swapping a pointer to a
new immutable metadata file; the filesystem catalog is unsafe under
concurrency without a conditional primitive. Delta's log is a directory of
numbered commit files with create-if-absent semantics, which on S3 required
an external table before conditional writes existed. The lesson Terrane
takes is that a monotonically numbered log of immutable commit objects, each
created with create-if-absent, is the object-store-native form of a ref
update, and losers re-read and retry.
<https://iceberg.apache.org/spec/>,
<https://docs.delta.io/delta-storage/>,
<https://delta.io/blog/2022-05-18-multi-cluster-writes-to-delta-lake-storage-in-s3/>

**Backup tools.** restic keeps `data/` packs of blobs, `index/` files
mapping blob to pack and offset, and `snapshots/`; prune takes an exclusive
lock, repacks partially live packs, rewrites the index, then deletes. rustic
makes prune lock-free by marking packs for deletion and removing them only
after a keep window (23 hours by default), so concurrent backups have that
window to finish, and a backup that references a marked pack un-marks it.
borg uses a single-writer lock, segment files, and a client-side chunk cache
with reference counts. casync and desync keep a chunk index per archive and
a flat chunk store with no garbage collection in the store by design; prune
computes the union of referenced chunks from given indexes. bup uses git
packfiles plus multi-pack indexes and bloom filters for membership tests.
<https://restic.readthedocs.io/en/stable/060_forget.html>,
<https://rustic.cli.rs/docs/FAQ.html>,
<https://borgbackup.readthedocs.io/en/stable/internals.html>,
<https://github.com/systemd/casync>,
<https://github.com/folbricht/desync>,
<https://bup.github.io/>

**What Terrane took.** Immutable, idempotent content objects needing no
conditions; all mutability in refs updated by compare-and-swap with a
fallback create-if-absent log that doubles as reflog and snapshot list; a
writer epoch per ref; self-describing packs with per-pack indexes and
periodically merged, filtered indexes; mark-then-delete with a keep window;
never depending on listing order for correctness. **What it left.**
Exclusive repository locks, client-side reference counts, and external
coordination tables.

## 3. Union filesystems and lazy content-addressed mounting

**composefs.** Directory metadata, names, modes, and extended attributes
live in an EROFS image; each regular file carries an overlay redirect into a
flat content-addressed object directory and a metacopy attribute carrying
the fs-verity digest. overlayfs mounts the object directory as a data-only
lower layer so object names never appear in the namespace, and
`verity=require` makes the kernel check the digest on open. One small image
per view, zero copies of file data, per-file integrity. Writable views are an
`upperdir` on top.
<https://github.com/composefs/composefs>,
<https://blogs.gnome.org/alexl/2023/07/11/composefs-state-of-the-union/>,
<https://docs.rs/composefs>

**ostree.** Objects stored by digest; deployments are hardlink or reflink
checkouts; modern ostree uses composefs for the root. File-level dedup, no
chunking below a file.
<https://ostreedev.github.io/ostree/repo/>

**Nix lazy trees.** Flake inputs mounted through a virtual filesystem and
hashed without copying to the store; only paths that become derivation
inputs are copied.
<https://github.com/NixOS/nix/pull/13225>

**Buildbarn bb_clientd.** A FUSE (or NFSv4 on macOS) mount where each input
root is materialized from a Remote Execution API `Directory` Merkle tree;
file bytes are fetched from the content-addressed store on first read;
outputs are written as lazy files so they never need to be downloaded. The
NFSv4 rationale is that FUSE directory-entry invalidation is expensive and
NFS lets the client cache aggressively.
<https://github.com/buildbarn/bb-clientd>,
<https://github.com/buildbarn/bb-adrs/blob/main/0009-nfsv4.md>

**EdenFS and Sapling.** A virtual checkout where inodes are loaded on
demand, inode numbers assigned lazily, and file content fetched on first
read into a local blob cache. "Redirections" bind-mount local directories
over build-output paths so heavy writes bypass the virtual filesystem.
<https://github.com/facebook/sapling/blob/main/eden/fs/docs/Overview.md>,
<https://github.com/facebook/sapling/blob/main/eden/fs/docs/Redirections.md>

**Clients in the Cloud (CitC).** A workspace is an overlay of local edits
over a snapshot of a monorepository served from a distributed store.
<https://dl.acm.org/doi/10.1145/2854146>

**Lazy container images.** eStargz rewrites a layer with a table of
contents; SOCI keeps the original layer and stores an external index of
compression checkpoints; Nydus replaces tar with a bootstrap (metadata,
EROFS-compatible) plus content-defined chunks deduplicated across images with
a shared local chunk cache. Nydus is the closest published design to
Terrane's host tier.
<https://github.com/containerd/stargz-snapshotter>,
<https://github.com/awslabs/soci-snapshotter>,
<https://github.com/containerd/nydus-snapshotter>

**What Terrane took.** An EROFS metadata image generated from the tree and
mounted with a data-only object directory for resident trees; FUSE with
passthrough for lazy trees, promoting fully present files into the sealed
object directory; redirections for hot output directories; directory
listings served from metadata without any object fetch. **What it left.**
Hardlink checkouts, tar-format layers, and whole-file-only dedup.

## 4. Garbage collection with branches and concurrent writers

**git.** Reachability from refs plus reflogs; `gc.pruneExpire` (two weeks
by default) leaves unreachable objects younger than the grace period alone,
and `gc.reflogExpire` keeps recently abandoned tips reachable. The mtime
grace period is what makes concurrent pushes safe: a push writes objects
before updating the ref, so a collection between the two would otherwise
delete them.
<https://git-scm.com/docs/git-gc>

**Bazel remote cache.** Semantically an LRU with no ownership. Bazel 7
adds a cache TTL assumption and a lease-extension mode that periodically
re-checks referenced blobs to refresh their position; eviction mid-build is
a distinct exit code with retry.
<https://blog.bazel.build/2023/10/06/bwob-in-bazel-7.html>

**Buildbarn completeness checking.** An action result is returned only if a
find-missing check confirms every referenced output blob exists, and the
check itself touches those blobs so the LRU keeps them. Local storage is a
ring buffer with old, current, and new generations; a blob referenced from
an old region is copied forward on access rather than reference-counted.
<https://github.com/buildbarn/bb-adrs/blob/main/0002-storage.md>

**Nix.** Explicit roots under a roots directory, closure computed from the
reference table at collection time, a store lock and per-process temporary
roots protecting in-flight builds.
<https://nixos.org/manual/nix/stable/package-management/garbage-collection>

**What Terrane took.** Refs and retained reflog entries as roots; mark from
roots skipping already-marked subtrees; sweep only objects older than a
grace window strictly longer than the maximum commit duration, enforced on
the client; two-step deletion through tombstones; writer ordering of packs,
then indexes, then ref. **What it left.** Reference counts, LRU-only
semantics, and lock-based collection.

## 5. Cross-tier deduplication

**virtiofs with DAX.** Maps host page-cache pages directly into a guest, so
a chunk directory shared by many virtual machines has one physical copy and
one page-cache copy.
<https://virtio-fs.gitlab.io/>,
<https://lwn.net/Articles/813807/>

**virtio-pmem.** A DAX-mapped file-backed persistent-memory device with no
guest page cache.
<https://lkml.iu.edu/hypermail/linux/kernel/1901.1/07045.html>

**Bind mounts and fs-verity.** A read-only bind mount of a flat object
directory as an overlay data-only lower, with fs-verity making it safe to
share across trust boundaries because the kernel verifies content on open.
<https://docs.kernel.org/filesystems/fsverity.html>

**FUSE passthrough.** Since Linux 6.9 a FUSE server can register a backing
file for an inode so the kernel serves reads and executes directly from it,
with one page-cache copy shared by every consumer of that inode.
<https://docs.kernel.org/filesystems/fuse-passthrough.html>

**What Terrane took.** One physical sealed object directory per host and
disclosure domain, exposed to containers by bind mount and to virtual
machines by virtiofs with DAX, consumed by EROFS images and FUSE
passthrough; a nested tier that can see a lower tier's object directory
stores nothing and only stages its own new chunks. **What it left.**
Per-tier private copies.

## 6. Naming

A survey of crate registries in September 2026 found single-word geology
names largely taken: `chunkfs`, `warehouse`, `strata`, `sediment`, `quarry`,
`lode`, `vein`, `stratum`, `ledge`, and `shale` were all registered. The
name Terrane was chosen for the accretion metaphor
([`../39-decision-register.md`](../39-decision-register.md) `D-20`);
availability of the plain crate names on public registries was not verified
at the time of writing and is an adopting project's concern.
