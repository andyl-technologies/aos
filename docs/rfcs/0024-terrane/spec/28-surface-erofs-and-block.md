# 28 — Surfaces: EROFS and block device

This file owns two realizers that share one idea: a tree's directory
structure is a pure function of its root hash, so the kernel can be handed a
precomputed, verifiable image of it instead of answering lookups from
userspace. The **EROFS surface** generates a composefs-style metadata image
and mounts it through overlayfs with the host tier's sealed object directory
as a data-only lower layer, giving native-speed reads with no FUSE round trip.
The **block surface** exposes the same deterministic EROFS layout, data
included, as a block device whose blocks are fetched lazily, for consumers
that need a disk rather than a mount. The FUSE realizer for lazy trees is in
[`27-surface-fuse.md`](27-surface-fuse.md); virtual-machine transports are in
[`29-surface-vm.md`](29-surface-vm.md).

## Model

composefs established the pattern this surface follows. The directory tree,
names, modes, ownership, timestamps, symlink targets, and extended attributes
live in an EROFS image. Each regular file in the image carries an overlayfs
redirect naming a flat, content-addressed object under a separate directory,
plus the object's fs-verity digest. overlayfs, mounted with that directory as
a **data-only lower layer**, resolves every read to the sealed object, and
`verity=require` makes the kernel refuse an object whose measured digest does
not match. The image is small (metadata only), the objects are shared by
every image that references them, and reads are ordinary page-cache reads on
ordinary inodes.

Terrane already keeps sealed objects in a flat, content-addressed object
directory ([`14-host-tier.md`](14-host-tier.md)) and already knows every
object's content hash. Generating the image is a deterministic walk of the
tree's index. The result is memoized by root hash, so mounting a commit that
was mounted before costs two mount system calls.

The block surface goes one step further. EROFS's on-disk layout is a
deterministic function of the tree and a small set of layout parameters, so
an implementation can compute, without materializing an image, which byte
range of the device corresponds to which file extent and therefore to which
chunk range. Serving the device is then the same routed read as any other,
addressed by block instead of by path.

## EROFS surface

### Image generation

- **[EROFS-1]** The image for a root MUST be a pure function of `(root hash,
  image format version, layout parameters)`. Two implementations given the
  same inputs MUST produce byte-identical images. *Gate:*
  `gate:erofs-image-determinism`.
- **[EROFS-2]** The image MUST contain every entry of the tree's metadata:
  directories, names in sorted order, mode, ownership, timestamps, symlink
  targets, hard-link identities, and, when the exposure enables them,
  extended attributes. It MUST NOT contain file content.
- **[EROFS-3]** Each regular file inode in the image MUST carry the overlayfs
  redirect to its sealed object's path relative to the data-only lower layer
  and the object's fs-verity digest in the overlayfs metacopy attribute,
  following the composefs conventions for these attributes.
- **[EROFS-4]** The image MUST be generated from the structural index
  ([`27-surface-fuse.md`](27-surface-fuse.md) FUSE-7) or directly from tree
  nodes, and MUST NOT require object content to be resident. `tree` entries
  MUST be inlined as with FUSE-12.
- **[EROFS-5]** Generated images MUST be sealed and stored in the host tier
  keyed by `(root hash, image format version, layout parameters hash)`. An
  image MUST be verified against its recorded hash before mounting after a
  restart.
- **[EROFS-6]** Where the view's schema fixes canonical attributes, the
  image MUST carry the canonical values (as FUSE-22).

### Mounting

```text
mount -t erofs -o ro,loop <image> <exposure>/meta
mount -t overlay overlay \
  -o lowerdir=<exposure>/meta::<objects>,metacopy=on,redirect_dir=follow,verity=require \
  <exposure>/merged
```

- **[EROFS-7]** The overlay MUST be mounted with the sealed object directory
  as a data-only lower layer (the `::` separator form), with `metacopy=on`,
  `redirect_dir=follow`, and `verity=require`. An implementation MUST NOT
  mount without `verity=require` unless the exposure's policy explicitly
  waives it, and it MUST then report a degraded feature. *Gate:*
  `gate:erofs-verity`.
- **[EROFS-8]** The data-only lower layer MUST be the host tier's object
  directory for the exposure's disclosure domain
  ([`24-disclosure-domains.md`](24-disclosure-domains.md)) and MUST be
  exposed read-only. Objects of a different domain MUST NOT be reachable from
  the image.
- **[EROFS-9]** Every object the image references MUST be sealed with
  fs-verity enabled before the mount is announced ready. The mount MUST NOT
  be exposed to a consumer while any referenced object is absent, unless the
  exposure declares `lazy = true` (see § resident versus lazy).
- **[EROFS-10]** A writable exposure MUST add a private upper and work
  directory to the same overlay mount rather than stacking a second overlay,
  and commit MUST proceed as FUSE-34.
- **[EROFS-11]** Replacement of the served commit in a `follow` view MUST
  generate the new image, ensure its objects are sealed, mount the new
  overlay beneath the old, and detach the old top, so that path resolution
  switches atomically and open descriptors remain valid.

### Resident versus lazy

The EROFS surface is the fastest realizer when a tree's objects are already
local: no userspace on the read path, one page-cache copy shared by every
consumer, integrity enforced by the kernel. Its cost is that overlayfs
cannot fault a missing lower file; every referenced object must exist before
the mount can serve.

- **[EROFS-12]** An exposure MUST declare `lazy = false` (the default) or
  `lazy = true`. With `lazy = false`, the implementation MUST fetch and seal
  every referenced object before announcing the mount ready, honoring the
  routed store's priorities and the exposure's `ready_deadline`.
- **[EROFS-13]** With `lazy = true`, the implementation MUST place the FUSE
  realizer's object-directory view beneath the image: the data-only lower
  layer is a FUSE mount presenting the object directory by hash, which
  fetches, verifies, and seals an object on first open and then serves it by
  passthrough. Once an object is sealed on the host filesystem, the FUSE
  view MUST serve it from the sealed inode so the page cache is shared with
  non-lazy exposures.
- **[EROFS-14]** For an `erofs` exposure, an implementation SHOULD serve
  the EROFS image once the view's objects are wholly resident or residency
  exceeds the `resident_threshold` option (default 90 percent by bytes),
  and MAY serve the same view through the FUSE realizer
  ([`27-surface-fuse.md`](27-surface-fuse.md)) until then. The realizer in
  use MUST be reported in status (SURF-27).
- **[EROFS-15]** A view's identity MUST NOT depend on which realizer served
  it. The same commit served by FUSE and by EROFS MUST present identical
  names, sizes, modes, symlink targets, and content.

### Options

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `lazy` | bool | `false` | fault objects through a FUSE object view |
| `resident_threshold` | percent | `90` | residency above which the EROFS image replaces FUSE serving |
| `ready_deadline` | duration | `10m` | bound on pre-sealing for non-lazy mounts |
| `upper` | `none` \| `private-cow` | `none` | writable overlay upper |
| `xattrs` | bool | `false` | include extended attributes in the image |
| `verity` | `require` \| `waive` | `require` | see EROFS-7 |

## Block surface

### Deterministic layout

The block surface presents a view as a read-only block device containing an
EROFS filesystem with data included. Nothing is materialized: the surface
computes, from the tree and the layout parameters, a map from device block
ranges to file extents, and from file extents to chunk ranges of the
underlying objects. A read of blocks `[a, b)` becomes a routed read of the
chunk ranges those blocks cover, plus deterministic metadata blocks generated
on demand.

```text
device blocks
  [0, M)        superblock, inode tables, directories, xattrs  (generated)
  [M, N)        file data, laid out in tree order, block-aligned (chunks)
```

- **[VBLK-1]** The device layout MUST be a pure function of `(root hash,
  layout format version, layout parameters)`. Given the same inputs, two
  implementations MUST produce a byte-identical device image when read end
  to end. *Gate:* `gate:block-layout-determinism`.
- **[VBLK-2]** File data MUST be placed in tree (path) order, each file
  starting at a block boundary, with no compression on the device. The
  block size is a layout parameter and MUST be a power of two between 512
  and 65536 bytes.
- **[VBLK-3]** The metadata region MUST be generated from tree metadata
  alone and MUST NOT require object content. Its size is a function of the
  tree and MUST be computed before any data block address is assigned.
- **[VBLK-4]** The surface MUST maintain an extent map from device block
  ranges to `(object hash, offset, length)` and MUST resolve reads to chunk
  ranges through the object's manifest. The extent map is derived and MAY be
  cached in the host tier keyed as EROFS-5.
- **[VBLK-5]** Reads of data blocks MUST be served from the routed store with
  the same verification as any other read: no unverified chunk bytes reach
  the device. A read spanning several files MUST be split at extent
  boundaries and served in parallel.
- **[VBLK-6]** Reads of unallocated or padding blocks MUST return zeros.

### Transports

- **[VBLK-7]** An implementation MUST support at least one of the following
  device transports and MUST report which it uses: `ublk` (a kernel block
  device backed by a userspace server), `vhost-user-blk` (a socket served
  directly to a virtual machine monitor, with no host kernel block device),
  or `nbd` (the network block device protocol, local or remote).
- **[VBLK-8]** For `vhost-user-blk` the surface MUST honor the monitor's
  queue and segment limits and MUST advertise the device as read-only.
- **[VBLK-9]** For `ublk` the resulting device node MUST be created
  read-only and the surface MUST reject write requests with the transport's
  error rather than silently discarding them.
- **[VBLK-10]** The surface SHOULD readahead by extent, fetching the
  remainder of a file whose first block was requested at a lower priority,
  and SHOULD honor the same access-profile prefetch as FUSE-30.

### Writes

- **[VBLK-11]** In version 1.0 the block surface is read-only. A consumer
  that needs a writable disk MUST layer its own copy-on-write image above the
  device (for example a qcow2 overlay or a volume-manager snapshot). The
  surface MUST NOT expose a writable device.
- **[VBLK-12]** Committing a guest's writes from a copy-on-write layer back
  into a tree (mounting the layer on the host after snapshot, diffing, and
  committing) is deferred and MUST NOT be claimed as supported by a 1.0
  implementation. It is recorded in
  [`40-risks-and-open-questions.md`](40-risks-and-open-questions.md).

### Deterministic harnesses

Because the device contents are a pure function of the root hash, a
simulation or replay harness that requires bit-identical disk contents across
runs can use this surface directly: the same commit yields the same device
bytes on every host, and the harness's block-level determinism contract is
satisfied by the layout's determinism rather than by copying an image.

- **[VBLK-13]** An implementation MUST expose the device's total size and a
  digest of the full layout (computed without reading data, from the tree and
  layout parameters) so that a harness can verify it is booting the intended
  bytes without reading the whole device.

### Options

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `transport` | `ublk` \| `vhost-user-blk` \| `nbd` | implementation default | device transport |
| `block_size` | integer | `4096` | layout block size |
| `readahead` | bool | `true` | extent readahead |
| `layout_version` | integer | `1` | layout format version |

## Interactions

- [`14-host-tier.md`](14-host-tier.md): sealing with fs-verity and the
  object directory are prerequisites for EROFS-7 through EROFS-9.
- [`24-disclosure-domains.md`](24-disclosure-domains.md): one object
  directory per domain; the image references only its domain's objects.
- [`27-surface-fuse.md`](27-surface-fuse.md): supplies the index EROFS
  generation reads and the lazy object view of EROFS-13.
- [`29-surface-vm.md`](29-surface-vm.md): the block surface and the object
  directory are the two ways a guest consumes a view.
- [`35-performance-targets.md`](35-performance-targets.md): the resident
  mount budget is measured against this surface.
