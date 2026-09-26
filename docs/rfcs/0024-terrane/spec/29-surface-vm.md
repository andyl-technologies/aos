# 29 — Surfaces: virtual machines

This file owns how a view reaches a guest running under a virtual machine
monitor on the host, and how a Terrane instance inside that guest
participates in the host's tiers without duplicating a byte. Two transports
carry file content into a guest: **virtiofs** over the host tier's sealed
object directory, with DAX so the guest maps the host's page cache directly,
and the **block surface** of
[`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md) for guests
that lack a virtiofs driver or need a disk. A **nested instance** in the
guest treats the shared object directory as its first tier and the host
instance as its remote, which is the same tier composition every other
deployment uses ([`11-store-trait.md`](11-store-trait.md),
[`19-tiering-and-topology.md`](19-tiering-and-topology.md)).

## Model

A virtual machine is a consumer like a container, with one difference that
matters to storage: it has its own kernel and therefore its own page cache.
Naively, every guest that reads a shared library holds its own copy of the
library's pages, and the host holds a third. virtiofs with DAX removes the
duplication by mapping host file pages into guest physical memory, so a
guest read of a sealed object is a page-cache hit on the host with no copy.
virtio-pmem offers the same property with a file-backed device the guest
treats as persistent memory and accesses without its own page cache.

What crosses into the guest is never the view's tree; it is the flat object
directory, keyed by hash. The guest builds its own namespace from tree
metadata it fetches through the host instance, exactly as a host builds one
from a bucket. This keeps the boundary simple: the host exports bytes it has
already verified and sealed, the guest never gains write access to them, and
the guest's own new content is staged privately and pushed up.

## virtiofs over the object directory

- **[VM-1]** A host that exposes views to guests over virtiofs MUST export
  the host tier's sealed object directory for the guest's disclosure domain
  ([`24-disclosure-domains.md`](24-disclosure-domains.md)) read-only. It
  MUST NOT export the object directory of any other domain, the pack
  directory, indexes, or refs. *Gate:* `gate:vm-export-scope`.
- **[VM-2]** The export MUST be configured so that the guest cannot create,
  modify, rename, or delete entries beneath it, independent of guest-side
  mount options. Read-only MUST be enforced on the host side of the
  transport.
- **[VM-3]** The export SHOULD enable DAX. Where the guest kernel and the
  monitor support it, the guest MUST mount with `dax` so that sealed objects
  are mapped from host page cache. Where DAX is unavailable, the export MUST
  still function with guest-side caching, and the host MUST report the
  degraded feature in the exposure's status.
- **[VM-4]** fs-verity measurement of a sealed object MUST be verifiable from
  the guest. Where the transport cannot convey fs-verity state, the nested
  instance MUST verify object content against the recorded hash before
  registering it as a backing file, at the cost of one read per object.
- **[VM-5]** The host MUST hold pins ([`14-host-tier.md`](14-host-tier.md))
  on every object the guest's exposures reference for the lifetime of the
  guest's leases, so that eviction on the host cannot remove an object the
  guest is mapping.

## virtio-pmem

- **[VM-6]** An implementation MAY export a sealed EROFS image with data
  included (the block surface's layout, VBLK-1) as a virtio-pmem device
  backed by a host file. The guest mounts it with `dax` and reads without a
  guest page cache. The backing file MUST be sealed before the device is
  attached and MUST NOT be modified while attached.
- **[VM-7]** A virtio-pmem export MUST be presented read-only, and the guest
  MUST NOT issue discard or trim operations against it; an implementation
  SHOULD configure the device to reject them.

## The block surface for guests

- **[VM-8]** A guest without virtiofs MUST be served by the block surface
  over `vhost-user-blk` or by a host-side `ublk` or `nbd` device attached as
  a virtual disk. The device is read-only (VBLK-11); the guest layers its
  own copy-on-write image for writes.
- **[VM-9]** A guest served by block MUST NOT be assumed to share page cache
  with the host or with other guests. An implementation SHOULD prefer
  virtiofs with DAX when the guest supports it and MUST record the transport
  chosen in the exposure's status.

## A nested instance in the guest

A guest that needs Terrane's namespace, surfaces, or commit path runs its own
instance. It is configured as any host is, with a store expression whose
first tier is the shared object directory and whose remote is the host's
serve endpoint:

```toml
[store]
expression = "routed[shared-dir(/terrane/objects), remote(vsock://2:7777)]"

[[expose]]
id      = "workspace"
view    = "refs/heads/pr/1234"
surface = "fuse"
at      = "/workspace"
token   = "file:/run/terrane/token"
mode    = { reader = "pinned", writer = "manual" }
```

- **[VM-10]** A nested instance MUST list the shared object directory as a
  `shared-dir` tier ahead of the host `remote`. A `shared-dir` tier answers
  reads for sealed objects and MUST NOT store anything
  ([`11-store-trait.md`](11-store-trait.md)). *Gate:* `gate:vm-no-duplication`.
- **[VM-11]** A nested instance MUST fetch tree nodes, manifests, commits,
  bundles, and ref values from the host instance over the wire protocol
  ([`18-protocol.md`](18-protocol.md)) and MUST NOT attempt to read packs,
  indexes, or refs from any exported directory.
- **[VM-12]** When a nested instance needs an object that is not present in
  the shared directory, it MUST request it from the host `remote`; the host
  fetches, verifies, seals, and the object then appears in the shared
  directory. The nested instance MUST NOT cache the object's bytes a second
  time in the guest when the shared directory is present. It MAY hold a
  guest-side page-cache copy where DAX is unavailable.
- **[VM-13]** A nested instance MAY be configured without a `shared-dir`
  tier (for example, on a transport that offers no shared directory). It then
  runs a `disk` tier of its own; this is the only configuration in which a
  chunk may exist on both the host and the guest, and the instance MUST
  report `duplication = possible` in status.
- **[VM-14]** A nested instance's exposures MUST present a `.terrane`
  control directory (FUSE-40) so that processes in the guest can commit,
  tag, and fork through the guest instance without network access.

### Writes from a guest

- **[VM-15]** New content produced in a guest MUST be chunked and hashed by
  the nested instance and staged in a private guest directory or
  block-backed staging area. The guest MUST NOT write into the shared object
  directory.
- **[VM-16]** On commit, the nested instance MUST push staged chunks and
  tree nodes to the host instance through the wire protocol. The host MUST
  validate them as it validates any upload
  ([`05-chunking.md`](05-chunking.md), [`18-protocol.md`](18-protocol.md)),
  seal the resulting objects into the shared directory, and forward packs to
  the authority tier. A guest MUST NOT be able to cause the host to seal
  bytes that do not match their claimed hash. *Gate:*
  `gate:vm-upload-validation`.
- **[VM-17]** The ref commit for a guest's view MUST be performed at the
  ref's authority ([`20-consistency.md`](20-consistency.md)). The host
  instance forwards the conditional write; it MUST NOT hold a cached ref
  value that lets a guest's commit succeed locally without reaching the
  authority.
- **[VM-18]** A guest's token MUST be an attenuation of a host-held token
  ([`22-authentication-and-authorization.md`](22-authentication-and-authorization.md))
  scoped to the guest's views. The host MUST refuse requests from a nested
  instance whose token exceeds what the host would grant that guest.

## What a guest may and may not do

| Action | Permitted |
| --- | --- |
| Read sealed objects of its domain through the shared directory | yes |
| Map those objects with DAX | yes, where supported |
| Fetch tree metadata and refs from the host instance | yes, under its token |
| Stage new chunks locally and push them to the host | yes |
| Commit refs through the host to the authority | yes, under its token |
| Write to, rename in, or delete from the shared directory | no |
| Read packs, indexes, refs, or other domains' objects from an export | no |
| Cause the host to seal unverified bytes | no |
| Hold a token broader than the host would attenuate for it | no |

## Options

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `transport` | `virtiofs` \| `virtio-pmem` \| `block` | `virtiofs` | how content reaches the guest |
| `dax` | `auto` \| `require` \| `off` | `auto` | DAX policy for virtiofs and pmem |
| `domain` | domain name | exposure's | which object directory to export |
| `remote` | endpoint | required | the host serve endpoint the guest instance uses |

## Interactions

- [`11-store-trait.md`](11-store-trait.md): the `shared-dir` backend and
  the rule that a tier never stores what a visible lower tier serves.
- [`14-host-tier.md`](14-host-tier.md): sealing, fs-verity, pins.
- [`18-protocol.md`](18-protocol.md): the guest-to-host channel.
- [`22-authentication-and-authorization.md`](22-authentication-and-authorization.md):
  token attenuation for guests.
- [`24-disclosure-domains.md`](24-disclosure-domains.md): one export per
  domain.
- [`28-surface-erofs-and-block.md`](28-surface-erofs-and-block.md): the
  block surface as the fallback transport.
