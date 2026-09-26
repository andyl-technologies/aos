# Reference: surface registry

This registry lists every surface name an implementation may register
([`../26-surfaces.md`](../26-surfaces.md) SURF-9). A name not listed here is
not a conforming surface. For each surface: the file that specifies it, the
endpoint kinds it accepts, whether it may be writable, the schema it requires
of a view's root, and the conformance level an implementation claims by
implementing it. Registering a new surface is a `MINOR` specification
change ([`../README.md`](../README.md) § versioning).

## Realizers

| Name | File | Endpoint kinds | Writable | Schema | Level |
| --- | --- | --- | --- | --- | --- |
| `fuse` | [`27-surface-fuse.md`](../27-surface-fuse.md) | `mount-path` | yes (`upper = private-cow`) | none | Surface: `fuse` |
| `erofs` | [`28-surface-erofs-and-block.md`](../28-surface-erofs-and-block.md) | `mount-path` | yes (`upper = private-cow`) | none | Surface: `erofs` |
| `mount` | [`28-surface-erofs-and-block.md`](../28-surface-erofs-and-block.md) EROFS-14 | `mount-path` | yes | none | Surface: `fuse` and Surface: `erofs` |
| `block` | [`28-surface-erofs-and-block.md`](../28-surface-erofs-and-block.md) | `device-node`, `vhost-user-socket`, `nbd-socket` | no | none | Surface: `block` |
| `virtiofs` | [`29-surface-vm.md`](../29-surface-vm.md) | `vhost-user-socket` | no (guest stages and pushes) | none | Surface: `virtiofs` |
| `virtio-pmem` | [`29-surface-vm.md`](../29-surface-vm.md) | `device-file` | no | none | Surface: `virtio-pmem` |

`mount` is the realizer-agnostic name: an exposure that asks for `mount`
lets the instance choose `erofs` when the view is resident and `fuse`
otherwise, and reports the choice in status.

## Protocol surfaces

| Name | File | Endpoint kinds | Writable | Schema | Level |
| --- | --- | --- | --- | --- | --- |
| `nix-cache` | [`30-surface-protocols.md`](../30-surface-protocols.md) § `nix-cache` | `http-prefix` | yes | § nix-cache schema | Surface: `nix-cache` |
| `reapi` | [`30-surface-protocols.md`](../30-surface-protocols.md) § `reapi` | `grpc-listen` | yes (`sync` only) | § reapi schema | Surface: `reapi` |
| `gha-cache` | [`30-surface-protocols.md`](../30-surface-protocols.md) § `gha-cache` | `http-prefix` | yes | § gha-cache schema | Surface: `gha-cache` |
| `git` | [`30-surface-protocols.md`](../30-surface-protocols.md) § `git` | `http-prefix`, `git-listen`, `ssh-listen` | no | `hashes` includes `git-blob-sha1` | Surface: `git` |
| `oci` | [`30-surface-protocols.md`](../30-surface-protocols.md) § `oci` | `http-prefix` | yes (`sync` only) | § oci schema | Surface: `oci` |
| `browse` | [`30-surface-protocols.md`](../30-surface-protocols.md) § `browse` | `http-prefix` | no | none | Surface: `browse` |
| `api` | [`30-surface-protocols.md`](../30-surface-protocols.md) § `api` | `http-prefix`, `unix-socket` | yes (the wire protocol's commit operations) | none | Surface: `api` |

## Endpoint kinds

| Kind | Form | Exclusive on |
| --- | --- | --- |
| `mount-path` | absolute directory path | the path |
| `device-node` | `/dev/...` node created by the surface | the node |
| `device-file` | host file backing a pmem device | the file |
| `vhost-user-socket` | unix socket path served to a monitor | the path |
| `nbd-socket` | unix socket path or `tcp://host:port` | the address |
| `unix-socket` | unix socket path | the path |
| `http-prefix` | `http(s)://host[:port]/prefix/` | `(listen address, prefix)` |
| `grpc-listen` | `grpc(s)://host:port` | the address |
| `git-listen` | `git://host:port` | the address |
| `ssh-listen` | `ssh://host:port` | the address |

## Schemas

### `nix-cache`

| Path | Kind | Required attributes |
| --- | --- | --- |
| `/` | root | `nix-cache-info.store_dir`, `nix-cache-info.priority` |
| `/<hash>-<name>` | file (NAR object) | `nar.hash_sha256`, `nar.size`, `nar.references` |

Optional per-entry: `nar.deriver`, `nar.signatures`, `nar.ca`,
`nar.file_hash`, `nar.file_size`, `nar.compression`.

### `reapi`

| Path | Kind | Required attributes |
| --- | --- | --- |
| `/` | root | `capabilities.digest_functions`, `capabilities.max_batch_total_size` |
| `/cas/<fn>/<hex>` | file | derived digest attribute for `<fn>` |
| `/ac/<fn>/<hex>` | file | `reapi.output_digests` |

### `gha-cache`

| Path | Kind | Required attributes |
| --- | --- | --- |
| `/<version>/<key>` | file | `gha.key`, `gha.version`, `gha.size`, `gha.created_at` |

### `oci`

| Path | Kind | Required attributes |
| --- | --- | --- |
| `/oci/blobs/<alg>/<hex>` | file | derived `sha256` (or `<alg>`) |
| `/oci/repositories/<name>/manifests/<digest>` | file | `oci.media_type`; optional `oci.subject` |
| `/oci/repositories/<name>/tags/<tag>` | symlink | target `../manifests/<digest>` |
| `/oci/repositories/<name>/referrers/<digest>/` | directory (derived) | symlinks to manifests |

### `git`

No path requirements. The root's `hashes` property lists `git-blob-sha1`
(and `git-blob-sha256` when the SHA-256 object format is advertised), so
every regular file entry carries `hash.git-blob-sha1` and, where enabled,
`hash.git-blob-sha256`.

### `fuse`, `erofs`, `mount`, `block`, `virtiofs`, `virtio-pmem`, `browse`, `api`

No schema. Where a view's policy declares canonical attributes, realizers
serve them (FUSE-22, EROFS-6).

## Reserved names

The names `mount`, `fuse`, `erofs`, `block`, `virtiofs`, `virtio-pmem`,
`nix-cache`, `reapi`, `gha-cache`, `git`, `oci`, `browse`, and `api` are
reserved by this registry. Implementation-specific experimental surfaces
MUST use a name beginning with `x-` and MUST NOT be claimed as conformant.
