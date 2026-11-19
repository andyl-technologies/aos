# Development builds

This page covers the day-to-day build loop for people changing the source
tree: the development shell, the `aos-dev` entry point, the shared VM image
cache, and the image reproducibility check. Contribution requirements are in
[`CONTRIBUTING.md`](../../../CONTRIBUTING.md).

## Development shell

Load the development shell through direnv or
`nix develop --accept-flake-config`. It puts `aos-dev` and the ordinary
packaged `aos` CLI in `PATH`:

```sh
aos --help
aos-dev run apm --help
aos-dev run apr --help
aos-dev cache init
aos-dev build package crucible --no-out-link
```

Tool-running commands (`aos-dev run`) fetch or build ordinary packaged binaries
on demand. Explicit development builds (`aos-dev build`) use shared compiler
caches.

The shell and `aos-dev` use the production experimental binary cache with
signature verification and source fallback, so an empty or unreachable cache
still permits source builds.

The [`aos-dev` section](../../../AGENTS.md#the-aos-dev-development-entry-point)
of `AGENTS.md` covers cache setup, the per-language cache flags, and
incremental Rust builds. [Rust builds](rust-builds.md#development-caches)
explains how the Cargo caches are keyed.

## VM image cache

Development VM and kernel-boot fleet tests materialize large images into the
local `images` cache and keep only small, closure-pinning recipes in the Nix
store. Each launch verifies the base image and creates a private reflink or
sparse copy of it.

```sh
aos-dev cache images status
aos-dev cache images prune --days 7 --max-gib 50
aos-dev --no-image-cache build check fleet.vm-artifact-reuse --no-out-link
```

### Location

Images live in `$AOS_DEV_CACHE_DIR/images`, mounted in the sandbox at
`/aos-build-cache/images` by default; `AOS_DEV_IMAGE_CACHE_DIR` selects the
sandbox path. Assembly scratch and the cache both require disk-backed storage.
Only completed images enter shared publication staging.

### Reuse and invalidation

- Changing assertions reuses the base image.
- Changing closures, tools, assembly, layout, or baked configuration selects
  another base.
- Missing or corrupt bases rebuild automatically.
- Image boot and integrity fixtures and interactive fleet launchers keep
  ordinary immutable images.

Existing realized test results still follow Nix reuse. To execute a check's VMs
again, change its assertions or rerun the check explicitly.

### Retention

Automatic maintenance retains at most 100 GiB of allocated idle bases for 14
days, oldest use first; active leases can temporarily exceed the bound. Pruning
skips active assembly and copy operations, reclaims abandoned staging, and keeps
lock files. It never removes source closures or private run disks.

### Trust and qualification

Builders must trust cache writers. The local integrity manifest detects
incomplete or corrupt entries, but it cannot authenticate a writer able to
replace both images and manifests.

For qualification, `--release` and `--no-cache` select ordinary derivations and
bypass the image cache, even alongside flags that enable caches.

## Image reproducibility

Shared ext4 root builders, headless assertion volumes, and fleet GPT assembly
normalize staged timestamps and ownership. They derive filesystem UUIDs,
directory hash seeds, and partition GUIDs from content and partition roles.

Independent cold ordinary builds and runtime recipe reconstructions are compared
byte for byte, including ext4 shrink/grow and the shared EROFS root builder:

```sh
aos-dev --release build check build.image-reproducibility --no-out-link
```

Normalization preserves modes, symlinks, extended attributes, and deliberate
staging hardlinks without modifying store inputs. Nix input copies discard
hardlinks introduced by store optimization, which NAR does not encode.

Different payloads receive different filesystem UUIDs. Identical image clones
retain their UUID and should not be mounted together by UUID.

This guarantee does not cover the separate production ESP/GPT assembly or guest
runtime provisioning, which continue to allocate fresh machine identities.
