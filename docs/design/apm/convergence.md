# APM / Cache Server Convergence

## Overview

The `aos serve` cache server (docs/design/aos-cache/) and `apm` package manager
both manage GC roots in the Nix store. This document identifies where the two
systems converge and how the designs should align.

## Critical Alignment: AOS_ROOT

AOS compiles Nix with `/var/lib/` as its store root — the `/nix/` directory
does not exist on an AOS system. All paths in the APM design must use
`AOS_ROOT` (`/var/lib/`) instead of `/nix/`.

| APM originally assumed | Correct AOS path |
|------------------------|-------------------|
| `/nix/store/...` | `/var/lib/store/...` |
| `/nix/var/nix/gcroots/...` | `/var/lib/gcroots/` (symlinks to `/var/lib/profiles/` and `/var/lib/views/`) |
| `nix-collect-garbage` | `aos gc --collect` |

## Views vs Profiles

Views and profiles are two distinct structures that share the same GC root
primitives (`usr/{hash}` + `src/{hash}`) but serve fundamentally different
purposes:

- **Views** (`/var/lib/views/{name}/`) are **retention mechanisms** for the
  cache server. They answer: "which store paths should the cache keep alive?"
  Views are flat, mutable, support TTL-based expiry, and have a `bin/{name}`
  name index that maps package names to GC roots. They are not user-facing.

- **Profiles** (`/var/lib/profiles/`) are **installation mechanisms** for APM.
  They answer: "what packages are installed, and how do they appear as a usable
  filesystem?" Profiles are generation-based (immutable snapshots with atomic
  switching and rollback), have a merged FHS tree (`bin/`, `lib/`, `share/`,
  etc.) with file-level symlinks into the store, and are user-facing (added to
  `$PATH`).

The convergence point is the `usr/{hash}` + `src/{hash}` root layout — the
same Rust code walks both for garbage collection. The divergence is everything
above that: views are flat and ephemeral; profiles are generational and
user-facing. See [store.md](store.md) for the full structural comparison.

`apm` installs to a **system profile** (with `sudo`) or a **user profile**
(default, non-root):

- System profile: `/var/lib/profiles/system/`
- User profile: `/var/lib/profiles/per-user/$USER/`

Each profile is generation-based. Installing or removing packages creates a new
generation. Profiles use a UNIX FHS layout so the active generation can be
added directly to `$PATH`, `$LD_LIBRARY_PATH`, etc.

```
/var/lib/
├── store/                                   ← Nix store
├── gcroots/                                 ← global GC root anchor
├── views/                                   ← cache server projections
│   ├── ci/
│   │   ├── usr/{hash} -> /var/lib/store/{hash}-curl-8.5.0
│   │   ├── src/{hash} -> /var/lib/store/{hash}-curl-8.5.0.drv
│   │   └── bin/
│   │       └── curl -> ../usr/{hash}
│   └── prod/
│       ├── usr/{hash} -> ...
│       ├── src/{hash} -> ...
│       └── bin/
│           └── nginx -> ../usr/{hash}
└── profiles/                                ← apm install targets
    ├── system/
    │   ├── current -> gen-2                 ← atomic symlink to active generation
    │   ├── gen-1/                           ← generation 1
    │   │   ├── usr/{hash} -> /var/lib/store/{hash}-curl-8.5.0
    │   │   ├── src/{hash} -> /var/lib/store/{hash}-curl-8.5.0.drv
    │   │   ├── bin/                         ← executables
    │   │   ├── sbin/                        ← system executables
    │   │   ├── lib/                         ← libraries
    │   │   ├── include/                     ← headers
    │   │   ├── share/                       ← data files
    │   │   └── etc/                         ← configuration
    │   ├── gen-2/                           ← generation 2 (latest)
    │   │   ├── usr/{hash} -> ...
    │   │   ├── src/{hash} -> ...
    │   │   ├── bin/
    │   │   ├── sbin/
    │   │   ├── lib/
    │   │   ├── include/
    │   │   ├── share/
    │   │   └── etc/
    │   ├── meta/
    │   │   ├── {hash}.json                  ← per-path metadata
    │   │   └── {hash}.json
    │   └── state.json                       ← generation counter and active generation pointer
    └── per-user/
        └── $USER/
            ├── current -> gen-1             ← atomic symlink to active generation
            ├── gen-1/
            │   ├── usr/{hash} -> ...
            │   ├── src/{hash} -> ...
            │   ├── bin/
            │   ├── sbin/
            │   ├── lib/
            │   ├── include/
            │   ├── share/
            │   └── etc/
            ├── meta/
            │   └── {hash}.json
            └── state.json                   ← generation counter and active generation pointer

~/.local/share/apm/
└── remote/                                  ← registry caches (metadata only)
    ├── aos-core/
    └── aos-extra/

~/.config/apm/
└── registries.d/                            ← per-user registry config
```

This means:

1. **Single namespace per profile** — all packages live in the current
   generation of the profile. Name uniqueness is enforced at install time.
   Per-path metadata in `meta/` records which registry each package came from
   (`apm.registry` field in the JSON sidecar).
2. **Store paths are deduplicated across users** — if two users install the
   same `zlib-1.3.1`, the store path exists once. Each profile has its own
   GC roots. The metadata records the originating registry for provenance.
3. **Consistent metadata format** — per-path JSON sidecars in the profile's
   `meta/` directory instead of a monolithic `state.toml`.
4. **Registry removal requires clean uninstall** — `apm registry remove
   aos-extra` refuses if any installed packages have `apm.registry =
   "aos-extra"` in their `meta/` entry. The user must first `apm remove`
   those packages (or `apm reinstall` them from another registry). This
   prevents orphaned packages that can never be upgraded or verified.
5. **Registry caches are separate** — `~/.local/share/apm/remote/` holds
   registry metadata (populated via HTTP bundles or git fetch) used by
   `apm update`. These are not GC roots and can be re-synced at any time.
6. **Generation rollback** — `apm rollback` switches the active generation
   symlink to a previous `gen-N/`. Previous generations are kept until
   explicitly garbage-collected.

## GC Root Naming: Hash vs Name

The cache server uses **hash-keyed** symlinks (`views/{name}/usr/{hash}`).
APM profiles also use **hash-keyed** roots in `gen-N/usr/` for GC, and the
FHS directories (`bin/`, `lib/`, etc.) provide name-based access.

Views (cache server) provide a **name index** via `bin/{name}` symlinks that
point to `../usr/{hash}`:

```
/var/lib/views/prod/
├── usr/{hash} -> /var/lib/store/{hash}-curl-8.5.0    (GC root — keeps path alive)
├── src/{hash} -> /var/lib/store/{hash}-curl-8.5.0.drv (source drv root)
└── bin/
    └── curl -> ../usr/{hash}                          (name index — human lookup)
```

Profiles use the FHS layout directly — `gen-N/bin/curl` is a real executable
or symlink into the store, not a name index:

```
/var/lib/profiles/per-user/$USER/
├── gen-3/
│   ├── usr/{hash} -> /var/lib/store/{hash}-curl-8.5.0    (GC root)
│   ├── src/{hash} -> /var/lib/store/{hash}-curl-8.5.0.drv (source root)
│   ├── bin/
│   │   └── curl -> /var/lib/store/{hash}-curl-8.5.0/bin/curl
│   ├── lib/
│   │   └── libcurl.so.4 -> /var/lib/store/{hash}-curl-8.5.0/lib/libcurl.so.4
│   ├── include/
│   ├── share/
│   └── etc/
└── meta/
    └── {hash}.json
```

The `bin/` directory in views is a name index (symlinks to `../usr/{hash}`).
The `bin/` directory in profiles is a merged FHS tree (symlinks into store
paths). Both `usr/` and `src/` directories share the same hash-keyed GC root
structure, which is the key convergence point.

## Metadata Convergence

### Cache Server Metadata (per-path JSON)

```json
{
  "store_path": "/var/lib/store/abc123-curl-8.5.0",
  "pushed_at": 1706000000,
  "pushed_by": "ci-token",
  "expires_at": 1706604800,
  "is_root": true,
  "last_accessed": 1706500000,
  "access_count": 42
}
```

### APM Metadata (extended per-path JSON)

```json
{
  "store_path": "/var/lib/store/abc123-curl-8.5.0",
  "pushed_at": 1707800000,
  "pushed_by": "apm",
  "expires_at": null,
  "is_root": true,
  "last_accessed": 1707800000,
  "access_count": 0,

  "apm": {
    "name": "curl",
    "version": "8.5.0",
    "explicit": true,
    "registry": "aos-core",
    "installed_at": "2026-02-13T10:30:00Z",
    "held": false
  }
}
```

APM extends the base metadata schema with an `apm` section. The base fields
(`store_path`, `pushed_at`, `expires_at`, `is_root`) are identical to cache
server metadata. This means:

- Cache server code can read APM metadata (ignores the `apm` section)
- APM code can read cache server metadata (ignores missing `apm` section)
- `aos gc` treats all metadata uniformly for TTL/eviction purposes

### What replaces state.toml?

The monolithic `state.toml` is replaced by the profile's `meta/` directory:

| Was in state.toml | Now lives in |
|-------------------|-------------|
| `packages.curl.explicit` | `meta/{hash}.json` -> `apm.explicit` |
| `packages.curl.version` | `meta/{hash}.json` -> `apm.version` |
| `packages.curl.registry` | `meta/{hash}.json` -> `apm.registry` |
| `packages.curl.installed` | `meta/{hash}.json` -> `apm.installed_at` |
| `holds.openssl` | `meta/{hash}.json` -> `apm.held: true` |
| `registries.aos-core.last_commit` | `~/.config/apm/registries.d/` (per-user registry config) |

## GC Integration

### Profile TTL policy

```toml
# Implicit config for APM profiles (not in serve.toml — built into apm)
[profile]
ttl = "none"            # user-installed packages never auto-expire
source_ttl = "none"     # source derivations kept indefinitely
source_mirror = true    # track source derivations for all installed packages
```

### Autoremove as GC

`apm autoremove` is APM-specific logic on top of the standard GC:

1. Find all `meta/{hash}.json` where `apm.explicit = false`
2. Check if any `apm.explicit = true` package transitively depends on it
3. If orphaned, remove the GC root from the current generation and delete the metadata
4. `aos gc --collect` handles actual store path deletion

### `apm gc` = `aos gc --collect`

They're the same operation. `apm gc` is sugar for cleaning up stale profile
generations and running Nix garbage collection. For a user profile, it removes
old generations (keeping the latest N); for a system profile, `sudo apm gc`
does the same.

## NAR Download Convergence

Both systems download NARs from remote servers:

- **Cache server client** (`aos build --remote`): downloads NARs from
  `aos serve` via the Nix substituter protocol (narinfo + NAR)
- **APM**: downloads NARs from registry-defined HTTPS mirrors

The transport layer is different (Nix substituter vs direct HTTPS), but the
NAR format is identical. APM could potentially use `aos serve` as a mirror
backend, but this is not required — APM mirrors are simpler (flat HTTPS,
no narinfo lookup).

### Could APM use the cache server as a mirror?

Yes, in theory. An APM registry's `[[mirrors]]` could point to an `aos serve`
instance:

```toml
[[mirrors]]
url = "https://cache.aos.dev/prod"
name = "aos-cache"
```

The cache server already serves NARs at `GET /:view/nar/{hash}.nar.zst`.
APM would need to construct the URL from the store path hash, which it
already has in the package TOML. This would let organizations use a single
`aos serve` instance as both a CI binary cache and an APM package mirror.

## Source Derivation Convergence

Both systems track source derivations:

- **Cache server**: creates `views/{name}/src/{hash}` roots for
  fixed-output source inputs after builds
- **APM**: creates `gen-N/src/{hash}` roots in the active profile generation

These converge naturally: both use `src/{hash}` symlinks pointing to `.drv`
store paths. When APM installs a package, it creates source roots in the
current generation's `src/` using the same pattern as cache server views.
`apm source --fetch` downloads and roots the source derivation chain.
`apm source --verify` rebuilds and compares.

## Shared Rust Code

Both APM and the cache server live in the `aos` CLI. Shared modules:

| Module | Used by | Purpose |
|--------|---------|---------|
| `src/server/store.rs` | serve, apm | Nix store queries (SQLite, dump-path) |
| `src/server/views.rs` | serve, apm | GC root creation/removal, metadata I/O |
| `src/server/sign.rs` | serve, apm | NAR signing and verification |
| `src/nix.rs` | all | NixRunner subprocess wrapper |

APM adds new modules:

| Module | Purpose |
|--------|---------|
| `src/package/mod.rs` | APM subcommand dispatch |
| `src/package/registry.rs` | Registry sync (HTTP bundles or git fetch) and parse |
| `src/package/resolve.rs` | Registry-scoped closure resolution (all deps resolve within the same registry) |
| `src/package/download.rs` | NAR download from HTTPS mirrors |
| `src/package/state.rs` | Name index management, explicit/auto tracking |
| `src/package/profile.rs` | Profile building (merged symlink tree, generations) |

## Summary

| Aspect | Before (independent) | After (converged) |
|--------|---------------------|-------------------|
| GC root dir | `/nix/var/nix/gcroots/apm/` | `/var/lib/profiles/{system,per-user/$USER}/gen-N/usr/` |
| Root naming | Name-keyed (`curl -> ...`) | Hash-keyed `usr/{hash}` + FHS tree in profile, `bin/{name}` index in views |
| Profiles | N/A | Generation-based at `/var/lib/profiles/` with FHS layout |
| Views | N/A | Cache server projections at `/var/lib/views/` with `bin/{name}` index |
| Metadata | Monolithic `state.toml` | Per-path JSON in profile `meta/` dir (extends cache schema) |
| GC command | `apm gc` (separate) | `aos gc --collect` (unified) |
| Dep resolution | Named deps in registry | Closure walk via store references |
| Store root | `/nix/` | `/var/lib/` (AOS_ROOT) |
| Source tracking | TOML field only | Actual `src/` roots (shared structure between views and profiles) |
| Rust code | Independent modules | Shared `views.rs`, `store.rs` |
| Install target | Flat per-user dir | System profile (`sudo`) or user profile (default) |
| Registry caches | Mixed with GC roots | `~/.local/share/apm/remote/` (separate) |
| Registry config | In state.toml | `~/.config/apm/registries.d/` |
