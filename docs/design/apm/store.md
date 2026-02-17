# Nix Store Integration

## Overview

`apm` (`aos package`) uses the Nix store as its package storage backend.
Packages are Nix store paths. Installation means downloading a NAR, importing
it into the shared store, creating GC roots in a profile, and rebuilding the
profile's merged FHS layout. Removal means deleting those roots and rebuilding.

`apm` can install packages into two targets:

- **System profile** (`/var/lib/profiles/system/`) -- shared across all users,
  requires root. Analogous to `apt install`.
- **User profile** (`/var/lib/profiles/per-user/$USER/`) -- per-user, no root
  required. Default target.

Both targets share the same underlying Nix store at `/var/lib/store/`. When
multiple profiles install the same package, the store path exists only once --
each profile simply has its own GC root pointing to it. Deduplication is
automatic and transparent.

## Directory Layout

```
/var/lib/
├── store/                                  <- shared Nix content-addressed store
├── db/                                     <- Nix database (SQLite)
├── profiles/                               <- generation-based install profiles
│   ├── system/                             <- system profile (requires root)
│   │   ├── current -> gen-42
│   │   ├── gen-42/                         <- active generation
│   │   │   ├── usr/{hash} -> /var/lib/store/...     (GC roots)
│   │   │   ├── src/{hash} -> /var/lib/store/...     (source roots)
│   │   │   ├── bin/                                  (executables)
│   │   │   ├── sbin/                                 (system executables)
│   │   │   ├── lib/                                  (libraries + pkgconfig)
│   │   │   ├── include/                              (headers)
│   │   │   ├── share/                                (man, info, etc.)
│   │   │   └── etc/                                  (config defaults)
│   │   ├── gen-41/                         <- previous generation (rollback)
│   │   ├── meta/                           <- per-path metadata
│   │   │   └── {hash}.json
│   │   └── state.json                      <- generation counter and active generation pointer
│   └── per-user/
│       └── $USER/                          <- user profile (non-root)
│           ├── current -> gen-12
│           ├── gen-12/                     <- (same structure as system)
│           ├── meta/
│           │   └── {hash}.json
│           └── state.json
├── views/                                  <- cache server projections
│   ├── ci/
│   │   ├── usr/{hash} -> /var/lib/store/...
│   │   ├── src/{hash} -> /var/lib/store/...
│   │   └── bin/{name} -> ../usr/{hash}
│   └── prod/
│       └── ...
└── gcroots/                                <- GC root registry
    ├── profiles -> /var/lib/profiles       <- Nix GC follows into profiles
    └── views -> /var/lib/views             <- Nix GC follows into views

/etc/apm/                                   <- system config (overlay, configured via cloud-init)
├── apm.conf                                <- system-wide defaults
├── registries.d/                           <- default registries for all users + system profile
│   ├── aos-core.toml
│   └── aos-extra.toml
└── trusted-keys.d/                         <- system-wide trusted signing keys

~/.config/apm/                              <- user config (XDG)
├── apm.conf                                <- user overrides
├── registries.d/                           <- user-added or overridden registries
│   └── company-internal.toml
└── trusted-keys.d/                         <- user-added trusted signing keys

~/.local/share/apm/                         <- user data (XDG)
└── remote/                                 <- registry metadata (via bundles or git)
    ├── aos-core/
    └── aos-extra/

~/.cache/apm/                               <- NAR download cache (XDG)
└── *.nar.zst
```

The Nix daemon creates `/var/lib/profiles/per-user/$USER/` with correct
ownership on first use. No root privileges are needed for user profile
operations -- the daemon handles store imports via its socket protocol.

---

## Views

Views are projections into a registry or cache. They are used by the
`aos serve` cache server to organize GC roots by build pipeline (e.g., `ci/`,
`prod/`). Views use a UNIX filesystem-inspired layout:

```
/var/lib/views/{name}/
├── usr/                                (hash-keyed GC roots)
│   ├── h7j3k8l2m9n4 -> /var/lib/store/h7j3k8l2m9n4...-curl-8.5.0
│   ├── xr5is7by89v3q -> /var/lib/store/xr5is7by89v3q...-openssl-3.2.0
│   └── ...
├── src/                                (source derivation GC roots)
│   ├── def456ghi789 -> /var/lib/store/def456ghi789...-curl-8.5.0.drv
│   └── ...
└── bin/                                (name index)
    ├── curl -> ../usr/h7j3k8l2m9n4
    ├── openssl -> ../usr/xr5is7by89v3q
    └── ...
```

- **`usr/{hash}`** -- GC roots. Each symlink points to a store path. The Nix
  garbage collector follows these to determine which store paths are alive.
- **`src/{hash}`** -- Source derivation roots for reproducible build
  verification.
- **`bin/{name}`** -- Name index mapping package names to their root in `usr/`.
  Provides human-readable enumeration (`ls bin/`) and name uniqueness.

Views are **not** profiles -- they don't have merged FHS symlinks for PATH
usage. They exist purely to root store paths for the cache server.

---

## Why Views and Profiles Are Separate Structures

Views and profiles share the same GC root primitives (`usr/{hash}` +
`src/{hash}`) but solve fundamentally different problems. The layers built
on top of those roots diverge enough to warrant distinct structures:

| | Views | Profiles |
|---|---|---|
| **Question answered** | "Which store paths should the cache keep alive?" | "What packages are installed, and how do they appear on disk?" |
| **Location** | `/var/lib/views/{name}/` | `/var/lib/profiles/{system,per-user/$USER}/` |
| **Managed by** | `aos serve` (cache server) | `apm` (package manager) |
| **GC roots** | `usr/{hash}` + `src/{hash}` | `usr/{hash}` + `src/{hash}` (same) |
| **`bin/` semantics** | Name index: `curl -> ../usr/{hash}` (package name to GC root) | Merged FHS: `curl -> /var/lib/store/{hash}-curl/bin/curl` (executable file) |
| **Generations** | No -- flat, mutable set of roots | Yes -- every mutation creates an immutable generation |
| **Merged FHS tree** | No | Yes -- `bin/`, `sbin/`, `lib/`, `include/`, `share/`, `etc/` |
| **TTL / expiry** | Yes -- cache eviction policies per view | No -- packages persist until explicitly removed |
| **Rollback** | No | Yes -- atomic symlink swap to a previous generation |
| **Conflict detection** | No -- views don't merge files | Yes -- two packages shipping the same `bin/foo` is an error |
| **User-facing** | No -- internal to the cache server | Yes -- `current/bin` goes on `$PATH` |

**Convergence point:** The shared `usr/` + `src/` root layout means the same
Rust code (`views.rs`) creates and walks GC roots in both structures. `aos gc`
doesn't need to know whether it's scanning a view or a profile -- it just
follows `usr/{hash}` symlinks to find live store paths.

**Divergence point:** Everything above the GC root layer is different. Views
are a flat retention mechanism for the cache server (which paths to keep, for
how long). Profiles are a user-facing installation mechanism (which packages
are installed, how they appear as a usable filesystem, how to roll back).

---

## Profiles

Profiles are generation-based install targets. Both system and user profiles
share the same structure and implementation mechanism. Each generation is a
self-contained directory that combines GC roots with a merged UNIX FHS symlink
tree.

### Profile Structure

Each generation emulates a traditional UNIX filesystem layout:

```
gen-N/
├── usr/                                    (GC roots -- hash-keyed)
│   ├── h7j3k8l2m9n4 -> /var/lib/store/h7j3k8l2m9n4...-curl-8.5.0
│   ├── xr5is7by89v3q -> /var/lib/store/xr5is7by89v3q...-openssl-3.2.0
│   ├── r4q1m2kp8v3x -> /var/lib/store/r4q1m2kp8v3x...-zlib-1.3.1
│   └── ...
├── src/                                    (source derivation GC roots)
│   ├── def456ghi789 -> /var/lib/store/def456ghi789...-curl-8.5.0.drv
│   └── ...
├── bin/                                    (executables -- merged from store paths)
│   ├── curl -> /var/lib/store/{hash}-curl-8.5.0/bin/curl
│   ├── openssl -> /var/lib/store/{hash}-openssl-3.2.0/bin/openssl
│   └── ...
├── sbin/                                   (system executables)
│   └── ...
├── lib/                                    (shared libraries)
│   ├── libcurl.so.4 -> /var/lib/store/{hash}-curl-8.5.0/lib/libcurl.so.4
│   ├── libssl.so.3 -> /var/lib/store/{hash}-openssl-3.2.0/lib/libssl.so.3
│   └── pkgconfig/
│       ├── libcurl.pc -> /var/lib/store/{hash}-curl-8.5.0/lib/pkgconfig/libcurl.pc
│       └── ...
├── include/                                (development headers)
│   ├── curl/ -> /var/lib/store/{hash}-curl-8.5.0/include/curl
│   └── openssl/ -> /var/lib/store/{hash}-openssl-3.2.0/include/openssl
├── share/                                  (architecture-independent data)
│   ├── man/
│   │   └── man1/curl.1 -> /var/lib/store/{hash}-curl-8.5.0/share/man/man1/curl.1
│   ├── info/
│   └── applications/
└── etc/                                    (default configuration files)
    └── ...
```

The generation directory serves dual purposes:

1. **GC roots** -- `usr/{hash}` symlinks keep store paths alive. The Nix
   garbage collector follows these to decide what to keep.
2. **Merged FHS view** -- `bin/`, `sbin/`, `lib/`, `include/`, `share/`,
   `etc/` directories provide a usable UNIX layout. Users add
   `current/bin` to their PATH and get working executables.

Every package in the closure gets a `usr/{hash}` entry (GC root). Only
packages that provide executables get `bin/` entries; only packages with
libraries get `lib/` entries; etc.

### System Profile

Located at `/var/lib/profiles/system/`. Requires root for modifications.
Visible to all users.

```
/var/lib/profiles/system/
├── current -> gen-42               <- atomic symlink to active generation
├── gen-42/
│   └── ... (generation structure above)
├── gen-41/                         <- previous generation (rollback target)
├── meta/                           <- per-path metadata JSON
│   └── {hash}.json
└── state.json                      <- generation counter and active generation pointer
```

### User Profile

Located at `/var/lib/profiles/per-user/$USER/`. No root required. The Nix
daemon creates the per-user directory with correct ownership on first use.

```
/var/lib/profiles/per-user/$USER/
├── current -> gen-12               <- atomic symlink
├── gen-12/
│   └── ... (same generation structure)
├── meta/
│   └── {hash}.json
└── state.json
```

### PATH Ordering

The golden image does not merge system binaries into a single directory.
Instead, the toplevel derivation writes `/etc/aos/system-path` — a file
containing colon-separated `bin/` directories for each system package. PATH
is assembled from three layers:

```
PATH=/var/lib/profiles/per-user/$USER/current/bin:/var/lib/profiles/per-user/$USER/current/sbin:/var/lib/profiles/system/current/bin:/var/lib/profiles/system/current/sbin:$(<cat /etc/aos/system-path)
```

1. **User profile** (`/var/lib/profiles/per-user/$USER/current/`) -- per-user
   `apm` installs (merged FHS), highest priority
2. **System profile** (`/var/lib/profiles/system/current/`) -- system-wide
   `apm` installs (merged FHS)
3. **Golden image** (`/etc/aos/system-path`) -- individual store-path `bin/`
   entries, immutable, lowest priority

This follows standard Unix PATH prepend semantics: user-specific entries come
first, so user-installed packages shadow system-wide and golden-image versions.
`apm list` annotates packages that are shadowed.

### Generation Mechanism

Every `apm install`, `apm remove`, or `apm upgrade` creates a new generation:

1. **Enumerate** -- Scan `meta/` to collect all installed packages and resolve
   their store paths.

2. **Build GC roots** -- Create `usr/{hash}` symlinks for all closure paths.

3. **Merge FHS layout** -- For each package, scan its store path for `bin/`,
   `sbin/`, `lib/`, `include/`, `share/`, `etc/` and create corresponding
   symlinks in the generation directory.

4. **Conflict detection** -- If two packages provide the same file (e.g., both
   ship `bin/python3`), the build fails with a clear error listing the
   conflicting packages.

5. **Atomic switch** -- Write the new generation directory, bump the counter in
   `state.json`, then `rename(2)` the `current` symlink.

The profile is built entirely in Rust -- no Nix daemon dependency, no
`buildEnv` derivation. Rebuilding takes ~100ms for typical installations.

Rollback is instantaneous -- a single symlink switch:

```sh
# System profile rollback
ln -sfn gen-41 /var/lib/profiles/system/current

# User profile rollback
ln -sfn gen-11 /var/lib/profiles/per-user/$USER/current
```

Old generations are kept until explicitly removed with `apm clean
--generations`. By default, APM retains the last 3 generations for rollback.

Note: `meta/` lives at the profile level, not inside each generation. When
`apm rollback` switches to a previous generation, it rebuilds `meta/` from
the target generation's `usr/` roots by cross-referencing with the registry.
This addresses the atomicity gap where `meta/` is profile-level but
generations are atomic snapshots.

### Multi-Profile Deduplication

The Nix store is shared across all profiles. When the system profile and a user
profile both install curl, the store path exists only once on disk:

```
/var/lib/profiles/
├── system/gen-42/usr/{hash} -> /var/lib/store/{hash}-curl-8.5.0
└── per-user/dylan/gen-12/usr/{hash} -> /var/lib/store/{hash}-curl-8.5.0
                                        ^ same store path, deduplicated
```

`aos gc --collect` only reclaims store paths that have zero roots across all
profiles and views.

---

## GC Root Management

> **Convergence note:** Profiles and views share the same `usr/` + `src/`
> root structure. The only difference is that profiles add the merged FHS
> layout (`bin/`, `lib/`, etc.) on top. See [convergence.md](convergence.md).

### Root Directories

GC roots are symlinks in `usr/` that point to store paths. The Nix garbage
collector recursively scans `/var/lib/gcroots/`, which contains symlinks to
`/var/lib/profiles/` and `/var/lib/views/`, and follows the `usr/{hash}`
entries to determine which store paths are alive.

### Properties

1. **Hash-keyed roots** -- GC roots in `usr/` use store path hashes,
   matching the cache server's view convention. This is the canonical
   root structure shared across views and profiles.

2. **Every closure path gets a root** -- Both explicitly installed packages
   and their transitive dependencies get `usr/{hash}` entries. This lets
   `apm autoremove` reason about orphans.

3. **Explicit vs automatic** -- Per-path metadata tracks whether a package
   was explicitly installed or pulled in as a dependency:

   ```
   /var/lib/profiles/{system,per-user/$USER}/meta/{hash}.json
   ```

4. **Flat namespace with registry provenance** -- Each package's metadata
   records which registry it came from (`apm.registry`). Name conflicts
   across registries are rejected at install time.

### Metadata (Per-Path JSON)

APM uses the same per-path JSON sidecar format as the cache server, extended
with an `apm` section. Metadata lives alongside the profile at
`/var/lib/profiles/{system,per-user/$USER}/meta/{hash}.json`:

```json
{
  "store_path": "/var/lib/store/h7j3k8l2m9n4...-curl-8.5.0",
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

The `apm.registry` field records provenance. `apm upgrade` uses it to check
the correct registry for newer versions. The base fields (`store_path`,
`pushed_at`, `expires_at`, `is_root`) are shared with the cache server
metadata schema, so `aos gc` can process all metadata uniformly.

### GC Roots for Dependencies

For `apm autoremove` to work, dependencies that were only installed as
transitive requirements need their own GC roots (so APM can enumerate them).

Strategy: **every package in the closure gets a `usr/{hash}` root**, but only
explicitly installed packages have `apm.explicit = true` in their metadata.

```
/var/lib/profiles/per-user/$USER/gen-12/usr/
  h7j3k8l2 -> /var/lib/store/...-curl-8.5.0         # explicit
  xr5is7by -> /var/lib/store/...-openssl-3.2.0       # auto (dep of curl)
  r4q1m2kp -> /var/lib/store/...-zlib-1.3.1          # auto (dep of curl, openssl)
  q8mn2pv7 -> /var/lib/store/...-nghttp2-1.58.0      # auto (dep of curl)
  kl9m3n0o -> /var/lib/store/...-cacert-2024.01      # auto (dep of curl, openssl)
```

When `apm remove curl` runs:

1. Remove curl's metadata from `meta/`
2. Check which `apm.explicit = false` packages are no longer needed by any
   explicit package (`openssl`, `zlib`, `nghttp2`, `cacert` become orphans)
3. Build a new generation without curl's roots and FHS entries
4. `apm autoremove` removes orphan metadata; new generation omits their roots
5. `aos gc --collect` reclaims store paths with zero roots across all profiles

---

## Installation Flow

### Target Selection

```
apm install curl               # installs to user profile (default)
apm install --system curl      # installs to system profile (requires root)
sudo apm install curl          # also targets system profile when run as root
```

### Step-by-Step

```
apm install curl
```

1. **Resolve package** -- Look up `curl` in registries by priority. Find
   `curl.toml` in the registry, select latest version for platform.

2. **Check store_dir** -- Verify the registry's `store_dir` matches the
   local store root (`/var/lib/store`). Reject immediately if mismatched.

3. **Compute closure** -- Walk the `references` field in the TOML
   transitively. All references are resolved within the same registry as
   the parent package -- dependency resolution is registry-scoped. For each
   referenced hash, look it up in the registry's hash index to get its own
   references. This produces the full set of store paths needed:
   `{curl, openssl, zlib, nghttp2, cacert}`

4. **Diff against store** -- Check which store paths in the closure already
   exist locally (via `nix-store --check-validity` or SQLite query). Only
   download what's missing.

5. **Display transaction** -- Show the user what will be installed:
   ```
   The following NEW packages will be installed:
     curl  nghttp2  cacert
   The following closure paths are already in store:
     openssl (3.2.0)  zlib (1.3.1)
   3 paths to download, 5.2 MiB to download (52 MiB closure).
   Do you want to continue? [Y/n]
   ```

6. **Download NARs** -- For each missing store path, download the compressed
   NAR from the first available mirror:
   ```
   GET <mirror_url>/<nar_hash>.nar.zst
   ```
   Downloads run in parallel (configurable, default 4). Any referenced path
   that doesn't correspond to a named package in the registry is downloaded
   as a raw store path (bootstrap deps like glibc).

7. **Verify hashes** -- After download, compute SHA-256 of the compressed
   NAR and compare against `download_hash` from the TOML. If mismatch,
   abort and report.

8. **Decompress** -- Decompress `.nar.zst` to `.nar` using zstd.

9. **Verify NAR hash** -- Compute hash of the decompressed NAR and compare
   against `nar_hash` from the TOML. This is a second verification layer.

10. **Import to store** -- Import the NAR into the shared Nix store via the
    daemon socket:
    ```
    nix-store --import < ~/.cache/apm/curl-8.5.0.nar
    ```
    This creates the store path and registers all its references in the
    Nix DB's `Refs` table. The daemon validates that all referenced paths
    exist in the store.

11. **Verify store path** -- Confirm the resulting store path matches the
    `store_path` recorded in the package TOML. If the paths diverge, the
    NAR content does not correspond to the expected package and the install
    is aborted.

12. **Write metadata** -- Create per-path JSON in the target profile's `meta/`
    directory, marking `curl` as `apm.explicit = true` and closure deps as
    `apm.explicit = false`. Each entry includes `apm.registry` for provenance.

13. **Build new generation** -- Create a new generation directory containing:
    - `usr/{hash}` GC roots for every closure path
    - `src/{hash}` roots for source derivations
    - Merged FHS symlinks (`bin/`, `lib/`, `include/`, `share/`, `etc/`)
    Atomically switch `current` to the new generation.

### Atomicity

The installation is **atomic at the generation level**: the old generation
remains active until the `current` symlink is switched. If the process crashes
during generation build, the previous generation stays active and any imported
store paths without roots are cleaned up on the next `aos gc --collect`.

For multi-package installs, the new generation is only written after ALL NARs
are successfully downloaded, verified, and imported. This prevents partial
installation states.

### NAR Cache

Downloaded NARs are cached in `~/.cache/apm/` for potential reuse
(reinstall, rollback). `apm clean` removes this cache.

---

## Removal Flow

### Step-by-Step

```
apm remove curl
```

1. **Verify installed** -- Check that the target profile's `meta/` contains
   curl as an installed package.

2. **Check reverse deps** -- Scan metadata for other explicit packages
   that depend on `curl`. If any, warn the user:
   ```
   WARNING: The following packages depend on curl:
     libcurl-dev
   Remove anyway? [y/N]
   ```

3. **Remove metadata** -- Delete curl's entry from `meta/`.

4. **Build new generation** -- Create a new generation directory without
   curl's `usr/` root or FHS entries. Atomically switch `current`.

5. **Report orphans** -- List packages that are now only installed as
   dependencies of the removed package:
   ```
   The following packages are no longer required:
     nghttp2  cacert
   Use 'apm autoremove' to remove them.
   ```

### `apm autoremove`

1. Scan `meta/` for entries where `apm.explicit = false`
2. For each, check if any `apm.explicit = true` package transitively depends
   on it
3. If orphaned, remove its metadata
4. Build new generation (orphaned paths are excluded from `usr/` and FHS)
5. `aos gc --collect` reclaims store paths with zero roots across all profiles

---

## NAR Download System

### Mirror Selection

1. Mirrors are listed in the registry's `registry.toml` under `[[mirrors]]`
2. `apm` tries mirrors in listed order
3. If a mirror fails (timeout, 404, hash mismatch), fall through to the next
4. A mirror that consistently fails is temporarily deprioritized for the
   session

### Parallel Downloads

- Default: 4 concurrent downloads (configurable)
- Each NAR is downloaded independently
- Progress is shown per-package with overall progress bar

### Compression

NARs are served compressed. The standard format is **zstd** (`.nar.zst`):

- zstd provides excellent compression ratios and fast decompression
- The `download_hash` in the TOML refers to the compressed file
- The `nar_hash` refers to the decompressed NAR

### Resume Support

If a download is interrupted, `apm` supports HTTP range requests to resume
partial downloads. The NAR cache retains partial files with a `.partial` suffix.

---

## Comparison with Nix Binary Caches

### How Nix Binary Caches Work

Nix's built-in substituter system uses `.narinfo` files:

```
# https://cache.nixos.org/abc123.narinfo
StorePath: /var/lib/store/abc123...-openssl-3.2.0
URL: nar/abc123.nar.xz
Compression: xz
FileHash: sha256:...
FileSize: 5242880
NarHash: sha256:...
NarSize: 14893056
References: /var/lib/store/...-zlib-1.3.1 /var/lib/store/...-glibc-2.38
Sig: cache.nixos.org-1:base64sig...
```

The substituter checks if a store path exists in the cache, downloads the
narinfo, then the NAR.

### How APM Differs

| Aspect | Nix Binary Cache | APM |
|--------|-----------------|-----|
| **Index** | Per-path narinfo files (HTTP) | TOML files via HTTP bundles (or git) |
| **Discovery** | By store path hash | By package name |
| **Guarantee** | Best-effort (may not have your path) | Strict (registry = built & tested) |
| **Versioning** | None (immutable store paths) | Semver tags for registry state |
| **Dependencies** | Store-level references only | Named package-level deps |
| **User model** | Developer-facing (store paths) | User-facing (package names) |
| **Overlay** | Substituter priority | Registry priority |
| **Offline audit** | Possible but manual | `apm source --verify` |
| **Metadata** | Minimal (narinfo) | Rich (TOML: description, license, etc.) |

### Why Both Can Coexist

`apm` and Nix binary caches operate at different levels:

- **Nix binary cache** (including `aos serve`) is a low-level
  content-addressed store accelerator. It answers: "Do you have this exact
  store path?"

- **apm** is a high-level package manager. It answers: "What is the latest
  version of `curl` and how do I get it installed?"

`apm` could theoretically use `aos serve` as a mirror backend -- the cache
server already serves NARs at `GET /:view/nar/{hash}.nar.zst`. An APM
registry's `[[mirrors]]` could point to an `aos serve` instance, letting
organizations use a single server for both CI caching and APM package
distribution.

---

## Source Derivation Tracking

### What's Stored

Each package version's TOML includes:

- `source_drv` -- The Nix store path of the `.drv` file that produces this
  package from source
- `source_nar_hash` -- The NAR hash of the source derivation itself

### Verification Flow

```
apm source --verify openssl
```

1. Fetch the source derivation NAR from mirrors
2. Import it into the local Nix store
3. Recursively fetch all input derivations (build deps, source tarballs)
4. Build the derivation locally: `nix-store --realise <source_drv>`
5. Compare the output store path with the installed binary's store path
6. Report match/mismatch

This enables any user to independently verify that the binary they installed
was built from the claimed source, using the claimed build process, with no
hidden modifications.

Note: `nar_hash` is not stored in the installed metadata (`meta/`), so
`apm source --verify` must consult the registry to obtain expected hashes.
If the registry is unavailable (e.g., removed or offline), verification
cannot proceed.

### Trust Model

The source derivation is the ground truth. If you trust the Nix evaluation
that produced the `.drv` file (which you can audit -- it's deterministic from
the AOS repository), and you trust the build sandbox (Nix builds in isolation),
then a matching hash proves the binary is exactly what the source says it
should be.
