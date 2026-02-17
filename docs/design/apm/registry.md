# APM Registry Structure

## Overview

An APM registry is a versioned collection of TOML metadata files describing
available packages. The registry does not contain package binaries — it only
contains metadata pointing to NAR files hosted on HTTPS mirrors.

Registries are **git repositories** internally — the git object model provides
cryptographic integrity for every file. However, the **transport** is
determined by the configured URI:

- **`https://` URI** (default) — HTTP bundle transport. The client downloads
  pre-built git bundle files (full snapshots and deltas) from static HTTP
  mirrors. No git server required — bundles are static files deployable via
  any CDN or HTTP server.

- **`git://` or `git+https://` URI** — Native git transport. The client uses
  `git clone`/`git fetch` directly against a git server. Useful for
  development, self-hosted registries, or environments where a git server is
  already available.

The registry's integrity properties come from the git object model regardless
of transport:

- **Versioning** — Registry state is referenced by semver tags (e.g., `v2026.02`)
- **Integrity** — Every TOML file (git blob) has a SHA hash; tampering changes
  the commit hash
- **Signing** — Commits can be GPG-signed; the client verifies signatures after
  import regardless of how the objects arrived
- **Efficiency** — Delta bundles transfer only changes between versions

## Repository Layout

```
registry.toml                    # Registry metadata and mirror config
packages/
  a/
    acl.toml
    attr.toml
    autoconf.toml
    automake.toml
  b/
    bash.toml
    binutils.toml
    bison.toml
    boost.toml
    brotli.toml
    bzip2.toml
  c/
    coreutils.toml
    curl.toml
  ...
  o/
    openssl.toml
  ...
  z/
    zlib.toml
    zstd.toml
```

### Directory Structure Rules

1. Packages are stored under `packages/<first-letter>/` for filesystem
   scalability (same convention as the Linux kernel's `drivers/` and many
   package registries like crates.io).

2. One TOML file per package. The filename is `<package-name>.toml`.

3. Each package name has at most one version per registry. The TOML file
   contains metadata for the single version available in this registry.

## Registry Root: `registry.toml`

The root file defines the registry itself — its identity, mirrors, and
capabilities.

```toml
[registry]
name = "aos-core"
description = "AOS core system packages — base OS, toolchain, and essential libraries"
version = "2026.02"
default_priority = 500

# REQUIRED: the store directory these packages were built against.
# All store paths in this registry embed this prefix. The client MUST
# reject a registry whose store_dir doesn't match the local AOS_ROOT/store.
# This catches incompatibility immediately (e.g., /var/lib/store vs /nix/store).
store_dir = "/var/lib/store"

# Supported platforms in this registry
platforms = ["x86_64-linux", "aarch64-linux"]

# Minimum apm version required to use this registry
min_apm_version = "0.1.0"

# Mirrors serving NAR files, tried in order
[[mirrors]]
url = "https://cache.aos.dev/nar"
name = "primary"

[[mirrors]]
url = "https://mirror.example.com/aos/nar"
name = "community-mirror"

# Bundle mirrors for registry distribution (HTTP transport).
# Clients fetch bundle-list.toml and bundle files from these mirrors.
# URL pattern: {url}/bundles/{registry-name}/bundle-list.toml
[[bundle_mirrors]]
url = "https://cache.aos.dev"
name = "primary"

[[bundle_mirrors]]
url = "https://mirror.example.com/aos"
name = "community-mirror"

# Signing configuration
[signing]
required = true
# Public key for verifying commit signatures
# Registry commits are signed by the maintainer before publishing
public_key = "aos-core:Ed25519:base64encodedpublickey=="
```

### Store Directory Compatibility

The `store_dir` field is critical. Store paths are a **build-time property** —
every binary in the closure embeds the store directory in its RPATH, shebang
lines, and config files. A package built with `store_dir = "/var/lib/store"`
contains literal strings like `/var/lib/store/abc123-openssl-3.2.0/lib` in
its ELF binaries. It cannot run on a system with a different store prefix.

On `apm registry add` or `apm update`, the client checks:

```
if registry.store_dir != local_store_dir:
    error: "Registry 'aos-core' was built for store directory
            '/var/lib/store' but this system uses '/nix/store'.
            Packages from this registry are incompatible."
```

The closure hashes themselves also discriminate — the same source built with
different store directories produces different hashes. But the `store_dir`
check catches this early with a clear error message instead of a cryptic hash
mismatch later.

### Mirror URL Convention

Mirrors serve NAR files at predictable URLs derived from the Nix store path
hash:

```
<mirror_url>/<nar_hash>.nar.zst
```

For example:
```
https://cache.aos.dev/nar/sha256-abc123def456.nar.zst
```

This is a flat namespace — no directory hierarchy for NARs. The hash alone
identifies the file. All NARs use **zstd compression** (`.nar.zst`). This is a
registry-wide invariant, not a per-package field.

## Bundle Distribution

When a registry is configured with an `https://` URI (the default), `apm`
fetches registry metadata via pre-built **git bundle** files. Git bundles are
the same pack format used by `git fetch`, packaged as static files. They
preserve all git object hashes, tree structure, and commit signatures — the
integrity model is identical to native git transport.

### Bundle Types

Every registry release is tagged with a semver version. Bundles are generated
from these tags:

| Release Type | Bundle Type | Contents |
|---|---|---|
| Major/minor (e.g., `v2026.02`) | Full snapshot | Complete registry state — no prerequisites |
| Patch (e.g., `v2026.02.2`) | Sequential delta | Changes from previous patch (`v2026.02.1 → v2026.02.2`) |
| Patch (e.g., `v2026.02.2`) | Skip-ahead delta | Changes from minor base (`v2026.02 → v2026.02.2`) |

Each patch tag generates **two** delta bundles:

1. **Sequential delta** from the previous patch — for systems one version
   behind (small, incremental).
2. **Skip-ahead delta** from the minor base — for systems jumping from the
   minor release to the latest patch in a single step, skipping intermediate
   patches.

For the first patch (e.g., `v2026.02.1`), both bases are the same, so only
one delta is generated.

### File Naming

```
{registry}-{tag}.bundle                              # full snapshot
{registry}-{from_tag}..{to_tag}.delta.bundle          # delta (sequential or skip-ahead)
```

Examples:
```
aos-core-v2026.02.bundle                              # full snapshot at v2026.02
aos-core-v2026.02..v2026.02.1.delta.bundle            # first patch (single delta)
aos-core-v2026.02.1..v2026.02.2.delta.bundle          # sequential: .1 → .2
aos-core-v2026.02..v2026.02.2.delta.bundle            # skip-ahead: .0 → .2
aos-core-v2026.02.2..v2026.02.3.delta.bundle          # sequential: .2 → .3
aos-core-v2026.02..v2026.02.3.delta.bundle            # skip-ahead: .0 → .3
```

The `..` in the filename mirrors git's range notation, making the prerequisite
relationship self-evident.

### Bundle List Manifest

Each registry's bundle mirror hosts a `bundle-list.toml` manifest that
describes all available bundles:

```toml
[manifest]
registry = "aos-core"
version = 1
generated = "2026-02-15T12:00:00Z"

# Full snapshots — one per major/minor release
[[bundles]]
tag = "v2026.02"
type = "snapshot"
uri = "aos-core-v2026.02.bundle"
creation_token = 2026020000
size = 153600
sha256 = "abc123..."

# Delta bundles — sequential and skip-ahead per patch
[[bundles]]
from_tag = "v2026.02"
to_tag = "v2026.02.1"
type = "delta"
uri = "aos-core-v2026.02..v2026.02.1.delta.bundle"
creation_token = 2026020001
size = 8192
sha256 = "def456..."

[[bundles]]
from_tag = "v2026.02.1"
to_tag = "v2026.02.2"
type = "delta"
uri = "aos-core-v2026.02.1..v2026.02.2.delta.bundle"
creation_token = 2026020002
size = 4096
sha256 = "789abc..."

[[bundles]]
from_tag = "v2026.02"
to_tag = "v2026.02.2"
type = "delta"
uri = "aos-core-v2026.02..v2026.02.2.delta.bundle"
creation_token = 2026020002
size = 6144
sha256 = "012def..."
```

The `creation_token` encodes the version as `YYYYMM` + 4-digit patch number
(e.g., `v2026.02.3` = `2026020003`). Tokens are monotonically increasing and
allow the client to skip already-applied bundles.

### Client Update Algorithm

**First-time bootstrap** (no local state):

1. Fetch `bundle-list.toml` from the mirror
2. Download the latest full snapshot bundle
3. Verify bundle SHA-256 against the manifest
4. Run `git bundle verify` to check pack integrity
5. Initialize the local registry cache and unbundle
6. Apply any skip-ahead delta from the minor base to the latest patch
7. Verify commit signatures (if `signing.required = true`)
8. Store `creation_token` and `last_commit` in local state

**Normal update** (e.g., at `v2026.02.1`, latest is `v2026.02.3`):

1. Fetch `bundle-list.toml`
2. Find the skip-ahead delta from the current minor base (`v2026.02 → v2026.02.3`)
   -- if available, download it; otherwise, download sequential deltas in order
   (`.1 → .2`, `.2 → .3`)
3. Verify each bundle's SHA-256 against the manifest
4. Run `git bundle verify` to check pack integrity and prerequisite consistency
5. Unbundle and apply
6. Verify commit signatures, enforce fast-forward from `last_commit`
7. Update `creation_token` and `last_commit`

**Minor version upgrade** (e.g., at `v2026.01.x`, latest is `v2026.02.3`):

1. Fetch `bundle-list.toml`
2. Download the `v2026.02` full snapshot (no prerequisites)
3. Verify SHA-256, run `git bundle verify`, unbundle
4. Apply the skip-ahead delta `v2026.02 → v2026.02.3`
5. Verify commit signatures and update local state

**Error handling:**

- Bundle SHA-256 mismatch → try the next mirror
- `git bundle verify` fails (missing prerequisites) → download a full snapshot
  to repair, then retry deltas
- All mirrors exhausted → report error (no silent fallback to a different
  transport; the user's configured URI determines the transport)
- Corrupt manifest → try the next mirror, then report error

### Bundle URL Layout

Bundles are served from a flat directory under each mirror:

```
https://cache.aos.dev/bundles/
  aos-core/
    bundle-list.toml
    aos-core-v2026.01.bundle
    aos-core-v2026.02.bundle
    aos-core-v2026.02..v2026.02.1.delta.bundle
    aos-core-v2026.02.1..v2026.02.2.delta.bundle
    aos-core-v2026.02..v2026.02.2.delta.bundle
  aos-extra/
    bundle-list.toml
    ...
```

The manifest URL is derived from the registry source URI:
`{source_url}/bundles/{registry_name}/bundle-list.toml`

### Size Estimates

For a registry with ~200 packages:
- **Full snapshot bundle**: ~50–200 KB (TOML files are small text)
- **Patch delta bundle**: ~1–10 KB (typically changes a few TOML files)
- **`bundle-list.toml`**: ~2–5 KB

The primary benefit of bundles over native git is eliminating the need for a
git server. Bundles are static files servable from any HTTP server or CDN,
requiring no server-side git computation.

## Multi-Registry Overlay

Users configure multiple registries with priorities. When resolving a package
name, `apm` searches registries in priority order (highest first).

### Priority Rules

1. **Numeric priority** — Higher number = higher priority (same as apt).
   Default: 500.

2. **First match wins** — For a given package name, the highest-priority
   registry that contains it is authoritative.

3. **One version per registry** — Each package name has at most one version
   per registry. There is no version constraint language — `apm install pkg`
   always installs the single version available in the highest-priority
   registry that contains it.

4. **Explicit override** — `apm install --registry=<name> pkg` bypasses
   priority and installs from a specific registry.

5. **Registry-scoped resolution** — All transitive dependencies of a package
   resolve from the **same registry** as the parent package. See
   "Registry-Scoped Dependency Resolution" below.

### Registry-Scoped Dependency Resolution

Each registry is **self-contained**: every package's transitive closure must be
present within the same registry. When installing a package, all `references`
(store path hashes) are resolved within the registry that provided the parent
package, recursively. If you install `curl` from `aos-core`, every store path
in curl's closure (openssl, zlib, nghttp2, cacert) must exist in `aos-core` and
is resolved from `aos-core`.

The registry maintains a **hash-to-package reverse index** for efficient
lookup during closure resolution. Given a store path hash from a `references`
list, the index maps it to the corresponding package TOML file containing the
`nar_hash`, `download_hash`, and mirror information needed for download.

**Store-level deduplication:** If two registries ship an identical package
(same source, same build inputs, same build process), the resulting store paths
produce the same hash and share a single store path on disk. Same content
produces the same hash regardless of which registry it came from. But
resolution is always registry-scoped — the registry determines which metadata
is consulted, even if the underlying store path is shared.

**Registry validation:** Because each registry is self-contained, maintainers
can integration-test every closure independently. There are no cross-registry
dependency surprises at install time — if a closure passes validation in the
registry, it will resolve correctly on any client that has the registry
configured.

### Registry Configuration Locations

Registry sources are configured at two levels:

```
/etc/apm/registries.d/                 ← system-level (configured via cloud-init)
  aos-core.toml                          priority: 500 — base OS packages
  aos-extra.toml                         priority: 400 — additional packages

~/.config/apm/registries.d/            ← user-level (overrides + additions)
  company-internal.toml                  priority: 600 — internal overrides
```

**Lookup order:** For user profile operations, `apm` merges both directories.
A user-level file with the same registry `name` overrides the system-level
file entirely. For system profile operations (`--system`), only
`/etc/apm/registries.d/` is read.

With this setup:
- `company-internal` (600) shadows `aos-core` (500) for any shared package
  names — useful for patched/custom builds
- `aos-core` (500) shadows `aos-extra` (400)
- Packages unique to `aos-extra` are still available

### Registry Source File

The URI scheme determines the transport:

```toml
# /etc/apm/registries.d/aos-core.toml       (system-level default)
# ~/.config/apm/registries.d/aos-core.toml   (user-level override)
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"       # https:// = HTTP bundles (default)
priority = 500
enabled = true

# Optional: pin to a specific registry version
# pin = "v2026.02"     # tag — works with both bundle and git transport
```

```toml
# Alternative: git transport (for development or self-hosted registries)
[registry]
name = "aos-core-dev"
url = "git+https://git.aos.dev/registries/core.git"   # git transport
branch = "main"        # git ref to track (git transport only)
priority = 500
enabled = true

# pin = "abc123def456" # commit SHA pinning (git transport only)
```

**Transport rules:**

| URI scheme | Transport | Update mechanism |
|---|---|---|
| `https://` | HTTP bundles | Download `bundle-list.toml`, apply snapshot/delta bundles |
| `http://` | HTTP bundles | Same as HTTPS (insecure — not recommended) |
| `git://` | Native git | `git fetch` against git server |
| `git+https://` | Git over HTTPS | `git fetch` over HTTPS |
| `git+ssh://` | Git over SSH | `git fetch` over SSH |

The `branch` field is only meaningful for git transport. For bundle transport,
the client always tracks the latest version available in the bundle list.

**Pinning:** When `pin` is set, `apm update` applies bundles (or fetches) up
to the pinned tag but no further. For bundle transport, the client downloads
only bundles whose `tag` or `to_tag` matches the pinned version. For git
transport, the pinned ref is checked out instead of the branch HEAD. SHA
pinning (`pin = "abc123..."`) requires git transport.

### Local Update State

After each successful update, `apm` appends a `[registry.state]` section to the
local copy of the registry config file. This section tracks synchronization
state and is managed by `apm` — it should not be edited manually.

```toml
# Appended by apm — do not edit manually
[registry.state]
last_commit = "abc123..."
last_creation_token = 2026020003
last_update = "2026-02-13T10:30:00Z"
```

- `last_commit` — SHA of the most recent verified registry commit. Used for
  fast-forward enforcement (downgrade protection).
- `last_creation_token` — Monotonic token from the last applied bundle. The
  client refuses to apply bundles with tokens at or below this value.
- `last_update` — Timestamp of the last successful update (informational).

See [security.md](security.md) for how these fields protect against downgrade
attacks.

## Registry Versioning

### Tags for Releases

Registry maintainers tag releases with semver versions. Tags drive bundle
generation — each tag produces snapshot or delta bundles (see Bundle
Distribution above):

```
v2026.01        # major/minor → full snapshot bundle
v2026.02        # major/minor → full snapshot bundle
v2026.02.1      # patch → delta bundles (sequential + skip-ahead)
v2026.02.2      # patch → delta bundles
```

### Tag Pinning

Pin a registry to a specific release tag:

```toml
pin = "v2026.02"
```

This works with both bundle and git transport. The client applies updates up
to the pinned tag but no further.

### SHA Pinning (Git Transport Only)

Commit SHA pinning requires git transport, since bundles are indexed by tags:

```toml
url = "git+https://git.aos.dev/registries/core.git"
pin = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
```

### Branch Tracking (Git Transport Only)

Tracking a branch (e.g., `main` or `stable`) gives rolling updates on each
`apm update`. This is only available with git transport — bundle transport
always tracks tagged releases:

```toml
url = "git+https://git.aos.dev/registries/core.git"
branch = "main"
```

## Integrity Model

The integrity model is **transport-independent**. Whether registry objects
arrive via HTTP bundles or native git, the same verification chain applies.

Git bundles contain the same pack format as `git fetch` — identical blob
SHAs, tree SHAs, commit SHAs, and commit signatures. A bundle is a
pre-packed fetch response served as a static file.

Verification layers:

1. **Object-level** — Every blob (TOML file) has a SHA hash in git's object
   store. Tampering with a file changes its hash, which changes the tree hash,
   which changes the commit hash. This holds for both bundle and git transport.

2. **Bundle-level** (HTTP transport) — Each bundle file has a SHA-256 hash in
   the `bundle-list.toml` manifest. The client verifies the download before
   unpacking. `git bundle verify` then checks pack integrity and prerequisite
   consistency.

3. **Commit-level** — Commits can be GPG-signed by registry maintainers.
   The client verifies signatures after import, regardless of transport.
   Signatures are embedded in the commit object and survive bundle transport.

4. **Transport-level** — HTTPS provides TLS encryption for both bundle
   downloads and git fetches.

5. **NAR-level** — Each package TOML file includes the NAR content hash.
   After downloading a NAR from a mirror, `apm` verifies it against the hash
   recorded in the (git-verified) TOML file.

The chain of trust is:

```
Registry maintainer signs commit
  -> bundle downloaded over HTTPS and verified (SHA-256 + git bundle verify)
     OR git fetch over HTTPS/SSH
    -> commit signature verified by apm
      -> TOML file integrity guaranteed by git object hashes
        -> NAR content hash in TOML verified against downloaded NAR
          -> Nix store path derived from NAR
```

Bundle mirrors are **untrusted by design**. A compromised mirror cannot serve
tampered content — git object hashes detect any modification. A mirror can
only deny service (serve corrupt bundles), not compromise integrity. This is
the same trust model as NAR mirrors.

See [security.md](security.md) for the full security model.

## Local Install Namespace and Remote Registry Caches

All packages install into generation-based profiles under
`/var/lib/profiles/per-user/$USER/`. Each registry's metadata is cached under
`~/.local/share/apm/remote/{registry}/`:

```
/var/lib/profiles/per-user/$USER/
├── current -> gen-42              ← active profile (atomic symlink swap)
├── gen-42/                        ← current generation
│   ├── usr/{hash} -> /var/lib/store/{hash}-curl-8.5.0          (GC roots)
│   ├── src/{hash} -> /var/lib/store/{hash}-curl-8.5.0.drv      (source roots)
│   ├── bin/                                                     (merged FHS)
│   │   ├── bash -> /var/lib/store/{hash}-bash-5.2.21/bin/bash
│   │   ├── curl -> /var/lib/store/{hash}-curl-8.5.0/bin/curl
│   │   └── vim -> /var/lib/store/{hash}-vim-9.1/bin/vim
│   ├── lib/
│   │   ├── libcurl.so.4 -> /var/lib/store/{hash}-curl-8.5.0/lib/libcurl.so.4
│   │   └── ...
│   ├── include/
│   └── share/
├── gen-41/                        ← previous generation (for rollback)
│   └── ...
├── meta/
│   └── {hash}.json                ← per-path metadata (registry, version, etc.)
└── state.json                     ← generation counter + metadata

~/.local/share/apm/
└── remote/                        ← registry metadata caches
    ├── aos-core/                  ← local git repo (populated via bundles or git fetch)
    │   └── repo/                  ← packages/a/acl.toml, etc.
    └── aos-extra/
        └── repo/
```

Each mutation (install, remove, upgrade) creates a new generation directory,
populates it, and atomically swaps the `current` symlink. Previous generations
are retained for rollback until garbage-collected.

### Why a single profile namespace?

1. **Name uniqueness** — Each generation is a single namespace. Cannot
   install conflicting packages from different registries. If `aos-core`
   and `aos-extra` both provide `openssl`, priority resolution picks one —
   there is exactly one `usr/{hash}` root and one `bin/openssl` executable.

2. **Clean GC** — Garbage collection walks profile generations. All
   installed packages always belong to a configured registry.

3. **Registry removal requires clean uninstall** — `apm registry remove
   aos-extra` refuses if any installed packages have `apm.registry =
   "aos-extra"` in their `meta/` entry. The user must first `apm remove`
   those packages (or reinstall them from another registry). This ensures
   every installed package can always be upgraded and verified against its
   source registry.

4. **Provenance tracking** — Per-path metadata in `meta/{hash}.json` records
   which registry each package came from. `apm upgrade` checks the
   appropriate registry for updates.

4. **Shared store deduplication** — If `aos-core` and `aos-extra` both
   reference the same `zlib-1.3.1` store path, there's one path in the store.
   The `usr/{hash}` GC root in the profile covers it regardless of registry
   origin.

### Effective Package Resolution

When resolving a package name, `apm` walks registry metadata caches by
priority, but installation always goes to the active profile:

```
apm install openssl
  1. Search ~/.local/share/apm/remote/company-internal/repo/ (priority 600) → not found
  2. Search ~/.local/share/apm/remote/aos-core/repo/ (priority 500) → found: openssl 3.2.0
  3. Create new generation with usr/{hash} GC root and merged FHS symlinks
  4. Write metadata to meta/{hash}.json with { registry: "aos-core" }
```

The profile's `meta/` directory is the installed-package namespace.
`apm list --installed` reads the profile's `meta/` and annotates each
package with its source registry from the `apm.registry` field.
