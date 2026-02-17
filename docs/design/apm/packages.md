# APM Package Metadata Schema

## Overview

Each package in an APM registry is described by a single TOML file. The file
contains all versions of the package available in the registry, along with
metadata and Nix store references.

**Key difference from apt:** Dependencies are NOT listed explicitly in the
registry. Instead, each package points to a Nix store closure -- a self-contained
tree of store paths. The closure's embedded references (RPATH, shebangs, etc.)
ARE the dependency graph. `apm` resolves dependencies by inspecting closure
references after downloading, not by reading a dependency list before
downloading. This is possible because the Nix store model guarantees that
closures are complete and self-consistent.

**Dependency resolution model:**

- Each package name has **at most one version** per registry. There is no
  version constraint syntax, no SAT solver, and no dependency conflicts.
- All transitive dependencies resolve from the **same registry** as the parent
  package. If you install `curl` from `aos-core`, every store path in curl's
  closure (openssl, zlib, nghttp2, cacert) is also resolved from `aos-core`.
  Each registry must therefore be self-contained -- it must provide every
  package in every closure it offers.
- The `references` field lists store path hashes. During closure resolution,
  `apm` looks up each hash in the **same registry** that provided the parent
  package, using a hash-to-package reverse index maintained by the registry.
- **Store-level deduplication:** If two registries ship an identical package
  (same inputs, same build), the resulting store paths share the same hash and
  are deduplicated in the store. Resolution is still registry-scoped -- the
  registry determines which metadata is consulted -- but the store avoids
  redundant data on disk.

## Schema

### Top-Level Fields

```toml
[package]
name = "openssl"                          # REQUIRED: unique package name
description = "TLS/SSL and general-purpose cryptography library"  # REQUIRED
homepage = "https://www.openssl.org"      # Optional
license = "Apache-2.0"                    # REQUIRED: SPDX identifier
maintainer = "aos-team"                   # REQUIRED

# Versions are listed as an array of tables.
# Multiple versions can coexist — apm installs the latest by default.

[[versions]]
version = "3.2.0"
# ... (see version fields below)

[[versions]]
version = "3.1.4"
# ... (see version fields below)
```

### Package Name Rules

- Lowercase ASCII letters, digits, and hyphens only: `[a-z0-9-]+`
- Must start with a letter: `[a-z]`
- Maximum 64 characters
- Names are globally unique within a registry
- Hyphens separate words: `lib-archive`, not `libarchive` or `lib_archive`
  (but legacy names without hyphens are permitted for compatibility)

### Version Table Fields

Each `[[versions]]` entry describes a single released version:

```toml
[[versions]]
version = "3.2.0"                         # REQUIRED: semver or upstream version

# Platform-specific builds
[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/xr5is7by89v3q...-openssl-3.2.0"  # REQUIRED
nar_hash = "sha256:a1b2c3d4e5f6..."       # REQUIRED: hash of the NAR file
nar_size = 14893056                        # REQUIRED: NAR size in bytes (uncompressed)
download_hash = "sha256:f6e5d4c3b2a1..."   # REQUIRED: hash of compressed NAR
download_size = 5242880                    # REQUIRED: compressed download size in bytes
closure_size = 47185920                    # REQUIRED: total NAR size of full closure

# Source derivation for reproducible build verification
source_drv = "/var/lib/store/ab12cd34ef...-openssl-3.2.0.drv"  # REQUIRED
source_nar_hash = "sha256:1a2b3c4d..."     # REQUIRED: hash of source drv NAR

# References: store path hashes of direct runtime dependencies.
# These are the Nix store references embedded in the NAR — not named packages.
# apm looks up each hash in the SAME registry that provided this package,
# using the registry's hash→package reverse index.
references = [
  "r4q1m2kp8v3x",      # zlib-1.3.1
  "kl9m3n0o5p6q",      # cacert-2024.01
]

[versions.platforms.aarch64-linux]
store_path = "/var/lib/store/kq8mn2pv73w...-openssl-3.2.0"
nar_hash = "sha256:9f8e7d6c5b4a..."
nar_size = 15204352
download_hash = "sha256:4a5b6c7d8e..."
download_size = 5505024
closure_size = 48234496
source_drv = "/var/lib/store/gh56ij78kl...-openssl-3.2.0.drv"
source_nar_hash = "sha256:5e6f7a8b..."
references = [
  "u6v3o4mr1x5z",      # zlib-1.3.1
  "w8x9y0z1a2b3",      # cacert-2024.01
]
```

### Closure-Based Dependency Model

Unlike apt (where dependencies are named packages listed in control files),
APM dependencies are **Nix store references** embedded in the NAR itself.

When a package is built, its output store path contains literal references to
all runtime dependencies — in ELF RPATH entries, shebang lines, pkg-config
files, etc. These references are the canonical dependency graph. The `references`
field in the TOML mirrors them for pre-download planning but is **not** the
authority — the NAR is.

**Why this is better than named deps:**

1. **No version constraint language** — There are no version ranges to
   satisfy. The closure was built and tested with exact dependency versions.
   What you download is what was tested.

2. **No dependency resolution** — There's no SAT solver, no conflicts, no
   "held-back" upgrades due to constraint violations. Each package points to
   an exact, self-consistent closure.

3. **No missing dep bugs** — The build system (Nix sandbox) guarantees that
   all runtime references are captured. If openssl links against zlib, zlib
   appears in the references. There's no way to forget a dependency.

4. **Atomic upgrade** — Upgrading `curl` means downloading a new closure.
   The new curl may reference a different openssl version than the old curl.
   Both coexist in the store until the old roots are removed.

**Trade-off:** You can't install `curl` and separately choose which `openssl`
version it uses — the closure is pre-determined. This is by design: the
pre-built guarantee requires that every combination was built and tested.

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `package.name` | string | yes | Unique package identifier |
| `package.description` | string | yes | One-line human description |
| `package.homepage` | string | no | Upstream project URL |
| `package.license` | string | yes | SPDX license identifier |
| `package.maintainer` | string | yes | Registry maintainer name/handle |
| `versions[].version` | string | yes | Version string |
| `versions[].platforms.<arch>.store_path` | string | yes | Full Nix store path |
| `versions[].platforms.<arch>.nar_hash` | string | yes | Hash of uncompressed NAR |
| `versions[].platforms.<arch>.nar_size` | int | yes | Uncompressed NAR size (bytes) |
| `versions[].platforms.<arch>.download_hash` | string | yes | Hash of compressed NAR |
| `versions[].platforms.<arch>.download_size` | int | yes | Compressed download size |
| `versions[].platforms.<arch>.closure_size` | int | yes | Total NAR size of full closure |
| `versions[].platforms.<arch>.source_drv` | string | yes | Source derivation store path |
| `versions[].platforms.<arch>.source_nar_hash` | string | yes | Hash of source derivation NAR |
| `versions[].platforms.<arch>.references` | string[] | yes | Store path hashes of direct refs |

### Version Ordering

Versions are ordered by the `version` string using semantic versioning rules
where possible. For packages with non-semver upstream versions (e.g., `2026a`),
lexicographic ordering is used, and the TOML file lists versions in
newest-first order — the first `[[versions]]` entry is the latest.

---

## Example Package Files

### Simple Package (leaf): zlib

A leaf package has no runtime references — its closure is just itself.

```toml
[package]
name = "zlib"
description = "General-purpose lossless data compression library"
homepage = "https://zlib.net"
license = "Zlib"
maintainer = "aos-team"

[[versions]]
version = "1.3.1"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/r4q1m2kp8v3x...-zlib-1.3.1"
nar_hash = "sha256:abc123..."
nar_size = 524288
download_hash = "sha256:def456..."
download_size = 196608
closure_size = 524288
source_drv = "/var/lib/store/s5t2n3lq9w4y...-zlib-1.3.1.drv"
source_nar_hash = "sha256:789abc..."
references = []     # leaf — no runtime deps

[versions.platforms.aarch64-linux]
store_path = "/var/lib/store/u6v3o4mr1x5z...-zlib-1.3.1"
nar_hash = "sha256:321cba..."
nar_size = 540672
download_hash = "sha256:654fed..."
download_size = 204800
closure_size = 540672
source_drv = "/var/lib/store/w7x4p5ns2y6a...-zlib-1.3.1.drv"
source_nar_hash = "sha256:cba987..."
references = []
```

### Package with References: curl

The `references` list contains store path hashes of curl's direct runtime
dependencies. These are the same references the Nix store would report via
`nix-store -q --references`. Transitive deps (e.g., zlib referenced by
openssl) are discovered recursively.

```toml
[package]
name = "curl"
description = "Command-line tool and library for URL transfers"
homepage = "https://curl.se"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "8.5.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/h7j3k8l2m9n4...-curl-8.5.0"
nar_hash = "sha256:aabbcc..."
nar_size = 3145728
download_hash = "sha256:ddeeff..."
download_size = 1048576
closure_size = 52428800
source_drv = "/var/lib/store/i8k4l9m3n0o5...-curl-8.5.0.drv"
source_nar_hash = "sha256:112233..."
# Direct references — the daemon resolves the rest transitively
references = [
  "xr5is7by89v3q",     # openssl-3.2.0
  "r4q1m2kp8v3x",      # zlib-1.3.1
  "q8mn2pv73w0x",      # nghttp2-1.58.0
  "kl9m3n0o5p6q",      # cacert-2024.01
]

[[versions]]
version = "8.4.0"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/a1b2c3d4e5f6...-curl-8.4.0"
nar_hash = "sha256:old111..."
nar_size = 3080192
download_hash = "sha256:old222..."
download_size = 1024000
closure_size = 51380224
source_drv = "/var/lib/store/g7h8i9j0k1l2...-curl-8.4.0.drv"
source_nar_hash = "sha256:old333..."
references = [
  "ab12cd34ef56",      # openssl-3.1.4 (different version than 8.5.0!)
  "r4q1m2kp8v3x",      # zlib-1.3.1 (same)
  "mn34op56qr78",      # nghttp2-1.57.0 (different)
  "kl9m3n0o5p6q",      # cacert-2024.01 (same)
]
```

Note how curl 8.5.0 and 8.4.0 reference *different* openssl versions.
Each closure is self-consistent — there's no version constraint to satisfy
because the build system already determined the exact dependency set.

### Meta-Package: base

A meta-package is a small store path whose only purpose is to hold references
to other packages. Its `references` list IS its content:

```toml
[package]
name = "base"
description = "AOS base system meta-package"
license = "MIT"
maintainer = "aos-team"

[[versions]]
version = "2026.02"

[versions.platforms.x86_64-linux]
store_path = "/var/lib/store/m3n8o4p9q5r0...-base-2026.02"
nar_hash = "sha256:meta11..."
nar_size = 4096
download_hash = "sha256:meta22..."
download_size = 256
closure_size = 524288000
source_drv = "/var/lib/store/s6t1u7v2w8x3...-base-2026.02.drv"
source_nar_hash = "sha256:meta33..."
references = [
  "abc123def456",      # bash-5.2.21
  "bcd234efg567",      # coreutils-9.4
  "cde345fgh678",      # glibc-2.38
  "def456ghi789",      # gcc-runtime-14.1.0
  "efg567hij890",      # systemd-255
  "fgh678ijk901",      # util-linux-2.39
  "xr5is7by89v3q",     # openssl-3.2.0
  "h7j3k8l2m9n4",      # curl-8.5.0
  "r4q1m2kp8v3x",      # zlib-1.3.1
]
```

---

## Closure Resolution

The **closure** of a package is the transitive set of all store paths it
references. Unlike apt (where the client resolves named dependencies from
the registry), APM discovers the closure by walking store references — either
from the `references` field in the TOML (for pre-download planning) or from
the actual NAR contents after import.

### Resolution Flow

When `apm install curl` is run:

1. Read `curl.toml` from the highest-priority registry that has it (say, `aos-core`)
2. Get `references`: `[openssl, zlib, nghttp2, cacert]` (store path hashes)
3. Check which of these hashes are already in the local store
4. For missing hashes, look them up in the **same registry** (`aos-core`) by store path hash
5. Each referenced path has its own `references` -- recurse, always within the same registry
6. After computing the full closure, download all missing NARs

```
curl (h7j3k8l2)
├── references: [xr5is7by, r4q1m2kp, q8mn2pv7, kl9m3n0o]
│
├── xr5is7by (openssl-3.2.0)
│   └── references: [r4q1m2kp, kl9m3n0o]     ← zlib + cacert (shared)
│
├── r4q1m2kp (zlib-1.3.1)
│   └── references: []                         ← leaf
│
├── q8mn2pv7 (nghttp2-1.58.0)
│   └── references: [r4q1m2kp]                ← zlib (shared)
│
└── kl9m3n0o (cacert-2024.01)
    └── references: []                         ← leaf
```

Closure = `{curl, openssl, zlib, nghttp2, cacert}` (5 store paths, 5 NARs
to download if none are already installed). Shared references (zlib appears
3 times) are deduplicated — only one NAR is downloaded.

### Registry as a Reference Index

The registry serves as a **lookup table for store path hashes**, scoped to the
registry that provided the parent package. When `apm` encounters a reference
hash during closure resolution, it searches the **same registry's** package
TOMLs to find the matching `store_path`, `nar_hash`, and `download_hash`.
Lookups never cross registry boundaries -- each registry maintains a
hash-to-package reverse index for efficient resolution. This is how unnamed
store paths map back to named packages for display purposes (e.g.,
`apm depends curl` shows "openssl 3.2.0" not just a hash).

Because resolution is registry-scoped and each registry is self-contained,
registry maintainers can integration-test every closure independently with no
cross-registry dependency surprises.

References that appear in a NAR but don't correspond to any named package in
the registry (e.g., glibc, gcc-runtime -- implicit bootstrap deps) are still
downloaded as raw store paths. They don't need package names; they just need
to be in the store for the closure to be complete.

### Comparison with apt

| Aspect | apt | apm |
|--------|-----|-----|
| Dep source | Control file in .deb | Store references in NAR |
| Resolution | Named packages + version SAT | Hash-based closure walk |
| Conflicts | Possible (version constraints) | Impossible (exact closures) |
| Mix versions | User can force | No — closure is pre-determined |
| Completeness | Trust the packager | Enforced by Nix sandbox |
| Upgrade | Resolve new constraint set | Download new closure |

## Source Derivation Chain

The `source_drv` field points to a Nix derivation that contains everything
needed to rebuild the package from source:

- All source tarballs (fetched as fixed-output derivations)
- Build scripts and patches
- References to build-time dependency derivations

This creates a complete provenance chain:

```
source_drv
  ├── src tarball (fetchurl with hash)
  ├── patches/
  ├── build-dep drvs
  │   ├── gcc.drv → gcc source → bootstrap tools
  │   ├── make.drv → make source → bootstrap tools
  │   └── ...
  └── build phases (configure, make, install)
```

A user can fetch this entire chain with `apm source --fetch <pkg>` and verify
with `apm source --verify <pkg>` that building the derivation produces the
same store path as the installed binary.
