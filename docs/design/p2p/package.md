# APM: Package Manager Integration with Views and P2P Mesh

## Overview

APM is a thin UX layer on top of views and the P2P mesh. It translates
human-friendly package operations (install, upgrade, rollback) into view/mesh
operations. The daemon handles all P2P infrastructure -- APM just provides
package metadata resolution and profile management.

Three layers:
```
APM (package names, versions, deps, profiles)
  |
  v
View (store path retention, GC policy, UCAN permissions)
  |
  v
Mesh (chunk-level content transfer, build execution)
```

## Package Resolution Flow

When `apm install curl --view staging`:

```
1. Read the registry symlink tree to find curl's output store path
2. Walk the output's closure (references) to identify all deps
3. For each store path (in dependency order):
   a. Local store has it? -> root in staging, done
   b. Mesh peers have it? -> WANT_MANIFEST, fetch chunks, root in staging
   c. No peers have it? -> submit build from .drv, root in staging
4. Update staging's profile: add curl to current generation
```

```rust
async fn resolve_and_install(
    packages: &[String],
    view: &str,
    registry: &Registry,
    daemon: &DaemonSocket,
) -> Result<Vec<InstalledPackage>> {
    // 1. Resolve package names via registry symlink tree
    //    registry.resolve() reads the symlinks to get store paths + .drv paths
    let resolved = registry.resolve_with_deps(packages)?;

    // 2. Determine which paths need to be fetched
    let mut to_fetch = Vec::new();
    for pkg in &resolved {
        if !daemon.store_has_path(&pkg.output_hash).await? {
            to_fetch.push(pkg);
        } else {
            daemon.root_in_view(&pkg.output_hash, view).await?;
        }
    }

    // 3. Fetch missing paths (daemon handles mesh/build fallback)
    for pkg in &to_fetch {
        daemon.fetch_or_build(&pkg.drv_path, view).await?;
    }

    // 4. Update the view's profile
    let generation = daemon.profile_add(view, &resolved).await?;

    Ok(resolved)
}
```

The daemon's `fetch_or_build` method implements the fallback chain:
```rust
async fn fetch_or_build(&self, drv_path: &str, view: &str) -> Result<()> {
    let drv = parse_derivation(drv_path)?;
    let output_hash = drv.output_hash();

    // Try mesh first (WANT_MANIFEST -> fetch chunks)
    if self.fetch_from_mesh(&output_hash, view).await.is_ok() {
        return Ok(());
    }

    // Build from source (drv is already local -- it's in the registry closure)
    self.submit_build(drv_path, view).await
}
```

## Registries

A registry is a Nix store path containing a structured symlink tree. Symlinks
point to built package outputs and their `.drv` files. Because Nix's reference
scanner detects store path hashes in symlink targets, the registry's closure
automatically includes every package binary and every derivation it references.

This design has three key properties:

1. **Servers hosting the registry are guaranteed to have all binaries.** The
   registry's closure includes every built output. Fetching the registry store
   path (via the mesh or any file-serving protocol) transitively fetches all
   packages.

2. **GC protection is automatic.** As long as the registry is rooted in a
   view, all referenced outputs and derivations are protected from garbage
   collection.

3. **Protocol-agnostic distribution.** The registry is a plain directory of
   symlinks and small metadata files -- servable over libp2p, HTTP, FTP,
   WebDAV, rsync, or any file-serving protocol. No special registry server
   software needed.

### Registry layout

```
/nix/store/{hash}-registry-main/
  metadata                          # registry-level metadata (name, version, etc.)
  packages/
    c/
      curl/
        out -> /nix/store/{hash}-curl-8.6.0          # symlink to built output
        drv -> /nix/store/{hash}-curl-8.6.0.drv      # symlink to derivation
        meta                                          # human metadata (description, license)
    g/
      gcc/
        out -> /nix/store/{hash}-gcc-14.2.0
        drv -> /nix/store/{hash}-gcc-14.2.0.drv
        meta
    l/
      llvm/
        out -> /nix/store/{hash}-llvm-22.0.0
        drv -> /nix/store/{hash}-llvm-22.0.0.drv
        meta
    o/
      openssl/
        out -> /nix/store/{hash}-openssl-3.2.0
        drv -> /nix/store/{hash}-openssl-3.2.0.drv
        meta
    z/
      zlib/
        out -> /nix/store/{hash}-zlib-1.3.1
        drv -> /nix/store/{hash}-zlib-1.3.1.drv
        meta
```

### What the symlinks provide (no TOML needed)

The symlink tree replaces almost all fields from the traditional TOML registry
schema. Everything is either encoded in the directory structure or derivable
from the store path and `.drv` file:

| Traditional TOML field | Symlink tree equivalent |
|---|---|
| `name` | Directory name (`packages/c/curl/`) |
| `version` | Extracted from store path name or `.drv` |
| `store_path` | `out` symlink target |
| `drv_path` | `drv` symlink target |
| `nar_hash` | Computable from store path (`nix-store --dump \| sha256`) |
| `nar_size` | Computable from store path |
| `download_hash` | Not needed (mesh handles transfer via chunks) |
| `download_size` | Not needed |
| `closure_size` | Computable (`nix-store -qR --size`) |
| `references` | Computable (`nix-store -q --references`) |
| `source_drv` | `drv` symlink target |

### The `meta` file

Each package has a small `meta` file containing human-readable metadata that
cannot be derived from the store path or derivation:

```
description: Command line tool and library for URL transfers
homepage: https://curl.se
license: MIT
maintainer: aos-team
```

Simple key-value format, one field per line. This is the only non-symlink file
per package. The format is intentionally minimal -- anything that CAN be
derived from the `.drv` or store path SHOULD be, rather than duplicated here.

### The `metadata` file

The registry root contains a `metadata` file with registry-level information:

```
name: main
version: 42
platform: x86_64-linux
parent: /nix/store/{hash}-registry-main-v41
maintainer_key: ed25519:abc123...
```

The `parent` field is a symlink target pointing to the previous registry
version, forming a chain for history and rollback. The `platform` field
indicates which architecture this registry's packages were built for -- each
platform has its own registry derivation.

### How Nix closures make this work

When the registry derivation is built, Nix scans the output for store path
hashes. Every symlink target containing a store path hash is detected as a
reference. This means:

```
Registry closure includes:
  +-- /nix/store/{hash}-registry-main        (the registry itself)
  +-- /nix/store/{hash}-curl-8.6.0           (curl binary -- from out symlink)
  +-- /nix/store/{hash}-curl-8.6.0.drv       (curl derivation -- from drv symlink)
  +-- /nix/store/{hash}-openssl-3.2.0        (openssl -- curl's runtime dep)
  +-- /nix/store/{hash}-zlib-1.3.1           (zlib -- openssl's runtime dep)
  +-- /nix/store/{hash}-gcc-14.2.0           (gcc binary)
  +-- /nix/store/{hash}-gcc-14.2.0.drv       (gcc derivation)
  +-- ... (every package output + drv + their transitive closures)
```

The registry's closure is the **complete package set**: every binary, every
derivation, and every transitive runtime dependency. A peer that has the
registry has everything.

### Building a registry

The registry is built by a Nix expression that takes all packages as inputs:

```nix
{ mkDerivation, curl, gcc, llvm, openssl, zlib, ... }:

mkDerivation {
  pname = "registry-main";
  version = "42";

  # All packages are build inputs -- they must be built before the
  # registry can be produced. Their outputs become part of the
  # registry's closure via symlinks.
  buildDeps = [];
  runtimeDeps = [ curl gcc llvm openssl zlib ];

  phases = [ "installPhase" ];
  installPhase = ''
    mkdir -p $out/packages

    # curl
    mkdir -p $out/packages/c/curl
    ln -s ${curl} $out/packages/c/curl/out
    ln -s ${curl.drvPath} $out/packages/c/curl/drv
    cat > $out/packages/c/curl/meta <<EOF
    description: Command line tool and library for URL transfers
    homepage: https://curl.se
    license: MIT
    maintainer: aos-team
    EOF

    # gcc
    mkdir -p $out/packages/g/gcc
    ln -s ${gcc} $out/packages/g/gcc/out
    ln -s ${gcc.drvPath} $out/packages/g/gcc/drv
    cat > $out/packages/g/gcc/meta <<EOF
    description: GNU Compiler Collection
    homepage: https://gcc.gnu.org
    license: GPL-3.0
    maintainer: aos-team
    EOF

    # ... (repeated for all packages)

    # Registry metadata
    cat > $out/metadata <<EOF
    name: main
    version: 42
    platform: x86_64-linux
    maintainer_key: ed25519:abc123...
    EOF
  '';
}
```

In practice, this would be generated programmatically from the package set
rather than written by hand.

### Registry as a closure guarantee

Because the registry derivation lists all packages as `runtimeDeps`, Nix
guarantees that every package has been successfully built before the registry
can be produced. A registry store path exists only if every package it
references was built successfully. This is the **pre-built guarantee** --
if the registry exists, every package in it is available.

## P2P Registry Distribution

The registry is distributed via the generic sync layer (see sync.md) -- no
special registry protocol needed. Registry pointers are entries in the
`sync/{universe}/registries/{name}` namespace, and updates flow through the
same CRDT-based anti-entropy protocol as all other distributed state.

### Publishing a registry update

```
1. Registry maintainer evaluates the registry Nix expression
   -> all packages must build successfully
   -> produces /nix/store/{hash}-registry-main

2. Registry store path + full closure chunked (FastCDC) and indexed

3. Maintainer writes a sync entry (Delta) to the
   sync/{universe}/registries/{name} namespace:
   -> {store_hash, version, platform, signature}
   -> LWW (last-writer-wins) semantics -- higher version wins

4. Delta propagates to peers via the sync/{universe} GossipSub topic
   -> anti-entropy repairs any missed updates
```

### Receiving a registry update

```
1. Peer receives a CRDT delta on the sync/{universe} GossipSub topic
   (or discovers it via anti-entropy reconciliation)

2. Merge via LWW -- higher version wins, signature verified
   against trusted maintainer key

3. Fetch the registry store path content:
   -> WANT_MANIFEST for the registry store path
   -> WANT_CHUNK for missing chunks
   -> Cross-version chunk dedup: most package outputs unchanged
   -> Only new/updated package chunks need to be fetched

4. The registry's closure includes all package outputs
   -> packages unchanged from previous version: already local
   -> new/updated packages: fetched as part of the closure

5. Root new registry in view, update local registry pointer
```

### Update cost

When a registry with 1000 packages is updated with 5 package changes:

- The 5 updated packages have new output store paths (new chunks to fetch)
- The 995 unchanged packages have identical store paths (already local)
- The registry symlink tree itself changes minimally (5 new symlink targets)
- Total transfer: the 5 new package outputs + a few KB of registry metadata

### Serving over non-P2P protocols

Because the registry is a plain store path, it can be served over any protocol:

- **HTTP/HTTPS**: Serve the store path as a static directory. Clients fetch
  the registry tree, then fetch individual package NARs by store hash.
- **rsync**: Sync the registry directory. Rsync's delta algorithm provides
  efficient incremental updates.
- **FTP/WebDAV**: Any file-serving protocol works.
- **libp2p mesh**: The native path -- chunk-level dedup, multi-peer parallel
  fetch, no external infrastructure.

For non-mesh protocols, the client needs the registry's store hash (from the
sync layer, a well-known URL, or configuration) and a way to fetch store paths
by hash from the server.

### Multiple registries

Peers can subscribe to multiple registries with priorities:

```toml
[registries.main]
maintainer_key = "ed25519:abc123..."
priority = 500
auto_update = true
pin = true              # protect from GC

[registries.extra]
maintainer_key = "ed25519:def456..."
priority = 400
auto_update = false     # manual: apm update --registry extra

[registries.company]
maintainer_key = "ed25519:ghi789..."
priority = 600          # overrides main for shared package names
auto_update = true
```

Higher priority wins for packages that appear in multiple registries.
Resolution is registry-scoped: all transitive dependencies of a package
resolve from the same registry that provided it.

### Platform registries

Each platform (x86_64-linux, aarch64-linux) has its own registry derivation
because the `out` symlinks point to platform-specific store paths. A server
hosting multiple platforms would have separate sync entries per platform:

```
sync/{universe}/registries/main/x86_64-linux  -> /nix/store/{hash}-registry-main-x86_64
sync/{universe}/registries/main/aarch64-linux -> /nix/store/{hash}-registry-main-aarch64
```

### Registry trust

The registry maintainer signs the sync entry with their ed25519 key. Peers
verify the signature before accepting a registry update (the sync layer
propagates the entry, but the application validates the signature on merge).
Trust is separate from UCAN:

- **UCAN** authorizes mesh actions (submit, fetch, observe)
- **Registry trust** authorizes metadata updates (which packages, which versions)

A compromised registry key could point to malicious packages, but:

- Derivation files are content-addressed -- a modified `.drv` has a different
  hash and store path
- Build outputs are verified against the derivation's expected output hash
- Source verification (`apm source --verify`) can independently confirm
  reproducibility

### Comparison with other registry models

| | apt | AOS TOML registry | AOS symlink registry |
|---|---|---|---|
| Metadata format | Binary control files | TOML files in git repo | Symlinks + small meta files |
| Content hosting | HTTP mirrors / CDN | Mesh peers | Mesh peers (or any protocol) |
| Binary guarantee | In repo | In registry TOML | In closure (structural) |
| Dep resolution | Named packages + SAT | Store hash closure walk | Store reference closure walk |
| .drv availability | N/A | Separate field | In closure (via drv symlink) |
| GC protection | N/A | Manual roots | Automatic (closure) |
| Update mechanism | `apt update` (HTTP) | Git pull / bundles | Chunk fetch (any protocol) |
| External deps | HTTP server + mirrors | Git server / HTTP | None (store path) |
| Integrity | GPG-signed Release | Git object hashes | Nix content addressing |

## Profiles

A profile is a set of active packages within a view. It represents "what's in
PATH" -- the usable environment.

### Profile generations

Each mutation (install, remove, upgrade) creates a new profile generation:

```
/var/lib/aos/views/staging/
  roots.mdb           # all retained store paths (GC boundary)
  access.mdb          # LRU tracking
  profiles/
    current -> 5       # symlink to current generation
    5.mdb              # gen 5: {curl-8.6, gcc-14, python-3.12}
    4.mdb              # gen 4: {curl-8.5, gcc-14, python-3.12}
    3.mdb              # gen 3: {curl-8.5, gcc-13, python-3.11}
```

### Profile operations

```
apm install curl --view staging
  -> creates gen 6: {curl-8.6, gcc-14, python-3.12, curl-8.6}
  -> current -> 6

apm remove gcc --view staging
  -> creates gen 7: {curl-8.6, python-3.12}
  -> gcc-14 stays in roots.mdb (retained until GC)
  -> current -> 7

apm rollback --view staging
  -> current -> 6 (reverts to previous generation)
  -> no store changes (paths still in roots.mdb)

apm rollback --generation 4 --view staging
  -> current -> 4 (jump to specific generation)
```

### Profile vs view roots

Two related but distinct sets:

| | View roots (roots.mdb) | Profile (generation N) |
|---|---|---|
| Purpose | GC boundary -- what's retained | Active set -- what's in PATH |
| Contents | All packages ever installed (until GC) | Current active packages only |
| Size | Grows over time (bounded by GC policy) | Fixed per generation |
| Mutation | Additive (install adds, GC removes) | Snapshot (each gen is immutable) |
| Rollback | N/A (roots accumulate) | Instant (change symlink) |

When GC runs, it considers profile generations:
- Paths in any recent generation (configurable retention, e.g., last 3 gens) are protected
- Paths not in any retained generation are eligible for eviction
- This means rollback is always safe within the retention window

### Profile scope: user vs system

```
apm install curl                    # user profile (per-user within the view)
apm install curl --system           # system profile (shared, requires manage capability)
```

User profiles: `~/.aos/profiles/{view}/`
System profiles: `/var/lib/aos/views/{name}/profiles/`

### Profile environment

A profile generation is materialized as a directory of symlinks:

```
/var/lib/aos/views/staging/profiles/env/
  bin/
    curl -> /nix/store/abc123-curl-8.6.0/bin/curl
    gcc -> /nix/store/def456-gcc-14.2.0/bin/gcc
    python3 -> /nix/store/ghi789-python-3.12.0/bin/python3
  lib/
    libcurl.so -> /nix/store/abc123-curl-8.6.0/lib/libcurl.so
    ...
  share/
    ...
```

Users add the profile's `bin/` to their PATH. This is the same mechanism as
`nix-env` profiles but scoped to views.

## Package Manager Commands with Views

The full command set with view integration:

```
# Install/remove (target a view)
apm install curl --view staging
apm install curl gcc python3 --view ci
apm remove gcc --view staging
apm autoremove --view staging

# Upgrade (within a view)
apm upgrade --view staging              # upgrade all
apm upgrade curl --view staging         # upgrade specific
apm full-upgrade --view staging         # with dep resolution changes

# Query (scoped to a view)
apm list --installed --view staging     # what's active in staging
apm show curl                            # package info (view-independent)
apm search python                        # search registries (view-independent)
apm depends curl --view staging         # closure tree in staging
apm policy curl                          # available versions across registries

# Profile management (per view)
apm rollback --view staging             # revert to previous generation
apm rollback --generation 3 --view staging
apm clean --generations --keep 3 --view staging  # remove old generations

# Registry (view-independent)
apm update                               # fetch latest registry from mesh
apm update --registry extra              # update specific registry
apm registry list
apm registry add --key ed25519:... --name extra
apm diff                                 # show changes since last update
```

## Security and Verification

### Package verification

```
apm verify curl --view staging
  -> reads output store path from registry symlink tree
  -> computes NAR hash of installed store path (on-the-fly from file tree)
  -> compares with expected hash from .drv
  -> verifies narinfo signature against trusted builder key
  -> reports: PASS or MISMATCH
```

### Source verification

```
apm source curl --verify --view staging
  -> reads .drv from registry (already local -- in registry closure)
  -> rebuilds from source locally
  -> compares output hash with installed binary
  -> reports: REPRODUCIBLE or DIFFERS
```

### Trust model

- **Registry closure** provides structural integrity -- the registry exists
  only if every package was successfully built. Symlink targets are
  content-addressed store paths that cannot be forged.
- **Registry pointer** (sync entry) is signed by the maintainer's key.
  Peers verify the signature before accepting updates.
- **Store paths** are verified by NAR hash (content integrity).
- **Narinfo** is signed by the building daemon's key (provenance).
- **UCAN** scopes which universes a user can install to (authorization).
- **Package source** can be independently verified via rebuild (reproducibility).

## Interaction with P2P Mesh

### `apm install` triggers mesh activity

When APM installs a package, the daemon:
1. Checks local store (instant)
2. Broadcasts WANT_MANIFEST to mesh peers (seconds)
3. Fetches chunks from responding peers (parallel, deduped)
4. If no peers have it: submits build from .drv (minutes)

The user sees: "installing curl... fetching from 3 peers... done (12s)"

### `apm update` fetches registry via sync layer

Registry updates are distributed via the generic sync protocol (see sync.md).
Registry pointers are sync entries in the `sync/{universe}/registries/{name}`
namespace:

```
$ apm update
Fetching registry "main" via sync layer...
  Registry version: 42 -> 43
  Changed: 5 packages (curl, openssl, python, nodejs, rust)
  New outputs: 5 packages + their updated closures
  Unchanged: 995 packages (already local)
  Transfer: 847 MB (5 updated package closures)
  Done (45s)
```

The daemon receives CRDT deltas on the `sync/{universe}` GossipSub topic. When
`auto_update = true`, registry updates are applied automatically when a new
delta arrives. When `auto_update = false`, `apm update` triggers anti-entropy
reconciliation to fetch the latest registry pointer from peers.

### Cross-view package sharing

If curl is installed in "staging" and someone does `apm install curl --view production`:
- The daemon already has curl locally (from staging)
- It just roots curl in production's roots.mdb
- Adds to production's profile
- Zero network transfer, instant

This is the same cross-view local sharing that builds use -- the daemon checks
all local views for the store path before going to the mesh.

## Relationship to Other Docs

- **sync.md**: Registry distribution uses the generic sync protocol. Registry
  pointers are sync entries in the `sync/{universe}/registries/{name}`
  namespace, distributed via CRDT deltas and anti-entropy reconciliation.
  Profile sync also uses this layer.
- **views.md**: Profiles are a layer on top of views. View roots determine
  retention; profiles determine active packages.
- **chunks.md**: APM fetches use the chunk transfer protocol
  (WANT_MANIFEST/WANT_CHUNK). Cross-version chunk dedup means upgrading
  curl 8.5 to 8.6 transfers only the changed chunks. Registry closures
  benefit from massive dedup across versions.
- **auth.md**: UCAN `aos://{universe}/submit` is required to install packages
  (install = add roots to a view). `aos://{universe}/manage` for system
  profiles. Registry trust is separate from UCAN.
- **daemon.md**: APM talks to the daemon via Unix socket. The daemon handles
  all mesh interaction, including registry update fetching.
- **builds.md**: When APM can't find a package on the mesh, the daemon builds
  from source using the .drv from the registry closure.
- **store.md**: Registry store paths are transferred using the same
  manifest/chunk protocol as any other store path.
- **docs/design/apm/**: The standalone APM design docs describe the CLI
  interface, security model, and profile mechanics in detail. This document
  focuses on the P2P integration -- how registries are distributed and how
  package operations interact with the mesh.
