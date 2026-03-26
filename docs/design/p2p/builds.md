# Build Isolation Model

Builds in AOS run inside nspawn containers with ephemeral FUSE-projected views
and OverlayFS for writable build outputs. This replaces the Nix builder sandbox
with a fundamentally stronger isolation model:

- **Whitelist, not blacklist**: The container sees ONLY declared inputs (FUSE
  returns ENOENT for everything else). Nix's sandbox bind-mounts the full store
  and tries to hide things -- a blacklist approach.
- **Network isolation**: nspawn controls network access (no network, or macvlan
  to a fetch proxy). Nix's sandbox has all-or-nothing network.
- **Resource isolation**: cgroup delegation gives per-build CPU, memory, and I/O
  limits.
- **Filesystem isolation**: Container user namespaces via `--private-users=pick`.
  No shared build users (nixbld1-32).

## Terminology

- **View**: A persistent named view of the Nix store (e.g., "staging",
  "profiles/dylan"). Views have LMDB-backed state, GC policies, and
  UCAN-scoped permissions. See `views.md` for full details.
- **Ephemeral view**: A short-lived, per-build projection of the store that
  exists only for the duration of a single build. Ephemeral views use an
  in-memory `ViewDb` (not LMDB) and flush access data to the parent view on
  completion.

## Directory Layout

```
/run/aos/                         # runtime (ephemeral, not persisted)
  views/
    {name}/                       # FUSE mounts (persistent views)
    builds/{drv-hash}/            # ephemeral per-build FUSE mounts
  sockets/                        # control + view + build sockets
    {drv-hash}.sock

/var/lib/aos/
  chunks/
    packs/                        # append-only pack files
    index.mdb                     # chunk locations, manifests, reverse refs

  views/                          # per-view state
    staging/
      access.mdb                  # per-view LRU tracking (hot, per-FUSE-read)
    production/
      access.mdb

  state/                          # global state (shared across views)
    roots.mdb                     # view roots across all views
    sync.mdb                      # CRDT sync state
    config.mdb                    # view/universe config
    history.mdb                   # build history, shell metadata (append-only)

  # Ephemeral build views have NO on-disk state. They use MemoryViewDb.
  # Access data is flushed to the parent view's access.mdb on completion.
  # Roots are written to state/roots.mdb.
```

## Full View Projection

A view presents a filtered projection of the full `/nix/` tree, not just
`/nix/store/`. The FUSE filesystem handles:

```
/run/aos/views/{name}/          or  /run/aos/views/builds/{drv-hash}/
  store/                        FUSE: filtered to view's closure
    abc123-gcc-14.2.0/          (allowed -- in roots)
    def456-glibc-2.39/          (allowed)
    xyz789-something/           ENOENT (not in this view)
```

### What about /nix/var/nix/?

For build containers, the build script (configure, make, make install) does not
need Nix tooling. The AOS daemon manages everything:

| Nix directory | In view? | Why |
|---|---|---|
| `store/` | Yes (FUSE filtered + OverlayFS) | Build inputs (read) and outputs (write) |
| `var/nix/db/` | No | AOS daemon handles path queries via socket |
| `var/nix/daemon-socket/` | No | Replaced by AOS control socket |
| `var/nix/gcroots/` | No | AOS manages roots in LMDB |
| `var/nix/profiles/` | No | Not relevant for builds |
| `var/nix/builds/` | No | AOS manages build locks |
| `var/nix/temproots/` | No | Ephemeral views handle this |
| `var/nix/userpool/` | No | Container user namespaces replace build users |

For persistent views (running a full system in a container), profiles and DB
access could be added later.

### The host exception

The host system is the ONE thing that accesses the real store directly. It
cannot use FUSE because:

- The kernel boots from the real store.
- initrd mounts the real `/nix/store`.
- The AOS daemon starts from the real store.
- Only after the daemon is running can FUSE mounts be created.

The daemon's relationship to the store is like a hypervisor to hardware: direct
access, managing the virtualized layers above.

## FUSE Mode for Build Views

Ephemeral build views always use **eager** mode regardless of the parent view's
FUSE configuration. Builds need all inputs available before starting -- a
configure script cannot block mid-execution waiting for a lazy fetch, and a
Makefile cannot tolerate non-deterministic latency from async chunk downloads.
The daemon ensures all manifests and all chunks for the input closure are fully
materialized before mounting the ephemeral FUSE view and starting the nspawn
container.

This is enforced automatically: the `fetch_missing_inputs` phase (step 1 in
the build flow below) downloads all missing chunks before proceeding. The
ephemeral view's FUSE mount is not created until all inputs are local.

## Build Flow

### Step by step

```
1. Job arrives: build foo.drv for view "staging"

2. Daemon parses the .drv file:
   - Builder: /nix/store/abc123-bash/bin/bash
   - Args: ["-e", "/nix/store/xyz789-builder.sh"]
   - Environment: {PATH=..., src=..., buildInputs=..., out=/nix/store/{out-hash}-foo}
   - Input closure: {gcc, glibc, bash, make, foo-src, builder.sh}

3. Daemon creates ephemeral view:
   - Populates in-memory MemoryViewDb with input closure hashes
   - Registers input closure as temporary GC roots (prevents
     nix-store --gc from deleting build inputs mid-build)
   - Mounts FUSE at /run/aos/views/builds/{drv-hash}/
   - Sets up OverlayFS for writable build outputs (see below)
   - Creates per-build socket at /run/aos/sockets/{drv-hash}.sock

4. Daemon starts nspawn container:
   systemd-nspawn \
     --machine=build-{drv-hash} \
     --directory=<minimal-rootfs> \
     --bind=/merged-{drv-hash}/nix/store:/nix/store \
     --bind=/run/aos/sockets/{drv-hash}.sock:/run/aos/control.sock \
     --private-network \
     --private-users=pick \
     --capability=CAP_SYS_CHROOT \
     -- /nix/store/abc123-bash/bin/bash -e /nix/store/xyz789-builder.sh

5. Inside the container:
   - /nix/store/ shows the input closure (FUSE lower) + writable output dir (overlay upper)
   - Build script runs (configure, make, make install)
   - Output written to $out (/nix/store/{out-hash}-foo/) -- goes to overlay upper layer
   - Self-references work because $out path matches the final store path
   - All store reads tracked in MemoryViewDb

6. Build completes:
   - Daemon reads output from overlay upper layer
   - Verifies output (see Output Verification below)
   - Imports into real store
   - Adds output + closure to state/roots.mdb (keyed by view "staging")
   - Flushes ephemeral view access data to parent view's access.mdb
     (at /var/lib/aos/views/staging/access.mdb)
   - Announces as provider on DHT

7. Cleanup:
   - Unmounts OverlayFS
   - Unmounts FUSE at /run/aos/views/builds/{drv-hash}/
   - Removes tmpfs upper/work directories
   - Removes socket
   - Tears down container
```

### OverlayFS for build outputs

The FUSE mount that projects the input closure into the container is read-only.
Builds need to write their output to `$out`, which is a path under `/nix/store`.
OverlayFS solves this by layering a writable tmpfs on top of the read-only FUSE
mount:

```
Container sees /nix/store as:
  lower = FUSE mount (read-only, filtered to build inputs)
  upper = tmpfs (writable, for build outputs)
  merged = overlayfs at /nix/store

Build writes to $out = /nix/store/{out-hash}-foo/
  --> goes to upper layer (tmpfs)
  --> self-references work (path matches final store path)

After build:
  Daemon reads upper layer contents
  Imports into real store
  Roots in parent view
```

The overlay is set up before nspawn starts:

```bash
# Set up overlay
mount -t overlay overlay \
  -o lowerdir=/run/aos/views/builds/{drv-hash}/,upperdir=/tmp/build-{drv-hash}/upper,workdir=/tmp/build-{drv-hash}/work \
  /merged-{drv-hash}/nix/store

systemd-nspawn \
  --machine=build-{drv-hash} \
  --directory=<rootfs> \
  --bind=/merged-{drv-hash}/nix/store:/nix/store \
  --bind=/run/aos/sockets/{drv-hash}.sock:/run/aos/control.sock \
  --private-network \
  --private-users=pick \
  ...
```

Alternatively, nspawn can handle it by binding the FUSE mount read-only and
the output directory separately, avoiding the explicit overlay setup:

```bash
systemd-nspawn \
  --machine=build-{drv-hash} \
  --directory=<rootfs> \
  --bind-ro=/run/aos/views/builds/{drv-hash}/:/nix/store \
  --bind=/tmp/build-{drv-hash}/upper/nix/store/{out-hash}-foo:/nix/store/{out-hash}-foo \
  --bind=/run/aos/sockets/{drv-hash}.sock:/run/aos/control.sock \
  --private-network \
  --private-users=pick \
  ...
```

This second form is simpler but requires knowing the exact output path(s)
upfront (which the daemon does, from parsing the .drv file).

### Why OverlayFS is necessary

Without OverlayFS, the build cannot write to `/nix/store` because the FUSE
mount is read-only. Previous iterations of this design routed output to a
separate `/build/` directory with `$out` pointing to
`/build/nix/store/{out-hash}-foo/`. This breaks self-references: when the build
embeds `$out` in scripts, config files, or ELF RPATHs, those references must
match the final `/nix/store/{out-hash}-foo` path. OverlayFS ensures the build
writes to the correct path from the start.

## Container Security: --private-users=pick

The `--private-users=pick` flag is mandatory for all build containers. Without
it, the build process runs as host root (UID 0). This has two consequences:

1. **Privilege escalation via SO_PEERCRED**: The per-build control socket
   authenticates callers via `SO_PEERCRED`. If the build runs as host UID 0,
   `SO_PEERCRED` reports `uid=0`, giving the build process admin-level access
   to the daemon socket. With `--private-users=pick`, the container's UID 0 maps
   to an unprivileged host UID, and `SO_PEERCRED` reports that unprivileged UID.

2. **Host filesystem access**: A build running as host root could escape the
   container's mount namespace through various kernel interfaces. User namespace
   mapping eliminates this class of attack.

## Build Timeout

All builds are wrapped in a timeout to prevent runaway processes from consuming
resources indefinitely:

```rust
match tokio::time::timeout(max_build_duration, execute_build(job)).await {
    Ok(Ok(result)) => { /* success */ }
    Ok(Err(e)) => { /* build failed normally */ }
    Err(_) => {
        // Timeout expired
        kill_container(&drv_hash).await;
        unmount_overlay(&drv_hash).await;
        unmount_fuse(&drv_hash).await;
        cleanup_tmpfs(&drv_hash).await;
        emit_error_event(&drv_hash, "build timed out").await;
    }
}
```

The `max_build_duration` is set in the daemon configuration (default: 4 hours).

## Per-Build Socket API

Each build gets a restricted control socket at
`/run/aos/sockets/{drv-hash}.sock`, bind-mounted into the container at
`/run/aos/control.sock`. This is one of three socket types in the AOS socket
architecture; see [sockets.md](sockets.md) for the full design.

Build sockets use the **restricted API**: only `path-info` and
`register-output` are permitted. All other commands are rejected.

| Command | Description |
|---------|-------------|
| `path-info` | Query metadata about a store path (narSize, references, deriver) |
| `register-output` | Tell the daemon about a completed build output |

The per-build socket does NOT support `gc`, `delegate`, `peers`, `build`, or
any other daemon control command. It is a minimal interface for the build
process to interact with the daemon without granting broader access.

The daemon authenticates per-build socket connections via `SO_PEERCRED`. With
`--private-users=pick`, the build's container UID 0 maps to an unprivileged
host UID, which the daemon recognizes as belonging to a specific in-flight
build (matched by the socket path).

## Ephemeral View: MemoryViewDb

Ephemeral views do not create LMDB environments on disk. They use an in-memory
`ViewDb` implementation (`MemoryViewDb`) that holds the input closure's hash
set and access tracking data in process memory.

```rust
struct MemoryViewDb {
    roots: HashSet<String>,           // input closure hashes
    access: HashMap<String, AccessEntry>,  // access tracking
}

impl ViewDb for MemoryViewDb {
    fn contains(&self, hash: &str) -> bool { self.roots.contains(hash) }
    fn record_access(&mut self, hash: &str, kind: AccessKind) { ... }
}
```

On build completion (success or failure), the daemon flushes the access data
from the `MemoryViewDb` to the parent view's per-view `access.mdb` (at
`/var/lib/aos/views/{name}/access.mdb`) and writes roots to the global
`state/roots.mdb`. This access data is valuable for the parent view's GC: it
shows which dependencies were actually READ during the build, not just which
were declared as inputs.

Benefits of in-memory over LMDB for ephemeral views:
- No disk I/O for short-lived builds (most are minutes, not hours).
- No cleanup of stale `.mdb` files after crashes.
- Lower latency for access tracking (no write-ahead log).

## Temporary GC Roots

Before starting a build, the daemon registers the ephemeral view's input
closure as temporary GC roots. This prevents `nix-store --gc` (whether
triggered by another process or by the daemon's own GC timer) from deleting
build inputs while the build is in progress.

```rust
fn register_temp_gc_roots(drv_hash: &str, input_closure: &[String]) -> Result<()> {
    let root_dir = format!("/var/lib/aos/temproots/{}", drv_hash);
    std::fs::create_dir_all(&root_dir)?;
    for store_path in input_closure {
        let hash = extract_store_hash(store_path);
        std::os::unix::fs::symlink(store_path, format!("{}/{}", root_dir, hash))?;
    }
    Ok(())
}
```

The temporary roots directory is removed during build cleanup (step 7).

## Output Verification

After the build completes and the daemon reads the output from the overlay
upper layer, it verifies the output before importing into the real store:

**Input-addressed builds** (the common case): The output hash is fixed by the
derivation. The daemon verifies that the output directory at
`/nix/store/{out-hash}-foo` exists in the upper layer and is non-empty. The
hash is not recomputed -- it was determined at evaluation time and the output
path is correct by construction.

**Content-addressed builds**: The daemon hashes the output contents to compute
the actual content hash. If this differs from the placeholder used during the
build, the daemon renames the output to its final content-addressed store path
before importing. Self-references in the output are rewritten to reflect the
final path.

```rust
fn verify_output(drv: &Derivation, upper_dir: &Path) -> Result<StorePath> {
    match drv.output_mode {
        OutputMode::InputAddressed { hash } => {
            let out_path = upper_dir.join(format!("{}-{}", hash, drv.name));
            if !out_path.exists() || is_empty_dir(&out_path)? {
                return Err(anyhow!("output path missing or empty"));
            }
            Ok(StorePath::new(hash, &drv.name))
        }
        OutputMode::ContentAddressed => {
            let out_path = upper_dir.join(&drv.placeholder_output);
            let content_hash = hash_store_path(&out_path)?;
            let final_path = StorePath::new(&content_hash, &drv.name);
            if final_path != drv.placeholder_output {
                rewrite_self_references(&out_path, &drv.placeholder_output, &final_path)?;
                std::fs::rename(&out_path, upper_dir.join(final_path.to_string()))?;
            }
            Ok(final_path)
        }
    }
}
```

## Daemon Crash Cleanup

If the daemon crashes or is killed, FUSE mounts and containers may be left
behind. On startup, the daemon scans for and cleans up stale state:

```rust
async fn cleanup_stale_builds() -> Result<()> {
    // Scan for stale FUSE mounts
    for entry in std::fs::read_dir("/run/aos/views/builds/")? {
        let drv_hash = entry?.file_name();
        // Unmount overlay first (if present), then FUSE
        let overlay_path = format!("/merged-{}/nix/store", drv_hash.to_string_lossy());
        let _ = Command::new("umount").arg(&overlay_path).output().await;
        let fuse_path = format!("/run/aos/views/builds/{}", drv_hash.to_string_lossy());
        let _ = Command::new("fusermount").args(["-u", &fuse_path]).output().await;
    }

    // Scan for orphaned containers
    let output = Command::new("machinectl").arg("list").output().await?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.starts_with("build-") {
            let machine = line.split_whitespace().next().unwrap();
            let _ = Command::new("machinectl")
                .args(["terminate", machine])
                .output()
                .await;
        }
    }

    // Clean up tmpfs directories
    for entry in std::fs::read_dir("/tmp/")? {
        let name = entry?.file_name().to_string_lossy().to_string();
        if name.starts_with("build-") {
            let _ = std::fs::remove_dir_all(format!("/tmp/{}", name));
        }
    }

    // Clean up stale temp GC roots
    if let Ok(entries) = std::fs::read_dir("/var/lib/aos/temproots/") {
        for entry in entries {
            let _ = std::fs::remove_dir_all(entry?.path());
        }
    }

    // Clean up stale sockets
    for entry in std::fs::read_dir("/run/aos/sockets/")? {
        let _ = std::fs::remove_file(entry?.path());
    }

    Ok(())
}
```

This runs before the daemon begins accepting jobs or creating new builds.

## Container Configuration

```toml
[build]
max_jobs = 8
arch = "x86_64-linux"
features = ["kvm"]
max_build_duration = "4h"

[build.container]
# Minimal rootfs for build containers (a Nix derivation)
rootfs = "/nix/store/{hash}-aos-build-rootfs"
# Scratch space per build
scratch_size = "10G"
# Network mode: "none", "fetch-proxy", "host"
network = "none"
# Resource limits per build
memory_limit = "8G"
cpu_limit = 4
```

## Comparison with Nix Sandbox

| | Nix sandbox | AOS build isolation |
|---|---|---|
| Mechanism | unshare + chroot + bind mounts | nspawn + FUSE + OverlayFS |
| Store visibility | Full store mounted, sandbox prevents access (blacklist) | Only declared inputs exist (whitelist via FUSE) |
| Write path | In-place (build writes to store directly) | OverlayFS upper layer (tmpfs), daemon imports after |
| Network | --sandbox-paths or no network | nspawn network namespace (none, macvlan, or proxy) |
| Resources | No limits | cgroup delegation (CPU, memory, I/O) |
| User isolation | Shared build users (nixbld1-32) | Container user namespaces (--private-users=pick) |
| Side channels | Timing attacks, /proc leaks possible | Full namespace isolation |
| Build users | 32 pre-created users, limits parallelism | Unlimited (one container per build) |
| Self-references | Build writes directly to final path | OverlayFS ensures $out matches final store path |
| Build timeout | None (builds can run forever) | Configurable timeout with forced cleanup |

## View Nesting

Views are logically nested but physically flat. All views are FUSE mounts
backed by the same real store. Nesting means the child's allowed set is a
subset of the parent's:

```
View "production" allowed: {A, B, C, D, E, F, G}
  View "staging" allowed: {A, B, C, D, E}      (subset of production)
    View "ci" allowed: {A, B, C}                (subset of staging)
      Ephemeral view "build-X" allowed: {A, B}  (subset of ci -- this build's inputs)
```

UCAN enforces this: a child view's UCAN is delegated from the parent's, and
capabilities can only be attenuated. There is no physical nesting (no
FUSE-on-FUSE). The daemon creates each view with the appropriate filter set.

Infinite nesting is supported because nesting is just set intersection on the
allowed hashes. The daemon manages the hierarchy; each view is an independent
FUSE mount. Ephemeral views are the leaf nodes -- they exist only for a single
build and are always children of a view.

## Ephemeral View Lifecycle

```
Created:    when daemon starts a build
Lives:      duration of the build (minutes to hours)
Tracks:     access patterns in MemoryViewDb
Destroyed:  when build completes or fails
Data:       MemoryViewDb is dropped; access data flushed to parent view's access.mdb,
            roots written to state/roots.mdb
```

The access data from ephemeral views is valuable for the parent view's GC: it
shows which dependencies were actually READ during the build, not just which
were declared as inputs. This is more accurate than using the drv's input
closure.

## Log Streaming

Build logs from the container are captured by the daemon:

- stdout/stderr from the nspawn process
- Published to GossipSub `build/logs/{drv-hash}`
- Buffered in the daemon's LogBuffer for replay
- Same log streaming infrastructure as described in logs.md

The daemon does not need to read logs from inside the container -- nspawn's
stdio is available to the parent process.

## Relationship to daemon.md

This document describes the complete build execution model: nspawn container
isolation, FUSE-projected ephemeral views, OverlayFS for writable outputs,
output verification, and cleanup. The daemon document (`daemon.md`) covers the
daemon's overall architecture, mesh participation, control socket protocol, and
job scheduling. For build execution specifics, `daemon.md` should reference
this document rather than inlining build execution details.
