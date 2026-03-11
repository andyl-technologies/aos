# Views: Permissions, Isolation, Access Tracking, and Garbage Collection

## Overview

A **view** is a FUSE projection of the Nix store -- the mechanism that presents
a filtered `/nix/store` to containers and tracks access. Views come in two
flavors:

1. **Named views** -- persistent, path-structured views (e.g. "staging",
   "profiles/dylan"). Admin-configured, has GC policy, UCAN-scoped, visible
   on the mesh.
2. **Ephemeral views** -- temporary, per-build sandbox views. Created and
   destroyed automatically. Local-only, no mesh presence, no LMDB overhead.

Both flavors act as:

- A **GC root collection** -- a set of store paths that should be retained.
- A **permission boundary** -- UCAN capabilities are scoped to universes.
- A **logical isolation layer** -- builds happen in a view, peers exchange
  paths within shared views.

Views are near-zero cost: they are projections over the shared, deduplicated
Nix store. The same store path can appear in multiple views.

```
                        Nix Store
 /nix/store/abc123-gcc  /nix/store/def456-glibc  ...
 (content-addressed, shared, single copy of each path)
          |                      |
   +------v-----------+  +------v-----------+
   | View: "staging"   |  | View: "production" |
   |                   |  |                    |
   | Per-view LMDB:    |  | Per-view LMDB:     |
   |   access.mdb      |  |   access.mdb       |
   |   (LRU tracking)  |  |   (LRU tracking)   |
   |                   |  |                    |
   | GC: ttl=7d        |  | GC: none (manual)  |
   | Auth: team-dev    |  | Auth: team-ops     |
   +-------------------+  +--------------------+
          |                      |
   +------v--------------------------v---------+
   | Global state/ LMDBs (shared across views) |
   |   roots.mdb   -- view roots (all views)   |
   |   sync.mdb    -- CRDT sync state          |
   |   config.mdb  -- view/universe config     |
   |   history.mdb -- build history (append)   |
   +-------------------------------------------+

   +-------------------+
   | Ephemeral:        |
   |   {drv-hash}      |
   |                   |
   | In-memory tracking |
   | No LMDB, no mesh  |
   | Destroyed on       |
   | build completion   |
   +-------------------+
```

### Sync Integration

Views can optionally synchronize with a universe via the generic CRDT sync
protocol (see sync.md). The sync layer maintains a CRDT of closure roots at
paths like `sync/{universe}/profiles/{user}`,
`sync/{universe}/packages/{name}`, etc. A view configured with `sync = "both"`
publishes local mutations (package installs, profile switches) as CRDT deltas
and receives remote mutations from other nodes in the same universe. The global
`state/roots.mdb` reflects the merged CRDT state plus any local-only state (e.g.
in-flight builds, locally-pinned paths) for all views.

## Desired State vs Local State (Two-Layer Model)

The sync integration introduces a two-layer model for view roots:

1. **CRDT desired state** (distributed via sync protocol): represents what
   SHOULD be available in the universe. This is the shared, eventually-consistent
   set of closure roots published by all participants. Explicit user actions --
   `apm install`, `apm remove`, profile switches -- mutate the CRDT and
   propagate to all syncing nodes.

2. **View roots** (local, in LMDB): represents what IS available locally.
   This is a superset of the CRDT desired state -- it includes CRDT-synced
   roots plus local-only roots (build outputs not yet published, temporarily
   pinned paths, etc.).

The two layers interact as follows:

- **CRDT add** (remote node installs a package): the local view receives the
  delta, adds the root to `state/roots.mdb` (keyed by `(view, store_hash)`),
  and (depending on `fetch` policy) either eagerly fetches the content or waits
  for first FUSE access.
- **CRDT remove** (remote node removes a package): the local view receives the
  delta and removes the root from `state/roots.mdb`. Content is reclaimed by
  normal GC.
- **Local GC** (TTL expiry, budget eviction): operates on local state ONLY.
  GC never publishes CRDT removals. If a node evicts a path locally for space
  reasons, other nodes are unaffected -- the path remains in the CRDT desired
  state and can be re-fetched later.
- **Explicit user removal** (`apm remove`): publishes a CRDT removal, which
  propagates to all syncing nodes. This is the only way to remove a root from
  the distributed desired state.

This separation ensures that local resource constraints (disk budget, TTL
policies) do not cause universe-wide data loss. A CI node with aggressive GC
can evict old builds locally without removing them from the universe's desired
state.

### View Sync Configuration

Each view's sync behavior is controlled in the view configuration:

```toml
[views.staging]
universe = "staging"
sync = "both"        # send + receive (default)
# sync = "send"      # publish changes, don't receive
# sync = "receive"   # receive changes, don't publish
# sync = "none"      # isolated local view
fetch = "eager"      # fetch content immediately on sync
# fetch = "lazy"     # fetch on first FUSE access
```

The `sync` field controls CRDT participation:

| Mode | Publishes deltas | Receives deltas | Use case |
|------|-----------------|-----------------|----------|
| `both` | yes | yes | Default -- full bidirectional sync |
| `send` | yes | no | CI publisher: pushes build results, ignores remote changes |
| `receive` | no | yes | Read-only mirror: tracks universe state without contributing |
| `none` | no | no | Isolated local view, no CRDT participation |

The `fetch` field controls content retrieval when a CRDT delta adds a new root:

| Mode | Behavior |
|------|----------|
| `eager` | Immediately fetch NARs/chunks for new roots (default) |
| `lazy` | Record root in `state/roots.mdb` but defer content fetch until first FUSE access |

Lazy fetch is useful for nodes with limited bandwidth or storage -- they
maintain awareness of the universe's desired state without paying the storage
cost for content they may never access. On first FUSE `open` or `lookup` for a
lazily-tracked path, the daemon fetches the content from peers on demand.

## Directory Layout

```
/var/lib/aos/
  chunks/
    packs/                        # append-only pack files
    index.mdb                     # chunk locations, manifests, reverse refs

  views/
    staging/
      access.mdb                  # per-view LRU tracking (hot, per-FUSE-read)
    production/
      access.mdb

  state/
    roots.mdb                     # view roots across all views
    sync.mdb                      # CRDT sync state
    config.mdb                    # view/universe config
    history.mdb                   # build history, shell metadata (append-only)

/nix/store/                       # immutable, boot essentials only

/run/aos/                         # runtime (ephemeral, not persisted)
  views/
    {name}/                       # FUSE mounts (persistent views)
    builds/{drv-hash}/            # ephemeral per-build FUSE mounts
  sockets/                        # control + view + build sockets
```

The rationale for this layout:

- **Per-view `access.mdb`** isolates the hottest write path (FUSE read
  tracking) so views don't contend with each other.
- **`chunks/index.mdb`** is separate because chunk ingestion is bursty and
  shouldn't block access tracking or sync.
- **`state/roots.mdb`** holds roots for ALL views (moderate writes on
  install/remove/CRDT merge), keyed by `(view, store_hash)`.
- **`state/sync.mdb`** holds CRDT state (moderate writes on delta reception).
- **`state/config.mdb`** holds view/universe config (rare writes).
- **`state/history.mdb`** is append-only. It stores completed build records
  (drv hash, builder peer, duration, success/failure, output hash) for
  `aos net builds --history` queries and build statistics. Shell metadata
  (name, host, status, creation time) is also stored here for `aos shell --list`.
- LMDB readers never block writers (MVCC), so GC reading `access.mdb` doesn't
  interfere with FUSE writes.
- GC reads `access.mdb` and writes to `state/roots.mdb` -- different LMDBs, no
  contention.

View FUSE mounts under `/run/aos/views/` are persistent -- they survive across
builds and are managed by the daemon. Ephemeral FUSE mounts under
`/run/aos/views/builds/` are created for each build and destroyed when the build
completes.

## ViewDb Trait

The backing store for view metadata is abstracted behind a trait, allowing
different implementations for named views (persistent, LMDB-backed) and ephemeral
views (in-memory, zero-overhead):

```rust
trait ViewDb: Send + Sync {
    fn contains(&self, hash: &str) -> bool;
    fn insert(&self, hash: &str) -> Result<()>;
    fn remove(&self, hash: &str) -> Result<()>;
    fn record_access(&self, hash: &str, kind: AccessKind) -> Result<()>;
    fn get_access(&self, hash: &str) -> Result<Option<AccessEntry>>;
    fn all_roots(&self) -> Result<Vec<String>>;
    fn flush(&self) -> Result<()>;
}

/// LMDB-backed implementation for named views (persistent views).
/// Uses per-view access.mdb (at /var/lib/aos/views/{name}/access.mdb)
/// for LRU tracking, and global state/roots.mdb for the root set.
struct LmdbViewDb {
    access_env: heed3::Env,  // per-view: /var/lib/aos/views/{name}/access.mdb
    roots_env: heed3::Env,   // global: /var/lib/aos/state/roots.mdb
    view_name: String,      // key prefix for roots.mdb lookups
    ...
}

/// In-memory implementation for ephemeral views (build sandboxes)
struct MemoryViewDb {
    roots: RwLock<HashSet<String>>,
    access: RwLock<HashMap<String, AccessEntry>>,
}
```

Ephemeral views use `MemoryViewDb` -- no LMDB overhead for thousands of
short-lived builds. On build completion (success or failure), access data is
flushed to the parent view's per-view `access.mdb` and roots are written to
the global `state/roots.mdb`. The access merge is a single LMDB transaction
on the per-view `access.mdb`:

- `last_accessed = max(old, new)` -- preserves the most recent timestamp.
- `access_count = old + new` -- accumulates total access events.

The flush is synchronous and completes before the ephemeral view's in-memory
data is freed. Always flush, even on build failure -- failed builds still
generate access data that informs GC decisions.

## Views as Permission Boundaries

UCAN capabilities are scoped to universes using the `with` field:

```json
{
  "att": [
    {"with": "aos://staging/*", "can": "build/submit"},
    {"with": "aos://staging/*", "can": "build/observe"},
    {"with": "aos://production/*", "can": "build/observe"}
  ]
}
```

This peer can submit builds to staging and observe both staging and production,
but cannot submit to production or fetch from production.

### Permission matrix per view

| Capability | Description |
|-----------|-------------|
| `build/submit` | Submit build jobs to this universe |
| `build/claim` | Claim and execute builds for this universe |
| `build/observe` | Subscribe to build logs and status in this universe |
| `store/serve` | Serve NARs from this universe to peers |
| `store/fetch` | Fetch NARs belonging to this universe from peers |
| `admin/manage` | GC, add/remove roots, change view configuration |

### Isolation properties

A peer with access to universe "staging" CANNOT:

- Read store paths that are only in "production" (even if they are on the same
  physical machine).
- Submit builds that would root outputs in "production".
- Fetch NARs from another daemon's "production" universe.

A peer with access to both "staging" and "production" CAN:

- See that the same store path (e.g. gcc) exists in both views.
- But operations are still scoped: a build submitted to "staging" roots outputs
  in "staging".

### Build container socket restrictions

Build containers connect to the daemon via a per-build Unix socket. This socket
exposes a restricted API surface:

- **Allowed**: path-info queries, output registration.
- **NOT allowed**: gc, delegate, peers, build.

This ensures that a compromised or malicious build cannot trigger GC, issue
UCAN delegations, or interact with the mesh.

### Build container user namespaces

Build containers MUST use `--private-users=pick` (or equivalent user namespace
isolation). Without it, `SO_PEERCRED` on the Unix socket reports the host root
UID, defeating permission checks. This is a mandatory requirement, not optional
hardening.

## Builds and Views

Every build happens in a specific view. The daemon creates an ephemeral view
for each build, scoped to the parent view that the build was submitted to.

1. User submits: `aos build foo` (daemon's default view) or
   `aos build foo --view staging`.
2. Daemon creates an ephemeral view with a `MemoryViewDb`, populating it with
   the build's input closure. No on-disk state is created for ephemerals.
3. Daemon mounts a FUSE filesystem at `/run/aos/views/builds/{drv-hash}/` exposing
   only the build inputs.
4. The build runs inside a container with the ephemeral FUSE mount at
   `/nix/store`.
5. On build completion, the daemon:
   a. Flushes the ephemeral `MemoryViewDb` access data into the parent view's
      per-view `access.mdb` (single transaction).
   b. Roots the build outputs in `state/roots.mdb` under the parent view.
   c. Unmounts the ephemeral FUSE mount.
   d. Destroys the ephemeral view directory.
6. Daemon publishes job results to GossipSub on the parent view's topics.

### Ephemeral GC root protection

Ephemeral build views register temporary GC roots with `nix-store --add-root`
for all build inputs. This prevents `nix-store --gc` (which may run
concurrently) from deleting build inputs mid-build. The temporary roots are
removed when the ephemeral view is destroyed.

### GossipSub topic scoping

Topics are scoped by universe. Ephemeral views have NO GossipSub topics.

```
build/wanted/{universe}/{system}     # job announcements for a specific universe and system
build/claimed/{universe}/{system}    # claim announcements
build/result/{universe}/{system}     # completion notifications
build/logs/{drv_hash}                # per-build log streams (drv-scoped, not universe-scoped)
```

Build logs are scoped by derivation hash, not by universe, because the same
derivation may be built in different universes and the log content is identical.

Daemons subscribe only to topics for universes they serve. A daemon with
access to "staging" and "default" subscribes to `build/wanted/staging/x86_64-linux` and
`build/wanted/default/x86_64-linux`, but not `build/wanted/production/x86_64-linux`.

### DHT records

DHT records are universe-agnostic. The universe is NOT included in DHT keys.

Provider records:

```
DHT Provider Record:
  key: "nar:{store_hash}"
  provider: peer_id
```

Build claim records:

```
DHT Record:
  key: "build:{drv_hash}"
  value: {peer_id, status, started_at}
```

Authorization is checked at the application layer, not at the DHT level. When
a daemon requests a NAR from a peer, the request includes the universe. The
serving daemon checks:

1. Does the requester's UCAN include `store/fetch` for this universe?
2. Is the requested path actually in this universe's corresponding local view
   on the serving daemon?

Both checks are required. If either fails, reject the request.

This separation (universe-agnostic DHT, universe-aware application layer) is
deliberate: DHT records are public infrastructure, and encoding the universe
into DHT keys would leak universe names to all DHT participants. Authorization
belongs at the application layer where UCAN verification happens.

### Pin propagation

Pins are stored as DHT records:

```
DHT Record:
  key: "pin:{universe}:{store_hash}"
  value: {closure: [hash1, hash2, ...], pinned_by: peer_id}
```

Daemons periodically query the DHT to discover pins for their views. When a
new daemon joins a view, it lazily fetches pinned paths from peers that have
them.

### GossipSub eavesdropping

GossipSub messages are visible to all subscribers of a topic. This is a known
limitation. Mitigation (future work): encrypt message payloads with a per-universe
symmetric key derived from the universe's UCAN chain. Subscribers without a valid
UCAN for the universe can see that messages exist but cannot decrypt their
contents.

## Access Tracking

Accurate access tracking is the foundation of the GC algorithm. The LRU
eviction scoring function requires reliable `last_accessed` timestamps for every
store path in a view. This section describes all observable access events, how
they are detected, and how they compose into the `effective_access` metric that
drives eviction decisions.

### Observable Access Events

All access events flow through the `ViewDb` trait. Both FUSE handlers and P2P
protocol handlers call `view_db.record_access()`.

| Event | Detection Method | ViewDb Call |
|-------|-----------------|-------------|
| Peer fetches store path via WANT_MANIFEST/WANT_CHUNK | P2P handler | `view_db.record_access(hash, PeerFetch)` |
| Build uses path as input dependency | Post-build analysis via `nix-store -qR` | `view_db.record_access(hash, BuildInput)` |
| Build produces output (new root) | Root creation | `view_db.insert(hash)` |
| User queries path via control socket | Control protocol handler | `view_db.record_access(hash, UserQuery)` |
| Container reads path from FUSE mount | ViewFs FUSE `open`/`lookup` | `view_db.record_access(hash, ContainerRead)` |

Each event updates the `last_accessed` timestamp and increments `access_count`
in the `ViewDb`. The `AccessKind` breakdown records which category of access
occurred, enabling operators to understand why a path is being retained.

### effective_access

The key metric for eviction scoring:

```
effective_access(R) = max(last_accessed(p) for p in unique(R))
```

This uses `unique(R)` -- the set of paths that ONLY root R keeps alive -- NOT
`closure(R)`. This is a critical distinction.

**Why `unique(R)` and not `closure(R)`**: using `closure(R)` causes the
"glibc problem." glibc is in nearly every closure and is accessed constantly as
a shared dependency. Under `closure(R)`, the recent access to glibc would make
`effective_access(R)` recent for ALL roots, keeping everything alive
indefinitely. Using `unique(R)` ensures that only accesses to paths uniquely
owned by R influence R's eviction score.

**Fallback when `unique(R)` is empty**: if all of R's dependencies are shared
with other roots (i.e. `unique(R)` is the empty set), fall back to
`last_accessed(R)` -- the access timestamp of the root itself.

### Merge Semantics for Ephemeral to View

When an ephemeral build view completes, its `MemoryViewDb` access data is
merged into the parent view's per-view `access.mdb`, and roots are written to
the global `state/roots.mdb`. The merge is explicit:

- Single LMDB write transaction per database (atomic within each).
- `last_accessed = max(old, new)` for each path.
- `access_count = old + new` for each path.
- Synchronous -- completes before ephemeral memory is freed.
- Always runs, even on build failure.

### Container/nspawn Access Tracking

When a view is mounted into a systemd-nspawn container (or any container), the
ViewFs FUSE mount intercepts every filesystem operation and records it through
the `ViewDb` trait. Each FUSE mount IS a view, so access attribution is
trivial -- no PID-to-cgroup mapping required.

**Alternative: fanotify**

For deployments where FUSE is not available, Linux's fanotify API can monitor
the store directory and attribute accesses to specific containers by mapping
PIDs through the cgroup hierarchy. This is simpler to deploy (standard bind
mounts, no special filesystem) but does not provide view-level path isolation --
the container can see the entire store.

```rust
// Simplified fanotify monitoring loop
fn monitor_store_access(store_dir: &Path) -> Result<()> {
    let fd = fanotify_init(FAN_CLASS_NOTIF, O_RDONLY)?;
    fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                  FAN_ACCESS | FAN_OPEN, store_dir)?;

    loop {
        let events = read_events(fd)?;
        for event in events {
            let path = proc_fd_path(event.fd)?;
            let pid = event.pid;
            let view = pid_to_view(pid)?;  // /proc/pid/cgroup -> machine name -> view
            update_access(view, store_hash_from_path(&path)?);
        }
    }
}
```

The PID-to-view mapping works as follows:

1. Read `/proc/{pid}/cgroup` to get the cgroup path.
2. The cgroup path for an nspawn container includes the machine name:
   `machine.slice/systemd-nspawn@staging.service/...`
3. The machine name maps to a view via the daemon's configuration.

Advantages of fanotify:
- Zero overhead for the container (no FUSE, no overlay).
- Works with standard bind mounts -- no special filesystem required.
- Kernel-level, so it captures all access patterns including `mmap`, `execve`,
  and `dlopen`.

Disadvantages:
- No view isolation -- the container can see the full store.
- Access attribution requires PID-to-cgroup-to-machine-to-view mapping, which
  is more fragile than the FUSE approach where each mount IS a view.
- Requires `CAP_SYS_ADMIN` for the monitoring process.
- High-frequency access events may need rate limiting or batching.

**Not recommended: inotify**

Simpler than fanotify but does not report the accessing PID. Less useful for
attributing access to specific views or containers. Suitable only when a single
view is mounted at a single mount point.

### Access Metadata

Each view root's access data is stored in the `ViewDb` (LMDB for named views,
in-memory for ephemerals). The logical schema per entry:

```rust
struct AccessEntry {
    store_path: String,          // /nix/store/abc123-gcc-14.2.0
    pushed_at: u64,              // when first added to this view
    last_accessed: u64,          // most recent access from any source
    access_count: u64,           // total access events across all sources
    access_sources: AccessSources, // breakdown by category
    is_root: bool,               // true for push roots, false for deps
    pinned: bool,                // exempt from GC if true
}

struct AccessSources {
    peer_fetch: u64,
    build_input: u64,
    container_read: u64,
    user_query: u64,
}
```

Fields:

- `pushed_at`: when the path was first added to this view.
- `last_accessed`: most recent access from any source. This is the timestamp
  used in the eviction scoring function.
- `access_count`: total number of access events across all sources.
- `access_sources`: breakdown by category. Useful for understanding access
  patterns and tuning GC policies.
- `is_root`: `true` for paths that were directly built or pushed (push roots).
  `false` for paths that exist only as transitive dependencies. Only push roots
  are eviction candidates.
- `pinned`: if `true`, exempt from both TTL expiry and budget eviction.

### Access Tracking for Non-Root Dependencies

Dependencies (paths with `is_root: false`) also have their `last_accessed`
timestamps updated when they are accessed. These timestamps are not used
directly for eviction decisions on the dependency itself -- dependencies are
never independently evicted. Instead, these timestamps feed into the
`effective_access` computation for the push roots that include them in their
`unique(R)` set.

## Garbage Collection

### Per-view GC policy

Each view has its own GC policy, configured on the daemon. Ephemeral views
have no GC policy -- they are destroyed when the build completes.

```toml
[[view]]
name = "staging"
universe = "acme-corp"
ttl = "7d"              # paths expire 7 days after last access
max_size = "50G"         # evict by score when view exceeds 50GB
max_paths = 10000        # cap the number of roots

[[view]]
name = "production"
universe = "acme-corp"
# No ttl, no max_size, no max_paths -- retain everything until manually removed

[[view]]
name = "ci"
universe = "acme-corp"
ttl = "24h"              # aggressive: CI artifacts expire after 1 day
source_ttl = "4h"        # source tarballs expire even faster
```

### Why Not Simple LRU

Naive per-path LRU is wrong for a DAG:

- **Shared deps break**: evicting `glibc` (shared by everything) would break
  the entire view. LRU does not account for the dependency structure.
- **Leaf eviction is pointless**: evicting a deep leaf dependency is useless if
  its parent closure is still active -- the leaf will be re-fetched immediately.
- **Size varies by 1000x**: glibc is 30MB, a config file is 1KB. Recency alone
  does not capture eviction "value" -- we need to account for how much space
  an eviction actually frees.

The Nix store is a DAG, and the eviction algorithm must respect that structure.

### Push Roots vs Dependencies

Only **push roots** (`is_root: true`) are eviction candidates. A push root is
what the user directly built or pushed to the view -- it is the "top" of a
closure. Everything else exists only as a transitive dependency and is never
independently evicted.

This is a critical distinction:
- Push root: `foo-1.0` (the thing the user asked for)
- Dependency: `glibc-2.39`, `gcc-lib-14.2.0`, `bash-5.2` (pulled in transitively)

The GC algorithm operates on push roots. Dependencies are collected
automatically by `nix-store --gc` when no remaining push root (in any view)
references them.

### The Algorithm: Weighted Closure Eviction

**Step 1**: Compute unique and shared closures per root.

```
For each push root R in the view:
  closure(R) = transitive runtime deps of R (from Nix DB Refs table)
  unique(R)  = closure(R) - union of closure(R') for all other push roots R'
  shared(R)  = closure(R) - unique(R)
```

`unique(R)` is the set of paths that ONLY this root keeps alive. Evicting R
frees exactly `sum(narSize(p) for p in unique(R))` bytes.

**Step 2**: Score each push root.

```
effective_access(R) = max(last_accessed(p) for p in unique(R))
                      // fallback: last_accessed(R) if unique(R) is empty
age(R)              = now - effective_access(R)
unique_size(R)      = sum(narSize(p) for p in unique(R))

score(R) = age(R) * unique_size(R)
```

Higher score = older and larger = evict first. This captures the intuition:
"evict the root whose unique dependencies have not been accessed recently and
whose removal frees the most space."

**Tiebreaker for score=0**: when multiple roots have score=0 (e.g. all recently
accessed or all with empty unique sets), fall back to `unique_size(R)`
descending as the primary tiebreaker, then `pushed_at` ascending as the
secondary sort (evict older pushes first).

**Why `effective_access` uses `unique(R)` not `closure(R)`**: using `closure(R)`
would cause glibc (accessed constantly as a shared dep) to keep ALL roots alive
indefinitely. Using `unique(R)` ensures only accesses to paths that are
exclusively owned by R influence R's eviction score. See the "effective_access"
section above for the full rationale.

**Step 3**: Evict greedily until under budget.

```
while view_size > max_size:
    candidates = non-pinned push roots, sorted by score descending
    if candidates is empty:
        log warning: "view over budget but no evictable roots"
        break
    R = candidates[0]  // highest score
    remove R from ViewDb (root + unique deps)
    remove gcroot symlinks
    view_size -= unique_size(R)
```

After removing roots, `nix-store --gc` handles the actual store path deletion.

**Complexity**: O(V + E) for a single closure computation (DFS traversal of the
Refs table). Scoring all roots: O(R * (V + E)) where R = number of push roots.
In practice, most views have <100 push roots and the Refs graph is cached
in-memory from SQLite.

### Shared Dependencies and the "glibc Problem"

Shared dependencies (glibc, gcc-lib, bash, coreutils) appear in nearly every
closure. They are never in any root's `unique(R)` set, so they are never
evicted by the algorithm above -- which is correct. They are only collected
when ALL roots that reference them are gone.

This means:
- Shared deps contribute to `view_size` but are not charged to any single root.
- A view's "shared overhead" is the cumulative size of deps referenced by 2+
  roots. This is bounded and stable (it is basically the bootstrap closure).
- The `max_size` limit should account for this: a view with 50 push roots
  sharing a 2GB bootstrap closure needs `max_size >= 2GB + unique sizes`.

### Example

```
View "ci" has max_size = 50G, currently at 65G.

Push roots (is_root=true):
  R1: foo-1.0 (last accessed 30d ago, unique deps = 8G)   -> score = 30 * 8  = 240
  R2: foo-2.0 (last accessed 2d ago,  unique deps = 9G)   -> score = 2  * 9  = 18
  R3: bar-3.1 (last accessed 15d ago, unique deps = 6G)   -> score = 15 * 6  = 90
  R4: baz-1.2 (last accessed 20d ago, unique deps = 4G)   -> score = 20 * 4  = 80
  Shared deps (glibc, gcc-lib, coreutils, ...): 3G

Eviction order: R1 (240), R3 (90), R4 (80)
  After evicting R1: 65 - 8 = 57G (still over)
  After evicting R3: 57 - 6 = 51G (still over)
  After evicting R4: 51 - 4 = 47G (under 50G -- stop)

R2 (foo-2.0, recently accessed) survives.
```

Note that R2 has the largest unique closure (9G) but the lowest score because
it was accessed 2 days ago. The algorithm correctly preserves recently-used
paths even when they are large.

### Alternative Scoring Functions

The `age * unique_size` score is simple but effective. For views with different
access patterns, alternative scores may be useful:

```
# Frequency-weighted: penalize infrequently accessed roots more
score(R) = age(R) * unique_size(R) / log(access_count(R) + 1)

# Priority-weighted: allow config to boost certain roots
score(R) = age(R) * unique_size(R) * (1 / priority(R))
```

The scoring function is a configuration choice, not an architectural one. Start
with `age * unique_size` and tune based on real-life eviction patterns.

### Four-Phase GC

The full GC process runs in four phases:

```
Phase 0: Dangling root cleanup (O(n))
  Scan all GC root symlinks in the view
  Remove any symlink pointing to a nonexistent store path
  Remove corresponding ViewDb entries

Phase 1: TTL expiry (deterministic, O(n))
  For each root with expires_at < now and not pinned:
    Remove from ViewDb + remove GC root symlink

Phase 2: Size-bounded eviction (if still over max_size)
  Score remaining push roots by age * unique_size
  Evict highest-score roots greedily until under budget
  If no evictable candidates remain, log warning and stop

Phase 2.5: Mesh availability update
  For each hash removed in phases 1-2:
    Check all views' roots_dbs for remaining references
    If no view still references the hash:
      Daemon stops responding to WANT_MANIFEST for that path
      (No DHT records to remove -- the WANT/HAVE protocol has no provider records)

Phase 3: Nix store collection (nix-store --gc)
  Removes paths with no remaining GC roots from any view

Phase 4: Chunk GC
  Scan local chunk store for chunks no longer referenced by any manifest
  Remove unreferenced chunks
```

Phase 0 is a consistency sweep -- it handles the case where `nix-store --gc`
ran externally and deleted paths that still have root symlinks. Phase 1 is cheap
and deterministic -- it only checks timestamps. Phase 2 is more expensive
(requires closure computation) and only runs when the view exceeds its size
budget after TTL expiry. Phase 2.5 updates mesh availability: because the
transfer protocol uses WANT/HAVE (not DHT provider records), there is nothing
to remove from the DHT. The daemon simply stops responding to WANT_MANIFEST
requests for paths that are no longer referenced by any view. Phase 3 delegates
to Nix's own garbage collector, which reclaims disk space. Phase 4 runs chunk
GC: it scans the local chunk store and removes chunks that are no longer
referenced by any manifest. This must run after Phase 3 because manifests
reference NARs, and NARs reference chunks.

### Pin budget safety

Before running Phase 2 eviction, check whether the sum of pinned path sizes
exceeds `max_size`. If so, log an error and skip eviction entirely -- eviction
cannot succeed when pinned paths alone exceed the budget. This prevents an
infinite loop of scoring and finding no evictable candidates.

```rust
fn gc_view(view: &View) {
    // Acquire write lock on root set -- blocks builds from adding roots
    let _lock = view.roots_lock.write();

    // Phase 0: Dangling root cleanup
    for root in view.scan_root_symlinks() {
        if !root.target_exists() {
            root.remove_symlink();
            view.view_db.remove(&root.hash);
        }
    }

    // Phase 1: TTL expiry
    for root in view.view_db.all_roots()? {
        let entry = view.view_db.get_access(&root)?;
        if let Some(ttl) = view.config.ttl {
            if now() - entry.last_accessed > ttl && !entry.pinned {
                view.remove_root(&root);
            }
        }
    }

    // Phase 2: Size-bounded eviction
    if let Some(max_size) = view.config.max_size {
        let current_size = view.total_size();
        if current_size > max_size {
            let pinned_size = view.total_pinned_size();
            if pinned_size > max_size {
                log::error!(
                    "view '{}': pinned paths ({}) exceed max_size ({}), skipping eviction",
                    view.name, pinned_size, max_size
                );
                return;
            }

            let mut candidates = view.score_push_roots();
            candidates.sort_by(|a, b| {
                b.score.partial_cmp(&a.score).unwrap()
                    .then(b.unique_size.cmp(&a.unique_size))
                    .then(a.pushed_at.cmp(&b.pushed_at))
            });
            for candidate in candidates {
                if candidate.pinned { continue; }
                candidate.evict();
                if view.total_size() <= max_size { break; }
            }

            if view.total_size() > max_size {
                log::warn!(
                    "view '{}': still over budget after eviction ({} > {}), \
                     no more evictable roots",
                    view.name, view.total_size(), max_size
                );
            }
        }
    }
}

// Phase 2.5: Mesh availability -- stop serving manifests for paths
// no longer referenced by any view. No DHT records to remove;
// the WANT/HAVE protocol has no provider records.
fn gc_update_availability(removed_hashes: &[String], roots_env: &heed3::Env, all_view_names: &[String], manifest_db: &ManifestDb) {
    for hash in removed_hashes {
        // Check state/roots.mdb for references from any view
        let still_referenced = all_view_names.iter()
            .any(|w| roots_env.contains(&(w, hash)));

        if !still_referenced {
            // Mark manifest as unavailable; daemon will reject
            // future WANT_MANIFEST requests for this path.
            manifest_db.mark_unavailable(hash);
        }
    }
}

// Phase 3 is triggered separately or via --collect:
// nix-store --gc (reclaims disk space)

// Phase 4: Chunk GC -- remove chunks no longer referenced by any manifest.
fn gc_chunks(chunk_store: &ChunkStore, manifest_db: &ManifestDb) {
    let referenced: HashSet<String> = manifest_db
        .all_available_manifests()
        .flat_map(|m| m.chunk_hashes.iter().cloned())
        .collect();

    for chunk_hash in chunk_store.all_chunks() {
        if !referenced.contains(&chunk_hash) {
            chunk_store.remove(&chunk_hash);
        }
    }
}
```

### GC Locking

GC holds a write lock on the view's root set. Builds acquire a read lock when
adding roots. This prevents a race between GC removing roots and a concurrent
build adding them:

- GC write lock: exclusive access to the root set during phases 0-2.5.
  Phase 4 (chunk GC) runs outside the write lock since it operates on the
  chunk store, not the root set.
- Build read lock: shared access to add new roots (multiple builds can add
  roots concurrently, but GC cannot run while builds are adding roots).

The lock scope is per-view. GC on "staging" does not block builds in
"production".

### GC Commands

```sh
# Expire TTL roots, then evict if over budget, then collect:
aos gc --collect

# GC a specific view only:
aos gc --view ci --collect

# Dry-run: show what would be evicted and how much space freed:
aos gc --dry-run
# -> Would evict: foo-1.0 (unique: 8G, last accessed: 30d ago, score: 240)
# -> Would evict: bar-3.1 (unique: 6G, last accessed: 15d ago, score: 90)
# -> Would free: 14G (65G -> 51G, under 50G limit)

# Force-remove all roots for a view (decommission):
aos gc --view dev --all
```

### Automated GC

For unattended operation, use a systemd timer:

```ini
[Timer]
OnCalendar=hourly
Persistent=true

[Service]
ExecStart=/usr/bin/aos gc --collect
```

### Pinning

Paths can be pinned to prevent GC eviction:

```
$ aos pin /nix/store/abc123-gcc-14.2.0 --view production
```

Pinned paths set `pinned: true` in the `ViewDb`, which exempts them from both
TTL expiry and budget eviction. Only the `admin/manage` capability can pin/unpin.

Pins are propagated to the mesh via DHT records (see "Pin propagation" above).

### Manual removal

Paths can be explicitly removed from a view:

```
$ aos unpin /nix/store/abc123-gcc-14.2.0 --view staging
$ aos gc --view staging  # or wait for automatic GC
```

Views with no GC policy (`production` in our example) only lose paths through
manual removal.

## FUSE Filesystem: ViewFs

The primary mechanism for mounting views into containers. A custom FUSE
filesystem that presents `/nix/store` but only exposes paths in the view's
closure. Every filesystem operation is tracked through the `ViewDb` trait.

Used for both view mounts (persistent, under `/run/aos/views/`) and ephemeral
build mounts (temporary, under `/run/aos/views/builds/`).

### Architecture

```
Container (nspawn)                     Host
+------------------+              +--------------+
|                  |              |              |
|  /nix/store/     |<-- FUSE --> |  ViewFs      |
|   abc123-gcc  ok |              |   view_db:   |
|   def456-glibc ok|              |     impl     |
|   xyz789-foo     |  (ENOENT)   |     ViewDb   |
|                  |              |   allowed:   |
|  nix-store       |              |     {abc123, |
|   --realise -----+--socket---> |      def456} |
|                  |              |              |
+------------------+              |  nix-daemon  |
                                  |   (real      |
                                  |    store)    |
                                  +--------------+
```

Each container gets a FUSE mount at `/nix/store`. The FUSE daemon knows which
view the container belongs to and only exposes paths in the view's closure --
everything else returns ENOENT. Every `open`, `read`, and `stat` is intercepted
and tracked via `view_db.record_access()`. The mount is read-only: builds go
through nix-daemon which writes to the real store.

This collapses two separate concerns -- view isolation and access tracking --
into a single mechanism.

### Inode Mapping

ViewFs must maintain an inode translation table mapping real filesystem inodes
to FUSE inodes:

```rust
struct InodeTable {
    /// Map (device, real_inode) -> fuse_inode
    real_to_fuse: RwLock<HashMap<(u64, u64), u64>>,
    /// Map fuse_inode -> real_path
    fuse_to_path: RwLock<HashMap<u64, PathBuf>>,
    /// Next FUSE inode to allocate
    next_ino: AtomicU64,
}
```

FUSE inodes are allocated monotonically starting from 2 (1 is reserved for the
root). All FUSE replies must return translated inode numbers, never raw
filesystem inodes. This is necessary because:

- Real inode numbers from the backing store may collide across different
  filesystems or mount namespaces.
- The kernel FUSE layer expects a consistent inode namespace controlled by the
  FUSE daemon.

### Pre-computed readdir Cache

The root-level `readdir` must NOT scan the full real store on every call.
Instead, ViewFs maintains a sorted `Vec<DirEntry>` of allowed paths:

```rust
struct ViewFs {
    view_db: Box<dyn ViewDb>,
    store_dir: PathBuf,
    inode_table: InodeTable,
    /// Pre-sorted directory entries for the root listing
    root_entries: RwLock<Vec<DirEntry>>,
}

impl ViewFs {
    fn add_paths(&self, hashes: &[String]) {
        let mut allowed = self.view_db; // insert into ViewDb
        for hash in hashes {
            allowed.insert(hash).unwrap();
        }
        self.rebuild_root_entries();
        // Invalidate kernel directory cache
        self.session.notify_inval_entry(FUSE_ROOT_ID, &OsString::new());
    }

    fn remove_paths(&self, hashes: &[String]) {
        for hash in hashes {
            self.view_db.remove(hash).unwrap();
        }
        self.rebuild_root_entries();
    }

    fn rebuild_root_entries(&self) {
        let roots = self.view_db.all_roots().unwrap();
        let mut entries: Vec<DirEntry> = roots.iter()
            .filter_map(|hash| {
                let path = self.store_dir.join(hash);
                // ... build DirEntry from real stat
            })
            .collect();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        *self.root_entries.write().unwrap() = entries;
    }
}
```

readdir serves from the cache -- O(page_size) per call, not O(total_store).
The cache is rebuilt on `add_paths` / `remove_paths`, which are infrequent
operations (only on build completion or explicit root management).

### TTL Strategy for Lookups

FUSE lookup replies include a TTL that controls how long the kernel caches the
result. ViewFs uses different TTLs for different levels:

- **Root-level lookups** (store path existence): TTL=0 or TTL=1s. Store path
  availability can change (paths added by builds, removed by GC). Short TTL
  ensures the container sees updates promptly.
- **Subdirectory lookups** (files within a store path): TTL=long (e.g. 3600s).
  Store paths are immutable -- once a path exists, its contents never change.
  Long TTL avoids unnecessary FUSE roundtrips for repeated access.

```rust
const ROOT_LOOKUP_TTL: Duration = Duration::from_secs(1);
const CONTENT_LOOKUP_TTL: Duration = Duration::from_secs(3600);
```

### Symlink Defense-in-Depth

Store paths may contain symlinks that point to other store paths (e.g.
`/nix/store/abc123-gcc/lib/libgcc_s.so -> /nix/store/def456-gcc-lib/lib/...`).
If a `readlink` within a store path returns a path under `/nix/store/`, ViewFs
verifies that the target hash is in the allowed set before returning the symlink
target:

```rust
fn readlink(&mut self, _req: &Request, ino: u64, reply: ReplyData) {
    let real_path = self.inode_table.fuse_to_path(ino);
    match std::fs::read_link(&real_path) {
        Ok(target) => {
            if let Some(hash) = store_hash_from_path_if_store(&target) {
                if !self.view_db.contains(&hash) {
                    reply.error(libc::ENOENT);
                    return;
                }
            }
            reply.data(target.as_os_str().as_bytes());
        }
        Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
    }
}
```

This prevents information leakage about store paths outside the view via
symlink traversal.

## FUSE Operation Modes

The FUSE layer supports three operation modes that control when chunk data is
fetched from peers. The key insight is that **manifests and chunks are separate**
in the chunk store. Manifests are tiny (file tree metadata: directory structure,
file sizes, permission bits, chunk lists). Chunks are large (actual file
content). All three modes can serve `readdir`, `stat`, and `getattr` instantly
because manifests are always fetched eagerly -- the difference is when chunk
data (the bytes behind `read()`) is fetched.

### Mode: eager

Blocks until all manifests AND all chunks are fetched locally. Once the mount
is available, every FUSE operation -- `readdir`, `stat`, `read` -- completes
instantly with zero network latency. The tradeoff is slow startup: the view
is not mountable until every store path's chunks are fully materialized.

| Operation | Behavior |
|-----------|----------|
| `mount()` | Blocks until all manifests and all chunks are local |
| `readdir()` | Instant (pre-computed from manifests) |
| `stat()` | Instant (metadata from manifests) |
| `read()` | Instant (chunks already in local pack files) |

Best for: production deployments, builds with strict dependency guarantees,
air-gapped or offline-capable nodes.

### Mode: async

Fetches all manifests immediately (mount available fast), then
background-fetches chunks with priority ordering. `read()` on a not-yet-fetched
file promotes that file's chunks to urgent priority and blocks briefly until
they arrive. Over time, the view converges to the same state as eager mode.

| Operation | Behavior |
|-----------|----------|
| `mount()` | Available as soon as manifests are fetched (fast) |
| `readdir()` | Instant (manifests are always fetched eagerly) |
| `stat()` | Instant (file sizes and metadata from manifests) |
| `read()` | Instant if chunks are local; brief block + urgent fetch if not |

The background fetcher uses a priority queue to order chunk fetches:

```rust
enum FetchPriority {
    Urgent,     // promoted by a blocking read() -- user is waiting
    High,       // bin/, lib/, libexec/ -- likely to be executed soon
    Normal,     // include/, share/man/ -- commonly accessed
    Low,        // share/doc/, share/locale/ -- rarely accessed
    Background, // everything else
}
```

When a `read()` hits a not-yet-fetched file in async mode, that file's chunks
get promoted to `Urgent` and jump the queue. The `read()` call blocks until
those specific chunks arrive, then returns the data. This keeps the common case
fast (executables and libraries are fetched first) while ensuring correctness
(every file is readable, even if it means a brief wait).

Best for: developer machines, login shells, interactive use. The view is
usable immediately and gets faster as the background fetch progresses.

### Mode: lazy

Fetches all manifests immediately (so `readdir`, `stat`, and `getattr` work
instantly, including file sizes), but fetches NO chunk data until a `read()`
actually needs it. The first `read()` for each file incurs network latency as
chunks are fetched on demand. Fetched chunks are cached in local pack files
for subsequent reads.

| Operation | Behavior |
|-----------|----------|
| `mount()` | Available as soon as manifests are fetched (fast) |
| `readdir()` | Instant (manifests are always fetched eagerly) |
| `stat()` | Instant (file sizes from manifests -- no chunk data needed) |
| `read()` | First access: network fetch + cache in pack file. Subsequent: instant |

Only fetches what is actually accessed. A view with 10,000 store paths might
only need 50 of them for a particular task -- lazy mode fetches just those 50.

Best for: browsing/inspecting remote views, edge nodes with limited storage,
large views with sparse access patterns, `aos shell --inspect` for examining
failed CI snapshots without downloading the full closure.

### Composition with sync modes

The FUSE mode composes with the view's sync mode (`send`, `receive`, `both`,
`none`). The sync mode determines when new store path roots appear in the
view's desired state; the FUSE mode determines when the chunk data for those
roots is fetched.

| Sync mode | FUSE mode | Behavior |
|-----------|-----------|----------|
| `receive` + `eager` | New CRDT entries trigger immediate full fetch (manifests + all chunks) |
| `receive` + `async` | New CRDT entries fetch manifests immediately, chunks background-fetch with priority |
| `receive` + `lazy` | New CRDT entries fetch manifests immediately, chunks not fetched until `read()` |
| `none` + any | No automatic sync; content fetched only when explicitly requested or built locally |

### Configuration

```toml
[views.staging]
universe = "staging"
sync = "both"
fuse = "async"              # eager, async, or lazy

[views.staging.fuse_async]
max_concurrent_fetches = 32
priority_prefixes = ["bin/", "lib/"]
```

The `fuse_async` sub-table is only relevant when `fuse = "async"`. The
`priority_prefixes` list controls which path prefixes within a store path get
`High` priority in the background fetch queue. The defaults (`bin/`, `lib/`,
`libexec/`) ensure executables and shared libraries are fetched first.

## Relationship to Other Docs

- **sync.md** -- Generic CRDT sync protocol. Views configured with
  `sync != "none"` participate in the sync protocol to distribute closure roots
  across the universe. The sync layer owns the CRDT; the view materializes it
  locally.
- **store.md** -- Content-addressed store and NAR transfer. The `fetch` policy
  (`eager` vs `lazy`) determines when NARs are retrieved after a sync delta
  arrives.
- **chunks.md** -- Chunk-level deduplication. Eagerly-fetched content goes
  through the chunk pipeline; lazily-fetched content is chunked on demand.
- **auth.md** -- UCAN capabilities. Sync deltas are authenticated via the same
  UCAN chain used for all universe-scoped operations.
- **jobs.md** -- Build job protocol. Build outputs are rooted in the view and
  optionally published as CRDT deltas (if `sync = "both"` or `sync = "send"`).
- **mesh.md** -- Peer discovery and connectivity. The sync protocol runs over
  the same libp2p mesh described there.

### Graceful ENOENT on Backing Store Deletion

If a path is in the allowed set (ViewDb) but the real store path does not exist
(e.g. `nix-store --gc` raced and deleted it), ViewFs removes it from the
allowed set and returns ENOENT. It does not panic or return EIO:

```rust
// In lookup or open:
let real_path = self.store_dir.join(&name);
match stat(&real_path) {
    Ok(attr) => reply.entry(&ttl, &attr, 0),
    Err(e) if e.kind() == io::ErrorKind::NotFound => {
        // Race: path was GC'd. Remove from allowed set.
        self.view_db.remove(&hash).ok();
        self.rebuild_root_entries();
        reply.error(libc::ENOENT);
    }
    Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
}
```

### GC to FUSE Ordering

When removing paths from a view (during GC), the ordering is critical to avoid
serving stale data or leaving dangling references:

1. Remove from `ViewDb` allowed set.
2. Invalidate FUSE kernel cache via `notify_inval_entry`.
3. THEN remove the gcroot symlink.

This ordering ensures that:
- After step 1, new FUSE lookups return ENOENT.
- After step 2, the kernel drops any cached directory entries.
- After step 3, `nix-store --gc` is free to delete the actual store path.

If the order were reversed (remove symlink first), a window exists where the
FUSE mount still serves the path but Nix's GC is free to delete it.

### Why FUSE Over fanotify

| | FUSE | fanotify |
|---|---|---|
| View isolation | Built-in (ENOENT for out-of-view paths) | None (full store visible) |
| Access attribution | Trivial -- each mount IS a view | Complex (PID -> cgroup -> machine -> view) |
| Granularity | Per-file open/read/stat | Per-file open/access |
| Overhead | Syscall roundtrip per operation | Kernel event stream |
| Setup | One mount per container | One fanotify watch for entire store |
| New paths appearing | FUSE daemon updates allowed set | Automatic (paths exist in real store) |

FUSE wins on isolation and attribution simplicity. fanotify wins on raw
overhead and setup simplicity. For most AOS deployments, the isolation and
attribution advantages of FUSE outweigh the overhead cost, especially given
the FUSE passthrough optimization described below.

### Implementation

The core struct and `Filesystem` trait implementation use the `fuser` crate:

```rust
use fuser::{Filesystem, Request, ReplyEntry, ReplyDirectory, ReplyData, ReplyOpen};
use std::path::PathBuf;

struct ViewFs {
    view_db: Box<dyn ViewDb>,
    store_dir: PathBuf,              // real /nix/store
    inode_table: InodeTable,
    root_entries: RwLock<Vec<DirEntry>>,
}
```

The `ViewDb` handles both the allowed set and access tracking. The
`inode_table` maps real inodes to FUSE inodes. The `root_entries` cache
provides efficient readdir.

#### `lookup` -- gate access to individual store paths

```rust
impl Filesystem for ViewFs {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_str = name.to_string_lossy();

        if parent == FUSE_ROOT_ID {
            let hash = store_hash_from_name(&name_str);
            if !self.view_db.contains(&hash) {
                reply.error(libc::ENOENT);
                return;
            }
            self.view_db.record_access(&hash, AccessKind::Lookup).ok();
        }

        let real_path = self.store_dir.join(name_str.as_ref());
        match stat(&real_path) {
            Ok(st) => {
                let fuse_ino = self.inode_table.get_or_alloc(st.st_dev, st.st_ino, &real_path);
                let mut attr = stat_to_fuse_attr(&st);
                attr.ino = fuse_ino;
                let ttl = if parent == FUSE_ROOT_ID { ROOT_LOOKUP_TTL }
                          else { CONTENT_LOOKUP_TTL };
                reply.entry(&ttl, &attr, 0);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if parent == FUSE_ROOT_ID {
                    self.view_db.remove(&store_hash_from_name(&name_str)).ok();
                    self.rebuild_root_entries();
                }
                reply.error(libc::ENOENT);
            }
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }
}
```

Paths outside the view's closure get ENOENT at the `lookup` level. The
container cannot even stat them, let alone read them.

#### `readdir` -- serve from pre-computed cache

```rust
    fn readdir(&mut self, _req: &Request, ino: u64, _fh: u64, offset: i64,
               mut reply: ReplyDirectory) {
        if ino == FUSE_ROOT_ID {
            // Root: serve from pre-computed sorted cache
            let entries = self.root_entries.read().unwrap();
            for (i, entry) in entries.iter().enumerate().skip(offset as usize) {
                if reply.add(entry.ino, (i + 1) as i64, entry.file_type, &entry.name) {
                    break; // buffer full
                }
            }
            reply.ok();
        } else {
            // Subdirectories: pass through to real filesystem unfiltered
            // (files within a store path are always fully visible)
            self.readdir_passthrough(ino, offset, reply);
        }
    }
```

Only the root `/nix/store` listing is filtered. Once inside a store path
(e.g. `/nix/store/abc123-gcc/lib/`), all files and subdirectories are visible
without filtering.

#### `open` -- record access and open the real file

```rust
    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let real_path = self.inode_table.fuse_to_path(ino);
        let hash = store_hash_from_path(&real_path);

        self.view_db.record_access(&hash, AccessKind::Open).ok();

        match std::fs::OpenOptions::new()
            .read(true)
            .open(&real_path)
        {
            Ok(file) => {
                let fd = self.register_open_file(file);
                reply.opened(fd, 0);
            }
            Err(e) => reply.error(e.raw_os_error().unwrap_or(libc::EIO)),
        }
    }
```

### Performance

The main concern with FUSE is the user-kernel context switch overhead on every
filesystem operation. Three factors make this acceptable for AOS:

**1. Builds are CPU-bound, not syscall-bound.** A C++ compilation spends the
vast majority of its time in the compiler, not in `open()` and `read()` calls.
The FUSE overhead per syscall is microseconds; the compilation time per file is
milliseconds to seconds. The overhead is negligible relative to actual work.

**2. Kernel page cache still works.** Once a file is read through FUSE, the
data is cached in the kernel page cache. Subsequent reads of the same file
(common during compilation -- headers are read many times) are served from
memory without hitting the FUSE daemon at all.

**3. FUSE passthrough (Linux 6.9+).** After `open()`, subsequent reads can
bypass the FUSE daemon entirely and go directly to the backing file. The FUSE
daemon still intercepts the `open()` for access tracking, but data reads have
zero FUSE overhead.

```rust
    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let real_path = self.inode_table.fuse_to_path(ino);
        let hash = store_hash_from_path(&real_path);

        self.view_db.record_access(&hash, AccessKind::Open).ok();

        let real_fd = libc::open(real_path.as_ptr(), flags);

        // Kernel reads bypass FUSE and go directly to the backing file
        reply.opened_with_passthrough(real_fd as u64, 0);
    }
```

Best of both worlds: access tracking on `open()` (for LRU) and zero overhead
on `read()` (kernel passthrough). On kernels older than 6.9, reads fall back
to the standard FUSE path, which is still acceptable given factors 1 and 2.

### What This Gives the GC

Summary of the data quality from ViewFs access tracking:

- **What was accessed**: exact store paths, not just roots.
- **When**: timestamps on every open.
- **How often**: access counts per path.
- **How much**: bytes read (distinguish "fully read" vs "just stat'd").
- **By whom**: each FUSE mount is a view, attribution is trivial.

This is strictly better data than fanotify (which requires PID-to-cgroup
mapping for attribution) or inotify (which cannot attribute at all). The GC
algorithm's `effective_access` computation benefits from having precise,
per-view access timestamps on every path in the closure.

### Mounting

Start a ViewFs instance for a view and use it in a container:

```bash
# Start ViewFs for the "ci" view
aos viewfs --view ci --mountpoint /run/aos/views/ci

# Use in nspawn
systemd-nspawn \
    --private-users=pick \
    --bind=/run/aos/views/ci:/nix/store \
    --bind=/var/lib/aos/var/nix/daemon-socket \
    ...
```

Or the daemon can manage FUSE mounts automatically based on configuration:

```toml
[[containers]]
name = "ci-builder"
view = "ci"
mountpoint = "/run/aos/views/ci"

[[containers]]
name = "staging-app"
view = "staging"
mountpoint = "/run/aos/views/staging"
```

When the daemon starts, it reads the container configuration, starts a ViewFs
instance for each configured view, and populates the `ViewDb` from the view's
LMDB state. When a container is stopped, the daemon can optionally unmount the
FUSE filesystem and flush the `ViewDb`.

For the nix-daemon container (which needs write access to the real store for
builds), the full `/nix/store` is bind-mounted read-write instead of using
ViewFs. ViewFs is for application containers that consume build outputs.

## Container Integration

Views interact with systemd-nspawn containers in two ways: projecting a view's
store paths into a container's filesystem, and tracking which paths the
container actually accesses. ViewFs handles both in a single mechanism.

### Mounting a View into nspawn

The recommended approach is a ViewFs FUSE mount per container. Each container
gets `/nix/store` backed by a FUSE daemon that only exposes paths in the view's
closure. See the **FUSE Filesystem: ViewFs** section above for full details.

All containers MUST use `--private-users=pick` for user namespace isolation.

For simpler deployments or when FUSE is not available, a view can be projected
into a container by bind-mounting individual store paths:

```bash
# Generate bind-mount flags for a view's closure
for path in $(aos view closure staging); do
    echo "--bind-ro=$path"
done | xargs systemd-nspawn --private-users=pick --machine=staging-app ...
```

This exposes only the view's paths but does not provide access tracking. Pair
with fanotify monitoring (described in the Access Tracking section) to track
which paths the container reads.

### Access Attribution

With ViewFs (recommended), access attribution is trivial: each FUSE mount IS a
view. Every filesystem operation on the mount is automatically attributed to the
correct view through the `ViewDb` trait without any PID-to-cgroup mapping.

With fanotify (alternative), access attribution requires mapping through the
cgroup hierarchy:

```
PID -> /proc/{pid}/cgroup -> cgroup path
     -> machine.slice/systemd-nspawn@{machine}.service/...
     -> machine name -> view configuration
```

This chain is reliable because systemd-nspawn places all container processes
in a well-defined cgroup subtree named after the machine. The daemon maintains
a mapping from machine names to views in its configuration:

```toml
[[view]]
name = "staging"
universe = "acme-corp"
containers = ["staging-app", "staging-worker"]

[[view]]
name = "production"
universe = "acme-corp"
containers = ["prod-app"]
```

### Container Lifecycle and GC

When a container is stopped, its paths are no longer being accessed. The
`last_accessed` timestamps freeze at the time of last container access. If the
view has a TTL policy, these paths will eventually expire. If the container is
restarted, new accesses refresh the timestamps.

A container that is running but idle (no store path access) does not keep paths
alive -- only actual filesystem access updates timestamps. This is intentional:
a deployed container that has loaded everything into memory and no longer reads
from the store should not indefinitely prevent GC of paths it is not using.

When using ViewFs, the FUSE daemon can be stopped when the container is stopped.
The access data persists in the LMDB-backed `ViewDb` on disk and is available
for GC decisions even after the FUSE mount is unmounted.

## Cross-View Deduplication

Since views are projections over the same Nix store:

- Building gcc in "staging" and then promoting it to "production" is just adding
  a second root -- zero copy cost.
- If both "staging" and "production" need the same dependency, it is stored once.
- A daemon with multiple views does not store duplicate NARs.
- On the mesh: if daemon A has gcc in "staging" and daemon B needs gcc for
  "production", B can fetch it from A IF:
  - The store hash matches (same content).
  - B's UCAN includes `store/fetch` for A's universe, OR
  - A's view allows anonymous reads (configurable per view).

### View promotion

Moving a closure from one view to another (e.g. staging to production):

```
$ aos promote /nix/store/abc123-foo-1.0 --from staging --to production
```

This:

1. Queries the closure: `nix-store -qR /nix/store/abc123-foo-1.0`.
2. Creates roots in the destination view's `ViewDb` for every path in the
   closure.
3. The paths are already in the store -- no data movement.

Requires `admin/manage` on both the source and destination views.

## View Configuration

```toml
[[view]]
name = "default"
universe = "acme-corp"
ttl = "30d"
anonymous_read = false

[[view]]
name = "staging"
universe = "acme-corp"
ttl = "7d"
source_ttl = "4h"        # source inputs expire faster than build outputs
max_size = "50G"
anonymous_read = false

[[view]]
name = "production"
universe = "acme-corp"
# No GC policy -- manual management only
anonymous_read = true     # allow unauthenticated peers to fetch NARs from this universe

[[view]]
name = "ci"
universe = "acme-corp"
ttl = "24h"
max_paths = 5000
anonymous_read = false
```

### anonymous_read

When `anonymous_read = true`, any peer can fetch NARs from this universe without a
UCAN that includes `store/fetch`. This is useful for "production" universes that
act as public binary caches -- any Nix user can substitute from them.

The daemon still authenticates the peer's identity (libp2p transport) but does
not require specific capabilities for read-only access to this universe.

## Distributed View Consistency

Views are LOCAL to each daemon. There is no global "view" -- each daemon
maintains its own projection. This means:

- Daemon A's "staging" view might have different paths than daemon B's
  "staging" view.
- That is fine -- they are independent caches of the same logical namespace.
- When daemon A builds something in "staging", it roots the output locally and
  announces as a provider.
- When daemon B needs that path for a "staging" build, it fetches from A.
- B then roots the fetched path in its own "staging" view.

Views are not replicated. They are discovery and permission scopes. The DHT and
GossipSub handle discovery; UCANs handle permissions; each daemon manages its
own roots.

### Provider Record Authorization

When a daemon receives a NAR fetch request, the request includes the universe
name. The serving daemon performs two checks:

1. **UCAN check**: does the requester's UCAN include `store/fetch` for the
   specified universe?
2. **Membership check**: is the requested path actually in that universe's
   corresponding local view on this daemon?

Both checks are required. This prevents:
- A peer with "staging" access fetching paths that only exist in "production"
  (fails check 2).
- A peer with no UCAN at all fetching any path (fails check 1, unless
  `anonymous_read` is enabled).

## View History (Merkle Tree)

A view's state is a set of `(store_hash, manifest_hash)` pairs -- these are
the store paths rooted in the view and their corresponding content manifests.
These pairs form the leaves of a Merkle tree using xxh3-128 as the hash
function. The root hash is the identity of the view's entire state at a point
in time. This enables snapshots, deltas, rollbacks, and efficient P2P sync.

This mechanism replaces the concept of profile generations entirely. Instead of
an opaque generation counter with full-scan diffing, every mutation to a view
produces a new Merkle root that can be compared structurally in O(log N) time.

### Merkle Tree Structure

```
View "staging" at generation 5:

              root: xxh3(left || right) = 0xabc123...
              /                              \
       xxh3(L1 || L2)                  xxh3(L3 || L4)
        /         \                     /         \
  xxh3(a||b)   xxh3(c||d)        xxh3(e||f)   xxh3(g)

Leaves (sorted by store_hash):
  a = xxh3("abc123" || manifest_hash_of_gcc)
  b = xxh3("def456" || manifest_hash_of_glibc)
  ...
```

Leaves are sorted by `store_hash` to produce a deterministic tree. The root
hash changes when any store path is added, removed, or has a different manifest.
Interior nodes are `xxh3(left_child || right_child)`.

### Snapshots

A snapshot is just a root hash plus a timestamp and an optional description.
The storage cost is tiny -- 32 bytes total per snapshot.

```
View "staging" history:
  gen 5: root=0xabc123  (2026-03-09 14:00)  current
  gen 4: root=0xdef456  (2026-03-08 10:30)
  gen 3: root=0x789abc  (2026-03-07 16:00)
```

A snapshot is created automatically on every mutation: install, remove, build
completion, or GC run. No explicit "commit" step is needed.

### Deltas

To find the delta between two view states, walk both trees from the root. When
a subtree hash matches, skip it entirely -- it is identical. When a subtree hash
differs, descend into both children. Only the changed leaves need examination.

For a view with 10,000 store paths, finding the delta is O(log N) comparisons,
not O(N).

**Concrete example**: gen 4 and gen 5 differ by one leaf (curl was added).

```
Gen 4 tree:                          Gen 5 tree:
      root_4: 0xdef456                     root_5: 0xabc123
      /            \                       /            \
  left_4: 0x111     right_4: 0x222     left_5: 0x111    right_5: 0x333
  /      \          /      \           /      \          /      \
 a: gcc  b: glibc  c: bash  (empty)   a: gcc  b: glibc  c: bash  d: curl

Comparison walk:
  1. root_4 (0xdef456) != root_5 (0xabc123) -> descend
  2. left_4 (0x111)    == left_5 (0x111)    -> SKIP (gcc, glibc unchanged)
  3. right_4 (0x222)   != right_5 (0x333)   -> descend
  4. c: bash unchanged, d: curl is new      -> delta = [Added(curl)]

Total comparisons: 4 nodes examined, 2 nodes skipped entirely.
A full scan would have examined all leaves.
```

### Rollback

Rollback changes the current root pointer to a previous snapshot's root hash.
Since pack files are append-only, old chunks still exist in the store. Rollback
is instant -- no data movement required.

```
aos view rollback staging --generation 3
  -> current root = gen 3's root hash
  -> view shows state from gen 3
  -> chunks from gen 4 and 5 still in pack files
  -> compaction eventually reclaims unreferenced chunks
```

The ViewDb allowed set is rebuilt from the Merkle tree leaves at the rolled-back
root. FUSE caches are invalidated. From the container's perspective, the view
state jumps back to generation 3 atomically.

### Persistent/Immutable Tree Structure

Snapshots share most of their tree nodes. Changing one leaf creates O(log N) new
interior nodes; everything else is shared with the previous snapshot. This is a
persistent data structure in the functional programming sense.

```
Gen 4:                           Gen 5 (curl added):

      root_4                           root_5  (new)
      /    \                           /    \
  left_4    right_4                left_4    right_5  (new)
  /    \    /    \                 /    \    /    \
 a      b  c    (-)              a      b  c      d  (new leaf)

 Shared: left_4, a, b, c  (4 nodes reused)
 New:    root_5, right_5, d  (3 nodes created)
```

For a view with N leaves, adding or removing one leaf creates O(log N) new
nodes. A view with 10,000 store paths and 100 snapshots stores far fewer than
100 * 10,000 nodes because the vast majority of interior nodes are shared.

### Storage in LMDB

Merkle tree data is stored in `state/history.mdb` (append-only):

```
view_history_db:  (view, generation) -> { root_hash, timestamp, description }
merkle_nodes_db:   node_hash  -> { left_child, right_child }  (interior nodes, shared across snapshots)
merkle_leaves_db:  node_hash  -> { store_hash, manifest_hash } (leaf nodes)
```

`merkle_nodes_db` and `merkle_leaves_db` are content-addressed -- the key is the
hash of the node's contents. This means identical subtrees across different
snapshots are stored exactly once. The `view_history_db` maps `(view, generation)`
pairs to root hashes, providing the linear history timeline per view.

### P2P View Sync

Two peers with the same universe compare Merkle roots for a view. If the roots
differ, they walk the trees together to find divergent branches and sync only the
differing manifests and chunks. This is analogous to `git fetch` -- only the
delta is transferred.

```
Peer A (staging): root = 0xabc123
Peer B (staging): root = 0xdef456

1. Compare roots -> different
2. Compare children -> left same (skip), right different
3. Descend right -> A has curl, B doesn't
4. B fetches curl's manifest + missing chunks from A
5. B rebuilds its Merkle tree with curl included
6. B's root now matches A's
```

The tree walk is interactive: peers exchange node hashes level by level, skipping
identical subtrees. For two views that differ by K store paths out of N total,
the sync transfers O(K * log N) hashes plus the K differing manifests and their
chunks.

### Comparison with Profile Generations

| Profile generations | Merkle tree |
|---|---|
| Generation counter N in LMDB | Merkle root hash (content-addressed) |
| Rollback = change pointer to gen N | Rollback = change root pointer to gen N's hash |
| Diff = full scan of both generations | Diff = O(log N) tree walk |
| P2P sync = transfer everything | P2P sync = exchange only differing subtrees |
| History = list of generation snapshots | History = list of root hashes (32 bytes each) |
| Identity = opaque integer | Identity = cryptographic content hash |

The Merkle tree approach is strictly more powerful. Two peers can independently
arrive at the same root hash if they have the same set of store paths with the
same manifests, regardless of the order in which paths were added. The root hash
is a content-addressed identity of the view state, not a counter.

### APM Integration

```
apm install curl --view staging
  -> adds curl manifest to Merkle tree -> new root -> new generation

apm rollback --view staging
  -> current root = previous generation's root

apm history --view staging
  -> list of generations with root hashes, timestamps, descriptions

apm diff --view staging --from 4 --to 6
  -> walk both trees, show additions/removals/changes
```

Every `apm` mutation is atomic: the new Merkle root is computed, the
`view_history_db` entry is written, and the current generation pointer is
updated in a single LMDB transaction.

### Merkle Tree Operations

```rust
struct MerkleTree {
    nodes_db: Database<Str, SerdeBincode<MerkleNode>>,
    leaves_db: Database<Str, SerdeBincode<MerkleLeaf>>,
}

enum MerkleNode {
    Interior { left: String, right: String },  // child hashes
    Leaf { store_hash: String, manifest_hash: String },
}

impl MerkleTree {
    /// Compute the root hash from a sorted set of (store_hash, manifest_hash) pairs.
    /// Leaves are sorted by store_hash to ensure deterministic tree construction.
    fn build(leaves: &[(String, String)]) -> String { ... }

    /// Find the delta between two roots by walking both trees and comparing
    /// subtree hashes. Identical subtrees are skipped entirely.
    fn diff(root_a: &str, root_b: &str) -> Vec<DeltaEntry> { ... }

    /// Insert a new leaf, return new root. The old root remains valid --
    /// this is a persistent tree, not an in-place mutation.
    fn insert(&self, root: &str, store_hash: &str, manifest_hash: &str) -> String { ... }

    /// Remove a leaf, return new root.
    fn remove(&self, root: &str, store_hash: &str) -> String { ... }
}

enum DeltaEntry {
    Added { store_hash: String, manifest_hash: String },
    Removed { store_hash: String, manifest_hash: String },
    Changed { store_hash: String, old_manifest: String, new_manifest: String },
}
```

The `MerkleTree` is append-only at the LMDB level. Interior nodes and leaves are
never deleted during normal operation -- they may be referenced by older
snapshots. Node reclamation happens during compaction, which scans all
`view_history_db` entries to find reachable nodes and removes the rest.
