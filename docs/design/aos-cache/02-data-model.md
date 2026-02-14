# Data Model

### 3.1 Views

A **view** is a named projection of the Nix store. Each view has:
- A name (URL path segment): `ci`, `prod`, `dev`, `alice`, etc.
- **Artifact namespaces** — `bin/` for build outputs and `src/` for source
  tarballs, each with its own GC roots and metadata
- Its own authentication tokens (defined in config)
- Independent TTLs per namespace (e.g. 7-day binary TTL, 90-day source TTL)

Views share the same underlying Nix store. All paths are content-addressed,
so there is no "leakage" concern — a store path is the same regardless of
which view references it. Views differ only in:
1. **Which paths they keep alive** (GC roots, per namespace)
2. **Who can read/write** (auth tokens)
3. **How long paths survive** (TTL, per namespace)

### 3.2 Directory Layout

`/var/lib/aos` is the **AOS state root** — it serves as both the Nix root and
the AOS root. It hosts the Nix store, Nix state, GC roots, metadata databases,
and per-view runtime state. The path is a compile-time constant (`AOS_ROOT`)
baked into the `aos` binary by the Nix build harness (see [Configuration](06-configuration.md)).

```
/var/lib/aos/                          ← AOS_ROOT (compile-time)
├── store/                              ← Nix store (compiled-in store dir)
├── var/nix/                            ← Nix state
│   ├── db/db.sqlite                    ← Nix metadata DB
│   ├── gcroots/                        ← Nix GC roots
│   │   └── aos -> /var/lib/aos/gcroots ← indirect root for AOS
│   └── log/                            ← Nix build logs
├── gcroots/                            ← AOS per-view GC roots
│   └── {view}/
│       ├── bin/{hash} -> /var/lib/aos/store/{hash}-{name}   (build outputs)
│       └── src/{hash} -> /var/lib/aos/store/{hash}-{name}   (source tarballs)
├── meta/                               ← AOS metadata
│   ├── {view}/bin/{hash}.json          (binary metadata, binary TTL)
│   ├── {view}/src/{hash}.json          (source metadata, source TTL)
│   └── tokens.db
└── views/                              ← AOS per-view runtime state
    └── {view}/
        └── builds/{drv-hash}.json
```

A single **indirect GC root** symlink connects the roots tree to Nix's GC:

```
/var/lib/aos/var/nix/gcroots/aos -> /var/lib/aos/gcroots
```

Nix's garbage collector recursively traverses `/var/lib/aos/var/nix/gcroots/`, follows
the `aos` symlink into our directory tree, and finds all the per-view
symlinks pointing to store paths. These paths (and their transitive closures)
are kept alive.

### 3.3 Path Metadata

For each GC root, we store minimal sidecar metadata. The path includes the
artifact namespace (`bin` or `src`):

```
/var/lib/aos/meta/{view}/bin/{store-path-hash}.json   (build outputs)
/var/lib/aos/meta/{view}/src/{store-path-hash}.json   (source tarballs)
```

```json
{
  "store_path": "/var/lib/aos/store/abc123-foo",
  "pushed_at": 1706000000,
  "pushed_by": "ci-token",
  "expires_at": 1706604800,
  "is_root": true,
  "last_accessed": 1706500000,
  "access_count": 42
}
```

**Fields**:
- `pushed_at`, `pushed_by`, `expires_at`: immutable, set on build completion
- `is_root`: `true` for directly-requested build outputs, `false` for transitive
  runtime dependencies. Only roots are scored for eviction ([Garbage Collection](05-garbage-collection.md)).
- `last_accessed`: updated on every `GET /:view/{hash}.narinfo` serve. Per-view.
- `access_count`: monotonic counter, incremented with each narinfo serve.

This is the **only custom state** we maintain. Everything else (narHash,
narSize, references, signatures) is queried from the Nix store on demand.

### 3.4 Visibility Model

**Each view can only see paths it has rooted.** A `GET /:view/{hash}.narinfo`
succeeds only if a GC root symlink exists in **any** namespace under the view —
the server checks `gcroots/{view}/bin/{hash}` then `gcroots/{view}/src/{hash}`.
The GC roots directories serve double duty:

1. **Visibility index**: the set of symlinks in `gcroots/{view}/{ns}/` defines
   exactly which store paths the view can serve. No symlink = 404.
2. **Liveness**: those same symlinks keep the paths alive during `nix-store --gc`.

This means the GC root directories ARE the view's projection of the store. No
separate index or database is needed — `ls gcroots/{view}/bin/` lists the
view's binary outputs; `ls gcroots/{view}/src/` lists its source mirror.

**Implications**:
- If two views push the same path, each gets its own symlink. The underlying
  store object is shared (content-addressed), but each view independently
  controls its visibility and TTL for that path.
- Removing a view's GC root for a path makes it invisible to that view AND
  removes that view's claim on keeping it alive. If no other view (or system
  GC root) references it, `nix-store --gc` will collect it.
- When a client pushes a closure (path + all transitive dependencies), the
  server creates GC root symlinks for **every path in the closure**. This
  ensures the view can serve the complete dependency tree and all paths
  remain alive.

**Push flow for a closure**:
```
Client builds /var/lib/aos/store/abc123-foo (depends on bar, baz)
  → Server creates binary roots:
    gcroots/{view}/bin/abc123 -> /var/lib/aos/store/abc123-foo
    gcroots/{view}/bin/def456 -> /var/lib/aos/store/def456-bar
    gcroots/{view}/bin/ghi789 -> /var/lib/aos/store/ghi789-baz
  → Server creates source roots:
    gcroots/{view}/src/jkl012 -> /var/lib/aos/store/jkl012-foo-src.tar.gz
    gcroots/{view}/src/mno345 -> /var/lib/aos/store/mno345-gcc-14.1.0.tar.xz
  → View can serve narinfo for all five paths
```

### 3.5 View Bounds

Each view can enforce resource limits:

```toml
[[views]]
name = "ci"
ttl = "7d"                     # binary output TTL
source_ttl = "90d"             # source tarball TTL (longer — sources are small)
source_mirror = true           # retain source inputs after build (default: true)
max_concurrent_builds = 4      # semaphore: max simultaneous nix-store --realise
max_store_size = "200G"        # total narSize of all paths in this view
max_paths = 50000              # max GC root symlinks in this view (bin + src)
```

**Enforcement**:
- `max_concurrent_builds`: a per-view `tokio::sync::Semaphore`. Build requests
  that exceed the limit queue with backpressure (the SSE stream sends
  `event: status {"phase": "queued", "position": 3}` while waiting).
- `max_store_size`: checked after a build completes. If adding the new closure
  would exceed the limit, run DAG-aware eviction ([Garbage Collection](05-garbage-collection.md)) before creating roots.
  The build itself is not rejected — outputs exist in the Nix store regardless.
  Only the view's claim on them is bounded.
- `max_paths`: simple count check. Prevents runaway views from creating millions
  of symlinks.

These bounds apply **per-view**. The underlying Nix store has its own disk limit
managed by `nix-store --gc --max-freed`. View bounds control how much of the
store each tenant can keep alive.

### 3.6 Access Tracking

To support DAG-aware eviction, each path's metadata tracks download activity:

```json
{
  "store_path": "/var/lib/aos/store/abc123-foo",
  "pushed_at": 1706000000,
  "pushed_by": "ci-token",
  "expires_at": 1706604800,
  "is_root": true,
  "last_accessed": 1706500000,
  "access_count": 42
}
```

**`is_root`**: `true` for paths that were the direct target of a build request
(top-level outputs), `false` for transitive runtime dependencies. Only root paths
are considered as eviction candidates — evicting a root removes its entire
unique dependency subtree.

### 3.7 Artifact Namespaces

Each view organises its GC roots and metadata into **namespaces** — typed
subdirectories that partition artifacts by kind:

| Namespace | Contains | TTL | Eviction |
|-----------|----------|-----|----------|
| `bin/` | Build outputs + runtime closure | `ttl` (e.g. 7d) | DAG-aware weighted closure eviction |
| `src/` | Fixed-output source tarballs (`fetchurl` inputs) | `source_ttl` (e.g. 90d) | Simple TTL + LRU (no dependency graph) |

This is analogous to Debian's `deb` / `deb-src` split: binary packages and
source packages are tracked independently, with different retention policies.

**Why separate namespaces?**

1. **Different lifetimes**: sources are small and worth keeping longer as a
   mirror. Binary outputs are large and cycle frequently.
2. **Different eviction strategies**: binary eviction needs DAG-aware scoring
   (§6.6). Source eviction is simple TTL — sources have no dependency graph
   between them.
3. **Extensibility**: future namespaces (e.g. `log/` for build transcripts,
   `llm/` for LLM chat logs tied to a build) can be added by creating a new
   subdirectory. No schema changes — the same GC root + metadata JSON pattern
   applies to any namespace.

**Source root creation**: when a build completes, `aos-serve` inspects the
`.drv` to find its fixed-output source inputs and creates roots in
`gcroots/{view}/src/`. Source metadata includes a `source_of` field
tracking which derivations consumed the source:

```json
{
  "store_path": "/var/lib/aos/store/abc123-gcc-14.1.0.tar.xz",
  "pushed_at": 1706000000,
  "expires_at": 1713776000,
  "source_of": ["/var/lib/aos/store/def456-gcc.drv"]
}
```

**Narinfo serving**: the Nix substituter protocol is namespace-agnostic — a
client requests `GET /:view/{hash}.narinfo` and the server checks all
namespaces (`bin/`, `src/`) for a matching root. The client never needs to
know which namespace a path belongs to.
