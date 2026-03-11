# FUSE Filesystem

The AOS FUSE filesystem presents a filtered, read-only view of the chunk store
as a standard directory tree. It reconstructs files on-the-fly from chunks in
pack files, projecting a subset of the store defined by a view. Multiple views
can be mounted simultaneously over the same underlying chunk data with no
duplication.

## View Model

A **view** is a set of store hashes. The FUSE mount shows only store paths
whose hash is in the set. Any lookup of a path outside the set returns
`ENOENT`. Views are immutable once created -- changing the visible set requires
creating a new view.

Four view types are supported:

| Type | Definition | Use Case |
|---|---|---|
| **Full** | All manifests known to the local store | Development, inspection |
| **Closure** | Transitive closure of a derivation's build inputs | Build isolation |
| **Profile** | Packages referenced by a user profile | Interactive shell environments |
| **Explicit** | A manually curated set of store hashes | Testing, debugging |

A view is constructed by collecting the relevant store hashes and loading their
manifests. The manifests provide the file tree structure needed to serve FUSE
operations.

```rust
struct View {
    name: String,
    allowed: HashSet<StoreHash>,
    manifests: HashMap<StoreHash, Manifest>,
    mode: ViewMode,
    access_db: lmdb::Database,  // access.mdb
}

enum ViewMode {
    Eager,
    Async,
    Lazy,
}
```

## FUSE Operations

All FUSE operations are read-only. The filesystem resolves paths by splitting
them into a store hash prefix (`/nix/store/{hash}-{name}/...`) and a relative
path within that store object's manifest.

### Path Resolution

```rust
fn resolve(&self, path: &Path) -> Result<(&Manifest, &ManifestEntry)> {
    let store_path = path.strip_prefix("/nix/store")?;
    let store_hash = parse_store_hash(store_path)?;

    if !self.view.allowed.contains(&store_hash) {
        return Err(ENOENT);
    }

    let manifest = self.view.manifests.get(&store_hash)
        .ok_or(ENOENT)?;

    let relative = store_path.strip_prefix(manifest.name())?;
    let entry = manifest.lookup(relative)?;

    self.view.access_db.touch(store_hash, Instant::now());
    Ok((manifest, entry))
}
```

### getattr

Look up the manifest entry for a path and return file metadata. Directory
entries return the stored mode. File entries return the size (sum of chunk
sizes) and executable bit. Symlink entries return the symlink type.

```rust
fn getattr(&self, path: &Path) -> Result<FileAttr> {
    let (_, entry) = self.resolve(path)?;
    match entry {
        ManifestEntry::Dir { mode } => Ok(FileAttr {
            kind: Directory,
            perm: *mode,
            size: 0,
            ..default_attr()
        }),
        ManifestEntry::File { size, executable, .. } => Ok(FileAttr {
            kind: RegularFile,
            perm: if *executable { 0o555 } else { 0o444 },
            size: *size,
            ..default_attr()
        }),
        ManifestEntry::Symlink { .. } => Ok(FileAttr {
            kind: Symlink,
            perm: 0o777,
            size: 0,
            ..default_attr()
        }),
    }
}
```

### readdir

List entries from the manifest at the given directory path. The manifest stores
entries in sorted order, so a prefix scan yields direct children.

```rust
fn readdir(&self, path: &Path) -> Result<Vec<DirEntry>> {
    let (manifest, entry) = self.resolve(path)?;
    match entry {
        ManifestEntry::Dir { .. } => {
            let children = manifest.children_of(path);
            Ok(children.map(|e| DirEntry {
                name: e.name().to_owned(),
                kind: e.file_type(),
            }).collect())
        }
        _ => Err(ENOTDIR),
    }
}
```

### read

Look up the file's chunk list from the manifest. Calculate which chunks overlap
the requested `[offset, offset+size)` range. Read each overlapping chunk from
its pack file via `pread`, slice to the relevant portion, and copy into the
output buffer.

```rust
fn read(&self, path: &Path, offset: u64, size: u32) -> Result<Vec<u8>> {
    let (_, entry) = self.resolve(path)?;
    let chunks = match entry {
        ManifestEntry::File { chunks, .. } => chunks,
        _ => return Err(EISDIR),
    };

    let mut buf = Vec::with_capacity(size as usize);
    let mut pos: u64 = 0;
    let end = offset + size as u64;

    for chunk_ref in chunks {
        let chunk_end = pos + chunk_ref.size;
        if chunk_end <= offset {
            pos = chunk_end;
            continue;
        }
        if pos >= end {
            break;
        }

        let data = self.chunk_store.pread_chunk(&chunk_ref.hash)?;

        let start_in_chunk = offset.saturating_sub(pos) as usize;
        let end_in_chunk = ((end - pos) as usize).min(data.len());
        buf.extend_from_slice(&data[start_in_chunk..end_in_chunk]);

        pos = chunk_end;
    }

    Ok(buf)
}
```

### readlink

Return the symlink target directly from the manifest entry.

```rust
fn readlink(&self, path: &Path) -> Result<PathBuf> {
    let (_, entry) = self.resolve(path)?;
    match entry {
        ManifestEntry::Symlink { target } => Ok(target.clone()),
        _ => Err(EINVAL),
    }
}
```

### open

Validate that the store path is in the view's allowed set. No file handle
state is needed -- all operations are stateless lookups against the manifest
and chunk store.

```rust
fn open(&self, path: &Path, flags: u32) -> Result<u64> {
    if flags & O_WRONLY != 0 || flags & O_RDWR != 0 {
        return Err(EROFS);
    }
    let _ = self.resolve(path)?;
    Ok(0) // no file handle needed
}
```

## Operation Modes

The three modes control when manifests and chunks are fetched from the network.
All modes serve the same FUSE interface -- the difference is whether a `read()`
or `readdir()` call can block on network I/O.

### Eager

All manifests and all chunks for every store hash in the view are fetched
before the FUSE mount becomes available. Every subsequent FUSE operation is a
local read with no network latency. The mount call blocks until fetch
completes.

Used for build containers where deterministic timing matters and all inputs are
known upfront.

```rust
async fn mount_eager(view: &View, store: &ChunkStore) -> Result<()> {
    let all_chunks: Vec<ChunkRef> = view.manifests.values()
        .flat_map(|m| m.all_chunk_refs())
        .collect();

    let missing = store.find_missing(&all_chunks);
    fetch_chunks_parallel(&missing, &view.providers).await?;

    fuse_mount(view)
}
```

### Async

Manifests are fetched immediately so the mount is available fast. A background
worker pool fetches chunks with priority ordering: `bin/` and `lib/` subtrees
first (likely to be accessed soonest), then everything else. If `read()` hits a
chunk that has not arrived yet, the chunk is promoted to urgent priority and the
call blocks until it is fetched. The view converges to fully local over time.

Used for interactive environments where startup latency matters but full
offline capability is desired eventually.

```rust
async fn mount_async(view: &View, store: &ChunkStore) -> Result<()> {
    // Manifests already loaded when view was created.
    let missing = store.find_missing(&view.all_chunk_refs());

    let fetch_queue = PriorityQueue::new();
    for chunk in &missing {
        let priority = if chunk.path_prefix == "bin" || chunk.path_prefix == "lib" {
            Priority::High
        } else {
            Priority::Normal
        };
        fetch_queue.push(chunk, priority);
    }

    tokio::spawn(background_fetcher(fetch_queue.clone(), store.clone()));
    fuse_mount_with_fallback(view, fetch_queue)
}

// Called when read() hits a not-yet-fetched chunk.
async fn fetch_urgent(hash: &ChunkHash, queue: &PriorityQueue) -> Vec<u8> {
    queue.promote(hash, Priority::Urgent);
    queue.wait_for(hash).await
}
```

### Lazy

Nothing is fetched until accessed. `readdir()` and `getattr()` on a store path
trigger manifest fetch for that store hash. `read()` triggers chunk fetch for
the specific chunks needed. Minimal local storage -- only accessed content is
ever fetched.

Used for browsing, inspecting, or one-off access to store paths where
downloading everything would be wasteful.

```rust
async fn resolve_lazy(
    &self,
    store_hash: &StoreHash,
) -> Result<&Manifest> {
    if let Some(m) = self.manifests.get(store_hash) {
        return Ok(m);
    }

    // Fetch manifest on demand.
    let manifest = fetch_manifest(store_hash, &self.providers).await?;
    self.manifests.insert(*store_hash, manifest);
    Ok(self.manifests.get(store_hash).unwrap())
}
```

## OverlayFS for Builds

Build containers need a writable `$out` directory. The FUSE mount is read-only,
so an OverlayFS layer provides writability:

```
overlay mount:
  lowerdir = /run/aos/views/{build_view}/store   (FUSE, read-only)
  upperdir = /run/aos/builds/{job_id}/upper       (tmpfs or ZFS dataset)
  workdir  = /run/aos/builds/{job_id}/work
  merged   = /run/aos/builds/{job_id}/merged      (bind-mounted as /nix/store in container)
```

The build process writes to `$out` (a path under `/nix/store/` in the
container). Writes land in the upper layer. After the build completes, the
daemon reads the upper layer contents, applies content-defined chunking, writes
chunks to the chunk store, generates a manifest, and publishes the new store
object to the DHT.

The lower FUSE layer is mounted in eager mode -- all input chunks must be local
before the build starts. This ensures builds never block on network I/O.

## Access Tracking

Each view maintains an LMDB database (`access.mdb`) that records the last
access time per store hash. Every `read()`, `readdir()`, or `getattr()` call
updates the record for the accessed store hash.

```rust
struct AccessRecord {
    store_hash: StoreHash,
    last_access: SystemTime,
    access_count: u64,
}
```

Access data serves two purposes:

- **GC eviction priority.** The daemon's LRU eviction policy uses access times
  to determine which chunks to evict first. Store hashes with recent access
  times are retained longer.
- **Provider TTL estimation.** When re-publishing DHT provider records, the
  daemon uses access frequency to estimate how long it will retain an object,
  setting the TTL accordingly.

When a view is destroyed, its access data can optionally be flushed to a global
access log for cross-view GC intelligence.

## Per-View State

```
/var/lib/aos/
  views/
    {view_name}/
      access.mdb          # LMDB: per-store-hash LRU tracking

/run/aos/
  views/
    {view_name}/
      store/              # FUSE mount point
```

Runtime state under `/run/aos/` is ephemeral and recreated on mount. Persistent
state under `/var/lib/aos/` survives reboots and is used for GC decisions.

## Build View Lifecycle

Build views are short-lived and tightly scoped. The full input delivery flow
-- from `.drv` fetch through closure resolution to FUSE mount -- is described in
[jobs.md](jobs.md) under "Build Input Delivery". See
[containers.md](containers.md) for the complete build container setup including
OverlayFS layering and output export flow.

1. **Create.** When a build job starts, the daemon creates a closure view
   containing the transitive input closure of the derivation. Mode is eager.

2. **Fetch.** All manifests and chunks for the input closure are fetched. The
   view mount blocks until everything is local.

3. **Mount.** The FUSE view is mounted. An OverlayFS layer is set up with a
   writable upper directory.

4. **Execute.** The build runs in a container with the overlay mounted as
   `/nix/store`. All reads are local. Writes go to the upper layer.

5. **Publish.** The daemon chunks the upper layer contents, generates a
   manifest, writes to the chunk store, and publishes to the DHT.

6. **Destroy.** The overlay is unmounted, the FUSE view is unmounted, and
   ephemeral state is cleaned up. Access data is optionally flushed.

## Relationship to Chunk Store

The FUSE filesystem is a read-only projection over the chunk store. All content
comes from pack files via `pread()`. The FUSE layer holds no data of its own --
it is purely a translation layer from POSIX filesystem semantics to manifest
lookups and chunk reads.

Multiple views over the same chunks share storage. A chunk that appears in ten
different store objects is stored once in the chunk store and served to any
view that references it. The FUSE layer does not copy or cache chunk data
beyond what the kernel's page cache provides.
