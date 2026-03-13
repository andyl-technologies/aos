# View Model

A **view** is a read-only projection of the chunk store, defined by a set of
store objects and their transitive closures. Views provide the filesystem
content that containers and interactive sessions operate on.

## ViewSpec

A view is defined by a `ViewSpec` — a list of root store hashes. The view
contains the **transitive closure** of those roots: every store object
referenced by the roots (directly or transitively through dependency
references) is included in the view.

```protobuf
message ViewSpec {
    repeated string store_hashes = 1;
}
```

For example, a build job's `ViewSpec` would list the input closure of the
derivation. A service container's `ViewSpec` would list the store hashes
composing the system profile. The transitive closure expands these roots to
include all dependencies.

## View Construction

When a view is created, the daemon:

1. **Resolves the closure.** Starting from the root store hashes, walks
   dependency references to compute the full transitive closure.
2. **Fetches manifests.** Retrieves the manifest for each store hash in the
   closure (from local store or via `/aos/store/manifest/1.0.0`).
3. **Fetches chunks.** Retrieves all chunks referenced by the manifests. The
   view mount blocks until all manifests and chunks are local — views are
   always fully materialized before becoming available.
4. **Mounts FUSE.** The daemon creates a FUSE filesystem presenting the
   closure as a directory tree. See [fuse.md](fuse.md) for FUSE implementation
   details.

All content must be local before the view is usable. There is no lazy or
partial fetching — the view is either fully available or not yet mounted.

## View as GC Pin

Store objects in an active (mounted) view are pinned against garbage
collection. The daemon tracks all store hashes in mounted views in memory.
GC cannot evict any of them. When a view is unmounted, its store hashes are
removed from the in-memory pin set and become eligible for LRU eviction.

See [gc.md](gc.md) for the full GC model.

## OverlayFS for Writable Containers

Some containers (notably `ACTIVATION_DERIVATION` builds) need a writable
output directory. Since the FUSE view is read-only, an OverlayFS layer
provides writability:

```
overlay mount:
  lowerdir = /run/aos/views/{view_name}/store   (FUSE, read-only)
  upperdir = /run/aos/builds/{job_id}/upper      (tmpfs or ZFS dataset)
  workdir  = /run/aos/builds/{job_id}/work
  merged   = /run/aos/builds/{job_id}/merged     (bind-mounted into container)
```

The build process writes to `$out` in the merged directory. Writes land in
the upper layer. After the build completes, the daemon reads the upper layer
contents, applies content-defined chunking, writes chunks to the chunk store,
generates a manifest, and publishes the new store object to the DHT.

See [containers.md](containers.md) for the full container setup including
OverlayFS layering and output export flow.

## View Lifecycle

1. **Create.** Daemon computes the transitive closure from the `ViewSpec`.
2. **Fetch.** All manifests and chunks are fetched. Mount blocks until
   everything is local.
3. **Mount.** FUSE view is mounted. Optional OverlayFS layer set up for
   writable containers.
4. **Active.** All reads are local. Store hashes are pinned against GC.
5. **Destroy.** Overlay unmounted (if present), FUSE view unmounted, ephemeral
   state cleaned up. Pin set updated.

## Per-View State

```
/run/aos/
  views/
    {view_name}/
      store/              # FUSE mount point
```

Runtime state under `/run/aos/` is ephemeral and recreated on mount.

## Relationship to Other Docs

- [fuse.md](fuse.md) -- FUSE filesystem implementation (path resolution, chunk
  reads, operations).
- [containers.md](containers.md) -- how containers use views (OverlayFS setup,
  output registration).
- [gc.md](gc.md) -- views as GC pins.
- [protocol.md](protocol.md) -- `ViewSpec` protobuf definition.
