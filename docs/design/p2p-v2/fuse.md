# FUSE Filesystem

The AOS FUSE filesystem presents a view as a standard read-only directory tree.
It reconstructs files on-the-fly from chunks in pack files. Multiple views can
be mounted simultaneously over the same underlying chunk data with no
duplication.

See [view.md](view.md) for the view model (ViewSpec, transitive closure,
lifecycle, OverlayFS). This document covers the FUSE implementation.

## View Struct

The FUSE layer operates over a fully materialized view — all manifests and
chunks are local before the mount becomes available.

```rust
struct View {
    name: String,
    allowed: HashSet<StoreHash>,
    manifests: HashMap<StoreHash, Manifest>,
}
```

## Path Resolution

All FUSE operations resolve paths by splitting them into a store hash prefix
and a relative path within that store object's manifest.

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

    Ok((manifest, entry))
}
```

## FUSE Operations

All operations are read-only.

### getattr

Look up the manifest entry for a path and return file metadata.

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

List entries from the manifest at the given directory path.

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
state is needed — all operations are stateless lookups against the manifest
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

## Relationship to Chunk Store

The FUSE filesystem is a read-only projection over the chunk store. All content
comes from pack files via `pread()`. The FUSE layer holds no data of its own —
it is purely a translation layer from POSIX filesystem semantics to manifest
lookups and chunk reads.

Multiple views over the same chunks share storage. A chunk that appears in ten
different store objects is stored once in the chunk store and served to any
view that references it. The FUSE layer does not copy or cache chunk data
beyond what the kernel's page cache provides.
