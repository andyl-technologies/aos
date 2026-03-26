# FUSE Filesystem

The AOS FUSE filesystem presents a view as a standard read-only directory tree.
It reconstructs files on-the-fly from chunks in pack files. Multiple views can
be mounted simultaneously over the same underlying chunk data with no
duplication.

See [view.md](view.md) for the view model (ViewSpec, transitive closure,
lifecycle, OverlayFS). This document covers the FUSE implementation.

## View Struct

The FUSE layer operates over a fully materialized view — all NixObjects, tree/blob objects, and
chunks are local before the mount becomes available.

```rust
struct View {
    name: String,
    allowed: HashSet<StoreHash>,
    root_trees: HashMap<StoreHash, TreeObject>,  // root tree per store object
    trees: HashMap<[u8; 32], TreeObject>,         // all trees by blake3
    blobs: HashMap<[u8; 32], BlobObject>,          // all blobs by blake3
}
```

## Path Resolution

All FUSE operations resolve paths by splitting them into a store hash prefix
and a relative path, then traversing the git merkle tree to find the entry.

```rust
fn resolve(&self, path: &Path) -> Result<(&TreeEntry, Option<&BlobObject>)> {
    let store_path = path.strip_prefix("/nix/store")?;
    let store_hash = parse_store_hash(store_path)?;

    if !self.view.allowed.contains(&store_hash) {
        return Err(ENOENT);
    }

    let root = self.view.root_trees.get(&store_hash).ok_or(ENOENT)?;
    let relative = store_path.strip_prefix_name()?;

    // Traverse the tree hierarchy
    let components: Vec<&str> = relative.components().collect();
    let mut current_tree = root;

    for (i, name) in components.iter().enumerate() {
        let entry = current_tree.entries.iter()
            .find(|e| e.name == *name)
            .ok_or(ENOENT)?;

        if i == components.len() - 1 {
            // Leaf: return entry + blob ref (if file/symlink)
            let blob = if entry.mode != 0o040000 {
                Some(self.view.blobs.get(&entry.hash).ok_or(ENOENT)?)
            } else {
                None
            };
            return Ok((entry, blob));
        }

        // Directory: descend into subtree
        current_tree = self.view.trees.get(&entry.hash).ok_or(ENOENT)?;
    }

    Err(ENOENT)
}
```

## FUSE Operations

All operations are read-only.

### getattr

Look up the tree entry for a path and return file metadata. The entry's `mode`
field determines the type: `040000` = directory, `100644`/`100755` = file,
`120000` = symlink.

```rust
fn getattr(&self, path: &Path) -> Result<FileAttr> {
    let (entry, blob) = self.resolve(path)?;
    match entry.mode {
        0o040000 => Ok(FileAttr {
            kind: Directory,
            perm: 0o555,
            size: 0,
            ..default_attr()
        }),
        0o100644 | 0o100755 => Ok(FileAttr {
            kind: RegularFile,
            perm: if entry.mode == 0o100755 { 0o555 } else { 0o444 },
            size: blob.unwrap().size,
            ..default_attr()
        }),
        0o120000 => Ok(FileAttr {
            kind: Symlink,
            perm: 0o777,
            size: 0,
            ..default_attr()
        }),
        _ => Err(ENOENT),
    }
}
```

### readdir

List entries from the tree object at the given directory path.

```rust
fn readdir(&self, path: &Path) -> Result<Vec<DirEntry>> {
    let (entry, _) = self.resolve(path)?;
    if entry.mode != 0o040000 {
        return Err(ENOTDIR);
    }

    let current_tree = self.view.trees.get(&entry.hash).ok_or(ENOENT)?;
    Ok(current_tree.entries.iter().map(|e| DirEntry {
        name: e.name.clone(),
        kind: match e.mode {
            0o040000 => Directory,
            0o120000 => Symlink,
            _ => RegularFile,
        },
    }).collect())
}
```

### read

Look up the file's BlobObject via tree traversal, then navigate its chunk tree.
For small files (`root_height == 0`), the root chunk is the single data chunk —
read it via `pread` and slice to the requested range. For large files
(`root_height > 0`), walk the chunk tree from the root down to the height-0
leaf chunks that cover `[offset, offset+size)`, read those data chunks, and
assemble the result.

```rust
fn read(&self, path: &Path, offset: u64, size: u32) -> Result<Vec<u8>> {
    let (entry, blob) = self.resolve(path)?;
    let blob = match entry.mode {
        0o100644 | 0o100755 => blob.ok_or(EISDIR)?,
        _ => return Err(EISDIR),
    };

    let end = (offset + size as u64).min(blob.size);
    if offset >= blob.size {
        return Ok(Vec::new());
    }

    if blob.root_height == 0 {
        // Small file: root_chunk IS the single data chunk
        let data = self.chunk_store.pread_chunk(&blob.root_chunk)?;
        let start = offset as usize;
        let end = (end as usize).min(data.len());
        return Ok(data[start..end].to_vec());
    }

    // Large file: walk the chunk tree to find leaf chunks
    let leaves = self.resolve_leaves(blob.root_chunk, blob.root_height, offset, end)?;

    let mut buf = Vec::with_capacity(size as usize);
    let mut pos = leaves[0].0; // file offset of first leaf

    for (leaf_offset, chunk_hash) in &leaves {
        let data = self.chunk_store.pread_chunk(chunk_hash)?;
        let chunk_end = leaf_offset + data.len() as u64;

        let start_in_chunk = offset.saturating_sub(*leaf_offset) as usize;
        let end_in_chunk = ((end - leaf_offset) as usize).min(data.len());
        buf.extend_from_slice(&data[start_in_chunk..end_in_chunk]);

        pos = chunk_end;
    }

    Ok(buf)
}

/// Walk the chunk tree from a node at the given height down to the height-0
/// leaf chunks that overlap [offset, end). Returns (file_offset, chunk_hash)
/// pairs for each leaf.
fn resolve_leaves(
    &self, node: XxH128, height: u32, offset: u64, end: u64,
) -> Result<Vec<(u64, XxH128)>> {
    let data = self.chunk_store.pread_chunk(&node)?;
    let children: Vec<ChunkRef> = decode_chunk_refs(&data);

    if height == 1 {
        // Children are data chunks (height 0)
        let mut leaves = Vec::new();
        let mut pos: u64 = 0;
        for child in &children {
            let child_end = pos + child.size;
            if child_end > offset && pos < end {
                leaves.push((pos, child.hash));
            }
            pos = child_end;
        }
        return Ok(leaves);
    }

    // Children are interior nodes — recurse into those that overlap
    let mut leaves = Vec::new();
    let mut pos: u64 = 0;
    for child in &children {
        let child_end = pos + child.size;
        if child_end > offset && pos < end {
            leaves.extend(self.resolve_leaves(child.hash, height - 1, offset, end)?);
        }
        pos = child_end;
    }
    Ok(leaves)
}
```

### readlink

Read the symlink target from the blob's chunk tree. Symlink targets are tiny,
so `root_height` is always 0 — the root chunk is the single data chunk
containing the target path.

```rust
fn readlink(&self, path: &Path) -> Result<PathBuf> {
    let (entry, blob) = self.resolve(path)?;
    match entry.mode {
        0o120000 => {
            let blob = blob.ok_or(EINVAL)?;
            // Symlinks are always small: root_height == 0, root_chunk is data
            let data = self.chunk_store.pread_chunk(&blob.root_chunk)?;
            Ok(PathBuf::from(OsString::from_vec(data)))
        }
        _ => Err(EINVAL),
    }
}
```

Symlink targets are returned as-is from the blob content. The FUSE layer does
NOT resolve symlinks — the kernel handles symlink resolution. Symlinks that
point outside the view (e.g., `../../../etc/passwd`) resolve to `ENOENT`
because the view only contains allowed store paths. Cross-view symlinks are
not a security concern — the FUSE mount presents a complete namespace where
paths outside the allowed set simply don't exist.

### open

Validate that the store path is in the view's allowed set. No file handle
state is needed — all operations are stateless lookups against the object store
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

## Content-Addressed Object Model

The FUSE layer operates on the git merkle tree structure. Path resolution
traverses tree objects (directories) to find entries (files, symlinks,
subdirectories). File reads navigate the BlobObject's chunk tree. See
[git-store.md](git-store.md) for the content-addressed object model.

## Relationship to Chunk Store

The FUSE filesystem is a read-only projection over the chunk store. All content
comes from pack files via `pread()`. The FUSE layer holds no data of its own —
it is purely a translation layer from POSIX filesystem semantics to tree/blob
lookups and chunk reads.

Multiple views over the same chunks share storage. A chunk that appears in ten
different store objects is stored once in the chunk store and served to any
view that references it. The FUSE layer does not copy or cache chunk data
beyond what the kernel's page cache provides.

- [git-store.md](git-store.md) -- content-addressed object model (tree/blob
  objects over chunk trees).
