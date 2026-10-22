//! Compiles and reads the FUSE worker's structural metadata index.
//!
//! The compiler consumes already resolved metadata, including graft boundaries;
//! it has no store or content-fetching interface. The reader borrows bytes and
//! validates their complete structure before exposing allocation-free lookup
//! and directory iteration. Neither compilation nor parsing authenticates a
//! root, seals an inode, pins a cache entry, or registers a FUSE surface.
//!
//! ```text
//! TRIX v2: header | root | paths | targets | hashes | metadata | entries | children | links
//! entries: full-path order; children: contiguous runs of entry-table indices
//! ```

mod compile;
mod compiled;
mod links;
mod mapping;
mod metadata;
mod nodes;
mod tree;

pub use compile::compile;
pub use compiled::{CompiledIndex, IndexKey};
pub use mapping::{MappedIndex, MappingError};
pub use metadata::{Field, Fields, FieldsIter, Metadata};
pub use nodes::compile_nodes;
pub use tree::compile_tree;

use std::fmt;

use terrane_format::identity::Digest;
use terrane_format::tree_format::{ContentRef, MAX_SYMLINK, validate_key};

/// The structural index format version.
pub const VERSION: u16 = 2;

const HEADER: usize = 84;
const ENTRY: usize = 76;
const NONE: u32 = u32::MAX;
const NO_HASH: u64 = u64::MAX;

/// A malformed index, invalid compiler input, or exceeded compilation bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The header, offsets, flags, or encoded entry is invalid.
    Encoding,
    /// Paths, parent links, or child runs do not describe one rooted tree.
    Tree,
    /// A configured size bound or an addressable format limit was exceeded.
    Limit,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Encoding => "invalid structural index encoding",
            Self::Tree => "invalid structural index tree",
            Self::Limit => "structural index limit exceeded",
        })
    }
}

impl std::error::Error for Error {}

/// Metadata retained for one resolved path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind<'a> {
    /// A directory, optionally beginning a graft governed by another root.
    Directory {
        /// The grafted root, or `None` to inherit the parent's governing root.
        governing_root: Option<Digest>,
    },
    /// An inline chunk or manifest reference and its logical file size.
    File {
        /// The typed content identity; no file bytes are retained here.
        content: ContentRef,
        /// The logical file length in bytes.
        size: u64,
    },
    /// An exact, unnormalized symlink target.
    Symlink(&'a [u8]),
}

/// One compiler input, in strictly increasing full-path byte order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record<'a> {
    /// A nonempty root-relative path; every parent directory must be present.
    pub path: &'a [u8],
    /// The resolved entry metadata, with graft roots explicitly preserved.
    pub kind: Kind<'a>,
}

/// A completely checked borrowed index; it owns no per-entry allocation.
#[derive(Clone, Copy, Debug)]
pub struct Index<'a> {
    bytes: &'a [u8],
    count: u32,
    paths: usize,
    targets: usize,
    hashes: usize,
    entries: usize,
    children: usize,
    metadata: usize,
    links: usize,
}

impl<'a> Index<'a> {
    /// Validates an entire index before making entries available.
    ///
    /// The supplied byte slice must remain stable for its borrowed lifetime.
    /// In a worker, the mapping owner must additionally establish actual sealed
    /// inode custody before constructing this slice.
    ///
    /// # Errors
    /// Returns an error for unsupported formats, malformed offsets or entries,
    /// noncanonical arenas, or inconsistent path and child relationships.
    pub fn open(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.get(..4) != Some(b"TRIX")
            || number::<2>(bytes, 4)? != u64::from(VERSION)
            || number::<2>(bytes, 6)? != 0
            || number::<8>(bytes, 12)? != HEADER as u64
            || offset(bytes, 60)? != bytes.len()
        {
            return Err(Error::Encoding);
        }

        let index = Self {
            bytes,
            count: number::<4>(bytes, 8)? as u32,
            paths: offset(bytes, 20)?,
            targets: offset(bytes, 28)?,
            hashes: offset(bytes, 36)?,
            entries: offset(bytes, 44)?,
            children: offset(bytes, 52)?,
            metadata: offset(bytes, 68)?,
            links: offset(bytes, 76)?,
        };
        let entry_bytes = (index.count as usize)
            .checked_mul(ENTRY)
            .ok_or(Error::Limit)?;
        let child_bytes = (index.count as usize)
            .checked_sub(1)
            .and_then(|count| count.checked_mul(4))
            .ok_or(Error::Encoding)?;
        if index.paths != HEADER + 32
            || index.paths > index.targets
            || index.targets > index.hashes
            || index.hashes > index.metadata
            || index.metadata > index.entries
            || !(index.metadata - index.hashes).is_multiple_of(32)
            || index.entries.checked_add(entry_bytes) != Some(index.children)
            || index.children.checked_add(child_bytes) != Some(index.links)
            || index.links > bytes.len()
            || !(bytes.len() - index.links).is_multiple_of(4)
        {
            return Err(Error::Encoding);
        }

        index.validate()?;
        index.validate_links()?;
        Ok(index)
    }

    /// Returns the root identity recorded in the index, without authenticating it.
    #[must_use]
    pub fn root_hash(&self) -> Digest {
        let mut hash = [0; 32];
        hash.copy_from_slice(&self.bytes[HEADER..HEADER + 32]);
        hash
    }

    /// Returns the number of entries, including the synthesized root directory.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.count
    }

    /// Returns whether the index has no entries (a valid index always has a root).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Finds a full path by binary search; the empty path selects the root.
    #[must_use]
    pub fn lookup(&self, path: &[u8]) -> Option<Entry<'a>> {
        let mut start = 0;
        let mut end = self.count;
        while start < end {
            let middle = start + (end - start) / 2;
            let entry = self.entry(middle)?;
            match entry.path().cmp(path) {
                std::cmp::Ordering::Less => start = middle + 1,
                std::cmp::Ordering::Greater => end = middle,
                std::cmp::Ordering::Equal => return Some(entry),
            }
        }
        None
    }

    /// Returns a validated entry by its stable table position.
    #[must_use]
    pub fn entry(&self, position: u32) -> Option<Entry<'a>> {
        let (path, kind) = self.decode(position).ok()?;
        Some(Entry {
            index: *self,
            position,
            path,
            kind,
        })
    }

    fn record(&self, position: u32) -> Result<&'a [u8], Error> {
        if position >= self.count {
            return Err(Error::Encoding);
        }
        let start = self
            .entries
            .checked_add((position as usize).checked_mul(ENTRY).ok_or(Error::Limit)?)
            .ok_or(Error::Limit)?;
        self.bytes.get(start..start + ENTRY).ok_or(Error::Encoding)
    }

    fn metadata_bytes(&self, position: u32) -> Result<&'a [u8], Error> {
        let record = self.record(position)?;
        arena_slice(
            self.bytes,
            self.metadata,
            self.entries,
            offset(record, 52)?,
            offset32(record, 60)?,
        )
    }

    fn hash(&self, position: u64) -> Result<Digest, Error> {
        let relative = usize::try_from(position)
            .map_err(|_| Error::Encoding)?
            .checked_mul(32)
            .ok_or(Error::Encoding)?;
        let arena = self
            .bytes
            .get(self.hashes..self.metadata)
            .ok_or(Error::Encoding)?;
        let mut hash = [0; 32];
        hash.copy_from_slice(
            arena
                .get(relative..relative.checked_add(32).ok_or(Error::Encoding)?)
                .ok_or(Error::Encoding)?,
        );
        Ok(hash)
    }

    fn decode(&self, position: u32) -> Result<(&'a [u8], Kind<'a>), Error> {
        let record = self.record(position)?;
        let path = arena_slice(
            self.bytes,
            self.paths,
            self.targets,
            offset(record, 0)?,
            offset32(record, 8)?,
        )?;
        let flags = record[13];
        let size = number::<8>(record, 16)?;
        let hash = number::<8>(record, 24)?;
        let target_offset = offset32(record, 32)?;
        let target_length = offset32(record, 36)?;
        if number::<2>(record, 14)? != 0 || flags > 1 {
            return Err(Error::Encoding);
        }
        let kind = match record[12] {
            1 if size == 0 && target_offset == 0 && target_length == 0 => Kind::Directory {
                governing_root: if flags == 1 {
                    Some(self.hash(hash)?)
                } else if hash == NO_HASH {
                    None
                } else {
                    return Err(Error::Encoding);
                },
            },
            2 if target_offset == 0 && target_length == 0 => Kind::File {
                content: if flags == 0 {
                    ContentRef::Inline(self.hash(hash)?)
                } else {
                    ContentRef::Manifest(self.hash(hash)?)
                },
                size,
            },
            3 if flags == 0
                && hash == NO_HASH
                && size == target_length as u64
                && target_length > 0
                && target_length <= MAX_SYMLINK =>
            {
                let target = arena_slice(
                    self.bytes,
                    self.targets,
                    self.hashes,
                    target_offset,
                    target_length,
                )?;
                if target.contains(&0) {
                    return Err(Error::Encoding);
                }
                Kind::Symlink(target)
            }
            _ => return Err(Error::Encoding),
        };
        Ok((path, kind))
    }

    fn validate(&self) -> Result<(), Error> {
        let mut metadata_cursor = 0;
        let mut path_cursor = 0;
        let mut target_cursor = 0;
        let mut child_cursor = 0;
        let mut previous_path: &[u8] = &[];
        for position in 0..self.count {
            let record = self.record(position)?;
            let (path, kind) = self.decode(position)?;
            if offset(record, 52)? != metadata_cursor {
                return Err(Error::Encoding);
            }
            let metadata_bytes = self.metadata_bytes(position)?;
            metadata::validate(metadata_bytes)?;
            let metadata = metadata::view(metadata_bytes)?;
            let is_graft = matches!(
                kind,
                Kind::Directory {
                    governing_root: Some(_)
                }
            );
            let permits_mode = position != 0
                && matches!(
                    kind,
                    Kind::File { .. }
                        | Kind::Directory {
                            governing_root: None
                        }
                );
            if (metadata.mode.is_some() && !permits_mode)
                || (position != 0 && !is_graft && !metadata.root_properties.is_empty())
                || (!is_graft && !metadata.graft_overrides.is_empty())
            {
                return Err(Error::Encoding);
            }
            metadata_cursor += metadata_bytes.len();
            if offset(record, 0)? != path_cursor {
                return Err(Error::Encoding);
            }
            path_cursor += path.len();
            let parent = number::<4>(record, 40)? as u32;
            if position == 0 {
                if !path.is_empty()
                    || parent != NONE
                    || kind
                        != (Kind::Directory {
                            governing_root: None,
                        })
                {
                    return Err(Error::Tree);
                }
            } else {
                validate_key(path).map_err(|_| Error::Tree)?;
                if previous_path >= path || parent >= position {
                    return Err(Error::Tree);
                }
                let (parent_path, parent_kind) = self.decode(parent)?;
                let expected_parent = path
                    .iter()
                    .rposition(|byte| *byte == b'/')
                    .map_or(&b""[..], |slash| &path[..slash]);
                if parent_path != expected_parent || !matches!(parent_kind, Kind::Directory { .. })
                {
                    return Err(Error::Tree);
                }
            }
            previous_path = path;

            if let Kind::Symlink(target) = kind {
                if offset32(record, 32)? != target_cursor {
                    return Err(Error::Encoding);
                }
                target_cursor += target.len();
            }
            let first = offset32(record, 44)?;
            let count = offset32(record, 48)?;
            if first != child_cursor || (!matches!(kind, Kind::Directory { .. }) && count != 0) {
                return Err(Error::Tree);
            }
            let end = first.checked_add(count).ok_or(Error::Tree)?;
            if end > self.count as usize - 1 {
                return Err(Error::Tree);
            }
            let mut previous_child = 0;
            for child in first..end {
                let child = number::<4>(self.bytes, self.children + child * 4)? as u32;
                if child == 0
                    || child <= previous_child
                    || number::<4>(self.record(child)?, 40)? != u64::from(position)
                {
                    return Err(Error::Tree);
                }
                previous_child = child;
            }
            child_cursor = end;
        }
        if metadata_cursor != self.entries - self.metadata
            || path_cursor != self.targets - self.paths
            || target_cursor != self.hashes - self.targets
            || child_cursor != self.count as usize - 1
        {
            return Err(Error::Encoding);
        }
        let mut previous_hash = None;
        for hash in self.bytes[self.hashes..self.metadata].as_chunks::<32>().0 {
            if previous_hash.is_some_and(|previous: &Digest| previous >= hash) {
                return Err(Error::Encoding);
            }
            previous_hash = Some(hash);
        }
        Ok(())
    }
}

/// A borrowed entry whose offsets and tree relationships were checked at open.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    index: Index<'a>,
    position: u32,
    path: &'a [u8],
    kind: Kind<'a>,
}

impl<'a> Entry<'a> {
    /// Returns the root-relative full path, or empty bytes for the root.
    #[must_use]
    pub fn path(&self) -> &'a [u8] {
        self.path
    }

    /// Returns the structural metadata for this entry.
    #[must_use]
    pub fn kind(&self) -> Kind<'a> {
        self.kind
    }

    /// Borrows recorded attributes and properties without decoding or allocation.
    ///
    /// Presentation schemas and defaults are applied by the worker, not here.
    ///
    /// # Errors
    /// Returns an error if the entry's checked metadata cannot be read.
    pub fn metadata(&self) -> Result<Metadata<'a>, Error> {
        metadata::view(self.index.metadata_bytes(self.position)?)
    }

    /// Returns this file's validated first hard-link path, or this nonfile entry.
    ///
    /// # Errors
    /// Returns an error if a canonical record cannot be read.
    pub fn canonical_inode(&self) -> Result<Self, Error> {
        if !matches!(self.kind, Kind::File { .. }) {
            return Ok(*self);
        }
        let canonical = number::<4>(self.index.record(self.position)?, 64)? as u32;
        self.index.entry(canonical).ok_or(Error::Tree)
    }

    /// Returns the exact file link count, directory subdirectory count plus two,
    /// or one for a symlink, without allocation.
    ///
    /// # Errors
    /// Returns an error if a checked record is unavailable or the count overflows.
    pub fn link_count(&self) -> Result<u32, Error> {
        match self.kind {
            Kind::File { .. } => {
                let canonical = self.canonical_inode()?;
                Ok(number::<4>(self.index.record(canonical.position)?, 72)? as u32)
            }
            Kind::Directory { .. } => self.children()?.try_fold(2u32, |count, child| {
                count
                    .checked_add(u32::from(matches!(child.kind, Kind::Directory { .. })))
                    .ok_or(Error::Limit)
            }),
            Kind::Symlink(_) => Ok(1),
        }
    }

    /// Returns the governing root, following validated directory ancestry.
    ///
    /// # Errors
    /// Returns an error if an ancestor record cannot be decoded.
    pub fn governing_root(&self) -> Result<Digest, Error> {
        let boundary = self.governing_boundary()?;
        if boundary == 0 {
            return Ok(self.index.root_hash());
        }
        match self.index.decode(boundary)?.1 {
            Kind::Directory {
                governing_root: Some(root),
            } => Ok(root),
            _ => Err(Error::Tree),
        }
    }

    // Equal graft hashes at different namespace paths are separate inode sets.
    fn governing_boundary(&self) -> Result<u32, Error> {
        let mut position = self.position;
        loop {
            if position == 0
                || matches!(
                    self.index.decode(position)?.1,
                    Kind::Directory {
                        governing_root: Some(_)
                    }
                )
            {
                return Ok(position);
            }
            position = number::<4>(self.index.record(position)?, 40)? as u32;
        }
    }

    /// Returns immediate children in full-path byte order without allocation.
    ///
    /// # Errors
    /// Returns an error if this entry is not a directory or its record is invalid.
    pub fn children(&self) -> Result<Children<'a>, Error> {
        if !matches!(self.kind(), Kind::Directory { .. }) {
            return Err(Error::Tree);
        }
        let record = self.index.record(self.position)?;
        Ok(Children {
            index: self.index,
            next: offset32(record, 44)?,
            remaining: offset32(record, 48)?,
        })
    }
}

/// An allocation-free scan of one directory's contiguous child-index run.
#[derive(Debug)]
pub struct Children<'a> {
    index: Index<'a>,
    next: usize,
    remaining: usize,
}

impl<'a> Iterator for Children<'a> {
    type Item = Entry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let position = number::<4>(self.index.bytes, self.index.children + self.next * 4).ok()?;
        self.next += 1;
        self.remaining -= 1;
        self.index.entry(position as u32)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for Children<'_> {}
impl std::iter::FusedIterator for Children<'_> {}

fn number<const N: usize>(bytes: &[u8], start: usize) -> Result<u64, Error> {
    let mut value = [0; 8];
    let end = start.checked_add(N).ok_or(Error::Encoding)?;
    value[..N].copy_from_slice(bytes.get(start..end).ok_or(Error::Encoding)?);
    Ok(u64::from_le_bytes(value))
}

fn offset(bytes: &[u8], start: usize) -> Result<usize, Error> {
    usize::try_from(number::<8>(bytes, start)?).map_err(|_| Error::Encoding)
}

fn offset32(bytes: &[u8], start: usize) -> Result<usize, Error> {
    usize::try_from(number::<4>(bytes, start)?).map_err(|_| Error::Encoding)
}

fn arena_slice(
    bytes: &[u8],
    start: usize,
    end: usize,
    relative: usize,
    length: usize,
) -> Result<&[u8], Error> {
    bytes
        .get(start..end)
        .and_then(|arena| arena.get(relative..relative.checked_add(length)?))
        .ok_or(Error::Encoding)
}

#[cfg(test)]
mod tests;
