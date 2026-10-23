//! Encodes bounded FUSE directory pages from checked structural metadata.
//!
//! Entries use the native-order Linux `fuse_dirent` layout and eight-byte record
//! alignment. The caller supplies a reusable output buffer and a connection's
//! startup-reserved inode table. No path, name, record or inode row is allocated
//! while reading a page. This module performs no IO and grants no repository,
//! connection or exposure authority; the worker separately retains its original
//! authenticated sealed index and matches requests to that served namespace.
//!
//! ```text
//! record: u64 inode | u64 next_cookie | u32 name_length | u32 type | name | padding
//! cookies: 0=start, 1=after '.', 2=after '..', 3=after first direct child, ...
//! ```

use crate::{
    inode_policy::{self, InodeTable},
    structural_index::{self, Entry, Index, Kind},
};
use std::fmt;

/// Refuses missing metadata, invalid worker storage and exhausted page bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The requested root-relative directory path is absent from the index.
    NotFound,
    /// The requested path names a file or symlink.
    NotDirectory,
    /// The table uses lazy storage, which could allocate in the request path.
    UnreservedInodes,
    /// The buffer cannot hold the first pending complete directory record.
    BufferTooSmall,
    /// Checked structural relationships cannot supply the requested metadata.
    Index(structural_index::Error),
    /// The connection's original inode table refuses a new or changed identity.
    Inode(inode_policy::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NotFound => "FUSE directory is absent from structural metadata",
            Self::NotDirectory => "FUSE directory request names a non-directory",
            Self::UnreservedInodes => "FUSE directory requires startup-reserved inode storage",
            Self::BufferTooSmall => "FUSE directory buffer cannot hold its next complete entry",
            Self::Index(_) => "FUSE directory structural metadata is invalid",
            Self::Inode(_) => "FUSE directory inode assignment failed",
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Index(error) => Some(error),
            Self::Inode(error) => Some(error),
            _ => None,
        }
    }
}

/// Writes one directory page and returns its initialized byte length.
///
/// The page contains `.` and `..`, followed by direct children in index order.
/// Names preserve their original bytes. Cookies count complete entries in this
/// immutable directory; resuming beyond the end returns zero, including with an
/// empty buffer. Seeking to a child skips its contiguous index run directly.
/// Root's parent is root. File hard-link aliases use their canonical inode row.
///
/// A record that does not fit is left for the next page and consumes no inode
/// number. Padding is initialized and bytes after the returned prefix stay
/// untouched. The worker must use the same inode table for all metadata replies
/// on this connection and fault that exposure if inode assignment fails.
///
/// # Errors
/// Refuses absent paths, non-directories, lazy inode storage, an output buffer
/// too small for the first pending record, invalid metadata and inode capacity
/// or collision failures. On error the caller must discard the entire output;
/// successfully assigned earlier inode numbers remain retained and are never
/// recycled. No partially encoded record is exposed.
pub fn read(
    index: Index<'_>,
    path: &[u8],
    cookie: u64,
    inodes: &mut InodeTable,
    output: &mut [u8],
) -> Result<usize, Error> {
    if !inodes.is_reserved() {
        return Err(Error::UnreservedInodes);
    }
    let directory = index.lookup(path).ok_or(Error::NotFound)?;
    let mut children = directory.children().map_err(|error| {
        if matches!(directory.kind(), Kind::Directory { .. }) {
            Error::Index(error)
        } else {
            Error::NotDirectory
        }
    })?;
    if cookie >= children.len() as u64 + 2 {
        return Ok(0);
    }

    let parent_path = path
        .iter()
        .rposition(|byte| *byte == b'/')
        .map_or(b"".as_slice(), |separator| &path[..separator]);
    let parent = index
        .lookup(parent_path)
        .ok_or(Error::Index(structural_index::Error::Tree))?;
    let mut written = 0;
    for (position, name, entry) in [(0, b".".as_slice(), directory), (1, b"..", parent)] {
        if cookie <= position && !append(entry, name, position + 1, inodes, output, &mut written)? {
            return Ok(written);
        }
    }

    let skipped = usize::try_from(cookie.saturating_sub(2))
        .map_err(|_| Error::Index(structural_index::Error::Limit))?;
    let first = children.nth(skipped);
    for (next_cookie, child) in (skipped as u64 + 3..).zip(first.into_iter().chain(children)) {
        let name = child
            .path()
            .rsplit(|byte| *byte == b'/')
            .next()
            .ok_or(Error::Index(structural_index::Error::Tree))?;
        if !append(child, name, next_cookie, inodes, output, &mut written)? {
            break;
        }
    }
    Ok(written)
}

/// Checks complete record capacity before assigning any new inode number.
fn append(
    entry: Entry<'_>,
    name: &[u8],
    cookie: u64,
    inodes: &mut InodeTable,
    output: &mut [u8],
    written: &mut usize,
) -> Result<bool, Error> {
    // Checked path components fit the tree format's finite component bound;
    // the two synthetic names are shorter. Record arithmetic fits usize/u32.
    let length = (24 + name.len() + 7) & !7;
    let Some(record) = output
        .get_mut(*written..)
        .and_then(|tail| tail.get_mut(..length))
    else {
        return if *written == 0 {
            Err(Error::BufferTooSmall)
        } else {
            Ok(false)
        };
    };
    let (_, inode) = inodes.touch_entry(entry).map_err(Error::Inode)?;
    let kind = match entry.kind() {
        Kind::Directory { .. } => libc::DT_DIR,
        Kind::File { .. } => libc::DT_REG,
        Kind::Symlink(_) => libc::DT_LNK,
    };

    record.fill(0);
    record[..8].copy_from_slice(&u64::from(inode.number()).to_ne_bytes());
    record[8..16].copy_from_slice(&cookie.to_ne_bytes());
    record[16..20].copy_from_slice(&(name.len() as u32).to_ne_bytes());
    record[20..24].copy_from_slice(&u32::from(kind).to_ne_bytes());
    record[24..24 + name.len()].copy_from_slice(name);
    *written += length;
    Ok(true)
}

#[cfg(test)]
mod tests;
