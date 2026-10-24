//! Encodes FUSE metadata replies from original checked structural entries.
//!
//! Native-order payloads follow Linux `fuse_entry_out` (128 bytes) and
//! `fuse_attr_out` (104 bytes). Caller-owned buffers and startup-reserved inode
//! storage keep first lookup and attribute presentation allocation-free. The
//! dispatcher separately authenticates the index, resolves schema/time policy,
//! matches the outstanding request and owns the original FUSE connection.
//!
//! ```text
//! entry: node | generation | entry_ttl | attr_ttl | ttl_nsec[2] | attr[88]
//! getattr: attr_ttl | ttl_nsec | padding | attr[88]
//! ```

use crate::{
    inode_policy::{self, InodeTable},
    structural_index::{self, Entry, Kind},
};
use std::fmt;
use terrane_format::cbor::Decoder;

/// Selects cache validity for one prepared view's metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CachePolicy {
    /// Retains positive and negative metadata indefinitely for a pinned view.
    Pinned,
    /// Disables caching for follow views and policies with access-time rules.
    Revalidate,
}

impl CachePolicy {
    fn seconds(self) -> u64 {
        match self {
            Self::Pinned => u64::MAX,
            Self::Revalidate => 0,
        }
    }
}

/// Holds a checked presentation timestamp, independent of native backing times.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    seconds: i64,
    nanoseconds: u32,
}

impl Timestamp {
    /// Checks signed Unix seconds and a fractional nanosecond component.
    ///
    /// # Errors
    /// Refuses nanoseconds greater than or equal to one billion.
    pub fn new(seconds: i64, nanoseconds: u32) -> Result<Self, Error> {
        if nanoseconds >= 1_000_000_000 {
            return Err(Error::Metadata);
        }
        Ok(Self {
            seconds,
            nanoseconds,
        })
    }
}

impl Default for Timestamp {
    fn default() -> Self {
        Self {
            seconds: 1,
            nanoseconds: 0,
        }
    }
}

/// Supplies presentation values resolved by the prepared view and its schema.
///
/// Optional canonical values override recorded fields, including malformed
/// recorded ownership. Otherwise recorded modes and registered `uid`/`gid`
/// attributes apply, with the RFC defaults. Time defaults to Unix second one;
/// a named timestamp attribute must be resolved by the caller before encoding.
/// These values grant no schema, repository or exposure authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct Presentation {
    /// Canonical permission/special bits, without file-type bits.
    pub mode: Option<u16>,
    /// Canonical user ID; the native all-ones sentinel is refused.
    pub uid: Option<u32>,
    /// Canonical group ID; the native all-ones sentinel is refused.
    pub gid: Option<u32>,
    /// Resolved access, modification and change time for this presentation.
    pub timestamp: Timestamp,
}

/// Refuses invalid presentation metadata or unavailable bounded worker storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Ownership, mode or timestamp cannot be represented faithfully.
    Metadata,
    /// The supplied output cannot hold the complete payload.
    BufferTooSmall,
    /// Lazy inode storage could allocate during a request.
    UnreservedInodes,
    /// The requested entry is not a symbolic link.
    NotSymlink,
    /// Checked structural relationships cannot supply the required metadata.
    Index(structural_index::Error),
    /// The original connection's inode assignment failed.
    Inode(inode_policy::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Metadata => "invalid FUSE presentation metadata",
            Self::BufferTooSmall => "FUSE metadata output is too small",
            Self::UnreservedInodes => "FUSE metadata requires reserved inode storage",
            Self::NotSymlink => "FUSE readlink names a non-symlink",
            Self::Index(_) => "FUSE metadata index is invalid",
            Self::Inode(_) => "FUSE metadata inode assignment failed",
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

/// Encodes a complete positive LOOKUP payload into reusable worker storage.
///
/// The root uses kernel node ID one and a separately allocated presented inode.
/// Other node IDs derive from the governing root and canonical hard-link path.
/// Generation one is permanent within this original immutable connection.
/// No inode number or output byte changes on failure.
///
/// # Errors
/// Refuses insufficient output, lazy inode storage, invalid recorded or canonical
/// presentation, checked index failures and exhausted/colliding inode identities.
pub fn lookup<'a>(
    entry: Entry<'_>,
    presentation: Presentation,
    cache: CachePolicy,
    inodes: &mut InodeTable,
    output: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let output = output.get_mut(..128).ok_or(Error::BufferTooSmall)?;
    let (node, attributes) = attributes(entry, presentation, inodes)?;
    output.fill(0);
    output[..8].copy_from_slice(&node.to_ne_bytes());
    output[8..16].copy_from_slice(&1_u64.to_ne_bytes());
    output[16..24].copy_from_slice(&cache.seconds().to_ne_bytes());
    output[24..32].copy_from_slice(&cache.seconds().to_ne_bytes());
    output[40..].copy_from_slice(&attributes);
    Ok(output)
}

/// Encodes a complete GETATTR payload from the same original connection table.
///
/// Unused capacity is untouched. Virtual blocks and device numbers remain zero;
/// structural metadata makes no claim about physical allocation or device nodes.
///
/// # Errors
/// Refuses the same metadata, inode and storage failures as [`lookup`].
pub fn getattr<'a>(
    entry: Entry<'_>,
    presentation: Presentation,
    cache: CachePolicy,
    inodes: &mut InodeTable,
    output: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    let output = output.get_mut(..104).ok_or(Error::BufferTooSmall)?;
    let (_, attributes) = attributes(entry, presentation, inodes)?;
    output.fill(0);
    output[..8].copy_from_slice(&cache.seconds().to_ne_bytes());
    output[16..].copy_from_slice(&attributes);
    Ok(output)
}

/// Encodes a negative LOOKUP with caching only for a pinned view.
///
/// Kernel node ID zero records absence; no inode is assigned. Revalidation
/// policy uses zero validity, so a later access must consult the worker again.
///
/// # Errors
/// Refuses an output buffer shorter than the complete 128-byte payload.
pub fn negative_lookup(cache: CachePolicy, output: &mut [u8]) -> Result<&[u8], Error> {
    let output = output.get_mut(..128).ok_or(Error::BufferTooSmall)?;
    output.fill(0);
    output[16..24].copy_from_slice(&cache.seconds().to_ne_bytes());
    Ok(output)
}

/// Borrows the exact recorded READLINK bytes without normalization or resolution.
///
/// # Errors
/// Refuses an entry that does not describe a symbolic link.
pub fn readlink(entry: Entry<'_>) -> Result<&[u8], Error> {
    match entry.kind() {
        Kind::Symlink(target) => Ok(target),
        _ => Err(Error::NotSymlink),
    }
}

fn attributes(
    entry: Entry<'_>,
    presentation: Presentation,
    inodes: &mut InodeTable,
) -> Result<(u64, [u8; 88]), Error> {
    if !inodes.is_reserved() {
        return Err(Error::UnreservedInodes);
    }
    let metadata = entry.metadata().map_err(Error::Index)?;
    let (kind, default_mode, size, links) = match entry.kind() {
        Kind::Directory { .. } => {
            let children = entry.children().map_err(Error::Index)?;
            let count = children
                .filter(|child| matches!(child.kind(), Kind::Directory { .. }))
                .count();
            let links = u32::try_from(count)
                .ok()
                .and_then(|count| count.checked_add(2))
                .ok_or(Error::Metadata)?;
            (libc::S_IFDIR, 0o555, 0, links)
        }
        Kind::File { size, .. } => (
            libc::S_IFREG,
            0o444,
            size,
            entry.link_count().map_err(Error::Index)?,
        ),
        Kind::Symlink(target) => (libc::S_IFLNK, 0o777, target.len() as u64, 1),
    };
    let mode = presentation.mode.or(metadata.mode).unwrap_or(default_mode);
    if mode & !0o7777 != 0 {
        return Err(Error::Metadata);
    }
    let uid = ownership(presentation.uid, metadata.attributes.get(b"uid"))?;
    let gid = ownership(presentation.gid, metadata.attributes.get(b"gid"))?;
    let time = presentation.timestamp;
    let (identity, inode) = inodes.touch_entry(entry).map_err(Error::Inode)?;
    let node = if entry.path().is_empty() {
        1
    } else {
        identity.node_id()
    };

    let mut attributes = [0; 88];
    attributes[..8].copy_from_slice(&u64::from(inode.number()).to_ne_bytes());
    attributes[8..16].copy_from_slice(&size.to_ne_bytes());
    for offset in [24, 32, 40] {
        attributes[offset..offset + 8].copy_from_slice(&time.seconds.to_ne_bytes());
    }
    for offset in [48, 52, 56] {
        attributes[offset..offset + 4].copy_from_slice(&time.nanoseconds.to_ne_bytes());
    }
    attributes[60..64].copy_from_slice(&(kind | u32::from(mode)).to_ne_bytes());
    attributes[64..68].copy_from_slice(&links.to_ne_bytes());
    attributes[68..72].copy_from_slice(&uid.to_ne_bytes());
    attributes[72..76].copy_from_slice(&gid.to_ne_bytes());
    attributes[80..84].copy_from_slice(&4096_u32.to_ne_bytes());
    Ok((node, attributes))
}

fn ownership(canonical: Option<u32>, recorded: Option<&[u8]>) -> Result<u32, Error> {
    let value = if let Some(value) = canonical {
        value
    } else if let Some(bytes) = recorded {
        let mut decoder = Decoder::new(bytes);
        let value = decoder.uint().map_err(|_| Error::Metadata)?;
        decoder.finish().map_err(|_| Error::Metadata)?;
        u32::try_from(value).map_err(|_| Error::Metadata)?
    } else {
        0
    };
    if value == u32::MAX {
        return Err(Error::Metadata);
    }
    Ok(value)
}

#[cfg(test)]
mod tests;
