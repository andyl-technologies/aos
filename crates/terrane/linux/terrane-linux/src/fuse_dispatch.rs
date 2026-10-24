//! Composes allocation-free metadata requests for one original FUSE namespace.
//!
//! The caller retains the authenticated mapping, negotiates INIT, owns request
//! framing and sends each returned payload on its original connection. Content
//! opens, reads, forget accounting, handle lifetime and exposure supervision
//! remain the surrounding worker's responsibility. This component performs no IO.

use crate::{
    fuse_directory,
    fuse_metadata::{self, CachePolicy, Presentation},
    fuse_namespace::{self, Namespace},
    fuse_protocol::{self, Request},
    fuse_xattr::{self, Policy as XattrPolicy},
    inode_policy::{self, InodeTable},
    structural_index::{Entry, Index, Kind},
};
use std::fmt;

/// Bounds namespace and presented-inode storage before request processing.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum original index entries, including root and hard-link aliases.
    pub namespace_entries: u32,
    /// Maximum allocated reverse-table bytes before alias deduplication.
    pub namespace_bytes: usize,
    /// Maximum distinct lazily presented inode numbers on this connection.
    pub inodes: u32,
    /// Maximum startup-reserved inode-table allocation.
    pub inode_bytes: usize,
}

/// Returns an ordinary payload, a positive errno, or an unhandled opcode.
#[derive(Debug)]
pub enum Response<'a> {
    /// Borrows initialized scratch storage or the original immutable index.
    Payload(&'a [u8]),
    /// Requires an error reply with this positive native errno.
    Errno(i32),
    /// Leaves this opcode to the surrounding worker, including no-reply records.
    Unhandled,
}

/// Refuses invalid records or faults the original namespace's bounded state.
#[derive(Debug)]
pub enum Error {
    /// A supported metadata request has invalid native framing or fields.
    Protocol(fuse_protocol::Error),
    /// The immutable namespace cannot be constructed or resolved.
    Namespace(fuse_namespace::Error),
    /// The original connection cannot reserve or assign its inode storage.
    Inode(inode_policy::Error),
    /// Metadata cannot be presented in the caller's bounded storage.
    Metadata(fuse_metadata::Error),
    /// A complete directory page cannot be encoded.
    Directory(fuse_directory::Error),
    /// Checked xattrs cannot be encoded in the worker's available storage.
    Xattr(fuse_xattr::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FUSE metadata dispatch cannot complete its original request")
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Namespace(error) => Some(error),
            Self::Inode(error) => Some(error),
            Self::Metadata(error) => Some(error),
            Self::Directory(error) => Some(error),
            Self::Xattr(error) => Some(error),
        }
    }
}

/// Retains one immutable namespace and its permanent presented-inode table.
pub struct Metadata<'index> {
    index: Index<'index>,
    namespace: Namespace<'index>,
    inodes: InodeTable,
    cache: CachePolicy,
    xattrs: XattrPolicy,
}

impl<'index> Metadata<'index> {
    /// Reserves bounded lookup and inode storage before accepting requests.
    ///
    /// The index must remain bound to the original authenticated mapping.
    /// Cache and xattr policy come from that prepared exposure. This constructor
    /// confers no view, mount, repository or connection authority.
    ///
    /// # Errors
    /// Refuses invalid budgets, allocation failure and colliding node identities.
    pub fn new(
        index: Index<'index>,
        limits: Limits,
        cache: CachePolicy,
        xattrs: XattrPolicy,
    ) -> Result<Self, Error> {
        let namespace = Namespace::new(index, limits.namespace_entries, limits.namespace_bytes)
            .map_err(Error::Namespace)?;
        let inodes = InodeTable::with_reserved_capacity(limits.inodes, limits.inode_bytes)
            .map_err(Error::Inode)?;
        Ok(Self {
            index,
            namespace,
            inodes,
            cache,
            xattrs,
        })
    }

    /// Borrows an original canonical entry without allocating a presented inode.
    pub fn entry(&self, node: u64) -> Option<Entry<'index>> {
        self.namespace.entry(node)
    }

    /// Encodes one supported metadata payload without allocation, IO or fetching.
    ///
    /// Supported operations are LOOKUP, GETATTR, READLINK, READDIR, GETXATTR and
    /// LISTXATTR. The caller supplies schema-resolved presentation per entry.
    /// Directory handles use their original node IDs; the surrounding worker
    /// validates open/closed handle lifetime, including GETATTR's optional fh.
    /// Unknown nodes return ESTALE and normal type/absence/xattr refusals return
    /// their operation errno. Unsupported opcodes do not modify bounded state.
    ///
    /// # Errors
    /// Refuses malformed supported requests, zero response IDs, insufficient
    /// scratch, invalid metadata, inode exhaustion/collisions and invalid index
    /// relationships. On error the caller discards scratch and faults/drains the
    /// exposure; assigning earlier inode numbers never permits their recycling.
    pub fn dispatch<'a>(
        &'a mut self,
        request: Request<'_>,
        presentation: impl FnOnce(Entry<'index>) -> Presentation,
        scratch: &'a mut [u8],
    ) -> Result<Response<'a>, Error> {
        if !matches!(request.opcode(), 1 | 3 | 5 | 22 | 23 | 28) {
            return Ok(Response::Unhandled);
        }
        if request.unique() == 0 {
            return Err(Error::Protocol(fuse_protocol::Error::Encoding));
        }
        let Some(entry) = self.namespace.entry(request.node()) else {
            return Ok(Response::Errno(libc::ESTALE));
        };
        let payload = match request.opcode() {
            1 => {
                let name = request.name(0, 255).map_err(Error::Protocol)?;
                let child = match self.namespace.lookup(request.node(), name) {
                    Ok(child) => child,
                    Err(fuse_namespace::Error::NotDirectory) => {
                        return Ok(Response::Errno(libc::ENOTDIR));
                    }
                    Err(error) => return Err(Error::Namespace(error)),
                };
                match child {
                    Some(child) => fuse_metadata::lookup(
                        child,
                        presentation(child),
                        self.cache,
                        &mut self.inodes,
                        scratch,
                    ),
                    None => fuse_metadata::negative_lookup(self.cache, scratch),
                }
                .map_err(Error::Metadata)?
            }
            3 => {
                if request.body().len() != 16
                    || request.body_u32(0).map_err(Error::Protocol)? & !1 != 0
                    || request.body_u32(4).map_err(Error::Protocol)? != 0
                {
                    return Err(Error::Protocol(fuse_protocol::Error::Encoding));
                }
                fuse_metadata::getattr(
                    entry,
                    presentation(entry),
                    self.cache,
                    &mut self.inodes,
                    scratch,
                )
                .map_err(Error::Metadata)?
            }
            5 => {
                if !request.body().is_empty() {
                    return Err(Error::Protocol(fuse_protocol::Error::Encoding));
                }
                if !matches!(entry.kind(), Kind::Symlink(_)) {
                    return Ok(Response::Errno(libc::EINVAL));
                }
                fuse_metadata::readlink(entry).map_err(Error::Metadata)?
            }
            22 | 23 => return self.xattr(request, entry, scratch),
            28 => {
                if request.body().len() != 40
                    || request.body_u64(0).map_err(Error::Protocol)? != request.node()
                    || request.body_u32(36).map_err(Error::Protocol)? != 0
                {
                    return Err(Error::Protocol(fuse_protocol::Error::Encoding));
                }
                if !matches!(entry.kind(), Kind::Directory { .. }) {
                    return Ok(Response::Errno(libc::ENOTDIR));
                }
                let cookie = request.body_u64(8).map_err(Error::Protocol)?;
                let requested = request.body_u32(16).map_err(Error::Protocol)? as usize;
                let capacity = scratch.len().min(requested);
                let length = fuse_directory::read(
                    self.index,
                    entry.path(),
                    cookie,
                    &mut self.inodes,
                    &mut scratch[..capacity],
                )
                .map_err(Error::Directory)?;
                &scratch[..length]
            }
            _ => return Ok(Response::Unhandled),
        };
        Ok(Response::Payload(payload))
    }

    fn xattr<'a>(
        &self,
        request: Request<'_>,
        entry: Entry<'_>,
        scratch: &'a mut [u8],
    ) -> Result<Response<'a>, Error> {
        if request.body_u32(4).map_err(Error::Protocol)? != 0 {
            return Err(Error::Protocol(fuse_protocol::Error::Encoding));
        }
        let requested = request.body_u32(0).map_err(Error::Protocol)?;
        let result = if request.opcode() == 22 {
            let name = request
                .body()
                .get(8..)
                .and_then(|name| name.strip_suffix(&[0]))
                .ok_or(Error::Protocol(fuse_protocol::Error::Encoding))?;
            fuse_xattr::get(entry, self.xattrs, name, requested, scratch)
        } else {
            if request.body().len() != 8 {
                return Err(Error::Protocol(fuse_protocol::Error::Encoding));
            }
            fuse_xattr::list(entry, self.xattrs, requested, scratch)
        };
        match result {
            Ok(payload) => Ok(Response::Payload(payload)),
            Err(error) => match error {
                fuse_xattr::Error::Disabled => Ok(Response::Errno(libc::EOPNOTSUPP)),
                fuse_xattr::Error::NoData => Ok(Response::Errno(libc::ENODATA)),
                fuse_xattr::Error::Name => Ok(Response::Errno(libc::EINVAL)),
                fuse_xattr::Error::Range => Ok(Response::Errno(libc::ERANGE)),
                fuse_xattr::Error::TooLarge => Ok(Response::Errno(libc::E2BIG)),
                error => Err(Error::Xattr(error)),
            },
        }
    }
}

#[cfg(test)]
mod tests;
