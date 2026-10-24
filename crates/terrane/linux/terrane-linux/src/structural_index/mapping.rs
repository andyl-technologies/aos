//! Owns read-only mappings of retained, independently measured fs-verity inodes.

use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr::NonNull;

use rustix::fs::{FileType, OFlags, fcntl_getfl, fstat};
use terrane_format::identity::Digest;
use terrane_sdk::host::publication::VerityBinding;

use super::{Error, Index};

/// A failed structural-index mapping or validation boundary.
#[derive(Debug)]
pub enum MappingError {
    /// The descriptor or native kernel operation failed.
    Io(io::Error),
    /// The descriptor is not a read-only regular file.
    Descriptor,
    /// The file exceeds the caller's mapping bound or addressable slice size.
    Limit,
    /// The kernel measurement differs from the expected sealed incarnation.
    Verity,
    /// The index records another root identity.
    Root,
    /// The sealed bytes do not encode a valid structural index.
    Index(Error),
}

impl fmt::Display for MappingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Descriptor => {
                f.write_str("structural index requires a read-only regular descriptor")
            }
            Self::Limit => f.write_str("structural index exceeds its mapping limit"),
            Self::Verity => f.write_str("structural index kernel measurement mismatch"),
            Self::Root => f.write_str("structural index root mismatch"),
            Self::Index(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for MappingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Index(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for MappingError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rustix::io::Errno> for MappingError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}

impl From<Error> for MappingError {
    fn from(error: Error) -> Self {
        Self::Index(error)
    }
}

/// Retains a sealed descriptor and its validated read-only structural mapping.
///
/// The mapping uses the kernel page cache directly, avoiding a full-file heap
/// copy for large trees. It owns no store credential, path opener, cache lease
/// or backing-handle authority. Each borrowed reader is bounded by this owner's
/// lifetime. Kernel-detected storage corruption can fault mapped pages; the
/// supervising process must treat the resulting worker exit as an exposure fault.
pub struct MappedIndex {
    mapping: Mapping,
    count: u32,
    paths: usize,
    targets: usize,
    hashes: usize,
    entries: usize,
    children: usize,
    metadata: usize,
    links: usize,
}

impl MappedIndex {
    /// Maps a retained descriptor only after measuring actual permanent sealing.
    ///
    /// The expected measurement must come from the caller's trusted descriptor
    /// exchange, and the root from its authenticated exposure. Matching supplied
    /// values does not authenticate either source. The descriptor is consumed
    /// on success and failure; no pathname is reopened during this operation.
    /// The maximum size is checked before `mmap` or byte parsing.
    ///
    /// # Errors
    /// Refuses writable, O_PATH, nonregular, empty, oversized, unsealed or
    /// unsupported descriptors, measurement/root mismatches, native mapping
    /// errors and malformed index bytes. No partially checked reader is returned.
    pub fn open(
        file: OwnedFd,
        expected_root: Digest,
        expected_verity: &VerityBinding,
        max_bytes: usize,
    ) -> Result<Self, MappingError> {
        let flags = fcntl_getfl(&file)?;
        let stat = fstat(&file)?;
        if flags.intersects(OFlags::WRONLY | OFlags::RDWR | OFlags::PATH)
            || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        {
            return Err(MappingError::Descriptor);
        }
        let length = usize::try_from(stat.st_size).map_err(|_| MappingError::Limit)?;
        if length == 0 || length > max_bytes || length > isize::MAX as usize {
            return Err(MappingError::Limit);
        }
        if crate::verity::measure(&file)? != *expected_verity {
            return Err(MappingError::Verity);
        }

        // Successful fs-verity measurement proves the inode can no longer be
        // written or truncated, including through another retained descriptor.
        // Remeasure size after that boundary before constructing a Rust slice.
        if fstat(&file)?.st_size != stat.st_size {
            return Err(MappingError::Descriptor);
        }
        let mapping = Mapping::new(file, length)?;
        let index = Index::open(mapping.bytes())?;
        if index.root_hash() != expected_root {
            return Err(MappingError::Root);
        }
        let result = Self {
            count: index.count,
            paths: index.paths,
            targets: index.targets,
            hashes: index.hashes,
            entries: index.entries,
            children: index.children,
            metadata: index.metadata,
            links: index.links,
            mapping,
        };
        Ok(result)
    }

    /// Borrows the previously validated index without reparsing or allocation.
    #[must_use]
    pub fn index(&self) -> Index<'_> {
        Index {
            bytes: self.mapping.bytes(),
            count: self.count,
            paths: self.paths,
            targets: self.targets,
            hashes: self.hashes,
            entries: self.entries,
            children: self.children,
            metadata: self.metadata,
            links: self.links,
        }
    }
}

struct Mapping {
    address: NonNull<u8>,
    length: usize,
    _file: OwnedFd,
}

impl Mapping {
    fn new(file: OwnedFd, length: usize) -> io::Result<Self> {
        // SAFETY: the caller retains a read-only, regular fs-verity inode with
        // immutable size >= length. The nonzero length is <= isize::MAX. A null
        // hint asks the kernel to choose an address; MAP_FIXED is never used.
        // The descriptor stays live for the call and in the returned owner.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let Some(address) = NonNull::new(address.cast::<u8>()) else {
            // SAFETY: mmap succeeded at address zero for exactly this length;
            // Rust slices cannot represent that mapping, so release it unused.
            unsafe { libc::munmap(address, length) };
            return Err(io::Error::other("kernel returned a null mapping address"));
        };
        Ok(Self {
            address,
            length,
            _file: file,
        })
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: this owner holds the successful, nonnull read-only mapping
        // for its entire lifetime. Permanent fs-verity prevents file mutation
        // or truncation. Its length is <= isize::MAX; no mutable view is exposed,
        // and returned references cannot outlive the owner or its Drop unmap.
        unsafe { std::slice::from_raw_parts(self.address.as_ptr(), self.length) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: the address and length are exactly this owner's live mmap.
        // No borrowed reader can outlive &self, and no other code can unmap it.
        unsafe { libc::munmap(self.address.as_ptr().cast(), self.length) };
    }
}
