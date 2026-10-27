//! Retains sealed reply descriptors for bounded FUSE fallback reads.
//!
//! Positioned reads preserve the descriptor cursor and use caller-owned buffers.
//! This module grants no content identity: the dispatcher must associate the
//! authenticated serve reply with the original prepared file and checked size.
//! It separately owns file handles, open coalescing, forgetting and exposure
//! lifetime. Dropping this descriptor never acknowledges physical release.
//!
//! ```text
//! fallback open: u64 file_handle | u32 FOPEN_KEEP_CACHE | u32 zero_padding
//! read: exact requested prefix, clamped at the prepared logical file size
//! ```

use std::{
    fmt,
    fs::File,
    io,
    num::NonZeroU64,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::fs::FileExt,
    },
};

/// Refuses invalid fallback bounds or reports actual sealed-file IO failure.
#[derive(Debug)]
pub enum Error {
    /// The kernel read does not match its original node, handle or native layout.
    Request(crate::fuse_protocol::Error),
    /// The configured or requested read exceeds the explicit byte bound.
    Limit,
    /// The complete reply cannot fit the supplied reusable buffer.
    BufferTooSmall,
    /// The descriptor size differs from its prepared size or cannot fit `off_t`.
    Size,
    /// Native metadata or positioned IO failed; the caller discards the payload.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(_) => formatter.write_str("invalid original FUSE read request"),
            Self::Limit => formatter.write_str("FUSE fallback read exceeds its byte bound"),
            Self::BufferTooSmall => formatter.write_str("FUSE fallback output is too small"),
            Self::Size => {
                formatter.write_str("FUSE fallback backing size differs from prepared metadata")
            }
            Self::Io(error) => write!(formatter, "FUSE fallback IO failed: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Request(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// Retains a checked native read range bound to its caller's original open.
///
/// Checking a record does not prove that its handle remains open or that its
/// backing belongs to this node. The dispatcher retains and verifies both.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Read {
    offset: u64,
    length: u32,
}

impl Read {
    /// Checks one FUSE READ against an original node and live file handle.
    ///
    /// The native layout is the 40-byte `fuse_read_in` used by supported
    /// protocols. File flags and lock-owner information confer no authority;
    /// this read-only path performs no locking or permission changes.
    ///
    /// # Errors
    /// Refuses other opcodes, zero response IDs, foreign nodes/handles,
    /// truncated or extended bodies, nonzero padding and unknown read flags.
    pub fn parse(
        request: crate::fuse_protocol::Request<'_>,
        node: NonZeroU64,
        handle: NonZeroU64,
    ) -> Result<Self, Error> {
        use crate::fuse_protocol::Error as Protocol;

        if request.opcode() != 15
            || request.unique() == 0
            || request.node() != node.get()
            || request.body().len() != 40
            || request.body_u64(0).map_err(Error::Request)? != handle.get()
            || request.body_u32(20).map_err(Error::Request)? & !1 != 0
            || request.body_u32(36).map_err(Error::Request)? != 0
        {
            return Err(Error::Request(Protocol::Encoding));
        }

        Ok(Self {
            offset: request.body_u64(8).map_err(Error::Request)?,
            length: request.body_u32(16).map_err(Error::Request)?,
        })
    }

    /// Returns the original unsigned offset, including ranges beyond EOF.
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Returns the requested byte count before the backing's configured limit.
    pub const fn length(self) -> u32 {
        self.length
    }
}

/// Owns one original authenticated read-only sealed descriptor for fallback IO.
pub struct Backing {
    file: File,
    size: u64,
    maximum_read_bytes: u32,
}

impl Backing {
    /// Consumes a checked worker-channel reply and verifies its prepared length.
    ///
    /// The channel has already checked credentials, exact request correlation,
    /// read-only regular-file status and fs-verity. The prepared logical size
    /// must come from the dispatcher's original checked file entry. This check
    /// does not substitute the fs-verity measurement for Terrane content identity.
    ///
    /// # Errors
    /// Refuses zero read limits, sizes beyond signed native file offsets,
    /// mismatched descriptor length and actual descriptor metadata errors.
    #[cfg(feature = "tokio")]
    pub fn from_reply(
        reply: crate::worker_channel::BackingReply,
        prepared_size: u64,
        maximum_read_bytes: u32,
    ) -> Result<Self, Error> {
        read_length(prepared_size, 0, 0, maximum_read_bytes, 0)?;
        let file = reply.into_file();
        if file.metadata().map_err(Error::Io)?.len() != prepared_size {
            return Err(Error::Size);
        }
        Ok(Self {
            file,
            size: prepared_size,
            maximum_read_bytes,
        })
    }

    /// Reads the complete bounded range without changing this file's cursor.
    ///
    /// Reads at or beyond EOF return zero. A short native read before the
    /// immutable prepared EOF is an error; no partial successful payload escapes.
    /// On any IO error the caller discards all output and faults the exposure
    /// as required by its verified backing policy. Refused bounds perform no IO
    /// and leave the entire output unchanged. Successful calls touch only the
    /// returned prefix, allocate nothing and never read beyond prepared EOF.
    ///
    /// # Errors
    /// Refuses oversized requests or insufficient output, and reports native
    /// IO/verification failures or an unexpected EOF before the prepared size.
    pub fn read(&self, offset: u64, requested: u32, output: &mut [u8]) -> Result<usize, Error> {
        let length = read_length(
            self.size,
            offset,
            requested,
            self.maximum_read_bytes,
            output.len(),
        )?;
        if length != 0 {
            self.file
                .read_exact_at(&mut output[..length], offset)
                .map_err(Error::Io)?;
        }
        Ok(length)
    }
}

impl AsFd for Backing {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

/// Encodes one fallback open payload with kernel cache retention enabled.
///
/// The nonzero handle belongs to the dispatcher's original connection table.
/// Passthrough and direct IO flags remain absent; repeated opens of one inode
/// must separately share that inode's original backing registration/descriptor.
///
/// # Errors
/// Refuses an output smaller than the 16-byte payload without modifying it.
pub fn open(handle: NonZeroU64, output: &mut [u8]) -> Result<&[u8], Error> {
    let output = output.get_mut(..16).ok_or(Error::BufferTooSmall)?;
    output[..8].copy_from_slice(&handle.get().to_ne_bytes());
    output[8..12].copy_from_slice(&2u32.to_ne_bytes());
    output[12..].fill(0);
    Ok(output)
}

fn read_length(
    size: u64,
    offset: u64,
    requested: u32,
    maximum: u32,
    capacity: usize,
) -> Result<usize, Error> {
    if maximum == 0 || requested > maximum {
        return Err(Error::Limit);
    }
    if size > i64::MAX as u64 {
        return Err(Error::Size);
    }
    let length = u64::from(requested).min(size.saturating_sub(offset));
    let length = usize::try_from(length).map_err(|_| Error::Limit)?;
    if length > capacity {
        return Err(Error::BufferTooSmall);
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    //! Checks payload bytes and range refusals without creating native files.

    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn open_keeps_cache_without_passthrough_or_direct_io_and_preserves_unused_bytes() {
        let mut output = [0xaa; 24];
        let bytes = open(NonZeroU64::new(17).unwrap(), &mut output).unwrap();
        assert_eq!(&bytes[..8], &17u64.to_ne_bytes());
        assert_eq!(&bytes[8..12], &2u32.to_ne_bytes());
        assert_eq!(&bytes[12..], &[0; 4]);
        assert_eq!(&output[16..], &[0xaa; 8]);

        output.fill(0xaa);
        assert!(matches!(
            open(NonZeroU64::new(1).unwrap(), &mut output[..15]),
            Err(Error::BufferTooSmall)
        ));
        assert_eq!(output, [0xaa; 24]);
    }

    #[test]
    fn positioned_ranges_clamp_only_at_prepared_eof_without_offset_overflow() {
        assert_eq!(read_length(100, 10, 20, 64, 20).unwrap(), 20);
        assert_eq!(read_length(100, 99, 64, 64, 1).unwrap(), 1);
        assert_eq!(read_length(100, 100, 64, 64, 0).unwrap(), 0);
        assert_eq!(read_length(100, u64::MAX, 64, 64, 0).unwrap(), 0);
        assert_eq!(read_length(0, 0, 64, 64, 0).unwrap(), 0);
        assert_eq!(
            read_length(i64::MAX as u64, i64::MAX as u64 - 1, u32::MAX, u32::MAX, 1).unwrap(),
            1
        );
    }

    #[test]
    fn invalid_limits_sizes_and_short_output_are_refused_before_io() {
        assert!(matches!(read_length(100, 0, 0, 0, 0), Err(Error::Limit)));
        assert!(matches!(
            read_length(100, u64::MAX, 65, 64, 0),
            Err(Error::Limit)
        ));
        assert!(matches!(
            read_length(100, 0, 20, 64, 19),
            Err(Error::BufferTooSmall)
        ));
        assert!(matches!(
            read_length(i64::MAX as u64 + 1, 0, 0, 64, 0),
            Err(Error::Size)
        ));
    }

    fn read_record() -> [u8; 80] {
        let mut bytes = [0; 80];
        bytes[..4].copy_from_slice(&80u32.to_ne_bytes());
        bytes[4..8].copy_from_slice(&15u32.to_ne_bytes());
        bytes[8..16].copy_from_slice(&7u64.to_ne_bytes());
        bytes[16..24].copy_from_slice(&19u64.to_ne_bytes());
        bytes[40..48].copy_from_slice(&23u64.to_ne_bytes());
        bytes[48..56].copy_from_slice(&u64::MAX.to_ne_bytes());
        bytes[56..60].copy_from_slice(&131072u32.to_ne_bytes());
        bytes
    }

    #[test]
    fn native_read_binds_original_node_and_handle_without_changing_unsigned_ranges() {
        let mut bytes = read_record();
        // The optional lock-owner field and original file flags cannot change
        // the positioned read. No locks are acquired or permissions mutated.
        bytes[60..64].copy_from_slice(&1u32.to_ne_bytes());
        bytes[64..72].copy_from_slice(&99u64.to_ne_bytes());
        bytes[72..76].copy_from_slice(&(libc::O_LARGEFILE as u32).to_ne_bytes());
        let request = crate::fuse_protocol::Request::parse(&bytes, 4096).unwrap();
        let read = Read::parse(
            request,
            NonZeroU64::new(19).unwrap(),
            NonZeroU64::new(23).unwrap(),
        )
        .unwrap();
        assert_eq!(read.offset(), u64::MAX);
        assert_eq!(read.length(), 131072);
    }

    #[test]
    fn native_read_refuses_foreign_records_handles_padding_and_unnegotiated_flags() {
        let node = NonZeroU64::new(19).unwrap();
        let handle = NonZeroU64::new(23).unwrap();
        for (offset, replacement) in [(4, 28), (8, 0), (16, 20), (40, 24), (60, 2), (76, 1)] {
            let mut bytes = read_record();
            bytes[offset] = replacement;
            let request = crate::fuse_protocol::Request::parse(&bytes, 4096).unwrap();
            assert!(matches!(
                Read::parse(request, node, handle),
                Err(Error::Request(_))
            ));
        }
        let bytes = read_record();
        for length in [40, 64, 79, 81] {
            let mut changed = bytes.to_vec();
            changed.resize(length, 0);
            changed[..4].copy_from_slice(&(length as u32).to_ne_bytes());
            let request = crate::fuse_protocol::Request::parse(&changed, 4096).unwrap();
            assert!(matches!(
                Read::parse(request, node, handle),
                Err(Error::Request(_))
            ));
        }
    }
}
