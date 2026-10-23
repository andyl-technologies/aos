//! Checks bounded records exchanged with a Linux FUSE connection.
//!
//! Records use the kernel's native byte order. Parsing borrows the original
//! read buffer and never casts untrusted bytes to native structures. This
//! module owns framing only; a valid record grants no inode, backing handle,
//! repository access or connection authority.
//!
//! ```text
//! request: u32 length | u32 opcode | u64 unique | u64 node |
//!          u32 uid | u32 gid | u32 pid | u16 extension_units | u16 padding | body
//! reply:   u32 length | i32 error | u64 unique | body
//! ```
//!
//! Field widths follow the Linux FUSE UAPI in `include/uapi/linux/fuse.h`.
//! Extensions are refused because the worker does not negotiate them. Unknown
//! opcodes remain visible so a dispatcher can return the appropriate errno.

use std::{fmt, num::NonZeroU64};

const REQUEST_HEADER: usize = 40;
const REPLY_HEADER: usize = 16;

/// Borrows one complete ordinary reply, excluding unsolicited notifications.
#[derive(Clone, Copy, Debug)]
pub struct Reply<'a> {
    bytes: &'a [u8],
    unique: NonZeroU64,
    errno: Option<i32>,
}

impl<'a> Reply<'a> {
    /// Checks the length, response identifier and signed Linux errno encoding.
    ///
    /// Matching the identifier to a particular outstanding operation remains the
    /// dispatcher's responsibility. Error responses cannot carry payload bytes.
    ///
    /// # Errors
    /// Refuses invalid limits, oversized or truncated records, inconsistent
    /// lengths, zero identifiers, positive errors and error payloads.
    pub fn parse(bytes: &'a [u8], maximum_bytes: usize) -> Result<Self, Error> {
        if maximum_bytes < REPLY_HEADER
            || u32::try_from(maximum_bytes).is_err()
            || bytes.len() > maximum_bytes
        {
            return Err(Error::Limit);
        }
        if bytes.len() < REPLY_HEADER
            || u32::from_ne_bytes(array(bytes, 0)?) as usize != bytes.len()
        {
            return Err(Error::Encoding);
        }
        let unique =
            NonZeroU64::new(u64::from_ne_bytes(array(bytes, 8)?)).ok_or(Error::Encoding)?;
        let error = i32::from_ne_bytes(array(bytes, 4)?);
        let errno = match error {
            0 => None,
            -4095..=-1 if bytes.len() == REPLY_HEADER => Some(-error),
            _ => return Err(Error::Encoding),
        };
        Ok(Self {
            bytes,
            unique,
            errno,
        })
    }

    /// Returns the nonzero response identifier without proving an outstanding request.
    pub const fn unique(self) -> NonZeroU64 {
        self.unique
    }

    /// Returns the positive errno, or `None` for a successful reply.
    pub const fn errno(self) -> Option<i32> {
        self.errno
    }

    /// Borrows the exact checked record for one complete connection write.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

/// Describes a malformed record or an exhausted caller-supplied buffer bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The record is truncated, inconsistent, or contains invalid field values.
    Encoding,
    /// A configured bound or output buffer cannot contain the complete record.
    Limit,
    /// The request contains extensions that this worker does not negotiate.
    Extensions,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Encoding => "invalid FUSE record encoding",
            Self::Limit => "FUSE record exceeds configured buffer bound",
            Self::Extensions => "unnegotiated FUSE request extensions",
        })
    }
}

impl std::error::Error for Error {}

/// Borrows exactly one complete request from the original connection read.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    bytes: &'a [u8],
}

impl<'a> Request<'a> {
    /// Checks the complete record against an explicit per-request byte limit.
    ///
    /// FUSE device reads deliver complete records; truncated input and concatenated
    /// records are refused. The limit includes the fixed header. It must fit the
    /// UAPI's 32-bit record length and be large enough for that header.
    ///
    /// # Errors
    /// Refuses invalid limits, oversized or inconsistent lengths, truncation,
    /// reserved padding and extensions that were not negotiated.
    pub fn parse(bytes: &'a [u8], maximum_bytes: usize) -> Result<Self, Error> {
        if maximum_bytes < REQUEST_HEADER || u32::try_from(maximum_bytes).is_err() {
            return Err(Error::Limit);
        }
        if bytes.len() > maximum_bytes {
            return Err(Error::Limit);
        }
        if bytes.len() < REQUEST_HEADER
            || u32::from_ne_bytes(array(bytes, 0)?) as usize != bytes.len()
            || u16::from_ne_bytes(array(bytes, 38)?) != 0
        {
            return Err(Error::Encoding);
        }
        if u16::from_ne_bytes(array(bytes, 36)?) != 0 {
            return Err(Error::Extensions);
        }
        Ok(Self { bytes })
    }

    /// Returns the raw opcode without treating unsupported operations as valid work.
    pub fn opcode(self) -> u32 {
        u32::from_ne_bytes(self.fixed(4))
    }

    /// Returns the kernel's request identifier, including zero for no-reply records.
    pub fn unique(self) -> u64 {
        u64::from_ne_bytes(self.fixed(8))
    }

    /// Returns the connection-local node identifier supplied by the kernel.
    pub fn node(self) -> u64 {
        u64::from_ne_bytes(self.fixed(16))
    }

    /// Returns the requesting task's kernel-supplied user identifier.
    pub fn uid(self) -> u32 {
        u32::from_ne_bytes(self.fixed(24))
    }

    /// Returns the requesting task's kernel-supplied group identifier.
    pub fn gid(self) -> u32 {
        u32::from_ne_bytes(self.fixed(28))
    }

    /// Returns the requesting task identifier, which is not repository authority.
    pub fn pid(self) -> u32 {
        u32::from_ne_bytes(self.fixed(32))
    }

    /// Borrows the complete opcode-specific body without copying or interpretation.
    pub fn body(self) -> &'a [u8] {
        &self.bytes[REQUEST_HEADER..]
    }

    /// Borrows one exact terminated filename from an opcode-specific body offset.
    ///
    /// The caller selects the offset defined by the negotiated opcode. This
    /// helper accepts ordinary namespace components, including `.` and `..`;
    /// traversal semantics belong to the dispatcher. It refuses embedded NULs,
    /// separators, empty components and bytes after the terminator.
    ///
    /// # Errors
    /// Returns an error for an invalid offset or filename, a missing terminator,
    /// trailing bytes or a name exceeding the explicit byte bound.
    pub fn name(self, offset: usize, maximum_bytes: usize) -> Result<&'a [u8], Error> {
        let bytes = self.body().get(offset..).ok_or(Error::Encoding)?;
        let name = bytes.strip_suffix(&[0]).ok_or(Error::Encoding)?;
        if name.is_empty() || name.contains(&0) || name.contains(&b'/') {
            return Err(Error::Encoding);
        }
        if maximum_bytes == 0 || name.len() > maximum_bytes {
            return Err(Error::Limit);
        }
        Ok(name)
    }

    /// Reads one native-order 32-bit field within the opcode-specific body.
    ///
    /// # Errors
    /// Returns an error if the complete field does not fit the original body.
    pub fn body_u32(self, offset: usize) -> Result<u32, Error> {
        Ok(u32::from_ne_bytes(array(self.body(), offset)?))
    }

    /// Reads one native-order 64-bit field within the opcode-specific body.
    ///
    /// # Errors
    /// Returns an error if the complete field does not fit the original body.
    pub fn body_u64(self, offset: usize) -> Result<u64, Error> {
        Ok(u64::from_ne_bytes(array(self.body(), offset)?))
    }

    fn fixed<const N: usize>(self, offset: usize) -> [u8; N] {
        // Only fixed header offsets call this helper, after complete validation.
        let mut value = [0; N];
        value.copy_from_slice(&self.bytes[offset..offset + N]);
        value
    }
}

/// Encodes a complete successful response in the caller's bounded output buffer.
///
/// The returned slice contains only the initialized reply. An insufficient buffer
/// leaves it unchanged. The caller must suppress replies for no-reply opcodes;
/// a nonzero identifier alone does not establish that a reply is appropriate.
///
/// # Errors
/// Refuses a length beyond the UAPI's 32-bit record size or output capacity.
pub fn reply<'a>(output: &'a mut [u8], unique: NonZeroU64, body: &[u8]) -> Result<&'a [u8], Error> {
    let length = REPLY_HEADER.checked_add(body.len()).ok_or(Error::Limit)?;
    let length_u32 = u32::try_from(length).map_err(|_| Error::Limit)?;
    let output = output.get_mut(..length).ok_or(Error::Limit)?;
    output[..4].copy_from_slice(&length_u32.to_ne_bytes());
    output[4..8].copy_from_slice(&0_i32.to_ne_bytes());
    output[8..16].copy_from_slice(&unique.get().to_ne_bytes());
    output[16..].copy_from_slice(body);
    Ok(output)
}

/// Encodes one Linux error response without an opcode-specific body.
///
/// The caller supplies a positive errno; the kernel receives its negative value.
/// Validation precedes writes, including when the output buffer is too small.
///
/// # Errors
/// Refuses errno values outside `1..=4095` and insufficient output capacity.
pub fn error_reply(output: &mut [u8], unique: NonZeroU64, errno: i32) -> Result<&[u8], Error> {
    if !(1..=4095).contains(&errno) {
        return Err(Error::Encoding);
    }
    let output = output.get_mut(..REPLY_HEADER).ok_or(Error::Limit)?;
    output[..4].copy_from_slice(&(REPLY_HEADER as u32).to_ne_bytes());
    output[4..8].copy_from_slice(&(-errno).to_ne_bytes());
    output[8..16].copy_from_slice(&unique.get().to_ne_bytes());
    Ok(output)
}

fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let end = offset.checked_add(N).ok_or(Error::Encoding)?;
    bytes
        .get(offset..end)
        .ok_or(Error::Encoding)?
        .try_into()
        .map_err(|_| Error::Encoding)
}

#[cfg(test)]
mod tests;
