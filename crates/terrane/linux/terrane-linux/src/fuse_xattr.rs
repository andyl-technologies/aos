//! Encodes bounded, read-only FUSE extended-attribute replies.
//!
//! GETXATTR and LISTXATTR use the entry's checked raw xattr map, never its
//! ordinary attributes or native backing inode. Size probes return the native
//! Linux `fuse_getxattr_out` layout; value replies preserve exact bytes. All
//! validation precedes writes and no operation allocates or performs IO.
//!
//! ```text
//! size probe: u32 payload_bytes | u32 zero_padding
//! list value: name | NUL | name | NUL | ...
//! ```

use crate::structural_index::{self, Entry};
use std::fmt;

const MAX_NAME: usize = 255;
const MAX_PAYLOAD: usize = 65536;

/// Selects the prepared exposure's extended-attribute presentation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Policy {
    /// Refuses attribute operations when the exposure disables xattrs.
    #[default]
    Disabled,
    /// Presents recorded names outside privileged namespaces.
    ///
    /// Security, system and trusted names remain hidden. Unknown root properties
    /// do not authorize them; registered privileged-namespace policy is separate.
    Recorded,
}

impl Policy {
    fn visible(self, name: &[u8]) -> bool {
        self == Self::Recorded
            && ![b"security.".as_slice(), b"system.", b"trusted."]
                .iter()
                .any(|prefix| name.starts_with(prefix))
    }
}

/// Describes a refused attribute request without modifying its output buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The prepared exposure disables extended attributes (`EOPNOTSUPP`).
    Disabled,
    /// The requested name is absent or hidden by policy (`ENODATA`).
    NoData,
    /// A raw name cannot be represented by the Linux xattr API (`EINVAL`).
    Name,
    /// The caller's nonzero requested size cannot hold the result (`ERANGE`).
    Range,
    /// A value or complete name list exceeds Linux's 64 KiB bound (`E2BIG`).
    TooLarge,
    /// Reusable worker output cannot hold the complete reply payload.
    BufferTooSmall,
    /// The original checked entry cannot supply metadata.
    Index(structural_index::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Disabled => "FUSE extended attributes are disabled",
            Self::NoData => "FUSE extended attribute is absent",
            Self::Name => "invalid Linux extended attribute name",
            Self::Range => "requested extended attribute size is too small",
            Self::TooLarge => "extended attributes exceed the Linux size bound",
            Self::BufferTooSmall => "FUSE extended attribute output is too small",
            Self::Index(_) => "FUSE extended attribute metadata is invalid",
        })
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Index(error) => Some(error),
            _ => None,
        }
    }
}

/// Encodes a size probe or one exact recorded attribute value.
///
/// A zero requested size probes even an empty value, returning eight bytes.
/// A nonzero request for an empty value returns an empty successful payload.
/// Hidden names have the same result as absent names, including on size probes.
///
/// # Errors
/// Refuses disabled presentation, invalid/absent/hidden names, values exceeding
/// Linux's limit, insufficient requested size or output, and invalid metadata.
pub fn get<'a>(
    entry: Entry<'_>,
    policy: Policy,
    name: &[u8],
    requested: u32,
    output: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    enabled(policy)?;
    valid_name(name)?;
    if !policy.visible(name) {
        return Err(Error::NoData);
    }
    let value = entry
        .metadata()
        .map_err(Error::Index)?
        .xattrs
        .get(name)
        .ok_or(Error::NoData)?;
    let length = reply_length(value.len(), requested)?;
    let output = output.get_mut(..length).ok_or(Error::BufferTooSmall)?;
    if requested == 0 {
        probe(output, value.len());
    } else {
        output.copy_from_slice(value);
    }
    Ok(output)
}

/// Encodes a size probe or the complete filtered NUL-terminated name list.
///
/// Names retain their raw bytes and canonical metadata order. Both passes read
/// the same immutable checked map; no partial list is emitted on any refusal.
/// Privileged names contribute neither bytes nor size to the visible result.
///
/// # Errors
/// Refuses disabled presentation, unrepresentable visible names, a list over
/// Linux's limit, insufficient requested size or output, and invalid metadata.
pub fn list<'a>(
    entry: Entry<'_>,
    policy: Policy,
    requested: u32,
    output: &'a mut [u8],
) -> Result<&'a [u8], Error> {
    enabled(policy)?;
    let fields = entry.metadata().map_err(Error::Index)?.xattrs;
    let mut size = 0usize;
    for field in fields.iter().filter(|field| policy.visible(field.name)) {
        valid_name(field.name)?;
        size = size
            .checked_add(field.name.len() + 1)
            .filter(|size| *size <= MAX_PAYLOAD)
            .ok_or(Error::TooLarge)?;
    }
    let length = reply_length(size, requested)?;
    let output = output.get_mut(..length).ok_or(Error::BufferTooSmall)?;
    if requested == 0 {
        probe(output, size);
    } else {
        let mut offset = 0;
        for field in fields.iter().filter(|field| policy.visible(field.name)) {
            let end = offset + field.name.len();
            output[offset..end].copy_from_slice(field.name);
            output[end] = 0;
            offset = end + 1;
        }
    }
    Ok(output)
}

fn enabled(policy: Policy) -> Result<(), Error> {
    if policy == Policy::Disabled {
        Err(Error::Disabled)
    } else {
        Ok(())
    }
}

fn valid_name(name: &[u8]) -> Result<(), Error> {
    if name.is_empty() || name.len() > MAX_NAME || name.contains(&0) {
        Err(Error::Name)
    } else {
        Ok(())
    }
}

fn reply_length(size: usize, requested: u32) -> Result<usize, Error> {
    if size > MAX_PAYLOAD {
        return Err(Error::TooLarge);
    }
    if requested == 0 {
        Ok(8)
    } else if (requested as usize) < size {
        Err(Error::Range)
    } else {
        Ok(size)
    }
}

fn probe(output: &mut [u8], size: usize) {
    // The complete payload has already been bounded to 64 KiB.
    output[..4].copy_from_slice(&(size as u32).to_ne_bytes());
    output[4..].fill(0);
}

#[cfg(test)]
mod tests;
