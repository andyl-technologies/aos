//! Verified writes of byte streams onto raw block devices.
//!
//! A write is complete only after the device has been synced and its first
//! `byte_size` bytes read back to the expected SHA-256 digest. A short source,
//! an undersized device, or a read-back mismatch is reported as an error; the
//! caller decides whether the partially written device is recoverable.

use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use crate::digest::sha256_prefix;
use crate::{MediaError, Tools};

/// Returns the usable byte capacity of a block device.
///
/// # Errors
///
/// Returns [`MediaError::Topology`] when the path is not a block device below
/// `/dev`.
pub fn capacity(device: &Path) -> Result<u64, MediaError> {
    let mut file = open_block(device, false)?;
    Ok(file.seek(SeekFrom::End(0))?)
}

/// Copies exactly `byte_size` bytes from `source` to `destination` and verifies them.
///
/// The destination must be a block device below `/dev` with at least
/// `byte_size` bytes of capacity. Bytes beyond `byte_size` are left untouched.
///
/// # Errors
///
/// Returns [`MediaError::Topology`] for an unsuitable destination and
/// [`MediaError::Rejected`] for a short source or a read-back digest mismatch.
pub fn write_verified(
    tools: &Tools,
    source: &mut impl Read,
    destination: &Path,
    byte_size: u64,
    sha256: &str,
) -> Result<(), MediaError> {
    let mut output = open_block(destination, true)?;
    // Seeking the already opened device obtains its usable extent without a
    // second lookup that a concurrent rename could redirect.
    if output.seek(SeekFrom::End(0))? < byte_size {
        return Err(MediaError::Topology(format!(
            "{} is smaller than the {byte_size}-byte payload",
            destination.display()
        )));
    }
    output.seek(SeekFrom::Start(0))?;

    let copied = io::copy(&mut source.take(byte_size), &mut output)?;
    if copied != byte_size {
        return Err(MediaError::Rejected(format!(
            "short block write: expected {byte_size} bytes, wrote {copied}"
        )));
    }
    output.sync_all()?;
    drop(output);

    if sha256_prefix(tools, destination, byte_size)? != sha256 {
        return Err(MediaError::Rejected(
            "block-device read-back digest mismatch".into(),
        ));
    }
    Ok(())
}

fn open_block(device: &Path, writable: bool) -> Result<fs::File, MediaError> {
    let resolved = fs::canonicalize(device)?;
    if !resolved.starts_with("/dev") {
        return Err(MediaError::Topology(format!(
            "{} resolves outside /dev",
            device.display()
        )));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(writable)
        .open(&resolved)?;
    if !file.metadata()?.file_type().is_block_device() {
        return Err(MediaError::Topology(format!(
            "{} is not a block device",
            device.display()
        )));
    }
    Ok(file)
}
