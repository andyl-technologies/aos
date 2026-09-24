//! Shared bounded file admission for optional, separate-purpose role credentials.
//!
//! Callers retain their own role codec, seed correspondence, and key-reuse
//! checks. This reader only preserves the common systemd file boundary.

use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use rustix::fs::{CWD, Mode, OFlags, openat};
use zeroize::Zeroizing;

/// Reports a missing safety property of an optional fixed role credential.
#[derive(Debug, thiserror::Error)]
#[error("fixed role credential is unsafe or malformed")]
pub(crate) struct FixedRoleCredentialErrorV1;

/// Reads one fixed, bounded systemd credential without following its final name.
pub(crate) fn read_optional_fixed_role_credential_v1(
    directory: &Path,
    name: &str,
    length: u64,
    private: bool,
) -> Result<Option<Zeroizing<Vec<u8>>>, FixedRoleCredentialErrorV1> {
    let descriptor = match openat(
        CWD,
        directory.join(name),
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(_) => return Err(FixedRoleCredentialErrorV1),
    };
    let mut file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| FixedRoleCredentialErrorV1)?;
    if !metadata.is_file()
        || metadata.len() != length
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || private && metadata.mode() & 0o077 != 0
    {
        return Err(FixedRoleCredentialErrorV1);
    }
    let mut bytes = Zeroizing::new(vec![0; length as usize]);
    file.read_exact(&mut bytes)
        .map_err(|_| FixedRoleCredentialErrorV1)?;
    let mut trailing = [0];
    if file
        .read(&mut trailing)
        .map_err(|_| FixedRoleCredentialErrorV1)?
        != 0
    {
        return Err(FixedRoleCredentialErrorV1);
    }
    Ok(Some(bytes))
}
