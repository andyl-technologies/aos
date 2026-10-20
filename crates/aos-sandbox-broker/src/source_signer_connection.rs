//! Shares the fixed Source socket pathname checks with retained observations.
//!
//! These observations describe filesystem custody only. They neither identify
//! a live Source signer nor admit a query; the owning Root verifies its actual
//! pinned signature and original deadline independently.

use std::fs::{self, Metadata};
use std::io;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

/// Names the sole systemd-owned Source signer ingress socket.
pub const SOURCE_SIGNER_SOCKET_PATH_V1: &str = "/run/aos/sandbox-source-signerd.sock";

const PATHS: [&str; 3] = ["/run", "/run/aos", SOURCE_SIGNER_SOCKET_PATH_V1];

/// Keeps each reached fixed-path metadata result before a later refusal.
#[doc(hidden)]
pub struct SourceSignerSocketCustodyOriginalsV1 {
    metadata: [Option<io::Result<Metadata>>; 3],
    comparison: [Option<io::Result<()>>; 3],
    returned: Option<io::Result<()>>,
}

impl Default for SourceSignerSocketCustodyOriginalsV1 {
    fn default() -> Self {
        Self {
            metadata: std::array::from_fn(|_| None),
            comparison: std::array::from_fn(|_| None),
            returned: None,
        }
    }
}

impl SourceSignerSocketCustodyOriginalsV1 {
    /// Observes the sole fixed socket recipe once while retaining reached data.
    ///
    /// # Errors
    /// Retains the first native metadata failure or unsafe owner/mode/type and
    /// refuses a repeated call without replacing the earlier results.
    pub fn observe_once(&mut self, signer_uid: u32, socket_gid: u32) -> io::Result<()> {
        if self.returned.is_some() { return Err(invalid("repeated Source socket observation")); }
        let returned = require_engine(signer_uid, socket_gid, Some(self));
        self.returned = Some(returned);
        if matches!(self.returned, Some(Ok(()))) { Ok(()) }
        else { Err(invalid("retained Source socket custody failure")) }
    }

    /// Borrows the first actual native or comparison cause without new IO.
    #[must_use]
    pub fn failure(&self) -> Option<&(dyn std::error::Error + 'static)> {
        for index in 0..PATHS.len() {
            if let Some(Err(cause)) = &self.metadata[index] { return Some(cause); }
            if let Some(Err(cause)) = &self.comparison[index] { return Some(cause); }
        }
        self.returned.as_ref().and_then(|value| value.as_ref().err()).map(|cause| cause as _)
    }
}

/// Checks the established fixed Source signer socket pathname recipe.
///
/// Ordinary callers use the same ordered metadata/comparison engine and keep
/// their existing per-path local disposal schedule.
///
/// # Errors
/// Rejects an unsafe fixed parent or socket owner, mode, type or link count,
/// and propagates the first actual filesystem error.
#[doc(hidden)]
pub fn require_source_signer_socket_custody_v1(signer_uid: u32, socket_gid: u32)
    -> io::Result<()>
{
    require_engine(signer_uid, socket_gid, None)
}

fn require_engine(signer_uid: u32, socket_gid: u32,
    mut originals: Option<&mut SourceSignerSocketCustodyOriginalsV1>) -> io::Result<()>
{
    for (index, path) in PATHS.into_iter().enumerate() {
        if let Some(originals) = originals.as_deref_mut() {
            originals.metadata[index] = Some(fs::symlink_metadata(path));
            let metadata = originals.metadata[index].as_ref().and_then(|value| value.as_ref().ok())
                .ok_or_else(|| invalid("retained Source metadata failure"))?;
            originals.comparison[index] = Some(require_metadata(index, metadata, signer_uid, socket_gid));
            if !matches!(originals.comparison[index], Some(Ok(()))) {
                return Err(invalid("retained Source metadata comparison failure"));
            }
        } else {
            let metadata = fs::symlink_metadata(path)?;
            require_metadata(index, &metadata, signer_uid, socket_gid)?;
        }
    }
    Ok(())
}

fn require_metadata(index: usize, metadata: &Metadata, signer_uid: u32, socket_gid: u32)
    -> io::Result<()>
{
    if index < 2 {
        if !metadata.file_type().is_dir() || metadata.uid() != 0 || metadata.gid() != 0
            || metadata.mode() & 0o022 != 0 {
            return Err(invalid("unsafe Source signer socket parent"));
        }
    } else if !metadata.file_type().is_socket() || metadata.uid() != signer_uid
        || metadata.gid() != socket_gid || metadata.mode() & 0o777 != 0o660
        || metadata.nlink() != 1 {
        return Err(invalid("unsafe Source signer socket node"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Checks the compiled Source service process UID/GID recipe.
///
/// This mechanical observation does not capture a financial original or admit a query.
///
/// # Errors
/// Rejects sentinel, overlapping or different real/effective process identities.
pub fn require_source_signer_process_identity_v1(
    controller_uid: u32,
    controller_gid: u32,
    signer_uid: u32,
    signer_gid: u32,
) -> io::Result<()> {
    if controller_uid == 0
        || controller_gid == 0
        || signer_uid == 0
        || signer_gid == 0
        || controller_uid == signer_uid
        || rustix::process::getuid().as_raw() != signer_uid
        || rustix::process::geteuid().as_raw() != signer_uid
        || rustix::process::getgid().as_raw() != signer_gid
        || rustix::process::getegid().as_raw() != signer_gid
    {
        return Err(invalid("wrong Source signer process identity"));
    }
    Ok(())
}

