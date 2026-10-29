//! Dependency-free primitives shared by AOS boot-time media handlers.
//!
//! Recovery, inactive-slot staging, and the USB installer all resolve block
//! devices from labels, authenticate artifacts against the immutable Secure
//! Boot db snapshot, and copy verified bytes onto raw block devices. This crate
//! owns those operations once so every consumer applies the same fail-closed
//! rules.
//!
//! The crate deliberately depends only on `std`. The recovery application is
//! compiled with plain `rustc` and carries no third-party code, so digests and
//! signature checks run through fixed, caller-supplied helper executables
//! ([`Tools`]) instead of linked libraries.
//!
//! # Modules
//!
//! - [`device`] resolves labels to unique block devices and validates the
//!   installed-disk partition set.
//! - [`digest`] computes and compares SHA-256 identities of files and devices.
//! - [`block`] writes a byte stream to a block device and verifies it by
//!   reading it back.
//! - [`trust`] verifies UKIs and detached signatures against a PEM db snapshot.
//!
//! All fallible operations return [`MediaError`].

#![forbid(unsafe_code)]

pub mod block;
pub mod device;
pub mod digest;
pub mod trust;

use std::error::Error;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::Output;

/// Names the fixed helper executables used by media operations.
///
/// Every path is chosen by the caller, normally a fixed `/bin/<name>` symlink
/// inside a purpose-built initrd. Nothing is resolved through `PATH`.
#[derive(Clone, Debug)]
pub struct Tools {
    /// `blkid` from util-linux.
    pub blkid: PathBuf,
    /// `openssl` command-line tool, used for SHA-256 and signature checks.
    pub openssl: PathBuf,
    /// `sbverify` from sbsigntools, used for UKI Authenticode checks.
    pub sbverify: PathBuf,
}

impl Tools {
    /// Returns the conventional `/bin/<name>` helper set used inside AOS initrds.
    #[must_use]
    pub fn initrd() -> Self {
        Self {
            blkid: PathBuf::from("/bin/blkid"),
            openssl: PathBuf::from("/bin/openssl"),
            sbverify: PathBuf::from("/bin/sbverify"),
        }
    }
}

/// Reports a failed device, digest, trust, or write operation.
#[derive(Debug)]
pub enum MediaError {
    /// A filesystem or process operation failed.
    Io(io::Error),
    /// A fixed helper executable rejected its input or failed.
    Helper(String),
    /// Device discovery did not produce one safe, unambiguous result.
    Topology(String),
    /// An artifact differed in type, size, digest, or authorization.
    Rejected(String),
}

impl fmt::Display for MediaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "media I/O failure: {error}"),
            Self::Helper(reason) => write!(formatter, "media helper failed: {reason}"),
            Self::Topology(reason) => write!(formatter, "unsafe device topology: {reason}"),
            Self::Rejected(reason) => write!(formatter, "artifact rejected: {reason}"),
        }
    }
}

impl Error for MediaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for MediaError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Summarizes a failed helper's stderr, falling back to its exit status.
pub(crate) fn stderr_reason(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.is_empty() {
        format!("exit status {}", output.status)
    } else {
        stderr
    }
}
