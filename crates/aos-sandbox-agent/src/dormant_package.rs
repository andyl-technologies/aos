//! Independently retainable dormant guest-agent package seam.
//!
//! This normal-source module validates the executable output consumed by the
//! offline root builder. The independently buildable package remains absent
//! from profiles, guest roots, services, listeners, and system activation.

use std::fs::File;
use std::io::Read as _;
use std::path::PathBuf;

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

/// Identifies one verified dormant guest-agent package output.
pub struct DormantGuestAgentPackageV1 {
    executable: PathBuf,
    executable_digest: ObjectDigest,
    encoded_size: u64,
}

impl DormantGuestAgentPackageV1 {
    /// Verifies one regular executable as an independently retainable output.
    ///
    /// # Errors
    ///
    /// Returns [`DormantGuestAgentPackageErrorV1`] for a relative path,
    /// nonregular or empty input, excessive size, I/O failure, or digest
    /// mismatch.
    pub fn verify(
        executable: PathBuf,
        expected_digest: ObjectDigest,
    ) -> Result<Self, DormantGuestAgentPackageErrorV1> {
        if !executable.is_absolute() || expected_digest.as_bytes() == &[0; 32] {
            return Err(DormantGuestAgentPackageErrorV1::InvalidInput);
        }
        let mut file = File::open(&executable)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 128 * 1_048_576 {
            return Err(DormantGuestAgentPackageErrorV1::InvalidInput);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)?;
        let mut digest = Sha256::new();
        digest.update(&bytes);
        if ObjectDigest::from_bytes(digest.finalize().into()) != expected_digest {
            return Err(DormantGuestAgentPackageErrorV1::DigestMismatch);
        }
        Ok(Self {
            executable,
            executable_digest: expected_digest,
            encoded_size: metadata.len(),
        })
    }

    /// Borrows the verified executable path.
    #[must_use]
    pub fn executable(&self) -> &std::path::Path {
        &self.executable
    }

    /// Returns the verified executable content commitment.
    #[must_use]
    pub const fn executable_digest(&self) -> ObjectDigest {
        self.executable_digest
    }

    /// Returns the verified executable byte size.
    #[must_use]
    pub const fn encoded_size(&self) -> u64 {
        self.encoded_size
    }
}

/// Reports dormant package verification failure.
#[derive(Debug, thiserror::Error)]
pub enum DormantGuestAgentPackageErrorV1 {
    /// The path, file shape, size, or commitment is invalid.
    #[error("dormant guest-agent package input is invalid")]
    InvalidInput,
    /// The executable bytes do not match the expected package digest.
    #[error("dormant guest-agent package digest does not match")]
    DigestMismatch,
    /// Package verification I/O failed.
    #[error("dormant guest-agent package verification failed: {0}")]
    Io(#[from] std::io::Error),
}
