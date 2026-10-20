//! Defines additive host-kernel inspection independently of frozen store traits.
//!
//! Production adapters obtain these facts from retained kernel descriptors and
//! a freshly publisher-created seal probe. Requests cannot supply inspection.

use super::DomainHostLayout;
use std::{io, path::Path};

/// Names a genuinely measured fs-verity seal on the layout's filesystem.
#[derive(Clone, Debug)]
pub struct SealInspection {
    /// Device observed on the retained publisher-created probe inode.
    pub device: u64,
    /// Kernel fs-verity measurement algorithm.
    pub algorithm: u16,
    /// Kernel measurement bytes, distinct from Terrane object identities.
    pub digest: Vec<u8>,
}

/// Carries filesystem facts from a trusted host I/O adapter.
#[derive(Clone, Debug)]
pub struct HostInspection {
    /// Device shared by chunks, sealed, staging, quarantine and pending-delete.
    pub device: u64,
    /// Root inode retained by the adapter throughout this inspection.
    pub root_inode: u64,
    /// Native filesystem type identifier.
    pub filesystem_type: u64,
    /// Native mount flags, used to refuse unsuitable writable backing storage.
    pub mount_flags: u64,
    /// Genuine publisher probe measurement on this same filesystem.
    pub seal: SealInspection,
}

impl HostInspection {
    /// Checks structural consistency of trusted adapter inspection.
    ///
    /// This does not manufacture kernel evidence: the adapter must retain and
    /// independently inspect the actual probe and directory descriptors.
    ///
    /// # Errors
    /// Refuses unsupported filesystem types, mismatched devices or bad digests.
    pub fn validate(&self) -> io::Result<()> {
        if self.mount_flags & 1 != 0
            || self.device != self.seal.device
            || !matches!(self.filesystem_type, 0xef53 | 0x9123683e | 0xf2f52010)
            || !matches!(
                (self.seal.algorithm, self.seal.digest.len()),
                (1, 32) | (2, 64)
            )
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "inconsistent host filesystem/seal inspection",
            ));
        }
        Ok(())
    }
}

/// Supplies genuine Linux host checks without changing `LocalFs` or stores.
///
/// This binding is selected by trusted composition, like `LocalFs`, never by an
/// upload. Implementations belong to `terrane-linux`; tests may use explicit I/O
/// fixtures, while kernel gates must use the real production adapter.
pub trait HostKernel {
    /// Inspects retained directories and a fresh publisher-owned seal probe.
    ///
    /// # Errors
    /// Refuses stacked/network mounts, different devices, unavailable seals,
    /// changed directory incarnations, and failed kernel inspection.
    fn inspect(&self, layout: &DomainHostLayout) -> io::Result<HostInspection>;

    /// Measures physical allocation for an existing retained inode.
    ///
    /// # Errors
    /// Rejects replaced paths and failed kernel allocation queries.
    fn allocated_bytes(&self, path: &Path) -> io::Result<u64>;

    /// Verifies the host-provisioned project identifier and exact quota.
    ///
    /// # Errors
    /// Rejects unsupported or unavailable required project quota enforcement.
    fn verify_project_quota(&self, path: &Path, project: u32, bytes: u64) -> io::Result<()>;
}
