//! Retains a genuine fresh creator through activation and first-enrollment checks.
//!
//! The opaque receipt owns original coordination separately from the read-only
//! observations exposed to an administrative consumer. Those observations alone
//! cannot construct another receipt or reopen Original publication authority.

#[path = "capture.rs"]
mod capture;

use super::super::super::super::{FencePolicy, NativeExclusion, NativeOpenedDirectory};
use super::super::{
    NativeGenesisStage, NativePendingRoot, NativePublicationInitialization, corrupt,
};
use super::bootstrap;
use crate::{
    bucket::BucketBinding,
    store::{LocalFs, StoreErrorKind, StoreFailure},
};
use std::{
    fs::{File, Metadata},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use terrane_format::{
    bucket::StoreProfile,
    gc::publication::{BackendBinding, PublicationTransaction},
};

/// Retains one genuine fresh bucket for a consuming administrative enrollment.
///
/// This value is noncloneable and has no public constructor. Its successful
/// creator event, exact empty genesis and retained exclusion cannot be replaced
/// by paths, descriptors, decoded metadata or an existing empty-looking root.
/// A native helper takes ownership of it and rechecks all observations before
/// first durable global claims or mutation. It grants no general bucket writer,
/// host project claim, recovery completion, final custody or deletion authority.
pub struct NativeInitialBucketEnrollment {
    request: NativePublicationInitialization,
    original_directories: Arc<[NativeOpenedDirectory]>,
    exclusions: Arc<[NativeExclusion]>,
    binding: BackendBinding,
    genesis: PublicationTransaction,
    directories: Vec<Directory>,
    files: Vec<Leaf>,
}

struct Directory {
    original: NativeOpenedDirectory,
    metadata: Metadata,
}

struct Leaf {
    path: PathBuf,
    file: File,
    metadata: Metadata,
    expected: Vec<u8>,
    policy: FencePolicy,
}

/// Borrows one original checked directory in the exact creator namespace.
pub struct NativeInitialDirectory<'a> {
    directory: &'a Directory,
}

impl NativeInitialDirectory<'_> {
    /// Borrows the normalized original directory path.
    pub fn path(&self) -> &Path {
        &self.directory.original.path
    }

    /// Borrows the actual retained read-only directory descriptor.
    pub fn descriptor(&self) -> &File {
        &self.directory.original.file
    }

    /// Borrows the original complete metadata, including UID, GID and mode.
    pub fn observed_metadata(&self) -> &Metadata {
        &self.directory.metadata
    }
}

/// Borrows one final regular leaf and its exact creator-owned preimage.
///
/// The coordination observation uses a separate read-only description, never
/// the exclusion description itself. Consumers cannot release the original
/// flock through this descriptor.
pub struct NativeInitialFile<'a> {
    leaf: &'a Leaf,
}

impl NativeInitialFile<'_> {
    /// Borrows the normalized original leaf path.
    pub fn path(&self) -> &Path {
        &self.leaf.path
    }

    /// Borrows the actual retained read-only regular-file descriptor.
    pub fn descriptor(&self) -> &File {
        &self.leaf.file
    }

    /// Borrows exact expected bytes checked through this same descriptor.
    pub fn expected_bytes(&self) -> &[u8] {
        &self.leaf.expected
    }

    /// Borrows the original complete metadata, including size and link count.
    pub fn observed_metadata(&self) -> &Metadata {
        &self.leaf.metadata
    }
}

impl NativeInitialBucketEnrollment {
    /// Borrows the original root created by the successful native event.
    pub fn root(&self) -> &Path {
        &self.request.root
    }

    /// Borrows the original external protected-control path.
    pub fn control(&self) -> &Path {
        &self.request.control
    }

    /// Returns the independently configured and actually checked creator UID.
    pub fn operator_uid(&self) -> u32 {
        self.request.operator_uid
    }

    /// Borrows the original root and coordination device/inode binding.
    pub fn binding(&self) -> &BackendBinding {
        &self.binding
    }

    /// Borrows the immutable registered profile of the exact fresh genesis.
    pub fn profile(&self) -> &StoreProfile {
        &self.request.profile
    }

    /// Borrows the canonical validated empty genesis proposal as data.
    ///
    /// Decoded transaction data cannot recreate this enrollment receipt.
    pub fn genesis(&self) -> &PublicationTransaction {
        &self.genesis
    }

    /// Iterates the complete original directory set under root and control.
    pub fn directories(&self) -> impl Iterator<Item = NativeInitialDirectory<'_>> {
        self.directories
            .iter()
            .map(|directory| NativeInitialDirectory { directory })
    }

    /// Iterates every final regular leaf, including coordination and control.
    pub fn files(&self) -> impl Iterator<Item = NativeInitialFile<'_>> {
        self.files.iter().map(|leaf| NativeInitialFile { leaf })
    }

    /// Rechecks original descriptors, exact bodies and the exhaustive namespace.
    ///
    /// This blocking native check performs no mutation or lock acquisition.
    /// Consumers run it on their owned administrative physical worker before
    /// persisting the first claims/ledger or changing custody or projects. Once
    /// setters begin, their own retained transaction must own partial-progress
    /// recovery; this original preimage checker does not authorize a replay.
    ///
    /// # Errors
    /// Refuses changed names, inodes, ownership, modes, sizes or exact bytes,
    /// extra/missing entries, links, cross-device children and native I/O failure.
    pub fn verify_inline(&self) -> Result<(), StoreFailure> {
        capture::verify(self)
    }
}

struct Activated {
    request: NativePublicationInitialization,
    directories: Arc<[NativeOpenedDirectory]>,
    exclusions: Arc<[NativeExclusion]>,
    binding: BackendBinding,
    staged: NativeGenesisStage,
    frame: super::super::super::Frame,
}

/// Activates only the exact configured successful fresh native creator.
///
/// # Errors
/// Refuses copied/unbranded receipts, mismatched configuration, changed original
/// inputs, failed activation/probes and failed complete physical sealing.
pub(crate) async fn activate<F: LocalFs + BucketBinding>(
    fs: &F,
    receipt: NativePendingRoot,
    expected: NativePublicationInitialization,
) -> Result<NativeInitialBucketEnrollment, StoreFailure> {
    let NativePendingRoot {
        _private: (),
        request,
        directories,
        exclusions,
        binding,
        pending,
        staged,
        names,
        reads,
    } = receipt;
    if request.copy.is_some()
        || request.creator.is_none()
        || expected.copy.is_some()
        || expected.creator.is_some()
        || request.root != expected.root
        || request.control != expected.control
        || request.operator_uid != expected.operator_uid
        || request.profile != expected.profile
        || request.timestamp != expected.timestamp
    {
        return Err(StoreFailure::new(StoreErrorKind::Unsupported));
    }
    let directories = Arc::new(Mutex::new(directories));
    let mut frame = bootstrap::restore_frame(request.operator_uid, exclusions, names, reads)?;
    bootstrap::finish(
        fs,
        &request,
        &binding,
        &pending,
        &staged,
        &mut frame,
        &directories,
    )
    .await?;
    bootstrap::probe(fs, &request, &staged, &mut frame, &directories).await?;
    let original_directories = Arc::clone(&*directories.lock().map_err(|_| corrupt())?);
    let activated = Activated {
        request,
        directories: original_directories,
        exclusions: Arc::clone(&frame.exclusions),
        binding,
        staged,
        frame,
    };

    #[cfg(feature = "tokio")]
    {
        let unavailable = || StoreFailure::new(StoreErrorKind::Unavailable { retry_after: None });
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| unavailable())?;
        // The submitted worker owns the brand, original directories and flock
        // through physical completion even when its asynchronous waiter drops.
        runtime
            .spawn_blocking(move || capture::seal(activated))
            .await
            .map_err(|_| unavailable())?
    }
    #[cfg(not(feature = "tokio"))]
    {
        capture::seal(activated)
    }
}

#[cfg(all(test, feature = "tokio", target_os = "linux"))]
#[path = "tests.rs"]
mod tests;
