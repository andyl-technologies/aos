//! Keeps actual admission files and progress outside embedded policy custody.

use super::{
    Input,
    io::{DirectoryProgress, PendingFile},
};
use std::{
    io,
    sync::{Arc, Mutex},
};
use terrane::pack::PackId;
use terrane_core::identity::Descriptor;

/// Retains every physical resource even if a reply or an external receipt drops.
pub(in crate::host_cache::owner) struct AdmissionJob {
    /// Actual owner, confinement, provisioning, helper and root custody.
    ///
    /// Custody contains no admission-job registry, so this lifetime edge cannot
    /// form an embedded-state cycle. External receipts retain guards too.
    pub(super) custody: Arc<Mutex<super::super::retention::Custody>>,
    /// Untrusted bytes retained for exact verification and failure reconstruction.
    pub(super) input: Input,
    /// Actual random durable reservation identifier after the physical command begins.
    pub(super) token: String,
    /// Exact deduplicated identities protected by this operation.
    pub(super) hashes: Vec<String>,
    /// Distinct future allocation policy hold, never measured physical bytes.
    pub(super) hold: u64,
    /// Synchronized allocation of the retained touched directory chain.
    pub(super) directory_bytes: u64,
    /// Actual members and still-unresolved physical namespace progress.
    pub(super) files: Vec<PendingFile>,
    /// Generated mkdir progress and real directory inodes retained through errors.
    pub(super) directory_progress: Vec<DirectoryProgress>,
    /// Actual previously admitted one-hop dictionary custody, never caller evidence.
    pub(super) dependencies: Vec<Arc<Mutex<AdmissionJob>>>,
    /// Records only fully reconciled physical completion.
    pub(super) complete: bool,
    /// Records the first attempted durable reservation mutation.
    pub(super) started: Arc<std::sync::atomic::AtomicBool>,
}

impl AdmissionJob {
    /// Recognizes only definitively effect-free rejected input custody.
    ///
    /// The physical owner calls this after a producer returns an error. A
    /// started, partially registered or uncertain operation is never reclaimed.
    pub(in crate::host_cache::owner) fn is_effect_free(&self) -> bool {
        !self.started.load(std::sync::atomic::Ordering::Acquire)
            && self.token.is_empty()
            && self.hashes.is_empty()
            && self.hold == 0
            && self.directory_bytes == 0
            && self.files.is_empty()
            && self.directory_progress.is_empty()
            && !self.complete
    }

    /// Reserves every physical member slot before filesystem effects.
    ///
    /// # Errors
    /// Refuses unavailable memory before accepting any physical member.
    pub(in crate::host_cache::owner) fn new(
        input: Input,
        custody: Arc<Mutex<super::super::retention::Custody>>,
    ) -> io::Result<Self> {
        let mut files = Vec::new();
        files.try_reserve_exact(2).map_err(io::Error::other)?;
        let mut directory_progress = Vec::new();
        directory_progress
            .try_reserve_exact(3)
            .map_err(io::Error::other)?;
        let mut dependencies = Vec::new();
        dependencies
            .try_reserve_exact(1)
            .map_err(io::Error::other)?;
        Ok(Self {
            custody,
            input,
            token: String::new(),
            hashes: Vec::new(),
            hold: 0,
            directory_bytes: 0,
            files,
            directory_progress,
            dependencies,
            complete: false,
            started: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }
}

/// Owns a genuinely admitted standalone chunk without granting serving authority.
///
/// Dropping this value never removes the worker's durable pins, reservation or
/// actual source registry. It is not a raw-file or consumer-lease constructor.
pub struct NativeChunkAdmission {
    /// Actual worker-registered physical resources retained independently of the waiter.
    pub(super) _job: Arc<Mutex<AdmissionJob>>,
    /// Verified canonical chunk declaration.
    pub(super) descriptor: Descriptor,
    /// Scoped synchronized member allocation, excluding directory and state charges.
    pub(super) allocated: u64,
    /// Separate full-project kernel charged-and-reserved observation.
    pub(super) charged: u64,
    /// Durable logical future hold retained independently of actual allocation.
    pub(super) future_hold: u64,
    /// Scoped synchronized allocation of the touched content directories.
    pub(super) directory_allocated: u64,
}

impl NativeChunkAdmission {
    /// Borrows the independently verified canonical declaration.
    pub fn descriptor(&self) -> &Descriptor {
        &self.descriptor
    }

    /// Returns synchronized allocation for this retained chunk inode alone.
    pub fn synchronized_chunk_bytes(&self) -> u64 {
        self.allocated
    }

    /// Returns the separate fresh full-project charged-and-reserved observation.
    pub fn charged_reserved_bytes(&self) -> u64 {
        self.charged
    }

    /// Returns the distinct retained future policy hold at acknowledgment.
    pub fn future_hold_bytes(&self) -> u64 {
        self.future_hold
    }

    /// Returns scoped synchronized allocation of the touched directory chain.
    pub fn synchronized_directory_bytes(&self) -> u64 {
        self.directory_allocated
    }
}

/// Owns a genuinely admitted, fully verified metadata pack/index pair.
///
/// This receipt is neither a manifest publication pin nor a native serving
/// handle. Later publication must independently retain its exact manifest range.
pub struct NativeMetadataAdmission {
    /// Actual worker-registered physical resources retained independently of the waiter.
    pub(super) _job: Arc<Mutex<AdmissionJob>>,
    /// Verified canonical pack identifier selecting both members.
    pub(super) id: PackId,
    /// Scoped synchronized member allocation, excluding directory and state charges.
    pub(super) allocated: u64,
    /// Separate full-project kernel charged-and-reserved observation.
    pub(super) charged: u64,
    /// Durable logical future hold retained independently of actual allocation.
    pub(super) future_hold: u64,
    /// Scoped synchronized allocation of the touched content directories.
    pub(super) directory_allocated: u64,
}

impl NativeMetadataAdmission {
    /// Returns the canonical identifier of the complete synchronized pair.
    pub fn pack_id(&self) -> PackId {
        self.id
    }

    /// Returns deduplicated synchronized allocation for the pair's two inodes.
    pub fn synchronized_pair_bytes(&self) -> u64 {
        self.allocated
    }

    /// Returns the separate fresh full-project charged-and-reserved observation.
    pub fn charged_reserved_bytes(&self) -> u64 {
        self.charged
    }

    /// Returns the distinct retained future policy hold at acknowledgment.
    pub fn future_hold_bytes(&self) -> u64 {
        self.future_hold
    }

    /// Returns scoped synchronized allocation of the touched directory chain.
    pub fn synchronized_directory_bytes(&self) -> u64 {
        self.directory_allocated
    }
}

/// Borrows the retained physical job without exposing raw native authority.
///
/// # Errors
/// Refuses unavailable, changed or invalid native inputs and failed completion.
pub(super) fn lock(
    job: &Arc<Mutex<AdmissionJob>>,
) -> io::Result<std::sync::MutexGuard<'_, AdmissionJob>> {
    job.lock()
        .map_err(|_| io::Error::other("admission resource custody poisoned"))
}
