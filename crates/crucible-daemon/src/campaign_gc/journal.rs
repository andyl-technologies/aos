//! Durable external ownership for one campaign GC plan and apply lifecycle.
//!
//! A journal directory contains the exact canonical plan, root manifest, and
//! candidate manifest plus a small checksummed state record:
//!
//! ```text
//! <journal>/lock
//! <journal>/plan-v1
//! <journal>/roots-v1
//! <journal>/candidates-v1
//! <journal>/state-v1
//! ```
//!
//! State replacement is write-fsync-rename-directory-fsync. Opening a journal
//! reacquires its exclusive process lock and re-fsyncs both the journal and its
//! parent before treating a visible transition as durable. The containing
//! namespace must be owned exclusively by the daemon operator.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crucible_campaign::CampaignHash;
use rustix::fs::{FlockOperation, flock};
use thiserror::Error;

use super::{
    CampaignGcCandidateManifest, CampaignGcManifestError, CampaignGcPlan, CampaignGcPlanError,
    CampaignGcPlanId, CampaignGcPreparedPlan, CampaignGcRootManifest, MAX_CAMPAIGN_GC_PLAN_BYTES,
};

const JOURNAL_LOCK_FILE: &str = "lock";
const JOURNAL_PLAN_FILE: &str = "plan-v1";
const JOURNAL_ROOTS_FILE: &str = "roots-v1";
const JOURNAL_CANDIDATES_FILE: &str = "candidates-v1";
const JOURNAL_STATE_FILE: &str = "state-v1";
const JOURNAL_STATE_MAGIC: &[u8] = b"crucible.campaign.gc-journal-state.v1\0";
const JOURNAL_STATE_HASH_DOMAIN: &str = "crucible.campaign.gc-journal-state.v1";
const JOURNAL_STATE_BYTES: usize = JOURNAL_STATE_MAGIC.len() + 32 + 1 + 32;

static JOURNAL_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Durable phase of one external campaign GC apply journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignGcJournalPhase {
    /// The exact plan and manifests are durable, but deletion has not started.
    Planned,
    /// At least one deletion may have occurred; a fresh plan is required after interruption.
    Applying,
    /// Every candidate deletion completed while all planned fences remained held.
    Complete,
}

impl CampaignGcJournalPhase {
    const fn tag(self) -> u8 {
        match self {
            Self::Planned => 1,
            Self::Applying => 2,
            Self::Complete => 3,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, CampaignGcJournalError> {
        match tag {
            1 => Ok(Self::Planned),
            2 => Ok(Self::Applying),
            3 => Ok(Self::Complete),
            _ => Err(CampaignGcJournalError::InvalidState),
        }
    }
}

/// Outcome of idempotently creating one external journal directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignGcJournalCreateDisposition {
    /// This call durably created the exact journal.
    Created,
    /// An exact journal already existed and was reopened.
    Existing,
}

/// Outcome of idempotently advancing one journal phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignGcJournalTransition {
    /// This call durably advanced the phase.
    Advanced,
    /// The journal was already in the requested phase.
    Existing,
}

/// Exclusive durable owner of one exact campaign GC plan and apply lifecycle.
pub struct DirectoryCampaignGcJournal {
    root: PathBuf,
    _lock: File,
    plan: CampaignGcPlan,
    roots: CampaignGcRootManifest,
    candidates: CampaignGcCandidateManifest,
    phase: CampaignGcJournalPhase,
}

impl DirectoryCampaignGcJournal {
    /// Creates or reopens one exact durable journal.
    ///
    /// An existing directory is accepted only when all three canonical records
    /// match `prepared` exactly. A crash before initial state publication leaves
    /// an incomplete directory that fails closed and must not be reused.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcJournalError`] when the directory cannot be created,
    /// locked, or synced; a record is incomplete or malformed; or an existing
    /// journal names a different plan, root set, or candidate set.
    pub fn create(
        root: impl Into<PathBuf>,
        prepared: &CampaignGcPreparedPlan,
    ) -> Result<(Self, CampaignGcJournalCreateDisposition), CampaignGcJournalError> {
        validate_prepared(prepared)?;
        let root = root.into();
        match fs::create_dir(&root) {
            Ok(()) => {
                let lock = acquire_lock(&root)?;
                initialize_new(&root, prepared)?;
                let journal = Self {
                    root,
                    _lock: lock,
                    plan: prepared.plan().clone(),
                    roots: prepared.roots().clone(),
                    candidates: prepared.candidates().clone(),
                    phase: CampaignGcJournalPhase::Planned,
                };
                Ok((journal, CampaignGcJournalCreateDisposition::Created))
            }
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                let journal = Self::open(root)?;
                if journal.plan != *prepared.plan() {
                    return Err(CampaignGcJournalError::PlanMismatch);
                }
                if journal.roots != *prepared.roots() {
                    return Err(CampaignGcJournalError::RootManifestMismatch);
                }
                if journal.candidates != *prepared.candidates() {
                    return Err(CampaignGcJournalError::CandidateManifestMismatch);
                }
                Ok((journal, CampaignGcJournalCreateDisposition::Existing))
            }
            Err(source) => Err(io_error("create-journal-directory", &root, source)),
        }
    }

    /// Opens and authenticates one complete durable journal.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcJournalError`] when locking, durability recovery,
    /// record decoding, manifest binding, or state authentication fails.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, CampaignGcJournalError> {
        let root = root.into();
        validate_directory(&root)?;
        let lock = acquire_lock(&root)?;
        sync_directory(&root, "sync-journal-directory-on-open")?;
        sync_parent(&root, "sync-journal-parent-on-open")?;

        let plan_bytes = read_bounded_file(
            &root.join(JOURNAL_PLAN_FILE),
            MAX_CAMPAIGN_GC_PLAN_BYTES,
            "read-journal-plan",
        )?;
        let plan = CampaignGcPlan::from_canonical_bytes(&plan_bytes)?;
        let mut roots_file = open_read(&root.join(JOURNAL_ROOTS_FILE), "open-journal-roots")?;
        let roots = CampaignGcRootManifest::from_canonical_reader(&mut roots_file)?;
        let mut candidates_file = open_read(
            &root.join(JOURNAL_CANDIDATES_FILE),
            "open-journal-candidates",
        )?;
        let candidates = CampaignGcCandidateManifest::from_canonical_reader(&mut candidates_file)?;
        validate_record_binding(&plan, &roots, &candidates)?;

        let state_bytes = read_bounded_file(
            &root.join(JOURNAL_STATE_FILE),
            JOURNAL_STATE_BYTES,
            "read-journal-state",
        )?;
        let (state_plan, phase) = decode_state(&state_bytes)?;
        if state_plan != plan.id()? {
            return Err(CampaignGcJournalError::StatePlanMismatch);
        }
        Ok(Self {
            root,
            _lock: lock,
            plan,
            roots,
            candidates,
            phase,
        })
    }

    /// Returns the exact journal directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the exact canonical plan header.
    #[must_use]
    pub const fn plan(&self) -> &CampaignGcPlan {
        &self.plan
    }

    /// Returns the exact authenticated logical-root manifest.
    #[must_use]
    pub const fn roots(&self) -> &CampaignGcRootManifest {
        &self.roots
    }

    /// Returns the exact physical-candidate manifest.
    #[must_use]
    pub const fn candidates(&self) -> &CampaignGcCandidateManifest {
        &self.candidates
    }

    /// Returns the current durable journal phase.
    #[must_use]
    pub const fn phase(&self) -> CampaignGcJournalPhase {
        self.phase
    }

    /// Durably records that candidate deletion may begin.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcJournalError::InvalidTransition`] if the journal is
    /// already complete, or an I/O error if state replacement is indeterminate.
    pub fn begin_apply(&mut self) -> Result<CampaignGcJournalTransition, CampaignGcJournalError> {
        match self.phase {
            CampaignGcJournalPhase::Planned => {
                self.replace_phase(CampaignGcJournalPhase::Applying)?;
                Ok(CampaignGcJournalTransition::Advanced)
            }
            CampaignGcJournalPhase::Applying => Ok(CampaignGcJournalTransition::Existing),
            CampaignGcJournalPhase::Complete => Err(CampaignGcJournalError::InvalidTransition),
        }
    }

    /// Durably records that every planned candidate deletion completed.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignGcJournalError::InvalidTransition`] if deletion was
    /// never started, or an I/O error if state replacement is indeterminate.
    pub fn mark_complete(&mut self) -> Result<CampaignGcJournalTransition, CampaignGcJournalError> {
        match self.phase {
            CampaignGcJournalPhase::Planned => Err(CampaignGcJournalError::InvalidTransition),
            CampaignGcJournalPhase::Applying => {
                self.replace_phase(CampaignGcJournalPhase::Complete)?;
                Ok(CampaignGcJournalTransition::Advanced)
            }
            CampaignGcJournalPhase::Complete => Ok(CampaignGcJournalTransition::Existing),
        }
    }

    fn replace_phase(
        &mut self,
        phase: CampaignGcJournalPhase,
    ) -> Result<(), CampaignGcJournalError> {
        let plan = self.plan.id()?;
        replace_state(&self.root, plan, phase)?;
        self.phase = phase;
        Ok(())
    }
}

/// Failure to persist, reopen, or advance one campaign GC journal.
#[derive(Debug, Error)]
pub enum CampaignGcJournalError {
    /// A filesystem operation failed.
    #[error("campaign GC journal {operation} failed for {path}")]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Affected journal path.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: io::Error,
    },
    /// The plan header was malformed or inconsistent.
    #[error(transparent)]
    Plan(#[from] CampaignGcPlanError),
    /// A root or candidate manifest was malformed.
    #[error(transparent)]
    Manifest(#[from] CampaignGcManifestError),
    /// A journal directory exists but initial publication did not complete.
    #[error("campaign GC journal is incomplete")]
    Incomplete,
    /// The journal directory is not an ordinary directory.
    #[error("campaign GC journal path is not an ordinary directory")]
    InvalidDirectory,
    /// The journal state record is malformed, unsupported, or corrupt.
    #[error("campaign GC journal state is invalid")]
    InvalidState,
    /// The decoded state names a different plan.
    #[error("campaign GC journal state names a different plan")]
    StatePlanMismatch,
    /// An existing journal contains a different plan.
    #[error("campaign GC journal contains a different plan")]
    PlanMismatch,
    /// An existing journal contains a different root manifest.
    #[error("campaign GC journal contains a different root manifest")]
    RootManifestMismatch,
    /// An existing journal contains a different candidate manifest.
    #[error("campaign GC journal contains a different candidate manifest")]
    CandidateManifestMismatch,
    /// The requested phase transition is not valid.
    #[error("campaign GC journal phase transition is invalid")]
    InvalidTransition,
}

fn validate_prepared(prepared: &CampaignGcPreparedPlan) -> Result<(), CampaignGcJournalError> {
    validate_record_binding(prepared.plan(), prepared.roots(), prepared.candidates())
}

fn initialize_new(
    root: &Path,
    prepared: &CampaignGcPreparedPlan,
) -> Result<(), CampaignGcJournalError> {
    write_new_bytes(
        &root.join(JOURNAL_PLAN_FILE),
        &prepared.plan().canonical_bytes()?,
        "write-journal-plan",
    )?;
    write_new_record(
        &root.join(JOURNAL_ROOTS_FILE),
        "write-journal-roots",
        |file| prepared.roots().write_canonical(file),
    )?;
    write_new_record(
        &root.join(JOURNAL_CANDIDATES_FILE),
        "write-journal-candidates",
        |file| prepared.candidates().write_canonical(file),
    )?;
    replace_state(root, prepared.plan().id()?, CampaignGcJournalPhase::Planned)?;
    sync_directory(root, "sync-new-journal-directory")?;
    sync_parent(root, "sync-new-journal-parent")
}

fn replace_state(
    root: &Path,
    plan: CampaignGcPlanId,
    phase: CampaignGcJournalPhase,
) -> Result<(), CampaignGcJournalError> {
    let bytes = encode_state(plan, phase);
    let suffix = JOURNAL_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(
        ".{JOURNAL_STATE_FILE}.tmp.{}.{suffix}",
        std::process::id()
    ));
    write_new_bytes(&temporary, &bytes, "write-journal-state-staging")?;
    let destination = root.join(JOURNAL_STATE_FILE);
    fs::rename(&temporary, &destination)
        .map_err(|source| io_error("rename-journal-state", &destination, source))?;
    sync_directory(root, "sync-journal-state-directory")
}

fn validate_record_binding(
    plan: &CampaignGcPlan,
    roots: &CampaignGcRootManifest,
    candidates: &CampaignGcCandidateManifest,
) -> Result<(), CampaignGcJournalError> {
    if plan.root_set() != roots.id() {
        return Err(CampaignGcJournalError::RootManifestMismatch);
    }
    if plan.candidates() != candidates.summary() {
        return Err(CampaignGcJournalError::CandidateManifestMismatch);
    }
    Ok(())
}

fn acquire_lock(root: &Path) -> Result<File, CampaignGcJournalError> {
    let path = root.join(JOURNAL_LOCK_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|source| io_error("open-journal-lock", &path, source))?;
    flock(&file, FlockOperation::LockExclusive).map_err(|source| {
        io_error(
            "lock-journal",
            &path,
            io::Error::from_raw_os_error(source.raw_os_error()),
        )
    })?;
    Ok(file)
}

fn validate_directory(root: &Path) -> Result<(), CampaignGcJournalError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|source| io_error("inspect-journal-directory", root, source))?;
    if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(CampaignGcJournalError::InvalidDirectory)
    }
}

fn write_new_record<F>(
    path: &Path,
    operation: &'static str,
    writer: F,
) -> Result<(), CampaignGcJournalError>
where
    F: FnOnce(&mut File) -> Result<(), CampaignGcManifestError>,
{
    let mut file = open_new_write(path, operation)?;
    writer(&mut file)?;
    file.sync_all()
        .map_err(|source| io_error(operation, path, source))
}

fn write_new_bytes(
    path: &Path,
    bytes: &[u8],
    operation: &'static str,
) -> Result<(), CampaignGcJournalError> {
    let mut file = open_new_write(path, operation)?;
    file.write_all(bytes)
        .map_err(|source| io_error(operation, path, source))?;
    file.sync_all()
        .map_err(|source| io_error(operation, path, source))
}

fn open_new_write(path: &Path, operation: &'static str) -> Result<File, CampaignGcJournalError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error(operation, path, source))
}

fn open_read(path: &Path, operation: &'static str) -> Result<File, CampaignGcJournalError> {
    File::open(path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            CampaignGcJournalError::Incomplete
        } else {
            io_error(operation, path, source)
        }
    })
}

fn read_bounded_file(
    path: &Path,
    maximum: usize,
    operation: &'static str,
) -> Result<Vec<u8>, CampaignGcJournalError> {
    let file = open_read(path, operation)?;
    let limit = u64::try_from(maximum)
        .map_err(|_| CampaignGcJournalError::InvalidState)?
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error(operation, path, source))?;
    if bytes.len() > maximum {
        return Err(CampaignGcJournalError::InvalidState);
    }
    Ok(bytes)
}

fn sync_directory(path: &Path, operation: &'static str) -> Result<(), CampaignGcJournalError> {
    let directory = File::open(path).map_err(|source| io_error(operation, path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error(operation, path, source))
}

fn sync_parent(path: &Path, operation: &'static str) -> Result<(), CampaignGcJournalError> {
    let parent = path
        .parent()
        .ok_or(CampaignGcJournalError::InvalidDirectory)?;
    sync_directory(parent, operation)
}

fn encode_state(plan: CampaignGcPlanId, phase: CampaignGcJournalPhase) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(JOURNAL_STATE_BYTES);
    bytes.extend_from_slice(JOURNAL_STATE_MAGIC);
    bytes.extend_from_slice(&plan.as_hash().as_bytes());
    bytes.push(phase.tag());
    let checksum = CampaignHash::derive(JOURNAL_STATE_HASH_DOMAIN, &bytes);
    bytes.extend_from_slice(&checksum.as_bytes());
    bytes
}

fn decode_state(
    bytes: &[u8],
) -> Result<(CampaignGcPlanId, CampaignGcJournalPhase), CampaignGcJournalError> {
    if bytes.len() != JOURNAL_STATE_BYTES || !bytes.starts_with(JOURNAL_STATE_MAGIC) {
        return Err(CampaignGcJournalError::InvalidState);
    }
    let plan_start = JOURNAL_STATE_MAGIC.len();
    let phase_index = plan_start + 32;
    let checksum_start = phase_index + 1;
    let plan = CampaignHash::from_bytes(
        bytes[plan_start..phase_index]
            .try_into()
            .map_err(|_| CampaignGcJournalError::InvalidState)?,
    );
    let phase = CampaignGcJournalPhase::from_tag(bytes[phase_index])?;
    let expected = CampaignHash::derive(JOURNAL_STATE_HASH_DOMAIN, &bytes[..checksum_start]);
    let actual = CampaignHash::from_bytes(
        bytes[checksum_start..]
            .try_into()
            .map_err(|_| CampaignGcJournalError::InvalidState)?,
    );
    if actual != expected {
        return Err(CampaignGcJournalError::InvalidState);
    }
    Ok((CampaignGcPlanId::from_hash(plan), phase))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> CampaignGcJournalError {
    CampaignGcJournalError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

impl CampaignGcPlanId {
    const fn from_hash(hash: CampaignHash) -> Self {
        Self(hash)
    }
}
