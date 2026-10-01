//! Dedicated Native SQLite persistence for one external authority issuer.
//!
//! Each explicitly initialized installation owns one existing private file and
//! its dedicated private parent directory,
//! separate from Hub SQL and `HUB_ROOT`. Serving never creates a file, installs
//! schema, or reconstructs a used issuer from archived Hub state. This adapter
//! owns no signing key, transport, process entry point or provider operation.
//!
//! Journal counters remain canonical decimal strings in bounded JSON blobs:
//!
//! ```json
//! {"generation":"1","last_sequence":"9007199254740993"}
//! ```
//!
//! Actual SQLite transactions serialize lease issuance with publication/denial.
//! Acknowledgment follows an EXTRA-synchronous commit (stronger than FULL).
//! Cancellation or lost acknowledgment cannot undo a possibly committed write.
//! Operators must preserve the complete file and immutable installation identity;
//! rollback restoration or copying a used installation into a fresh namespace
//! is unsupported. File existence alone proves no provider/namespace novelty.

use std::path::{Path, PathBuf};

use anyhow::Result;
use aos_hub_core::storage_authority::{
    control::{StorageAuthorityDeniedTransition, StorageAuthorityPublication},
    lease::{
        BoundedLeaseRevocationPolicy, EpochLeaseIssuerJournal, IssuerTransition, LeaseClock,
        LeaseInteger,
    },
};
use rand::TryRngCore as _;

mod control_replay;
mod filesystem;
pub mod recovery;
mod sqlite;

#[cfg(test)]
pub(crate) mod tests;

pub use aos_hub_core::storage_authority::lease::control::{
    IssuerInstallation, IssuerLiveState, IssuerPublicationReceipt,
};

/// Explicit paths excluded from the issuer's durable journal installation.
///
/// Callers supply the actual Hub root and the actual Hub SQL file when SQLite
/// is used for Hub SQL. This does not inspect or infer environment/defaults.
#[derive(Debug, Clone)]
pub struct HubDataBoundary {
    /// Explicit actual Hub data root; the separate issuer need not mount it.
    pub hub_root: PathBuf,
    /// Actual Hub SQLite file, if Hub SQL uses SQLite.
    pub hub_sqlite_file: Option<PathBuf>,
}

/// Existing private per-authority SQLite installation, with no cached head.
///
/// Clones retain only immutable coordinates and file identity. Every operation
/// reloads and validates actual SQLite state; the complete expected journal is
/// compared inside the write transaction. The future separate authority process
/// must independently verify publication provenance and confine issuer keys.
#[derive(Debug, Clone)]
pub struct AuthorityJournal {
    file: filesystem::PrivateFile,
    marker: IssuerInstallation,
}

impl AuthorityJournal {
    /// Explicitly creates a freshly qualified per-authority installation.
    ///
    /// The caller must independently establish a never-used issuer resource and
    /// authority namespace. This accepts only first-generation reviewed state.
    /// Existing files are never reused or overwritten. Failure may leave an
    /// incomplete file which serving will refuse; this is not a recovery API.
    ///
    /// # Errors
    /// Returns an error for existing/insecure/Hub-owned paths, identity mismatch,
    /// invalid initial publication/profile/time, or initialization/fsync failure.
    pub fn initialize_fresh(
        path: &Path,
        boundary: &HubDataBoundary,
        marker: IssuerInstallation,
        publication: StorageAuthorityPublication,
        policy: BoundedLeaseRevocationPolicy,
        clock: LeaseClock,
    ) -> Result<Self> {
        Self::initialize_inner(path, boundary, marker, publication, policy, clock, None)
    }

    /// Creates a fresh format 3 journal with an immutable independent recovery policy.
    ///
    /// Existing journals, installation markers and publication history are never
    /// adopted, copied or upgraded by this operation.
    ///
    /// # Errors
    /// Returns an error for invalid or mismatched policies, existing/insecure
    /// files, invalid state, or initialization and durability failures.
    pub fn initialize_recoverable(
        path: &Path,
        boundary: &HubDataBoundary,
        marker: IssuerInstallation,
        publication: StorageAuthorityPublication,
        policy: BoundedLeaseRevocationPolicy,
        clock: LeaseClock,
        recovery: recovery::ClockRecoveryPolicy,
    ) -> Result<Self> {
        recovery.validate()?;
        anyhow::ensure!(
            recovery.total_uncertainty()? <= policy.timing_profile.maximum_clock_uncertainty.get(),
            "recovery uncertainty exceeds installed timing profile"
        );
        Self::initialize_inner(
            path,
            boundary,
            marker,
            publication,
            policy,
            clock,
            Some(&recovery),
        )
    }

    fn initialize_inner(
        path: &Path,
        boundary: &HubDataBoundary,
        marker: IssuerInstallation,
        publication: StorageAuthorityPublication,
        policy: BoundedLeaseRevocationPolicy,
        clock: LeaseClock,
        recovery: Option<&recovery::ClockRecoveryPolicy>,
    ) -> Result<Self> {
        marker.validate()?;
        let journal = EpochLeaseIssuerJournal::initialize_fresh_namespace(
            &publication,
            &marker.executor_identity,
            policy,
            clock,
        )?;
        let snapshot = IssuerLiveState {
            installation: marker.clone(),
            publication,
            journal,
        };
        snapshot.validate()?;
        let file = filesystem::PrivateFile::create_new(path, boundary)?;
        let adapter = Self { file, marker };
        match recovery {
            Some(policy) => sqlite::initialize_with_policy(&adapter, &snapshot, Some(policy))?,
            None => sqlite::initialize(&adapter, &snapshot)?,
        }
        adapter.file.sync_installation()?;
        Ok(adapter)
    }

    /// Opens only an existing exact installation; never creates or migrates.
    ///
    /// # Errors
    /// Returns an error for missing/corrupt/insecure files, schema or marker
    /// mismatch, invalid retained state/receipts, or inconsistent publication.
    pub fn open_existing(
        path: &Path,
        boundary: &HubDataBoundary,
        expected: IssuerInstallation,
    ) -> Result<Self> {
        expected.validate()?;
        let adapter = Self {
            file: filesystem::PrivateFile::existing(path, boundary)?,
            marker: expected,
        };
        adapter.load()?;
        Ok(adapter)
    }

    /// Opens an inactive exact format 3 resource for an explicit operator action.
    ///
    /// The nonblocking inode lock precedes all SQLite reads. Each later recovery
    /// action reacquires that lock and rechecks the complete original transactionally.
    ///
    /// # Errors
    /// Returns an error for active owners, format 2, corrupt or changed files,
    /// installation mismatch or a different immutable recovery policy.
    pub fn open_recovery_existing(
        path: &Path,
        boundary: &HubDataBoundary,
        expected: IssuerInstallation,
        policy: &recovery::ClockRecoveryPolicy,
    ) -> Result<Self> {
        expected.validate()?;
        let adapter = Self {
            file: filesystem::PrivateFile::existing(path, boundary)?,
            marker: expected,
        };
        let _lock = adapter.file.lock_exclusive()?;
        adapter.load()?;
        adapter.verify_recovery_policy(Some(policy))?;
        Ok(adapter)
    }

    /// Reloads a complete validated current snapshot from the actual file.
    ///
    /// # Errors
    /// Returns an error for changed file/installation, corruption or SQLite I/O.
    pub fn load(&self) -> Result<IssuerLiveState> {
        sqlite::load(self)
    }

    /// Irreversibly claims this process's unresolved clock observation session.
    ///
    /// The actual session marker is committed before any clock sample. It remains
    /// retained for the entire process lifetime, including crashes and successful
    /// observations. Serving cannot clear it; restart requires a later explicit
    /// reviewed operator resolution for freshly initialized format 3 journals.
    /// Format 2 journals have no supported recovery or adoption path.
    /// State and historical receipts remain independently readable.
    ///
    /// # Errors
    /// Returns an error for an existing unresolved session, corruption, changed
    /// installation or indeterminate commit. A possibly committed claim is never
    /// retried by substituting cached success or implicitly authorizing restart.
    pub fn begin_clock_observation_session(&self) -> Result<AuthorityClockSession> {
        self.begin_clock_session_with_resolution(None)
    }

    /// Claims the one successor authorized by an exact retained recovery receipt.
    ///
    /// The inode lock remains held for the whole returned observer lifetime.
    /// A receipt cannot authorize two starts, even when the first start crashes.
    ///
    /// # Errors
    /// Returns an error for active owners, format 2, changed or consumed receipts,
    /// stale state, insecure files or indeterminate commit.
    pub fn begin_recovered_clock_session(
        &self,
        receipt: &recovery::ClockRecoveryReceipt,
    ) -> Result<AuthorityClockSession> {
        self.begin_clock_session_with_resolution(Some(receipt))
    }

    fn begin_clock_session_with_resolution(
        &self,
        receipt: Option<&recovery::ClockRecoveryReceipt>,
    ) -> Result<AuthorityClockSession> {
        let lock = self.file.lock_exclusive()?;
        let mut random = [0_u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| anyhow::anyhow!("clock session entropy unavailable"))?;
        let session = match receipt {
            Some(receipt) => {
                sqlite::recovery::consume(self, receipt)?;
                receipt.review.plan.successor_session.clone()
            }
            None => {
                let session = hex::encode(random);
                sqlite::begin_clock_session(self, &session)?;
                session
            }
        };
        Ok(AuthorityClockSession {
            journal: self.clone(),
            session,
            _lock: lock,
        })
    }

    /// Retrieves an exact retained historical publication receipt.
    ///
    /// A receipt acknowledges history, not current admission or provider drain.
    ///
    /// # Errors
    /// Returns an error for corruption or a changed installation/file.
    pub fn receipt(&self, generation: LeaseInteger) -> Result<Option<IssuerPublicationReceipt>> {
        sqlite::receipt(self, generation)
    }

    /// Retrieves a receipt only for the exact originally retained control operation.
    ///
    /// Nonce and request times are absent from the immutable semantic intent.
    /// A changed operation kind, denial CAS or installation is rejected even
    /// when the resulting publication has the same digest. A historical receipt
    /// does not assert current admission or provider settlement.
    ///
    /// # Errors
    /// Returns an error for a changed intent, invalid operation, corrupt history
    /// or changed installation/file. Returns `None` for an uncommitted generation.
    pub fn receipt_for_operation(
        &self,
        operation: aos_hub_core::storage_authority::lease::control::IssuerOperation,
    ) -> Result<Option<IssuerPublicationReceipt>> {
        sqlite::receipt_for_operation(self, operation)
    }

    /// Durably commits an issuance or time-floor transition under the live gate.
    ///
    /// The whole expected journal and unchanged publication are reloaded and
    /// checked within BEGIN IMMEDIATE. Only monotonic issuance/history or a
    /// time-floor update is allowed. Acknowledgment follows SQLite commit.
    /// Dropping this future cannot cancel/undo an already running blocking
    /// transaction; a lost acknowledgment must be recovered by reloading state.
    /// This callback fits `PreparedEpochLease::commit_and_sign` without cached
    /// success, but does not verify publication provenance or mint any token.
    ///
    /// # Errors
    /// Returns an error for a stale/forked expectation, invalid transition,
    /// changed installation or SQLite/worker-task failure. Commit outcome may
    /// be indeterminate on any error; callers must not restore prior state.
    pub async fn commit_lease(&self, transition: IssuerTransition) -> Result<()> {
        self.commit_lease_inner(transition, || {}).await
    }

    async fn commit_lease_inner(
        &self,
        transition: IssuerTransition,
        before_commit: impl FnOnce() + Send + 'static,
    ) -> Result<()> {
        let adapter = self.clone();
        tokio::task::spawn_blocking(move || {
            sqlite::commit_lease(&adapter, transition, before_commit)
        })
        .await??;
        Ok(())
    }

    /// Atomically commits a reviewed publication, journal and historical receipt.
    ///
    /// This recomputes the pure publication transition against the actual head,
    /// with qualified clock observation, then compares the complete caller
    /// expectation. Publication provenance remains a caller prerequisite.
    ///
    /// # Errors
    /// Returns an error for stale/forked/terminal state, premature reopening,
    /// invalid time/publication, changed installation or indeterminate I/O.
    pub async fn commit_publication(
        &self,
        transition: IssuerTransition,
        publication: StorageAuthorityPublication,
        clock: LeaseClock,
    ) -> Result<IssuerPublicationReceipt> {
        let adapter = self.clone();
        tokio::task::spawn_blocking(move || {
            sqlite::commit_publication(&adapter, transition, publication, clock, || Ok(()))
        })
        .await?
    }

    /// Atomically denies across undelivered history using an exact live journal.
    ///
    /// Only reviewed blocked/retired state is accepted. The pure denial-gap
    /// transition is recomputed within the transaction against the actual head;
    /// sequence, largest issued expiry and historical receipts are retained.
    /// This stops lease issuance and does not settle any provider operation.
    ///
    /// # Errors
    /// Returns an error for stale/forked/terminal state, invalid denial/time,
    /// changed installation or indeterminate SQLite/worker-task failure.
    pub async fn commit_denial(
        &self,
        transition: IssuerTransition,
        denial: StorageAuthorityDeniedTransition,
        clock: LeaseClock,
    ) -> Result<IssuerPublicationReceipt> {
        let adapter = self.clone();
        tokio::task::spawn_blocking(move || {
            sqlite::commit_denial(&adapter, transition, denial, clock)
        })
        .await?
    }
}

/// Durable unresolved observation session owned by one separately running issuer.
///
/// Only an acknowledged actual journal claim constructs this value. It cannot
/// authorize another process after restart. Format 3 recovery requires a separate
/// independent review and exact one-use successor; serving never clears a session.
pub struct AuthorityClockSession {
    journal: AuthorityJournal,
    session: String,
    _lock: std::fs::File,
}

impl AuthorityClockSession {
    /// Commits an actual observation floor and interval under this exact live session.
    ///
    /// Acknowledgment follows the same-file EXTRA commit. The clock adapter must
    /// then obtain a fresh post-commit observation and validate the independent
    /// uncertainty/latency/rounding bounds before exposing a qualified value.
    /// The floor is the sampled wall time, not the interval's padded upper bound.
    /// Retaining it alone proves no clock qualification or usable time.
    ///
    /// # Errors
    /// Returns an error for rollback, uncertainty/session mismatch, corruption,
    /// changed installation or indeterminate I/O. No failed outcome clears the
    /// permanently retained unresolved-session marker.
    pub fn retain_ceiling(&self, clock: LeaseClock) -> Result<LeaseClock> {
        sqlite::observe_clock(&self.journal, &self.session, clock)
    }
}
