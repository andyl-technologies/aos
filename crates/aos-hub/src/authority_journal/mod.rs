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

mod filesystem;
mod sqlite;

#[cfg(test)]
mod tests;

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
        sqlite::initialize(&adapter, &snapshot)?;
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

    /// Reloads a complete validated current snapshot from the actual file.
    ///
    /// # Errors
    /// Returns an error for changed file/installation, corruption or SQLite I/O.
    pub fn load(&self) -> Result<IssuerLiveState> {
        sqlite::load(self)
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
