//! Offline capture and record verification over private local archive files.
//!
//! Reports concern records/reconstruction and authenticated signer declarations.
//! They authorize no import, runtime, provider operation, journal adoption or job.
//! Cancellation is cooperative; one blocked kernel I/O cannot be forcibly bounded.
//!
//! ```json
//! {"schema_version":"aos.hub.offline-database-capture-report/v1",
//!  "operation":"verify_capture","verification_scope":"records_and_reconstruction",
//!  "signed_root_profile":"framing_only","tables":267,"retained_rows":0,
//!  "omitted_rows":0,"private_cells":0,
//!  "source_audit_scope":"authenticated_exporter_declaration",
//!  "pending_recovery_requirements":["unique_keys_and_global_sql_constraints",
//!    "application_and_object_closure","original_sealing_key_custody",
//!    "external_credential_custody","live_external_journal_continuity",
//!    "activation_and_old_writer_fencing"]}
//! ```

use std::io::{BufWriter, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aos_hub_core::backend::sqlite_snapshot::{
    SqliteSnapshotAuditLimits, SqliteSnapshotLimits, SqliteSnapshotReader,
};
use aos_hub_core::snapshot::archive::records::{
    capture_sqlite, verify_database_capture, CaptureKeyCustody, DatabaseCaptureCounts,
    SqliteCaptureOptions,
};
use aos_hub_core::snapshot::archive::root::verify_declared_root;
use aos_hub_core::snapshot::archive::StreamLimits;
use serde::Serialize;

use super::credentials::{load_capture, load_exclusions, load_trust, load_wrapping};
use super::filesystem::{self, Directory, PublishError, SourceAdmission, Stage};
use super::{CaptureCredentials, VerifyCredentials};

/// Value-free failure stage, including the irreversible publication boundary.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// Arguments exceed the supported local work bounds.
    #[error("snapshot work limits are invalid")]
    Limits,
    /// Explicit external credentials or trust could not be admitted.
    #[error("snapshot credentials or external signer trust are invalid")]
    Credentials,
    /// The existing source could not be securely admitted or schema-validated.
    #[error("snapshot existing SQLite source is unavailable or invalid")]
    Source,
    /// No completed published archive was produced.
    #[error("snapshot capture failed before publication")]
    Capture,
    /// Private staging or publication failed before rename committed.
    #[error("snapshot output failed before publication")]
    Output,
    /// Actual paired record verification failed.
    #[error("snapshot record verification failed")]
    Verification,
    /// Cancellation/deadline was observed before a completed operation.
    #[error("snapshot operation cancelled before completion")]
    Cancelled,
    /// The directory rename succeeded but parent durability was not confirmed.
    #[error("snapshot directory published; durability was not confirmed")]
    PublishedDurabilityUnconfirmed,
}

/// Cooperative cancellation and deadline shared with synchronous file operations.
#[derive(Clone)]
pub struct SnapshotBudget {
    cancelled: Arc<AtomicBool>,
    notified: Arc<tokio::sync::Notify>,
    deadline: Instant,
    streams: StreamLimits,
}

impl SnapshotBudget {
    /// Admits a one-day maximum deadline and at most 64GiB plaintext per stream.
    ///
    /// # Errors
    ///
    /// Rejects zero/excessive durations or byte limits and arithmetic overflow.
    pub fn new(timeout: Duration, plaintext_bytes: u64) -> Result<Self, SnapshotError> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(86400)
            || plaintext_bytes == 0
            || plaintext_bytes > 64 * 1024 * 1024 * 1024
        {
            return Err(SnapshotError::Limits);
        }
        // Fixed v1 format: 256KiB encoder frames, 32 bytes DATA overhead,
        // and 116 bytes header/END. Core enforces its independent hard bounds.
        let frames = plaintext_bytes.div_ceil(262144);
        let ciphertext = frames
            .checked_mul(32)
            .and_then(|extra| plaintext_bytes.checked_add(extra))
            .and_then(|size| size.checked_add(116))
            .ok_or(SnapshotError::Limits)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(SnapshotError::Limits)?;
        Ok(Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notified: Arc::new(tokio::sync::Notify::new()),
            deadline,
            streams: StreamLimits {
                max_data_frames: frames,
                max_plaintext_bytes: plaintext_bytes,
                max_ciphertext_bytes: ciphertext,
            },
        })
    }

    /// Requests cooperative cancellation without touching source or files.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notified.notify_one();
    }

    fn check(&self) -> Result<(), SnapshotError> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            Err(SnapshotError::Cancelled)
        } else {
            Ok(())
        }
    }

    async fn stopped(&self) {
        if self.check().is_err() {
            return;
        }
        tokio::select! {
            _ = self.notified.notified() => {},
            _ = tokio::time::sleep_until(self.deadline.into()) => {},
        }
    }
}

// Dropping an awaiting operation requests cancellation for any owned blocking
// verifier that cannot be aborted immediately. Blocking Read liveness remains
// caller/kernel-owned; this does not promise forced cancellation of one syscall.
struct CancelOnDrop(SnapshotBudget);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct BudgetIo<T> {
    inner: T,
    budget: SnapshotBudget,
}

impl<T: Read> Read for BudgetIo<T> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.budget
            .check()
            .map_err(|_| std::io::Error::other("snapshot cancelled"))?;
        self.inner.read(bytes)
    }
}

impl<T: Write> Write for BudgetIo<T> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.budget
            .check()
            .map_err(|_| std::io::Error::other("snapshot cancelled"))?;
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.budget
            .check()
            .map_err(|_| std::io::Error::other("snapshot cancelled"))?;
        self.inner.flush()
    }
}

/// A sanitized record-only report, without private values, paths or key material.
#[derive(Debug, Serialize)]
pub struct SnapshotReport {
    /// Exact report format for offline local records, never a restore grant.
    pub schema_version: &'static str,
    /// The executed operation: capture_sqlite or verify_capture.
    pub operation: &'static str,
    /// Grammar, reconstruction and count verification scope.
    pub verification_scope: &'static str,
    /// Existing signed-root scope remains framing_only.
    pub signed_root_profile: &'static str,
    /// Every admitted table, including empty and explicit omission tables.
    pub tables: u64,
    /// Reconstructed retained rows.
    pub retained_rows: u64,
    /// Declared source rows omitted by classification policy.
    pub omitted_rows: u64,
    /// Exact matched private-cell dependencies.
    pub private_cells: u64,
    /// Source audit provenance is an authenticated exporter declaration.
    pub source_audit_scope: &'static str,
    /// Separately required contracts before any stronger recovery acceptance.
    pub pending_recovery_requirements: [&'static str; 6],
}

fn report(operation: &'static str, counts: &DatabaseCaptureCounts) -> SnapshotReport {
    SnapshotReport {
        schema_version: "aos.hub.offline-database-capture-report/v1",
        operation,
        verification_scope: "records_and_reconstruction",
        signed_root_profile: "framing_only",
        tables: counts.tables,
        retained_rows: counts.retained_rows,
        omitted_rows: counts.omitted_rows,
        private_cells: counts.private_cells,
        source_audit_scope: "authenticated_exporter_declaration",
        pending_recovery_requirements: [
            "unique_keys_and_global_sql_constraints",
            "application_and_object_closure",
            "original_sealing_key_custody",
            "external_credential_custody",
            "live_external_journal_continuity",
            "activation_and_old_writer_fencing",
        ],
    }
}

fn verify_directory(
    directory: Directory,
    root: Vec<u8>,
    trust: aos_hub_core::snapshot::archive::root::ArchiveSignerTrust,
    wrapping: aos_hub_core::snapshot::archive::root::ArchiveWrappingKeys,
    exclusions: Vec<aos_hub_core::snapshot::archive::root::ExcludedArchiveKey>,
    budget: SnapshotBudget,
) -> Result<DatabaseCaptureCounts, SnapshotError> {
    budget.check()?;
    let metadata = BudgetIo {
        inner: directory
            .file("metadata.aosh")
            .map_err(|_| SnapshotError::Verification)?,
        budget: budget.clone(),
    };
    let private = BudgetIo {
        inner: directory
            .file("private.aosh")
            .map_err(|_| SnapshotError::Verification)?,
        budget: budget.clone(),
    };
    let verified = verify_database_capture(
        &root,
        &trust,
        &wrapping,
        &exclusions,
        metadata,
        private,
        budget.streams,
        |_, _, _| budget.check().map_err(anyhow::Error::from),
    );
    budget.check()?;
    verified
        .map(|verified| verified.counts().clone())
        .map_err(|_| SnapshotError::Verification)
}

/// Captures an existing SQLite file and atomically publishes a private directory.
///
/// Source path admission cannot defeat malicious same-owner pathname replacement;
/// SQLx still opens a path, while the original reader preserves normal WAL reads.
/// No runtime initializer, source sealer, provider or imported SQL is invoked.
///
/// # Errors
///
/// Returns sanitized credential/source/capture/staging/verification/cancellation
/// failures. A post-rename sync failure distinctly reports published durability
/// unconfirmed and never deletes the published directory.
pub async fn capture(
    source: &Path,
    destination: &Path,
    credentials: &CaptureCredentials,
    budget: SnapshotBudget,
) -> Result<SnapshotReport, SnapshotError> {
    let _cancellation = CancelOnDrop(budget.clone());
    budget.check()?;
    let custody = load_capture(credentials).map_err(|_| SnapshotError::Credentials)?;
    let admitted = SourceAdmission::open(source).map_err(|_| SnapshotError::Source)?;
    let reader = tokio::select! {
        result = SqliteSnapshotReader::open(&admitted.path) => result.map_err(|_| SnapshotError::Source)?,
        _ = budget.stopped() => return Err(SnapshotError::Cancelled),
    };
    admitted
        .check_identity()
        .map_err(|_| SnapshotError::Source)?;
    budget.check()?;
    let mut stage = Stage::create(destination).map_err(|_| SnapshotError::Output)?;
    let metadata = BudgetIo {
        inner: BufWriter::new(
            stage
                .create_file("metadata.aosh")
                .map_err(|_| SnapshotError::Output)?,
        ),
        budget: budget.clone(),
    };
    let private = BudgetIo {
        inner: BufWriter::new(
            stage
                .create_file("private.aosh")
                .map_err(|_| SnapshotError::Output)?,
        ),
        budget: budget.clone(),
    };
    let options = SqliteCaptureOptions {
        audit: SqliteSnapshotAuditLimits {
            max_duration: Duration::from_secs(300),
            max_progress_callbacks: 1_000_000,
        },
        pages: SqliteSnapshotLimits::default(),
        streams: budget.streams,
    };
    let mut rng = rand::rngs::OsRng;
    let output = tokio::select! {
        result = capture_sqlite(reader, metadata, private, CaptureKeyCustody { signer: &custody.signer,
            wrapping: &custody.wrapping, exclusions: &custody.exclusions }, &mut rng, options) => result,
        _ = budget.stopped() => return Err(SnapshotError::Cancelled),
    };
    budget.check()?;
    let output = output.map_err(|_| SnapshotError::Capture)?;
    admitted
        .check_identity()
        .map_err(|_| SnapshotError::Source)?;
    let metadata = output
        .metadata
        .inner
        .into_inner()
        .map_err(|_| SnapshotError::Output)?;
    let private = output
        .private
        .inner
        .into_inner()
        .map_err(|_| SnapshotError::Output)?;
    metadata.sync_all().map_err(|_| SnapshotError::Output)?;
    private.sync_all().map_err(|_| SnapshotError::Output)?;
    drop((metadata, private));
    stage
        .write_root(output.root.as_bytes())
        .map_err(|_| SnapshotError::Output)?;
    let directory = Directory {
        fd: rustix::io::dup(&stage.directory().fd).map_err(|_| SnapshotError::Verification)?,
    };
    let root = filesystem::root(stage.directory()).map_err(|_| SnapshotError::Verification)?;
    let readback_budget = budget.clone();
    let observed = tokio::task::spawn_blocking(move || {
        verify_directory(
            directory,
            root,
            custody.trust,
            custody.wrapping,
            custody.exclusions,
            readback_budget,
        )
    })
    .await
    .map_err(|_| SnapshotError::Verification)??;
    if observed != output.counts {
        return Err(SnapshotError::Verification);
    }
    budget.check()?;
    stage.publish().map_err(|error| match error {
        PublishError::BeforeRename => SnapshotError::Output,
        PublishError::DurabilityUnconfirmed => SnapshotError::PublishedDurabilityUnconfirmed,
    })?;
    Ok(report("capture_sqlite", &observed))
}

/// Verifies a private archive's actual paired streams using external signer trust.
///
/// Private callbacks only discard reconstructed rows. No SQL, scratch replay,
/// output directory, import or activation operation occurs. Both complete EOFs
/// are mandatory; source audit facts remain authenticated declarations.
///
/// # Errors
///
/// Returns sanitized trust/custody, directory, stream, record or cancellation
/// failures. Blocking kernel I/O can delay cooperative cancellation.
pub async fn verify(
    archive: &Path,
    credentials: &VerifyCredentials,
    budget: SnapshotBudget,
) -> Result<SnapshotReport, SnapshotError> {
    let _cancellation = CancelOnDrop(budget.clone());
    budget.check()?;
    let directory = Directory::open(archive, true).map_err(|_| SnapshotError::Verification)?;
    let root = filesystem::root(&directory).map_err(|_| SnapshotError::Verification)?;
    let trust =
        load_trust(&credentials.signer_trust_file).map_err(|_| SnapshotError::Credentials)?;
    verify_declared_root(&root, &trust).map_err(|_| SnapshotError::Verification)?;
    let wrapping = load_wrapping(&credentials.wrapping).map_err(|_| SnapshotError::Credentials)?;
    let exclusions =
        load_exclusions(&credentials.exclusion_files).map_err(|_| SnapshotError::Credentials)?;
    let cancellation = budget.clone();
    let worker = tokio::task::spawn_blocking(move || {
        verify_directory(directory, root, trust, wrapping, exclusions, budget)
    });
    let counts = worker.await.map_err(|_| SnapshotError::Verification)??;
    cancellation.check()?;
    Ok(report("verify_capture", &counts))
}
