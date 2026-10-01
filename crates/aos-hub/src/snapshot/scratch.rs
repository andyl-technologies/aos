//! Private in-memory SQLite verification of retained capture constraints.
//!
//! Reconstructed rows remain provisional until both encrypted streams and their
//! signed summaries complete. Trusted compiled DDL independently enforces SQL
//! constraints; the database is rolled back and destroyed before a report is
//! returned. No source files, serving initializer, jobs or providers are opened.
//! Synthetic lineage markers are derived metadata, never exported originals.
//! Authentication omissions stay empty. Source key custody, application/object
//! closure and activation remain unproved. No plaintext scratch file is created.
//!
//! Page/cache settings bound selected resources, not every SQLite allocation or
//! driver/caller copy. Blocking readers and scheduling prevent hard physical-I/O
//! or wall-clock cancellation promises; owned memory has no perfect-erasure claim.

use std::fmt;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aos_hub_core::backend::sqlite_snapshot::CompiledSqliteSnapshotCatalogue;
use aos_hub_core::snapshot::archive::StreamLimits;
use aos_hub_core::snapshot::archive::records::VerifiedDatabaseCaptureRecords;
use aos_hub_core::snapshot::archive::root::{
    ArchiveSignerTrust, ArchiveWrappingKeys, ExcludedArchiveKey,
};

mod budget;
mod replay;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fixture;

use budget::WorkBudget;

/// Explicit limits for private SQLite replay, separate from source capture limits.
#[derive(Debug, Clone, Copy)]
pub struct ScratchVerificationLimits {
    /// Maximum primary in-memory database pages, expressed as bytes.
    ///
    /// The supported ceiling is 256 MiB. This is not a total heap bound.
    pub max_database_bytes: u64,
    /// Maximum retained rows accepted from provisional callbacks.
    pub max_retained_rows: u64,
    /// Maximum cumulative original typed-cell payload bytes.
    pub max_value_bytes: u64,
    /// Monotonic work deadline; blocking input can outlive its observation.
    pub max_duration: Duration,
    /// Maximum approximately thousand-instruction SQLite progress callbacks.
    pub max_progress_callbacks: u64,
    /// Independent limits for each encrypted stream.
    pub streams: StreamLimits,
}

impl Default for ScratchVerificationLimits {
    fn default() -> Self {
        Self {
            max_database_bytes: 64 * 1024 * 1024,
            max_retained_rows: 1_000_000,
            max_value_bytes: 256 * 1024 * 1024,
            max_duration: Duration::from_secs(300),
            max_progress_callbacks: 100_000,
            streams: StreamLimits::default(),
        }
    }
}

impl ScratchVerificationLimits {
    fn validate(self) -> ScratchResult<()> {
        if !(4096..=256 * 1024 * 1024).contains(&self.max_database_bytes)
            || !(1..=10_000_000).contains(&self.max_retained_rows)
            || !(1..=1024 * 1024 * 1024).contains(&self.max_value_bytes)
            || self.max_duration.is_zero()
            || self.max_duration > Duration::from_secs(3600)
            || !(1..=1_000_000).contains(&self.max_progress_callbacks)
        {
            return Err(ScratchVerificationError::InvalidLimits);
        }
        Ok(())
    }
}

/// A cooperative one-operation cancellation signal with no reset operation.
///
/// Cancellation stops later work observations, never claims immediate reader or
/// physical-I/O termination. Clones share the same monotonic cancellation flag.
#[derive(Clone, Default)]
pub struct ScratchCancellation(Arc<AtomicBool>);

impl fmt::Debug for ScratchCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScratchCancellation { <cooperative> }")
    }
}

impl ScratchCancellation {
    /// Requests cancellation without clearing or replacing any prior request.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
}

/// Owned private verification inputs transferred to one blocking worker.
///
/// Reader and wrapping custody are explicit. No paths, provider credentials,
/// source sealing keys or Hub runtime initializers are selected implicitly.
pub struct ScratchVerificationInputs<M, P> {
    /// Bounded signed root bytes; these do not contain plaintext archive keys.
    pub root: Vec<u8>,
    /// Independently provisioned signer trust.
    pub trust: ArchiveSignerTrust,
    /// Explicit separate metadata/private archive wrapping custody.
    pub wrapping: ArchiveWrappingKeys,
    /// Known nonarchive material used only for bounded equality exclusions.
    pub exclusions: Vec<ExcludedArchiveKey>,
    /// Immutable encrypted metadata input; blocking liveness is caller-owned.
    pub metadata: M,
    /// Immutable encrypted private input; blocking liveness is caller-owned.
    pub private: P,
}

impl<M, P> fmt::Debug for ScratchVerificationInputs<M, P> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScratchVerificationInputs { <private custody and inputs> }")
    }
}

/// A completed retained-SQLite constraint report without a recoverable database.
///
/// Source audit remains a signer declaration. This report proves no source-key
/// association, application references, provider/object closure, import or
/// activation. Construction requires actual paired completion and independent
/// scratch checks, followed by rollback and connection destruction.
pub struct VerifiedRetainedSqliteCapture {
    records: VerifiedDatabaseCaptureRecords,
    checked_tables: usize,
}

impl fmt::Debug for VerifiedRetainedSqliteCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedRetainedSqliteCapture")
            .field("counts", self.records.counts())
            .field("scope", &"retained_sqlite_constraints_only")
            .finish_non_exhaustive()
    }
}

impl VerifiedRetainedSqliteCapture {
    /// Borrows the completed record proof, including declared source audit facts.
    pub fn records(&self) -> &VerifiedDatabaseCaptureRecords {
        &self.records
    }

    /// Returns the count of retained tables independently checked in scratch.
    pub fn checked_tables(&self) -> usize {
        self.checked_tables
    }

    /// Returns two synthetic lineage rows derived from the compiled contract.
    ///
    /// These rows are not exported originals or historical migration evidence.
    pub fn synthetic_lineage_rows(&self) -> usize {
        2
    }
}

/// Constant failure categories that exclude SQL/private/parser diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ScratchVerificationError {
    /// Requested work/resource limits are unsupported.
    #[error("snapshot scratch limits are invalid")]
    InvalidLimits,
    /// The trusted schema cannot be constructed exactly.
    #[error("snapshot scratch compiled schema is unavailable")]
    Schema,
    /// Signed framing and complete record verification failed.
    #[error("snapshot capture records are incomplete or invalid")]
    Records,
    /// An original row cannot be retained with exact SQL values and constraints.
    #[error("snapshot retained row constraints failed")]
    RetainedRow,
    /// Complete scratch contents violate relational constraints or exact counts.
    #[error("snapshot retained SQL constraints failed")]
    Constraints,
    /// Selected resource/work limits were exceeded.
    #[error("snapshot scratch work exceeds limits")]
    Limits,
    /// Caller cancellation or future drop stopped cooperative work.
    #[error("snapshot scratch verification was cancelled")]
    Cancelled,
    /// The worker or scratch resource could not be closed successfully.
    #[error("snapshot scratch cleanup failed")]
    Cleanup,
}

type ScratchResult<T> = Result<T, ScratchVerificationError>;

// Projections are provisional private output. Callers may publish only after
// full replay, stream EOF, relational/provenance checks and resource closure.
pub(crate) trait ScratchProjection: Send {
    fn schema(
        &mut self,
        schema: &aos_hub_core::snapshot::SnapshotSchemaManifest,
    ) -> anyhow::Result<()>;
    fn row(
        &mut self,
        table: &str,
        sequence: u64,
        row: &aos_hub_core::value::Row,
    ) -> anyhow::Result<()>;
}

pub(crate) async fn verify_with_projection<M, P>(
    inputs: ScratchVerificationInputs<M, P>,
    limits: ScratchVerificationLimits,
    cancellation: ScratchCancellation,
    projection: Box<dyn ScratchProjection>,
) -> ScratchResult<VerifiedRetainedSqliteCapture>
where
    M: Read + Send + 'static,
    P: Read + Send + 'static,
{
    verify_inner_with_projection(
        inputs,
        limits,
        cancellation,
        Default::default(),
        Some(projection),
    )
    .await
}

/// Verifies complete capture records and retained SQL constraints in private memory.
///
/// An owned blocking worker consumes provisional rows, then destroys its database
/// even on success. Dropping this future requests cancellation through a guard
/// outside the worker; dropping a JoinHandle alone would not stop it. The worker
/// can retain private memory until its next cooperative observation. No hard
/// blocking-read deadline, heap bound, perfect erasure or activation is claimed.
///
/// # Errors
///
/// Returns constant errors for invalid inputs/limits, schema or record failures,
/// original row/SQL constraints, cancellation, exhausted work or cleanup failure.
pub async fn verify_capture_in_scratch<M, P>(
    inputs: ScratchVerificationInputs<M, P>,
    limits: ScratchVerificationLimits,
    cancellation: ScratchCancellation,
) -> ScratchResult<VerifiedRetainedSqliteCapture>
where
    M: Read + Send + 'static,
    P: Read + Send + 'static,
{
    verify_inner(inputs, limits, cancellation, Default::default()).await
}

async fn verify_inner<M, P>(
    inputs: ScratchVerificationInputs<M, P>,
    limits: ScratchVerificationLimits,
    cancellation: ScratchCancellation,
    controls: budget::TestControls,
) -> ScratchResult<VerifiedRetainedSqliteCapture>
where
    M: Read + Send + 'static,
    P: Read + Send + 'static,
{
    verify_inner_with_projection(inputs, limits, cancellation, controls, None).await
}

async fn verify_inner_with_projection<M, P>(
    inputs: ScratchVerificationInputs<M, P>,
    limits: ScratchVerificationLimits,
    cancellation: ScratchCancellation,
    controls: budget::TestControls,
    projection: Option<Box<dyn ScratchProjection>>,
) -> ScratchResult<VerifiedRetainedSqliteCapture>
where
    M: Read + Send + 'static,
    P: Read + Send + 'static,
{
    limits.validate()?;
    if inputs.root.len() > 64 * 1024 || inputs.exclusions.len() > 32 {
        return Err(ScratchVerificationError::Records);
    }
    let budget = WorkBudget::new(limits, cancellation, controls)?;
    let _future_scope = budget::CancelOnDrop::new(budget.clone());
    budget.check()?;
    // The fixed supported set is compiled before blocking input is read. Only
    // matching authenticated headers choose one; rows never select replay DDL.
    let generation3 = CompiledSqliteSnapshotCatalogue::load_generation(3)
        .await
        .map_err(|_| budget.error_or(ScratchVerificationError::Schema))?;
    budget.check()?;
    let generation4 = CompiledSqliteSnapshotCatalogue::load_generation(4)
        .await
        .map_err(|_| budget.error_or(ScratchVerificationError::Schema))?;
    budget.check()?;
    let generation5 = CompiledSqliteSnapshotCatalogue::load_generation(5)
        .await
        .map_err(|_| budget.error_or(ScratchVerificationError::Schema))?;
    budget.check()?;

    let generation6 = CompiledSqliteSnapshotCatalogue::load_generation(6)
        .await
        .map_err(|_| budget.error_or(ScratchVerificationError::Schema))?;
    budget.check()?;

    let generation7 = CompiledSqliteSnapshotCatalogue::load_generation(7)
        .await
        .map_err(|_| budget.error_or(ScratchVerificationError::Schema))?;
    budget.check()?;

    let generation8 = CompiledSqliteSnapshotCatalogue::load_generation(8)
        .await
        .map_err(|_| budget.error_or(ScratchVerificationError::Schema))?;
    budget.check()?;

    tokio::task::spawn_blocking(move || {
        replay::verify(
            inputs,
            [
                generation3,
                generation4,
                generation5,
                generation6,
                generation7,
                generation8,
            ],
            limits,
            budget,
            projection,
        )
    })
    .await
    .map_err(|_| ScratchVerificationError::Cleanup)?
}
