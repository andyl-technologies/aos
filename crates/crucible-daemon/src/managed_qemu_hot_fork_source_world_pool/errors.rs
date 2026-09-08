//! Managed source-world pool admission, checkout, and lifecycle failures.

use thiserror::Error;

use super::ManagedQemuHotForkSourceWorld;
use crate::{
    DurableHotCheckpointCatalogError, HotCheckpointAdmissionCommitError,
    HotCheckpointAdmissionRejection, HotCheckpointDemotion, HotCheckpointFallbackRetentionError,
    HotCheckpointFallbackSlot, HotCheckpointInventoryError, QemuHotForkTemplateKey,
};

/// Invalid managed source-world pool construction.
#[derive(Debug, Error)]
pub enum ManagedQemuHotForkSourceWorldPoolConstructionError {
    /// The durable catalog could not be inventoried completely.
    #[error("managed source-world fallback inventory failed")]
    Catalog(#[source] HotCheckpointFallbackRetentionError),
}

/// Provider checkout failure before source ownership changes.
#[derive(Debug, Error)]
pub enum ManagedQemuHotForkSourceWorldCheckoutError {
    /// A prior source remains owned by an execution or quarantine path.
    #[error("managed source-world provider still has a prior checkout")]
    PriorCheckoutPending,
    /// The process-wide fork-start rate gate rejected this attempt.
    #[error("managed source-world fork rate rejected the attempt")]
    ForkRate(#[source] crate::HotCheckpointForkRateError),
}

/// Failed admission retaining the candidate source world.
#[must_use = "recover the candidate and any durable cleanup slot"]
pub struct ManagedQemuHotForkSourceWorldAdmissionFailure<E> {
    candidate: Box<ManagedQemuHotForkSourceWorld>,
    cleanup_slot: Option<HotCheckpointFallbackSlot>,
    error: Box<ManagedQemuHotForkSourceWorldAdmissionError<E>>,
}

impl<E> ManagedQemuHotForkSourceWorldAdmissionFailure<E> {
    pub(super) fn new(
        candidate: ManagedQemuHotForkSourceWorld,
        cleanup_slot: Option<HotCheckpointFallbackSlot>,
        error: ManagedQemuHotForkSourceWorldAdmissionError<E>,
    ) -> Self {
        Self {
            candidate: Box::new(candidate),
            cleanup_slot,
            error: Box::new(error),
        }
    }

    /// Consumes the failure into its retained authorities and diagnostic.
    pub fn into_parts(
        self,
    ) -> (
        ManagedQemuHotForkSourceWorld,
        Option<HotCheckpointFallbackSlot>,
        ManagedQemuHotForkSourceWorldAdmissionError<E>,
    ) {
        (*self.candidate, self.cleanup_slot, *self.error)
    }
}

impl<E: std::fmt::Debug> std::fmt::Debug for ManagedQemuHotForkSourceWorldAdmissionFailure<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedQemuHotForkSourceWorldAdmissionFailure")
            .field("cleanup_slot", &self.cleanup_slot)
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

/// Exact reason managed source-world admission failed.
#[derive(Debug, Error)]
pub enum ManagedQemuHotForkSourceWorldAdmissionError<E> {
    /// The no-parallelism policy already retains this source coordinate.
    #[error("source-world coordinate already has a retained source")]
    DuplicateSource,
    /// Shared resource/hotness policy rejected the candidate.
    #[error("source-world candidate was rejected by hot-checkpoint policy")]
    Rejected(#[source] HotCheckpointAdmissionRejection),
    /// Exact/thin fallback authentication failed.
    #[error("source-world fallback authentication failed")]
    Fallback(E),
    /// A planned victim is checked out, invalidated, or missing.
    #[error("planned source-world victim is unavailable")]
    VictimUnavailable {
        /// Accounting reconciliation for earlier completed victims.
        reconciliation: Result<Vec<HotCheckpointDemotion>, HotCheckpointInventoryError>,
    },
    /// A planned victim's active durable fallback record changed or disappeared.
    #[error("planned source-world victim durable fallback differs")]
    VictimCatalog {
        /// Exact durable-catalog failure.
        source: DurableHotCheckpointCatalogError,
        /// Accounting reconciliation for earlier completed victims.
        reconciliation: Result<Vec<HotCheckpointDemotion>, HotCheckpointInventoryError>,
    },
    /// A planned victim could not be reauthenticated and reaped.
    #[error("source-world victim demotion failed")]
    Demotion {
        /// Demotion-sink failure.
        source: E,
        /// Accounting reconciliation for earlier completed victims.
        reconciliation: Result<Vec<HotCheckpointDemotion>, HotCheckpointInventoryError>,
    },
    /// The candidate fallback record could not be created or cleaned up.
    #[error("source-world durable fallback operation failed")]
    Catalog(#[source] DurableHotCheckpointCatalogError),
    /// The bounded durable fallback catalog has no free slot.
    #[error("source-world durable fallback catalog is full")]
    CatalogFull,
    /// Manager commit failed after physical victim demotion.
    #[error("source-world manager admission commit failed")]
    ManagerCommit {
        /// Exact manager commit failure.
        source: HotCheckpointAdmissionCommitError,
        /// Accounting reconciliation for physically completed victims.
        reconciliation: Result<Vec<HotCheckpointDemotion>, HotCheckpointInventoryError>,
    },
}

/// Exact reason an explicit source-world demotion failed.
#[derive(Debug, Error)]
pub enum ManagedQemuHotForkSourceWorldDemotionError<E> {
    /// The live source or its active fallback binding is absent.
    #[error("managed source world is absent")]
    Missing,
    /// The source is checked out or permanently invalidated.
    #[error("managed source world is unavailable")]
    Unavailable,
    /// Shared manager planning or commit failed.
    #[error("managed source-world inventory operation failed")]
    Manager(#[source] HotCheckpointInventoryError),
    /// The durable fallback record is unavailable or changed.
    #[error("managed source-world durable fallback differs")]
    Catalog(#[source] DurableHotCheckpointCatalogError),
    /// Fallback preflight failed before source transfer.
    #[error("managed source-world fallback authentication failed")]
    Fallback(E),
    /// Reauthentication or complete source reap failed.
    #[error("managed source-world demotion failed")]
    Demotion(E),
}

/// Failure to release one durable cold fallback.
#[derive(Debug, Error)]
pub enum ManagedQemuHotForkSourceWorldReleaseError {
    /// The fallback still protects a live source.
    #[error("source-world fallback still protects a live source")]
    Active,
    /// The catalog slot is absent.
    #[error("source-world fallback slot is absent")]
    Missing,
    /// The durable catalog rejected the exact removal.
    #[error("release source-world fallback")]
    Catalog(#[source] DurableHotCheckpointCatalogError),
}

/// Complete failure report from orderly process-wide source shutdown.
#[derive(Debug)]
pub struct ManagedQemuHotForkSourceWorldShutdownError<E> {
    failures: Vec<(
        QemuHotForkTemplateKey,
        ManagedQemuHotForkSourceWorldDemotionError<E>,
    )>,
}

impl<E> ManagedQemuHotForkSourceWorldShutdownError<E> {
    pub(super) fn new(
        failures: Vec<(
            QemuHotForkTemplateKey,
            ManagedQemuHotForkSourceWorldDemotionError<E>,
        )>,
    ) -> Self {
        Self { failures }
    }

    /// Returns every exact source key and its shutdown failure.
    #[must_use]
    pub fn failures(
        &self,
    ) -> &[(
        QemuHotForkTemplateKey,
        ManagedQemuHotForkSourceWorldDemotionError<E>,
    )] {
        &self.failures
    }
}

impl<E> std::fmt::Display for ManagedQemuHotForkSourceWorldShutdownError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} managed QEMU source world(s) could not be shut down",
            self.failures.len()
        )
    }
}

impl<E: std::fmt::Debug> std::error::Error for ManagedQemuHotForkSourceWorldShutdownError<E> {}

/// Failure while shutting down a shared process-wide source owner.
#[derive(Debug, Error)]
pub enum SharedManagedQemuHotForkSourceWorldShutdownError<E>
where
    E: std::fmt::Debug,
{
    /// A prior operation panicked while holding the process-wide pool lock.
    #[error("shared source-world pool lock is poisoned during shutdown")]
    Poisoned,
    /// One or more retained source worlds could not be demoted and reaped.
    #[error(transparent)]
    Sources(#[from] ManagedQemuHotForkSourceWorldShutdownError<E>),
}
