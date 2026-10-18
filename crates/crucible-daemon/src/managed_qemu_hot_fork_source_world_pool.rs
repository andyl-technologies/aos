//! Durable managed ownership for complete retained QEMU source worlds.
//!
//! This pool applies the shared [`HotCheckpointManager`] policy to atomic
//! multi-node source worlds. Canonical factories admit scenario genesis, while
//! production-restored tokens admit later exact-checkpoint frontiers. The pool
//! exact-matches scenario and executor compatibility, distinguishes retained
//! frontiers even when their modeled configurations are equal, persists an
//! exact/thin fallback before admission, charges conservatively measured QEMU
//! process resources, and retains cold fallback records for campaign GC after
//! orderly source reap.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

use crate::vm_lifecycle::ProductionVmHotForkSourceWorld;
use thiserror::Error;

use crate::qemu_hot_fork_source_capture::{
    AuthenticatedCanonicalQemuHotForkSource, AuthenticatedExactQemuHotForkSource,
};
use crate::qemu_hot_fork_world_factory::{
    QemuHotForkSourceWorldCheckoutIdentity, QemuHotForkSourceWorldProvider,
};
use crate::supervision::ForkRateClock;
use crate::{
    HotCheckpointAdmissionCommit, HotCheckpointCandidate, HotCheckpointDemotion,
    HotCheckpointDemotionReason, HotCheckpointFallback, HotCheckpointFallbackRecord,
    HotCheckpointFallbackRetentionCas, HotCheckpointFallbackRetentionError,
    HotCheckpointFallbackRetentionStore, HotCheckpointFallbackSlot, HotCheckpointHotnessSignals,
    HotCheckpointLimits, HotCheckpointManager, HotCheckpointPlannedDemotion, HotCheckpointPoolKey,
    HotCheckpointPoolSlot, HotCheckpointPressure, HotCheckpointResourceProfile,
    HotCheckpointSourceDemoter, HotCheckpointTemplateDemotionFailure,
    HotCheckpointTemplateDemotionSink, HotCheckpointUsage, MAX_HOT_CHECKPOINT_FALLBACK_ROOTS,
    QemuHotForkSourceWorldKey,
};

mod errors;
mod shared_ownership;
use shared_ownership::{LeaseSource, SharedSourceOwnership};

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
mod parent_park;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
pub(crate) use parent_park::{ManagedParentParkError, ManagedParentParkGate};

/// Exact durable-catalog mutation failure.
#[derive(Debug, thiserror::Error)]
pub enum DurableHotCheckpointCatalogError {
    /// Durable storage or authentication failed.
    #[error("hot-checkpoint fallback catalog operation failed")]
    Store(#[source] HotCheckpointFallbackRetentionError),
    /// The exact slot changed outside the single-owner lifecycle.
    #[error("hot-checkpoint fallback catalog slot changed concurrently")]
    Conflict {
        /// Exact conflicting slot.
        slot: HotCheckpointFallbackSlot,
        /// Current value observed by the failed conditional mutation.
        current: Option<HotCheckpointFallbackRecord>,
    },
}

pub use errors::{
    ManagedQemuHotForkSourceWorldAdmissionError, ManagedQemuHotForkSourceWorldAdmissionFailure,
    ManagedQemuHotForkSourceWorldCheckoutError, ManagedQemuHotForkSourceWorldDemotionError,
    ManagedQemuHotForkSourceWorldPoolConstructionError, ManagedQemuHotForkSourceWorldShutdownError,
    SharedManagedQemuHotForkSourceWorldShutdownError,
};

/// One full-key-bound source world owned by the managed pool.
#[must_use = "admit, demote, or retain the complete source-world authority"]
pub struct ManagedQemuHotForkSourceWorld {
    key: QemuHotForkSourceWorldKey,
    resources: HotCheckpointResourceProfile,
    source: Option<ProductionVmHotForkSourceWorld>,
    leased_source: Option<SharedSourceOwnership>,
    invalidated: bool,
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    parent_park: Option<parent_park::ManagedParentParkSelection>,
}

impl ManagedQemuHotForkSourceWorld {
    /// Binds a prepared source world to its authenticated reuse key.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedQemuHotForkSourceWorldBindingFailure`] with the source
    /// unchanged when its captured scenario or configuration differs.
    pub(crate) fn bind(
        key: QemuHotForkSourceWorldKey,
        source: ProductionVmHotForkSourceWorld,
    ) -> Result<Self, ManagedQemuHotForkSourceWorldBindingFailure> {
        Self::bind_at_boundary(key, source, true)
    }

    fn bind_authenticated_exact(
        key: QemuHotForkSourceWorldKey,
        source: ProductionVmHotForkSourceWorld,
    ) -> Result<Self, ManagedQemuHotForkSourceWorldBindingFailure> {
        Self::bind_at_boundary(key, source, false)
    }

    fn bind_at_boundary(
        key: QemuHotForkSourceWorldKey,
        mut source: ProductionVmHotForkSourceWorld,
        require_canonical_genesis: bool,
    ) -> Result<Self, ManagedQemuHotForkSourceWorldBindingFailure> {
        let continuation = match source.continuation() {
            Ok(continuation) => continuation,
            Err(error) => {
                return Err(ManagedQemuHotForkSourceWorldBindingFailure::new(
                    source,
                    ManagedQemuHotForkSourceWorldBindingError::Continuation(error),
                ));
            }
        };
        let actual_scenario = continuation.configuration().def.id();
        let actual_configuration = continuation.configuration().id();
        if actual_scenario != key.scenario() || actual_configuration != key.configuration() {
            let error = ManagedQemuHotForkSourceWorldBindingError::SourceKeyMismatch {
                expected_scenario: key.scenario(),
                actual_scenario,
                expected_configuration: key.configuration(),
                actual_configuration,
            };
            return Err(ManagedQemuHotForkSourceWorldBindingFailure::new(
                source, error,
            ));
        }
        if require_canonical_genesis
            && let Some(detail) = canonical_genesis_reuse_boundary_error(continuation)
        {
            return Err(ManagedQemuHotForkSourceWorldBindingFailure::new(
                source,
                ManagedQemuHotForkSourceWorldBindingError::NonCanonicalBoundary { detail },
            ));
        }

        let usage = match source.measure_retained_resources() {
            Ok(usage) => usage,
            Err(error) => {
                return Err(ManagedQemuHotForkSourceWorldBindingFailure::new(
                    source,
                    ManagedQemuHotForkSourceWorldBindingError::ResourceMeasurement(error),
                ));
            }
        };
        let resources = match HotCheckpointResourceProfile::new(
            usage.template_bytes(),
            usage.expected_private_dirty_bytes(),
            usage.process_count(),
            usage.virtual_cpu_count(),
            usage.descriptor_count(),
            usage.overlay_count(),
        ) {
            Ok(resources) => resources,
            Err(error) => {
                return Err(ManagedQemuHotForkSourceWorldBindingFailure::new(
                    source,
                    ManagedQemuHotForkSourceWorldBindingError::InvalidResourceProfile(error),
                ));
            }
        };

        Ok(Self {
            key,
            resources,
            source: Some(source),
            leased_source: None,
            invalidated: false,
            #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
            parent_park: None,
        })
    }

    /// Returns the complete exact reuse key.
    #[must_use]
    pub const fn key(&self) -> &QemuHotForkSourceWorldKey {
        &self.key
    }

    /// Returns whether this source may be checked out immediately.
    #[must_use]
    pub fn available(&self) -> bool {
        self.source.is_some()
            && !self.invalidated
            && !self.parent_park_owned()
            && !self.fork_target_owned()
    }

    fn fork_target_owned(&self) -> bool {
        self.source
            .as_ref()
            .is_some_and(ProductionVmHotForkSourceWorld::fork_target_is_owned)
            || self.leased_source.as_ref().is_some_and(|source| {
                source.owner_ref().is_none_or(|source| {
                    source
                        .try_lock()
                        .map_or(true, |source| source.fork_target_is_owned())
                })
            })
    }

    fn parent_park_owned(&self) -> bool {
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        {
            self.parent_park
                .as_ref()
                .is_some_and(parent_park::ManagedParentParkSelection::is_owned)
        }
        #[cfg(not(all(target_os = "linux", feature = "private-measurement-domain")))]
        {
            false
        }
    }

    fn lease_available(&self) -> bool {
        (self.source.is_some() || self.leased_source.is_some())
            && !self.invalidated
            && !self.parent_park_owned()
            && !self.fork_target_owned()
    }

    fn begin_lease(&mut self) -> Option<Arc<Mutex<ProductionVmHotForkSourceWorld>>> {
        if self.invalidated || self.parent_park_owned() || self.fork_target_owned() {
            return None;
        }
        if let Some(source) = &self.leased_source {
            return source.owner_ref().map(Arc::clone);
        }

        let source = self.source.take()?;
        let shared = match SharedSourceOwnership::prepare(source) {
            Ok(shared) => shared,
            Err(source) => {
                self.source = Some(source);
                self.invalidated = true;
                return None;
            }
        };
        let alias = shared.owner_ref().map(Arc::clone);
        self.leased_source = Some(shared);
        alias
    }

    fn finish_leases(&mut self) {
        if self.invalidated || self.parent_park_owned() || self.fork_target_owned() {
            return;
        }
        let Some(source) = self.leased_source.take() else {
            return;
        };
        match source.into_unique() {
            Ok(source) => self.restore(source),
            Err(source) => {
                self.leased_source = Some(source);
                self.invalidated = true;
            }
        }
    }

    fn take(&mut self) -> Option<ProductionVmHotForkSourceWorld> {
        if self.invalidated
            || self.leased_source.is_some()
            || self.parent_park_owned()
            || self.fork_target_owned()
        {
            return None;
        }
        self.source.take()
    }

    fn restore(&mut self, mut source: ProductionVmHotForkSourceWorld) {
        if source.fork_target_is_owned() {
            // Keep the actual owner without restoring supervision or claiming
            // reusable Source while its physical Target remains retained.
            self.source = Some(source);
            return;
        }
        if self.parent_park_owned() {
            self.source = Some(source);
            return;
        }
        if source.restore_retained_service_supervisor().is_err() {
            self.invalidated = true;
            self.source = Some(source);
            return;
        }
        match source.into_reusable() {
            Ok(source) => self.source = Some(source),
            Err(failure) => {
                self.invalidated = true;
                drop(failure);
            }
        }
    }

    fn invalidate(&mut self) {
        if self.parent_park_owned() || self.fork_target_owned() {
            // Preserve the real pool record, complete source and occupied charge.
            self.invalidated = true;
            return;
        }
        self.invalidated = true;
        self.source = None;
        // Both actual native owners deliver through their original pair on
        // destruction. Borrowed aliases delay allocation/body closure in Main.
        drop(self.leased_source.take());
    }

    pub(crate) fn into_source(
        mut self,
    ) -> Result<ProductionVmHotForkSourceWorld, ManagedQemuHotForkSourceWorld> {
        match self.source.take() {
            Some(source) => Ok(source),
            None => Err(self),
        }
    }
}

/// Failed source-world key binding retaining the prepared source.
#[must_use = "recover or quarantine the returned source world"]
pub struct ManagedQemuHotForkSourceWorldBindingFailure {
    source: Box<ProductionVmHotForkSourceWorld>,
    error: Box<ManagedQemuHotForkSourceWorldBindingError>,
}

impl ManagedQemuHotForkSourceWorldBindingFailure {
    fn new(
        source: ProductionVmHotForkSourceWorld,
        error: ManagedQemuHotForkSourceWorldBindingError,
    ) -> Self {
        Self {
            source: Box::new(source),
            error: Box::new(error),
        }
    }

    /// Consumes the failure into the retained source and exact diagnostic.
    pub fn into_parts(
        self,
    ) -> (
        ProductionVmHotForkSourceWorld,
        ManagedQemuHotForkSourceWorldBindingError,
    ) {
        (*self.source, *self.error)
    }
}

impl std::fmt::Debug for ManagedQemuHotForkSourceWorldBindingFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ManagedQemuHotForkSourceWorldBindingFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ManagedQemuHotForkSourceWorldBindingFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl std::error::Error for ManagedQemuHotForkSourceWorldBindingFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

/// Exact reason a source world could not enter managed ownership.
#[derive(Debug, Error)]
pub enum ManagedQemuHotForkSourceWorldBindingError {
    /// The complete continuation is unavailable; the binding failure keeps its source.
    #[error("authenticate retained source continuation")]
    Continuation(#[source] crate::vm_lifecycle::ProductionVmHotForkContinuationUnavailable),
    /// Captured semantic content differs from the internally derived reuse key.
    #[error("source world scenario/configuration differs from its managed reuse key")]
    SourceKeyMismatch {
        /// Scenario required by the reuse key.
        expected_scenario: crucible::ContentHash,
        /// Scenario captured by the source.
        actual_scenario: crucible::ContentHash,
        /// Configuration required by the reuse key.
        expected_configuration: crucible::ContentHash,
        /// Configuration captured by the source.
        actual_configuration: crucible::ContentHash,
    },
    /// The source crossed a scheduler, event, or lifecycle frontier that its
    /// configuration identity does not represent.
    #[error("source world is not at the canonical genesis reuse boundary: {detail}")]
    NonCanonicalBoundary {
        /// Failed boundary predicate and its captured values.
        detail: String,
    },
    /// The source process incarnation or retained footprint could not be measured.
    #[error("measure complete retained source-world resources")]
    ResourceMeasurement(#[source] crucible_api::LifecycleApiError),
    /// Measured source resources do not describe a live retained world.
    #[error("construct measured source-world resource profile")]
    InvalidResourceProfile(#[source] crate::HotCheckpointResourceProfileError),
    /// The sealed token's exact checkpoint differs from its reuse-key boundary.
    #[error("exact source checkpoint differs from its authenticated reuse boundary")]
    ExactBoundaryCredentialMismatch,
}

/// Failed authenticated-source admission retaining the complete source authority.
#[must_use = "recover the rejected source and any durable cleanup obligation"]
pub enum ManagedQemuHotForkAuthenticatedAdmissionFailure<E> {
    /// Source binding, frontier validation, or resource measurement failed.
    Binding(ManagedQemuHotForkSourceWorldBindingFailure),
    /// Durable fallback or managed hot-retention admission failed.
    Admission(ManagedQemuHotForkSourceWorldAdmissionFailure<E>),
}

/// Source-free diagnostic after a rejected candidate enters quarantine.
#[derive(Debug, Error)]
pub enum ManagedQemuHotForkAuthenticatedAdmissionError<E> {
    /// Source binding, frontier validation, or resource measurement failed.
    #[error("bind authenticated source world")]
    Binding(#[source] ManagedQemuHotForkSourceWorldBindingError),
    /// Durable fallback or managed hot-retention admission failed.
    #[error("admit authenticated source world")]
    Admission {
        /// Durable fallback slot whose cleanup remains unresolved.
        cleanup_slot: Option<HotCheckpointFallbackSlot>,
        /// Exact managed-admission diagnostic.
        #[source]
        source: ManagedQemuHotForkSourceWorldAdmissionError<E>,
    },
}

impl<E: std::fmt::Debug> std::fmt::Debug for ManagedQemuHotForkAuthenticatedAdmissionFailure<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Binding(error) => formatter.debug_tuple("Binding").field(error).finish(),
            Self::Admission(error) => formatter.debug_tuple("Admission").field(error).finish(),
        }
    }
}

impl<E> std::fmt::Display for ManagedQemuHotForkAuthenticatedAdmissionFailure<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Binding(_) => formatter.write_str("bind authenticated source world"),
            Self::Admission(_) => formatter.write_str("admit authenticated source world"),
        }
    }
}

fn canonical_genesis_reuse_boundary_error(
    continuation: &crate::ProductionVmHotForkWorldContinuation,
) -> Option<String> {
    let event_log = continuation.event_log_offset();
    let scheduler = continuation.scheduler();
    if !continuation.configuration().schedule.is_empty()
        || scheduler.frontier().ticks != 0
        || scheduler.quanta() != 0
        || !is_canonical_genesis_event_log(event_log)
        || continuation.terminal_verdict().is_some()
        || !continuation.initial_lifecycle_observations_pending()
    {
        return Some(format!(
            "schedule_len={} frontier={} quanta={} event_log={event_log:?} terminal={} initial_observations_pending={}",
            continuation.configuration().schedule.len(),
            scheduler.frontier().ticks,
            scheduler.quanta(),
            continuation.terminal_verdict().is_some(),
            continuation.initial_lifecycle_observations_pending(),
        ));
    }

    for node in continuation.nodes() {
        let ready_point = scheduler.epoch_ready_point_counter_for_node(node.node());
        let physical_matches =
            match (node.physical_time(), ready_point) {
                (Some(physical), Some(counter)) => physical.ticks == counter.ticks,
                (None, Some(_)) => node.service_state()
                    == crate::vm_lifecycle::ProductionVmHotForkNodeServiceState::PermanentlyFailed,
                _ => false,
            };
        if node.scheduler_time().ticks != 0 || !physical_matches {
            return Some(format!(
                "node={} scheduler_time={} physical_time={:?} epoch_ready_point={ready_point:?} service_state={:?}",
                node.node().name,
                node.scheduler_time().ticks,
                node.physical_time(),
                node.service_state(),
            ));
        }
    }
    None
}

fn is_canonical_genesis_event_log(offset: crucible::EventLogOffset) -> bool {
    // Counts alone cannot authenticate an empty log: its prefix is part of the boundary.
    offset == crucible::EventLog::new().offset()
}

/// Reaps a complete source world after fallback reauthentication.
#[derive(Clone, Copy, Debug, Default)]
pub struct QemuHotForkSourceWorldDemoter;

impl HotCheckpointSourceDemoter<ManagedQemuHotForkSourceWorld> for QemuHotForkSourceWorldDemoter {
    type Error = QemuHotForkSourceWorldDemotionError;

    fn demote_source(
        &mut self,
        mut world: ManagedQemuHotForkSourceWorld,
        plan: HotCheckpointPlannedDemotion,
    ) -> Result<(), HotCheckpointTemplateDemotionFailure<ManagedQemuHotForkSourceWorld, Self::Error>>
    {
        let expected = plan.slot().template_key();
        let actual = manager_source_key(&world.key);
        if expected != actual {
            return Err(HotCheckpointTemplateDemotionFailure::new(
                world,
                QemuHotForkSourceWorldDemotionError::TemplateKeyMismatch { expected, actual },
            ));
        }
        let Some(mut source) = world.take() else {
            return Err(HotCheckpointTemplateDemotionFailure::new(
                world,
                QemuHotForkSourceWorldDemotionError::Unavailable,
            ));
        };
        if let Err(error) = source.retire() {
            if source.continuation().is_ok() {
                // Retirement moves this identity before starting cleanup. A
                // pre-effect refusal keeps the same owner available for retry,
                // even if the target loan clears just after that refusal.
                world.source = Some(source);
            } else {
                world.invalidated = true;
            }
            return Err(HotCheckpointTemplateDemotionFailure::new(
                world,
                QemuHotForkSourceWorldDemotionError::Retirement(error),
            ));
        }
        Ok(())
    }
}

/// Failure to attest complete source-world reap.
#[derive(Debug, Error)]
pub enum QemuHotForkSourceWorldDemotionError {
    /// The manager plan names another lineage/configuration coordinate.
    #[error("source-world demotion plan names another template key")]
    TemplateKeyMismatch {
        /// Key named by the manager plan.
        expected: HotCheckpointPoolKey,
        /// Key bound to the source world.
        actual: HotCheckpointPoolKey,
    },
    /// The source has already been checked out or invalidated.
    #[error("source world is unavailable for orderly demotion")]
    Unavailable,
    /// Production lifecycle retirement could not attest complete cleanup.
    #[error("retire production source world: {0}")]
    Retirement(#[source] crucible_api::LifecycleApiError),
}

/// One non-cloneable checkout of a retained source shared by concurrent children.
#[must_use = "return the source lease after complete child reconciliation or abandon it"]
pub struct QemuHotForkSourceWorldLease {
    managed_lease: Option<u64>,
    template: HotCheckpointPoolKey,
    identity: QemuHotForkSourceWorldCheckoutIdentity,
    source: LeaseSource,
}

impl QemuHotForkSourceWorldLease {
    pub(crate) fn exclusive(
        template: HotCheckpointPoolKey,
        source: ProductionVmHotForkSourceWorld,
        identity: QemuHotForkSourceWorldCheckoutIdentity,
    ) -> Result<Self, ProductionVmHotForkSourceWorld> {
        Ok(Self {
            managed_lease: None,
            template,
            identity,
            source: LeaseSource::Exclusive(SharedSourceOwnership::prepare(source)?),
        })
    }

    pub(crate) fn source_owner_ref(&self) -> Option<&Arc<Mutex<ProductionVmHotForkSourceWorld>>> {
        self.source.owner_ref()
    }

    pub(crate) fn source_owner(&self) -> Option<Arc<Mutex<ProductionVmHotForkSourceWorld>>> {
        self.source_owner_ref().map(Arc::clone)
    }

    pub(crate) fn identity(&self) -> &QemuHotForkSourceWorldCheckoutIdentity {
        &self.identity
    }

    pub(crate) fn reauthenticates_source(&self) -> bool {
        self.source_owner_ref().is_some_and(|source| {
            source.try_lock().is_ok_and(|mut source| {
                !source.fork_target_is_owned()
                    && self.identity.matches(&source)
                    && source.restore_retained_service_supervisor().is_ok()
                    && source.fork_continuation().is_ok()
            })
        })
    }

    pub(crate) fn into_exclusive_source(mut self) -> Result<ProductionVmHotForkSourceWorld, Self> {
        if self.managed_lease.is_some() {
            return Err(self);
        }
        let LeaseSource::Exclusive(source) = &mut self.source else {
            return Err(self);
        };
        // Validate identity while the SAME allocation is exclusively borrowed;
        // neither a weak alias nor poison can pass before supervisor metadata.
        let valid = source
            .with_unique(|source| {
                self.identity.matches(source)
                    && !source.fork_target_is_owned()
                    && source.restore_retained_service_supervisor().is_ok()
            })
            .unwrap_or(false);
        if !valid {
            return Err(self);
        }
        let Self {
            managed_lease,
            template,
            identity,
            source,
        } = self;
        match source {
            LeaseSource::Exclusive(source) => source.into_unique().map_err(|source| Self {
                managed_lease,
                template,
                identity,
                source: LeaseSource::Exclusive(source),
            }),
            source @ LeaseSource::Borrowed(_) => Err(Self {
                managed_lease,
                template,
                identity,
                source,
            }),
        }
    }
}

impl std::fmt::Debug for QemuHotForkSourceWorldLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkSourceWorldLease")
            .field("managed_lease", &self.managed_lease)
            .field("template", &self.template)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

struct ManagedQemuHotForkSourceWorldLeaseRecord {
    lease: u64,
    template: HotCheckpointPoolKey,
    identity: QemuHotForkSourceWorldCheckoutIdentity,
    source: Weak<Mutex<ProductionVmHotForkSourceWorld>>,
    resources: HotCheckpointResourceProfile,
    _permit: crate::HotCheckpointForkPermit,
    returned_lease: Option<QemuHotForkSourceWorldLease>,
    abandoned: bool,
}

/// Durable, resource-accounted provider for complete source worlds.
pub struct ManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    manager: HotCheckpointManager,
    worlds: BTreeMap<HotCheckpointPoolKey, ManagedQemuHotForkSourceWorld>,
    demotions: D,
    retention: R,
    records: BTreeMap<HotCheckpointFallbackSlot, HotCheckpointFallbackRecord>,
    active: BTreeMap<HotCheckpointPoolKey, HotCheckpointFallbackSlot>,
    checked_out: BTreeMap<
        u64,
        (
            HotCheckpointPoolKey,
            QemuHotForkSourceWorldCheckoutIdentity,
            crate::HotCheckpointForkPermit,
        ),
    >,
    leased_out: BTreeMap<u64, ManagedQemuHotForkSourceWorldLeaseRecord>,
    lease_usage: HotCheckpointUsage,
    next_lease: u64,
    fork_rate_clock: ForkRateClock,
}

mod pool;

/// Shared process-wide source pool that mints one checkout session per worker.
pub struct SharedManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    pool: Arc<Mutex<ManagedQemuHotForkSourceWorldPool<D, R>>>,
    next_provider: Arc<AtomicU64>,
}

impl<D, R> Clone for SharedManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    fn clone(&self) -> Self {
        Self {
            pool: Arc::clone(&self.pool),
            next_provider: Arc::clone(&self.next_provider),
        }
    }
}

impl<D, R> SharedManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    /// Creates shared ownership around one completely initialized pool.
    #[must_use]
    pub fn new(pool: ManagedQemuHotForkSourceWorldPool<D, R>) -> Self {
        Self {
            pool: Arc::new(Mutex::new(pool)),
            next_provider: Arc::new(AtomicU64::new(1)),
        }
    }

    /// Mints an independent checkout session for one execution worker.
    ///
    /// # Errors
    ///
    /// Returns [`SharedQemuHotForkSourceWorldProviderConstructionError`] after
    /// exhausting the nonzero provider identity space.
    pub fn provider(
        &self,
    ) -> Result<
        SharedQemuHotForkSourceWorldProvider<D, R>,
        SharedQemuHotForkSourceWorldProviderConstructionError,
    > {
        let provider = self
            .next_provider
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                SharedQemuHotForkSourceWorldProviderConstructionError::IdentityExhausted
            })?;
        Ok(SharedQemuHotForkSourceWorldProvider {
            pool: Arc::clone(&self.pool),
            provider,
        })
    }

    pub(crate) fn admit_authenticated_exact_source(
        &self,
        source: AuthenticatedExactQemuHotForkSource,
        signals: HotCheckpointHotnessSignals,
    ) -> Result<HotCheckpointAdmissionCommit, SharedManagedQemuHotForkExactAdmissionFailure<D::Error>>
    {
        let mut pool = match self.pool.lock() {
            Ok(pool) => pool,
            Err(_error) => {
                let _retained_for_process_lifetime = Box::leak(Box::new(source));
                return Err(SharedManagedQemuHotForkExactAdmissionFailure::Poisoned);
            }
        };
        pool.admit_authenticated_exact_source(source, signals)
            .map_err(SharedManagedQemuHotForkExactAdmissionFailure::Admission)
    }

    pub(crate) fn retain_cold_fallback(
        &self,
        key: HotCheckpointPoolKey,
        fallback: HotCheckpointFallback,
    ) -> Result<HotCheckpointFallbackSlot, SharedManagedQemuHotForkColdRetentionError<D::Error>>
    {
        self.pool
            .lock()
            .map_err(|_error| SharedManagedQemuHotForkColdRetentionError::Poisoned)?
            .retain_cold_fallback(key, fallback)
            .map_err(SharedManagedQemuHotForkColdRetentionError::Retention)
    }

    /// Demotes and reaps every retained source through the shared owner.
    ///
    /// # Errors
    ///
    /// Returns [`SharedManagedQemuHotForkSourceWorldShutdownError`] when the
    /// pool lock is poisoned or any retained source cannot be reaped.
    pub fn orderly_shutdown(
        &self,
    ) -> Result<
        Vec<HotCheckpointDemotion>,
        SharedManagedQemuHotForkSourceWorldShutdownError<D::Error>,
    >
    where
        D::Error: std::fmt::Debug,
    {
        self.pool
            .lock()
            .map_err(|_error| SharedManagedQemuHotForkSourceWorldShutdownError::Poisoned)?
            .orderly_shutdown()
            .map_err(Into::into)
    }
}

pub(crate) enum SharedManagedQemuHotForkExactAdmissionFailure<E> {
    Poisoned,
    Admission(ManagedQemuHotForkAuthenticatedAdmissionFailure<E>),
}

#[derive(Debug, Error)]
pub(crate) enum SharedManagedQemuHotForkColdRetentionError<E> {
    #[error("shared source-world pool lock is poisoned")]
    Poisoned,
    #[error("retain demanded exact source fallback")]
    Retention(#[source] Box<ManagedQemuHotForkSourceWorldAdmissionError<E>>),
}

/// One worker's independent session over the shared managed source pool.
pub struct SharedQemuHotForkSourceWorldProvider<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    pool: Arc<Mutex<ManagedQemuHotForkSourceWorldPool<D, R>>>,
    provider: u64,
}

/// Failure while minting a shared source-provider session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum SharedQemuHotForkSourceWorldProviderConstructionError {
    /// The process exhausted every nonzero provider identity.
    #[error("shared source-world provider identity space is exhausted")]
    IdentityExhausted,
}

/// Failure while checking out a source through a shared provider.
#[derive(Debug, Error)]
pub enum SharedQemuHotForkSourceWorldProviderError {
    /// A prior operation panicked while holding the process-wide pool lock.
    #[error("shared source-world pool lock is poisoned")]
    Poisoned,
    /// The managed pool rejected this provider's checkout.
    #[error(transparent)]
    Checkout(#[from] ManagedQemuHotForkSourceWorldCheckoutError),
}

impl<D, R> crate::qemu_hot_fork_world_factory::source_world_provider_sealed::Sealed
    for SharedQemuHotForkSourceWorldProvider<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
}

impl<D, R> QemuHotForkSourceWorldProvider for SharedQemuHotForkSourceWorldProvider<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld> + Send,
    D::Error: Send + Sync + 'static,
    R: HotCheckpointFallbackRetentionStore + Send,
{
    type Error = SharedQemuHotForkSourceWorldProviderError;

    fn checkout(
        &mut self,
        key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<QemuHotForkSourceWorldLease>, Self::Error> {
        self.pool
            .lock()
            .map_err(|_error| SharedQemuHotForkSourceWorldProviderError::Poisoned)?
            .checkout_lease_for(self.provider, key)
            .map_err(Into::into)
    }

    fn restore(&mut self, source: QemuHotForkSourceWorldLease) {
        match self.pool.lock() {
            Ok(mut pool) => pool.restore_lease_for(self.provider, source),
            Err(_error) => {
                drop(source);
            }
        }
    }

    fn abandon(&mut self) {
        if let Ok(mut pool) = self.pool.lock() {
            pool.abandon_lease_for(self.provider);
        }
    }
}

#[cfg(test)]
#[path = "managed_qemu_hot_fork_source_world_pool/tests.rs"]
mod tests;

fn source_slot(key: HotCheckpointPoolKey) -> HotCheckpointPoolSlot {
    HotCheckpointPoolSlot::new(key, 0)
}

fn manager_source_key(key: &QemuHotForkSourceWorldKey) -> HotCheckpointPoolKey {
    match key.boundary() {
        crate::QemuHotForkSourceWorldBoundary::CanonicalGenesis => key.template_key(),
        crate::QemuHotForkSourceWorldBoundary::ExactCheckpoint(checkpoint) => {
            let material = format!(
                "configuration={}\ncheckpoint={}",
                key.configuration().to_hex(),
                checkpoint.to_text(),
            );
            HotCheckpointPoolKey::new(
                key.template_key().lineage(),
                crucible::ContentHash::from_canonical_material(
                    "crucible.qemu-hot-fork.operational-source.v1",
                    &material,
                ),
            )
        }
    }
}

fn inventory_records<R>(
    retention: &R,
) -> Result<
    BTreeMap<HotCheckpointFallbackSlot, HotCheckpointFallbackRecord>,
    HotCheckpointFallbackRetentionError,
>
where
    R: HotCheckpointFallbackRetentionStore,
{
    let mut records = BTreeMap::new();
    let mut fence = retention.acquire_hot_checkpoint_retention_fence()?;
    let summary = fence.visit_fallbacks(&mut |slot, record| {
        if records.insert(slot, record).is_some() {
            return Err(HotCheckpointFallbackRetentionError::Visitor);
        }
        Ok(())
    })?;
    if summary.roots() != u64::try_from(records.len()).unwrap_or(u64::MAX) {
        return Err(HotCheckpointFallbackRetentionError::Visitor);
    }
    Ok(records)
}
