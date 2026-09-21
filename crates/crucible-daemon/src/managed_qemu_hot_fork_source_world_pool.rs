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

use crucible_api::vm_lifecycle::ProductionVmHotForkSourceWorld;
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
    leased_source: Option<Arc<Mutex<ProductionVmHotForkSourceWorld>>>,
    invalidated: bool,
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
        let actual_scenario = source.continuation().configuration().def.id();
        let actual_configuration = source.continuation().configuration().id();
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
        if require_canonical_genesis && !is_canonical_genesis_reuse_boundary(&source) {
            return Err(ManagedQemuHotForkSourceWorldBindingFailure::new(
                source,
                ManagedQemuHotForkSourceWorldBindingError::NonCanonicalBoundary,
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
        })
    }

    /// Returns the complete exact reuse key.
    #[must_use]
    pub const fn key(&self) -> &QemuHotForkSourceWorldKey {
        &self.key
    }

    /// Returns whether this source may be checked out immediately.
    #[must_use]
    pub const fn available(&self) -> bool {
        self.source.is_some() && !self.invalidated
    }

    fn lease_available(&self) -> bool {
        (self.source.is_some() || self.leased_source.is_some()) && !self.invalidated
    }

    fn begin_lease(&mut self) -> Option<Arc<Mutex<ProductionVmHotForkSourceWorld>>> {
        if self.invalidated {
            return None;
        }
        if let Some(source) = &self.leased_source {
            return Some(Arc::clone(source));
        }

        let source = Arc::new(Mutex::new(self.source.take()?));
        self.leased_source = Some(Arc::clone(&source));
        Some(source)
    }

    fn finish_leases(&mut self) {
        if self.invalidated {
            return;
        }
        let Some(source) = self.leased_source.take() else {
            return;
        };
        let source = match Arc::try_unwrap(source) {
            Ok(source) => source,
            Err(source) => {
                self.leased_source = Some(source);
                self.invalidate();
                return;
            }
        };
        let source = match source.into_inner() {
            Ok(source) => source,
            Err(poisoned) => {
                let source = Arc::new(Mutex::new(poisoned.into_inner()));
                self.leased_source = Some(source);
                self.invalidate();
                return;
            }
        };

        self.restore(source);
    }

    fn take(&mut self) -> Option<ProductionVmHotForkSourceWorld> {
        if self.invalidated || self.leased_source.is_some() {
            return None;
        }
        self.source.take()
    }

    fn restore(&mut self, source: ProductionVmHotForkSourceWorld) {
        match source.into_reusable() {
            Ok(source) => self.source = Some(source),
            Err(failure) => {
                self.invalidated = true;
                let _retained_for_process_lifetime = Box::leak(Box::new(failure));
            }
        }
    }

    fn invalidate(&mut self) {
        self.invalidated = true;
        self.source = None;
        if let Some(source) = self.leased_source.take() {
            let _retained_for_process_lifetime = Box::leak(Box::new(source));
        }
    }

    pub(crate) fn into_source(
        mut self,
    ) -> Result<ProductionVmHotForkSourceWorld, Box<ManagedQemuHotForkSourceWorld>> {
        match self.source.take() {
            Some(source) => Ok(source),
            None => Err(Box::new(self)),
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
    #[error("source world is not at the canonical genesis reuse boundary")]
    NonCanonicalBoundary,
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

fn is_canonical_genesis_reuse_boundary(source: &ProductionVmHotForkSourceWorld) -> bool {
    let continuation = source.continuation();
    let event_log = continuation.event_log_offset();

    continuation.configuration().schedule.is_empty()
        && continuation.scheduler().frontier().ticks == 0
        && event_log.bytes == 0
        && event_log.events == 0
        && event_log.appended_segment.is_none()
        && continuation.terminal_verdict().is_none()
        && continuation.initial_lifecycle_observations_pending()
        && continuation.nodes().iter().all(|node| {
            node.scheduler_time().ticks == 0
                && node.physical_time().is_none_or(|time| time.ticks == 0)
        })
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
        let Some(source) = world.take() else {
            return Err(HotCheckpointTemplateDemotionFailure::new(
                world,
                QemuHotForkSourceWorldDemotionError::Unavailable,
            ));
        };
        if let Err(source) = source.retire() {
            world.invalidated = true;
            return Err(HotCheckpointTemplateDemotionFailure::new(
                world,
                QemuHotForkSourceWorldDemotionError::Retirement(source),
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
    source: Arc<Mutex<ProductionVmHotForkSourceWorld>>,
}

impl QemuHotForkSourceWorldLease {
    pub(crate) fn exclusive(
        template: HotCheckpointPoolKey,
        source: ProductionVmHotForkSourceWorld,
    ) -> Self {
        let identity = QemuHotForkSourceWorldCheckoutIdentity::capture(&source);
        Self {
            managed_lease: None,
            template,
            identity,
            source: Arc::new(Mutex::new(source)),
        }
    }

    pub(crate) fn source_owner(&self) -> Arc<Mutex<ProductionVmHotForkSourceWorld>> {
        Arc::clone(&self.source)
    }

    pub(crate) fn identity(&self) -> &QemuHotForkSourceWorldCheckoutIdentity {
        &self.identity
    }

    pub(crate) fn reauthenticates_source(&self) -> bool {
        self.source.lock().is_ok_and(|mut source| {
            self.identity.matches(&source) && source.fork_continuation().is_ok()
        })
    }

    pub(crate) fn into_exclusive_source(self) -> Result<ProductionVmHotForkSourceWorld, Box<Self>> {
        if self.managed_lease.is_some() {
            return Err(Box::new(self));
        }
        let Self {
            managed_lease,
            template,
            identity,
            source,
        } = self;
        let source = match Arc::try_unwrap(source) {
            Ok(source) => source,
            Err(source) => {
                return Err(Box::new(Self {
                    managed_lease,
                    template,
                    identity,
                    source,
                }));
            }
        };
        match source.into_inner() {
            Ok(source) if identity.matches(&source) => Ok(source),
            Ok(source) => Err(Box::new(Self {
                managed_lease,
                template,
                identity,
                source: Arc::new(Mutex::new(source)),
            })),
            Err(poisoned) => Err(Box::new(Self {
                managed_lease,
                template,
                identity,
                source: Arc::new(Mutex::new(poisoned.into_inner())),
            })),
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
                let _retained_for_process_lifetime = Box::leak(Box::new(source.source));
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
