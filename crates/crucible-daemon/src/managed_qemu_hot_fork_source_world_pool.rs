//! Durable managed ownership for complete retained QEMU source worlds.
//!
//! This pool applies the shared [`HotCheckpointManager`] policy to atomic
//! multi-node source worlds. It currently admits only the canonical genesis
//! frontier, permits one source per lineage/configuration coordinate,
//! exact-matches the scenario and executor compatibility profile, persists an
//! exact/thin fallback before admission, charges conservatively measured QEMU
//! process resources, and retains cold fallback records for campaign GC after
//! orderly source reap. Later replay frontiers require an explicit semantic
//! boundary identity before they may enter this owner.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crucible_api::vm_lifecycle::ProductionVmHotForkSourceWorld;
use thiserror::Error;

use crate::qemu_hot_fork_source_capture::AuthenticatedCanonicalQemuHotForkSource;
use crate::qemu_hot_fork_world_factory::QemuHotForkSourceWorldCheckoutIdentity;
use crate::supervision::ForkRateClock;
use crate::{
    DurableHotCheckpointCatalogError, HotCheckpointAdmissionCommit, HotCheckpointCandidate,
    HotCheckpointDemotion, HotCheckpointDemotionReason, HotCheckpointFallback,
    HotCheckpointFallbackRecord, HotCheckpointFallbackRetentionAdmin,
    HotCheckpointFallbackRetentionCas, HotCheckpointFallbackRetentionError,
    HotCheckpointFallbackRetentionStore, HotCheckpointFallbackSlot, HotCheckpointHotnessSignals,
    HotCheckpointInventoryError, HotCheckpointLimits, HotCheckpointManager,
    HotCheckpointPlannedDemotion, HotCheckpointResourceProfile, HotCheckpointSourceDemoter,
    HotCheckpointStatus, HotCheckpointTemplateDemotionFailure, HotCheckpointTemplateDemotionSink,
    MAX_HOT_CHECKPOINT_FALLBACK_ROOTS, QemuHotForkSourceWorldKey, QemuHotForkSourceWorldProvider,
    QemuHotForkTemplateKey, QemuHotForkTemplatePoolSlot,
};

mod errors;

pub use errors::{
    ManagedQemuHotForkSourceWorldAdmissionError, ManagedQemuHotForkSourceWorldAdmissionFailure,
    ManagedQemuHotForkSourceWorldCheckoutError, ManagedQemuHotForkSourceWorldDemotionError,
    ManagedQemuHotForkSourceWorldPoolConstructionError, ManagedQemuHotForkSourceWorldReleaseError,
    ManagedQemuHotForkSourceWorldShutdownError, SharedManagedQemuHotForkSourceWorldShutdownError,
};

/// One full-key-bound source world owned by the managed pool.
#[must_use = "admit, demote, or retain the complete source-world authority"]
pub struct ManagedQemuHotForkSourceWorld {
    key: QemuHotForkSourceWorldKey,
    resources: HotCheckpointResourceProfile,
    source: Option<ProductionVmHotForkSourceWorld>,
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
        mut source: ProductionVmHotForkSourceWorld,
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
        if !is_canonical_genesis_reuse_boundary(&source) {
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

    fn take(&mut self) -> Option<ProductionVmHotForkSourceWorld> {
        if self.invalidated {
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

    /// Returns the unchanged source world.
    pub fn into_source(self) -> ProductionVmHotForkSourceWorld {
        *self.source
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
    #[error("bind canonical genesis source world")]
    Binding(#[source] ManagedQemuHotForkSourceWorldBindingError),
    /// Durable fallback or managed hot-retention admission failed.
    #[error("admit canonical genesis source world")]
    Admission {
        /// Durable fallback slot whose cleanup remains unresolved.
        cleanup_slot: Option<HotCheckpointFallbackSlot>,
        /// Exact managed-admission diagnostic.
        #[source]
        source: ManagedQemuHotForkSourceWorldAdmissionError<E>,
    },
}

impl<E: 'static> ManagedQemuHotForkAuthenticatedAdmissionFailure<E> {
    /// Transfers the retained source to process-lifetime quarantine and returns its diagnostic.
    #[must_use]
    pub fn quarantine(self) -> ManagedQemuHotForkAuthenticatedAdmissionError<E> {
        match self {
            Self::Binding(failure) => {
                let (source, error) = failure.into_parts();
                let _retained_for_process_lifetime = Box::leak(Box::new(source));
                ManagedQemuHotForkAuthenticatedAdmissionError::Binding(error)
            }
            Self::Admission(failure) => {
                let (candidate, cleanup_slot, source) = failure.into_parts();
                let _retained_for_process_lifetime = Box::leak(Box::new(candidate));
                ManagedQemuHotForkAuthenticatedAdmissionError::Admission {
                    cleanup_slot,
                    source,
                }
            }
        }
    }
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
            Self::Binding(_) => formatter.write_str("bind canonical genesis source world"),
            Self::Admission(_) => formatter.write_str("admit canonical genesis source world"),
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
        let actual = world.key.template_key();
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
        expected: QemuHotForkTemplateKey,
        /// Key bound to the source world.
        actual: QemuHotForkTemplateKey,
    },
    /// The source has already been checked out or invalidated.
    #[error("source world is unavailable for orderly demotion")]
    Unavailable,
    /// Production lifecycle retirement could not attest complete cleanup.
    #[error("retire production source world: {0}")]
    Retirement(#[source] crucible_api::LifecycleApiError),
}

/// Durable, resource-accounted provider for complete source worlds.
pub struct ManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    manager: HotCheckpointManager,
    worlds: BTreeMap<QemuHotForkTemplateKey, ManagedQemuHotForkSourceWorld>,
    demotions: D,
    retention: R,
    records: BTreeMap<HotCheckpointFallbackSlot, HotCheckpointFallbackRecord>,
    active: BTreeMap<QemuHotForkTemplateKey, HotCheckpointFallbackSlot>,
    checked_out: BTreeMap<
        u64,
        (
            QemuHotForkTemplateKey,
            QemuHotForkSourceWorldCheckoutIdentity,
            crate::HotCheckpointForkPermit,
        ),
    >,
    fork_rate_clock: ForkRateClock,
}

impl<D, R> ManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    /// Opens an empty live-source pool over one authenticated durable catalog.
    ///
    /// Existing records are cold fallback roots. Live source processes are
    /// never inferred from durable operational records after restart.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedQemuHotForkSourceWorldPoolConstructionError`] when the
    /// complete durable fallback inventory cannot be authenticated.
    pub fn open(
        limits: HotCheckpointLimits,
        demotions: D,
        retention: R,
    ) -> Result<Self, ManagedQemuHotForkSourceWorldPoolConstructionError> {
        let records = inventory_records(&retention)
            .map_err(ManagedQemuHotForkSourceWorldPoolConstructionError::Catalog)?;
        Ok(Self {
            manager: HotCheckpointManager::new(limits),
            worlds: BTreeMap::new(),
            demotions,
            retention,
            records,
            active: BTreeMap::new(),
            checked_out: BTreeMap::new(),
            fork_rate_clock: ForkRateClock::new(),
        })
    }

    /// Returns the shared hot-checkpoint manager view.
    #[must_use]
    pub const fn manager(&self) -> &HotCheckpointManager {
        &self.manager
    }

    /// Returns the durable fallback-root inventory used by campaign GC.
    #[must_use]
    pub fn retention_admin(&self) -> &dyn HotCheckpointFallbackRetentionAdmin {
        &self.retention
    }

    /// Returns whether an exact complete key has one immediately reusable source.
    #[must_use]
    pub fn source_available(&self, key: &QemuHotForkSourceWorldKey) -> bool {
        self.worlds
            .get(&key.template_key())
            .is_some_and(|world| world.key() == key && world.available())
    }

    /// Iterates every cold exact/thin fallback retained for restart and GC.
    pub fn cold_fallbacks(
        &self,
    ) -> impl Iterator<Item = (HotCheckpointFallbackSlot, HotCheckpointFallbackRecord)> + '_ {
        self.records
            .iter()
            .filter(|(slot, _record)| !self.active.values().any(|active| active == *slot))
            .map(|(&slot, &record)| (slot, record))
    }

    /// Admits a factory-authenticated canonical source after measuring it.
    ///
    /// The source carries a sealed key minted by its validated preparation
    /// factory. Admission rechecks the canonical initial frontier, measures
    /// resource use internally, and does not accept caller-supplied accounting
    /// or compatibility identities.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedQemuHotForkAuthenticatedAdmissionFailure`] retaining
    /// the complete source authority when lineage binding, boundary validation,
    /// measurement, fallback persistence, or managed admission fails.
    pub fn admit_authenticated_source(
        &mut self,
        authenticated: AuthenticatedCanonicalQemuHotForkSource,
        signals: HotCheckpointHotnessSignals,
        fallback: HotCheckpointFallback,
    ) -> Result<
        HotCheckpointAdmissionCommit,
        ManagedQemuHotForkAuthenticatedAdmissionFailure<D::Error>,
    > {
        let (key, source) = authenticated.into_parts();
        let world = ManagedQemuHotForkSourceWorld::bind(key, source)
            .map_err(ManagedQemuHotForkAuthenticatedAdmissionFailure::Binding)?;

        self.admit_source(world, signals, fallback)
            .map_err(ManagedQemuHotForkAuthenticatedAdmissionFailure::Admission)
    }

    /// Updates one source's operational hotness and pin signals.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointInventoryError`] when the source is absent or the
    /// manager generation cannot advance.
    pub fn update_signals(
        &mut self,
        key: QemuHotForkTemplateKey,
        signals: HotCheckpointHotnessSignals,
    ) -> Result<HotCheckpointStatus, HotCheckpointInventoryError> {
        self.manager.update_signals(source_slot(key), signals)
    }

    /// Admits one complete source after durably retaining its exact fallback.
    ///
    /// Colder victims are reauthenticated and reaped before the new source is
    /// installed. Exactly one source is permitted for each lineage/source
    /// configuration coordinate, regardless of executor profile.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedQemuHotForkSourceWorldAdmissionFailure`] with the
    /// candidate when admission, fallback persistence, victim retirement, or
    /// manager commit fails.
    pub(crate) fn admit_source(
        &mut self,
        world: ManagedQemuHotForkSourceWorld,
        signals: HotCheckpointHotnessSignals,
        fallback: HotCheckpointFallback,
    ) -> Result<HotCheckpointAdmissionCommit, ManagedQemuHotForkSourceWorldAdmissionFailure<D::Error>>
    {
        let key = world.key.template_key();
        let candidate = HotCheckpointCandidate::new(key, world.resources, signals, fallback);
        if self.worlds.contains_key(&key) {
            return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                world,
                None,
                ManagedQemuHotForkSourceWorldAdmissionError::DuplicateSource,
            ));
        }
        let plan = match self.manager.plan_admission(candidate) {
            Ok(plan) => plan,
            Err(source) => {
                return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                    world,
                    None,
                    ManagedQemuHotForkSourceWorldAdmissionError::Rejected(source),
                ));
            }
        };
        if let Err(source) = self.demotions.validate_fallback(key, candidate.fallback()) {
            return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                world,
                None,
                ManagedQemuHotForkSourceWorldAdmissionError::Fallback(source),
            ));
        }
        for victim in plan.demotions() {
            let victim_key = victim.slot().template_key();
            if let Err(source) = self
                .demotions
                .validate_fallback(victim_key, victim.fallback())
            {
                return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                    world,
                    None,
                    ManagedQemuHotForkSourceWorldAdmissionError::Fallback(source),
                ));
            }
            let Some(catalog_slot) = self.active.get(&victim_key).copied() else {
                return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                    world,
                    None,
                    ManagedQemuHotForkSourceWorldAdmissionError::VictimUnavailable {
                        reconciliation: Ok(Vec::new()),
                    },
                ));
            };
            if let Err(source) =
                self.require_fallback_record(catalog_slot, victim_key, victim.fallback())
            {
                return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                    world,
                    None,
                    ManagedQemuHotForkSourceWorldAdmissionError::VictimCatalog {
                        source,
                        reconciliation: Ok(Vec::new()),
                    },
                ));
            }
            if !self
                .worlds
                .get(&victim_key)
                .is_some_and(ManagedQemuHotForkSourceWorld::available)
            {
                return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                    world,
                    None,
                    ManagedQemuHotForkSourceWorldAdmissionError::VictimUnavailable {
                        reconciliation: Ok(Vec::new()),
                    },
                ));
            }
        }

        let record = HotCheckpointFallbackRecord::new(key, candidate.fallback());
        let catalog_slot = match self.reserve_fallback(record) {
            Ok(slot) => slot,
            Err(source) => {
                return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                    world, None, *source,
                ));
            }
        };

        let mut completed = Vec::with_capacity(plan.demotions().len());
        for victim in plan.demotions().iter().copied() {
            let victim_key = victim.slot().template_key();
            let Some(retired) = self.worlds.remove(&victim_key) else {
                let reconciliation = self.manager.commit_completed_demotions(&completed);
                let cleanup = self.remove_exact_fallback(catalog_slot, record).err();
                return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                    world,
                    cleanup.map(|_| catalog_slot),
                    ManagedQemuHotForkSourceWorldAdmissionError::VictimUnavailable {
                        reconciliation,
                    },
                ));
            };
            if let Err(failure) = self.demotions.demote(retired, victim) {
                let (retired, source) = failure.into_parts();
                self.worlds.insert(victim_key, retired);
                let reconciliation = self.manager.commit_completed_demotions(&completed);
                let cleanup = self.remove_exact_fallback(catalog_slot, record).err();
                return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                    world,
                    cleanup.map(|_| catalog_slot),
                    ManagedQemuHotForkSourceWorldAdmissionError::Demotion {
                        source,
                        reconciliation,
                    },
                ));
            }
            self.active.remove(&victim_key);
            completed.push(victim);
        }

        match self.manager.commit_admission(plan, source_slot(key)) {
            Ok(commit) => {
                self.worlds.insert(key, world);
                self.active.insert(key, catalog_slot);
                Ok(commit)
            }
            Err(source) => {
                let reconciliation = self.manager.commit_completed_demotions(&completed);
                let cleanup = self.remove_exact_fallback(catalog_slot, record).err();
                Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                    world,
                    cleanup.map(|_| catalog_slot),
                    ManagedQemuHotForkSourceWorldAdmissionError::ManagerCommit {
                        source,
                        reconciliation,
                    },
                ))
            }
        }
    }

    /// Demotes one idle source while retaining its fallback as a cold GC root.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedQemuHotForkSourceWorldDemotionError`] when the exact
    /// source or durable record is absent, busy, invalidated, or cannot be
    /// reauthenticated and reaped.
    pub fn demote_source(
        &mut self,
        key: QemuHotForkTemplateKey,
        reason: HotCheckpointDemotionReason,
    ) -> Result<HotCheckpointDemotion, ManagedQemuHotForkSourceWorldDemotionError<D::Error>> {
        let slot = source_slot(key);
        let status = self
            .manager
            .status(slot)
            .ok_or(ManagedQemuHotForkSourceWorldDemotionError::Missing)?;
        let catalog_slot = self
            .active
            .get(&key)
            .copied()
            .ok_or(ManagedQemuHotForkSourceWorldDemotionError::Missing)?;
        self.require_fallback_record(catalog_slot, key, status.fallback())
            .map_err(ManagedQemuHotForkSourceWorldDemotionError::Catalog)?;
        let plan = self
            .manager
            .plan_orderly_demotion(slot, reason)
            .map_err(ManagedQemuHotForkSourceWorldDemotionError::Manager)?;
        self.demotions
            .validate_fallback(key, status.fallback())
            .map_err(ManagedQemuHotForkSourceWorldDemotionError::Fallback)?;
        let world = self
            .worlds
            .remove(&key)
            .ok_or(ManagedQemuHotForkSourceWorldDemotionError::Missing)?;
        if !world.available() {
            self.worlds.insert(key, world);
            return Err(ManagedQemuHotForkSourceWorldDemotionError::Unavailable);
        }
        if let Err(failure) = self
            .demotions
            .demote(world, HotCheckpointPlannedDemotion::new(status, reason))
        {
            let (world, source) = failure.into_parts();
            self.worlds.insert(key, world);
            return Err(ManagedQemuHotForkSourceWorldDemotionError::Demotion(source));
        }
        let demotion = self
            .manager
            .commit_orderly_demotion(plan)
            .map_err(ManagedQemuHotForkSourceWorldDemotionError::Manager)?;
        self.active.remove(&key);
        Ok(demotion)
    }

    /// Removes one cold exact/thin root from the durable GC inventory.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedQemuHotForkSourceWorldReleaseError`] when the record is
    /// live, missing, changed concurrently, or cannot be durably removed.
    pub fn release_cold_fallback(
        &mut self,
        slot: HotCheckpointFallbackSlot,
    ) -> Result<HotCheckpointFallbackRecord, ManagedQemuHotForkSourceWorldReleaseError> {
        if self.active.values().any(|active| *active == slot) {
            return Err(ManagedQemuHotForkSourceWorldReleaseError::Active);
        }
        let record = self
            .records
            .get(&slot)
            .copied()
            .ok_or(ManagedQemuHotForkSourceWorldReleaseError::Missing)?;
        self.remove_exact_fallback(slot, record)
            .map_err(ManagedQemuHotForkSourceWorldReleaseError::Catalog)?;
        Ok(record)
    }

    /// Retains an authenticated fallback for a source declined by hot policy.
    ///
    /// The returned slot is cold: it is never entered in the active source
    /// inventory and therefore remains only a campaign-GC root.
    pub(crate) fn retain_cold_fallback(
        &mut self,
        key: QemuHotForkTemplateKey,
        fallback: HotCheckpointFallback,
    ) -> Result<HotCheckpointFallbackSlot, Box<ManagedQemuHotForkSourceWorldAdmissionError<D::Error>>>
    {
        self.demotions
            .validate_fallback(key, fallback)
            .map_err(|source| {
                Box::new(ManagedQemuHotForkSourceWorldAdmissionError::Fallback(
                    source,
                ))
            })?;
        self.reserve_fallback(HotCheckpointFallbackRecord::new(key, fallback))
    }

    /// Demotes and reaps every retained source while preserving cold fallbacks.
    ///
    /// Shutdown attempts every source in canonical key order. Failed sources
    /// remain owned by the pool and are all reported with their exact keys.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedQemuHotForkSourceWorldShutdownError`] when any source
    /// is checked out, invalidated, missing durable fallback authentication, or
    /// cannot be reaped completely.
    pub fn orderly_shutdown(
        &mut self,
    ) -> Result<Vec<HotCheckpointDemotion>, ManagedQemuHotForkSourceWorldShutdownError<D::Error>>
    {
        let keys = self.worlds.keys().copied().collect::<Vec<_>>();
        let mut demotions = Vec::with_capacity(keys.len());
        let mut failures = Vec::new();

        for key in keys {
            match self.demote_source(key, HotCheckpointDemotionReason::DaemonShutdown) {
                Ok(demotion) => demotions.push(demotion),
                Err(source) => failures.push((key, source)),
            }
        }

        if failures.is_empty() {
            Ok(demotions)
        } else {
            Err(ManagedQemuHotForkSourceWorldShutdownError::new(failures))
        }
    }

    fn reserve_fallback(
        &mut self,
        record: HotCheckpointFallbackRecord,
    ) -> Result<HotCheckpointFallbackSlot, Box<ManagedQemuHotForkSourceWorldAdmissionError<D::Error>>>
    {
        let reusable_slots = self
            .records
            .iter()
            .filter(|(slot, current)| {
                **current == record && !self.active.values().any(|active| active == *slot)
            })
            .map(|(&slot, _current)| slot)
            .collect::<Vec<_>>();
        for slot in reusable_slots {
            match self
                .retention
                .compare_exchange_fallback(slot, Some(record), Some(record))
                .map_err(|source| {
                    Box::new(ManagedQemuHotForkSourceWorldAdmissionError::Catalog(
                        DurableHotCheckpointCatalogError::Store(source),
                    ))
                })? {
                HotCheckpointFallbackRetentionCas::Advanced => return Ok(slot),
                HotCheckpointFallbackRetentionCas::Conflict { current } => {
                    if let Some(current) = current {
                        self.records.insert(slot, current);
                    } else {
                        self.records.remove(&slot);
                    }
                }
            }
        }

        for index in 0..MAX_HOT_CHECKPOINT_FALLBACK_ROOTS {
            let slot = HotCheckpointFallbackSlot::new(index).map_err(|source| {
                Box::new(ManagedQemuHotForkSourceWorldAdmissionError::Catalog(
                    DurableHotCheckpointCatalogError::Store(source),
                ))
            })?;
            if self.records.contains_key(&slot) {
                continue;
            }
            match self
                .retention
                .compare_exchange_fallback(slot, None, Some(record))
                .map_err(|source| {
                    Box::new(ManagedQemuHotForkSourceWorldAdmissionError::Catalog(
                        DurableHotCheckpointCatalogError::Store(source),
                    ))
                })? {
                HotCheckpointFallbackRetentionCas::Advanced => {
                    self.records.insert(slot, record);
                    return Ok(slot);
                }
                HotCheckpointFallbackRetentionCas::Conflict {
                    current: Some(current),
                } => {
                    self.records.insert(slot, current);
                }
                HotCheckpointFallbackRetentionCas::Conflict { current: None } => {}
            }
        }
        Err(Box::new(
            ManagedQemuHotForkSourceWorldAdmissionError::CatalogFull,
        ))
    }

    fn require_fallback_record(
        &mut self,
        slot: HotCheckpointFallbackSlot,
        key: QemuHotForkTemplateKey,
        fallback: HotCheckpointFallback,
    ) -> Result<(), DurableHotCheckpointCatalogError> {
        let expected = HotCheckpointFallbackRecord::new(key, fallback);
        let current = self
            .retention
            .load_fallback(slot)
            .map_err(DurableHotCheckpointCatalogError::Store)?;
        if current != Some(expected) {
            return Err(DurableHotCheckpointCatalogError::Conflict { slot, current });
        }
        Ok(())
    }

    fn remove_exact_fallback(
        &mut self,
        slot: HotCheckpointFallbackSlot,
        record: HotCheckpointFallbackRecord,
    ) -> Result<(), DurableHotCheckpointCatalogError> {
        match self
            .retention
            .compare_exchange_fallback(slot, Some(record), None)
            .map_err(DurableHotCheckpointCatalogError::Store)?
        {
            HotCheckpointFallbackRetentionCas::Advanced => {
                self.records.remove(&slot);
                Ok(())
            }
            HotCheckpointFallbackRetentionCas::Conflict { current } => {
                if let Some(current) = current {
                    self.records.insert(slot, current);
                } else {
                    self.records.remove(&slot);
                }
                Err(DurableHotCheckpointCatalogError::Conflict { slot, current })
            }
        }
    }
}

impl<D, R> crate::qemu_hot_fork_world_factory::source_world_provider_sealed::Sealed
    for ManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
}

const DIRECT_SOURCE_WORLD_PROVIDER_ID: u64 = 0;

impl<D, R> QemuHotForkSourceWorldProvider for ManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    type Error = ManagedQemuHotForkSourceWorldCheckoutError;

    fn checkout(
        &mut self,
        key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, Self::Error> {
        self.checkout_for(DIRECT_SOURCE_WORLD_PROVIDER_ID, key)
    }

    fn restore(&mut self, source: ProductionVmHotForkSourceWorld) {
        self.restore_for(DIRECT_SOURCE_WORLD_PROVIDER_ID, source);
    }

    fn abandon(&mut self) {
        self.abandon_for(DIRECT_SOURCE_WORLD_PROVIDER_ID);
    }
}

impl<D, R> ManagedQemuHotForkSourceWorldPool<D, R>
where
    D: HotCheckpointTemplateDemotionSink<ManagedQemuHotForkSourceWorld>,
    R: HotCheckpointFallbackRetentionStore,
{
    fn checkout_for(
        &mut self,
        provider: u64,
        key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, ManagedQemuHotForkSourceWorldCheckoutError>
    {
        if self.checked_out.contains_key(&provider) {
            return Err(ManagedQemuHotForkSourceWorldCheckoutError::PriorCheckoutPending);
        }
        let template = key.template_key();
        let Some(world) = self.worlds.get_mut(&template) else {
            return Ok(None);
        };
        if world.key() != key {
            return Ok(None);
        }
        if !world.available() {
            return Ok(None);
        }

        let tick = self.fork_rate_clock.elapsed_nanos();
        let permit = self
            .manager
            .admit_fork(tick)
            .map_err(ManagedQemuHotForkSourceWorldCheckoutError::ForkRate)?;
        let Some(source) = world.take() else {
            return Ok(None);
        };
        let identity = QemuHotForkSourceWorldCheckoutIdentity::capture(&source);
        self.checked_out
            .insert(provider, (template, identity, permit));
        Ok(Some(source))
    }

    fn restore_for(&mut self, provider: u64, source: ProductionVmHotForkSourceWorld) {
        let Some((_, identity, _)) = self.checked_out.get(&provider) else {
            let _ = source.retire();
            return;
        };
        if !identity.matches(&source) {
            let _ = source.retire();
            return;
        }
        let Some((key, _identity, _permit)) = self.checked_out.remove(&provider) else {
            let _ = source.retire();
            return;
        };
        match self.worlds.get_mut(&key) {
            Some(world) => world.restore(source),
            None => {
                let _ = source.retire();
            }
        }
    }

    fn abandon_for(&mut self, provider: u64) {
        let Some((key, _identity, _permit)) = self.checked_out.remove(&provider) else {
            return;
        };
        if let Some(world) = self.worlds.get_mut(&key) {
            world.invalidate();
        }
    }
}

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
    ) -> Result<Option<ProductionVmHotForkSourceWorld>, Self::Error> {
        self.pool
            .lock()
            .map_err(|_error| SharedQemuHotForkSourceWorldProviderError::Poisoned)?
            .checkout_for(self.provider, key)
            .map_err(Into::into)
    }

    fn restore(&mut self, source: ProductionVmHotForkSourceWorld) {
        match self.pool.lock() {
            Ok(mut pool) => pool.restore_for(self.provider, source),
            Err(_error) => {
                let _retained_for_process_lifetime = Box::leak(Box::new(source));
            }
        }
    }

    fn abandon(&mut self) {
        if let Ok(mut pool) = self.pool.lock() {
            pool.abandon_for(self.provider);
        }
    }
}

#[cfg(test)]
#[path = "managed_qemu_hot_fork_source_world_pool/tests.rs"]
mod tests;

fn source_slot(key: QemuHotForkTemplateKey) -> QemuHotForkTemplatePoolSlot {
    QemuHotForkTemplatePoolSlot::new(key, 0)
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
