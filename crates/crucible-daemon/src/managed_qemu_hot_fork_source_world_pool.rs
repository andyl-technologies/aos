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

use crucible_api::vm_lifecycle::ProductionVmHotForkSourceWorld;
use thiserror::Error;

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

/// Canonical source accepted by managed admission after factory authentication.
///
/// Its fields and production constructors remain private until a validated
/// factory receipt can bind the actual launch profile. This prevents callers
/// from relabeling a source's compatibility profile or semantic frontier.
#[must_use = "admit the authenticated source or retain its complete authority"]
pub struct AuthenticatedCanonicalQemuHotForkSource {
    key: QemuHotForkSourceWorldKey,
    source: ProductionVmHotForkSourceWorld,
}

impl AuthenticatedCanonicalQemuHotForkSource {
    #[cfg(test)]
    fn new_for_test(
        key: QemuHotForkSourceWorldKey,
        source: ProductionVmHotForkSourceWorld,
    ) -> Self {
        Self { key, source }
    }
}

/// Failed authenticated-source admission retaining the complete source authority.
#[must_use = "recover the rejected source and any durable cleanup obligation"]
pub enum ManagedQemuHotForkAuthenticatedAdmissionFailure<E> {
    /// Source binding, frontier validation, or resource measurement failed.
    Binding(ManagedQemuHotForkSourceWorldBindingFailure),
    /// Durable fallback or managed hot-retention admission failed.
    Admission(ManagedQemuHotForkSourceWorldAdmissionFailure<E>),
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
    checked_out: Option<(
        QemuHotForkTemplateKey,
        QemuHotForkSourceWorldCheckoutIdentity,
        crate::HotCheckpointForkPermit,
    )>,
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
            checked_out: None,
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
        let AuthenticatedCanonicalQemuHotForkSource { key, source } = authenticated;
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

    fn reserve_fallback(
        &mut self,
        record: HotCheckpointFallbackRecord,
    ) -> Result<HotCheckpointFallbackSlot, Box<ManagedQemuHotForkSourceWorldAdmissionError<D::Error>>>
    {
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
        if self.checked_out.is_some() {
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
        self.checked_out = Some((template, identity, permit));
        Ok(Some(source))
    }

    fn restore(&mut self, source: ProductionVmHotForkSourceWorld) {
        let Some((_, identity, _)) = self.checked_out.as_ref() else {
            let _ = source.retire();
            return;
        };
        if !identity.matches(&source) {
            let _ = source.retire();
            return;
        }
        let Some((key, _identity, _permit)) = self.checked_out.take() else {
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

    fn abandon(&mut self) {
        let Some((key, _identity, _permit)) = self.checked_out.take() else {
            return;
        };
        if let Some(world) = self.worlds.get_mut(&key) {
            world.invalidate();
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
