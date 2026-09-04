//! Durable ownership for managed hot and cold checkpoint fallbacks.
//!
//! The ordinary managed pool owns live QEMU sources and their process-local
//! accounting. This owner composes it with the bounded fallback catalog. A
//! fallback record becomes durable before its source may enter the hot pool,
//! remains as a cold restart/GC root after orderly demotion, and is removed
//! only through an explicit release of a non-hot catalog slot. Reopening the
//! owner conservatively treats every durable record as cold; live QEMU sources
//! are never inferred from operational records after daemon restart.

use std::collections::BTreeMap;

use thiserror::Error;

use crate::HotCheckpointTemplateDemotionSink;
use crate::{
    AttemptExecutionContext, AttemptExecutionRuntimeBasis, AttemptWorkerFailure,
    CrucibleAttemptExecution, HotCheckpointAdmissionCommit, HotCheckpointCandidate,
    HotCheckpointDemotion, HotCheckpointDemotionReason, HotCheckpointFallbackRecord,
    HotCheckpointFallbackRetentionCas, HotCheckpointFallbackRetentionError,
    HotCheckpointFallbackRetentionStore, HotCheckpointFallbackSlot, HotCheckpointInventoryError,
    HotCheckpointLimits, HotCheckpointStatus, MAX_HOT_CHECKPOINT_FALLBACK_ROOTS,
    ManagedHotCheckpointAdmissionError, ManagedHotCheckpointDemotionError,
    ManagedHotCheckpointStartError, ManagedQemuHotForkTemplatePool,
    ManagedQemuHotForkTemplatePoolConstructionError, QemuHotForkAttemptLifecycleFactory,
    QemuHotForkAttemptLifecycleRecoveryError, QemuHotForkKeyedLifecycleFactory,
    QemuHotForkLifecycleQuarantine, QemuHotForkTemplatePool, QemuHotForkTemplatePoolLifecycle,
    QemuHotForkTemplatePoolSlot,
};

/// Durable single-process owner of hot sources and cold fallback roots.
pub struct DurableManagedQemuHotForkTemplatePool<F, Q, D, R>
where
    F: QemuHotForkKeyedLifecycleFactory,
    Q: QemuHotForkLifecycleQuarantine<QemuHotForkTemplatePoolLifecycle<F::Lifecycle>>,
    D: HotCheckpointTemplateDemotionSink<F>,
    R: HotCheckpointFallbackRetentionStore,
{
    managed: ManagedQemuHotForkTemplatePool<F, Q, D>,
    retention: R,
    records: BTreeMap<HotCheckpointFallbackSlot, HotCheckpointFallbackRecord>,
    active: BTreeMap<QemuHotForkTemplatePoolSlot, HotCheckpointFallbackSlot>,
}

impl<F, Q, D, R> DurableManagedQemuHotForkTemplatePool<F, Q, D, R>
where
    F: QemuHotForkKeyedLifecycleFactory,
    Q: QemuHotForkLifecycleQuarantine<QemuHotForkTemplatePoolLifecycle<F::Lifecycle>>,
    D: HotCheckpointTemplateDemotionSink<F>,
    R: HotCheckpointFallbackRetentionStore,
{
    /// Opens an empty live-source owner over one authenticated durable catalog.
    ///
    /// Existing records are reconstructed as cold fallback roots. Reopening
    /// never claims that a QEMU process survived daemon restart.
    ///
    /// # Errors
    ///
    /// Returns [`DurableManagedHotCheckpointConstructionError`] when the live
    /// pool rejects its capacity or the complete catalog cannot be inventoried.
    pub fn open(
        limits: HotCheckpointLimits,
        quarantine: Q,
        demotions: D,
        retention: R,
    ) -> Result<Self, DurableManagedHotCheckpointConstructionError> {
        let managed = ManagedQemuHotForkTemplatePool::new(limits, quarantine, demotions)
            .map_err(DurableManagedHotCheckpointConstructionError::Managed)?;
        let records = inventory_records(&retention)
            .map_err(DurableManagedHotCheckpointConstructionError::Catalog)?;
        Ok(Self {
            managed,
            retention,
            records,
            active: BTreeMap::new(),
        })
    }

    /// Returns the enforced live-source manager view.
    #[must_use]
    pub const fn manager(&self) -> &crate::HotCheckpointManager {
        self.managed.manager()
    }

    /// Returns the immutable live-source pool view.
    #[must_use]
    pub const fn pool(&self) -> &QemuHotForkTemplatePool<F, Q> {
        self.managed.pool()
    }

    /// Returns the read-only fallback-root inventory capability used by GC.
    #[must_use]
    pub fn retention_admin(&self) -> &dyn crate::HotCheckpointFallbackRetentionAdmin {
        &self.retention
    }

    /// Returns the durable fallback at one exact catalog slot.
    #[must_use]
    pub fn fallback_record(
        &self,
        slot: HotCheckpointFallbackSlot,
    ) -> Option<HotCheckpointFallbackRecord> {
        self.records.get(&slot).copied()
    }

    /// Returns the catalog slot protecting one live source.
    #[must_use]
    pub fn active_fallback_slot(
        &self,
        source: QemuHotForkTemplatePoolSlot,
    ) -> Option<HotCheckpointFallbackSlot> {
        self.active.get(&source).copied()
    }

    /// Iterates every durable cold fallback in exact catalog order.
    pub fn cold_fallbacks(
        &self,
    ) -> impl Iterator<Item = (HotCheckpointFallbackSlot, HotCheckpointFallbackRecord)> + '_ {
        self.records
            .iter()
            .filter(|(slot, _record)| !self.active.values().any(|active| active == *slot))
            .map(|(&slot, &record)| (slot, record))
    }

    /// Updates one retained source's explainable hotness and pin signals.
    ///
    /// # Errors
    ///
    /// Returns [`HotCheckpointInventoryError`] when the live manager rejects
    /// the exact coordinate or its generation cannot advance.
    pub fn update_signals(
        &mut self,
        slot: QemuHotForkTemplatePoolSlot,
        signals: crate::HotCheckpointHotnessSignals,
    ) -> Result<HotCheckpointStatus, HotCheckpointInventoryError> {
        self.managed.update_signals(slot, signals)
    }

    /// Admits one source only after its exact fallback record is durable.
    ///
    /// Successful victim demotions preserve their records as cold roots. If
    /// live admission fails before ownership transfer, the reserved record is
    /// removed. A failed cleanup or an internally retained candidate returns
    /// the exact catalog slot so the caller can recover without losing the GC
    /// root.
    ///
    /// # Errors
    ///
    /// Returns [`DurableManagedHotCheckpointAdmissionFailure`] retaining every
    /// source factory not owned by this object and any durable cleanup token.
    pub fn admit_template(
        &mut self,
        factory: F,
        candidate: HotCheckpointCandidate,
    ) -> Result<
        HotCheckpointAdmissionCommit,
        DurableManagedHotCheckpointAdmissionFailure<F, D::Error>,
    > {
        if factory.template_key() != candidate.template_key() {
            return Err(DurableManagedHotCheckpointAdmissionFailure::new(
                Some(factory),
                None,
                None,
                DurableManagedHotCheckpointAdmissionError::CandidateKeyMismatch,
            ));
        }

        let record =
            HotCheckpointFallbackRecord::new(candidate.template_key(), candidate.fallback());
        let catalog_slot = match self.reserve_fallback(record) {
            Ok(slot) => slot,
            Err(source) => {
                return Err(DurableManagedHotCheckpointAdmissionFailure::new(
                    Some(factory),
                    None,
                    None,
                    *source,
                ));
            }
        };

        match self.managed.admit_template(factory, candidate) {
            Ok(commit) => {
                for demotion in commit.demoted() {
                    self.active.remove(&demotion.status().slot());
                }
                self.active.insert(commit.retained().slot(), catalog_slot);
                Ok(commit)
            }
            Err(failure) => {
                let (candidate, stranded, source) = failure.into_parts();
                self.reconcile_active_sources();
                if candidate.is_none() {
                    return Err(DurableManagedHotCheckpointAdmissionFailure::new(
                        None,
                        stranded,
                        Some(catalog_slot),
                        DurableManagedHotCheckpointAdmissionError::Managed(source),
                    ));
                }

                match self.remove_exact_fallback(catalog_slot, record) {
                    Ok(()) => Err(DurableManagedHotCheckpointAdmissionFailure::new(
                        candidate,
                        stranded,
                        None,
                        DurableManagedHotCheckpointAdmissionError::Managed(source),
                    )),
                    Err(cleanup) => Err(DurableManagedHotCheckpointAdmissionFailure::new(
                        candidate,
                        stranded,
                        Some(catalog_slot),
                        DurableManagedHotCheckpointAdmissionError::Cleanup {
                            admission: Box::new(source),
                            cleanup,
                        },
                    )),
                }
            }
        }
    }

    /// Demotes one live source while retaining its fallback as a cold GC root.
    ///
    /// # Errors
    ///
    /// Returns [`DurableManagedHotCheckpointDemotionFailure`] when the source
    /// has no exact catalog binding, that binding changed, or live demotion
    /// fails. Any stranded source authority is retained by the failure.
    pub fn demote_template(
        &mut self,
        slot: QemuHotForkTemplatePoolSlot,
        reason: HotCheckpointDemotionReason,
    ) -> Result<HotCheckpointDemotion, DurableManagedHotCheckpointDemotionFailure<F, D::Error>>
    {
        let catalog_slot = self.active.get(&slot).copied().ok_or_else(|| {
            DurableManagedHotCheckpointDemotionFailure::new(
                None,
                DurableManagedHotCheckpointDemotionError::UntrackedSource,
            )
        })?;
        let status = self.manager().status(slot).ok_or_else(|| {
            DurableManagedHotCheckpointDemotionFailure::new(
                None,
                DurableManagedHotCheckpointDemotionError::UntrackedSource,
            )
        })?;
        let expected = HotCheckpointFallbackRecord::new(slot.template_key(), status.fallback());
        let current = self
            .retention
            .load_fallback(catalog_slot)
            .map_err(|source| {
                DurableManagedHotCheckpointDemotionFailure::new(
                    None,
                    DurableManagedHotCheckpointDemotionError::Catalog(
                        DurableHotCheckpointCatalogError::Store(source),
                    ),
                )
            })?;
        if current != Some(expected) {
            return Err(DurableManagedHotCheckpointDemotionFailure::new(
                None,
                DurableManagedHotCheckpointDemotionError::Catalog(
                    DurableHotCheckpointCatalogError::Conflict {
                        slot: catalog_slot,
                        current,
                    },
                ),
            ));
        }

        let outcome = self.managed.demote_template(slot, reason);
        self.reconcile_active_sources();
        outcome.map_err(|failure| {
            let (factory, source) = failure.into_parts();
            DurableManagedHotCheckpointDemotionFailure::new(
                factory,
                DurableManagedHotCheckpointDemotionError::Managed(source),
            )
        })
    }

    /// Durably releases one cold fallback root.
    ///
    /// # Errors
    ///
    /// Returns [`DurableManagedHotCheckpointReleaseError`] when the slot is
    /// still bound to a live source, absent, changed concurrently, or cannot be
    /// removed durably.
    pub fn release_cold_fallback(
        &mut self,
        slot: HotCheckpointFallbackSlot,
    ) -> Result<HotCheckpointFallbackRecord, DurableManagedHotCheckpointReleaseError> {
        if self.active.values().any(|active| *active == slot) {
            return Err(DurableManagedHotCheckpointReleaseError::Active);
        }
        let record = self
            .records
            .get(&slot)
            .copied()
            .ok_or(DurableManagedHotCheckpointReleaseError::Missing)?;
        self.remove_exact_fallback(slot, record)
            .map_err(DurableManagedHotCheckpointReleaseError::Catalog)?;
        Ok(record)
    }

    fn reserve_fallback(
        &mut self,
        record: HotCheckpointFallbackRecord,
    ) -> Result<HotCheckpointFallbackSlot, Box<DurableManagedHotCheckpointAdmissionError<D::Error>>>
    {
        for index in 0..MAX_HOT_CHECKPOINT_FALLBACK_ROOTS {
            let slot = HotCheckpointFallbackSlot::new(index).map_err(|source| {
                Box::new(DurableManagedHotCheckpointAdmissionError::Catalog(
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
                    Box::new(DurableManagedHotCheckpointAdmissionError::Catalog(
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
            DurableManagedHotCheckpointAdmissionError::CatalogFull,
        ))
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
                match current {
                    Some(current) => {
                        self.records.insert(slot, current);
                    }
                    None => {
                        self.records.remove(&slot);
                    }
                }
                Err(DurableHotCheckpointCatalogError::Conflict { slot, current })
            }
        }
    }

    fn reconcile_active_sources(&mut self) {
        self.active.retain(|source, _catalog_slot| {
            self.managed.manager().status(*source).is_some()
                && self.managed.pool().slot_available(*source).is_some()
        });
    }
}

impl<F, Q, D, R> QemuHotForkAttemptLifecycleFactory
    for DurableManagedQemuHotForkTemplatePool<F, Q, D, R>
where
    F: QemuHotForkKeyedLifecycleFactory,
    Q: QemuHotForkLifecycleQuarantine<QemuHotForkTemplatePoolLifecycle<F::Lifecycle>>,
    D: HotCheckpointTemplateDemotionSink<F>,
    R: HotCheckpointFallbackRetentionStore,
{
    type Lifecycle = QemuHotForkTemplatePoolLifecycle<F::Lifecycle>;
    type Error = ManagedHotCheckpointStartError<F::Error>;

    fn start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        runtime_basis: AttemptExecutionRuntimeBasis,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.managed.start(input, context, runtime_basis)
    }

    fn recover(
        &mut self,
        lifecycle: Self::Lifecycle,
    ) -> Result<(), QemuHotForkAttemptLifecycleRecoveryError<Self::Lifecycle, Self::Error>> {
        self.managed.recover(lifecycle)
    }

    fn quarantine(&mut self, lifecycle: Self::Lifecycle) {
        self.managed.quarantine(lifecycle);
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

/// Invalid durable managed-pool construction.
#[derive(Debug, Error)]
pub enum DurableManagedHotCheckpointConstructionError {
    /// The live pool rejected its configured capacity.
    #[error("durable managed hot-checkpoint pool construction failed")]
    Managed(ManagedQemuHotForkTemplatePoolConstructionError),
    /// The durable catalog could not be authenticated completely.
    #[error("durable hot-checkpoint fallback inventory failed")]
    Catalog(HotCheckpointFallbackRetentionError),
}

/// Exact durable-catalog mutation failure.
#[derive(Debug, Error)]
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

/// Failed durable admission retaining all recoverable authorities.
#[must_use = "recover factories and any retained catalog cleanup slot"]
pub struct DurableManagedHotCheckpointAdmissionFailure<F, E> {
    candidate: Option<Box<F>>,
    stranded_factory: Option<Box<F>>,
    catalog_slot: Option<HotCheckpointFallbackSlot>,
    error: Box<DurableManagedHotCheckpointAdmissionError<E>>,
}

impl<F, E> DurableManagedHotCheckpointAdmissionFailure<F, E> {
    fn new(
        candidate: Option<F>,
        stranded_factory: Option<F>,
        catalog_slot: Option<HotCheckpointFallbackSlot>,
        error: DurableManagedHotCheckpointAdmissionError<E>,
    ) -> Self {
        Self {
            candidate: candidate.map(Box::new),
            stranded_factory: stranded_factory.map(Box::new),
            catalog_slot,
            error: Box::new(error),
        }
    }

    /// Consumes the failure into source authorities, cleanup slot, and cause.
    pub fn into_parts(
        self,
    ) -> (
        Option<F>,
        Option<F>,
        Option<HotCheckpointFallbackSlot>,
        DurableManagedHotCheckpointAdmissionError<E>,
    ) {
        (
            self.candidate.map(|factory| *factory),
            self.stranded_factory.map(|factory| *factory),
            self.catalog_slot,
            *self.error,
        )
    }
}

impl<F, E> std::fmt::Debug for DurableManagedHotCheckpointAdmissionFailure<F, E>
where
    E: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableManagedHotCheckpointAdmissionFailure")
            .field("has_candidate", &self.candidate.is_some())
            .field("has_stranded_factory", &self.stranded_factory.is_some())
            .field("catalog_slot", &self.catalog_slot)
            .field("error", &self.error)
            .finish()
    }
}

/// Exact reason durable hot-source admission failed.
#[derive(Debug, Error)]
pub enum DurableManagedHotCheckpointAdmissionError<E> {
    /// Factory and candidate name different exact source keys.
    #[error("hot-checkpoint candidate key differs from its source factory")]
    CandidateKeyMismatch,
    /// The bounded durable catalog has no free slot.
    #[error("hot-checkpoint fallback catalog is full")]
    CatalogFull,
    /// Reserving the candidate's durable fallback failed.
    #[error("hot-checkpoint fallback catalog reservation failed")]
    Catalog(#[source] DurableHotCheckpointCatalogError),
    /// Live-source validation, demotion, insertion, or accounting failed.
    #[error("managed hot-checkpoint admission failed")]
    Managed(#[source] ManagedHotCheckpointAdmissionError<E>),
    /// Live admission failed and its newly reserved record could not be removed.
    #[error("managed hot-checkpoint admission and catalog cleanup both failed")]
    Cleanup {
        /// Original live-source admission failure.
        admission: Box<ManagedHotCheckpointAdmissionError<E>>,
        /// Exact catalog cleanup failure.
        cleanup: DurableHotCheckpointCatalogError,
    },
}

/// Failed durable explicit demotion retaining any stranded source.
#[must_use = "recover any stranded source authority"]
pub struct DurableManagedHotCheckpointDemotionFailure<F, E> {
    stranded_factory: Option<Box<F>>,
    error: Box<DurableManagedHotCheckpointDemotionError<E>>,
}

impl<F, E> DurableManagedHotCheckpointDemotionFailure<F, E> {
    fn new(factory: Option<F>, error: DurableManagedHotCheckpointDemotionError<E>) -> Self {
        Self {
            stranded_factory: factory.map(Box::new),
            error: Box::new(error),
        }
    }

    /// Consumes the failure into any stranded source and exact cause.
    pub fn into_parts(self) -> (Option<F>, DurableManagedHotCheckpointDemotionError<E>) {
        (self.stranded_factory.map(|factory| *factory), *self.error)
    }
}

impl<F, E> std::fmt::Debug for DurableManagedHotCheckpointDemotionFailure<F, E>
where
    E: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableManagedHotCheckpointDemotionFailure")
            .field("has_stranded_factory", &self.stranded_factory.is_some())
            .field("error", &self.error)
            .finish()
    }
}

/// Exact reason durable explicit source demotion failed.
#[derive(Debug, Error)]
pub enum DurableManagedHotCheckpointDemotionError<E> {
    /// The live source lacks an exact durable catalog binding.
    #[error("live hot-checkpoint source has no durable fallback binding")]
    UntrackedSource,
    /// The bound catalog record is unavailable or changed.
    #[error("live hot-checkpoint fallback catalog binding failed")]
    Catalog(#[source] DurableHotCheckpointCatalogError),
    /// The managed live-source transition failed.
    #[error("managed hot-checkpoint demotion failed")]
    Managed(#[source] ManagedHotCheckpointDemotionError<E>),
}

/// Failed explicit cold-root release.
#[derive(Debug, Error)]
pub enum DurableManagedHotCheckpointReleaseError {
    /// The catalog record still protects a live source.
    #[error("cannot release the fallback of a live hot-checkpoint source")]
    Active,
    /// The requested durable catalog slot is absent.
    #[error("hot-checkpoint fallback catalog slot is absent")]
    Missing,
    /// The exact conditional durable removal failed.
    #[error("hot-checkpoint fallback catalog release failed")]
    Catalog(#[source] DurableHotCheckpointCatalogError),
}

#[cfg(test)]
mod tests;
