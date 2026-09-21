//! Durable admission, checkout, reconciliation, and retirement operations.

use super::*;

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
            leased_out: BTreeMap::new(),
            lease_usage: HotCheckpointUsage::default(),
            next_lease: 1,
            fork_rate_clock: ForkRateClock::new(),
        })
    }

    /// Returns the shared hot-checkpoint manager view.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn manager(&self) -> &HotCheckpointManager {
        &self.manager
    }

    /// Returns whether an exact complete key has one immediately reusable source.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn source_available(&self, key: &QemuHotForkSourceWorldKey) -> bool {
        self.worlds
            .get(&manager_source_key(key))
            .is_some_and(|world| world.key() == key && world.available())
    }

    /// Returns whether an exact source can admit another resource-bounded lease.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn source_lease_available(&self, key: &QemuHotForkSourceWorldKey) -> bool {
        self.worlds
            .get(&manager_source_key(key))
            .is_some_and(|world| world.key() == key && world.lease_available())
    }

    /// Returns resources reserved for children with live source leases.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn source_lease_usage(&self) -> HotCheckpointUsage {
        self.lease_usage
    }

    /// Iterates every cold exact/thin fallback retained for restart and GC.
    #[cfg(test)]
    pub(crate) fn cold_fallbacks(
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

    /// Admits a production-restored exact source after measuring it.
    ///
    /// The exact checkpoint and reuse key are sealed into the source token by
    /// [`crate::ProductionQemuHotForkSourceFactory`]. Admission derives the
    /// durable exact fallback from that token and never accepts a caller-authored
    /// later-frontier label.
    ///
    /// # Errors
    ///
    /// Returns [`ManagedQemuHotForkAuthenticatedAdmissionFailure`] retaining
    /// the complete source authority when key binding, measurement, exact
    /// fallback persistence, or managed admission fails.
    pub fn admit_authenticated_exact_source(
        &mut self,
        authenticated: AuthenticatedExactQemuHotForkSource,
        signals: HotCheckpointHotnessSignals,
    ) -> Result<
        HotCheckpointAdmissionCommit,
        ManagedQemuHotForkAuthenticatedAdmissionFailure<D::Error>,
    > {
        let (key, checkpoint, source) = authenticated.into_parts();
        if key.boundary() != crate::QemuHotForkSourceWorldBoundary::ExactCheckpoint(checkpoint) {
            return Err(ManagedQemuHotForkAuthenticatedAdmissionFailure::Binding(
                ManagedQemuHotForkSourceWorldBindingFailure::new(
                    source,
                    ManagedQemuHotForkSourceWorldBindingError::ExactBoundaryCredentialMismatch,
                ),
            ));
        }
        let world = ManagedQemuHotForkSourceWorld::bind_authenticated_exact(key, source)
            .map_err(ManagedQemuHotForkAuthenticatedAdmissionFailure::Binding)?;

        self.admit_source(world, signals, HotCheckpointFallback::Exact(checkpoint))
            .map_err(ManagedQemuHotForkAuthenticatedAdmissionFailure::Admission)
    }

    /// Admits one complete source after durably retaining its exact fallback.
    ///
    /// Colder victims are reauthenticated and reaped before the new source is
    /// installed. Exactly one source is permitted for each lineage/source
    /// authenticated source-boundary coordinate, regardless of executor profile.
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
        let semantic_key = world.key.template_key();
        let manager_key = manager_source_key(&world.key);
        let candidate =
            HotCheckpointCandidate::new(manager_key, world.resources, signals, fallback);
        if self.worlds.contains_key(&manager_key) {
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
        let mut projected_usage = self.manager.usage();
        for victim in plan.demotions().iter().copied() {
            projected_usage = match projected_usage.remove(victim.status().resources()) {
                Some(usage) => usage,
                None => {
                    return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                        world,
                        None,
                        ManagedQemuHotForkSourceWorldAdmissionError::Rejected(
                            crate::HotCheckpointAdmissionRejection::AccountingOverflow,
                        ),
                    ));
                }
            };
        }
        projected_usage = match projected_usage.add(candidate.resources()) {
            Some(usage) => usage,
            None => {
                return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                    world,
                    None,
                    ManagedQemuHotForkSourceWorldAdmissionError::Rejected(
                        crate::HotCheckpointAdmissionRejection::AccountingOverflow,
                    ),
                ));
            }
        };
        projected_usage = match projected_usage.add_reservations(self.lease_usage) {
            Some(usage) => usage,
            None => {
                return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                    world,
                    None,
                    ManagedQemuHotForkSourceWorldAdmissionError::Rejected(
                        crate::HotCheckpointAdmissionRejection::AccountingOverflow,
                    ),
                ));
            }
        };
        let limits = self.manager.limits();
        if !projected_usage.fits(limits) {
            return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                world,
                None,
                ManagedQemuHotForkSourceWorldAdmissionError::LeaseCapacity {
                    pressure: HotCheckpointPressure::for_usage(projected_usage, limits),
                },
            ));
        }
        if let Err(source) = self
            .demotions
            .validate_fallback(semantic_key, candidate.fallback())
        {
            return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                world,
                None,
                ManagedQemuHotForkSourceWorldAdmissionError::Fallback(source),
            ));
        }
        for victim in plan.demotions() {
            let victim_key = victim.slot().template_key();
            let Some(victim_world) = self.worlds.get(&victim_key) else {
                return Err(ManagedQemuHotForkSourceWorldAdmissionFailure::new(
                    world,
                    None,
                    ManagedQemuHotForkSourceWorldAdmissionError::VictimUnavailable {
                        reconciliation: Ok(Vec::new()),
                    },
                ));
            };
            let victim_semantic_key = victim_world.key.template_key();
            if let Err(source) = self
                .demotions
                .validate_fallback(victim_semantic_key, victim.fallback())
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
                self.require_fallback_record(catalog_slot, victim_semantic_key, victim.fallback())
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

        let record = HotCheckpointFallbackRecord::new(semantic_key, candidate.fallback());
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

        match self
            .manager
            .commit_admission(plan, source_slot(manager_key))
        {
            Ok(commit) => {
                self.worlds.insert(manager_key, world);
                self.active.insert(manager_key, catalog_slot);
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
    #[cfg(test)]
    pub(crate) fn demote_source(
        &mut self,
        key: HotCheckpointPoolKey,
        reason: HotCheckpointDemotionReason,
    ) -> Result<HotCheckpointDemotion, ManagedQemuHotForkSourceWorldDemotionError<D::Error>> {
        self.demote_manager_source(key, reason)
    }

    fn demote_manager_source(
        &mut self,
        manager_key: HotCheckpointPoolKey,
        reason: HotCheckpointDemotionReason,
    ) -> Result<HotCheckpointDemotion, ManagedQemuHotForkSourceWorldDemotionError<D::Error>> {
        let slot = source_slot(manager_key);
        let status = self
            .manager
            .status(slot)
            .ok_or(ManagedQemuHotForkSourceWorldDemotionError::Missing)?;
        let catalog_slot = self
            .active
            .get(&manager_key)
            .copied()
            .ok_or(ManagedQemuHotForkSourceWorldDemotionError::Missing)?;
        let semantic_key = self
            .worlds
            .get(&manager_key)
            .ok_or(ManagedQemuHotForkSourceWorldDemotionError::Missing)?
            .key
            .template_key();
        self.require_fallback_record(catalog_slot, semantic_key, status.fallback())
            .map_err(ManagedQemuHotForkSourceWorldDemotionError::Catalog)?;
        let plan = self
            .manager
            .plan_orderly_demotion(slot, reason)
            .map_err(ManagedQemuHotForkSourceWorldDemotionError::Manager)?;
        self.demotions
            .validate_fallback(semantic_key, status.fallback())
            .map_err(ManagedQemuHotForkSourceWorldDemotionError::Fallback)?;
        let world = self
            .worlds
            .remove(&manager_key)
            .ok_or(ManagedQemuHotForkSourceWorldDemotionError::Missing)?;
        if !world.available() {
            self.worlds.insert(manager_key, world);
            return Err(ManagedQemuHotForkSourceWorldDemotionError::Unavailable);
        }
        if let Err(failure) = self
            .demotions
            .demote(world, HotCheckpointPlannedDemotion::new(status, reason))
        {
            let (world, source) = failure.into_parts();
            self.worlds.insert(manager_key, world);
            return Err(ManagedQemuHotForkSourceWorldDemotionError::Demotion(source));
        }
        let demotion = self
            .manager
            .commit_orderly_demotion(plan)
            .map_err(ManagedQemuHotForkSourceWorldDemotionError::Manager)?;
        self.active.remove(&manager_key);
        Ok(demotion)
    }

    /// Retains an authenticated fallback for a source declined by hot policy.
    ///
    /// The returned slot is cold: it is never entered in the active source
    /// inventory and therefore remains only a campaign-GC root.
    pub(crate) fn retain_cold_fallback(
        &mut self,
        key: HotCheckpointPoolKey,
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
            match self.demote_manager_source(key, HotCheckpointDemotionReason::DaemonShutdown) {
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
        key: HotCheckpointPoolKey,
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
    ) -> Result<Option<QemuHotForkSourceWorldLease>, Self::Error> {
        self.checkout_for(DIRECT_SOURCE_WORLD_PROVIDER_ID, key)
            .map(|source| {
                source.map(|source| {
                    QemuHotForkSourceWorldLease::exclusive(manager_source_key(key), source)
                })
            })
    }

    fn restore(&mut self, source: QemuHotForkSourceWorldLease) {
        match source.into_exclusive_source() {
            Ok(source) => self.restore_for(DIRECT_SOURCE_WORLD_PROVIDER_ID, source),
            Err(source) => {
                let _retained_for_process_lifetime = Box::leak(source);
                self.abandon_for(DIRECT_SOURCE_WORLD_PROVIDER_ID);
            }
        }
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
        if self.checked_out.contains_key(&provider) || self.leased_out.contains_key(&provider) {
            return Err(ManagedQemuHotForkSourceWorldCheckoutError::PriorCheckoutPending);
        }
        let template = manager_source_key(key);
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

    pub(super) fn checkout_lease_for(
        &mut self,
        provider: u64,
        key: &QemuHotForkSourceWorldKey,
    ) -> Result<Option<QemuHotForkSourceWorldLease>, ManagedQemuHotForkSourceWorldCheckoutError>
    {
        if self.checked_out.contains_key(&provider) || self.leased_out.contains_key(&provider) {
            return Err(ManagedQemuHotForkSourceWorldCheckoutError::PriorCheckoutPending);
        }

        let template = manager_source_key(key);
        let Some(world) = self.worlds.get(&template) else {
            return Ok(None);
        };
        if world.key() != key || !world.lease_available() {
            return Ok(None);
        }

        // A forked child inherits the source's exact VM configuration and
        // device roster. Define its reservation as one complete measured source
        // profile: full guest RAM is charged as template bytes, another full
        // guest-RAM allowance covers private dirties, and the source's process,
        // vCPU, descriptor, and writable-overlay counts bound the corresponding
        // child dimensions. Any future child-only resource class must extend
        // this profile explicitly before that configuration can be admitted.
        let resources = world.resources;
        let projected_lease_usage = self
            .lease_usage
            .add_resource_reservation(resources)
            .ok_or(ManagedQemuHotForkSourceWorldCheckoutError::LeaseAccountingOverflow)?;
        let projected_usage = self
            .manager
            .usage()
            .add_reservations(projected_lease_usage)
            .ok_or(ManagedQemuHotForkSourceWorldCheckoutError::LeaseAccountingOverflow)?;
        let limits = self.manager.limits();
        if !projected_usage.fits(limits) {
            return Err(ManagedQemuHotForkSourceWorldCheckoutError::LeaseCapacity {
                pressure: HotCheckpointPressure::for_usage(projected_usage, limits),
            });
        }

        let lease = self.next_lease;
        self.next_lease = self
            .next_lease
            .checked_add(1)
            .ok_or(ManagedQemuHotForkSourceWorldCheckoutError::LeaseIdentityExhausted)?;
        let source = self
            .worlds
            .get_mut(&template)
            .and_then(ManagedQemuHotForkSourceWorld::begin_lease)
            .ok_or(ManagedQemuHotForkSourceWorldCheckoutError::SourcePoisoned)?;
        let identity = match source.lock() {
            Ok(mut source) => {
                let identity = QemuHotForkSourceWorldCheckoutIdentity::capture(&source);
                let authenticated = identity.matches(&source) && source.fork_continuation().is_ok();
                if !authenticated {
                    drop(source);
                    if let Some(world) = self.worlds.get_mut(&template) {
                        world.invalidate();
                    }
                    return Ok(None);
                }
                identity
            }
            Err(_error) => {
                if let Some(world) = self.worlds.get_mut(&template) {
                    world.invalidate();
                }
                return Err(ManagedQemuHotForkSourceWorldCheckoutError::SourcePoisoned);
            }
        };
        let tick = self.fork_rate_clock.elapsed_nanos();
        let permit = match self.manager.admit_fork(tick) {
            Ok(permit) => permit,
            Err(error) => {
                drop(source);
                if !self
                    .leased_out
                    .values()
                    .any(|record| record.template == template)
                    && let Some(world) = self.worlds.get_mut(&template)
                {
                    world.finish_leases();
                }
                return Err(ManagedQemuHotForkSourceWorldCheckoutError::ForkRate(error));
            }
        };

        self.lease_usage = projected_lease_usage;
        self.leased_out.insert(
            provider,
            ManagedQemuHotForkSourceWorldLeaseRecord {
                lease,
                template,
                identity: identity.clone(),
                source: Arc::downgrade(&source),
                resources,
                _permit: permit,
            },
        );
        Ok(Some(QemuHotForkSourceWorldLease {
            managed_lease: Some(lease),
            template,
            identity,
            source,
        }))
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

    pub(super) fn restore_lease_for(&mut self, provider: u64, lease: QemuHotForkSourceWorldLease) {
        let Some(record) = self.leased_out.get(&provider) else {
            let _retained_for_process_lifetime = Box::leak(Box::new(lease.source));
            return;
        };
        let record_lease = record.lease;
        let template = record.template;
        let record_identity = record.identity.clone();
        let resources = record.resources;
        let matching_receipt = Some(record.lease) == lease.managed_lease
            && record.template == lease.template
            && record.identity == lease.identity;
        let matching_source = record
            .source
            .upgrade()
            .is_some_and(|source| Arc::ptr_eq(&source, &lease.source));
        if !matching_receipt || !matching_source {
            let _retained_for_process_lifetime = Box::leak(Box::new(lease.source));
            self.abandon_lease_for(provider);
            return;
        }

        let source_reusable = match lease.source.lock() {
            Ok(mut source) => {
                record_identity.matches(&source) && source.fork_continuation().is_ok()
            }
            Err(_error) => false,
        };
        if self
            .leased_out
            .remove(&provider)
            .is_none_or(|record| record.lease != record_lease)
        {
            let _retained_for_process_lifetime = Box::leak(Box::new(lease.source));
            if let Some(world) = self.worlds.get_mut(&template) {
                world.invalidate();
            }
            return;
        }
        self.lease_usage = match self.lease_usage.remove_resource_reservation(resources) {
            Some(usage) => usage,
            None => {
                if let Some(world) = self.worlds.get_mut(&template) {
                    world.invalidate();
                }
                let _retained_for_process_lifetime = Box::leak(Box::new(lease.source));
                return;
            }
        };
        drop(lease);

        let sibling_lease_remains = self
            .leased_out
            .values()
            .any(|record| record.template == template);
        let Some(world) = self.worlds.get_mut(&template) else {
            return;
        };
        if !source_reusable {
            world.invalidate();
        } else if !sibling_lease_remains {
            world.finish_leases();
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

    pub(super) fn abandon_lease_for(&mut self, provider: u64) {
        let Some(record) = self.leased_out.remove(&provider) else {
            return;
        };
        if let Some(world) = self.worlds.get_mut(&record.template) {
            world.invalidate();
        }

        // An abandoned child may still own live resources in quarantine. Its
        // reservation remains charged so another source cannot over-admit work.
    }
}
