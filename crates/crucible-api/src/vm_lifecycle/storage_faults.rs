//! Production signal coordination for live World-backed block devices.
//!
//! The coordinator owns the exact seams around the shared-memory block
//! servicer. It evaluates one authenticated opportunity per authored phase and
//! never substitutes an implicit fault-free result after scheduler admission.

use std::sync::{Arc, Mutex};

use super::*;

use crucible::model::{
    ContentHash, EffectSpecification, FAULT_RUNTIME_STATE_VERSION, FaultCoordinate,
    FaultObservation, FaultObservationKind, FaultPhase, FaultSignalPlan, ResolvedBindingAction,
    ResolvedFaultTarget, StorageEffectSpecification, World, WorldIoNodeKind,
};
use crucible_device::block::{
    BaseImage, BlockDurabilityConfig, BlockOp, BlockPersistenceMediaOutcome, BlockRequest,
    BlockRetainedRelease, BlockServiceCompletion, BlockStorageOutcome,
    ResolvedBlockDeliveryDirective, ResolvedBlockExecutionDirective,
    ResolvedBlockRequestPersistenceDirective,
};
use crucible_qemu::{
    ProductionFaultRuntime, QemuAsyncDriverRuntimeError, QemuBlockFaultCoordinator,
    QemuLiveBlockIoDeliveryStep, QemuLiveBlockIoIntakeStep, QemuLiveBlockIoServiceStep,
    QemuLiveBlockIoServicer, ResolvedVolatileCacheLoss, StorageFaultResolutionContext,
    VolatileCacheLossReplay, block_delivery_fault_opportunity, block_durability_config,
    block_persistence_fault_opportunity, block_request_fault_opportunity,
    block_request_persistence_fault_opportunity, merge_block_fault_phase_directive,
    resolve_block_fault_directive, resolve_block_persistence_media_directive,
    resolve_volatile_cache_loss, storage_recovery_event_key,
};

/// Maximum phase/device settle transitions performed during one host poll.
const HARD_STORAGE_SETTLE_STEPS: usize = 4_096;
/// Maximum undrained signal observations across one backend quantum.
const HARD_STORAGE_FAULT_OBSERVATIONS: usize = 262_144;

/// Authenticated World material retained for launch and coordinator binding.
#[derive(Clone)]
pub(super) struct ProductionBlockBinding {
    /// Immutable base image passed to the live servicer.
    pub(super) base: BaseImage,
    /// Complete World durability contract.
    pub(super) durability: BlockDurabilityConfig,
    /// Resolved signal target for every request opportunity.
    pub(super) target: ResolvedFaultTarget,
}

/// Resolves the optional block device owned by one World VM.
pub(super) fn block_binding_for_vm(
    world: &World,
    vm: &crucible::NodeId,
    artifacts: Option<&Arc<dyn crucible::model::DagStore>>,
) -> Result<Option<ProductionBlockBinding>, LifecycleApiError> {
    let blocks = world
        .io_nodes()
        .filter(|node| node.owner == *vm && matches!(node.kind, WorldIoNodeKind::Block { .. }))
        .collect::<Vec<_>>();
    if blocks.len() > 1 {
        return Err(loop_factory_error(format!(
            "QEMU node `{}` declares {} block devices but the current shared-memory transport has one block executor slot",
            vm.name,
            blocks.len()
        )));
    }
    let Some(node) = blocks.first().copied() else {
        return Ok(None);
    };
    let WorldIoNodeKind::Block {
        base_image,
        base_length,
        ..
    } = &node.kind
    else {
        return Err(loop_factory_error("selected World block node changed kind"));
    };
    let store = artifacts.ok_or_else(|| {
        loop_factory_error(format!(
            "QEMU node `{}` owns block device `{}` but no production World artifact store was configured",
            vm.name, node.id.name
        ))
    })?;
    let bytes = store.get(&base_image.hash()).map_err(|error| {
        loop_factory_error(format!(
            "load block base image for `{}` from the World artifact store: {error}",
            node.id.name
        ))
    })?;
    let base = BaseImage::new(bytes);
    let actual = ContentHash { bytes: base.hash() };
    if actual != base_image.hash() || base.len() != *base_length {
        return Err(loop_factory_error(format!(
            "World block base image for `{}` differs from its declared hash or length",
            node.id.name
        )));
    }
    let target = ResolvedFaultTarget::BlockDevice {
        device: node.fault_target_hash(),
    };
    let durability = block_durability_config(world, &target).map_err(|error| {
        loop_factory_error(format!(
            "resolve block durability for `{}`: {error}",
            node.id.name
        ))
    })?;
    Ok(Some(ProductionBlockBinding {
        base,
        durability,
        target,
    }))
}

/// Globally sequenced fault-observation journal shared by every live adapter.
#[derive(Clone, Default)]
pub(super) struct ProductionFaultObservationJournal {
    batches: std::collections::BTreeMap<u64, Vec<FaultObservation>>,
    observations: usize,
}

impl ProductionFaultObservationJournal {
    fn ensure_capacity(&self, additional: usize) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.observations
            .checked_add(additional)
            .filter(|count| *count <= HARD_STORAGE_FAULT_OBSERVATIONS)
            .map(|_count| ())
            .ok_or_else(|| {
                storage_error(
                    "record fault observations",
                    "fault observation journal exceeds its hard bound",
                )
            })
    }

    pub(super) fn append(
        &mut self,
        sequence: u64,
        observations: Vec<FaultObservation>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.append_observation_batches(vec![(sequence, observations)])?;
        Ok(())
    }

    pub(super) fn append_observation_batches(
        &mut self,
        batches: Vec<(u64, Vec<FaultObservation>)>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let additional = batches
            .iter()
            .try_fold(0_usize, |count, (_, batch)| count.checked_add(batch.len()));
        let additional = additional.ok_or_else(|| {
            storage_error(
                "record fault observations",
                "fault observation batch count overflow",
            )
        })?;
        self.ensure_capacity(additional)?;
        self.observations += additional;
        for (sequence, observations) in batches {
            self.batches
                .entry(sequence)
                .or_default()
                .extend(observations);
        }
        Ok(())
    }

    fn append_batches(
        &mut self,
        batches: Vec<(u64, FaultObservation)>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.ensure_capacity(batches.len())?;
        self.observations += batches.len();
        for (sequence, observation) in batches {
            self.batches.entry(sequence).or_default().push(observation);
        }
        Ok(())
    }

    pub(super) fn snapshot(&self) -> Vec<FaultObservation> {
        self.batches.values().flatten().cloned().collect()
    }

    pub(super) fn clear(&mut self) {
        self.observations = 0;
        self.batches.clear();
    }

    pub(super) fn is_empty(&self) -> bool {
        self.observations == 0
    }

    pub(super) fn contains_sequence(&self, sequence: u64) -> bool {
        self.batches.contains_key(&sequence)
    }

    pub(super) fn rollback_sequence(
        &mut self,
        sequence: u64,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if let Some(observations) = self.batches.remove(&sequence) {
            self.observations = self
                .observations
                .checked_sub(observations.len())
                .ok_or_else(|| {
                    storage_error(
                        "roll back fault observations",
                        "fault observation journal count is inconsistent",
                    )
                })?;
        }
        Ok(())
    }
}

/// Shared owner of the globally sequenced observation journal.
pub(super) type ProductionStorageObservations = Arc<Mutex<ProductionFaultObservationJournal>>;

/// Coordinates one live block servicer with the authoritative signal runtime.
pub(super) struct ProductionBlockFaultCoordinator {
    runtime: Arc<Mutex<ProductionFaultRuntime>>,
    cursor: SharedProductionFaultEvaluationCursor,
    observations: ProductionStorageObservations,
    world: World,
    target: ResolvedFaultTarget,
    opportunity_targets: Vec<ResolvedFaultTarget>,
    context: StorageFaultResolutionContext,
    icount_shift: u8,
}

impl ProductionBlockFaultCoordinator {
    /// Binds a World block target to the shared production continuation.
    pub(super) fn new(
        runtime: Arc<Mutex<ProductionFaultRuntime>>,
        cursor: SharedProductionFaultEvaluationCursor,
        observations: ProductionStorageObservations,
        world: World,
        target: ResolvedFaultTarget,
        fault_plan: &FaultSignalPlan,
        scenario_seed: ContentHash,
        icount_shift: u8,
    ) -> Self {
        let mut opportunity_targets = fault_plan
            .bindings()
            .iter()
            .flat_map(|binding| binding.selector().resolved().targets())
            .filter(|candidate| block_targets_same_device(&target, candidate))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        opportunity_targets.insert(target.clone());
        Self {
            runtime,
            cursor,
            observations,
            world,
            target,
            opportunity_targets: opportunity_targets.into_iter().collect(),
            context: StorageFaultResolutionContext::new(scenario_seed),
            icount_shift,
        }
    }

    fn request_targets(&self, request: &BlockRequest) -> Vec<ResolvedFaultTarget> {
        self.opportunity_targets
            .iter()
            .filter(|target| block_target_intersects_request(target, request))
            .cloned()
            .collect()
    }

    fn range_targets(&self, offset: u64, count: u32) -> Vec<ResolvedFaultTarget> {
        self.opportunity_targets
            .iter()
            .filter(|target| block_target_intersects_range(target, offset, u64::from(count)))
            .cloned()
            .collect()
    }

    fn virtual_nanos(&self, icount: u64) -> Result<u64, QemuAsyncDriverRuntimeError> {
        icount
            .checked_shl(u32::from(self.icount_shift))
            .ok_or_else(|| storage_error("convert block icount", "virtual time overflow"))
    }

    fn retired_instructions_at(
        &self,
        nanos: u64,
        observed_guest_icount: u64,
    ) -> Result<u64, QemuAsyncDriverRuntimeError> {
        let quantum = 1_u64
            .checked_shl(u32::from(self.icount_shift))
            .ok_or_else(|| storage_error("convert block coordinate", "icount shift overflow"))?;
        let icount = nanos
            .checked_add(quantum.saturating_sub(1))
            .map(|rounded| rounded >> self.icount_shift)
            .ok_or_else(|| storage_error("convert block coordinate", "icount rounding overflow"))?;
        if icount > observed_guest_icount {
            return Err(storage_error(
                "convert block coordinate",
                "storage opportunity is later than the observed guest frontier",
            ));
        }
        Ok(icount)
    }

    fn evaluate_phase(
        &mut self,
        opportunity: &crucible::model::FaultOpportunity,
    ) -> Result<Vec<ResolvedBindingAction>, QemuAsyncDriverRuntimeError> {
        let mut cursor = self.cursor.lock().map_err(|_| {
            storage_error(
                "sequence block fault opportunity",
                "production fault evaluation cursor lock is poisoned",
            )
        })?;
        let cursor_before = *cursor;
        let sequence = cursor
            .next_sequence(opportunity.coordinate().virtual_nanos)
            .map_err(|error| storage_error("sequence block fault opportunity", error))?;
        let mut runtime = self.runtime.lock().map_err(|_| {
            storage_error(
                "evaluate block fault opportunity",
                "production fault runtime lock is poisoned",
            )
        })?;
        let evaluation = match runtime.evaluate_host_opportunity(opportunity, sequence) {
            Ok(evaluation) => evaluation,
            Err(error) => {
                *cursor = cursor_before;
                return Err(storage_error("evaluate block fault opportunity", error));
            }
        };
        let impulses = runtime.drain_host_impulses();
        if impulses.iter().any(|action| {
            action.target != *opportunity.target() || action.phase != opportunity.phase()
        }) {
            runtime.poison();
            return Err(storage_error(
                "evaluate block fault opportunity",
                "host impulse escaped its exact storage target or phase",
            ));
        }
        let mut actions = runtime
            .host_state()
            .matching(opportunity.target(), opportunity.phase())
            .cloned()
            .collect::<Vec<_>>();
        actions.extend(impulses);
        let mut observations = match self.observations.lock() {
            Ok(observations) => observations,
            Err(_) => {
                runtime.poison();
                return Err(storage_error(
                    "record block fault observations",
                    "storage observation queue lock is poisoned",
                ));
            }
        };
        if let Err(error) = observations.append(sequence, evaluation.observations) {
            runtime.poison();
            return Err(error);
        }
        drop(runtime);
        Ok(actions)
    }

    fn persistent_flash_actions(
        &self,
        target: &ResolvedFaultTarget,
    ) -> Result<Vec<ResolvedBindingAction>, QemuAsyncDriverRuntimeError> {
        let runtime = self.runtime.lock().map_err(|_| {
            storage_error(
                "resolve physical storage persistence",
                "production fault runtime lock is poisoned",
            )
        })?;
        Ok(runtime
            .host_state()
            .matching(target, FaultPhase::Persist)
            .filter(|action| {
                matches!(
                    action.effect.specification(),
                    EffectSpecification::Storage(StorageEffectSpecification::FlashState { .. })
                )
            })
            .cloned()
            .collect())
    }

    fn after_evaluation<T>(
        &self,
        operation: &'static str,
        result: Result<T, impl std::fmt::Display>,
    ) -> Result<T, QemuAsyncDriverRuntimeError> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                if let Ok(mut runtime) = self.runtime.lock() {
                    runtime.poison();
                }
                Err(storage_error(operation, error))
            }
        }
    }

    fn targets_attached_device(&self, target: &ResolvedFaultTarget) -> bool {
        let attached = match &self.target {
            ResolvedFaultTarget::BlockDevice { device }
            | ResolvedFaultTarget::BlockRange { device, .. } => device,
            _ => return false,
        };
        matches!(
            target,
            ResolvedFaultTarget::BlockDevice { device }
                | ResolvedFaultTarget::BlockRange { device, .. }
                if device == attached
        )
    }

    fn record_device_outcomes(
        &self,
        servicer: &mut QemuLiveBlockIoServicer,
        guest_icount: u64,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let result = self.try_record_device_outcomes(servicer, guest_icount);
        if result.is_err()
            && let Ok(mut runtime) = self.runtime.lock()
        {
            runtime.poison();
        }
        result
    }

    fn try_record_device_outcomes(
        &self,
        servicer: &mut QemuLiveBlockIoServicer,
        guest_icount: u64,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let outcomes = servicer
            .storage_outcomes()
            .map_err(|error| storage_error("inspect storage device outcomes", error))?;
        if outcomes.is_empty() {
            return Ok(());
        }
        let mut observations = Vec::with_capacity(outcomes.len());
        for outcome in &outcomes {
            let (nanos, evidence) = match outcome {
                BlockStorageOutcome::Service(outcome) => {
                    (outcome.finished_nanos, storage_service_evidence(outcome))
                }
                BlockStorageOutcome::Persistence(outcome) => {
                    (outcome.executed_nanos, persistence_media_evidence(outcome))
                }
            };
            observations.push((
                nanos,
                FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: FaultObservationKind::EffectApplied,
                    coordinate: FaultCoordinate {
                        virtual_nanos: nanos,
                        retired_instructions: Some(
                            self.retired_instructions_at(nanos, guest_icount)?,
                        ),
                    },
                    binding: None,
                    target: Some(self.target.clone()),
                    opportunity: None,
                    evidence,
                },
            ));
        }
        let mut cursor = self.cursor.lock().map_err(|_| {
            storage_error(
                "sequence storage device outcomes",
                "production fault evaluation cursor lock is poisoned",
            )
        })?;
        let mut queued = self.observations.lock().map_err(|_| {
            storage_error(
                "record storage device outcomes",
                "storage observation queue lock is poisoned",
            )
        })?;
        queued.ensure_capacity(observations.len())?;
        let cursor_before = *cursor;
        let mut batches = Vec::with_capacity(observations.len());
        for (nanos, observation) in observations {
            let sequence = match cursor.next_sequence(nanos) {
                Ok(sequence) => sequence,
                Err(error) => {
                    *cursor = cursor_before;
                    return Err(storage_error("sequence storage device outcomes", error));
                }
            };
            batches.push((sequence, observation));
        }
        if let Err(error) = queued.append_batches(batches) {
            *cursor = cursor_before;
            return Err(error);
        }
        let drained = servicer
            .drain_storage_outcomes()
            .map_err(|error| storage_error("acknowledge storage device outcomes", error))?;
        if drained != outcomes {
            return Err(storage_error(
                "record storage device outcomes",
                "storage outcome queues changed during their atomic journal commit",
            ));
        }
        Ok(())
    }

    fn admit_head_request(
        &mut self,
        servicer: &mut QemuLiveBlockIoServicer,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let pin = servicer
            .pin_next_request_completion()
            .map_err(|error| storage_error("pin live block request", error))?;
        let Some(observed) = pin.observed else {
            return Ok(());
        };
        let request = observed.request.ok_or_else(|| {
            storage_error(
                "decode live block request",
                "malformed block request payload",
            )
        })?;
        let request_nanos = self.virtual_nanos(observed.request_icount)?;
        let coordinate = FaultCoordinate {
            virtual_nanos: request_nanos,
            retired_instructions: Some(observed.request_icount),
        };
        let mut directive = crucible_device::block::ResolvedBlockFaultDirective::fault_free(
            &request,
            servicer.storage_fault_state().config().length_bytes,
        );
        directive.request_sequence = observed.request_sequence;
        directive.execution_nanos = request_nanos;
        for phase in [FaultPhase::Admit, FaultPhase::Queue] {
            for target in self.request_targets(&request) {
                let opportunity = block_request_fault_opportunity(
                    target.clone(),
                    &request,
                    observed.wire_digest,
                    phase,
                    coordinate,
                    observed.request_sequence,
                )
                .map_err(|error| storage_error("construct block request opportunity", error))?;
                let actions = self.evaluate_phase(&opportunity)?;
                let partial = self.after_evaluation(
                    "resolve block request phase",
                    resolve_block_fault_directive(
                        &self.world,
                        &target,
                        &request,
                        observed.request_sequence,
                        &opportunity,
                        self.context,
                        actions.iter(),
                    ),
                )?;
                self.after_evaluation(
                    "compose block request phases",
                    merge_block_fault_phase_directive(&mut directive, phase, partial),
                )?;
            }
        }
        directive.execution_nanos = request_nanos;
        self.after_evaluation(
            "install block admission directive",
            servicer.install_storage_fault_directive(request.identity(), directive),
        )
    }

    fn settle_opportunities(
        &mut self,
        servicer: &mut QemuLiveBlockIoServicer,
        guest_icount: u64,
        now_nanos: u64,
        aggregate: &mut QemuLiveBlockIoServiceStep,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        for _ in 0..HARD_STORAGE_SETTLE_STEPS {
            let mut installed = false;
            while let Some(opportunity) = servicer.next_storage_execution_opportunity(now_nanos) {
                let coordinate = FaultCoordinate {
                    virtual_nanos: opportunity.ready_nanos,
                    retired_instructions: Some(
                        self.retired_instructions_at(opportunity.ready_nanos, guest_icount)?,
                    ),
                };
                let mut directive = opportunity.admission.clone();
                for target in self.request_targets(&opportunity.request) {
                    let fault_opportunity = block_request_fault_opportunity(
                        target.clone(),
                        &opportunity.request,
                        opportunity.wire_digest,
                        FaultPhase::Resolve,
                        coordinate,
                        opportunity.request_sequence,
                    )
                    .map_err(|error| storage_error("construct block resolve opportunity", error))?;
                    let actions = self.evaluate_phase(&fault_opportunity)?;
                    let partial = self.after_evaluation(
                        "resolve block resolve phase",
                        resolve_block_fault_directive(
                            &self.world,
                            &target,
                            &opportunity.request,
                            opportunity.request_sequence,
                            &fault_opportunity,
                            self.context,
                            actions.iter(),
                        ),
                    )?;
                    self.after_evaluation(
                        "compose block resolve phase",
                        merge_block_fault_phase_directive(
                            &mut directive,
                            FaultPhase::Resolve,
                            partial,
                        ),
                    )?;
                }
                directive.execution_nanos = opportunity.ready_nanos;
                self.after_evaluation(
                    "install block resolve directive",
                    servicer.install_storage_execution_directive(ResolvedBlockExecutionDirective {
                        opportunity,
                        directive,
                    }),
                )?;
                installed = true;
            }
            while let Some(opportunity) =
                servicer.next_storage_request_persistence_opportunity(now_nanos)
            {
                let coordinate = FaultCoordinate {
                    virtual_nanos: opportunity.ready_nanos,
                    retired_instructions: Some(
                        self.retired_instructions_at(opportunity.ready_nanos, guest_icount)?,
                    ),
                };
                let mut directive = opportunity.resolved.clone();
                for target in self.request_targets(&opportunity.request) {
                    let fault_opportunity = block_request_persistence_fault_opportunity(
                        target.clone(),
                        &opportunity,
                        coordinate,
                    )
                    .map_err(|error| storage_error("construct block persist opportunity", error))?;
                    let actions = self.evaluate_phase(&fault_opportunity)?;
                    let partial = self.after_evaluation(
                        "resolve block persist phase",
                        resolve_block_fault_directive(
                            &self.world,
                            &target,
                            &opportunity.request,
                            opportunity.request_sequence,
                            &fault_opportunity,
                            self.context,
                            actions.iter(),
                        ),
                    )?;
                    self.after_evaluation(
                        "compose block persist phase",
                        merge_block_fault_phase_directive(
                            &mut directive,
                            FaultPhase::Persist,
                            partial,
                        ),
                    )?;
                }
                directive.execution_nanos = opportunity.ready_nanos;
                if !directive.persistence_transforms.is_empty() {
                    directive.persistence_admitted_nanos = opportunity.ready_nanos;
                }
                self.after_evaluation(
                    "install block persist directive",
                    servicer.install_storage_request_persistence_directive(
                        ResolvedBlockRequestPersistenceDirective {
                            opportunity,
                            directive,
                        },
                    ),
                )?;
                installed = true;
            }
            while let Some(opportunity) = servicer.next_storage_persistence_opportunity(now_nanos) {
                let coordinate = FaultCoordinate {
                    virtual_nanos: opportunity.ready_nanos,
                    retired_instructions: Some(
                        self.retired_instructions_at(opportunity.ready_nanos, guest_icount)?,
                    ),
                };
                let mut flash_rules = Vec::new();
                for target in self.range_targets(opportunity.offset, opportunity.count) {
                    let fault_opportunity = block_persistence_fault_opportunity(
                        target.clone(),
                        &opportunity,
                        coordinate,
                    )
                    .map_err(|error| {
                        storage_error("construct physical persistence opportunity", error)
                    })?;
                    let actions = self.persistent_flash_actions(&target)?;
                    let mut partial = resolve_block_persistence_media_directive(
                        &self.world,
                        &target,
                        &opportunity,
                        &fault_opportunity,
                        self.context,
                        actions.iter(),
                    )
                    .map_err(|error| storage_error("resolve physical persistence", error))?;
                    flash_rules.append(&mut partial.flash_rules);
                }
                flash_rules.sort_by_key(|rule| rule.contributor);
                let directive = crucible_device::block::ResolvedBlockPersistenceMediaDirective {
                    opportunity: opportunity.clone(),
                    flash_rules,
                };
                servicer
                    .install_storage_persistence_media_directive(directive)
                    .map_err(|error| {
                        storage_error("install physical persistence directive", error)
                    })?;
                installed = true;
            }
            let delivery = servicer
                .advance_storage_to(guest_icount)
                .map_err(|error| storage_error("advance coordinated block device", error))?;
            absorb_delivery(aggregate, delivery)?;
            self.record_device_outcomes(servicer, guest_icount)?;
            let mut delivery_installed = false;
            while let Some(opportunity) = servicer.next_storage_delivery_opportunity(now_nanos) {
                let coordinate = FaultCoordinate {
                    virtual_nanos: opportunity.ready_nanos,
                    retired_instructions: Some(
                        self.retired_instructions_at(opportunity.ready_nanos, guest_icount)?,
                    ),
                };
                let mut directive = opportunity.resolved.clone();
                for target in self.request_targets(&opportunity.request) {
                    let fault_opportunity =
                        block_delivery_fault_opportunity(target.clone(), &opportunity, coordinate)
                            .map_err(|error| {
                                storage_error("construct block delivery opportunity", error)
                            })?;
                    let actions = self.evaluate_phase(&fault_opportunity)?;
                    let partial = self.after_evaluation(
                        "resolve block delivery phase",
                        resolve_block_fault_directive(
                            &self.world,
                            &target,
                            &opportunity.request,
                            opportunity.request_sequence,
                            &fault_opportunity,
                            self.context,
                            actions.iter(),
                        ),
                    )?;
                    self.after_evaluation(
                        "compose block delivery phase",
                        merge_block_fault_phase_directive(
                            &mut directive,
                            FaultPhase::Deliver,
                            partial,
                        ),
                    )?;
                }
                self.after_evaluation(
                    "install block delivery directive",
                    servicer.install_storage_delivery_directive(ResolvedBlockDeliveryDirective {
                        opportunity,
                        directive,
                    }),
                )?;
                delivery_installed = true;
                installed = true;
            }
            if delivery_installed {
                let delivery = servicer.advance_storage_to(guest_icount).map_err(|error| {
                    storage_error("publish coordinated block completion", error)
                })?;
                absorb_delivery(aggregate, delivery)?;
                self.record_device_outcomes(servicer, guest_icount)?;
            }
            if !installed {
                return Ok(());
            }
        }
        Err(storage_error(
            "settle block fault opportunities",
            "storage opportunity transitions exceeded the hard bound",
        ))
    }
}

impl QemuBlockFaultCoordinator for ProductionBlockFaultCoordinator {
    fn apply_boundary_actions(
        &mut self,
        servicer: &mut QemuLiveBlockIoServicer,
        _coordinate: FaultCoordinate,
        evaluation_sequence: u64,
        actions: &[ResolvedBindingAction],
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let matching = actions
            .iter()
            .filter(|action| self.targets_attached_device(&action.target))
            .collect::<Vec<_>>();
        let mut staged = servicer.storage_fault_state().clone();
        let mut selected = Vec::new();
        let mut observations = Vec::new();
        for action in matching {
            match action.effect.specification() {
                EffectSpecification::Storage(StorageEffectSpecification::VolatileCacheLoss {
                    ..
                }) => {
                    let resolved = resolve_volatile_cache_loss(
                        &action.target,
                        &staged,
                        self.context,
                        action,
                        VolatileCacheLossReplay::Record,
                    )
                    .map_err(|error| {
                        storage_error("resolve volatile-cache loss boundary", error)
                    })?;
                    staged
                        .lose_volatile(&resolved.selected_sequences)
                        .map_err(|error| storage_error("stage volatile-cache loss", error))?;
                    selected.extend(resolved.selected_sequences.iter().copied());
                    observations.push(FaultObservation {
                        semantic_version: FAULT_RUNTIME_STATE_VERSION,
                        kind: FaultObservationKind::EffectApplied,
                        coordinate: action.coordinate,
                        binding: Some(action.binding.clone()),
                        target: Some(action.target.clone()),
                        opportunity: action.opportunity,
                        evidence: volatile_cache_loss_evidence(&resolved),
                    });
                }
                EffectSpecification::Storage(_) => {
                    return Err(storage_error(
                        "apply storage boundary action",
                        format!(
                            "storage effect `{}` has no block boundary mutation",
                            action.effect.kind().as_str()
                        ),
                    ));
                }
                _ => {
                    return Err(storage_error(
                        "apply storage boundary action",
                        "non-storage action crossed the block adapter boundary",
                    ));
                }
            }
        }
        if selected.is_empty() && observations.is_empty() {
            return Ok(());
        }
        let mut queued = self.observations.lock().map_err(|_| {
            storage_error(
                "record volatile-cache loss boundary",
                "storage observation queue lock is poisoned",
            )
        })?;
        queued.ensure_capacity(observations.len())?;
        servicer
            .lose_storage_volatile(&selected)
            .map_err(|error| storage_error("apply volatile-cache loss boundary", error))?;
        queued.append(evaluation_sequence, observations)
    }

    fn service_block_io(
        &mut self,
        servicer: &mut QemuLiveBlockIoServicer,
        guest_icount: u64,
    ) -> Result<QemuLiveBlockIoServiceStep, QemuAsyncDriverRuntimeError> {
        let now_nanos = self.virtual_nanos(guest_icount)?;
        let recovery_events = self
            .runtime
            .lock()
            .map_err(|_| {
                storage_error(
                    "read storage recovery events",
                    "fault runtime lock is poisoned",
                )
            })?
            .emitted_events()
            .iter()
            .filter(|event| event.coordinate.virtual_nanos <= now_nanos)
            .map(|event| {
                (
                    event.signal.clone(),
                    event.coordinate.virtual_nanos,
                    event.evidence,
                )
            })
            .collect::<Vec<_>>();
        let mut releases = std::collections::BTreeMap::new();
        for (signal, event_nanos, event_evidence) in recovery_events {
            let signal = crucible::model::FaultObjectId::parse(signal.as_str())
                .map_err(|error| storage_error("resolve storage recovery event", error))?;
            let key = storage_recovery_event_key(&signal);
            for identity in servicer
                .storage_fault_state()
                .retained_recoveries_for(key, event_nanos)
            {
                let retained = servicer
                    .storage_fault_state()
                    .retained_completion(identity)
                    .ok_or_else(|| {
                        storage_error(
                            "select recovered block completion",
                            "retained completion disappeared during selection",
                        )
                    })?;
                if event_nanos <= retained.timeout_nanos {
                    releases
                        .entry(identity)
                        .and_modify(|selected: &mut (BlockRetainedRelease, u64, ContentHash)| {
                            if event_nanos < selected.1 {
                                *selected =
                                    (BlockRetainedRelease::Recovery, event_nanos, event_evidence);
                            }
                        })
                        .or_insert((BlockRetainedRelease::Recovery, event_nanos, event_evidence));
                }
            }
        }
        for identity in servicer
            .storage_fault_state()
            .retained_timeouts_due(now_nanos)
        {
            let retained = servicer
                .storage_fault_state()
                .retained_completion(identity)
                .ok_or_else(|| {
                    storage_error(
                        "select timed-out block completion",
                        "retained completion disappeared during selection",
                    )
                })?;
            releases.entry(identity).or_insert_with(|| {
                (
                    BlockRetainedRelease::Timeout,
                    retained.timeout_nanos,
                    retained_release_evidence(
                        identity,
                        BlockRetainedRelease::Timeout,
                        retained.timeout_nanos,
                        None,
                    ),
                )
            });
        }
        if !releases.is_empty() {
            let device_releases = releases
                .iter()
                .map(|(identity, (release, _, _))| (*identity, *release))
                .collect::<Vec<_>>();
            let mut cursor = self.cursor.lock().map_err(|_| {
                storage_error(
                    "sequence retained block releases",
                    "production fault evaluation cursor lock is poisoned",
                )
            })?;
            let mut journal = self.observations.lock().map_err(|_| {
                storage_error(
                    "record retained block releases",
                    "storage observation queue lock is poisoned",
                )
            })?;
            let mut staged_cursor = *cursor;
            let mut staged_journal = journal.clone();
            let mut batches = Vec::with_capacity(releases.len());
            for (identity, (release, release_nanos, cause)) in &releases {
                let sequence = staged_cursor
                    .next_sequence(*release_nanos)
                    .map_err(|error| storage_error("sequence retained block release", error))?;
                batches.push((
                    sequence,
                    FaultObservation {
                        semantic_version: FAULT_RUNTIME_STATE_VERSION,
                        kind: FaultObservationKind::EffectApplied,
                        coordinate: FaultCoordinate {
                            virtual_nanos: *release_nanos,
                            retired_instructions: Some(
                                self.retired_instructions_at(*release_nanos, guest_icount)?,
                            ),
                        },
                        binding: None,
                        target: Some(self.target.clone()),
                        opportunity: None,
                        evidence: retained_release_evidence(
                            *identity,
                            *release,
                            *release_nanos,
                            Some(*cause),
                        ),
                    },
                ));
            }
            staged_journal.append_batches(batches)?;
            servicer
                .release_storage_completions(&device_releases)
                .map_err(|error| storage_error("release retained block completions", error))?;
            *cursor = staged_cursor;
            *journal = staged_journal;
        }
        self.record_device_outcomes(servicer, guest_icount)?;
        self.admit_head_request(servicer)?;
        let intake = servicer
            .process_one_storage_request()
            .map_err(|error| storage_error("consume coordinated block request", error))?;
        let mut aggregate = QemuLiveBlockIoServiceStep::default();
        absorb_intake(&mut aggregate, intake)?;
        self.settle_opportunities(servicer, guest_icount, now_nanos, &mut aggregate)?;
        Ok(aggregate)
    }
}

fn absorb_intake(
    aggregate: &mut QemuLiveBlockIoServiceStep,
    intake: QemuLiveBlockIoIntakeStep,
) -> Result<(), QemuAsyncDriverRuntimeError> {
    aggregate.processed = aggregate
        .processed
        .checked_add(intake.processed)
        .ok_or_else(|| {
            storage_error(
                "account coordinated block service",
                "request count overflow",
            )
        })?;
    aggregate.write_frames_processed = aggregate
        .write_frames_processed
        .checked_add(intake.write_frames_processed)
        .ok_or_else(|| {
            storage_error("account coordinated block service", "write count overflow")
        })?;
    aggregate.first_request_icount = aggregate
        .first_request_icount
        .or(intake.first_request_icount);
    aggregate.computed_completion_icount = aggregate
        .computed_completion_icount
        .or(intake.computed_completion_icount);
    aggregate.next_completion_icount = intake.next_completion_icount;
    Ok(())
}

fn absorb_delivery(
    aggregate: &mut QemuLiveBlockIoServiceStep,
    delivery: QemuLiveBlockIoDeliveryStep,
) -> Result<(), QemuAsyncDriverRuntimeError> {
    aggregate.delivered = aggregate
        .delivered
        .checked_add(delivery.delivered)
        .ok_or_else(|| {
            storage_error(
                "account coordinated block service",
                "delivery count overflow",
            )
        })?;
    aggregate.next_completion_icount = delivery.next_completion_icount;
    Ok(())
}

fn block_targets_same_device(left: &ResolvedFaultTarget, right: &ResolvedFaultTarget) -> bool {
    let device = |target: &ResolvedFaultTarget| match target {
        ResolvedFaultTarget::BlockDevice { device }
        | ResolvedFaultTarget::BlockRange { device, .. } => Some(*device),
        _ => None,
    };
    device(left)
        .zip(device(right))
        .is_some_and(|(left, right)| left == right)
}

fn block_target_intersects_request(target: &ResolvedFaultTarget, request: &BlockRequest) -> bool {
    match request.op {
        BlockOp::Read | BlockOp::Write | BlockOp::Discard => {
            block_target_intersects_range(target, request.offset, u64::from(request.count))
        }
        BlockOp::Flush | BlockOp::GetLength => matches!(
            target,
            ResolvedFaultTarget::BlockDevice { .. } | ResolvedFaultTarget::BlockRange { .. }
        ),
    }
}

fn block_target_intersects_range(target: &ResolvedFaultTarget, offset: u64, length: u64) -> bool {
    match target {
        ResolvedFaultTarget::BlockDevice { .. } => true,
        ResolvedFaultTarget::BlockRange {
            start_byte,
            length_bytes,
            ..
        } => offset
            .checked_add(length)
            .zip(start_byte.checked_add(*length_bytes))
            .is_some_and(|(end, target_end)| offset < target_end && *start_byte < end),
        _ => false,
    }
}

fn retained_release_evidence(
    identity: crucible_device::block::BlockRequestIdentity,
    release: BlockRetainedRelease,
    release_nanos: u64,
    cause: Option<ContentHash>,
) -> ContentHash {
    let release = match release {
        BlockRetainedRelease::Recovery => "recovery",
        BlockRetainedRelease::Timeout => "timeout",
    };
    ContentHash::from_canonical_material(
        "crucible.storage-retained-release-evidence.v1",
        &format!(
            "epoch={}\nrequest_id={}\nrelease={release}\nrelease_nanos={release_nanos}\ncause={}",
            identity.epoch,
            identity.request_id,
            cause.map_or_else(|| String::from("none"), |value| value.to_hex()),
        ),
    )
}

fn volatile_cache_loss_evidence(resolved: &ResolvedVolatileCacheLoss) -> ContentHash {
    let list = |values: &[u64]| {
        values
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    ContentHash::from_canonical_material(
        "crucible.storage-volatile-cache-loss-evidence.v1",
        &format!(
            "entry_set_digest={}\neligible={}\nprotected={}\nselected={}\ndurable_frontier_before={}\ndurable_frontier_after={}",
            ContentHash {
                bytes: resolved.entry_set_digest
            }
            .to_hex(),
            list(&resolved.eligible_sequences),
            list(&resolved.protected_sequences),
            list(&resolved.selected_sequences),
            resolved.durable_frontier_before,
            resolved.durable_frontier_after,
        ),
    )
}

fn persistence_media_evidence(outcome: &BlockPersistenceMediaOutcome) -> ContentHash {
    let spans = outcome
        .applied_spans
        .iter()
        .map(|span| format!("{}:{}", span.start, span.length))
        .collect::<Vec<_>>()
        .join(",");
    ContentHash::from_canonical_material(
        "crucible.storage-persistence-media-evidence.v1",
        &format!(
            "sequence={}\nrequest_id={}\noperation_sequence={}\noperation={}\nrequest_digest={}\noffset={}\ncount={}\nintended_digest={}\nready_nanos={}\nexecuted_nanos={}\napplied_spans={}\nmedia_failed={}\napplied_digest={}",
            outcome.opportunity.sequence,
            outcome.opportunity.request_id,
            outcome.opportunity.operation_sequence,
            outcome.opportunity.operation.to_wire(),
            ContentHash {
                bytes: outcome.opportunity.request_digest
            }
            .to_hex(),
            outcome.opportunity.offset,
            outcome.opportunity.count,
            ContentHash {
                bytes: outcome.opportunity.intended_digest
            }
            .to_hex(),
            outcome.opportunity.ready_nanos,
            outcome.executed_nanos,
            spans,
            outcome.media_failed,
            ContentHash {
                bytes: outcome.applied_digest
            }
            .to_hex(),
        ),
    )
}

fn storage_service_evidence(outcome: &BlockServiceCompletion) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.storage-service-evidence.v1",
        &format!(
            "contributor={}\nsequence={}\nstarted_nanos={}\nfinished_nanos={}\nbusy_epoch_bytes={}\nbusy_epoch_operations={}",
            ContentHash {
                bytes: outcome.contributor
            }
            .to_hex(),
            outcome.sequence,
            outcome.started_nanos,
            outcome.finished_nanos,
            outcome.busy_epoch_bytes,
            outcome.busy_epoch_operations,
        ),
    )
}

fn storage_error(
    operation: &'static str,
    error: impl std::fmt::Display,
) -> QemuAsyncDriverRuntimeError {
    QemuAsyncDriverRuntimeError::new(operation, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(evidence: &'static [u8]) -> FaultObservation {
        FaultObservation {
            semantic_version: FAULT_RUNTIME_STATE_VERSION,
            kind: FaultObservationKind::EffectApplied,
            coordinate: FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            binding: None,
            target: None,
            opportunity: None,
            evidence: ContentHash::from_bytes(evidence),
        }
    }

    #[test]
    fn observation_journal_drains_batches_in_global_sequence_order() {
        let earlier = observation(b"authorizing-evaluation");
        let same_sequence = observation(b"authorized-mutation");
        let later = observation(b"later");
        let mut journal = ProductionFaultObservationJournal::default();

        journal
            .append(9, vec![later.clone()])
            .unwrap_or_else(|error| panic!("later observation should append: {error}"));
        journal
            .append(3, vec![earlier.clone()])
            .unwrap_or_else(|error| panic!("earlier observations should append: {error}"));
        journal
            .append(3, vec![same_sequence.clone()])
            .unwrap_or_else(|error| panic!("same-sequence mutation should append: {error}"));

        assert_eq!(journal.snapshot(), vec![earlier, same_sequence, later]);
        journal.clear();
        assert!(journal.is_empty());
        assert!(journal.snapshot().is_empty());
    }

    #[test]
    fn observation_journal_rolls_back_one_boundary_sequence_exactly() {
        let retained = observation(b"retained-before-boundary");
        let evaluation = observation(b"rolled-back-evaluation");
        let mutation = observation(b"rolled-back-mutation");
        let mut journal = ProductionFaultObservationJournal::default();
        journal
            .append(4, vec![retained.clone()])
            .unwrap_or_else(|error| panic!("prior observation should append: {error}"));
        journal
            .append(5, vec![evaluation, mutation])
            .unwrap_or_else(|error| panic!("boundary observations should append: {error}"));

        journal
            .rollback_sequence(5)
            .unwrap_or_else(|error| panic!("boundary sequence should roll back: {error}"));

        assert_eq!(journal.snapshot(), vec![retained]);
        assert!(!journal.contains_sequence(5));
    }
}
