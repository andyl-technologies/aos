//! Production signal coordination for live World-backed block devices.
//!
//! The coordinator owns the exact seams around the shared-memory block
//! servicer. It evaluates one authenticated opportunity per authored phase and
//! never substitutes an implicit fault-free result after scheduler admission.

use std::sync::{Arc, Mutex};

use super::*;

use crucible::model::{
    ContentHash, EffectSpecification, FaultCoordinate, FaultObservation, FaultPhase,
    ResolvedBindingAction, ResolvedFaultTarget, StorageEffectSpecification, World, WorldIoNodeKind,
};
use crucible_device::block::{
    BaseImage, BlockDurabilityConfig, ResolvedBlockExecutionDirective,
    ResolvedBlockRequestPersistenceDirective,
};
use crucible_qemu::{
    ProductionFaultRuntime, QemuAsyncDriverRuntimeError, QemuBlockFaultCoordinator,
    QemuLiveBlockIoDeliveryStep, QemuLiveBlockIoIntakeStep, QemuLiveBlockIoServiceStep,
    QemuLiveBlockIoServicer, StorageFaultResolutionContext, block_durability_config,
    block_persistence_fault_opportunity, block_request_fault_opportunity,
    block_request_persistence_fault_opportunity, merge_block_fault_phase_directive,
    resolve_block_fault_directive, resolve_block_persistence_media_directive,
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

/// Durable observation queue drained by the lifecycle immediately after advance.
pub(super) type ProductionStorageObservations = Arc<Mutex<Vec<FaultObservation>>>;

/// Coordinates one live block servicer with the authoritative signal runtime.
pub(super) struct ProductionBlockFaultCoordinator {
    runtime: Arc<Mutex<ProductionFaultRuntime>>,
    cursor: SharedProductionFaultEvaluationCursor,
    observations: ProductionStorageObservations,
    world: World,
    target: ResolvedFaultTarget,
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
        scenario_seed: ContentHash,
        icount_shift: u8,
    ) -> Self {
        Self {
            runtime,
            cursor,
            observations,
            world,
            target,
            context: StorageFaultResolutionContext::new(scenario_seed),
            icount_shift,
        }
    }

    fn virtual_nanos(&self, icount: u64) -> Result<u64, QemuAsyncDriverRuntimeError> {
        icount
            .checked_shl(u32::from(self.icount_shift))
            .ok_or_else(|| storage_error("convert block icount", "virtual time overflow"))
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
        if impulses
            .iter()
            .any(|action| action.target != self.target || action.phase != opportunity.phase())
        {
            runtime.poison();
            return Err(storage_error(
                "evaluate block fault opportunity",
                "host impulse escaped its exact storage target or phase",
            ));
        }
        let mut actions = runtime
            .host_state()
            .matching(&self.target, opportunity.phase())
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
        if observations
            .len()
            .checked_add(evaluation.observations.len())
            .is_none_or(|count| count > HARD_STORAGE_FAULT_OBSERVATIONS)
        {
            runtime.poison();
            return Err(storage_error(
                "record block fault observations",
                "storage observation queue exceeds its hard bound",
            ));
        }
        observations.extend(evaluation.observations);
        drop(runtime);
        Ok(actions)
    }

    fn persistent_flash_actions(
        &self,
    ) -> Result<Vec<ResolvedBindingAction>, QemuAsyncDriverRuntimeError> {
        let runtime = self.runtime.lock().map_err(|_| {
            storage_error(
                "resolve physical storage persistence",
                "production fault runtime lock is poisoned",
            )
        })?;
        Ok(runtime
            .host_state()
            .matching(&self.target, FaultPhase::Persist)
            .filter(|action| {
                matches!(
                    action.effect.specification(),
                    EffectSpecification::Storage(StorageEffectSpecification::FlashState { .. })
                )
            })
            .cloned()
            .collect())
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
            let opportunity = block_request_fault_opportunity(
                self.target.clone(),
                &request,
                observed.wire_digest,
                phase,
                coordinate,
                observed.request_sequence,
            )
            .map_err(|error| storage_error("construct block request opportunity", error))?;
            let actions = self.evaluate_phase(&opportunity)?;
            let partial = resolve_block_fault_directive(
                &self.world,
                &self.target,
                &request,
                observed.request_sequence,
                &opportunity,
                self.context,
                actions.iter(),
            )
            .map_err(|error| storage_error("resolve block request phase", error))?;
            merge_block_fault_phase_directive(&mut directive, phase, partial)
                .map_err(|error| storage_error("compose block request phases", error))?;
        }
        directive.execution_nanos = request_nanos;
        servicer
            .install_storage_fault_directive(request.request_id, directive)
            .map_err(|error| storage_error("install block admission directive", error))
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
                    retired_instructions: Some(guest_icount),
                };
                let fault_opportunity = block_request_fault_opportunity(
                    self.target.clone(),
                    &opportunity.request,
                    opportunity.wire_digest,
                    FaultPhase::Resolve,
                    coordinate,
                    opportunity.request_sequence,
                )
                .map_err(|error| storage_error("construct block resolve opportunity", error))?;
                let actions = self.evaluate_phase(&fault_opportunity)?;
                let partial = resolve_block_fault_directive(
                    &self.world,
                    &self.target,
                    &opportunity.request,
                    opportunity.request_sequence,
                    &fault_opportunity,
                    self.context,
                    actions.iter(),
                )
                .map_err(|error| storage_error("resolve block resolve phase", error))?;
                let mut directive = opportunity.admission.clone();
                merge_block_fault_phase_directive(&mut directive, FaultPhase::Resolve, partial)
                    .map_err(|error| storage_error("compose block resolve phase", error))?;
                directive.execution_nanos = opportunity.ready_nanos;
                servicer
                    .install_storage_execution_directive(ResolvedBlockExecutionDirective {
                        opportunity,
                        directive,
                    })
                    .map_err(|error| storage_error("install block resolve directive", error))?;
                installed = true;
            }
            while let Some(opportunity) =
                servicer.next_storage_request_persistence_opportunity(now_nanos)
            {
                let coordinate = FaultCoordinate {
                    virtual_nanos: opportunity.ready_nanos,
                    retired_instructions: Some(guest_icount),
                };
                let fault_opportunity = block_request_persistence_fault_opportunity(
                    self.target.clone(),
                    &opportunity,
                    coordinate,
                )
                .map_err(|error| storage_error("construct block persist opportunity", error))?;
                let actions = self.evaluate_phase(&fault_opportunity)?;
                let partial = resolve_block_fault_directive(
                    &self.world,
                    &self.target,
                    &opportunity.request,
                    opportunity.request_sequence,
                    &fault_opportunity,
                    self.context,
                    actions.iter(),
                )
                .map_err(|error| storage_error("resolve block persist phase", error))?;
                let mut directive = opportunity.resolved.clone();
                merge_block_fault_phase_directive(&mut directive, FaultPhase::Persist, partial)
                    .map_err(|error| storage_error("compose block persist phase", error))?;
                directive.execution_nanos = opportunity.ready_nanos;
                if !directive.persistence_transforms.is_empty() {
                    directive.persistence_admitted_nanos = opportunity.ready_nanos;
                }
                servicer
                    .install_storage_request_persistence_directive(
                        ResolvedBlockRequestPersistenceDirective {
                            opportunity,
                            directive,
                        },
                    )
                    .map_err(|error| storage_error("install block persist directive", error))?;
                installed = true;
            }
            while let Some(opportunity) = servicer.next_storage_persistence_opportunity(now_nanos) {
                let coordinate = FaultCoordinate {
                    virtual_nanos: opportunity.ready_nanos,
                    retired_instructions: Some(guest_icount),
                };
                let fault_opportunity = block_persistence_fault_opportunity(
                    self.target.clone(),
                    &opportunity,
                    coordinate,
                )
                .map_err(|error| {
                    storage_error("construct physical persistence opportunity", error)
                })?;
                let actions = self.persistent_flash_actions()?;
                let directive = resolve_block_persistence_media_directive(
                    &self.world,
                    &self.target,
                    &opportunity,
                    &fault_opportunity,
                    self.context,
                    actions.iter(),
                )
                .map_err(|error| storage_error("resolve physical persistence", error))?;
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
    fn service_block_io(
        &mut self,
        servicer: &mut QemuLiveBlockIoServicer,
        guest_icount: u64,
    ) -> Result<QemuLiveBlockIoServiceStep, QemuAsyncDriverRuntimeError> {
        let now_nanos = self.virtual_nanos(guest_icount)?;
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

fn storage_error(
    operation: &'static str,
    error: impl std::fmt::Display,
) -> QemuAsyncDriverRuntimeError {
    QemuAsyncDriverRuntimeError::new(operation, error.to_string())
}
