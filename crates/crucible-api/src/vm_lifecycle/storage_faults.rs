//! Production signal coordination for live World-backed block devices.
//!
//! The coordinator owns the exact seams around the shared-memory block
//! servicer. It evaluates one authenticated opportunity per authored phase and
//! never substitutes an implicit fault-free result after scheduler admission.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::*;

use crucible::model::{
    ContentHash, EffectSpecification, FAULT_RUNTIME_STATE_VERSION, FaultCoordinate,
    FaultObservation, FaultObservationKind, FaultOperation, FaultOpportunity, FaultPhase,
    FaultSignalPlan, NinePResultKind, OpportunityPayload, ResolvedBindingAction,
    ResolvedFaultTarget, StorageEffectSpecification, StoragePolicyArtifactKind,
    StoragePolicyNinePVisibilityScope, World, WorldIoNodeKind,
};
use crucible_device::block::{
    BaseImage, BlockDurabilityConfig, BlockFaultMisdirectionDestination, BlockFaultReadTransform,
    BlockFaultWriteDisposition, BlockOp, BlockPersistenceMediaOutcome, BlockRequest,
    BlockRetainedRelease, BlockServiceCompletion, BlockStorageOutcome,
    ResolvedBlockDeliveryDirective, ResolvedBlockExecutionDirective,
    ResolvedBlockRequestPersistenceDirective,
};
use crucible_device::{
    FsTree, NinepLatency, NinepObjectVersion, NinepOperation, NinepRequestOpportunity,
    NinepResultDirective, NinepVisibilityLookup, NinepVisibilityPolicy, NinepVisibilityRelease,
    NinepVisibilityScope, NinepVisibilityState, NinepVisibilityUpdate,
    ResolvedNinepRequestDirective,
};
use crucible_qemu::{
    ProductionFaultRuntime, QemuAsyncDriverRuntimeError, QemuBlockFaultCoordinator,
    QemuLive9pIoServiceStep, QemuLive9pIoServicer, QemuLive9pResponseEvidence,
    QemuLiveBlockIoDeliveryStep, QemuLiveBlockIoIntakeStep, QemuLiveBlockIoServiceStep,
    QemuLiveBlockIoServicer, QemuNinepFaultCoordinator, QemuSharedBlockDevice,
    ResolvedVolatileCacheLoss, StorageArrayError, StorageFaultResolutionContext,
    StorageFaultResolutionError, VolatileCacheLossReplay, block_delivery_fault_opportunity,
    block_durability_config, block_persistence_fault_opportunity, block_request_fault_opportunity,
    block_request_persistence_fault_opportunity, merge_block_fault_phase_directive,
    plan_storage_array_write, read_storage_array, resolve_block_controller_transition,
    resolve_block_fault_directive, resolve_block_persistence_media_directive,
    resolve_storage_array_policy, resolve_volatile_cache_loss, storage_recovery_event_key,
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
    /// Immutable World hash indexing the authoritative live device.
    device_hash: ContentHash,
}

impl ProductionBlockBinding {
    pub(super) fn device_hash(&self) -> ContentHash {
        self.device_hash
    }
}

/// Authenticated World material retained for one production 9p device.
#[derive(Clone)]
pub(super) struct ProductionNinepBinding {
    /// Immutable filesystem tree passed to the live servicer.
    pub(super) tree: FsTree,
    /// Deterministic World-declared latency model.
    pub(super) latency: NinepLatency,
    /// Resolved signal target for typed 9p opportunities.
    pub(super) target: ResolvedFaultTarget,
    /// Immutable World hash indexing the device.
    device_hash: ContentHash,
}

impl ProductionNinepBinding {
    pub(super) const fn device_hash(&self) -> ContentHash {
        self.device_hash
    }
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
        device_hash: node.fault_target_hash(),
    }))
}

/// Resolves the optional 9p device owned by one World VM.
pub(super) fn ninep_binding_for_vm(
    world: &World,
    vm: &crucible::NodeId,
    artifacts: Option<&Arc<dyn crucible::model::DagStore>>,
) -> Result<Option<ProductionNinepBinding>, LifecycleApiError> {
    let devices = world
        .io_nodes()
        .filter(|node| node.owner == *vm && matches!(node.kind, WorldIoNodeKind::NineP { .. }))
        .collect::<Vec<_>>();
    if devices.len() > 1 {
        return Err(loop_factory_error(format!(
            "QEMU node `{}` declares {} 9p devices but the shared-memory transport has one 9p executor slot",
            vm.name,
            devices.len()
        )));
    }
    let Some(node) = devices.first().copied() else {
        return Ok(None);
    };
    let WorldIoNodeKind::NineP {
        tree: artifact,
        latency,
    } = &node.kind
    else {
        return Err(loop_factory_error("selected World 9p node changed kind"));
    };
    let store = artifacts.ok_or_else(|| {
        loop_factory_error(format!(
            "QEMU node `{}` owns 9p device `{}` but no production World artifact store was configured",
            vm.name, node.id.name
        ))
    })?;
    let bytes = store.get(&artifact.hash()).map_err(|error| {
        loop_factory_error(format!(
            "load 9p tree for `{}` from the World artifact store: {error}",
            node.id.name
        ))
    })?;
    let tree = FsTree::from_canonical_bytes(&bytes).map_err(|error| {
        loop_factory_error(format!(
            "decode canonical 9p tree for `{}`: {error}",
            node.id.name
        ))
    })?;
    let actual = ContentHash {
        bytes: tree.content_hash(),
    };
    if actual != artifact.hash() {
        return Err(loop_factory_error(format!(
            "World 9p tree for `{}` differs from its declared hash",
            node.id.name
        )));
    }
    Ok(Some(ProductionNinepBinding {
        tree,
        latency: NinepLatency::new(latency.control_ns, latency.data_ns, latency.per_byte_ns),
        target: ResolvedFaultTarget::NinePDevice {
            device: node.fault_target_hash(),
        },
        device_hash: node.fault_target_hash(),
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

/// Authoritative live devices indexed by their immutable World target hashes.
pub(super) type ProductionBlockDevices = Arc<Mutex<BTreeMap<ContentHash, QemuSharedBlockDevice>>>;

struct EvaluatedStoragePhase {
    actions: Vec<ResolvedBindingAction>,
    same_coordinate_sequence: u64,
    journal_sequence: u64,
}

/// Coordinates one live block servicer with the authoritative signal runtime.
pub(super) struct ProductionBlockFaultCoordinator {
    runtime: Arc<Mutex<ProductionFaultRuntime>>,
    cursor: SharedProductionFaultEvaluationCursor,
    observations: ProductionStorageObservations,
    devices: ProductionBlockDevices,
    world: World,
    target: ResolvedFaultTarget,
    opportunity_targets: Vec<ResolvedFaultTarget>,
    array_targets: Vec<ResolvedFaultTarget>,
    context: StorageFaultResolutionContext,
    icount_shift: u8,
}

impl ProductionBlockFaultCoordinator {
    /// Binds a World block target to the shared production continuation.
    pub(super) fn new(
        runtime: Arc<Mutex<ProductionFaultRuntime>>,
        cursor: SharedProductionFaultEvaluationCursor,
        observations: ProductionStorageObservations,
        devices: ProductionBlockDevices,
        world: World,
        target: ResolvedFaultTarget,
        signal_plan: &FaultSignalPlan,
        scenario_seed: ContentHash,
        icount_shift: u8,
    ) -> Self {
        let mut opportunity_targets = signal_plan
            .bindings()
            .iter()
            .flat_map(|binding| binding.selector().resolved().targets())
            .filter(|candidate| block_targets_same_device(&target, candidate))
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        opportunity_targets.insert(target.clone());
        let array_targets = signal_plan
            .bindings()
            .iter()
            .flat_map(|binding| binding.selector().resolved().targets())
            .filter(|candidate| {
                matches!(candidate, ResolvedFaultTarget::StorageArray { .. })
                    && storage_array_target_attaches_device(&world, candidate, &target)
            })
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .collect();
        Self {
            runtime,
            cursor,
            observations,
            devices,
            world,
            target,
            opportunity_targets: opportunity_targets.into_iter().collect(),
            array_targets,
            context: StorageFaultResolutionContext::new(scenario_seed),
            icount_shift,
        }
    }

    fn active_array_policy(
        &self,
        actions: &[ResolvedBindingAction],
    ) -> Result<Option<crucible_qemu::ResolvedStorageArrayPolicy>, StorageFaultResolutionError>
    {
        let mut policies = actions
            .iter()
            .filter(|action| {
                matches!(
                    action.effect.specification(),
                    EffectSpecification::Storage(StorageEffectSpecification::ArrayState { .. })
                )
            })
            .map(|action| resolve_storage_array_policy(&self.world, action))
            .collect::<Result<Vec<_>, _>>()?;
        policies.dedup();
        if policies.len() > 1 {
            return Err(StorageFaultResolutionError::UnsupportedTarget);
        }
        Ok(policies.pop())
    }

    fn evaluate_array_phase(
        &mut self,
        request: &BlockRequest,
        request_sequence: u64,
        wire_digest: ContentHash,
        phase: FaultPhase,
        coordinate: FaultCoordinate,
    ) -> Result<Option<crucible_qemu::ResolvedStorageArrayPolicy>, QemuAsyncDriverRuntimeError>
    {
        let mut actions = Vec::new();
        for target in self.array_targets.clone() {
            let opportunity = block_request_fault_opportunity(
                target,
                request,
                wire_digest,
                phase,
                coordinate,
                request_sequence,
            )
            .map_err(|error| storage_error("construct storage array opportunity", error))?;
            actions.extend(self.evaluate_phase(&opportunity)?.actions);
        }
        self.active_array_policy(&actions)
            .map_err(|error| storage_error("resolve storage array policy", error))
    }

    fn compose_array_phase(
        &self,
        directive: &mut crucible_device::block::ResolvedBlockFaultDirective,
        policy: Option<&crucible_qemu::ResolvedStorageArrayPolicy>,
        request: &BlockRequest,
        phase: FaultPhase,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let Some(policy) = policy else {
            return Ok(());
        };
        if request.op == BlockOp::Read && phase == FaultPhase::Resolve {
            match self.array_read_transform(policy, request) {
                Ok(bytes) => directive
                    .read_transforms
                    .push(BlockFaultReadTransform::Replace { bytes }),
                Err(StorageArrayError::QuorumUnavailable) => {
                    directive.error_result = Some(policy.failure_result)
                }
                Err(error) => return Err(storage_error("read storage array", error)),
            }
        }
        Ok(())
    }

    fn array_read_transform(
        &self,
        policy: &crucible_qemu::ResolvedStorageArrayPolicy,
        request: &BlockRequest,
    ) -> Result<Vec<u8>, StorageArrayError> {
        let devices = self
            .devices
            .lock()
            .map_err(|_| StorageArrayError::MemberRead {
                ordinal: 0,
                message: String::from("authoritative block-device registry is poisoned"),
            })?;
        read_storage_array(
            policy,
            request.offset,
            request.count,
            &request
                .encode()
                .map_err(|error| StorageArrayError::MemberRead {
                    ordinal: 0,
                    message: error.to_string(),
                })?,
            &BTreeMap::new(),
            |device, offset, count| {
                devices
                    .get(&device)
                    .cloned()
                    .ok_or_else(|| {
                        format!("World block device {} has no live runtime", device.to_hex())
                    })?
                    .inspect_storage_visible(offset, count)
                    .map_err(|error| error.to_string())
            },
        )
    }

    fn array_write_destinations(
        &self,
        policy: &crucible_qemu::ResolvedStorageArrayPolicy,
        request: &BlockRequest,
    ) -> Result<Vec<(ContentHash, QemuSharedBlockDevice, Vec<(u64, Vec<u8>)>)>, StorageArrayError>
    {
        let devices = self
            .devices
            .lock()
            .map_err(|_| StorageArrayError::MemberRead {
                ordinal: 0,
                message: String::from("authoritative block-device registry is poisoned"),
            })?;
        let plan = plan_storage_array_write(
            policy,
            request.offset,
            &request.data,
            |device, offset, count| {
                devices
                    .get(&device)
                    .cloned()
                    .ok_or_else(|| {
                        format!("World block device {} has no live runtime", device.to_hex())
                    })?
                    .inspect_storage_visible(offset, count)
                    .map_err(|error| error.to_string())
            },
        )?;
        let mut grouped = BTreeMap::<ContentHash, Vec<(u64, Vec<u8>)>>::new();
        for write in plan.writes {
            grouped
                .entry(write.device)
                .or_default()
                .push((write.offset, write.bytes));
        }
        grouped
            .into_iter()
            .map(|(device, writes)| {
                let handle =
                    devices
                        .get(&device)
                        .cloned()
                        .ok_or_else(|| StorageArrayError::MemberRead {
                            ordinal: 0,
                            message: format!(
                                "World block device {} has no live runtime",
                                device.to_hex()
                            ),
                        })?;
                Ok((device, handle, writes))
            })
            .collect()
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

    fn external_durability_satisfied(
        &self,
        opportunity: &crucible_device::block::BlockDeliveryOpportunity,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let devices = self.devices.lock().map_err(|_| {
            storage_error(
                "check cross-device durability",
                "authoritative block-device registry is poisoned",
            )
        })?;
        for dependency in &opportunity.resolved.external_durability_dependencies {
            let destination_id = ContentHash {
                bytes: dependency.destination_device,
            };
            let destination = devices.get(&destination_id).cloned().ok_or_else(|| {
                storage_error(
                    "check cross-device durability",
                    format!(
                        "World block device {} has no authoritative live runtime",
                        destination_id.to_hex()
                    ),
                )
            })?;
            if !destination
                .satisfies_external_durability(*dependency)
                .map_err(|error| storage_error("check cross-device durability", error))?
            {
                return Ok(false);
            }
        }
        Ok(true)
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
    ) -> Result<EvaluatedStoragePhase, QemuAsyncDriverRuntimeError> {
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
        let evaluation =
            match runtime.evaluate_host_opportunity(opportunity, sequence.same_coordinate) {
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
        if let Err(error) = observations.append(sequence.journal, evaluation.observations) {
            runtime.poison();
            return Err(error);
        }
        drop(runtime);
        Ok(EvaluatedStoragePhase {
            actions,
            same_coordinate_sequence: sequence.same_coordinate,
            journal_sequence: sequence.journal,
        })
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
        ) || self.controller_target_attaches_device(target, *attached)
    }

    fn controller_target_attaches_device(
        &self,
        target: &ResolvedFaultTarget,
        attached: ContentHash,
    ) -> bool {
        let ResolvedFaultTarget::StorageController {
            controller,
            namespace_or_path,
        } = target
        else {
            return false;
        };
        let Some(controller) = self
            .world
            .fault_topology()
            .storage_controllers
            .iter()
            .find(|candidate| candidate.id.as_str() == controller.as_str())
        else {
            return false;
        };
        let selected_is_path = controller
            .paths
            .iter()
            .any(|path| path.id.as_str() == namespace_or_path.as_str());
        controller.namespaces.iter().any(|namespace| {
            (selected_is_path || namespace.id.as_str() == namespace_or_path.as_str())
                && self.world.io_nodes().any(|node| {
                    node.id.name == namespace.device.as_str()
                        && node.fault_target_hash() == attached
                })
        })
    }

    fn attached_device_hash(&self) -> Result<ContentHash, QemuAsyncDriverRuntimeError> {
        match self.target {
            ResolvedFaultTarget::BlockDevice { device }
            | ResolvedFaultTarget::BlockRange { device, .. } => Ok(device),
            _ => Err(storage_error(
                "resolve attached block device",
                "production block coordinator target changed to a non-block target",
            )),
        }
    }

    fn resolve_request_directive(
        &self,
        target: &ResolvedFaultTarget,
        request: &BlockRequest,
        request_sequence: u64,
        opportunity: &crucible::model::FaultOpportunity,
        actions: &[ResolvedBindingAction],
    ) -> Result<crucible_device::block::ResolvedBlockFaultDirective, String> {
        let devices = Arc::clone(&self.devices);
        let mut read_source = move |device: ContentHash, offset: u64, count: u32| {
            let handle = devices
                .lock()
                .map_err(|_| String::from("authoritative block-device registry is poisoned"))?
                .get(&device)
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "World block device {} has no authoritative live runtime",
                        device.to_hex()
                    )
                })?;
            handle
                .inspect_storage_visible(offset, count)
                .map_err(|error| error.to_string())
        };
        resolve_block_fault_directive(
            &self.world,
            target,
            request,
            request_sequence,
            opportunity,
            self.context,
            &mut read_source,
            actions,
        )
        .map_err(|error| error.to_string())
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
                Ok(sequence) => sequence.journal,
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
            servicer
                .storage_fault_state()
                .map_err(|error| storage_error("inspect block fault state", error))?
                .config()
                .length_bytes,
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
                let evaluation = self.evaluate_phase(&opportunity)?;
                let mut partial = self.after_evaluation(
                    "resolve block request phase",
                    self.resolve_request_directive(
                        &target,
                        &request,
                        observed.request_sequence,
                        &opportunity,
                        &evaluation.actions,
                    ),
                )?;
                bind_recovery_subscription_sequence(
                    &mut partial,
                    evaluation.same_coordinate_sequence,
                );
                self.after_evaluation(
                    "compose block request phases",
                    merge_block_fault_phase_directive(&mut directive, phase, partial),
                )?;
            }
            let array_policy = self.evaluate_array_phase(
                &request,
                observed.request_sequence,
                observed.wire_digest,
                phase,
                coordinate,
            )?;
            self.compose_array_phase(&mut directive, array_policy.as_ref(), &request, phase)?;
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
            while let Some(opportunity) = servicer
                .next_storage_execution_opportunity(now_nanos)
                .map_err(|error| storage_error("inspect block execution opportunity", error))?
            {
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
                    let evaluation = self.evaluate_phase(&fault_opportunity)?;
                    let mut partial = self.after_evaluation(
                        "resolve block resolve phase",
                        self.resolve_request_directive(
                            &target,
                            &opportunity.request,
                            opportunity.request_sequence,
                            &fault_opportunity,
                            &evaluation.actions,
                        ),
                    )?;
                    bind_recovery_subscription_sequence(
                        &mut partial,
                        evaluation.same_coordinate_sequence,
                    );
                    self.after_evaluation(
                        "compose block resolve phase",
                        merge_block_fault_phase_directive(
                            &mut directive,
                            FaultPhase::Resolve,
                            partial,
                        ),
                    )?;
                }
                let array_policy = self.evaluate_array_phase(
                    &opportunity.request,
                    opportunity.request_sequence,
                    opportunity.wire_digest,
                    FaultPhase::Resolve,
                    coordinate,
                )?;
                self.compose_array_phase(
                    &mut directive,
                    array_policy.as_ref(),
                    &opportunity.request,
                    FaultPhase::Resolve,
                )?;
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
            while let Some(opportunity) = servicer
                .next_storage_request_persistence_opportunity(now_nanos)
                .map_err(|error| storage_error("inspect block persistence opportunity", error))?
            {
                let coordinate = FaultCoordinate {
                    virtual_nanos: opportunity.ready_nanos,
                    retired_instructions: Some(
                        self.retired_instructions_at(opportunity.ready_nanos, guest_icount)?,
                    ),
                };
                let mut directive = opportunity.resolved.clone();
                let mut array_policy = None;
                for target in self.request_targets(&opportunity.request) {
                    let fault_opportunity = block_request_persistence_fault_opportunity(
                        target.clone(),
                        &opportunity,
                        coordinate,
                    )
                    .map_err(|error| storage_error("construct block persist opportunity", error))?;
                    let evaluation = self.evaluate_phase(&fault_opportunity)?;
                    let mut partial = self.after_evaluation(
                        "resolve block persist phase",
                        self.resolve_request_directive(
                            &target,
                            &opportunity.request,
                            opportunity.request_sequence,
                            &fault_opportunity,
                            &evaluation.actions,
                        ),
                    )?;
                    bind_recovery_subscription_sequence(
                        &mut partial,
                        evaluation.same_coordinate_sequence,
                    );
                    self.after_evaluation(
                        "compose block persist phase",
                        merge_block_fault_phase_directive(
                            &mut directive,
                            FaultPhase::Persist,
                            partial,
                        ),
                    )?;
                }
                for target in self.array_targets.clone() {
                    let fault_opportunity = block_request_persistence_fault_opportunity(
                        target,
                        &opportunity,
                        coordinate,
                    )
                    .map_err(|error| {
                        storage_error("construct storage array persist opportunity", error)
                    })?;
                    let evaluation = self.evaluate_phase(&fault_opportunity)?;
                    let resolved = self
                        .active_array_policy(&evaluation.actions)
                        .map_err(|error| storage_error("resolve storage array policy", error))?;
                    if let Some(resolved) = resolved {
                        if let Some(existing) = &array_policy
                            && existing != &resolved
                        {
                            return Err(storage_error(
                                "resolve storage array policy",
                                "multiple active array policies disagree",
                            ));
                        }
                        array_policy = Some(resolved);
                    }
                }
                directive.execution_nanos = opportunity.ready_nanos;
                if !directive.persistence_transforms.is_empty() {
                    directive.persistence_admitted_nanos = opportunity.ready_nanos;
                }
                let resolved = ResolvedBlockRequestPersistenceDirective {
                    opportunity,
                    directive,
                };
                if resolved.opportunity.request.op == BlockOp::Write
                    && let Some(policy) = array_policy
                {
                    let destinations = match self
                        .array_write_destinations(&policy, &resolved.opportunity.request)
                    {
                        Ok(destinations) => destinations,
                        Err(StorageArrayError::QuorumUnavailable) => {
                            let mut failed = resolved;
                            failed.directive.error_result = Some(policy.failure_result);
                            failed.directive.write_disposition = BlockFaultWriteDisposition::Lost;
                            self.after_evaluation(
                                "install failed storage array persistence",
                                servicer.install_storage_request_persistence_directive(failed),
                            )?;
                            installed = true;
                            continue;
                        }
                        Err(error) => {
                            return Err(storage_error("plan storage array persistence", error));
                        }
                    };
                    let source = servicer.shared_device();
                    let source_id = self.attached_device_hash()?;
                    self.after_evaluation(
                        "install storage array persistence",
                        source.install_multi_device_persistence(source_id, &destinations, resolved),
                    )?;
                } else if let BlockFaultWriteDisposition::Misdirected {
                    destination: BlockFaultMisdirectionDestination::ExternalDevice(bytes),
                    ..
                } = &resolved.directive.write_disposition
                {
                    let destination_id = ContentHash { bytes: *bytes };
                    let destination = self
                        .devices
                        .lock()
                        .map_err(|_| {
                            storage_error(
                                "install cross-device block persistence",
                                "authoritative block-device registry is poisoned",
                            )
                        })?
                        .get(&destination_id)
                        .cloned()
                        .ok_or_else(|| {
                            storage_error(
                                "install cross-device block persistence",
                                format!(
                                    "World block device {} has no authoritative live runtime",
                                    destination_id.to_hex()
                                ),
                            )
                        })?;
                    let source = servicer.shared_device();
                    let source_id = self.attached_device_hash()?;
                    self.after_evaluation(
                        "install cross-device block persistence",
                        source.install_cross_device_misdirected_persistence(
                            source_id,
                            &destination,
                            destination_id,
                            resolved,
                        ),
                    )?;
                } else {
                    self.after_evaluation(
                        "install block persist directive",
                        servicer.install_storage_request_persistence_directive(resolved),
                    )?;
                }
                installed = true;
            }
            while let Some(opportunity) = servicer
                .next_storage_persistence_opportunity(now_nanos)
                .map_err(|error| {
                storage_error("inspect physical persistence opportunity", error)
            })? {
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
            while let Some(opportunity) = servicer
                .next_storage_delivery_opportunity(now_nanos)
                .map_err(|error| storage_error("inspect block delivery opportunity", error))?
            {
                // An externally redirected write is not merely delayed by the
                // destination's predicted horizon. Delivery is held until the
                // authoritative destination confirms that the exact cache
                // sequence is inside its actual durable frontier. This also
                // makes equal-coordinate node ordering harmless.
                if !self.external_durability_satisfied(&opportunity)? {
                    break;
                }
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
                    let evaluation = self.evaluate_phase(&fault_opportunity)?;
                    let mut partial = self.after_evaluation(
                        "resolve block delivery phase",
                        self.resolve_request_directive(
                            &target,
                            &opportunity.request,
                            opportunity.request_sequence,
                            &fault_opportunity,
                            &evaluation.actions,
                        ),
                    )?;
                    bind_recovery_subscription_sequence(
                        &mut partial,
                        evaluation.same_coordinate_sequence,
                    );
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
        let mut staged = servicer
            .storage_fault_state()
            .map_err(|error| storage_error("inspect block boundary state", error))?;
        let mut selected = Vec::new();
        let mut controller_transitions = Vec::new();
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
                EffectSpecification::Storage(StorageEffectSpecification::ControllerLifecycle {
                    ..
                }) => {
                    let transition = resolve_block_controller_transition(&self.world, action)
                        .map_err(|error| {
                            storage_error("resolve controller lifecycle boundary", error)
                        })?;
                    let boundary_nanos = action.coordinate.virtual_nanos;
                    let _staged_responses = staged
                        .apply_transport_reset(
                            transition
                                .transport_reset(staged.transport_epoch().unwrap_or(0))
                                .map_err(|error| {
                                    storage_error("stage controller lifecycle boundary", error)
                                })?,
                            boundary_nanos,
                        )
                        .map_err(|error| {
                            storage_error("stage controller lifecycle boundary", error)
                        })?;
                    controller_transitions.push((transition.clone(), boundary_nanos));
                    observations.push(FaultObservation {
                        semantic_version: FAULT_RUNTIME_STATE_VERSION,
                        kind: FaultObservationKind::EffectApplied,
                        coordinate: action.coordinate,
                        binding: Some(action.binding.clone()),
                        target: Some(action.target.clone()),
                        opportunity: action.opportunity,
                        evidence: controller_transition_evidence(&transition),
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
            .shared_device()
            .apply_storage_boundary_mutations(&selected, &controller_transitions)
            .map_err(|error| storage_error("apply storage boundary mutations", error))?;
        queued.append(evaluation_sequence, observations)
    }

    fn service_block_io(
        &mut self,
        servicer: &mut QemuLiveBlockIoServicer,
        guest_icount: u64,
    ) -> Result<QemuLiveBlockIoServiceStep, QemuAsyncDriverRuntimeError> {
        let now_nanos = self.virtual_nanos(guest_icount)?;
        let storage_state = servicer
            .storage_fault_state()
            .map_err(|error| storage_error("inspect retained block completions", error))?;
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
                    event.same_coordinate_sequence,
                    event.evidence,
                )
            })
            .collect::<Vec<_>>();
        let mut releases = std::collections::BTreeMap::new();
        for (signal, event_nanos, event_sequence, event_evidence) in recovery_events {
            let signal = crucible::model::FaultObjectId::parse(signal.as_str())
                .map_err(|error| storage_error("resolve storage recovery event", error))?;
            let key = storage_recovery_event_key(&signal);
            for identity in storage_state.retained_recoveries_for(key, event_nanos, event_sequence)
            {
                let retained = storage_state.retained_completion(identity).ok_or_else(|| {
                    storage_error(
                        "select recovered block completion",
                        "retained completion disappeared during selection",
                    )
                })?;
                if event_nanos <= retained.timeout_nanos {
                    releases
                        .entry(identity)
                        .and_modify(
                            |selected: &mut (BlockRetainedRelease, u64, u64, ContentHash)| {
                                if (event_nanos, event_sequence) < (selected.1, selected.2) {
                                    *selected = (
                                        BlockRetainedRelease::Recovery {
                                            event_nanos,
                                            event_sequence,
                                        },
                                        event_nanos,
                                        event_sequence,
                                        event_evidence,
                                    );
                                }
                            },
                        )
                        .or_insert((
                            BlockRetainedRelease::Recovery {
                                event_nanos,
                                event_sequence,
                            },
                            event_nanos,
                            event_sequence,
                            event_evidence,
                        ));
                }
            }
        }
        for identity in storage_state.retained_timeouts_due(now_nanos) {
            let retained = storage_state.retained_completion(identity).ok_or_else(|| {
                storage_error(
                    "select timed-out block completion",
                    "retained completion disappeared during selection",
                )
            })?;
            releases.entry(identity).or_insert_with(|| {
                (
                    BlockRetainedRelease::Timeout,
                    retained.timeout_nanos,
                    0,
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
                .map(|(identity, (release, _, _, _))| (*identity, *release))
                .collect::<Vec<_>>();
            let release_outcomes = servicer
                .preview_storage_completion_releases(&device_releases)
                .map_err(|error| storage_error("preview retained block completions", error))?;
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
            for ((identity, (release, release_nanos, _release_sequence, cause)), outcome) in
                releases.iter().zip(&release_outcomes)
            {
                if *outcome
                    == crucible_device::block::BlockRetainedReleaseOutcome::PendingPersistence
                {
                    continue;
                }
                let sequence = staged_cursor
                    .next_sequence(*release_nanos)
                    .map_err(|error| storage_error("sequence retained block release", error))?;
                batches.push((
                    sequence.journal,
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
            let committed_outcomes = servicer
                .release_storage_completions(&device_releases)
                .map_err(|error| storage_error("release retained block completions", error))?;
            if committed_outcomes != release_outcomes {
                return Err(storage_error(
                    "release retained block completions",
                    "release outcome changed between transactional preview and commit",
                ));
            }
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

/// Coordinates one live 9p servicer with the authoritative signal runtime.
pub(super) struct ProductionNinepFaultCoordinator {
    runtime: Arc<Mutex<ProductionFaultRuntime>>,
    cursor: SharedProductionFaultEvaluationCursor,
    observations: ProductionStorageObservations,
    world: World,
    target: ResolvedFaultTarget,
    icount_shift: u8,
}

impl ProductionNinepFaultCoordinator {
    /// Binds one World 9p target to the shared production continuation.
    pub(super) fn new(
        runtime: Arc<Mutex<ProductionFaultRuntime>>,
        cursor: SharedProductionFaultEvaluationCursor,
        observations: ProductionStorageObservations,
        world: World,
        target: ResolvedFaultTarget,
        icount_shift: u8,
    ) -> Self {
        Self {
            runtime,
            cursor,
            observations,
            world,
            target,
            icount_shift,
        }
    }

    fn virtual_nanos(&self, icount: u64) -> Result<u64, QemuAsyncDriverRuntimeError> {
        icount
            .checked_shl(u32::from(self.icount_shift))
            .ok_or_else(|| storage_error("convert 9p icount", "virtual time overflow"))
    }

    fn operation(operation: NinepOperation) -> FaultOperation {
        match operation {
            NinepOperation::Read => FaultOperation::StorageRead,
            NinepOperation::Enumerate => FaultOperation::StorageEnumerate,
            NinepOperation::Admit => FaultOperation::StorageAdmit,
            NinepOperation::Flush => FaultOperation::StorageFlush,
            NinepOperation::Complete => FaultOperation::StorageComplete,
            NinepOperation::Write => FaultOperation::StorageWrite,
        }
    }

    fn opportunity(
        &self,
        request: &NinepRequestOpportunity,
        phase: FaultPhase,
        icount: u64,
    ) -> Result<FaultOpportunity, QemuAsyncDriverRuntimeError> {
        FaultOpportunity::new(
            self.target.clone(),
            Self::operation(request.operation),
            phase,
            FaultCoordinate {
                virtual_nanos: self.virtual_nanos(icount)?,
                retired_instructions: Some(icount),
            },
            u64::from(request.identity.transport_sequence),
            None,
            OpportunityPayload::StorageRequest {
                request_sequence: u64::from(request.identity.transport_sequence),
                start_byte: None,
                length_bytes: None,
                request_digest: ContentHash {
                    bytes: request.identity.digest,
                },
            },
        )
        .map_err(|error| storage_error("construct 9p fault opportunity", error))
    }

    fn evaluate_phase(
        &mut self,
        opportunity: &FaultOpportunity,
    ) -> Result<EvaluatedStoragePhase, QemuAsyncDriverRuntimeError> {
        let mut cursor = self.cursor.lock().map_err(|_| {
            storage_error(
                "sequence 9p fault opportunity",
                "production fault evaluation cursor lock is poisoned",
            )
        })?;
        let cursor_before = *cursor;
        let sequence = cursor
            .next_sequence(opportunity.coordinate().virtual_nanos)
            .map_err(|error| storage_error("sequence 9p fault opportunity", error))?;
        let mut runtime = self.runtime.lock().map_err(|_| {
            storage_error(
                "evaluate 9p fault opportunity",
                "production fault runtime lock is poisoned",
            )
        })?;
        let evaluation =
            match runtime.evaluate_host_opportunity(opportunity, sequence.same_coordinate) {
                Ok(evaluation) => evaluation,
                Err(error) => {
                    *cursor = cursor_before;
                    return Err(storage_error("evaluate 9p fault opportunity", error));
                }
            };
        let impulses = runtime.drain_host_impulses();
        if impulses.iter().any(|action| {
            action.target != *opportunity.target() || action.phase != opportunity.phase()
        }) {
            runtime.poison();
            return Err(storage_error(
                "evaluate 9p fault opportunity",
                "host impulse escaped its exact 9p target or phase",
            ));
        }
        let mut actions = runtime
            .host_state()
            .matching(opportunity.target(), opportunity.phase())
            .cloned()
            .collect::<Vec<_>>();
        actions.extend(impulses);
        actions.sort_by(|left, right| left.binding.cmp(&right.binding));
        self.observations
            .lock()
            .map_err(|_| {
                storage_error(
                    "record 9p fault observations",
                    "storage observation queue lock is poisoned",
                )
            })?
            .append(sequence.journal, evaluation.observations)?;
        Ok(EvaluatedStoragePhase {
            actions,
            same_coordinate_sequence: sequence.same_coordinate,
            journal_sequence: sequence.journal,
        })
    }

    fn object(
        &self,
        id: &crucible::model::FaultObjectId,
    ) -> Result<NinepObjectVersion, QemuAsyncDriverRuntimeError> {
        let declaration = self
            .world
            .fault_topology()
            .storage_policy_artifact(id)
            .ok_or_else(|| storage_error("resolve 9p object", "object artifact is absent"))?;
        let StoragePolicyArtifactKind::NinePObject(object) = &declaration.artifact else {
            return Err(storage_error(
                "resolve 9p object",
                "referenced artifact is not a 9p object",
            ));
        };
        let version = u32::try_from(object.version)
            .map_err(|_| storage_error("resolve 9p object", "object version exceeds u32"))?;
        Ok(NinepObjectVersion {
            path: object.path.clone(),
            version,
            mode: object.mode,
            data: object.data.clone(),
            deleted: object.deleted,
        })
    }

    fn visibility_policy(
        &self,
        id: &crucible::model::FaultObjectId,
    ) -> Result<NinepVisibilityPolicy, QemuAsyncDriverRuntimeError> {
        let declaration = self
            .world
            .fault_topology()
            .storage_policy_artifact(id)
            .ok_or_else(|| storage_error("resolve 9p visibility", "policy artifact is absent"))?;
        let StoragePolicyArtifactKind::NinePVisibility(policy) = &declaration.artifact else {
            return Err(storage_error(
                "resolve 9p visibility",
                "referenced artifact is not a 9p visibility policy",
            ));
        };
        Ok(NinepVisibilityPolicy {
            scope: match policy.scope {
                StoragePolicyNinePVisibilityScope::Global => NinepVisibilityScope::Global,
                StoragePolicyNinePVisibilityScope::PerSession => NinepVisibilityScope::PerSession,
                StoragePolicyNinePVisibilityScope::WriterImmediate => {
                    NinepVisibilityScope::WriterImmediate
                }
            },
            atomic_metadata_and_data: policy.atomic_metadata_and_data,
            retain_deleted_objects: policy.retain_deleted_objects,
        })
    }

    fn resolve_result(
        &self,
        request: &NinepRequestOpportunity,
        actions: &[ResolvedBindingAction],
    ) -> Result<NinepResultDirective, QemuAsyncDriverRuntimeError> {
        let operation = Self::operation(request.operation);
        let mut selected = NinepResultDirective::Normal;
        for action in actions {
            let EffectSpecification::Storage(StorageEffectSpecification::NinePResult {
                operations,
                kind,
                errno,
                version,
                object,
            }) = action.effect.specification()
            else {
                return Err(storage_error(
                    "resolve 9p result",
                    "non-result effect crossed the 9p resolve phase",
                ));
            };
            if !operations.contains(operation) {
                continue;
            }
            let candidate = match kind {
                NinePResultKind::Errno => {
                    let errno = errno.filter(|errno| *errno > 0).ok_or_else(|| {
                        storage_error("resolve 9p result", "errno is not positive")
                    })?;
                    NinepResultDirective::Errno(
                        u32::try_from(errno)
                            .map_err(|_| storage_error("resolve 9p result", "errno exceeds u32"))?,
                    )
                }
                NinePResultKind::Stale => {
                    NinepResultDirective::Stale(self.object(version.as_ref().ok_or_else(
                        || storage_error("resolve 9p result", "stale object is absent"),
                    )?)?)
                }
                NinePResultKind::Misdirected => {
                    NinepResultDirective::Misdirected(self.object(object.as_ref().ok_or_else(
                        || storage_error("resolve 9p result", "misdirected object is absent"),
                    )?)?)
                }
            };
            if matches!(candidate, NinepResultDirective::Errno(_))
                || !matches!(selected, NinepResultDirective::Errno(_))
            {
                selected = candidate;
            }
        }
        Ok(selected)
    }

    fn apply_visibility(
        &self,
        servicer: &mut QemuLive9pIoServicer,
        actions: &[ResolvedBindingAction],
    ) -> Result<Vec<FaultObservation>, QemuAsyncDriverRuntimeError> {
        let mut observations = Vec::new();
        for action in actions {
            let EffectSpecification::Storage(StorageEffectSpecification::NinePVisibility {
                update,
                delay_nanos,
                visibility_event,
                visibility_policy,
            }) = action.effect.specification()
            else {
                return Err(storage_error(
                    "apply 9p visibility",
                    "non-visibility effect crossed a 9p visibility phase",
                ));
            };
            let release = match (delay_nanos, visibility_event) {
                (Some(delay), None) => NinepVisibilityRelease::AtNanos(
                    action
                        .coordinate
                        .virtual_nanos
                        .checked_add(delay.get())
                        .ok_or_else(|| {
                            storage_error("apply 9p visibility", "visibility deadline overflow")
                        })?,
                ),
                (None, Some(event)) => {
                    NinepVisibilityRelease::OnEvent(storage_recovery_event_key(event))
                }
                _ => {
                    return Err(storage_error(
                        "apply 9p visibility",
                        "visibility release is not exclusive",
                    ));
                }
            };
            let update_id = ContentHash::from_canonical_material(
                "crucible.ninep.visibility-update.v1",
                &format!(
                    "action={}\nupdate={}",
                    action.id().to_hex(),
                    update.as_str()
                ),
            );
            let object = self.object(update)?;
            let policy = self.visibility_policy(visibility_policy)?;
            let data_lag_nanos = self.visibility_data_lag(visibility_policy)?;
            let sequence = servicer
                .commit_visibility_update(
                    update_id.bytes,
                    object.clone(),
                    policy,
                    release,
                    data_lag_nanos,
                )
                .map_err(|error| storage_error("apply 9p visibility", error))?;
            observations.push(FaultObservation {
                semantic_version: FAULT_RUNTIME_STATE_VERSION,
                kind: FaultObservationKind::EffectApplied,
                coordinate: action.coordinate,
                binding: Some(action.binding.clone()),
                target: Some(action.target.clone()),
                opportunity: action.opportunity,
                evidence: ninep_visibility_evidence(
                    action,
                    update_id,
                    sequence,
                    &object,
                    policy,
                    release,
                    data_lag_nanos,
                    servicer.visibility_session(),
                    servicer.visibility_state(),
                ),
            });
        }
        Ok(observations)
    }

    fn observed_visibility_events(
        &self,
        now_nanos: u64,
    ) -> Result<std::collections::BTreeMap<[u8; 32], u64>, QemuAsyncDriverRuntimeError> {
        self.runtime
            .lock()
            .map_err(|_| {
                storage_error(
                    "read 9p visibility events",
                    "fault runtime lock is poisoned",
                )
            })?
            .emitted_events()
            .iter()
            .filter(|event| event.coordinate.virtual_nanos <= now_nanos)
            .map(|event| {
                crucible::model::FaultObjectId::parse(event.signal.as_str())
                    .map(|id| {
                        (
                            storage_recovery_event_key(&id),
                            event.coordinate.virtual_nanos,
                        )
                    })
                    .map_err(|error| storage_error("read 9p visibility events", error))
            })
            .collect()
    }

    fn advance_visibility(
        &self,
        servicer: &mut QemuLive9pIoServicer,
        guest_icount: u64,
        now_nanos: u64,
        events: &BTreeMap<[u8; 32], u64>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let session = servicer.visibility_session();
        let before = servicer.visibility_state().visible_frontier(session);
        let after = servicer
            .advance_visibility(now_nanos, events)
            .map_err(|error| storage_error("advance 9p visibility", error))?;
        if before == after {
            return Ok(());
        }
        let mut sequences = std::collections::BTreeSet::new();
        sequences.extend(before.0..after.0);
        sequences.extend(before.1..after.1);
        let updates = sequences
            .into_iter()
            .flat_map(|sequence| {
                servicer
                    .visibility_state()
                    .updates_between(sequence, sequence.saturating_add(1))
            })
            .collect::<Vec<_>>();
        let evidence = ninep_visibility_advance_evidence(
            session,
            before,
            after,
            now_nanos,
            events,
            &updates,
            servicer.visibility_state(),
        );
        let mut cursor = self.cursor.lock().map_err(|_| {
            storage_error(
                "sequence 9p visibility advancement",
                "production fault evaluation cursor lock is poisoned",
            )
        })?;
        let cursor_before = *cursor;
        let sequence = cursor
            .next_sequence(now_nanos)
            .map_err(|error| storage_error("sequence 9p visibility advancement", error))?;
        let observation = FaultObservation {
            semantic_version: FAULT_RUNTIME_STATE_VERSION,
            kind: FaultObservationKind::EffectApplied,
            coordinate: FaultCoordinate {
                virtual_nanos: now_nanos,
                retired_instructions: Some(guest_icount),
            },
            binding: None,
            target: Some(self.target.clone()),
            opportunity: None,
            evidence,
        };
        if let Err(error) = self
            .observations
            .lock()
            .map_err(|_| storage_error("record 9p visibility advancement", "journal is poisoned"))?
            .append(sequence.journal, vec![observation])
        {
            *cursor = cursor_before;
            return Err(error);
        }
        Ok(())
    }

    fn visibility_data_lag(
        &self,
        id: &crucible::model::FaultObjectId,
    ) -> Result<u64, QemuAsyncDriverRuntimeError> {
        let declaration = self
            .world
            .fault_topology()
            .storage_policy_artifact(id)
            .ok_or_else(|| storage_error("resolve 9p visibility", "policy artifact is absent"))?;
        let StoragePolicyArtifactKind::NinePVisibility(policy) = &declaration.artifact else {
            return Err(storage_error(
                "resolve 9p visibility",
                "referenced artifact is not a 9p visibility policy",
            ));
        };
        Ok(policy
            .data_visibility_lag_nanos
            .map(crucible::model::PositiveU64::get)
            .unwrap_or_default())
    }

    fn service_ninep_io_transaction(
        &mut self,
        servicer: &mut QemuLive9pIoServicer,
        guest_icount: u64,
        shared_commit_started: &mut bool,
    ) -> Result<QemuLive9pIoServiceStep, QemuAsyncDriverRuntimeError> {
        let now_nanos = self.virtual_nanos(guest_icount)?;
        let events = self.observed_visibility_events(now_nanos)?;
        self.advance_visibility(servicer, guest_icount, now_nanos, &events)?;

        let mut result = QemuLive9pIoServiceStep::default();
        result.next_completion_icount = servicer.next_completion_icount();
        let due = servicer.due_fault_opportunities(guest_icount);
        for (completion_icount, request) in &due {
            let visibility = self.evaluate_phase(&self.opportunity(
                request,
                FaultPhase::Visibility,
                *completion_icount,
            )?)?;
            let applied = self.apply_visibility(servicer, &visibility.actions)?;
            self.observations
                .lock()
                .map_err(|_| storage_error("record 9p visibility", "journal is poisoned"))?
                .append(visibility.journal_sequence, applied)?;
            let deliver = self.evaluate_phase(&self.opportunity(
                request,
                FaultPhase::Deliver,
                *completion_icount,
            )?)?;
            let applied = self.apply_visibility(servicer, &deliver.actions)?;
            self.observations
                .lock()
                .map_err(|_| storage_error("record 9p delivery", "journal is poisoned"))?
                .append(deliver.journal_sequence, applied)?;
            servicer
                .authorize_fault_opportunities(
                    guest_icount,
                    &[(*completion_icount, request.identity)],
                )
                .map_err(|error| storage_error("authorize 9p delivery", error))?;
        }
        if servicer.has_authorized_due(guest_icount) {
            let delivered = match servicer.deliver_due(guest_icount) {
                Ok(delivered) => delivered,
                Err(failure) => {
                    *shared_commit_started = failure.shared_transition_started;
                    return Err(storage_error(
                        "deliver coordinated 9p replies",
                        failure.source,
                    ));
                }
            };
            *shared_commit_started = delivered.delivered > 0;
            result.delivered = delivered.delivered;
            result.next_completion_icount = delivered.next_completion_icount;
            return Ok(result);
        }

        if let Some(pin) = servicer
            .pin_next_request()
            .map_err(|error| storage_error("pin 9p request", error))?
        {
            let resolve = self.evaluate_phase(&self.opportunity(
                &pin.opportunity,
                FaultPhase::Resolve,
                pin.opportunity.request_icount,
            )?)?;
            let selected = self.resolve_result(&pin.opportunity, &resolve.actions)?;
            servicer
                .install_fault_directive(
                    pin.opportunity.request_icount,
                    pin.opportunity.identity.transport_sequence,
                    &pin.opportunity.frame,
                    ResolvedNinepRequestDirective {
                        identity: pin.opportunity.identity,
                        operation: pin.opportunity.operation,
                        result: selected.clone(),
                    },
                )
                .map_err(|error| storage_error("install 9p result", error))?;
            let persist = self.evaluate_phase(&self.opportunity(
                &pin.opportunity,
                FaultPhase::Persist,
                pin.opportunity.request_icount,
            )?)?;
            let applied = self.apply_visibility(servicer, &persist.actions)?;
            self.observations
                .lock()
                .map_err(|_| storage_error("record 9p persistence", "journal is poisoned"))?
                .append(persist.journal_sequence, applied)?;
            let prepared = servicer
                .prepare_request(&pin)
                .map_err(|error| storage_error("prepare computed 9p response", error))?;
            let response = prepared.evidence();
            let applied = resolve
                .actions
                .iter()
                .filter(|action| {
                    matches!(
                        action.effect.specification(),
                        EffectSpecification::Storage(StorageEffectSpecification::NinePResult {
                            operations,
                            ..
                        }) if operations.contains(Self::operation(pin.opportunity.operation))
                    )
                })
                .map(|action| FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: FaultObservationKind::EffectApplied,
                    coordinate: action.coordinate,
                    binding: Some(action.binding.clone()),
                    target: Some(action.target.clone()),
                    opportunity: action.opportunity,
                    evidence: ninep_result_evidence(action, &pin.opportunity, &selected, response),
                })
                .collect();
            self.observations
                .lock()
                .map_err(|_| storage_error("record 9p result", "journal is poisoned"))?
                .append(resolve.journal_sequence, applied)?;
            let processed = match servicer.commit_prepared_request(prepared) {
                Ok(processed) => processed,
                Err(failure) => {
                    *shared_commit_started = failure.shared_transition_started;
                    return Err(storage_error(
                        "commit coordinated 9p request",
                        failure.source,
                    ));
                }
            };
            *shared_commit_started = processed.processed > 0;
            result.processed = processed.processed;
            result.first_request_icount = processed.first_request_icount;
            result.computed_completion_icount = processed.computed_completion_icount;
            result.next_completion_icount = processed.next_completion_icount;
        }
        Ok(result)
    }
}

impl QemuNinepFaultCoordinator for ProductionNinepFaultCoordinator {
    fn service_ninep_io(
        &mut self,
        servicer: &mut QemuLive9pIoServicer,
        guest_icount: u64,
    ) -> Result<QemuLive9pIoServiceStep, QemuAsyncDriverRuntimeError> {
        let servicer_before = servicer
            .begin_transaction()
            .map_err(|error| storage_error("begin coordinated 9p transaction", error))?;
        let runtime_before = self
            .runtime
            .lock()
            .map_err(|_| storage_error("begin coordinated 9p transaction", "runtime is poisoned"))?
            .clone();
        let cursor_before = *self
            .cursor
            .lock()
            .map_err(|_| storage_error("begin coordinated 9p transaction", "cursor is poisoned"))?;
        let observations_before = self
            .observations
            .lock()
            .map_err(|_| storage_error("begin coordinated 9p transaction", "journal is poisoned"))?
            .clone();

        let mut shared_commit_started = false;
        let error = match self.service_ninep_io_transaction(
            servicer,
            guest_icount,
            &mut shared_commit_started,
        ) {
            Ok(result) => return Ok(result),
            Err(error) => error,
        };
        if shared_commit_started {
            return Err(error);
        }
        let mut rollback_failures = Vec::new();
        if let Err(rollback) = servicer.rollback_transaction(servicer_before) {
            rollback_failures.push(format!("servicer rollback failed: {rollback}"));
        }
        match self.runtime.lock() {
            Ok(mut runtime) => *runtime = runtime_before,
            Err(_) => rollback_failures.push(String::from("runtime rollback lock is poisoned")),
        }
        match self.cursor.lock() {
            Ok(mut cursor) => *cursor = cursor_before,
            Err(_) => rollback_failures.push(String::from("cursor rollback lock is poisoned")),
        }
        match self.observations.lock() {
            Ok(mut observations) => *observations = observations_before,
            Err(_) => rollback_failures.push(String::from("journal rollback lock is poisoned")),
        }
        if rollback_failures.is_empty() {
            Err(error)
        } else {
            Err(storage_error(
                "roll back coordinated 9p transaction",
                format!("{error}; {}", rollback_failures.join("; ")),
            ))
        }
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

fn bind_recovery_subscription_sequence(
    directive: &mut crucible_device::block::ResolvedBlockFaultDirective,
    same_coordinate_sequence: u64,
) {
    if directive.retention_recovery_event.is_some() {
        directive.retention_recovery_after_sequence = Some(same_coordinate_sequence);
    }
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

fn storage_array_target_attaches_device(
    world: &World,
    candidate: &ResolvedFaultTarget,
    attached: &ResolvedFaultTarget,
) -> bool {
    let ResolvedFaultTarget::StorageArray { array, .. } = candidate else {
        return false;
    };
    let attached = match attached {
        ResolvedFaultTarget::BlockDevice { device }
        | ResolvedFaultTarget::BlockRange { device, .. } => *device,
        _ => return false,
    };
    world
        .fault_topology()
        .storage_arrays
        .iter()
        .find(|candidate| candidate.id.as_str() == array.as_str())
        .is_some_and(|array| {
            world.io_nodes().any(|node| {
                node.id.name == array.device.as_str() && node.fault_target_hash() == attached
            })
        })
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
        BlockRetainedRelease::Recovery { .. } => "recovery",
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

fn ninep_object_evidence(object: &NinepObjectVersion) -> String {
    format!(
        "path={}\nversion={}\nmode={}\ndeleted={}\ndata_len={}\ndata_digest={}",
        object.path,
        object.version,
        object.mode,
        object.deleted,
        object.data.len(),
        ContentHash {
            bytes: *blake3::hash(&object.data).as_bytes(),
        }
        .to_hex(),
    )
}

fn ninep_result_evidence(
    action: &ResolvedBindingAction,
    request: &NinepRequestOpportunity,
    selected: &NinepResultDirective,
    response: QemuLive9pResponseEvidence,
) -> ContentHash {
    let result = match selected {
        NinepResultDirective::Normal => String::from("kind=normal"),
        NinepResultDirective::Errno(errno) => format!("kind=errno\nerrno={errno}"),
        NinepResultDirective::Stale(object) => {
            format!("kind=stale\n{}", ninep_object_evidence(object))
        }
        NinepResultDirective::Misdirected(object) => {
            format!("kind=misdirected\n{}", ninep_object_evidence(object))
        }
    };
    let status = match response.status {
        crucible_device::ResponseStatus::Ok => "ok",
        crucible_device::ResponseStatus::Error => "error",
    };
    ContentHash::from_canonical_material(
        "crucible.ninep-result-evidence.v1",
        &format!(
            "action={}\nrequest_icount={}\ntransport_sequence={}\ntag={}\nrequest_digest={}\noperation={:?}\n{result}\ncompletion_icount={}\nresponse_transport_sequence={}\nresponse_status={status}\nresponse_len={}\nresponse_digest={}",
            action.id().to_hex(),
            request.identity.request_icount,
            request.identity.transport_sequence,
            request.identity.tag,
            ContentHash {
                bytes: request.identity.digest,
            }
            .to_hex(),
            request.operation,
            response.completion_icount,
            response.transport_sequence,
            response.payload_len,
            ContentHash {
                bytes: response.payload_digest,
            }
            .to_hex(),
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn ninep_visibility_evidence(
    action: &ResolvedBindingAction,
    update_id: ContentHash,
    sequence: u64,
    object: &NinepObjectVersion,
    policy: NinepVisibilityPolicy,
    release: NinepVisibilityRelease,
    data_lag_nanos: u64,
    writer_session: u64,
    state: &NinepVisibilityState,
) -> ContentHash {
    let scope = match policy.scope {
        NinepVisibilityScope::Global => "global",
        NinepVisibilityScope::PerSession => "per_session",
        NinepVisibilityScope::WriterImmediate => "writer_immediate",
    };
    let release = match release {
        NinepVisibilityRelease::AtNanos(nanos) => format!("at_nanos:{nanos}"),
        NinepVisibilityRelease::OnEvent(event) => {
            format!("on_event:{}", ContentHash { bytes: event }.to_hex(),)
        }
    };
    let frontiers = state
        .session_frontiers()
        .into_iter()
        .map(|(session, metadata, data)| format!("{session}:{metadata}:{data}"))
        .collect::<Vec<_>>()
        .join(",");
    let lookup =
        ninep_visibility_lookup_evidence(state.lookup_object(writer_session, object.path.as_str()));
    ContentHash::from_canonical_material(
        "crucible.ninep-visibility-evidence.v1",
        &format!(
            "action={}\nupdate_id={}\nsequence={sequence}\n{}\nscope={scope}\natomic_metadata_and_data={}\nretain_deleted_objects={}\nrelease={release}\ndata_lag_nanos={data_lag_nanos}\nwriter_session={writer_session}\ncommitted_frontier={}\nsession_frontiers={frontiers}\nlookup={lookup}",
            action.id().to_hex(),
            update_id.to_hex(),
            ninep_object_evidence(object),
            policy.atomic_metadata_and_data,
            policy.retain_deleted_objects,
            state.committed_frontier(),
        ),
    )
}

fn ninep_visibility_lookup_evidence(lookup: NinepVisibilityLookup) -> String {
    match lookup {
        NinepVisibilityLookup::Base => String::from("base"),
        NinepVisibilityLookup::Deleted => String::from("deleted"),
        NinepVisibilityLookup::Object(object) => {
            format!(
                "object:{}",
                ninep_object_evidence(&object).replace('\n', ";")
            )
        }
    }
}

fn ninep_visibility_advance_evidence(
    session: u64,
    before: (u64, u64),
    after: (u64, u64),
    observed_nanos: u64,
    events: &BTreeMap<[u8; 32], u64>,
    updates: &[NinepVisibilityUpdate],
    state: &NinepVisibilityState,
) -> ContentHash {
    let updates = updates
        .iter()
        .map(|update| {
            let release = match update.release {
                NinepVisibilityRelease::AtNanos(deadline) => {
                    format!("deadline:{deadline}:satisfied_at:{deadline}")
                }
                NinepVisibilityRelease::OnEvent(event) => format!(
                    "event:{}:observed_at:{}",
                    ContentHash { bytes: event }.to_hex(),
                    events
                        .get(&event)
                        .map_or_else(|| String::from("absent"), u64::to_string),
                ),
            };
            format!(
                "sequence={};writer_session={};release={release};lookup={}",
                update.sequence,
                update.writer_session,
                ninep_visibility_lookup_evidence(
                    state.lookup_object(session, update.object.path.as_str())
                ),
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    ContentHash::from_canonical_material(
        "crucible.ninep-visibility-advance-evidence.v1",
        &format!(
            "session={session}\nobserved_nanos={observed_nanos}\nmetadata_before={}\nmetadata_after={}\ndata_before={}\ndata_after={}\nupdates={updates}",
            before.0, after.0, before.1, after.1,
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

fn controller_transition_evidence(
    transition: &crucible_device::block::ResolvedBlockControllerTransition,
) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.storage-controller-transition-evidence.v1",
        &format!(
            "failure_result={:?}\nunadmitted={:?}\nqueued={:?}\nexecuting={:?}\nresolved={:?}\ncompleted_undelivered={:?}\ncontroller_buffer={:?}\nvolatile_cache={:?}\nrequest_ids={:?}\nduplicate_history={:?}\ntopology={:?}\nrecovery_nanos={}",
            transition.failure_result,
            transition.unadmitted,
            transition.queued,
            transition.executing,
            transition.resolved,
            transition.completed_undelivered,
            transition.controller_buffer,
            transition.volatile_cache,
            transition.request_ids,
            transition.duplicate_history,
            transition.topology,
            transition.recovery_nanos,
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
