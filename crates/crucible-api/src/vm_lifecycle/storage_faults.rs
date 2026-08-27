//! Production signal coordination for live World-backed block and 9p devices.
//!
//! Coordinators fail closed after admission and evaluate only authenticated opportunities.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::*;

use crucible::model::{
    ContentHash, EffectSpecification, FAULT_RUNTIME_STATE_VERSION, FaultCoordinate, FaultObjectId,
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
    QemuLive9pIoServiceStep, QemuLive9pIoServicer,
    QemuLive9pResponseEvidence as LiveNinepResponseEvidence, QemuLiveBlockIoDeliveryStep,
    QemuLiveBlockIoIntakeStep, QemuLiveBlockIoServiceStep, QemuLiveBlockIoServicer,
    QemuNinepFaultCoordinator, QemuSharedBlockDevice, ResolvedVolatileCacheLoss, StorageArrayError,
    StorageFaultResolutionContext, StorageFaultResolutionError, VolatileCacheLossReplay,
    block_delivery_fault_opportunity, block_durability_config, block_persistence_fault_opportunity,
    block_request_fault_opportunity, block_request_persistence_fault_opportunity,
    merge_block_fault_phase_directive, plan_storage_array_write, read_storage_array,
    resolve_block_controller_transition, resolve_block_fault_directive,
    resolve_block_persistence_media_directive, resolve_storage_array_baseline,
    resolve_storage_array_policy, resolve_storage_array_rebuild_failure,
    resolve_storage_array_rebuild_service, resolve_volatile_cache_loss,
    storage_array_rebuild_fault_opportunity, storage_recovery_event_key,
};

/// Maximum phase/device settle transitions performed during one host poll.
const HARD_STORAGE_SETTLE_STEPS: usize = 4_096;
/// Maximum undrained signal observations across one backend quantum.
const HARD_STORAGE_FAULT_OBSERVATIONS: usize = 262_144;
type StorageArrayDestinations = Vec<(ContentHash, QemuSharedBlockDevice, Vec<BlockRequest>)>;
type StorageArrayDirtyRanges = Vec<crucible_device::block::BlockArrayDirtyRange>;
type StorageArrayWriteDestinations = (StorageArrayDestinations, StorageArrayDirtyRanges);
type DeviceRuntimeError = QemuAsyncDriverRuntimeError;

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
    }))
}

/// Globally sequenced fault-observation journal shared by every live adapter.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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

    #[cfg(test)]
    pub(super) fn snapshot(&self) -> Vec<FaultObservation> {
        self.batches.values().flatten().cloned().collect()
    }

    pub(super) fn drain_ready(&mut self, frontier: u64) -> Vec<FaultObservation> {
        let mut ready = Vec::new();
        for (sequence, observations) in &mut self.batches {
            let mut retained = Vec::new();
            for (index, observation) in std::mem::take(observations).into_iter().enumerate() {
                if observation.coordinate.virtual_nanos <= frontier {
                    ready.push((
                        observation.coordinate.virtual_nanos,
                        *sequence,
                        index,
                        observation,
                    ));
                } else {
                    retained.push(observation);
                }
            }
            *observations = retained;
        }
        self.batches
            .retain(|_sequence, observations| !observations.is_empty());
        self.observations = self.batches.values().map(Vec::len).sum();
        ready.sort_by_key(|(nanos, sequence, index, _observation)| (*nanos, *sequence, *index));
        ready
            .into_iter()
            .map(|(_nanos, _sequence, _index, observation)| observation)
            .collect()
    }

    pub(super) fn validate(&self, next_sequence: u64) -> bool {
        let actual = self
            .batches
            .values()
            .try_fold(0_usize, |count, batch| count.checked_add(batch.len()));
        self.observations <= HARD_STORAGE_FAULT_OBSERVATIONS
            && actual == Some(self.observations)
            && self.batches.iter().all(|(sequence, batch)| {
                *sequence < next_sequence
                    && !batch.is_empty()
                    && batch.iter().all(|observation| {
                        observation.semantic_version == FAULT_RUNTIME_STATE_VERSION
                            && observation.evidence != ContentHash::default()
                    })
            })
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
    baseline_array_id: Option<String>,
    context: StorageFaultResolutionContext,
    icount_shift: u8,
}

impl ProductionBlockFaultCoordinator {
    /// Binds a World block target to the shared production continuation.
    // crucible-lint: allow rust-allow -- the coordinator binds independently owned runtime, observation, world, target, plan, seed, and clock inputs.
    #[allow(
        clippy::too_many_arguments,
        reason = "the coordinator binds independently owned runtime, observation, world, target, plan, seed, and clock inputs"
    )]
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
            .into_iter()
            .collect();
        let baseline_array_id = world
            .fault_topology()
            .storage_arrays
            .iter()
            .find(|array| storage_array_attaches_device(&world, array, &target))
            .map(|array| array.id.as_str().to_owned());
        Self {
            runtime,
            cursor,
            observations,
            devices,
            world,
            target,
            opportunity_targets: opportunity_targets.into_iter().collect(),
            array_targets,
            baseline_array_id,
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
        if let Some(policy) = policies.pop() {
            return Ok(Some(policy));
        }
        self.baseline_array_id
            .as_deref()
            .map(FaultObjectId::parse)
            .transpose()
            .map_err(|_| StorageFaultResolutionError::UnsupportedTarget)?
            .map(|array| resolve_storage_array_baseline(&self.world, &array))
            .transpose()
    }

    fn current_array_policy(
        &self,
    ) -> Result<Option<crucible_qemu::ResolvedStorageArrayPolicy>, QemuAsyncDriverRuntimeError>
    {
        let runtime = self.runtime.lock().map_err(|_| {
            storage_error(
                "resolve active storage array policy",
                "production fault runtime lock is poisoned",
            )
        })?;
        let mut actions = Vec::new();
        for target in &self.array_targets {
            actions.extend(
                runtime
                    .host_state()
                    .matching(target, FaultPhase::Persist)
                    .cloned(),
            );
        }
        drop(runtime);
        super::fault_implementation::require_storage_actions_implemented(actions.iter()).map_err(
            |error| {
                storage_error(
                    "resolve active storage array policy",
                    format!(
                        "storage action is absent from the production implementation registry: {error}"
                    ),
                )
            },
        )?;
        self.active_array_policy(&actions)
            .map_err(|error| storage_error("resolve active storage array policy", error))
    }

    fn current_array_rebuild_service(
        &self,
    ) -> Result<Option<crucible_qemu::ResolvedStorageRebuildService>, QemuAsyncDriverRuntimeError>
    {
        let runtime = self.runtime.lock().map_err(|_| {
            storage_error(
                "resolve shared array rebuild service",
                "production fault runtime lock is poisoned",
            )
        })?;
        let mut actions = Vec::new();
        for target in self
            .opportunity_targets
            .iter()
            .chain(self.array_targets.iter())
        {
            actions.extend(
                runtime
                    .host_state()
                    .matching(target, FaultPhase::Queue)
                    .cloned(),
            );
        }
        drop(runtime);
        super::fault_implementation::require_storage_actions_implemented(actions.iter()).map_err(
            |error| {
                storage_error(
                    "resolve shared array rebuild service",
                    format!(
                        "storage action is absent from the production implementation registry: {error}"
                    ),
                )
            },
        )?;
        resolve_storage_array_rebuild_service(&self.world, &actions)
            .map_err(|error| storage_error("resolve shared array rebuild service", error))
    }

    fn evaluate_array_phase(
        &mut self,
        request: &BlockRequest,
        request_sequence: u64,
        wire_digest: [u8; 32],
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

    fn service_array_rebuild(
        &mut self,
        servicer: &QemuLiveBlockIoServicer,
        now_nanos: u64,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let policy = self.current_array_policy()?;
        let Some(policy) = policy else {
            return Ok(());
        };
        let source = servicer.shared_device();
        let shared_service = self.current_array_rebuild_service()?;
        let rebuild_rate =
            shared_service
                .as_ref()
                .map_or(policy.rebuild.bytes_per_second.get(), |service| {
                    policy
                        .rebuild
                        .bytes_per_second
                        .get()
                        .min(service.bytes_per_second)
                });
        let rebuild_iops = shared_service
            .as_ref()
            .and_then(|service| service.operations_per_second);
        let rebuild_queue_depth = shared_service
            .as_ref()
            .map_or(policy.rebuild.queue_depth.get(), |service| {
                policy.rebuild.queue_depth.get().min(service.queue_depth)
            });
        for _ in 0..rebuild_queue_depth {
            let Some(rebuild) = source
                .next_storage_array_rebuild_opportunity(
                    now_nanos,
                    policy.rebuild.chunk_bytes.get(),
                    rebuild_rate,
                    rebuild_iops,
                )
                .map_err(|error| storage_error("schedule storage array rebuild", error))?
            else {
                break;
            };
            let member = policy
                .members
                .iter()
                .find(|member| member.ordinal == rebuild.member_ordinal)
                .ok_or_else(|| {
                    storage_error(
                        "resolve storage array rebuild member",
                        "dirty range names no declared array member",
                    )
                })?;
            if !member.online || policy.online_paths == 0 {
                source
                    .pause_storage_array_rebuild(now_nanos, &rebuild)
                    .map_err(|error| storage_error("pause storage array rebuild", error))?;
                break;
            }
            let target = ResolvedFaultTarget::StorageArray {
                array: policy.array.clone(),
                member_or_path: member.member.clone(),
            };
            let opportunity =
                storage_array_rebuild_fault_opportunity(target, &rebuild).map_err(|error| {
                    storage_error("construct storage array rebuild opportunity", error)
                })?;
            let evaluation = self.evaluate_phase(&opportunity)?;
            let failure_actions = evaluation.actions.iter().filter(|action| {
                matches!(
                    action.effect.specification(),
                    EffectSpecification::Storage(
                        StorageEffectSpecification::OperationFailure { .. }
                    )
                )
            });
            if resolve_storage_array_rebuild_failure(
                &self.world,
                &opportunity,
                self.context,
                &rebuild,
                failure_actions,
            )
            .map_err(|error| storage_error("resolve storage array rebuild failure", error))?
            .is_some()
            {
                source
                    .defer_storage_array_rebuild(&rebuild)
                    .map_err(|error| storage_error("defer failed storage array rebuild", error))?;
                continue;
            }
            let destination = self
                .devices
                .lock()
                .map_err(|_| {
                    storage_error(
                        "resolve storage array rebuild member",
                        "authoritative block-device registry is poisoned",
                    )
                })?
                .get(&member.device)
                .cloned()
                .ok_or_else(|| {
                    storage_error(
                        "resolve storage array rebuild member",
                        format!(
                            "World block device {} has no live runtime",
                            member.device.to_hex()
                        ),
                    )
                })?;
            source
                .install_storage_array_rebuild(
                    self.attached_device_hash()?,
                    &destination,
                    member.device,
                    &rebuild,
                )
                .map_err(|error| storage_error("commit storage array rebuild", error))?;
        }
        Ok(())
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
        if policy.online_paths == 0 {
            return Err(StorageArrayError::QuorumUnavailable);
        }
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
    ) -> Result<StorageArrayWriteDestinations, StorageArrayError> {
        if policy.online_paths == 0 {
            return Err(StorageArrayError::QuorumUnavailable);
        }
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
        let mut grouped = BTreeMap::<ContentHash, Vec<BlockRequest>>::new();
        for write in plan.writes {
            grouped
                .entry(write.device)
                .or_default()
                .push(BlockRequest::write(
                    request.request_id,
                    write.offset,
                    write.bytes,
                ));
        }
        let dirty_writes = plan
            .dirty_writes
            .into_iter()
            .map(|write| crucible_device::block::BlockArrayDirtyRange {
                member_ordinal: write.ordinal,
                start_byte: write.offset,
                bytes: write.bytes,
                generation: 0,
                dirty_nanos: 0,
            })
            .collect();
        let destinations =
            grouped
                .into_iter()
                .map(|(device, writes)| {
                    let handle = devices.get(&device).cloned().ok_or_else(|| {
                        StorageArrayError::MemberRead {
                            ordinal: 0,
                            message: format!(
                                "World block device {} has no live runtime",
                                device.to_hex()
                            ),
                        }
                    })?;
                    Ok((device, handle, writes))
                })
                .collect::<Result<Vec<_>, _>>()?;
        Ok((destinations, dirty_writes))
    }

    fn array_flush_destinations(
        &self,
        policy: &crucible_qemu::ResolvedStorageArrayPolicy,
        request_id: u32,
    ) -> Result<Vec<(ContentHash, QemuSharedBlockDevice, Vec<BlockRequest>)>, StorageArrayError>
    {
        if policy.online_paths == 0
            || policy.members.iter().filter(|member| member.online).count()
                < usize::from(policy.write_quorum)
        {
            return Err(StorageArrayError::QuorumUnavailable);
        }
        let devices = self
            .devices
            .lock()
            .map_err(|_| StorageArrayError::MemberRead {
                ordinal: 0,
                message: String::from("authoritative block-device registry is poisoned"),
            })?;
        policy
            .members
            .iter()
            .filter(|member| member.online)
            .map(|member| {
                let handle = devices.get(&member.device).cloned().ok_or_else(|| {
                    StorageArrayError::MemberRead {
                        ordinal: member.ordinal,
                        message: format!(
                            "World block device {} has no live runtime",
                            member.device.to_hex()
                        ),
                    }
                })?;
                Ok((member.device, handle, vec![BlockRequest::flush(request_id)]))
            })
            .collect()
    }

    fn array_discard_destinations(
        &self,
        policy: &crucible_qemu::ResolvedStorageArrayPolicy,
        request: &BlockRequest,
        logical: &QemuSharedBlockDevice,
    ) -> Result<StorageArrayWriteDestinations, StorageArrayError> {
        let bytes = logical
            .storage_array_discard_replacement(request)
            .map_err(|error| StorageArrayError::MemberRead {
                ordinal: 0,
                message: error.to_string(),
            })?
            .map_or_else(|| self.array_read_transform(policy, request), Ok)?;
        let mut write = request.clone();
        write.op = BlockOp::Write;
        write.data = bytes;
        self.array_write_destinations(policy, &write)
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
        if let Err(error) =
            super::fault_implementation::require_storage_actions_implemented(actions.iter())
        {
            runtime.poison();
            return Err(storage_error(
                "evaluate block fault opportunity",
                format!(
                    "storage action is absent from the production implementation registry: {error}"
                ),
            ));
        }
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
        let actions = runtime
            .host_state()
            .matching(target, FaultPhase::Persist)
            .filter(|action| {
                matches!(
                    action.effect.specification(),
                    EffectSpecification::Storage(StorageEffectSpecification::FlashState { .. })
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        super::fault_implementation::require_storage_actions_implemented(actions.iter()).map_err(
            |error| {
                storage_error(
                    "resolve physical storage persistence",
                    format!(
                        "storage action is absent from the production implementation registry: {error}"
                    ),
                )
            },
        )?;
        Ok(actions)
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
        // crucible-lint: allow stringly-error -- the coordinator trait's private adapter diagnostic is immediately wrapped by the lifecycle boundary.
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
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        let pin = servicer
            .pin_next_request_completion()
            .map_err(|error| storage_error("pin live block request", error))?;
        let Some(observed) = pin.observed else {
            return Ok(false);
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
        }
        directive.execution_nanos = request_nanos;
        self.after_evaluation(
            "install block admission directive",
            servicer.install_storage_fault_directive(request.identity(), directive),
        )?;
        Ok(true)
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
                let mut array_actions = Vec::new();
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
                    array_actions.extend(evaluation.actions);
                }
                let array_policy = self
                    .active_array_policy(&array_actions)
                    .map_err(|error| storage_error("resolve storage array policy", error))?;
                directive.execution_nanos = opportunity.ready_nanos;
                if !directive.persistence_transforms.is_empty() {
                    directive.persistence_admitted_nanos = opportunity.ready_nanos;
                }
                let resolved = ResolvedBlockRequestPersistenceDirective {
                    opportunity,
                    directive,
                };
                let source = servicer.shared_device();
                if matches!(
                    resolved.opportunity.request.op,
                    BlockOp::Write | BlockOp::Discard | BlockOp::Flush
                ) && let Some(policy) = array_policy
                {
                    let planned = match resolved.opportunity.request.op {
                        BlockOp::Write => {
                            self.array_write_destinations(&policy, &resolved.opportunity.request)
                        }
                        BlockOp::Discard => self.array_discard_destinations(
                            &policy,
                            &resolved.opportunity.request,
                            &source,
                        ),
                        BlockOp::Flush => self
                            .array_flush_destinations(
                                &policy,
                                resolved.opportunity.request.request_id,
                            )
                            .map(|destinations| (destinations, Vec::new())),
                        BlockOp::Read | BlockOp::GetLength => {
                            return Err(storage_error(
                                "plan storage array persistence",
                                "non-mutating operation entered array persistence",
                            ));
                        }
                    };
                    let (destinations, dirty_writes) = match planned {
                        Ok(destinations) => destinations,
                        Err(StorageArrayError::QuorumUnavailable) => {
                            let mut failed = resolved;
                            failed.directive.error_result = Some(policy.failure_result);
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
                    let source_id = self.attached_device_hash()?;
                    self.after_evaluation(
                        "install storage array persistence",
                        source.install_multi_device_mutation(
                            source_id,
                            &destinations,
                            &dirty_writes,
                            resolved,
                        ),
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
        super::fault_implementation::require_storage_actions_implemented(actions.iter()).map_err(
            |error| {
                storage_error(
                    "apply storage boundary action",
                    format!(
                        "storage action is absent from the production implementation registry: {error}"
                    ),
                )
            },
        )?;
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
        self.service_array_rebuild(servicer, now_nanos)?;
        let mut aggregate = QemuLiveBlockIoServiceStep::default();
        if self.admit_head_request(servicer)? {
            let intake = servicer
                .process_one_storage_request()
                .map_err(|error| storage_error("consume coordinated block request", error))?;
            absorb_intake(&mut aggregate, intake)?;
        }
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
        if let Err(error) =
            super::fault_implementation::require_storage_actions_implemented(actions.iter())
        {
            runtime.poison();
            return Err(storage_error(
                "evaluate 9p fault opportunity",
                format!("9p action is absent from the production implementation registry: {error}"),
            ));
        }
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
                    action.committed_state_id().to_hex(),
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

        let mut result = QemuLive9pIoServiceStep {
            next_completion_icount: servicer.next_completion_icount(),
            ..QemuLive9pIoServiceStep::default()
        };
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
            .try_clone()
            .map_err(|error| storage_error("clone coordinated 9p runtime", error))?;
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
            return Err(fail_after_shared_ninep_commit(&self.runtime, error));
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

mod ambiguous_commit;
mod evidence;
use ambiguous_commit::*;
use evidence::*;

#[cfg(test)]
fn mapped_ninep_test_servicer(
    shared_memory: std::os::fd::BorrowedFd<'_>,
    region_len: u64,
) -> Result<QemuLive9pIoServicer, crucible_qemu::QemuLive9pIoServicerError> {
    QemuLive9pIoServicer::from_shmem_fd(shared_memory, region_len, 0, 0)
}

#[cfg(test)]
#[path = "storage_faults/tests.rs"]
mod tests;
