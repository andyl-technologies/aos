//! Production resolution of host storage actions into exact block directives.
//!
//! Signal evaluation and keyed hazard decisions occur in `crucible`. This
//! module is the live block-adapter boundary: it consumes only committed,
//! typed [`ResolvedBindingAction`] values for one exact request and translates
//! them into a [`ResolvedBlockFaultDirective`]. It never evaluates signals,
//! consults host time, or silently substitutes a different device behavior.

use crucible::model::{
    BindingActionCause, BindingActionKind, ContentHash, EffectLifetime, EffectSpecification,
    FaultContractError, FaultCoordinate, FaultObjectId, FaultOperation, FaultOpportunity,
    FaultPhase, MappedEffectParameter, OpportunityPayload, ResolvedBindingAction,
    ResolvedFaultTarget, ResolvedMappingOutput, SignalValue, StorageAvailabilityState,
    StorageEffectSpecification, StorageFlushKind, StorageMediaState, StoragePolicyArrayConsistency,
    StoragePolicyArraySelection, StoragePolicyArtifactKind,
    StoragePolicyCacheEviction, StoragePolicyDirtyEviction, StoragePolicyDuplicateCompletion,
    StoragePolicyPersistenceOrdering, StoragePolicyQueueDiscipline, StoragePolicyRebuild,
    StoragePolicyServiceClass,
    StoragePolicyTransitionPendingOperation, StoragePolicyTransitionRequestIds,
    StoragePolicyTransitionResolvedOperation, StoragePolicyTransitionState,
    StoragePolicyTransitionTopology, StoragePolicyTransitionUnadmitted,
    StoragePolicyTransitionUndeliveredOperation, StoragePolicyTypedResult, StorageReadMutation,
    StorageSelection, StorageVolatileCacheLossKind, StorageVolatileCacheLossSelector,
    StorageWriteDispositionKind, World, WorldCompletionDurability, WorldDiscardSemantics,
};

/// Scenario-owned entropy used only for keyed storage adapter choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageFaultResolutionContext {
    scenario_seed: ContentHash,
}

/// Exact, replay-verifiable result of one volatile-cache loss resolution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedVolatileCacheLoss {
    /// Digest of the complete live entry set observed atomically before loss.
    pub entry_set_digest: [u8; 32],
    /// Canonical sequence set eligible after target and protection filtering.
    pub eligible_sequences: Vec<u64>,
    /// Canonical target-scoped sequence set protected from ordinary power loss.
    pub protected_sequences: Vec<u64>,
    /// Exact canonical sequence set removed by this impulse.
    pub selected_sequences: Vec<u64>,
    /// Actual durable frontier immediately before the loss.
    pub durable_frontier_before: u64,
    /// Actual durable frontier immediately after the selected loss.
    pub durable_frontier_after: u64,
}

/// One resolved member of a live storage array.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedStorageArrayMember {
    /// Stable member identity within the array.
    pub member: FaultObjectId,
    /// Immutable target hash of the authoritative backing block device.
    pub device: ContentHash,
    /// Stable layout ordinal.
    pub ordinal: u16,
    /// Whether the member accepts operations in this state transition.
    pub online: bool,
}

/// Complete closed policy for one live array-state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedStorageArrayPolicy {
    /// Stable array identity.
    pub array: FaultObjectId,
    /// Immutable target hash of the guest-visible logical block device.
    pub logical_device: ContentHash,
    /// Declared read quorum.
    pub read_quorum: u16,
    /// Declared write quorum.
    pub write_quorum: u16,
    /// Positive stripe chunk size.
    pub chunk_bytes: u64,
    /// Canonically member-ID-ordered backing members.
    pub members: Vec<ResolvedStorageArrayMember>,
    /// Number of online access paths.
    pub online_paths: u16,
    /// Deterministic member-selection policy.
    pub selection: StoragePolicyArraySelection,
    /// Bounded rebuild service policy.
    pub rebuild: StoragePolicyRebuild,
    /// Partial-update consistency policy.
    pub consistency: StoragePolicyArrayConsistency,
    /// Typed failure returned when no legal quorum exists.
    pub failure_result: BlockFaultResult,
}

/// Resolves a registered controller transition policy for a live block device.
///
/// # Errors
///
/// Returns [`StorageFaultResolutionError`] when `action` is not a controller
/// lifecycle action or when its policy/result references are absent or have the
/// wrong closed type.
pub fn resolve_block_controller_transition(
    world: &World,
    action: &ResolvedBindingAction,
) -> Result<ResolvedBlockControllerTransition, StorageFaultResolutionError> {
    let EffectSpecification::Storage(StorageEffectSpecification::ControllerLifecycle {
        transition,
        transition_policy,
        ..
    }) = action.effect.specification()
    else {
        return Err(unsupported(action, "controller lifecycle boundary"));
    };
    let policy = world
        .fault_topology()
        .storage_policy_artifact(transition_policy)
        .and_then(|artifact| match &artifact.artifact {
            StoragePolicyArtifactKind::ControllerTransition(policy)
                if policy.transition == *transition =>
            {
                Some(policy)
            }
            _ => None,
        })
        .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
            binding: action.binding.clone(),
            reference: transition_policy.clone(),
            expected: "matching controller_transition",
        })?;
    let failure_result = resolve_block_failure(world, &policy.failure_result).ok_or_else(|| {
        StorageFaultResolutionError::PolicyReference {
            binding: action.binding.clone(),
            reference: policy.failure_result.clone(),
            expected: "non-success block typed_result",
        }
    })?;
    Ok(ResolvedBlockControllerTransition {
        failure_result,
        unadmitted: match policy.unadmitted {
            StoragePolicyTransitionUnadmitted::Reject => BlockTransitionUnadmitted::Reject,
            StoragePolicyTransitionUnadmitted::WaitForRecovery => {
                BlockTransitionUnadmitted::WaitForRecovery
            }
        },
        queued: resolve_transition_pending(policy.queued),
        executing: resolve_transition_pending(policy.executing),
        resolved: resolve_transition_resolved(policy.resolved),
        completed_undelivered: resolve_transition_undelivered(policy.completed_undelivered),
        controller_buffer: resolve_transition_state(policy.controller_buffer),
        volatile_cache: resolve_transition_state(policy.volatile_cache),
        request_ids: match policy.request_ids {
            StoragePolicyTransitionRequestIds::PreserveMonotonic => {
                BlockTransportRequestIds::PreserveMonotonic
            }
            StoragePolicyTransitionRequestIds::NewEpochFromZero => {
                BlockTransportRequestIds::NewEpochFromZero
            }
        },
        duplicate_history: resolve_transition_state(policy.duplicate_history),
        topology: match policy.topology {
            StoragePolicyTransitionTopology::Preserve => BlockTransitionTopology::Preserve,
            StoragePolicyTransitionTopology::ReenumerateDeclared => {
                BlockTransitionTopology::ReenumerateDeclared
            }
        },
        recovery_nanos: policy.recovery_nanos.get(),
    })
}

/// Resolves every artifact referenced by one array-state action.
///
/// # Errors
///
/// Returns [`StorageFaultResolutionError`] when the action is not an array
/// transition, its array/logical/member device is absent, or any referenced
/// artifact has the wrong closed type.
pub fn resolve_storage_array_policy(
    world: &World,
    action: &ResolvedBindingAction,
) -> Result<ResolvedStorageArrayPolicy, StorageFaultResolutionError> {
    let EffectSpecification::Storage(StorageEffectSpecification::ArrayState {
        layout,
        member_path_state,
        selection_policy,
        rebuild_service,
        consistency_policy,
        failure_result,
    }) = action.effect.specification()
    else {
        return Err(unsupported(action, "array state boundary"));
    };
    let array = world
        .fault_topology()
        .storage_arrays
        .iter()
        .find(|array| array.id.as_str() == layout.as_str())
        .ok_or(StorageFaultResolutionError::UnsupportedTarget)?;
    let device_id = FaultObjectId::parse(array.device.as_str())
        .map_err(|_| StorageFaultResolutionError::UnsupportedTarget)?;
    let logical_device = storage_device_by_id(world, &device_id)
        .map(|(_, hash)| hash)
        .ok_or(StorageFaultResolutionError::UnsupportedTarget)?;
    let (member_states, path_states) = world
        .fault_topology()
        .storage_policy_artifact(member_path_state)
        .and_then(|artifact| match &artifact.artifact {
            StoragePolicyArtifactKind::ArrayState { members, paths } => Some((members, paths)),
            _ => None,
        })
        .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
            binding: action.binding.clone(),
            reference: member_path_state.clone(),
            expected: "array_state",
        })?;
    let mut members = Vec::with_capacity(array.members.len());
    for member in &array.members {
        let member_id = FaultObjectId::parse(member.id.as_str())
            .map_err(|_| StorageFaultResolutionError::UnsupportedTarget)?;
        let online = member_states
            .iter()
            .find(|candidate| candidate.member == member_id)
            .map(|candidate| candidate.online)
            .ok_or(StorageFaultResolutionError::UnsupportedTarget)?;
        let member_device_id = FaultObjectId::parse(member.device.as_str())
            .map_err(|_| StorageFaultResolutionError::UnsupportedTarget)?;
        let device = storage_device_by_id(world, &member_device_id)
            .map(|(_, hash)| hash)
            .ok_or(StorageFaultResolutionError::UnsupportedTarget)?;
        members.push(ResolvedStorageArrayMember {
            member: member_id,
            device,
            ordinal: member.ordinal,
            online,
        });
    }
    let selection = array_selection(world, action, selection_policy)?;
    let rebuild = array_rebuild(world, action, rebuild_service)?;
    let consistency = array_consistency(world, action, consistency_policy)?;
    let failure_result = resolve_block_failure(world, failure_result).ok_or_else(|| {
        StorageFaultResolutionError::PolicyReference {
            binding: action.binding.clone(),
            reference: failure_result.clone(),
            expected: "non-success block typed_result",
        }
    })?;
    let online_paths = u16::try_from(path_states.iter().filter(|path| path.online).count())
        .map_err(|_| StorageFaultResolutionError::Overflow {
            binding: action.binding.clone(),
            field: "array_online_paths",
        })?;
    Ok(ResolvedStorageArrayPolicy {
        array: layout.clone(),
        logical_device,
        read_quorum: array.read_quorum,
        write_quorum: array.write_quorum,
        chunk_bytes: array.chunk_bytes,
        members,
        online_paths,
        selection,
        rebuild,
        consistency,
        failure_result,
    })
}

fn array_selection(
    world: &World,
    action: &ResolvedBindingAction,
    reference: &FaultObjectId,
) -> Result<StoragePolicyArraySelection, StorageFaultResolutionError> {
    world
        .fault_topology()
        .storage_policy_artifact(reference)
        .and_then(|artifact| match artifact.artifact {
            StoragePolicyArtifactKind::ArraySelection(policy) => Some(policy),
            _ => None,
        })
        .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
            binding: action.binding.clone(),
            reference: reference.clone(),
            expected: "array_selection",
        })
}

fn array_rebuild(
    world: &World,
    action: &ResolvedBindingAction,
    reference: &FaultObjectId,
) -> Result<StoragePolicyRebuild, StorageFaultResolutionError> {
    world
        .fault_topology()
        .storage_policy_artifact(reference)
        .and_then(|artifact| match &artifact.artifact {
            StoragePolicyArtifactKind::Rebuild(policy) => Some(policy.clone()),
            _ => None,
        })
        .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
            binding: action.binding.clone(),
            reference: reference.clone(),
            expected: "rebuild",
        })
}

fn array_consistency(
    world: &World,
    action: &ResolvedBindingAction,
    reference: &FaultObjectId,
) -> Result<StoragePolicyArrayConsistency, StorageFaultResolutionError> {
    world
        .fault_topology()
        .storage_policy_artifact(reference)
        .and_then(|artifact| match artifact.artifact {
            StoragePolicyArtifactKind::ArrayConsistency(policy) => Some(policy),
            _ => None,
        })
        .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
            binding: action.binding.clone(),
            reference: reference.clone(),
            expected: "array_consistency",
        })
}

/// Replay policy for one atomic volatile-cache loss transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolatileCacheLossReplay {
    /// Records the observed entry-set digest for a new execution.
    Record,
    /// Requires the live entry set to match locked replay evidence before mutation.
    Locked {
        /// Digest recorded immediately before the original loss transition.
        expected_entry_set_digest: [u8; 32],
    },
}

impl StorageFaultResolutionContext {
    /// Creates a resolution context from the admitted scenario seed.
    #[must_use]
    pub const fn new(scenario_seed: ContentHash) -> Self {
        Self { scenario_seed }
    }
}

/// Resolves the exact device durability bounds declared by one World target.
///
/// # Errors
///
/// Returns [`StorageFaultResolutionError::UnsupportedTarget`] unless `target`
/// resolves to one declared block device.
pub fn block_durability_config(
    world: &World,
    target: &ResolvedFaultTarget,
) -> Result<BlockDurabilityConfig, StorageFaultResolutionError> {
    let persistence = &target_storage_device(world, target)?.persistence;
    Ok(BlockDurabilityConfig {
        length_bytes: persistence.length_bytes,
        atomic_write_bytes: persistence.atomic_write_bytes,
        maximum_request_bytes: persistence.maximum_request_bytes,
        discard_granularity_bytes: persistence.discard_granularity_bytes,
        discard_semantics: match persistence.discard_semantics {
            WorldDiscardSemantics::DeterministicZero => BlockDiscardSemantics::DeterministicZero,
            WorldDiscardSemantics::ReadsOldData => BlockDiscardSemantics::ReadsOldData,
            WorldDiscardSemantics::UndefinedRecorded => BlockDiscardSemantics::UndefinedKeyed,
        },
        volatile_cache_bytes: persistence.volatile_cache_bytes,
        cache_entries: persistence.cache_entries,
        controller_buffer_bytes: persistence.controller_buffer_bytes,
        controller_entries: persistence.controller_entries,
        persistence_dependencies: persistence.persistence_dependencies,
        retained_versions: u32::from(persistence.retained_versions_per_interval),
        completion_durability: match persistence.completion_durability {
            WorldCompletionDurability::ControllerAccepted => {
                BlockCompletionDurability::ControllerAccepted
            }
            WorldCompletionDurability::VolatileCacheAccepted => {
                BlockCompletionDurability::VolatileCacheAccepted
            }
            WorldCompletionDurability::Durable => BlockCompletionDurability::Durable,
        },
    })
}

/// Builds the canonical signal opportunity for one exact block request phase.
///
/// `request_sequence` is the adapter-owned monotone sequence, not the reusable
/// guest request ID. `wire_digest` must be the BLAKE3 digest of the complete
/// immutable request payload observed on the shared-memory ring.
///
/// # Errors
///
/// Returns [`FaultContractError`] when `target` is not a valid storage target or
/// the request range cannot be represented by the opportunity contract.
pub fn block_request_fault_opportunity(
    target: ResolvedFaultTarget,
    request: &BlockRequest,
    wire_digest: [u8; 32],
    phase: FaultPhase,
    coordinate: FaultCoordinate,
    request_sequence: u64,
) -> Result<FaultOpportunity, FaultContractError> {
    let operation = match request.op {
        BlockOp::Read => crucible::model::FaultOperation::StorageRead,
        BlockOp::Write => crucible::model::FaultOperation::StorageWrite,
        BlockOp::Flush => crucible::model::FaultOperation::StorageFlush,
        BlockOp::GetLength => crucible::model::FaultOperation::StorageGetLength,
        BlockOp::Discard => crucible::model::FaultOperation::StorageDiscard,
    };
    let (start_byte, length_bytes) = match request.op {
        BlockOp::Read | BlockOp::Write | BlockOp::Discard => {
            (Some(request.offset), Some(u64::from(request.count)))
        }
        BlockOp::Flush | BlockOp::GetLength => (None, None),
    };
    FaultOpportunity::new(
        target,
        operation,
        phase,
        coordinate,
        request_sequence,
        None,
        OpportunityPayload::StorageRequest {
            request_sequence,
            start_byte,
            length_bytes,
            request_digest: crucible::model::ContentHash { bytes: wire_digest },
        },
    )
}

/// Builds the canonical opportunity for one exact physical-media mutation.
///
/// # Errors
///
/// Returns [`FaultContractError`] when `target` is not a block target or the
/// physical range cannot be represented by the opportunity contract.
pub fn block_persistence_fault_opportunity(
    target: ResolvedFaultTarget,
    persistence: &BlockPersistenceOpportunity,
    coordinate: FaultCoordinate,
) -> Result<FaultOpportunity, FaultContractError> {
    let operation = match persistence.operation {
        BlockOp::Write => FaultOperation::StorageWrite,
        BlockOp::Discard => FaultOperation::StorageDiscard,
        BlockOp::Read | BlockOp::Flush | BlockOp::GetLength => {
            return Err(FaultContractError::InvalidPayload);
        }
    };
    FaultOpportunity::new(
        target,
        operation,
        FaultPhase::Persist,
        coordinate,
        persistence.sequence,
        None,
        OpportunityPayload::StorageRequest {
            request_sequence: persistence.sequence,
            start_byte: Some(persistence.offset),
            length_bytes: Some(u64::from(persistence.count)),
            request_digest: ContentHash {
                bytes: persistence.intended_digest,
            },
        },
    )
}

/// Builds the canonical persist-phase opportunity for a staged request mutation.
///
/// # Errors
///
/// Returns [`FaultContractError`] under the same conditions as
/// [`block_request_fault_opportunity`].
pub fn block_request_persistence_fault_opportunity(
    target: ResolvedFaultTarget,
    persistence: &BlockRequestPersistenceOpportunity,
    coordinate: FaultCoordinate,
) -> Result<FaultOpportunity, FaultContractError> {
    block_request_fault_opportunity(
        target,
        &persistence.request,
        persistence.wire_digest,
        FaultPhase::Persist,
        coordinate,
        persistence.request_sequence,
    )
}

/// Builds the canonical deliver-phase opportunity for one computed completion.
///
/// # Errors
///
/// Returns [`FaultContractError`] under the same conditions as
/// [`block_request_fault_opportunity`]. The response-bearing delivery envelope
/// is authenticated again when the resolved directive is installed.
pub fn block_delivery_fault_opportunity(
    target: ResolvedFaultTarget,
    delivery: &BlockDeliveryOpportunity,
    coordinate: FaultCoordinate,
) -> Result<FaultOpportunity, FaultContractError> {
    let operation = match delivery.request.op {
        BlockOp::Read => FaultOperation::StorageRead,
        BlockOp::Write => FaultOperation::StorageWrite,
        BlockOp::Flush => FaultOperation::StorageFlush,
        BlockOp::GetLength => FaultOperation::StorageGetLength,
        BlockOp::Discard => FaultOperation::StorageDiscard,
    };
    let (start_byte, length_bytes) = match delivery.request.op {
        BlockOp::Read | BlockOp::Write | BlockOp::Discard => (
            Some(delivery.request.offset),
            Some(u64::from(delivery.request.count)),
        ),
        BlockOp::Flush | BlockOp::GetLength => (None, None),
    };
    let response = delivery
        .response
        .encode()
        .map_err(|_error| FaultContractError::InvalidPayload)?;
    FaultOpportunity::new(
        target,
        operation,
        FaultPhase::Deliver,
        coordinate,
        delivery.request_sequence,
        None,
        OpportunityPayload::StorageCompletion {
            request_sequence: delivery.request_sequence,
            start_byte,
            length_bytes,
            request_digest: ContentHash {
                bytes: delivery.wire_digest,
            },
            response_status: delivery.response.status.to_wire(),
            response_digest: ContentHash::from_bytes(&response),
        },
    )
}
use crucible_device::block::{
    BlockCompletionDurability, BlockDeliveryOpportunity, BlockDiscardSemantics,
    BlockDuplicatePolicy, BlockDurabilityConfig, BlockFaultAvailability, BlockFaultByteSpan,
    BlockFaultCacheEviction, BlockFaultDirtyEviction, BlockFaultFlushDisposition,
    BlockFaultMisdirectionDestination, BlockFaultReadTransform, BlockFaultResult, BlockFaultState,
    BlockFaultWriteDisposition, BlockMediaRangeState, BlockOp, BlockPersistenceOpportunity,
    BlockPersistenceOrdering, BlockRequest, BlockRequestPersistenceOpportunity, BlockResponse,
    BlockServiceDiscipline, BlockTransitionPending, BlockTransitionResolved, BlockTransitionState,
    BlockTransitionTopology, BlockTransitionUnadmitted, BlockTransitionUndelivered,
    BlockTransportRequestIds, ResolvedBlockCachePolicy, ResolvedBlockControllerTransition,
    ResolvedBlockFaultDirective, ResolvedBlockFlashProgramErase, ResolvedBlockFlashReadDisturb,
    ResolvedBlockFlashRetention, ResolvedBlockFlashRule, ResolvedBlockMediaRule,
    ResolvedBlockPersistenceMediaDirective, ResolvedBlockPersistenceTransform,
    ResolvedBlockServiceClass, ResolvedBlockServiceRule,
};

/// Resolves persistent flash policy for one exact physical persistence opportunity.
///
/// Contributions are sorted by binding/action identity and retain distinct
/// contributor state. The returned directive authenticates the complete live
/// opportunity, so a delayed or replayed decision cannot attach to another
/// fragment with a reused guest request ID.
///
/// # Errors
///
/// Returns [`StorageFaultResolutionError`] for a mismatched opportunity/action,
/// a non-flash effect, a wrong-shaped policy reference, or duplicate contributor.
pub fn resolve_block_persistence_media_directive<'a>(
    world: &World,
    target: &ResolvedFaultTarget,
    opportunity: &BlockPersistenceOpportunity,
    fault_opportunity: &FaultOpportunity,
    context: StorageFaultResolutionContext,
    actions: impl IntoIterator<Item = &'a ResolvedBindingAction>,
) -> Result<ResolvedBlockPersistenceMediaDirective, StorageFaultResolutionError> {
    let expected_operation = match opportunity.operation {
        BlockOp::Write => FaultOperation::StorageWrite,
        BlockOp::Discard => FaultOperation::StorageDiscard,
        BlockOp::Read | BlockOp::Flush | BlockOp::GetLength => {
            return Err(StorageFaultResolutionError::OpportunityMismatch);
        }
    };
    if fault_opportunity.target() != target
        || fault_opportunity.operation() != expected_operation
        || fault_opportunity.phase() != FaultPhase::Persist
        || fault_opportunity.sequence() != opportunity.sequence
        || !matches!(
            fault_opportunity.payload(),
            OpportunityPayload::StorageRequest {
                request_sequence,
                start_byte: Some(start),
                length_bytes: Some(length),
                request_digest,
            } if *request_sequence == opportunity.sequence
                && *start == opportunity.offset
                && *length == u64::from(opportunity.count)
                && request_digest.bytes == opportunity.intended_digest
        )
    {
        return Err(StorageFaultResolutionError::OpportunityMismatch);
    }
    let mut actions = actions.into_iter().collect::<Vec<_>>();
    actions.sort_by(|left, right| {
        left.binding
            .cmp(&right.binding)
            .then_with(|| left.transition_sequence.cmp(&right.transition_sequence))
    });
    let mut flash_rules = Vec::new();
    let mut contributors = std::collections::BTreeSet::new();
    for action in actions {
        if action.target != *target {
            return Err(StorageFaultResolutionError::TargetMismatch {
                binding: action.binding.clone(),
            });
        }
        validate_action_identity(action, fault_opportunity)?;
        if action.kind == BindingActionKind::RemovePersistent
            || matches!(
                action.mapping_output.as_ref(),
                ResolvedMappingOutput::Activation { active: false }
            )
        {
            continue;
        }
        let EffectSpecification::Storage(effect @ StorageEffectSpecification::FlashState { .. }) =
            action.effect.specification()
        else {
            return Err(unsupported(action, "non-flash persistence-media effect"));
        };
        let rule = resolve_flash_rule(world, context, action, effect)?;
        let contributor = rule.contributor;
        if !contributors.insert(contributor) {
            return Err(StorageFaultResolutionError::InvalidDirective {
                binding: action.binding.clone(),
                reason: String::from("duplicate flash persistence contributor"),
            });
        }
        flash_rules.push(rule);
    }
    flash_rules.sort_by_key(|rule| rule.contributor);
    Ok(ResolvedBlockPersistenceMediaDirective {
        opportunity: opportunity.clone(),
        flash_rules,
    })
}

/// Resolves one cache-loss impulse into exact live cache sequence identities.
///
/// Protection is part of eligibility rather than a post-selection filter:
/// ordinary power loss excludes protected entries, while protection failure
/// makes every live entry eligible. Canonical and keyed selection therefore
/// operate over the same explicitly evidenced set.
///
/// # Errors
///
/// Returns [`StorageFaultResolutionError`] when the action is not an exact
/// impulse for `target` or does not carry `storage.volatile_cache_loss`.
pub fn resolve_volatile_cache_loss(
    target: &ResolvedFaultTarget,
    state: &BlockFaultState,
    context: StorageFaultResolutionContext,
    action: &ResolvedBindingAction,
    replay: VolatileCacheLossReplay,
) -> Result<ResolvedVolatileCacheLoss, StorageFaultResolutionError> {
    if action.target != *target {
        return Err(StorageFaultResolutionError::TargetMismatch {
            binding: action.binding.clone(),
        });
    }
    if action.kind != BindingActionKind::Apply
        || action.effect.lifetime() != EffectLifetime::Impulse
        || action.phase != FaultPhase::Boundary
        || action.opportunity.is_some()
        || !matches!(action.cause, BindingActionCause::Signal)
        || !matches!(
            action.mapping_output.as_ref(),
            ResolvedMappingOutput::Impulse {
                event: SignalValue::Event { .. }
            }
        )
    {
        return Err(StorageFaultResolutionError::ActionIdentity {
            binding: action.binding.clone(),
        });
    }
    let EffectSpecification::Storage(StorageEffectSpecification::VolatileCacheLoss {
        selector,
        loss,
    }) = action.effect.specification()
    else {
        return Err(unsupported(action, "volatile-cache loss impulse"));
    };
    let entry_set_digest = state.volatile_entries_digest();
    if let VolatileCacheLossReplay::Locked {
        expected_entry_set_digest,
    } = replay
        && expected_entry_set_digest != entry_set_digest
    {
        return Err(StorageFaultResolutionError::ReplayEntrySetMismatch {
            binding: action.binding.clone(),
            expected: expected_entry_set_digest,
            actual: entry_set_digest,
        });
    }
    let target_range = match target {
        ResolvedFaultTarget::BlockDevice { .. } => None,
        ResolvedFaultTarget::BlockRange {
            start_byte,
            length_bytes,
            ..
        } => Some((*start_byte, *length_bytes)),
        _ => return Err(StorageFaultResolutionError::UnsupportedTarget),
    };
    let target_entries = state
        .volatile_entries()
        .iter()
        .filter_map(|(sequence, entry)| {
            let target_eligible = target_range.is_none_or(|(start, length)| {
                ranges_intersect(start, length, entry.offset, entry.bytes.len())
            });
            target_eligible.then_some((*sequence, entry.power_loss_protected))
        })
        .collect::<Vec<_>>();
    let protected_sequences = target_entries
        .iter()
        .filter_map(|(sequence, protected)| protected.then_some(*sequence))
        .collect::<Vec<_>>();
    let eligible = target_entries
        .iter()
        .filter_map(|(sequence, protected)| {
            (*loss == StorageVolatileCacheLossKind::ProtectionFailure || !protected)
                .then_some(*sequence)
        })
        .collect::<Vec<_>>();
    let selected_sequences =
        select_volatile_cache_loss(context, action, selector, state, &eligible)?;
    let durable_frontier_before = state.actual_durable_frontier();
    let mut after = state.clone();
    after.lose_volatile(&selected_sequences).map_err(|error| {
        StorageFaultResolutionError::InvalidDirective {
            binding: action.binding.clone(),
            reason: error.to_string(),
        }
    })?;
    Ok(ResolvedVolatileCacheLoss {
        entry_set_digest,
        eligible_sequences: eligible,
        protected_sequences,
        selected_sequences,
        durable_frontier_before,
        durable_frontier_after: after.actual_durable_frontier(),
    })
}

fn select_volatile_cache_loss(
    context: StorageFaultResolutionContext,
    action: &ResolvedBindingAction,
    selector: &StorageVolatileCacheLossSelector,
    state: &BlockFaultState,
    eligible: &[u64],
) -> Result<Vec<u64>, StorageFaultResolutionError> {
    match selector {
        StorageVolatileCacheLossSelector::All => Ok(eligible.to_vec()),
        StorageVolatileCacheLossSelector::AfterSequence { sequence } => Ok(eligible
            .iter()
            .copied()
            .filter(|candidate| candidate > sequence)
            .collect()),
        StorageVolatileCacheLossSelector::RangeIntersection { range } => Ok(eligible
            .iter()
            .copied()
            .filter(|sequence| {
                state.volatile_entries().get(sequence).is_some_and(|entry| {
                    ranges_intersect(
                        range.start(),
                        range.length(),
                        entry.offset,
                        entry.bytes.len(),
                    )
                })
            })
            .collect()),
        StorageVolatileCacheLossSelector::KeyedSubset { count } => {
            let eligible_digest = volatile_cache_eligible_digest(eligible);
            let mut ranked = eligible
                .iter()
                .copied()
                .map(|sequence| {
                    (
                        keyed_action_rank(
                            context,
                            action,
                            eligible_digest,
                            b"storage.volatile-cache-loss.subset.v1",
                            sequence,
                        ),
                        sequence,
                    )
                })
                .collect::<Vec<_>>();
            ranked.sort_unstable();
            let take = usize::try_from(count.get())
                .unwrap_or(usize::MAX)
                .min(ranked.len());
            let mut selected = ranked
                .into_iter()
                .take(take)
                .map(|(_rank, sequence)| sequence)
                .collect::<Vec<_>>();
            selected.sort_unstable();
            Ok(selected)
        }
    }
}

/// Resolves committed host actions for one exact live block request.
///
/// The caller supplies actions already matched to `target` and the request's
/// exact opportunity. Contributions are sorted by effect kind, binding ID, and
/// transition sequence before composition so caller iteration order cannot
/// affect the result. `request_sequence` must be the monotone adapter sequence
/// pinned with this request, not the reusable guest request ID.
/// `read_source` inspects controller-visible bytes from the authoritative live
/// device selected by a misdirected-read action and is never called otherwise.
///
/// # Errors
///
/// Returns [`StorageFaultResolutionError`] when an action targets another
/// device, is a removal action, carries a non-storage effect, references a
/// missing or wrong-shaped World artifact, overflows a checked sum, or selects
/// storage semantics that have no complete live implementation.
pub fn resolve_block_fault_directive<'a>(
    world: &World,
    target: &ResolvedFaultTarget,
    request: &BlockRequest,
    request_sequence: u64,
    opportunity: &FaultOpportunity,
    context: StorageFaultResolutionContext,
    read_source: &mut dyn FnMut(ContentHash, u64, u32) -> Result<Vec<u8>, String>,
    actions: impl IntoIterator<Item = &'a ResolvedBindingAction>,
) -> Result<ResolvedBlockFaultDirective, StorageFaultResolutionError> {
    let capacity = target_capacity(world, target)?;
    resolve_block_fault_directive_with_capacity(
        world,
        target,
        request,
        request_sequence,
        opportunity,
        capacity,
        context,
        read_source,
        actions,
    )
}

/// Merges one independently evaluated request phase into an accumulated directive.
///
/// Each `phase` must have been resolved from its own authenticated
/// [`FaultOpportunity`]. The merge copies only fields owned by that phase, so a
/// fault-free baseline from a later phase cannot erase an earlier decision.
/// Resolve- and deliver-phase latency contributions compose by checked sum.
///
/// # Errors
///
/// Returns [`StorageFaultResolutionError::OpportunityMismatch`] when request
/// identity differs, [`StorageFaultResolutionError::PhaseMergeOverflow`] when
/// latency composition exceeds `u64`, or
/// [`StorageFaultResolutionError::PhaseMergeConflict`] when independently
/// sampled phases both retain the same completion.
pub fn merge_block_fault_phase_directive(
    accumulated: &mut ResolvedBlockFaultDirective,
    phase: FaultPhase,
    partial: ResolvedBlockFaultDirective,
) -> Result<(), StorageFaultResolutionError> {
    if accumulated.request_sequence != partial.request_sequence
        || accumulated.operation != partial.operation
        || accumulated.offset != partial.offset
        || accumulated.count != partial.count
        || accumulated.request_digest != partial.request_digest
    {
        return Err(StorageFaultResolutionError::OpportunityMismatch);
    }
    match phase {
        FaultPhase::Admit | FaultPhase::Produce => {
            accumulated.availability = partial.availability;
            accumulated.reported_capacity_bytes = partial.reported_capacity_bytes;
        }
        FaultPhase::Queue => {
            accumulated.service_rules = partial.service_rules;
        }
        FaultPhase::Resolve => {
            accumulated.additional_latency_nanos = accumulated
                .additional_latency_nanos
                .checked_add(partial.additional_latency_nanos)
                .ok_or(StorageFaultResolutionError::PhaseMergeOverflow {
                    field: "additional_latency_nanos",
                })?;
            accumulated.execution_nanos = partial.execution_nanos;
            accumulated.error_result = partial.error_result;
            accumulated.retain_completion = partial.retain_completion;
            accumulated.retention_timeout_response = partial.retention_timeout_response;
            accumulated.retention_timeout_nanos = partial.retention_timeout_nanos;
            accumulated.retention_recovery_event = partial.retention_recovery_event;
            accumulated.retention_recovery_after_nanos = partial.retention_recovery_after_nanos;
            accumulated.retention_recovery_after_sequence =
                partial.retention_recovery_after_sequence;
            accumulated.read_transforms = partial.read_transforms;
            accumulated.media_rules.extend(partial.media_rules);
        }
        FaultPhase::Persist => {
            accumulated.execution_nanos = partial.execution_nanos;
            accumulated.write_disposition = partial.write_disposition;
            accumulated.flush_disposition = partial.flush_disposition;
            if partial.retain_completion {
                if accumulated.retain_completion {
                    return Err(StorageFaultResolutionError::PhaseMergeConflict {
                        field: "completion retention",
                    });
                }
                accumulated.retain_completion = true;
                accumulated.retention_timeout_response = partial.retention_timeout_response;
                accumulated.retention_timeout_nanos = partial.retention_timeout_nanos;
                accumulated.retention_recovery_event = partial.retention_recovery_event;
                accumulated.retention_recovery_after_nanos = partial.retention_recovery_after_nanos;
                accumulated.retention_recovery_after_sequence =
                    partial.retention_recovery_after_sequence;
            }
            accumulated.cache_policy = partial.cache_policy;
            accumulated.persistence_transforms = partial.persistence_transforms;
            accumulated.persistence_media_rules = partial.persistence_media_rules;
            accumulated.persistence_admitted_nanos = partial.persistence_admitted_nanos;
            accumulated.media_rules.extend(partial.media_rules);
        }
        FaultPhase::Deliver => {
            accumulated.additional_latency_nanos = accumulated
                .additional_latency_nanos
                .checked_add(partial.additional_latency_nanos)
                .ok_or(StorageFaultResolutionError::PhaseMergeOverflow {
                    field: "additional_latency_nanos",
                })?;
            accumulated.duplicate_completions = partial.duplicate_completions;
        }
        FaultPhase::Visibility
        | FaultPhase::Transition
        | FaultPhase::Boundary
        | FaultPhase::Run
        | FaultPhase::BeforeInstruction
        | FaultPhase::AfterInstruction
        | FaultPhase::BeforeRead
        | FaultPhase::AfterRead
        | FaultPhase::BeforeWrite
        | FaultPhase::AfterWrite
        | FaultPhase::Fetch
        | FaultPhase::Load
        | FaultPhase::Store
        | FaultPhase::DmaRead
        | FaultPhase::DmaWrite
        | FaultPhase::PageTableWalk
        | FaultPhase::Refresh
        | FaultPhase::Raise
        | FaultPhase::Route
        | FaultPhase::Acknowledge
        | FaultPhase::InterruptDeliver
        | FaultPhase::Return
        | FaultPhase::ClockRead
        | FaultPhase::Arm
        | FaultPhase::Fire
        | FaultPhase::Synchronize
        | FaultPhase::SourceSwitch
        | FaultPhase::Submit
        | FaultPhase::Execute
        | FaultPhase::Complete
        | FaultPhase::AcceleratorMemoryAccess => {
            return Err(StorageFaultResolutionError::OpportunityMismatch);
        }
    }
    accumulated.media_rules.sort_by_key(|rule| rule.contributor);
    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "exact storage resolution keeps independently typed world, target, request, time, and evidence inputs explicit"
)]
fn resolve_block_fault_directive_with_capacity<'a>(
    world: &World,
    target: &ResolvedFaultTarget,
    request: &BlockRequest,
    request_sequence: u64,
    opportunity: &FaultOpportunity,
    capacity: u64,
    context: StorageFaultResolutionContext,
    read_source: &mut dyn FnMut(ContentHash, u64, u32) -> Result<Vec<u8>, String>,
    actions: impl IntoIterator<Item = &'a ResolvedBindingAction>,
) -> Result<ResolvedBlockFaultDirective, StorageFaultResolutionError> {
    validate_request_opportunity(target, request, request_sequence, opportunity)?;
    let mut directive = ResolvedBlockFaultDirective::fault_free(request, capacity);
    directive.request_sequence = request_sequence;
    directive.execution_nanos = opportunity.coordinate().virtual_nanos;
    let mut actions = actions.into_iter().collect::<Vec<_>>();
    actions.sort_by(|left, right| {
        left.effect
            .kind()
            .cmp(&right.effect.kind())
            .then_with(|| left.binding.cmp(&right.binding))
            .then_with(|| left.transition_sequence.cmp(&right.transition_sequence))
    });
    for action in actions {
        if action.target != *target {
            return Err(StorageFaultResolutionError::TargetMismatch {
                binding: action.binding.clone(),
            });
        }
        validate_action_identity(action, opportunity)?;
        if action.kind == BindingActionKind::RemovePersistent {
            return Err(StorageFaultResolutionError::RemovalAction {
                binding: action.binding.clone(),
            });
        }
        if matches!(
            action.mapping_output.as_ref(),
            ResolvedMappingOutput::Activation { active: false }
        ) {
            continue;
        }
        let EffectSpecification::Storage(effect) = action.effect.specification() else {
            return Err(StorageFaultResolutionError::NonStorageAction {
                binding: action.binding.clone(),
            });
        };
        apply_effect(
            world,
            request,
            context,
            read_source,
            action,
            effect,
            &mut directive,
        )?;
    }
    directive
        .persistence_media_rules
        .sort_by_key(|rule| rule.contributor);
    directive.service_rules.sort_by_key(|rule| rule.contributor);
    Ok(directive)
}

fn apply_effect(
    world: &World,
    request: &BlockRequest,
    context: StorageFaultResolutionContext,
    read_source: &mut dyn FnMut(ContentHash, u64, u32) -> Result<Vec<u8>, String>,
    action: &ResolvedBindingAction,
    effect: &StorageEffectSpecification,
    directive: &mut ResolvedBlockFaultDirective,
) -> Result<(), StorageFaultResolutionError> {
    match effect {
        StorageEffectSpecification::Availability { state, .. } => {
            let incoming = match state {
                StorageAvailabilityState::Online => BlockFaultAvailability::Online,
                StorageAvailabilityState::Offline => BlockFaultAvailability::Offline,
                StorageAvailabilityState::ReadOnly => BlockFaultAvailability::ReadOnly,
                StorageAvailabilityState::Degraded => BlockFaultAvailability::Degraded,
            };
            directive.availability = availability_max(directive.availability, incoming);
        }
        StorageEffectSpecification::ReportedCapacity { length_bytes, .. } => {
            let length_bytes = mapped_u64(action, MappedEffectParameter::UnsignedCount)?
                .unwrap_or(length_bytes.get());
            directive.reported_capacity_bytes = directive.reported_capacity_bytes.min(length_bytes);
        }
        StorageEffectSpecification::Service {
            bytes_per_second,
            iops,
            queue_depth,
            service_policy,
        } => {
            let policy = storage_policy(
                world,
                service_policy,
                &action.binding,
                "service",
                |artifact| match artifact {
                    StoragePolicyArtifactKind::Service(policy) => Some(policy.clone()),
                    _ => None,
                },
            )?;
            let mapped = match action.mapping_output.as_ref() {
                ResolvedMappingOutput::Parameter { parameter, value } => Some((*parameter, value)),
                _ => None,
            };
            let mapped_rate = |parameter: MappedEffectParameter, default: u64| {
                mapped
                    .filter(|(actual, _)| *actual == parameter)
                    .map_or(Ok(default), |_| {
                        mapped_u64(action, parameter)?.ok_or_else(|| {
                            StorageFaultResolutionError::MappingOutput {
                                binding: action.binding.clone(),
                                expected: parameter,
                            }
                        })
                    })
            };
            let bytes_per_second = mapped_rate(
                MappedEffectParameter::BytesPerSecond,
                bytes_per_second.get(),
            )?;
            let iops = match iops {
                Some(default) => Some(mapped_rate(
                    MappedEffectParameter::OperationsPerSecond,
                    default.get(),
                )?),
                None if mapped.is_some_and(|(parameter, _)| {
                    parameter == MappedEffectParameter::OperationsPerSecond
                }) =>
                {
                    Some(mapped_rate(MappedEffectParameter::OperationsPerSecond, 0)?)
                }
                None => None,
            };
            let queue_depth = mapped_rate(
                MappedEffectParameter::UnsignedCount,
                u64::from(queue_depth.get()),
            )?;
            let queue_depth = u32::try_from(queue_depth).map_err(|_error| {
                StorageFaultResolutionError::InvalidDirective {
                    binding: action.binding.clone(),
                    reason: String::from("storage service queue depth exceeds u32"),
                }
            })?;
            let classes = resolve_service_classes(policy.classes)?;
            directive.service_rules.push(ResolvedBlockServiceRule {
                contributor: action.id().bytes,
                bytes_per_second,
                iops,
                queue_depth,
                discipline: match policy.discipline {
                    StoragePolicyQueueDiscipline::Fifo => BlockServiceDiscipline::Fifo,
                    StoragePolicyQueueDiscipline::StrictPriority => {
                        BlockServiceDiscipline::StrictPriority
                    }
                    StoragePolicyQueueDiscipline::WeightedRoundRobin => {
                        BlockServiceDiscipline::WeightedRoundRobin
                    }
                },
                classes,
                rebuild_shares_service: policy.rebuild_shares_service,
            });
        }
        StorageEffectSpecification::Latency {
            operations,
            extra_nanos,
            jitter_nanos,
        } if operation_selected(operations.as_slice(), request.op) => {
            if !probability_applies(context, action, request, 1_000_000)? {
                return Ok(());
            }
            let delay = if matches!(
                action.mapping_output.as_ref(),
                ResolvedMappingOutput::Parameter {
                    parameter: MappedEffectParameter::Probability,
                    ..
                }
            ) {
                *extra_nanos
            } else {
                mapped_u64(action, MappedEffectParameter::DurationNanos)?.unwrap_or(*extra_nanos)
            };
            let jitter = keyed_inclusive(
                context,
                action,
                request,
                b"storage.latency.jitter.v1",
                *jitter_nanos,
            );
            directive.additional_latency_nanos = directive
                .additional_latency_nanos
                .checked_add(delay)
                .and_then(|delay| delay.checked_add(jitter))
                .ok_or_else(|| StorageFaultResolutionError::Overflow {
                    binding: action.binding.clone(),
                    field: "additional_latency_nanos",
                })?;
        }
        StorageEffectSpecification::OperationFailure {
            operations,
            probability,
            status,
        } if operation_selected(operations.as_slice(), request.op) => {
            if !probability_applies(context, action, request, probability.get())? {
                return Ok(());
            }
            require_block_result(world, status, false, &action.binding)?;
            directive.error_result =
                Some(resolve_block_failure(world, status).ok_or_else(|| {
                    StorageFaultResolutionError::PolicyReference {
                        binding: action.binding.clone(),
                        reference: status.clone(),
                        expected: "non-success block typed_result",
                    }
                })?);
        }
        StorageEffectSpecification::StallTimeout {
            stall_nanos,
            recovery_event,
            timeout_result,
        } => {
            require_block_result(world, timeout_result, false, &action.binding)?;
            let stall_nanos = mapped_u64(action, MappedEffectParameter::DurationNanos)?
                .unwrap_or(stall_nanos.get());
            let timeout = resolve_block_failure(world, timeout_result).ok_or_else(|| {
                StorageFaultResolutionError::PolicyReference {
                    binding: action.binding.clone(),
                    reference: timeout_result.clone(),
                    expected: "non-success block typed_result",
                }
            })?;
            if let Some(recovery_event) = recovery_event {
                directive.retain_completion = true;
                directive.retention_timeout_response =
                    Some(BlockResponse::error_for(request.identity(), timeout));
                directive.retention_timeout_nanos = Some(
                    action
                        .coordinate
                        .virtual_nanos
                        .checked_add(stall_nanos)
                        .ok_or_else(|| StorageFaultResolutionError::Overflow {
                            binding: action.binding.clone(),
                            field: "retention_timeout_nanos",
                        })?,
                );
                directive.retention_recovery_event =
                    Some(storage_recovery_event_key(recovery_event));
                directive.retention_recovery_after_nanos = Some(action.coordinate.virtual_nanos);
            } else {
                directive.error_result = Some(timeout);
                directive.additional_latency_nanos = directive
                    .additional_latency_nanos
                    .checked_add(stall_nanos)
                    .ok_or_else(|| StorageFaultResolutionError::Overflow {
                        binding: action.binding.clone(),
                        field: "additional_latency_nanos",
                    })?;
            }
        }
        StorageEffectSpecification::DuplicateCompletion {
            copies,
            gap_nanos,
            protocol_policy,
        } => {
            if !probability_applies(context, action, request, 1_000_000)? {
                return Ok(());
            }
            let copies = if matches!(
                action.mapping_output.as_ref(),
                ResolvedMappingOutput::Parameter {
                    parameter: MappedEffectParameter::Probability,
                    ..
                }
            ) {
                u64::from(copies.get())
            } else {
                mapped_u64(action, MappedEffectParameter::UnsignedCount)?
                    .unwrap_or(u64::from(copies.get()))
            };
            let copies = u32::try_from(copies).map_err(|_error| {
                StorageFaultResolutionError::InvalidDirective {
                    binding: action.binding.clone(),
                    reason: String::from("duplicate count exceeds the block transport width"),
                }
            })?;
            let policy = world
                .fault_topology()
                .storage_policy_artifact(protocol_policy)
                .and_then(|artifact| match &artifact.artifact {
                    StoragePolicyArtifactKind::DuplicateCompletion(policy) => Some(policy),
                    _ => None,
                })
                .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
                    binding: action.binding.clone(),
                    reference: protocol_policy.clone(),
                    expected: "duplicate_completion",
                })?;
            let policy = match policy {
                StoragePolicyDuplicateCompletion::Ignore => BlockDuplicatePolicy::Ignore,
                StoragePolicyDuplicateCompletion::ProtocolError { result } => {
                    require_block_result(world, result, false, &action.binding)?;
                    BlockDuplicatePolicy::ProtocolError(BlockResponse::error_for(
                        request.identity(),
                        resolve_block_failure(world, result).ok_or_else(|| {
                            StorageFaultResolutionError::PolicyReference {
                                binding: action.binding.clone(),
                                reference: result.clone(),
                                expected: "non-success block typed_result",
                            }
                        })?,
                    ))
                }
                StoragePolicyDuplicateCompletion::Reset { transition_policy } => {
                    let transition = world
                        .fault_topology()
                        .storage_policy_artifact(transition_policy)
                        .and_then(|artifact| match &artifact.artifact {
                            StoragePolicyArtifactKind::ControllerTransition(policy) => Some(policy),
                            _ => None,
                        })
                        .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
                            binding: action.binding.clone(),
                            reference: transition_policy.clone(),
                            expected: "controller_transition",
                        })?;
                    let failure_result = resolve_block_failure(world, &transition.failure_result)
                        .ok_or_else(|| {
                        StorageFaultResolutionError::PolicyReference {
                            binding: action.binding.clone(),
                            reference: transition.failure_result.clone(),
                            expected: "non-success block typed_result",
                        }
                    })?;
                    BlockDuplicatePolicy::Reset(ResolvedBlockControllerTransition {
                        failure_result,
                        unadmitted: match transition.unadmitted {
                            StoragePolicyTransitionUnadmitted::Reject => {
                                BlockTransitionUnadmitted::Reject
                            }
                            StoragePolicyTransitionUnadmitted::WaitForRecovery => {
                                BlockTransitionUnadmitted::WaitForRecovery
                            }
                        },
                        queued: resolve_transition_pending(transition.queued),
                        executing: resolve_transition_pending(transition.executing),
                        resolved: resolve_transition_resolved(transition.resolved),
                        completed_undelivered: resolve_transition_undelivered(
                            transition.completed_undelivered,
                        ),
                        controller_buffer: resolve_transition_state(transition.controller_buffer),
                        volatile_cache: resolve_transition_state(transition.volatile_cache),
                        request_ids: match transition.request_ids {
                            StoragePolicyTransitionRequestIds::PreserveMonotonic => {
                                BlockTransportRequestIds::PreserveMonotonic
                            }
                            StoragePolicyTransitionRequestIds::NewEpochFromZero => {
                                BlockTransportRequestIds::NewEpochFromZero
                            }
                        },
                        duplicate_history: resolve_transition_state(transition.duplicate_history),
                        topology: match transition.topology {
                            StoragePolicyTransitionTopology::Preserve => {
                                BlockTransitionTopology::Preserve
                            }
                            StoragePolicyTransitionTopology::ReenumerateDeclared => {
                                BlockTransitionTopology::ReenumerateDeclared
                            }
                        },
                        recovery_nanos: transition.recovery_nanos.get(),
                    })
                }
            };
            directive
                .append_duplicate_completions(request.request_id, copies, *gap_nanos, policy)
                .map_err(|error| StorageFaultResolutionError::InvalidDirective {
                    binding: action.binding.clone(),
                    reason: error.to_string(),
                })?;
        }
        StorageEffectSpecification::ReadTransform { mutation } if request.op == BlockOp::Read => {
            match mutation {
                StorageReadMutation::BitFlip { range, mask } => {
                    directive
                        .read_transforms
                        .push(BlockFaultReadTransform::Xor {
                            offset: range.start(),
                            mask: mask.decode(),
                        });
                }
                StorageReadMutation::Stale { version } => {
                    let bytes = world
                        .fault_topology()
                        .storage_policy_artifact(version)
                        .and_then(|artifact| match &artifact.artifact {
                            StoragePolicyArtifactKind::Bytes { bytes } => Some(bytes),
                            _ => None,
                        })
                        .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
                            binding: action.binding.clone(),
                            reference: version.clone(),
                            expected: "bytes",
                        })?;
                    let count = usize::try_from(request.count).map_err(|_error| {
                        StorageFaultResolutionError::Overflow {
                            binding: action.binding.clone(),
                            field: "read count",
                        }
                    })?;
                    let replacement = bytes.get(..count).ok_or_else(|| {
                        StorageFaultResolutionError::PolicyReference {
                            binding: action.binding.clone(),
                            reference: version.clone(),
                            expected: "bytes covering the complete read",
                        }
                    })?;
                    directive
                        .read_transforms
                        .push(BlockFaultReadTransform::Replace {
                            bytes: replacement.to_vec(),
                        });
                }
                StorageReadMutation::Misdirected {
                    source_device,
                    source_range,
                } => {
                    if u64::from(request.count) > source_range.length() {
                        return Err(StorageFaultResolutionError::InvalidDirective {
                            binding: action.binding.clone(),
                            reason: String::from(
                                "misdirected read exceeds the declared source window",
                            ),
                        });
                    }
                    let (source, source_hash) = storage_device_by_id(world, source_device)
                        .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
                            binding: action.binding.clone(),
                            reference: source_device.clone(),
                            expected: "declared live block device",
                        })?;
                    let source_end = source_range
                        .start()
                        .checked_add(u64::from(request.count))
                        .ok_or_else(|| StorageFaultResolutionError::Overflow {
                            binding: action.binding.clone(),
                            field: "misdirected read source end",
                        })?;
                    if source_end > source.persistence.length_bytes {
                        return Err(StorageFaultResolutionError::InvalidDirective {
                            binding: action.binding.clone(),
                            reason: String::from(
                                "misdirected read exceeds the source device capacity",
                            ),
                        });
                    }
                    let bytes = read_source(source_hash, source_range.start(), request.count)
                        .map_err(|reason| StorageFaultResolutionError::InvalidDirective {
                            binding: action.binding.clone(),
                            reason: format!("read misdirected source bytes: {reason}"),
                        })?;
                    if bytes.len() != request.count as usize {
                        return Err(StorageFaultResolutionError::InvalidDirective {
                            binding: action.binding.clone(),
                            reason: String::from(
                                "misdirected source returned a non-exact byte count",
                            ),
                        });
                    }
                    directive
                        .read_transforms
                        .push(BlockFaultReadTransform::Replace { bytes });
                }
            }
        }
        StorageEffectSpecification::WriteDisposition {
            disposition,
            acknowledged_status,
        } if request.op == BlockOp::Write => {
            require_block_result(world, acknowledged_status, true, &action.binding)?;
            directive.write_disposition =
                resolve_write_disposition(world, context, action, request, disposition)?;
        }
        StorageEffectSpecification::PersistenceOrder {
            ordering_group,
            ordering_rule,
        } if request.op == BlockOp::Write => {
            let policy = world
                .fault_topology()
                .storage_policy_artifact(ordering_rule)
                .and_then(|artifact| match &artifact.artifact {
                    StoragePolicyArtifactKind::Persistence(policy) => Some(policy),
                    _ => None,
                })
                .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
                    binding: action.binding.clone(),
                    reference: ordering_rule.clone(),
                    expected: "persistence",
                })?;
            if !directive.persistence_transforms.is_empty()
                && directive.persistence_admitted_nanos != action.coordinate.virtual_nanos
            {
                return Err(StorageFaultResolutionError::InvalidDirective {
                    binding: action.binding.clone(),
                    reason: String::from(
                        "composed persistence transformations disagree on admission time",
                    ),
                });
            }
            directive.persistence_admitted_nanos = action.coordinate.virtual_nanos;
            directive
                .persistence_transforms
                .push(ResolvedBlockPersistenceTransform {
                    contributor: action.id().bytes,
                    ordering_group: *blake3::hash(ordering_group.as_str().as_bytes()).as_bytes(),
                    ordering: match policy.ordering {
                        StoragePolicyPersistenceOrdering::Preserve => {
                            BlockPersistenceOrdering::Preserve
                        }
                        StoragePolicyPersistenceOrdering::ReverseReady => {
                            BlockPersistenceOrdering::ReverseReady
                        }
                        StoragePolicyPersistenceOrdering::DescendingRange => {
                            BlockPersistenceOrdering::DescendingRange
                        }
                        StoragePolicyPersistenceOrdering::KeyedPermutation => {
                            BlockPersistenceOrdering::KeyedPermutation
                        }
                    },
                    delay_nanos: policy.delay_nanos,
                    preserve_barriers: policy.preserve_barriers,
                });
        }
        StorageEffectSpecification::VolatileCache {
            capacity_bytes,
            cache_policy,
            ..
        } if request.op == BlockOp::Write => {
            if directive.cache_policy.is_some() {
                return Err(StorageFaultResolutionError::InvalidDirective {
                    binding: action.binding.clone(),
                    reason: String::from("multiple volatile-cache policies conflict"),
                });
            }
            let policy = world
                .fault_topology()
                .storage_policy_artifact(cache_policy)
                .and_then(|artifact| match &artifact.artifact {
                    StoragePolicyArtifactKind::Cache(policy) => Some(policy),
                    _ => None,
                })
                .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
                    binding: action.binding.clone(),
                    reference: cache_policy.clone(),
                    expected: "cache",
                })?;
            let dirty_eviction = match &policy.dirty_eviction {
                StoragePolicyDirtyEviction::Persist => BlockFaultDirtyEviction::Persist,
                StoragePolicyDirtyEviction::Fail { result } => {
                    require_block_result(world, result, false, &action.binding)?;
                    BlockFaultDirtyEviction::Fail(resolve_block_failure(world, result).ok_or_else(
                        || StorageFaultResolutionError::PolicyReference {
                            binding: action.binding.clone(),
                            reference: result.clone(),
                            expected: "non-success block typed_result",
                        },
                    )?)
                }
            };
            directive.cache_policy = Some(ResolvedBlockCachePolicy {
                capacity_bytes: capacity_bytes.get(),
                eviction: match policy.eviction {
                    StoragePolicyCacheEviction::Fifo => BlockFaultCacheEviction::Fifo,
                    StoragePolicyCacheEviction::Lru => BlockFaultCacheEviction::Lru,
                    StoragePolicyCacheEviction::WritebackSequence => {
                        BlockFaultCacheEviction::WritebackSequence
                    }
                },
                dirty_eviction,
                power_loss_protected: policy.power_loss_protected,
            });
        }
        StorageEffectSpecification::VolatileCacheLoss { .. } => {
            return Err(unsupported(action, "request-local volatile-cache loss"));
        }
        StorageEffectSpecification::MediaRange {
            range,
            state,
            operations,
            count_threshold,
            time_threshold_nanos,
        } if operation_selected(operations.as_slice(), request.op)
            && request_intersects(request, range.start(), range.length()) =>
        {
            directive.media_rules.push(ResolvedBlockMediaRule {
                contributor: action.id().bytes,
                start: range.start(),
                length: range.length(),
                state: match state {
                    StorageMediaState::Bad => BlockMediaRangeState::Bad,
                    StorageMediaState::Latent => BlockMediaRangeState::Latent,
                    StorageMediaState::Poisoned => BlockMediaRangeState::Poisoned,
                    StorageMediaState::ReadOnly => BlockMediaRangeState::ReadOnly,
                },
                operations: [
                    BlockOp::Read,
                    BlockOp::Write,
                    BlockOp::Flush,
                    BlockOp::GetLength,
                    BlockOp::Discard,
                ]
                .into_iter()
                .filter(|operation| operation_selected(operations.as_slice(), *operation))
                .collect(),
                count_threshold: count_threshold.as_ref().map(|value| value.get()),
                time_threshold_nanos: time_threshold_nanos.as_ref().map(|value| value.get()),
            });
        }
        StorageEffectSpecification::FlashState { .. }
            if matches!(
                request.op,
                BlockOp::Read | BlockOp::Write | BlockOp::Discard
            ) =>
        {
            let rule = resolve_flash_rule(world, context, action, effect)?;
            if directive
                .persistence_media_rules
                .iter()
                .any(|existing| existing.contributor == rule.contributor)
            {
                return Err(StorageFaultResolutionError::InvalidDirective {
                    binding: action.binding.clone(),
                    reason: String::from("duplicate flash persistence contributor"),
                });
            }
            directive.persistence_media_rules.push(rule);
        }
        StorageEffectSpecification::FlushDisposition {
            kind,
            status,
            stall_nanos,
            recovery_event,
        } if request.op == BlockOp::Flush => {
            let success = !matches!(kind, StorageFlushKind::Error | StorageFlushKind::Stall);
            require_block_result(world, status, success, &action.binding)?;
            directive.flush_disposition = match kind {
                StorageFlushKind::Honest => BlockFaultFlushDisposition::Honest,
                StorageFlushKind::Error => BlockFaultFlushDisposition::Error(
                    resolve_block_failure(world, status).ok_or_else(|| {
                        StorageFaultResolutionError::PolicyReference {
                            binding: action.binding.clone(),
                            reference: status.clone(),
                            expected: "non-success block typed_result",
                        }
                    })?,
                ),
                StorageFlushKind::Lie => BlockFaultFlushDisposition::Lie,
                StorageFlushKind::Stall => {
                    let stall_nanos = stall_nanos.ok_or_else(|| {
                        StorageFaultResolutionError::InvalidDirective {
                            binding: action.binding.clone(),
                            reason: String::from("flush stall has no timeout duration"),
                        }
                    })?;
                    let stall_nanos = mapped_u64(action, MappedEffectParameter::DurationNanos)?
                        .unwrap_or(stall_nanos.get());
                    let timeout = resolve_block_failure(world, status).ok_or_else(|| {
                        StorageFaultResolutionError::PolicyReference {
                            binding: action.binding.clone(),
                            reference: status.clone(),
                            expected: "non-success block typed_result",
                        }
                    })?;
                    directive.retain_completion = true;
                    directive.retention_timeout_response =
                        Some(BlockResponse::error_for(request.identity(), timeout));
                    directive.retention_timeout_nanos = Some(
                        action
                            .coordinate
                            .virtual_nanos
                            .checked_add(stall_nanos)
                            .ok_or_else(|| StorageFaultResolutionError::Overflow {
                                binding: action.binding.clone(),
                                field: "retention_timeout_nanos",
                            })?,
                    );
                    directive.retention_recovery_event =
                        recovery_event.as_ref().map(storage_recovery_event_key);
                    directive.retention_recovery_after_nanos = recovery_event
                        .as_ref()
                        .map(|_event| action.coordinate.virtual_nanos);
                    BlockFaultFlushDisposition::Stall
                }
            };
        }
        StorageEffectSpecification::CompletionReorder {
            window_nanos,
            selection,
        } => {
            if !probability_applies(context, action, request, 1_000_000)? {
                return Ok(());
            }
            let window_nanos = if matches!(
                action.mapping_output.as_ref(),
                ResolvedMappingOutput::Parameter {
                    parameter: MappedEffectParameter::Probability,
                    ..
                }
            ) {
                window_nanos.get()
            } else {
                mapped_u64(action, MappedEffectParameter::UnsignedCount)?
                    .unwrap_or(window_nanos.get())
            };
            let delay = selection_delay(context, action, request, *selection, window_nanos);
            directive.additional_latency_nanos = directive
                .additional_latency_nanos
                .checked_add(delay)
                .ok_or_else(|| StorageFaultResolutionError::Overflow {
                    binding: action.binding.clone(),
                    field: "additional_latency_nanos",
                })?;
        }
        StorageEffectSpecification::Latency { .. }
        | StorageEffectSpecification::OperationFailure { .. }
        | StorageEffectSpecification::ReadTransform { .. }
        | StorageEffectSpecification::WriteDisposition { .. }
        | StorageEffectSpecification::PersistenceOrder { .. }
        | StorageEffectSpecification::VolatileCache { .. }
        | StorageEffectSpecification::MediaRange { .. }
        | StorageEffectSpecification::FlashState { .. }
        | StorageEffectSpecification::FlushDisposition { .. } => {}
        StorageEffectSpecification::ControllerLifecycle { .. }
        | StorageEffectSpecification::ArrayState { .. }
        | StorageEffectSpecification::NinePResult { .. }
        | StorageEffectSpecification::NinePVisibility { .. } => {
            return Err(unsupported(action, effect.kind().as_str()));
        }
    }
    Ok(())
}

fn resolve_service_classes(
    classes: Vec<StoragePolicyServiceClass>,
) -> Result<Vec<ResolvedBlockServiceClass>, StorageFaultResolutionError> {
    let mut resolved = classes
        .into_iter()
        .map(|class| {
            let mut operations = class
                .operations
                .as_slice()
                .iter()
                .copied()
                .map(block_op_from_fault_operation)
                .collect::<Result<Vec<_>, _>>()?;
            operations.sort_unstable_by_key(|operation| operation.to_wire());
            Ok(ResolvedBlockServiceClass {
                class: *blake3::hash(class.class.as_str().as_bytes()).as_bytes(),
                operations,
                priority: class.priority,
                weight: class.weight.get(),
            })
        })
        .collect::<Result<Vec<_>, StorageFaultResolutionError>>()?;
    resolved.sort_unstable_by_key(|class| class.class);
    Ok(resolved)
}

fn availability_max(
    left: BlockFaultAvailability,
    right: BlockFaultAvailability,
) -> BlockFaultAvailability {
    fn severity(value: BlockFaultAvailability) -> u8 {
        match value {
            BlockFaultAvailability::Online => 0,
            BlockFaultAvailability::Degraded => 1,
            BlockFaultAvailability::ReadOnly => 2,
            BlockFaultAvailability::Offline => 3,
        }
    }
    if severity(left) >= severity(right) {
        left
    } else {
        right
    }
}

fn operation_selected(operations: &[crucible::model::FaultOperation], operation: BlockOp) -> bool {
    let operation = block_fault_operation(operation);
    operations.binary_search(&operation).is_ok()
}

fn block_fault_operation(operation: BlockOp) -> FaultOperation {
    match operation {
        BlockOp::Read => FaultOperation::StorageRead,
        BlockOp::Write => FaultOperation::StorageWrite,
        BlockOp::Flush => FaultOperation::StorageFlush,
        BlockOp::GetLength => FaultOperation::StorageGetLength,
        BlockOp::Discard => FaultOperation::StorageDiscard,
    }
}

fn block_op_from_fault_operation(
    operation: FaultOperation,
) -> Result<BlockOp, StorageFaultResolutionError> {
    match operation {
        FaultOperation::StorageRead => Ok(BlockOp::Read),
        FaultOperation::StorageWrite => Ok(BlockOp::Write),
        FaultOperation::StorageFlush => Ok(BlockOp::Flush),
        FaultOperation::StorageGetLength => Ok(BlockOp::GetLength),
        FaultOperation::StorageDiscard => Ok(BlockOp::Discard),
        _ => Err(StorageFaultResolutionError::UnsupportedTarget),
    }
}

fn validate_request_opportunity(
    target: &ResolvedFaultTarget,
    request: &BlockRequest,
    request_sequence: u64,
    opportunity: &FaultOpportunity,
) -> Result<(), StorageFaultResolutionError> {
    let request_digest = request
        .encode()
        .map(|wire| ContentHash::from_bytes(&wire))
        .map_err(|_error| StorageFaultResolutionError::OpportunityMismatch)?;
    let expected_range = match request.op {
        BlockOp::Read | BlockOp::Write | BlockOp::Discard => {
            (Some(request.offset), Some(u64::from(request.count)))
        }
        BlockOp::Flush | BlockOp::GetLength => (None, None),
    };
    let payload_matches = matches!(
        opportunity.payload(),
        OpportunityPayload::StorageRequest {
            request_sequence: payload_sequence,
            start_byte,
            length_bytes,
            request_digest: payload_digest,
        } if *payload_sequence == request_sequence
            && (*start_byte, *length_bytes) == expected_range
            && *payload_digest == request_digest
    );
    if opportunity.target() != target
        || opportunity.operation() != block_fault_operation(request.op)
        || opportunity.sequence() != request_sequence
        || opportunity.direction().is_some()
        || !payload_matches
    {
        return Err(StorageFaultResolutionError::OpportunityMismatch);
    }
    Ok(())
}

fn validate_action_identity(
    action: &ResolvedBindingAction,
    opportunity: &FaultOpportunity,
) -> Result<(), StorageFaultResolutionError> {
    if action.phase != opportunity.phase() {
        return Err(StorageFaultResolutionError::ActionIdentity {
            binding: action.binding.clone(),
        });
    }
    match action.effect.lifetime() {
        EffectLifetime::Persistent
            if action.kind == BindingActionKind::UpsertPersistent
                && action.opportunity.is_none()
                && !matches!(action.cause, BindingActionCause::Opportunity(_)) =>
        {
            Ok(())
        }
        EffectLifetime::Opportunity
            if action.kind == BindingActionKind::Apply
                && action.opportunity == Some(opportunity.id())
                && action.cause == BindingActionCause::Opportunity(opportunity.id()) =>
        {
            Ok(())
        }
        EffectLifetime::Persistent | EffectLifetime::Opportunity => {
            Err(StorageFaultResolutionError::ActionIdentity {
                binding: action.binding.clone(),
            })
        }
        EffectLifetime::Impulse | EffectLifetime::StateMachine => Err(unsupported(
            action,
            "request-local impulse or state-machine application",
        )),
    }
}

fn selection_delay(
    context: StorageFaultResolutionContext,
    action: &ResolvedBindingAction,
    request: &BlockRequest,
    selection: StorageSelection,
    window_nanos: u64,
) -> u64 {
    match selection {
        StorageSelection::CanonicalFirst => 0,
        StorageSelection::CanonicalLast | StorageSelection::All => window_nanos,
        StorageSelection::KeyedUniform => keyed_inclusive(
            context,
            action,
            request,
            b"storage.completion-reorder.shift.v1",
            window_nanos,
        ),
    }
}

fn probability_applies(
    context: StorageFaultResolutionContext,
    action: &ResolvedBindingAction,
    request: &BlockRequest,
    fallback_millionths: u32,
) -> Result<bool, StorageFaultResolutionError> {
    let probability = match action.mapping_output.as_ref() {
        ResolvedMappingOutput::Hazard {
            probability_millionths,
        } => *probability_millionths,
        ResolvedMappingOutput::Parameter {
            parameter: MappedEffectParameter::Probability,
            value: SignalValue::ProbabilityMillionths(value),
        } => *value,
        ResolvedMappingOutput::Parameter {
            parameter: MappedEffectParameter::Probability,
            ..
        } => {
            return Err(StorageFaultResolutionError::MappingOutput {
                binding: action.binding.clone(),
                expected: MappedEffectParameter::Probability,
            });
        }
        _ => fallback_millionths,
    };
    if probability >= 1_000_000 {
        return Ok(true);
    }
    if probability == 0 {
        return Ok(false);
    }
    Ok(keyed_inclusive(
        context,
        action,
        request,
        b"storage.effect-probability.v1",
        999_999,
    ) < u64::from(probability))
}

fn keyed_inclusive(
    context: StorageFaultResolutionContext,
    action: &ResolvedBindingAction,
    request: &BlockRequest,
    domain: &[u8],
    maximum: u64,
) -> u64 {
    let range = u128::from(maximum) + 1;
    if range == (1_u128 << 64) {
        return keyed_word(context, action, request, domain, 0);
    }
    let rejection = ((1_u128 << 64) % range) as u64;
    let mut counter = 0_u64;
    loop {
        let word = keyed_word(context, action, request, domain, counter);
        let product = u128::from(word) * range;
        if product as u64 >= rejection {
            return (product >> 64) as u64;
        }
        counter = counter.wrapping_add(1);
    }
}

fn keyed_word(
    context: StorageFaultResolutionContext,
    action: &ResolvedBindingAction,
    request: &BlockRequest,
    domain: &[u8],
    counter: u64,
) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.storage-fault-choice.v1\0");
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(&context.scenario_seed.bytes);
    hasher.update(&action.id().bytes);
    hasher.update(&request.request_id.to_be_bytes());
    hasher.update(&request.offset.to_be_bytes());
    hasher.update(&request.count.to_be_bytes());
    hasher.update(&[match request.op {
        BlockOp::Read => 1,
        BlockOp::Write => 2,
        BlockOp::Flush => 3,
        BlockOp::GetLength => 4,
        BlockOp::Discard => 5,
    }]);
    hasher.update(blake3::hash(&request.data).as_bytes());
    hasher.update(&counter.to_be_bytes());
    let digest = hasher.finalize();
    let mut word = [0_u8; 8];
    word.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_be_bytes(word)
}

fn keyed_action_rank(
    context: StorageFaultResolutionContext,
    action: &ResolvedBindingAction,
    eligible_digest: [u8; 32],
    domain: &[u8],
    selected_sequence: u64,
) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.storage-fault-choice.v1\0");
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(&context.scenario_seed.bytes);
    hasher.update(&action.id().bytes);
    hasher.update(&eligible_digest);
    hasher.update(&selected_sequence.to_be_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_be_bytes(bytes)
}

fn volatile_cache_eligible_digest(eligible: &[u64]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.storage-volatile-loss-eligible.v1\0");
    hasher.update(
        &u64::try_from(eligible.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    for sequence in eligible {
        hasher.update(&sequence.to_be_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn ranges_intersect(
    left_offset: u64,
    left_length: u64,
    right_offset: u64,
    right_len: usize,
) -> bool {
    let left_end = left_offset.saturating_add(left_length);
    let right_end = right_offset.saturating_add(u64::try_from(right_len).unwrap_or(u64::MAX));
    left_offset < right_end && right_offset < left_end
}

fn mapped_u64(
    action: &ResolvedBindingAction,
    parameter: MappedEffectParameter,
) -> Result<Option<u64>, StorageFaultResolutionError> {
    let ResolvedMappingOutput::Parameter {
        parameter: actual,
        value,
    } = action.mapping_output.as_ref()
    else {
        return Ok(None);
    };
    if *actual != parameter {
        return Err(StorageFaultResolutionError::MappingOutput {
            binding: action.binding.clone(),
            expected: parameter,
        });
    }
    match (parameter, value) {
        (MappedEffectParameter::DurationNanos, SignalValue::DurationNanos(value))
        | (
            MappedEffectParameter::BitsPerSecond
            | MappedEffectParameter::BytesPerSecond
            | MappedEffectParameter::OperationsPerSecond,
            SignalValue::U64(value) | SignalValue::RatePerSecond(value),
        )
        | (MappedEffectParameter::UnsignedCount, SignalValue::U64(value)) => Ok(Some(*value)),
        (MappedEffectParameter::Probability, SignalValue::ProbabilityMillionths(value)) => {
            Ok(Some(u64::from(*value)))
        }
        _ => Err(StorageFaultResolutionError::MappingOutput {
            binding: action.binding.clone(),
            expected: parameter,
        }),
    }
}

fn require_block_result(
    world: &World,
    reference: &FaultObjectId,
    success: bool,
    binding: &FaultObjectId,
) -> Result<(), StorageFaultResolutionError> {
    let result = world
        .fault_topology()
        .storage_policy_artifact(reference)
        .and_then(|artifact| match &artifact.artifact {
            StoragePolicyArtifactKind::TypedResult(StoragePolicyTypedResult::Block { result }) => {
                Some(*result)
            }
            _ => None,
        })
        .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
            binding: binding.clone(),
            reference: reference.clone(),
            expected: "block typed_result",
        })?;
    if (result == crucible::model::StoragePolicyResult::Success) != success {
        return Err(StorageFaultResolutionError::PolicyReference {
            binding: binding.clone(),
            reference: reference.clone(),
            expected: if success {
                "successful block typed_result"
            } else {
                "non-success block typed_result"
            },
        });
    }
    Ok(())
}

fn resolve_block_failure(world: &World, reference: &FaultObjectId) -> Option<BlockFaultResult> {
    let result = world
        .fault_topology()
        .storage_policy_artifact(reference)
        .and_then(|artifact| match &artifact.artifact {
            StoragePolicyArtifactKind::TypedResult(StoragePolicyTypedResult::Block { result }) => {
                Some(*result)
            }
            _ => None,
        })?;
    block_failure_from_result(result)
}

const fn resolve_transition_pending(
    policy: StoragePolicyTransitionPendingOperation,
) -> BlockTransitionPending {
    match policy {
        StoragePolicyTransitionPendingOperation::Fail => BlockTransitionPending::Fail,
        StoragePolicyTransitionPendingOperation::RetryPreserveId => {
            BlockTransitionPending::RetryPreserveId
        }
        StoragePolicyTransitionPendingOperation::RetryNewId => BlockTransitionPending::RetryNewId,
    }
}

const fn resolve_transition_resolved(
    policy: StoragePolicyTransitionResolvedOperation,
) -> BlockTransitionResolved {
    match policy {
        StoragePolicyTransitionResolvedOperation::Complete => BlockTransitionResolved::Complete,
        StoragePolicyTransitionResolvedOperation::Fail => BlockTransitionResolved::Fail,
        StoragePolicyTransitionResolvedOperation::RetryPreserveId => {
            BlockTransitionResolved::RetryPreserveId
        }
        StoragePolicyTransitionResolvedOperation::RetryNewId => BlockTransitionResolved::RetryNewId,
    }
}

const fn resolve_transition_undelivered(
    policy: StoragePolicyTransitionUndeliveredOperation,
) -> BlockTransitionUndelivered {
    match policy {
        StoragePolicyTransitionUndeliveredOperation::Complete => {
            BlockTransitionUndelivered::Complete
        }
        StoragePolicyTransitionUndeliveredOperation::Fail => BlockTransitionUndelivered::Fail,
        StoragePolicyTransitionUndeliveredOperation::RetryPreserveId => {
            BlockTransitionUndelivered::RetryPreserveId
        }
        StoragePolicyTransitionUndeliveredOperation::RetryNewId => {
            BlockTransitionUndelivered::RetryNewId
        }
        StoragePolicyTransitionUndeliveredOperation::DropCompletion => {
            BlockTransitionUndelivered::DropCompletion
        }
    }
}

const fn resolve_transition_state(policy: StoragePolicyTransitionState) -> BlockTransitionState {
    match policy {
        StoragePolicyTransitionState::Preserve => BlockTransitionState::Preserve,
        StoragePolicyTransitionState::Lose => BlockTransitionState::Lose,
    }
}

fn block_failure_from_result(
    result: crucible::model::StoragePolicyResult,
) -> Option<BlockFaultResult> {
    match result {
        crucible::model::StoragePolicyResult::Success => None,
        crucible::model::StoragePolicyResult::Offline => Some(BlockFaultResult::Offline),
        crucible::model::StoragePolicyResult::ReadOnly => Some(BlockFaultResult::ReadOnly),
        crucible::model::StoragePolicyResult::InvalidRange => Some(BlockFaultResult::InvalidRange),
        crucible::model::StoragePolicyResult::Busy => Some(BlockFaultResult::Busy),
        crucible::model::StoragePolicyResult::Timeout => Some(BlockFaultResult::Timeout),
        crucible::model::StoragePolicyResult::MediumError => Some(BlockFaultResult::MediumError),
        crucible::model::StoragePolicyResult::IntegrityError => {
            Some(BlockFaultResult::IntegrityError)
        }
        crucible::model::StoragePolicyResult::IoError => Some(BlockFaultResult::IoError),
        crucible::model::StoragePolicyResult::NoSpace => Some(BlockFaultResult::NoSpace),
        crucible::model::StoragePolicyResult::NotFound => Some(BlockFaultResult::NotFound),
        crucible::model::StoragePolicyResult::Stale => Some(BlockFaultResult::Stale),
    }
}

fn storage_policy<T>(
    world: &World,
    reference: &FaultObjectId,
    binding: &FaultObjectId,
    expected: &'static str,
    select: impl FnOnce(&StoragePolicyArtifactKind) -> Option<T>,
) -> Result<T, StorageFaultResolutionError> {
    world
        .fault_topology()
        .storage_policy_artifact(reference)
        .and_then(|artifact| select(&artifact.artifact))
        .ok_or_else(|| StorageFaultResolutionError::PolicyReference {
            binding: binding.clone(),
            reference: reference.clone(),
            expected,
        })
}

fn resolve_flash_rule(
    world: &World,
    context: StorageFaultResolutionContext,
    action: &ResolvedBindingAction,
    effect: &StorageEffectSpecification,
) -> Result<ResolvedBlockFlashRule, StorageFaultResolutionError> {
    let StorageEffectSpecification::FlashState {
        erase_block_bytes,
        program_page_bytes,
        endurance_cycles,
        retention_rule,
        read_disturb_rule,
        program_erase_rule,
    } = effect
    else {
        return Err(unsupported(action, "non-flash persistence-media effect"));
    };
    let retention = storage_policy(
        world,
        retention_rule,
        &action.binding,
        "retention",
        |kind| match kind {
            StoragePolicyArtifactKind::Retention(policy) => Some(policy.clone()),
            _ => None,
        },
    )?;
    let read_disturb = storage_policy(
        world,
        read_disturb_rule,
        &action.binding,
        "read_disturb",
        |kind| match kind {
            StoragePolicyArtifactKind::ReadDisturb(policy) => Some(policy.clone()),
            _ => None,
        },
    )?;
    let program_erase = storage_policy(
        world,
        program_erase_rule,
        &action.binding,
        "program_erase",
        |kind| match kind {
            StoragePolicyArtifactKind::ProgramErase(policy) => Some(policy.clone()),
            _ => None,
        },
    )?;
    let contributor = action.id().bytes;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.storage-flash-choice-key.v1\0");
    hasher.update(&context.scenario_seed.bytes);
    hasher.update(&contributor);
    if let Some(opportunity) = action.opportunity {
        hasher.update(&opportunity.bytes);
    }
    Ok(ResolvedBlockFlashRule {
        contributor,
        choice_key: *hasher.finalize().as_bytes(),
        erase_block_bytes: erase_block_bytes.get(),
        program_page_bytes: program_page_bytes.get(),
        endurance_cycles: endurance_cycles.get(),
        retention: ResolvedBlockFlashRetention {
            minimum_age_nanos: retention.minimum_age_nanos.get(),
            wear_age_nanos: retention.wear_age_nanos,
            bit_probability_millionths: retention.bit_probability.get(),
            maximum_changed_bits: retention.maximum_changed_bits.get(),
        },
        read_disturb: ResolvedBlockFlashReadDisturb {
            read_threshold: read_disturb.read_threshold.get(),
            neighbor_pages: read_disturb.neighbor_pages.get(),
            bit_probability_millionths: read_disturb.bit_probability.get(),
            maximum_changed_bits: read_disturb.maximum_changed_bits.get(),
        },
        program_erase: ResolvedBlockFlashProgramErase {
            program_probability_millionths: program_erase.program_probability.get(),
            erase_probability_millionths: program_erase.erase_probability.get(),
            worn_probability_millionths: program_erase.worn_probability.get(),
            partial_program: program_erase.partial_program,
            partial_erase: program_erase.partial_erase,
        },
    })
}

fn resolve_write_disposition(
    world: &World,
    context: StorageFaultResolutionContext,
    action: &ResolvedBindingAction,
    request: &BlockRequest,
    disposition: &StorageWriteDispositionKind,
) -> Result<BlockFaultWriteDisposition, StorageFaultResolutionError> {
    let count = u64::from(request.count);
    let atomic_write_bytes = u64::from(
        target_storage_device(world, &action.target)?
            .persistence
            .atomic_write_bytes,
    );
    let fragments = atomic_fragments(request, atomic_write_bytes, &action.binding)?;
    match disposition {
        StorageWriteDispositionKind::Apply => Ok(BlockFaultWriteDisposition::Apply),
        StorageWriteDispositionKind::Lost { selection } => {
            if *selection == StorageSelection::All {
                return Ok(BlockFaultWriteDisposition::Lost);
            }
            let selected =
                selected_fragment_index(context, action, request, *selection, fragments.len())?;
            let spans = fragments
                .iter()
                .enumerate()
                .filter_map(|(index, fragment)| (index != selected).then_some(*fragment))
                .collect::<Vec<_>>();
            if spans.is_empty() {
                Ok(BlockFaultWriteDisposition::Lost)
            } else {
                Ok(BlockFaultWriteDisposition::Torn { spans })
            }
        }
        StorageWriteDispositionKind::Torn { selection } => {
            if *selection == StorageSelection::All || fragments.len() < 2 {
                return Err(StorageFaultResolutionError::InvalidDirective {
                    binding: action.binding.clone(),
                    reason: String::from(
                        "a torn write must select a strict nonempty set of atomic fragments",
                    ),
                });
            }
            let selected =
                selected_fragment_index(context, action, request, *selection, fragments.len())?;
            Ok(BlockFaultWriteDisposition::Torn {
                spans: vec![fragments[selected]],
            })
        }
        StorageWriteDispositionKind::Misdirected {
            destination_device,
            destination_range,
        } => {
            let source = target_storage_device(world, &action.target)?;
            let (destination_device_contract, destination_hash) =
                storage_device_by_id(world, destination_device).ok_or_else(|| {
                    StorageFaultResolutionError::PolicyReference {
                        binding: action.binding.clone(),
                        reference: destination_device.clone(),
                        expected: "declared live block device",
                    }
                })?;
            if count > destination_range.length() {
                return Err(StorageFaultResolutionError::InvalidDirective {
                    binding: action.binding.clone(),
                    reason: String::from(
                        "misdirected write exceeds the declared destination window",
                    ),
                });
            }
            let destination_end =
                destination_range
                    .start()
                    .checked_add(count)
                    .ok_or_else(|| StorageFaultResolutionError::Overflow {
                        binding: action.binding.clone(),
                        field: "misdirected write destination end",
                    })?;
            if destination_end > destination_device_contract.persistence.length_bytes {
                return Err(StorageFaultResolutionError::InvalidDirective {
                    binding: action.binding.clone(),
                    reason: String::from(
                        "misdirected write exceeds the destination device capacity",
                    ),
                });
            }
            let destination = if destination_device.as_str() == source.device.as_str() {
                BlockFaultMisdirectionDestination::AttachedDevice
            } else {
                BlockFaultMisdirectionDestination::ExternalDevice(destination_hash.bytes)
            };
            Ok(BlockFaultWriteDisposition::Misdirected {
                destination,
                destination_offset: destination_range.start(),
            })
        }
    }
}

fn atomic_fragments(
    request: &BlockRequest,
    atomic_write_bytes: u64,
    binding: &FaultObjectId,
) -> Result<Vec<BlockFaultByteSpan>, StorageFaultResolutionError> {
    if request.count == 0 || atomic_write_bytes == 0 {
        return Err(StorageFaultResolutionError::InvalidDirective {
            binding: binding.clone(),
            reason: String::from("write mutation requires nonzero request and atomic widths"),
        });
    }
    let request_end = request
        .offset
        .checked_add(u64::from(request.count))
        .ok_or_else(|| StorageFaultResolutionError::Overflow {
            binding: binding.clone(),
            field: "write request end",
        })?;
    let mut absolute = request.offset;
    let mut fragments = Vec::new();
    while absolute < request_end {
        let remainder = absolute % atomic_write_bytes;
        let available = if remainder == 0 {
            atomic_write_bytes
        } else {
            atomic_write_bytes - remainder
        };
        let fragment_end = absolute.saturating_add(available).min(request_end);
        fragments.push(BlockFaultByteSpan {
            start: absolute - request.offset,
            length: fragment_end - absolute,
        });
        absolute = fragment_end;
    }
    Ok(fragments)
}

fn selected_fragment_index(
    context: StorageFaultResolutionContext,
    action: &ResolvedBindingAction,
    request: &BlockRequest,
    selection: StorageSelection,
    fragment_count: usize,
) -> Result<usize, StorageFaultResolutionError> {
    let last = fragment_count.checked_sub(1).ok_or_else(|| {
        StorageFaultResolutionError::InvalidDirective {
            binding: action.binding.clone(),
            reason: String::from("write mutation requires at least one atomic fragment"),
        }
    })?;
    match selection {
        StorageSelection::CanonicalFirst => Ok(0),
        StorageSelection::CanonicalLast => Ok(last),
        StorageSelection::KeyedUniform => {
            let maximum =
                u64::try_from(last).map_err(|_error| StorageFaultResolutionError::Overflow {
                    binding: action.binding.clone(),
                    field: "atomic fragment count",
                })?;
            usize::try_from(keyed_inclusive(
                context,
                action,
                request,
                b"storage.write-disposition.atomic-fragment.v1",
                maximum,
            ))
            .map_err(|_error| StorageFaultResolutionError::Overflow {
                binding: action.binding.clone(),
                field: "selected atomic fragment",
            })
        }
        StorageSelection::All => Err(StorageFaultResolutionError::InvalidDirective {
            binding: action.binding.clone(),
            reason: String::from("all does not identify one atomic fragment"),
        }),
    }
}

fn request_intersects(request: &BlockRequest, range_start: u64, range_length: u64) -> bool {
    match request.op {
        BlockOp::Read | BlockOp::Write | BlockOp::Discard => {
            let Some(request_end) = request.offset.checked_add(u64::from(request.count)) else {
                return false;
            };
            let Some(range_end) = range_start.checked_add(range_length) else {
                return false;
            };
            request.offset < range_end && range_start < request_end
        }
        BlockOp::Flush | BlockOp::GetLength => true,
    }
}

fn target_capacity(
    world: &World,
    target: &ResolvedFaultTarget,
) -> Result<u64, StorageFaultResolutionError> {
    Ok(target_storage_device(world, target)?
        .persistence
        .length_bytes)
}

fn target_storage_device<'a>(
    world: &'a World,
    target: &ResolvedFaultTarget,
) -> Result<&'a crucible::model::WorldStorageFaultDevice, StorageFaultResolutionError> {
    let hash = match target {
        ResolvedFaultTarget::BlockDevice { device }
        | ResolvedFaultTarget::BlockRange { device, .. } => device,
        _ => return Err(StorageFaultResolutionError::UnsupportedTarget),
    };
    let node = world
        .io_nodes()
        .find(|node| node.fault_target_hash() == *hash)
        .ok_or(StorageFaultResolutionError::UnsupportedTarget)?;
    world
        .fault_topology()
        .storage_devices
        .iter()
        .find(|device| {
            device.kind == crucible::model::WorldStorageKind::Block
                && device.device.as_str() == node.id.name.as_str()
        })
        .ok_or(StorageFaultResolutionError::UnsupportedTarget)
}

fn storage_device_by_id<'a>(
    world: &'a World,
    device_id: &FaultObjectId,
) -> Option<(&'a crucible::model::WorldStorageFaultDevice, ContentHash)> {
    let device = world
        .fault_topology()
        .storage_devices
        .iter()
        .find(|device| {
            device.kind == crucible::model::WorldStorageKind::Block
                && device.device.as_str() == device_id.as_str()
        })?;
    let node = world.io_nodes().find(|node| {
        matches!(node.kind, crucible::model::WorldIoNodeKind::Block { .. })
            && node.id.name == device_id.as_str()
    })?;
    Some((device, node.fault_target_hash()))
}

/// Returns the process-independent subscription key stored by the block device.
#[must_use]
pub fn storage_recovery_event_key(event: &FaultObjectId) -> [u8; 32] {
    ContentHash::from_canonical_material("crucible.storage-recovery-event.v1", event.as_str()).bytes
}

fn unsupported(
    action: &ResolvedBindingAction,
    parameter: &'static str,
) -> StorageFaultResolutionError {
    StorageFaultResolutionError::UnsupportedEffect {
        binding: action.binding.clone(),
        parameter,
    }
}

/// Deterministic failure to resolve a production block directive.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StorageFaultResolutionError {
    /// The supplied opportunity does not describe this target and operation.
    #[error("storage opportunity does not match this block request")]
    OpportunityMismatch,
    /// Independently sampled phase contributions overflowed during composition.
    #[error("storage phase composition overflowed `{field}`")]
    PhaseMergeOverflow {
        /// Overflowed directive field.
        field: &'static str,
    },
    /// Independently sampled phases selected mutually exclusive request behavior.
    #[error("storage phase composition conflicts on `{field}`")]
    PhaseMergeConflict {
        /// Conflicting directive field.
        field: &'static str,
    },
    /// An action is not bound to the supplied opportunity and phase.
    #[error("storage binding `{binding}` is not bound to this request opportunity")]
    ActionIdentity {
        /// Binding carrying invalid action identity.
        binding: FaultObjectId,
    },
    /// An action selected a different concrete target.
    #[error("storage binding `{binding}` does not target this block request")]
    TargetMismatch {
        /// Mismatched binding.
        binding: FaultObjectId,
    },
    /// Removal actions must be applied to host state before request resolution.
    #[error("storage binding `{binding}` supplied a removal action at request resolution")]
    RemovalAction {
        /// Invalid binding.
        binding: FaultObjectId,
    },
    /// A non-storage action crossed the storage adapter boundary.
    #[error("binding `{binding}` supplied a non-storage effect to the block resolver")]
    NonStorageAction {
        /// Invalid binding.
        binding: FaultObjectId,
    },
    /// A referenced policy artifact was missing or wrong-shaped.
    #[error("storage binding `{binding}` reference `{reference}` is not {expected}")]
    PolicyReference {
        /// Binding containing the reference.
        binding: FaultObjectId,
        /// Referenced artifact.
        reference: FaultObjectId,
        /// Required artifact shape.
        expected: &'static str,
    },
    /// Checked directive composition overflowed.
    #[error("storage binding `{binding}` overflowed `{field}`")]
    Overflow {
        /// Binding whose contribution overflowed.
        binding: FaultObjectId,
        /// Overflowed field.
        field: &'static str,
    },
    /// A dynamic mapping named the wrong effect field or carried the wrong value type.
    #[error("storage binding `{binding}` did not map a valid {expected:?} value")]
    MappingOutput {
        /// Binding carrying the invalid mapping.
        binding: FaultObjectId,
        /// Effect field required by this resolver branch.
        expected: MappedEffectParameter,
    },
    /// The composed device directive violates an exact live invariant.
    #[error("storage binding `{binding}` produced an invalid block directive: {reason}")]
    InvalidDirective {
        /// Binding that produced the invalid contribution.
        binding: FaultObjectId,
        /// Stable failure detail.
        reason: String,
    },
    /// Locked replay observed a different pre-loss cache entry set.
    #[error(
        "storage binding `{binding}` cache-loss replay digest mismatch: expected {expected:?}, actual {actual:?}"
    )]
    ReplayEntrySetMismatch {
        /// Binding whose recorded transition is being replayed.
        binding: FaultObjectId,
        /// Digest recorded by the original execution.
        expected: [u8; 32],
        /// Digest computed from the live state before mutation.
        actual: [u8; 32],
    },
    /// The live adapter does not yet implement the complete selected semantics.
    #[error("storage binding `{binding}` selects unavailable live semantics: {parameter}")]
    UnsupportedEffect {
        /// Binding selecting the effect.
        binding: FaultObjectId,
        /// Unsupported semantic component.
        parameter: &'static str,
    },
    /// The selected target is not a declared live block device.
    #[error("storage action target is not a declared live block device")]
    UnsupportedTarget,
}

#[cfg(test)]
#[path = "storage_fault_resolver_tests.rs"]
mod tests;
