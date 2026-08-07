//! Production resolution of host storage actions into exact block directives.
//!
//! Signal evaluation and keyed hazard decisions occur in `crucible`. This
//! module is the live block-adapter boundary: it consumes only committed,
//! typed [`ResolvedBindingAction`] values for one exact request and translates
//! the currently executable subset into a [`ResolvedBlockFaultDirective`]. It
//! never evaluates signals, consults host time, or silently accepts an effect
//! whose device semantics are not implemented.

use crucible::model::{
    BindingActionCause, BindingActionKind, ContentHash, EffectLifetime, EffectSpecification,
    FaultContractError, FaultCoordinate, FaultObjectId, FaultOperation, FaultOpportunity,
    FaultPhase, MappedEffectParameter, OpportunityPayload, ResolvedBindingAction,
    ResolvedFaultTarget, ResolvedMappingOutput, SignalValue, StorageAvailabilityState,
    StorageEffectSpecification, StorageFlushKind, StorageMediaState, StoragePolicyArtifactKind,
    StoragePolicyCacheEviction, StoragePolicyDirtyEviction, StoragePolicyDuplicateCompletion,
    StoragePolicyPersistenceOrdering, StoragePolicyQueueDiscipline, StoragePolicyServiceClass,
    StoragePolicyTypedResult, StorageReadMutation, StorageSelection, StorageVolatileCacheLossKind,
    StorageVolatileCacheLossSelector, StorageWriteDispositionKind, World,
    WorldCompletionDurability, WorldDiscardSemantics,
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
    BlockFaultReadTransform, BlockFaultResult, BlockFaultState, BlockFaultWriteDisposition,
    BlockMediaRangeState, BlockOp, BlockPersistenceOpportunity, BlockPersistenceOrdering,
    BlockRequest, BlockRequestPersistenceOpportunity, BlockResponse, BlockServiceDiscipline,
    ResolvedBlockCachePolicy, ResolvedBlockFaultDirective, ResolvedBlockFlashProgramErase,
    ResolvedBlockFlashReadDisturb, ResolvedBlockFlashRetention, ResolvedBlockFlashRule,
    ResolvedBlockMediaRule, ResolvedBlockPersistenceMediaDirective,
    ResolvedBlockPersistenceTransform, ResolvedBlockServiceClass, ResolvedBlockServiceRule,
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
        _ => return Err(StorageFaultResolutionError::OpportunityMismatch),
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
/// identity differs, or [`StorageFaultResolutionError::PhaseMergeOverflow`]
/// when latency composition exceeds `u64`.
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
            accumulated.read_transforms = partial.read_transforms;
            accumulated.media_rules.extend(partial.media_rules);
        }
        FaultPhase::Persist => {
            accumulated.execution_nanos = partial.execution_nanos;
            accumulated.write_disposition = partial.write_disposition;
            accumulated.flush_disposition = partial.flush_disposition;
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
        _ => return Err(StorageFaultResolutionError::OpportunityMismatch),
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
        apply_effect(world, request, context, action, effect, &mut directive)?;
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
            if let Some(stall_nanos) = stall_nanos {
                let stall_nanos = mapped_u64(action, MappedEffectParameter::DurationNanos)?
                    .unwrap_or(stall_nanos.get());
                directive.error_result =
                    Some(resolve_block_failure(world, timeout_result).ok_or_else(|| {
                        StorageFaultResolutionError::PolicyReference {
                            binding: action.binding.clone(),
                            reference: timeout_result.clone(),
                            expected: "non-success block typed_result",
                        }
                    })?);
                directive.additional_latency_nanos = directive
                    .additional_latency_nanos
                    .checked_add(stall_nanos)
                    .ok_or_else(|| StorageFaultResolutionError::Overflow {
                        binding: action.binding.clone(),
                        field: "additional_latency_nanos",
                    })?;
            } else if recovery_event.is_some() {
                return Err(unsupported(action, "recovery-event completion stall"));
            } else {
                return Err(StorageFaultResolutionError::InvalidDirective {
                    binding: action.binding.clone(),
                    reason: String::from("stall has neither a duration nor a recovery event"),
                });
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
                    BlockDuplicatePolicy::ProtocolError(BlockResponse::error(
                        request.request_id,
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
                    require_policy_kind(
                        world,
                        transition_policy,
                        &action.binding,
                        "controller_transition",
                        |artifact| {
                            matches!(artifact, StoragePolicyArtifactKind::ControllerTransition(_))
                        },
                    )?;
                    BlockDuplicatePolicy::Reset
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
                StorageReadMutation::Misdirected { .. } => {
                    return Err(unsupported(action, "cross-device misdirected read"));
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
        StorageEffectSpecification::FlushDisposition { kind, status }
            if request.op == BlockOp::Flush =>
        {
            let success = !matches!(kind, StorageFlushKind::Error);
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
                    return Err(unsupported(action, "event-driven flush stall"));
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
        _ => return Err(unsupported(action, effect.kind().as_str())),
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

fn require_policy_kind(
    world: &World,
    reference: &FaultObjectId,
    binding: &FaultObjectId,
    expected: &'static str,
    predicate: impl FnOnce(&StoragePolicyArtifactKind) -> bool,
) -> Result<(), StorageFaultResolutionError> {
    let valid = world
        .fault_topology()
        .storage_policy_artifact(reference)
        .is_some_and(|artifact| predicate(&artifact.artifact));
    if !valid {
        return Err(StorageFaultResolutionError::PolicyReference {
            binding: binding.clone(),
            reference: reference.clone(),
            expected,
        });
    }
    Ok(())
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
            if destination_device.as_str() != source.device.as_str() {
                return Err(unsupported(action, "cross-device misdirected write"));
            }
            if count > destination_range.length() {
                return Err(StorageFaultResolutionError::InvalidDirective {
                    binding: action.binding.clone(),
                    reason: String::from(
                        "misdirected write exceeds the declared destination window",
                    ),
                });
            }
            Ok(BlockFaultWriteDisposition::Misdirected {
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
mod tests {
    use std::sync::Arc;

    use crucible::model::{
        BindingActionCause, BoundedCount, ContentHash, CountLimit, EFFECT_SEMANTIC_VERSION,
        EffectLifetime, EffectRequest, FaultCoordinate, FaultOperation, FaultPhase, OperationSet,
        PositiveU64, SignalId, StoragePolicyServiceClass,
    };

    use super::*;

    fn id(value: &str) -> FaultObjectId {
        FaultObjectId::parse(value)
            .unwrap_or_else(|error| panic!("test object ID should be valid: {error}"))
    }

    fn target() -> ResolvedFaultTarget {
        ResolvedFaultTarget::BlockDevice {
            device: ContentHash::from_bytes(b"block-device-hash"),
        }
    }

    fn action(
        binding: &str,
        lifetime: EffectLifetime,
        phase: FaultPhase,
        specification: StorageEffectSpecification,
        mapping_output: ResolvedMappingOutput,
    ) -> ResolvedBindingAction {
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            lifetime,
            EffectSpecification::Storage(specification),
        )
        .unwrap_or_else(|error| panic!("test effect should be valid: {error}"));
        ResolvedBindingAction {
            kind: match lifetime {
                EffectLifetime::Persistent | EffectLifetime::StateMachine => {
                    BindingActionKind::UpsertPersistent
                }
                EffectLifetime::Opportunity | EffectLifetime::Impulse => BindingActionKind::Apply,
            },
            binding: id(binding),
            target: target(),
            phase,
            effect: Arc::new(effect),
            mapping_output: Arc::new(mapping_output),
            mapped_digest: ContentHash::from_bytes(binding.as_bytes()),
            transition_sequence: 1,
            opportunity: None,
            coordinate: FaultCoordinate {
                virtual_nanos: 10,
                retired_instructions: None,
            },
            cause: BindingActionCause::Signal,
        }
    }

    fn opaque_world() -> World {
        World::from_content_hash(ContentHash::from_bytes(b"storage-resolver-test-world"))
    }

    fn context() -> StorageFaultResolutionContext {
        StorageFaultResolutionContext::new(ContentHash::from_bytes(b"storage-resolver-seed"))
    }

    fn opportunity(request: &BlockRequest, phase: FaultPhase) -> FaultOpportunity {
        let wire = request
            .encode()
            .unwrap_or_else(|error| panic!("test request should encode: {error}"));
        block_request_fault_opportunity(
            target(),
            request,
            *blake3::hash(&wire).as_bytes(),
            phase,
            FaultCoordinate {
                virtual_nanos: 10,
                retired_instructions: None,
            },
            1,
        )
        .unwrap_or_else(|error| panic!("test opportunity should be valid: {error}"))
    }

    fn bind_to_opportunity(
        mut action: ResolvedBindingAction,
        opportunity: &FaultOpportunity,
    ) -> ResolvedBindingAction {
        action.opportunity = Some(opportunity.id());
        action.cause = BindingActionCause::Opportunity(opportunity.id());
        action
    }

    #[test]
    fn service_classes_are_canonical_after_identity_and_operation_conversion() {
        let classes = vec![
            StoragePolicyServiceClass {
                class: id("class-a"),
                operations: OperationSet::new(vec![
                    FaultOperation::StorageGetLength,
                    FaultOperation::StorageDiscard,
                ])
                .unwrap_or_else(|error| panic!("service operations should be valid: {error}")),
                priority: 1,
                weight: PositiveU64::new("weight", 1)
                    .unwrap_or_else(|error| panic!("service weight should be valid: {error}")),
            },
            StoragePolicyServiceClass {
                class: id("class-b"),
                operations: OperationSet::new(vec![FaultOperation::StorageRead])
                    .unwrap_or_else(|error| panic!("service operations should be valid: {error}")),
                priority: 0,
                weight: PositiveU64::new("weight", 2)
                    .unwrap_or_else(|error| panic!("service weight should be valid: {error}")),
            },
        ];

        let resolved = resolve_service_classes(classes)
            .unwrap_or_else(|error| panic!("service classes should resolve: {error}"));

        assert!(
            resolved
                .windows(2)
                .all(|pair| pair[0].class < pair[1].class)
        );
        assert!(resolved.iter().all(|class| {
            class
                .operations
                .windows(2)
                .all(|pair| pair[0].to_wire() < pair[1].to_wire())
        }));
        for class in &resolved {
            assert!(
                class.operations.contains(&BlockOp::Discard)
                    != class.operations.contains(&BlockOp::Read)
            );
        }
    }

    #[test]
    fn persistence_resolver_accepts_discard_and_rejects_operation_aliasing() {
        let physical = BlockPersistenceOpportunity {
            sequence: 4,
            request_id: 17,
            operation_sequence: 3,
            operation: BlockOp::Discard,
            request_digest: [3; 32],
            offset: 4096,
            count: 4096,
            intended_digest: [5; 32],
            ready_nanos: 10,
        };
        let coordinate = FaultCoordinate {
            virtual_nanos: 10,
            retired_instructions: None,
        };
        let payload = OpportunityPayload::StorageRequest {
            request_sequence: physical.sequence,
            start_byte: Some(physical.offset),
            length_bytes: Some(u64::from(physical.count)),
            request_digest: ContentHash {
                bytes: physical.intended_digest,
            },
        };
        let discard = FaultOpportunity::new(
            target(),
            FaultOperation::StorageDiscard,
            FaultPhase::Persist,
            coordinate,
            physical.sequence,
            None,
            payload.clone(),
        )
        .unwrap_or_else(|error| panic!("discard persistence opportunity should build: {error}"));
        let resolved = resolve_block_persistence_media_directive(
            &opaque_world(),
            &target(),
            &physical,
            &discard,
            context(),
            std::iter::empty::<&ResolvedBindingAction>(),
        )
        .unwrap_or_else(|error| panic!("discard persistence should resolve: {error}"));
        assert_eq!(resolved.opportunity, physical);
        assert!(resolved.flash_rules.is_empty());

        let write_alias = FaultOpportunity::new(
            target(),
            FaultOperation::StorageWrite,
            FaultPhase::Persist,
            coordinate,
            physical.sequence,
            None,
            payload,
        )
        .unwrap_or_else(|error| panic!("write alias opportunity should build: {error}"));
        assert!(matches!(
            resolve_block_persistence_media_directive(
                &opaque_world(),
                &target(),
                &physical,
                &write_alias,
                context(),
                std::iter::empty::<&ResolvedBindingAction>(),
            ),
            Err(StorageFaultResolutionError::OpportunityMismatch)
        ));
    }

    #[test]
    fn composition_is_canonical_and_uses_most_severe_availability() {
        let degraded = action(
            "z-degraded",
            EffectLifetime::Persistent,
            FaultPhase::Admit,
            StorageEffectSpecification::Availability {
                state: StorageAvailabilityState::Degraded,
                reconnect_policy: crucible::model::StorageTransitionPolicy::Fail,
            },
            ResolvedMappingOutput::Activation { active: true },
        );
        let offline = action(
            "a-offline",
            EffectLifetime::Persistent,
            FaultPhase::Admit,
            StorageEffectSpecification::Availability {
                state: StorageAvailabilityState::Offline,
                reconnect_policy: crucible::model::StorageTransitionPolicy::Fail,
            },
            ResolvedMappingOutput::Activation { active: true },
        );
        let request = BlockRequest::read(7, 0, 512);
        let opportunity = opportunity(&request, FaultPhase::Admit);
        let world = opaque_world();

        let first = resolve_block_fault_directive_with_capacity(
            &world,
            &target(),
            &request,
            1,
            &opportunity,
            4096,
            context(),
            [&degraded, &offline],
        )
        .unwrap_or_else(|error| panic!("composition should resolve: {error}"));
        let second = resolve_block_fault_directive_with_capacity(
            &world,
            &target(),
            &request,
            1,
            &opportunity,
            4096,
            context(),
            [&offline, &degraded],
        )
        .unwrap_or_else(|error| panic!("composition should resolve: {error}"));

        assert_eq!(first, second);
        assert_eq!(first.availability, BlockFaultAvailability::Offline);
    }

    #[test]
    fn latency_uses_typed_dynamic_value_and_checked_sum() {
        let operations = OperationSet::new(vec![FaultOperation::StorageRead])
            .unwrap_or_else(|error| panic!("operation set should be valid: {error}"));
        let dynamic = action(
            "dynamic-latency",
            EffectLifetime::Opportunity,
            FaultPhase::Resolve,
            StorageEffectSpecification::Latency {
                operations: operations.clone(),
                extra_nanos: 3,
                jitter_nanos: 0,
            },
            ResolvedMappingOutput::Parameter {
                parameter: MappedEffectParameter::DurationNanos,
                value: SignalValue::DurationNanos(11),
            },
        );
        let fixed = action(
            "fixed-latency",
            EffectLifetime::Opportunity,
            FaultPhase::Resolve,
            StorageEffectSpecification::Latency {
                operations,
                extra_nanos: 7,
                jitter_nanos: 0,
            },
            ResolvedMappingOutput::Hazard {
                probability_millionths: 1_000_000,
            },
        );

        let request = BlockRequest::read(9, 0, 512);
        let opportunity = opportunity(&request, FaultPhase::Resolve);
        let dynamic = bind_to_opportunity(dynamic, &opportunity);
        let fixed = bind_to_opportunity(fixed, &opportunity);
        let directive = resolve_block_fault_directive_with_capacity(
            &opaque_world(),
            &target(),
            &request,
            1,
            &opportunity,
            4096,
            context(),
            [&fixed, &dynamic],
        )
        .unwrap_or_else(|error| panic!("latency should resolve: {error}"));
        assert_eq!(directive.additional_latency_nanos, 18);
    }

    #[test]
    fn wrong_dynamic_parameter_fails_closed() {
        let latency = action(
            "bad-latency-mapping",
            EffectLifetime::Opportunity,
            FaultPhase::Resolve,
            StorageEffectSpecification::Latency {
                operations: OperationSet::new(vec![FaultOperation::StorageRead])
                    .unwrap_or_else(|error| panic!("operation set should be valid: {error}")),
                extra_nanos: 3,
                jitter_nanos: 0,
            },
            ResolvedMappingOutput::Parameter {
                parameter: MappedEffectParameter::BitsPerSecond,
                value: SignalValue::RatePerSecond(11),
            },
        );

        let request = BlockRequest::read(9, 0, 512);
        let opportunity = opportunity(&request, FaultPhase::Resolve);
        let latency = bind_to_opportunity(latency, &opportunity);
        let error = match resolve_block_fault_directive_with_capacity(
            &opaque_world(),
            &target(),
            &request,
            1,
            &opportunity,
            4096,
            context(),
            [&latency],
        ) {
            Ok(_) => panic!("wrong dynamic field must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            StorageFaultResolutionError::MappingOutput {
                expected: MappedEffectParameter::DurationNanos,
                ..
            }
        ));
    }

    #[test]
    fn opportunity_binds_wire_digest_range_phase_and_monotone_sequence() {
        let request = BlockRequest::read(7, 512, 1024);
        let coordinate = FaultCoordinate {
            virtual_nanos: 40,
            retired_instructions: Some(20),
        };
        let first = block_request_fault_opportunity(
            target(),
            &request,
            [3; 32],
            FaultPhase::Resolve,
            coordinate,
            11,
        )
        .unwrap_or_else(|error| panic!("opportunity should be valid: {error}"));
        let next = block_request_fault_opportunity(
            target(),
            &request,
            [3; 32],
            FaultPhase::Resolve,
            coordinate,
            12,
        )
        .unwrap_or_else(|error| panic!("opportunity should be valid: {error}"));
        let changed_wire = block_request_fault_opportunity(
            target(),
            &request,
            [4; 32],
            FaultPhase::Resolve,
            coordinate,
            11,
        )
        .unwrap_or_else(|error| panic!("opportunity should be valid: {error}"));

        assert_eq!(first.operation(), FaultOperation::StorageRead);
        assert_eq!(first.phase(), FaultPhase::Resolve);
        assert_ne!(first.id(), next.id());
        assert_ne!(first.id(), changed_wire.id());
    }

    #[test]
    fn delivery_opportunity_binds_the_computed_response() {
        let request = BlockRequest::read(7, 512, 4);
        let directive = ResolvedBlockFaultDirective::fault_free(&request, 4096);
        let delivery = BlockDeliveryOpportunity {
            request_sequence: 11,
            request: request.clone(),
            request_icount: 20,
            ready_nanos: 40,
            wire_digest: [3; 32],
            response: BlockResponse::ok(request.request_id, b"good".to_vec()),
            resolved: directive,
            required_durable_frontier: None,
        };
        let coordinate = FaultCoordinate {
            virtual_nanos: 40,
            retired_instructions: Some(20),
        };
        let first = block_delivery_fault_opportunity(target(), &delivery, coordinate)
            .unwrap_or_else(|error| panic!("delivery opportunity should be valid: {error}"));
        let mut changed = delivery;
        changed.response = BlockResponse::ok(request.request_id, b"evil".to_vec());
        let changed = block_delivery_fault_opportunity(target(), &changed, coordinate)
            .unwrap_or_else(|error| panic!("changed delivery should be valid: {error}"));

        assert_eq!(first.phase(), FaultPhase::Deliver);
        assert_ne!(first.id(), changed.id());
        assert!(matches!(
            first.payload(),
            OpportunityPayload::StorageCompletion {
                response_status: 0,
                ..
            }
        ));
    }

    #[test]
    fn keyed_choices_are_reproducible_and_scenario_owned() {
        let latency = action(
            "keyed-choice",
            EffectLifetime::Opportunity,
            FaultPhase::Resolve,
            StorageEffectSpecification::Latency {
                operations: OperationSet::new(vec![FaultOperation::StorageRead])
                    .unwrap_or_else(|error| panic!("operation set should be valid: {error}")),
                extra_nanos: 0,
                jitter_nanos: 99,
            },
            ResolvedMappingOutput::Hazard {
                probability_millionths: 1_000_000,
            },
        );
        let request = BlockRequest::read(5, 512, 512);
        let first = keyed_inclusive(context(), &latency, &request, b"test-choice", u64::MAX);
        let repeated = keyed_inclusive(context(), &latency, &request, b"test-choice", u64::MAX);
        let different_seed = keyed_inclusive(
            StorageFaultResolutionContext::new(ContentHash::from_bytes(b"different-seed")),
            &latency,
            &request,
            b"test-choice",
            u64::MAX,
        );

        assert_eq!(first, repeated);
        assert_ne!(first, different_seed);
    }

    #[test]
    fn every_non_success_block_policy_result_maps_exactly() {
        use crucible::model::StoragePolicyResult;

        let cases = [
            (StoragePolicyResult::Offline, BlockFaultResult::Offline),
            (StoragePolicyResult::ReadOnly, BlockFaultResult::ReadOnly),
            (
                StoragePolicyResult::InvalidRange,
                BlockFaultResult::InvalidRange,
            ),
            (StoragePolicyResult::Busy, BlockFaultResult::Busy),
            (StoragePolicyResult::Timeout, BlockFaultResult::Timeout),
            (
                StoragePolicyResult::MediumError,
                BlockFaultResult::MediumError,
            ),
            (
                StoragePolicyResult::IntegrityError,
                BlockFaultResult::IntegrityError,
            ),
            (StoragePolicyResult::IoError, BlockFaultResult::IoError),
            (StoragePolicyResult::NoSpace, BlockFaultResult::NoSpace),
            (StoragePolicyResult::NotFound, BlockFaultResult::NotFound),
            (StoragePolicyResult::Stale, BlockFaultResult::Stale),
        ];
        assert_eq!(
            block_failure_from_result(StoragePolicyResult::Success),
            None
        );
        for (policy, expected) in cases {
            assert_eq!(block_failure_from_result(policy), Some(expected));
        }
    }

    #[test]
    fn hazard_probability_uses_the_request_keyed_draw() {
        let latency = action(
            "small-hazard",
            EffectLifetime::Opportunity,
            FaultPhase::Resolve,
            StorageEffectSpecification::Latency {
                operations: OperationSet::new(vec![FaultOperation::StorageRead])
                    .unwrap_or_else(|error| panic!("operation set should be valid: {error}")),
                extra_nanos: 1,
                jitter_nanos: 0,
            },
            ResolvedMappingOutput::Hazard {
                probability_millionths: 1,
            },
        );
        let request = BlockRequest::read(5, 512, 512);
        let expected = keyed_inclusive(
            context(),
            &latency,
            &request,
            b"storage.effect-probability.v1",
            999_999,
        ) < 1;

        assert_eq!(
            probability_applies(context(), &latency, &request, 1_000_000)
                .unwrap_or_else(|error| panic!("hazard should resolve: {error}")),
            expected
        );
    }

    #[test]
    fn opportunity_action_requires_exact_opportunity_identity() {
        let request = BlockRequest::read(9, 0, 512);
        let opportunity = opportunity(&request, FaultPhase::Resolve);
        let latency = action(
            "unbound-latency",
            EffectLifetime::Opportunity,
            FaultPhase::Resolve,
            StorageEffectSpecification::Latency {
                operations: OperationSet::new(vec![FaultOperation::StorageRead])
                    .unwrap_or_else(|error| panic!("operation set should be valid: {error}")),
                extra_nanos: 1,
                jitter_nanos: 0,
            },
            ResolvedMappingOutput::Hazard {
                probability_millionths: 1_000_000,
            },
        );

        assert!(matches!(
            resolve_block_fault_directive_with_capacity(
                &opaque_world(),
                &target(),
                &request,
                1,
                &opportunity,
                4096,
                context(),
                [&latency],
            ),
            Err(StorageFaultResolutionError::ActionIdentity { .. })
        ));
    }

    #[test]
    fn opportunity_payload_cannot_alias_another_same_operation_request() {
        let first_request = BlockRequest::read(9, 0, 512);
        let second_request = BlockRequest::read(10, 512, 512);
        let first_opportunity = opportunity(&first_request, FaultPhase::Resolve);

        assert_eq!(
            resolve_block_fault_directive_with_capacity(
                &opaque_world(),
                &target(),
                &second_request,
                1,
                &first_opportunity,
                4096,
                context(),
                [],
            ),
            Err(StorageFaultResolutionError::OpportunityMismatch)
        );
    }

    #[test]
    fn write_fragments_follow_physical_atomic_boundaries() {
        let request = BlockRequest::write(1, 6, vec![0; 12]);
        assert_eq!(
            atomic_fragments(&request, 8, &id("atomic-test"))
                .unwrap_or_else(|error| panic!("fragments should resolve: {error}")),
            vec![
                BlockFaultByteSpan {
                    start: 0,
                    length: 2,
                },
                BlockFaultByteSpan {
                    start: 2,
                    length: 8,
                },
                BlockFaultByteSpan {
                    start: 10,
                    length: 2,
                },
            ]
        );
    }

    #[test]
    fn volatile_cache_loss_selection_is_exact_and_reproducible() {
        let all = action(
            "cache-loss-all",
            EffectLifetime::Impulse,
            FaultPhase::Boundary,
            StorageEffectSpecification::VolatileCacheLoss {
                selector: StorageVolatileCacheLossSelector::All,
                loss: StorageVolatileCacheLossKind::ProtectionFailure,
            },
            ResolvedMappingOutput::Impulse {
                event: SignalValue::Bytes(vec![1]),
            },
        );
        let state = BlockFaultState::write_through(4096);
        let eligible = [2, 5, 9];
        assert_eq!(
            select_volatile_cache_loss(
                context(),
                &all,
                &StorageVolatileCacheLossSelector::All,
                &state,
                &eligible,
            )
            .unwrap_or_else(|error| panic!("all selection should resolve: {error}")),
            vec![2, 5, 9]
        );
        assert_eq!(
            select_volatile_cache_loss(
                context(),
                &all,
                &StorageVolatileCacheLossSelector::AfterSequence { sequence: 2 },
                &state,
                &eligible,
            )
            .unwrap_or_else(|error| panic!("sequence selection should resolve: {error}")),
            vec![5, 9]
        );
        let subset = StorageVolatileCacheLossSelector::KeyedSubset {
            count: BoundedCount::new(CountLimit::LargeStateEntries, 2)
                .unwrap_or_else(|error| panic!("subset count should be valid: {error}")),
        };
        let first = select_volatile_cache_loss(context(), &all, &subset, &state, &eligible)
            .unwrap_or_else(|error| panic!("keyed selection should resolve: {error}"));
        let repeated = select_volatile_cache_loss(context(), &all, &subset, &state, &eligible)
            .unwrap_or_else(|error| panic!("keyed selection should repeat: {error}"));
        assert_eq!(first, repeated);
        assert_eq!(first.len(), 2);
        assert!(first.iter().all(|sequence| eligible.contains(sequence)));
    }

    #[test]
    fn volatile_cache_loss_requires_a_boundary_event_payload() {
        let bytes = action(
            "cache-loss-bytes",
            EffectLifetime::Impulse,
            FaultPhase::Boundary,
            StorageEffectSpecification::VolatileCacheLoss {
                selector: StorageVolatileCacheLossSelector::All,
                loss: StorageVolatileCacheLossKind::PowerLoss,
            },
            ResolvedMappingOutput::Impulse {
                event: SignalValue::Bytes(vec![1]),
            },
        );
        assert!(matches!(
            resolve_volatile_cache_loss(
                &target(),
                &BlockFaultState::write_through(4096),
                context(),
                &bytes,
                VolatileCacheLossReplay::Record,
            ),
            Err(StorageFaultResolutionError::ActionIdentity { .. })
        ));

        let event = action(
            "cache-loss-event",
            EffectLifetime::Impulse,
            FaultPhase::Boundary,
            StorageEffectSpecification::VolatileCacheLoss {
                selector: StorageVolatileCacheLossSelector::All,
                loss: StorageVolatileCacheLossKind::PowerLoss,
            },
            ResolvedMappingOutput::Impulse {
                event: SignalValue::Event {
                    schema: SignalId::parse("loss-event")
                        .unwrap_or_else(|error| panic!("test signal ID should be valid: {error}")),
                    payload: vec![7],
                },
            },
        );
        let state = BlockFaultState::write_through(4096);
        let resolved = resolve_volatile_cache_loss(
            &target(),
            &state,
            context(),
            &event,
            VolatileCacheLossReplay::Record,
        )
        .unwrap_or_else(|error| panic!("event loss should resolve: {error}"));
        assert_eq!(resolved.entry_set_digest, state.volatile_entries_digest());
        assert!(resolved.eligible_sequences.is_empty());
        assert!(resolved.protected_sequences.is_empty());
        assert!(resolved.selected_sequences.is_empty());
        assert_eq!(resolved.durable_frontier_before, 0);
        assert_eq!(resolved.durable_frontier_after, 0);
        assert!(matches!(
            resolve_volatile_cache_loss(
                &target(),
                &state,
                context(),
                &event,
                VolatileCacheLossReplay::Locked {
                    expected_entry_set_digest: [9; 32],
                },
            ),
            Err(StorageFaultResolutionError::ReplayEntrySetMismatch { .. })
        ));
    }

    #[test]
    fn independently_sampled_storage_phases_merge_without_erasing_prior_fields() {
        let request = BlockRequest::write(77, 8, vec![1; 4]);
        let mut accumulated = ResolvedBlockFaultDirective::fault_free(&request, 4096);
        accumulated.request_sequence = 1_001;

        let mut admit = accumulated.clone();
        admit.availability = BlockFaultAvailability::Degraded;
        admit.reported_capacity_bytes = 2048;
        merge_block_fault_phase_directive(&mut accumulated, FaultPhase::Admit, admit)
            .unwrap_or_else(|error| panic!("admit phase should merge: {error}"));

        let mut resolve = ResolvedBlockFaultDirective::fault_free(&request, 4096);
        resolve.request_sequence = 1_001;
        resolve.execution_nanos = 31;
        resolve.additional_latency_nanos = 7;
        resolve.error_result = Some(BlockFaultResult::IoError);
        merge_block_fault_phase_directive(&mut accumulated, FaultPhase::Resolve, resolve)
            .unwrap_or_else(|error| panic!("resolve phase should merge: {error}"));

        let mut deliver = ResolvedBlockFaultDirective::fault_free(&request, 4096);
        deliver.request_sequence = 1_001;
        deliver.additional_latency_nanos = 11;
        merge_block_fault_phase_directive(&mut accumulated, FaultPhase::Deliver, deliver)
            .unwrap_or_else(|error| panic!("deliver phase should merge: {error}"));

        assert_eq!(accumulated.availability, BlockFaultAvailability::Degraded);
        assert_eq!(accumulated.reported_capacity_bytes, 2048);
        assert_eq!(accumulated.execution_nanos, 31);
        assert_eq!(accumulated.additional_latency_nanos, 18);
        assert_eq!(accumulated.error_result, Some(BlockFaultResult::IoError));
    }
}
