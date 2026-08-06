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
    StoragePolicyDuplicateCompletion, StoragePolicyTypedResult, StorageReadMutation,
    StorageSelection, StorageWriteDispositionKind, World, WorldCompletionDurability,
};

/// Scenario-owned entropy used only for keyed storage adapter choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageFaultResolutionContext {
    scenario_seed: ContentHash,
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
        volatile_cache_bytes: persistence.volatile_cache_bytes,
        cache_entries: persistence.cache_entries,
        controller_buffer_bytes: persistence.controller_buffer_bytes,
        controller_entries: persistence.controller_entries,
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
    };
    let (start_byte, length_bytes) = match request.op {
        BlockOp::Read | BlockOp::Write => (Some(request.offset), Some(u64::from(request.count))),
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
use crucible_device::block::{
    BlockCompletionDurability, BlockDuplicatePolicy, BlockDurabilityConfig, BlockFaultAvailability,
    BlockFaultByteSpan, BlockFaultFlushDisposition, BlockFaultReadTransform,
    BlockFaultWriteDisposition, BlockOp, BlockRequest, BlockResponse, ResolvedBlockFaultDirective,
};

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
            directive.force_error = true;
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
                directive.force_error = true;
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
                    BlockDuplicatePolicy::ProtocolError(BlockResponse::error(request.request_id))
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
            directive.allow_subatomic_mutation = false;
        }
        StorageEffectSpecification::VolatileCache { .. } if request.op == BlockOp::Write => {
            return Err(unsupported(action, "volatile-cache state machine"));
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
            if count_threshold.is_some() {
                return Err(unsupported(action, "stateful media access threshold"));
            }
            if time_threshold_nanos
                .is_some_and(|threshold| action.coordinate.virtual_nanos < threshold.get())
            {
                return Ok(());
            }
            match state {
                StorageMediaState::Bad | StorageMediaState::Latent => directive.force_error = true,
                StorageMediaState::Poisoned if request.op == BlockOp::Read => {
                    directive.force_error = true;
                }
                StorageMediaState::ReadOnly if request.op == BlockOp::Write => {
                    directive.force_error = true;
                }
                StorageMediaState::Poisoned | StorageMediaState::ReadOnly => {}
            }
        }
        StorageEffectSpecification::FlushDisposition { kind, status }
            if request.op == BlockOp::Flush =>
        {
            let success = !matches!(kind, StorageFlushKind::Error);
            require_block_result(world, status, success, &action.binding)?;
            directive.flush_disposition = match kind {
                StorageFlushKind::Honest => BlockFaultFlushDisposition::Honest,
                StorageFlushKind::Error => BlockFaultFlushDisposition::Error,
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
        | StorageEffectSpecification::VolatileCache { .. }
        | StorageEffectSpecification::MediaRange { .. }
        | StorageEffectSpecification::FlushDisposition { .. } => {}
        _ => return Err(unsupported(action, effect.kind().as_str())),
    }
    Ok(())
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
        BlockOp::Read | BlockOp::Write => (Some(request.offset), Some(u64::from(request.count))),
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
    }]);
    hasher.update(blake3::hash(&request.data).as_bytes());
    hasher.update(&counter.to_be_bytes());
    let digest = hasher.finalize();
    let mut word = [0_u8; 8];
    word.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_be_bytes(word)
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
                .filter_map(|(index, fragment)| (index != selected).then_some(fragment.clone()))
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
                spans: vec![fragments[selected].clone()],
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
        BlockOp::Read | BlockOp::Write => {
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
        BindingActionCause, ContentHash, EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest,
        FaultCoordinate, FaultOperation, FaultPhase, OperationSet,
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
        let error = resolve_block_fault_directive_with_capacity(
            &opaque_world(),
            &target(),
            &request,
            1,
            &opportunity,
            4096,
            context(),
            [&latency],
        )
        .expect_err("wrong dynamic field must fail closed");
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
}
