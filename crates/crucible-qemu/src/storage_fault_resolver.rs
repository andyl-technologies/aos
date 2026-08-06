//! Production resolution of host storage actions into exact block directives.
//!
//! Signal evaluation and keyed hazard decisions occur in `crucible`. This
//! module is the live block-adapter boundary: it consumes only committed,
//! typed [`ResolvedBindingAction`] values for one exact request and translates
//! the currently executable subset into a [`ResolvedBlockFaultDirective`]. It
//! never evaluates signals, consults host time, or silently accepts an effect
//! whose device semantics are not implemented.

use crucible::model::{
    BindingActionKind, EffectSpecification, FaultContractError, FaultCoordinate, FaultObjectId,
    FaultOpportunity, FaultPhase, MappedEffectParameter, OpportunityPayload, ResolvedBindingAction,
    ResolvedFaultTarget, ResolvedMappingOutput, SignalValue, StorageAvailabilityState,
    StorageEffectSpecification, StorageFlushKind, StoragePolicyArtifactKind,
    StoragePolicyTypedResult, StorageReadMutation, World,
};

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
    BlockFaultAvailability, BlockFaultFlushDisposition, BlockFaultReadTransform, BlockOp,
    BlockRequest, ResolvedBlockFaultDirective,
};

/// Resolves committed host actions for one exact live block request.
///
/// The caller supplies actions already matched to `target` and the request's
/// exact opportunity. Contributions are sorted by effect kind, binding ID, and
/// transition sequence before composition so caller iteration order cannot
/// affect the result.
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
    actions: impl IntoIterator<Item = &'a ResolvedBindingAction>,
) -> Result<ResolvedBlockFaultDirective, StorageFaultResolutionError> {
    let capacity = target_capacity(world, target)?;
    resolve_block_fault_directive_with_capacity(world, target, request, capacity, actions)
}

fn resolve_block_fault_directive_with_capacity<'a>(
    world: &World,
    target: &ResolvedFaultTarget,
    request: &BlockRequest,
    capacity: u64,
    actions: impl IntoIterator<Item = &'a ResolvedBindingAction>,
) -> Result<ResolvedBlockFaultDirective, StorageFaultResolutionError> {
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
        apply_effect(world, request, action, effect, &mut directive)?;
    }
    Ok(directive)
}

fn apply_effect(
    world: &World,
    request: &BlockRequest,
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
            directive.reported_capacity_bytes =
                directive.reported_capacity_bytes.min(length_bytes.get());
        }
        StorageEffectSpecification::Latency {
            operations,
            extra_nanos,
            jitter_nanos,
        } if operation_selected(operations.as_slice(), request.op) => {
            if *jitter_nanos != 0 {
                return Err(unsupported(action, "storage latency jitter"));
            }
            let delay =
                mapped_u64(action, MappedEffectParameter::DurationNanos)?.unwrap_or(*extra_nanos);
            directive.additional_latency_nanos = directive
                .additional_latency_nanos
                .checked_add(delay)
                .ok_or_else(|| StorageFaultResolutionError::Overflow {
                    binding: action.binding.clone(),
                    field: "additional_latency_nanos",
                })?;
        }
        StorageEffectSpecification::OperationFailure {
            operations, status, ..
        } if operation_selected(operations.as_slice(), request.op) => {
            require_block_result(world, status, false, &action.binding)?;
            directive.force_error = true;
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
                    return Err(unsupported(action, "retained flush release"));
                }
            };
        }
        StorageEffectSpecification::Latency { .. }
        | StorageEffectSpecification::OperationFailure { .. }
        | StorageEffectSpecification::ReadTransform { .. }
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
    let operation = match operation {
        BlockOp::Read => crucible::model::FaultOperation::StorageRead,
        BlockOp::Write => crucible::model::FaultOperation::StorageWrite,
        BlockOp::Flush => crucible::model::FaultOperation::StorageFlush,
        BlockOp::GetLength => crucible::model::FaultOperation::StorageGetLength,
    };
    operations.binary_search(&operation).is_ok()
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
    match value {
        SignalValue::U64(value)
        | SignalValue::DurationNanos(value)
        | SignalValue::RatePerSecond(value) => Ok(Some(*value)),
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

fn target_capacity(
    world: &World,
    target: &ResolvedFaultTarget,
) -> Result<u64, StorageFaultResolutionError> {
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
        .map(|device| device.persistence.length_bytes)
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
        let world = opaque_world();

        let first = resolve_block_fault_directive_with_capacity(
            &world,
            &target(),
            &request,
            4096,
            [&degraded, &offline],
        )
        .unwrap_or_else(|error| panic!("composition should resolve: {error}"));
        let second = resolve_block_fault_directive_with_capacity(
            &world,
            &target(),
            &request,
            4096,
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

        let directive = resolve_block_fault_directive_with_capacity(
            &opaque_world(),
            &target(),
            &BlockRequest::read(9, 0, 512),
            4096,
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

        let error = resolve_block_fault_directive_with_capacity(
            &opaque_world(),
            &target(),
            &BlockRequest::read(9, 0, 512),
            4096,
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
}
