//! Instruction, register, exception, and hardware-error evidence translation.

use super::*;

/// Updates bridge-side instruction expectations after QEMU publishes a command result.
///
/// A terminal one-shot `Apply` result deliberately retains its expectation until
/// the corresponding applied or fail-closed evidence event has been translated
/// and published.
pub(super) fn track_instruction_result(
    commands: &mut BTreeMap<u64, InstructionCommandExpectation>,
    active_bindings: &mut BTreeMap<[u8; 32], u64>,
    command_sequence: u64,
    status: u16,
) -> Result<(), FaultCommandBridgeError> {
    let command = commands
        .get(&command_sequence)
        .cloned()
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    if status == FaultResultStatus::Applied as u16 {
        match command.operation {
            NodeFaultOperationV1::Upsert => {
                if let Some(prior) = active_bindings.insert(command.binding_hash, command_sequence)
                    && prior != command_sequence
                {
                    commands.remove(&prior);
                }
            }
            NodeFaultOperationV1::Remove => {
                if let Some(prior) = active_bindings.remove(&command.binding_hash) {
                    commands.remove(&prior);
                }
                commands.remove(&command_sequence);
            }
            NodeFaultOperationV1::Apply => {}
        }
    } else if command.operation != NodeFaultOperationV1::Apply
        || status != FaultResultStatus::InternalError as u16
    {
        commands.remove(&command_sequence);
    }
    Ok(())
}

/// Advances exact replay-event correlation and releases terminal one-shot state.
pub(super) fn track_instruction_event(
    commands: &mut BTreeMap<u64, InstructionCommandExpectation>,
    command_sequence: u64,
    payload: &[u8],
) -> Result<(), FaultCommandBridgeError> {
    let evidence = FaultInstructionEvidenceV1::decode(payload)
        .map_err(|_source| FaultCommandBridgeError::InstructionEvidence)?;
    let command = commands
        .get_mut(&command_sequence)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    if evidence.replay_ordinal != command.next_replay_ordinal
        || evidence.replay_total != command.replay_total
    {
        return Err(FaultCommandBridgeError::InstructionEvidence);
    }
    let terminal = evidence.outcome != FaultInstructionEvidenceOutcomeV1::Applied
        || evidence.mutation_kind != FaultInstructionMutationKindV1::Replay
        || evidence.replay_ordinal == evidence.replay_total;
    if terminal {
        if command.operation == NodeFaultOperationV1::Apply {
            commands.remove(&command_sequence);
        } else {
            command.next_replay_ordinal = 0;
        }
    } else {
        command.next_replay_ordinal = command
            .next_replay_ordinal
            .checked_add(1)
            .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    }
    Ok(())
}

/// Releases the command identity correlated with one global terminal event.
pub(super) fn track_terminal_instruction_event(
    commands: &mut BTreeMap<u64, InstructionCommandExpectation>,
    active_bindings: &mut BTreeMap<[u8; 32], u64>,
    command_sequence: u64,
) -> Result<(), FaultCommandBridgeError> {
    let command = commands
        .remove(&command_sequence)
        .ok_or(FaultCommandBridgeError::InstructionEvidence)?;
    if active_bindings.get(&command.binding_hash) == Some(&command_sequence) {
        active_bindings.remove(&command.binding_hash);
    }
    Ok(())
}

pub(super) fn target_manifest_capability_row(
    architecture: FaultCapabilityScope,
    register_manifest_digest: [u8; 32],
    interrupt_manifest_digest: Option<[u8; 32]>,
    hardware_error_manifest_digest: Option<[u8; 32]>,
    clock_manifest_digest: Option<[u8; 32]>,
    accelerator_manifest_digest: Option<[u8; 32]>,
) -> FaultCapabilityRowV1 {
    let name = b"qemu.target-manifest.node.v1";
    let schema = b"crucible.target-manifest-query.v1;kinds=register,interrupt,hardware-error,clock,accelerator";
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_HASH_DOMAIN);
    hasher.update(name);
    hasher.update(&[0]);
    hasher.update(schema);
    hasher.update(&[0]);
    hasher.update(&register_manifest_digest);
    match interrupt_manifest_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match hardware_error_manifest_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match clock_manifest_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    match accelerator_manifest_digest {
        Some(digest) => {
            hasher.update(&[1]);
            hasher.update(&digest);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    FaultCapabilityRowV1 {
        command_kind: FaultCommandKind::QueryTargetManifest,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        scope: architecture,
        phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
        maximum_payload_bytes: FAULT_TARGET_MANIFEST_QUERY_V1_BYTES as u32,
        maximum_pending_commands: 1,
        required_feature_bits: FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION
            | interrupt_manifest_digest.map_or(0, |_digest| FAULT_CAPABILITY_FEATURE_INTERRUPT)
            | hardware_error_manifest_digest
                .map_or(0, |_digest| FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR)
            | clock_manifest_digest.map_or(0, |_digest| FAULT_CAPABILITY_FEATURE_GUEST_CLOCK),
        capability_hash: *hasher.finalize().as_bytes(),
    }
}

pub(super) fn register_capability_hash(
    architecture: FaultCapabilityScope,
    manifest_digest: [u8; 32],
) -> [u8; 32] {
    let name = match architecture {
        FaultCapabilityScope::X86_64 => b"qemu.register.mutate.x86_64.v1".as_slice(),
        FaultCapabilityScope::Aarch64 => b"qemu.register.mutate.aarch64.v1".as_slice(),
        _ => b"qemu.register.mutate.invalid.v1".as_slice(),
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(CAPABILITY_HASH_DOMAIN);
    hasher.update(name);
    hasher.update(&[0]);
    hasher.update(b"crucible.node-fault-payload.v1");
    hasher.update(&[0]);
    hasher.update(&manifest_digest);
    *hasher.finalize().as_bytes()
}

mod expectations;
mod hardware;
mod translation;

pub(super) use expectations::*;
pub(super) use hardware::*;
pub(super) use translation::*;
