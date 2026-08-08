//! Translation from resolved signal actions to the public QEMU node payload.

use crucible::model::{
    AcceleratorTransition, BindingActionKind, ClockMutation, ContentHash, EffectSpecification,
    FaultObjectId, FaultPhase, InstructionMutation, InterruptMutation, MemoryAccessMutation,
    MemoryEccKind, MemoryRegionKind, NodeEffectSpecification, NodeHangScope,
    NodeLifecycleTransition, NodeStatePolicy, RegisterMutation, ResolvedBindingAction,
    ResolvedFaultTarget, VcpuState,
};
use crucible_shmem::{
    FaultCommandKind, NodeFaultFieldV1, NodeFaultOperationV1, NodeFaultPayloadError,
    NodeFaultPayloadV1, NodeFaultTargetKindV1, node_fault_field,
};

/// Fully encoded non-memory-impulse action and its owning QEMU node.
pub(super) struct EncodedNodeAction {
    pub(super) node: String,
    pub(super) command_kind: FaultCommandKind,
    pub(super) payload: NodeFaultPayloadV1,
}

pub(super) fn encode_node_action(
    action: &ResolvedBindingAction,
    schema_hash: [u8; 32],
) -> Result<EncodedNodeAction, NodeFaultPayloadError> {
    let command_kind =
        command_kind(action.effect.specification()).ok_or(NodeFaultPayloadError::CommandKind(0))?;
    let (node, target_kind, mut target_fields) = target_fields(&action.target)?;
    let operation = match action.kind {
        BindingActionKind::UpsertPersistent => NodeFaultOperationV1::Upsert,
        BindingActionKind::RemovePersistent => NodeFaultOperationV1::Remove,
        BindingActionKind::Apply => NodeFaultOperationV1::Apply,
    };
    let mut fields = if operation == NodeFaultOperationV1::Remove {
        Vec::new()
    } else {
        effect_fields(action.effect.specification())?
    };
    fields.append(&mut target_fields);
    let payload = NodeFaultPayloadV1 {
        command_kind,
        operation,
        target_kind,
        model_phase: phase_tag(action.phase),
        generation: action.transition_sequence,
        action_hash: action.id().bytes,
        target_hash: ContentHash::from_canonical_material(
            "crucible.resolved-fault-target.v1",
            &action.target.canonical_material(),
        )
        .bytes,
        schema_hash,
        fields,
    };
    payload.encode()?;
    Ok(EncodedNodeAction {
        node,
        command_kind,
        payload,
    })
}

fn command_kind(specification: &EffectSpecification) -> Option<FaultCommandKind> {
    let EffectSpecification::Node(effect) = specification else {
        return None;
    };
    Some(match effect {
        NodeEffectSpecification::Lifecycle { .. } => FaultCommandKind::NodeLifecycle,
        NodeEffectSpecification::Hang { .. } => FaultCommandKind::NodeHang,
        NodeEffectSpecification::CpuService { .. } => FaultCommandKind::CpuService,
        NodeEffectSpecification::VcpuState { .. } => FaultCommandKind::CpuVcpuState,
        NodeEffectSpecification::RegisterTransform { .. } => FaultCommandKind::CpuRegisterTransform,
        NodeEffectSpecification::InstructionTransform { .. } => {
            FaultCommandKind::CpuInstructionTransform
        }
        NodeEffectSpecification::CpuException { .. } => FaultCommandKind::CpuException,
        NodeEffectSpecification::InterruptDisposition { .. } => {
            FaultCommandKind::InterruptDisposition
        }
        NodeEffectSpecification::InterruptStorm { .. } => FaultCommandKind::InterruptStorm,
        NodeEffectSpecification::MemoryMutation { .. } => return None,
        NodeEffectSpecification::MemoryAccessTransform { .. } => {
            FaultCommandKind::MemoryAccessTransform
        }
        NodeEffectSpecification::MemoryEccEvent { .. } => FaultCommandKind::MemoryEccEvent,
        NodeEffectSpecification::MemoryRegionState { .. } => FaultCommandKind::MemoryRegionState,
        NodeEffectSpecification::MemoryService { .. } => FaultCommandKind::MemoryService,
        NodeEffectSpecification::ClockTransform { .. } => FaultCommandKind::ClockTransform,
        NodeEffectSpecification::ClockSourceState { .. } => FaultCommandKind::ClockSourceState,
        NodeEffectSpecification::AcceleratorLifecycle { .. } => {
            FaultCommandKind::AcceleratorLifecycle
        }
        NodeEffectSpecification::AcceleratorResultTransform { .. } => {
            FaultCommandKind::AcceleratorResultTransform
        }
        NodeEffectSpecification::AcceleratorMemoryEvent { .. } => {
            FaultCommandKind::AcceleratorMemoryEvent
        }
        NodeEffectSpecification::AcceleratorService { .. } => FaultCommandKind::AcceleratorService,
    })
}

fn effect_fields(
    specification: &EffectSpecification,
) -> Result<Vec<NodeFaultFieldV1>, NodeFaultPayloadError> {
    use node_fault_field::*;
    let EffectSpecification::Node(effect) = specification else {
        return Err(NodeFaultPayloadError::CommandKind(0));
    };
    let fields = match effect {
        NodeEffectSpecification::Lifecycle {
            transition,
            downtime_nanos,
            boot_policy,
            volatile_state_policy,
            device_state_policy,
        } => vec![
            NodeFaultFieldV1::u32(P1, lifecycle_tag(*transition)),
            NodeFaultFieldV1::u64(P2, *downtime_nanos),
            id_field(P3, boot_policy),
            NodeFaultFieldV1::u32(P4, state_policy_tag(*volatile_state_policy)),
            NodeFaultFieldV1::u32(P5, state_policy_tag(*device_state_policy)),
        ],
        NodeEffectSpecification::Hang {
            scope,
            recovery_event,
            watchdog_policy,
        } => vec![
            NodeFaultFieldV1::u32(P1, hang_scope_tag(scope)),
            NodeFaultFieldV1::hash(P2, hang_scope_hash(scope)),
            id_field(P3, recovery_event),
            id_field(P4, watchdog_policy),
        ],
        NodeEffectSpecification::CpuService {
            vcpus,
            capacity,
            quantum_instructions,
            service_rule,
        } => vec![
            NodeFaultFieldV1::hash_set(P1, &id_set(vcpus.as_slice()))?,
            NodeFaultFieldV1::ratio(P2, capacity.numerator(), capacity.denominator()),
            NodeFaultFieldV1::u64(P3, quantum_instructions.get()),
            id_field(P4, service_rule),
        ],
        NodeEffectSpecification::VcpuState {
            state,
            recovery_event,
        } => vec![
            NodeFaultFieldV1::u32(P1, vcpu_state_tag(*state)),
            NodeFaultFieldV1::boolean(P2, recovery_event.is_some()),
            NodeFaultFieldV1::hash(P3, recovery_event.as_ref().map_or([0; 32], id_hash)),
        ],
        NodeEffectSpecification::RegisterTransform {
            register,
            first_bit,
            bit_count,
            mutation,
            occurrence,
        } => {
            let (kind, mask, has_value, value) = register_mutation(mutation);
            vec![
                id_field(P1, register),
                NodeFaultFieldV1::u32(P2, u32::from(*first_bit)),
                NodeFaultFieldV1::u32(P3, bit_count.get()),
                NodeFaultFieldV1::u32(P4, kind),
                NodeFaultFieldV1::bytes(P5, mask),
                NodeFaultFieldV1::boolean(P6, has_value),
                NodeFaultFieldV1::bytes(P7, value),
                id_field(P8, occurrence),
            ]
        }
        NodeEffectSpecification::InstructionTransform { selector, mutation } => {
            let (kind, destination, transform, count) = instruction_mutation(mutation);
            vec![
                id_field(P1, selector),
                NodeFaultFieldV1::u32(P2, kind),
                NodeFaultFieldV1::hash(P3, destination),
                NodeFaultFieldV1::hash(P4, transform),
                NodeFaultFieldV1::u32(P5, count),
            ]
        }
        NodeEffectSpecification::CpuException {
            architecture,
            exception,
            error_fields,
        } => vec![
            id_field(P1, architecture),
            id_field(P2, exception),
            id_field(P3, error_fields),
        ],
        NodeEffectSpecification::InterruptDisposition { mutation } => {
            let (kind, delay, copies, gap, vector) = interrupt_mutation(mutation);
            vec![
                NodeFaultFieldV1::u32(P1, kind),
                NodeFaultFieldV1::u64(P2, delay),
                NodeFaultFieldV1::u32(P3, copies),
                NodeFaultFieldV1::u64(P4, gap),
                NodeFaultFieldV1::u32(P5, vector),
            ]
        }
        NodeEffectSpecification::InterruptStorm {
            source,
            vector,
            period_nanos,
            burst,
            count,
            routing,
        } => vec![
            id_field(P1, source),
            NodeFaultFieldV1::u32(P2, *vector),
            NodeFaultFieldV1::u64(P3, period_nanos.get()),
            NodeFaultFieldV1::u32(P4, burst.get()),
            NodeFaultFieldV1::u32(P5, count.get()),
            id_field(P6, routing),
        ],
        NodeEffectSpecification::MemoryMutation { .. } => {
            return Err(NodeFaultPayloadError::CommandKind(
                FaultCommandKind::MemoryMutation as u16,
            ));
        }
        NodeEffectSpecification::MemoryAccessTransform {
            range,
            mutation,
            occurrence,
        } => {
            let (kind, mask, has_value, value) = memory_access_mutation(mutation);
            vec![
                NodeFaultFieldV1::u64(P1, range.start()),
                NodeFaultFieldV1::u64(P2, range.length()),
                NodeFaultFieldV1::u32(P3, kind),
                NodeFaultFieldV1::bytes(P4, mask),
                NodeFaultFieldV1::boolean(P5, has_value),
                NodeFaultFieldV1::bytes(P6, value),
                id_field(P7, occurrence),
            ]
        }
        NodeEffectSpecification::MemoryEccEvent {
            kind,
            address,
            syndrome,
            bank,
            channel,
            rank,
            guest_visibility,
        } => vec![
            NodeFaultFieldV1::u32(P1, ecc_tag(*kind)),
            NodeFaultFieldV1::u64(P2, *address),
            NodeFaultFieldV1::u64(P3, *syndrome),
            id_field(P4, bank),
            id_field(P5, channel),
            id_field(P6, rank),
            id_field(P7, guest_visibility),
        ],
        NodeEffectSpecification::MemoryRegionState {
            range,
            kind,
            process,
        } => vec![
            NodeFaultFieldV1::u64(P1, range.start()),
            NodeFaultFieldV1::u64(P2, range.length()),
            NodeFaultFieldV1::u32(P3, memory_region_tag(*kind)),
            id_field(P4, process),
        ],
        NodeEffectSpecification::MemoryService {
            latency_nanos,
            bandwidth_bytes_per_second,
            operations_per_second,
            sharing_scope,
        } => vec![
            NodeFaultFieldV1::u64(P1, *latency_nanos),
            NodeFaultFieldV1::boolean(P2, bandwidth_bytes_per_second.is_some()),
            NodeFaultFieldV1::u64(
                P3,
                bandwidth_bytes_per_second.map_or(0, |value| value.get()),
            ),
            NodeFaultFieldV1::boolean(P4, operations_per_second.is_some()),
            NodeFaultFieldV1::u64(P5, operations_per_second.map_or(0, |value| value.get())),
            id_field(P6, sharing_scope),
        ],
        NodeEffectSpecification::ClockTransform {
            source,
            mutation,
            monotonicity,
        } => {
            let (kind, signed, numerator, denominator, unsigned, process) =
                clock_mutation(mutation);
            vec![
                id_field(P1, source),
                NodeFaultFieldV1::u32(P2, kind),
                NodeFaultFieldV1::i64(P3, signed),
                NodeFaultFieldV1::ratio(P4, numerator, denominator),
                NodeFaultFieldV1::u64(P5, unsigned),
                NodeFaultFieldV1::hash(P6, process),
                id_field(P7, monotonicity),
            ]
        }
        NodeEffectSpecification::ClockSourceState {
            sources,
            transition,
            synchronization_policy,
        } => vec![
            NodeFaultFieldV1::hash_set(P1, &id_set(sources.as_slice()))?,
            id_field(P2, transition),
            id_field(P3, synchronization_policy),
        ],
        NodeEffectSpecification::AcceleratorLifecycle {
            device,
            transition,
            queue_policy,
            memory_policy,
        } => vec![
            id_field(P1, device),
            NodeFaultFieldV1::u32(P2, accelerator_transition_tag(*transition)),
            NodeFaultFieldV1::u32(P3, state_policy_tag(*queue_policy)),
            NodeFaultFieldV1::u32(P4, state_policy_tag(*memory_policy)),
        ],
        NodeEffectSpecification::AcceleratorResultTransform {
            job_selector,
            transform,
        } => vec![id_field(P1, job_selector), id_field(P2, transform)],
        NodeEffectSpecification::AcceleratorMemoryEvent {
            range,
            ecc,
            syndrome,
            transform,
        } => vec![
            NodeFaultFieldV1::u64(P1, range.start()),
            NodeFaultFieldV1::u64(P2, range.length()),
            NodeFaultFieldV1::boolean(P3, ecc.is_some()),
            NodeFaultFieldV1::u32(P4, ecc.map_or(0, ecc_tag)),
            NodeFaultFieldV1::boolean(P5, syndrome.is_some()),
            NodeFaultFieldV1::u64(P6, syndrome.unwrap_or(0)),
            NodeFaultFieldV1::boolean(P7, transform.is_some()),
            NodeFaultFieldV1::hash(P8, transform.as_ref().map_or([0; 32], id_hash)),
        ],
        NodeEffectSpecification::AcceleratorService {
            capacity,
            memory_bytes_per_second,
            jobs_per_second,
            thermal_power,
        } => vec![
            NodeFaultFieldV1::ratio(P1, capacity.numerator(), capacity.denominator()),
            NodeFaultFieldV1::boolean(P2, memory_bytes_per_second.is_some()),
            NodeFaultFieldV1::u64(P3, memory_bytes_per_second.map_or(0, |value| value.get())),
            NodeFaultFieldV1::boolean(P4, jobs_per_second.is_some()),
            NodeFaultFieldV1::u64(P5, jobs_per_second.map_or(0, |value| value.get())),
            id_field(P6, thermal_power),
        ],
    };
    Ok(fields)
}

fn target_fields(
    target: &ResolvedFaultTarget,
) -> Result<(String, NodeFaultTargetKindV1, Vec<NodeFaultFieldV1>), NodeFaultPayloadError> {
    use node_fault_field::*;
    let value = match target {
        ResolvedFaultTarget::Node { node } => (
            node.as_str().to_owned(),
            NodeFaultTargetKindV1::Node,
            vec![],
        ),
        ResolvedFaultTarget::Vcpu { node, vcpu } => (
            node.as_str().to_owned(),
            NodeFaultTargetKindV1::Vcpu,
            vec![NodeFaultFieldV1::u32(T1, *vcpu)],
        ),
        ResolvedFaultTarget::Register {
            node,
            vcpu,
            architecture,
            register,
            first_bit,
            bit_count,
        } => (
            node.as_str().to_owned(),
            NodeFaultTargetKindV1::Register,
            vec![
                NodeFaultFieldV1::u32(T1, *vcpu),
                id_field(T2, architecture),
                id_field(T3, register),
                NodeFaultFieldV1::u32(T4, u32::from(*first_bit)),
                NodeFaultFieldV1::u32(T5, u32::from(*bit_count)),
            ],
        ),
        ResolvedFaultTarget::MemoryRange {
            node,
            address_space,
            guest_address,
            vcpu,
            length_bytes,
        } => (
            node.as_str().to_owned(),
            NodeFaultTargetKindV1::Memory,
            vec![
                id_field(T1, address_space),
                NodeFaultFieldV1::u64(T2, *guest_address),
                NodeFaultFieldV1::boolean(T3, vcpu.is_some()),
                NodeFaultFieldV1::u32(T4, vcpu.unwrap_or(0)),
                NodeFaultFieldV1::u64(T5, *length_bytes),
            ],
        ),
        ResolvedFaultTarget::Interrupt {
            node,
            controller,
            source,
            target_vcpu,
            vector,
        } => (
            node.as_str().to_owned(),
            NodeFaultTargetKindV1::Interrupt,
            vec![
                id_field(T1, controller),
                id_field(T2, source),
                NodeFaultFieldV1::u32(T3, *target_vcpu),
                NodeFaultFieldV1::u32(T4, *vector),
            ],
        ),
        ResolvedFaultTarget::ClockSource { node, source } => (
            node.as_str().to_owned(),
            NodeFaultTargetKindV1::Clock,
            vec![id_field(T1, source)],
        ),
        ResolvedFaultTarget::Accelerator { node, device } => (
            node.as_str().to_owned(),
            NodeFaultTargetKindV1::Accelerator,
            vec![id_field(T1, device)],
        ),
        _ => return Err(NodeFaultPayloadError::TargetKind(0)),
    };
    Ok(value)
}

fn id_hash(id: &FaultObjectId) -> [u8; 32] {
    ContentHash::from_canonical_material("crucible.fault-object.v1", id.as_str()).bytes
}

fn id_field(tag: u16, id: &FaultObjectId) -> NodeFaultFieldV1 {
    NodeFaultFieldV1::hash(tag, id_hash(id))
}

fn id_set(ids: &[FaultObjectId]) -> Vec<[u8; 32]> {
    let mut hashes: Vec<_> = ids.iter().map(id_hash).collect();
    hashes.sort_unstable();
    hashes.dedup();
    hashes
}

fn hang_scope_hash(scope: &NodeHangScope) -> [u8; 32] {
    let material = match scope {
        NodeHangScope::Node => "node".to_owned(),
        NodeHangScope::Vcpus(vcpus) => vcpus
            .as_slice()
            .iter()
            .map(FaultObjectId::as_str)
            .collect::<Vec<_>>()
            .join(","),
        NodeHangScope::Device(device) => format!("device:{}", device.as_str()),
    };
    ContentHash::from_canonical_material("crucible.node-hang-scope.v1", &material).bytes
}

fn register_mutation(mutation: &RegisterMutation) -> (u32, Vec<u8>, bool, Vec<u8>) {
    match mutation {
        RegisterMutation::BitFlip { mask } => (1, mask.decode(), false, vec![0]),
        RegisterMutation::Stuck { mask, value } => (2, mask.decode(), true, value.decode()),
        RegisterMutation::Replace { value } => {
            (3, vec![0xff; value.decode().len()], true, value.decode())
        }
    }
}

fn instruction_mutation(mutation: &InstructionMutation) -> (u32, [u8; 32], [u8; 32], u32) {
    match mutation {
        InstructionMutation::ResultCorrupt {
            destination,
            transform,
        } => (1, id_hash(destination), id_hash(transform), 0),
        InstructionMutation::Skip => (2, [0; 32], [0; 32], 0),
        InstructionMutation::Replay { count } => (3, [0; 32], [0; 32], count.get()),
    }
}

fn interrupt_mutation(mutation: &InterruptMutation) -> (u32, u64, u32, u64, u32) {
    match mutation {
        InterruptMutation::Drop => (1, 0, 0, 0, 0),
        InterruptMutation::Delay { delay_nanos } => (2, delay_nanos.get(), 0, 0, 0),
        InterruptMutation::Duplicate { copies, gap_nanos } => (3, 0, copies.get(), *gap_nanos, 0),
        InterruptMutation::Replace { vector } => (4, 0, 0, 0, *vector),
    }
}

fn memory_access_mutation(mutation: &MemoryAccessMutation) -> (u32, Vec<u8>, bool, Vec<u8>) {
    match mutation {
        MemoryAccessMutation::Stuck { mask, value } => (1, mask.decode(), true, value.decode()),
        MemoryAccessMutation::ReadCorrupt { mask } => (2, mask.decode(), false, vec![0]),
        MemoryAccessMutation::LostWrite => (3, vec![0], false, vec![0]),
        MemoryAccessMutation::TornWrite { selector } => {
            (4, vec![0], true, id_hash(selector).to_vec())
        }
        MemoryAccessMutation::Poison { policy } => (5, vec![0], true, id_hash(policy).to_vec()),
    }
}

fn clock_mutation(mutation: &ClockMutation) -> (u32, i64, i64, u64, u64, [u8; 32]) {
    match mutation {
        ClockMutation::Offset { offset_nanos } => (1, *offset_nanos, 1, 1, 0, [0; 32]),
        ClockMutation::Drift { ratio } => {
            (2, 0, ratio.numerator(), ratio.denominator(), 0, [0; 32])
        }
        ClockMutation::Jump { delta_nanos } => (3, *delta_nanos, 1, 1, 0, [0; 32]),
        ClockMutation::Freeze { value_nanos } => (4, 0, 1, 1, *value_nanos, [0; 32]),
        ClockMutation::Jitter {
            maximum_nanos,
            distribution,
        } => (5, 0, 1, 1, maximum_nanos.get(), id_hash(distribution)),
        ClockMutation::Wander { process } => (6, 0, 1, 1, 0, id_hash(process)),
    }
}

const fn lifecycle_tag(value: NodeLifecycleTransition) -> u32 {
    match value {
        NodeLifecycleTransition::Boot => 1,
        NodeLifecycleTransition::Crash => 2,
        NodeLifecycleTransition::Reset => 3,
        NodeLifecycleTransition::PowerOff => 4,
        NodeLifecycleTransition::PowerCycle => 5,
        NodeLifecycleTransition::PermanentFailure => 6,
    }
}
const fn state_policy_tag(value: NodeStatePolicy) -> u32 {
    match value {
        NodeStatePolicy::Preserve => 1,
        NodeStatePolicy::Clear => 2,
        NodeStatePolicy::DeviceReset => 3,
    }
}
const fn hang_scope_tag(value: &NodeHangScope) -> u32 {
    match value {
        NodeHangScope::Node => 1,
        NodeHangScope::Vcpus(_) => 2,
        NodeHangScope::Device(_) => 3,
    }
}
const fn vcpu_state_tag(value: VcpuState) -> u32 {
    match value {
        VcpuState::Online => 1,
        VcpuState::Offline => 2,
        VcpuState::Stalled => 3,
    }
}
const fn ecc_tag(value: MemoryEccKind) -> u32 {
    match value {
        MemoryEccKind::Corrected => 1,
        MemoryEccKind::Uncorrectable => 2,
    }
}
const fn memory_region_tag(value: MemoryRegionKind) -> u32 {
    match value {
        MemoryRegionKind::Failed => 1,
        MemoryRegionKind::Retention => 2,
        MemoryRegionKind::Rowhammer => 3,
    }
}
const fn accelerator_transition_tag(value: AcceleratorTransition) -> u32 {
    match value {
        AcceleratorTransition::Disappear => 1,
        AcceleratorTransition::Reset => 2,
        AcceleratorTransition::Reconnect => 3,
    }
}

const fn phase_tag(value: FaultPhase) -> u16 {
    match value {
        FaultPhase::Produce => 1,
        FaultPhase::Admit => 2,
        FaultPhase::Queue => 3,
        FaultPhase::Resolve => 4,
        FaultPhase::Persist => 5,
        FaultPhase::Visibility => 6,
        FaultPhase::Deliver => 7,
        FaultPhase::Transition => 8,
        FaultPhase::Boundary => 9,
        FaultPhase::Run => 10,
        FaultPhase::BeforeInstruction => 11,
        FaultPhase::AfterInstruction => 12,
        FaultPhase::BeforeRead => 13,
        FaultPhase::AfterRead => 14,
        FaultPhase::BeforeWrite => 15,
        FaultPhase::AfterWrite => 16,
        FaultPhase::Fetch => 17,
        FaultPhase::Load => 18,
        FaultPhase::Store => 19,
        FaultPhase::DmaRead => 20,
        FaultPhase::DmaWrite => 21,
        FaultPhase::Refresh => 22,
        FaultPhase::Raise => 23,
        FaultPhase::Route => 24,
        FaultPhase::Acknowledge => 25,
        FaultPhase::InterruptDeliver => 26,
        FaultPhase::Return => 27,
        FaultPhase::ClockRead => 28,
        FaultPhase::Arm => 29,
        FaultPhase::Fire => 30,
        FaultPhase::Synchronize => 31,
        FaultPhase::SourceSwitch => 32,
        FaultPhase::Submit => 33,
        FaultPhase::Execute => 34,
        FaultPhase::Complete => 35,
        FaultPhase::AcceleratorMemoryAccess => 36,
    }
}
