//! Target and typed value encoders for node-fault payloads.

use super::*;

pub(super) fn target_fields(
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

pub(super) fn id_hash(id: &FaultObjectId) -> [u8; 32] {
    fault_object_id_hash_v1(id.as_str())
}

pub(super) fn qemu_virtio_dma_identity(id: &FaultObjectId) -> [u8; 32] {
    let mut digest = Sha256::new();

    digest.update(b"qemu.virtio.dma-id.v1");
    digest.update(id.as_str().as_bytes());
    digest.finalize().into()
}

pub(super) fn id_field(tag: u16, id: &FaultObjectId) -> NodeFaultFieldV1 {
    NodeFaultFieldV1::hash(tag, id_hash(id))
}

pub(super) fn id_set(ids: &[FaultObjectId]) -> Vec<[u8; 32]> {
    let mut hashes: Vec<_> = ids.iter().map(id_hash).collect();
    hashes.sort_unstable();
    hashes.dedup();
    hashes
}

pub(super) fn register_mutation(mutation: &RegisterMutation) -> (u32, Vec<u8>, bool, Vec<u8>) {
    match mutation {
        RegisterMutation::BitFlip { mask } => (1, mask.decode(), false, vec![0]),
        RegisterMutation::Stuck { mask, value } => (2, mask.decode(), true, value.decode()),
        RegisterMutation::Replace { value } => {
            (3, vec![0xff; value.decode().len()], true, value.decode())
        }
    }
}

pub(super) fn instruction_mutation(
    mutation: &InstructionMutation,
) -> Result<(u32, [u8; 32], Vec<u8>, u32), NodeFaultPayloadError> {
    Ok(match mutation {
        InstructionMutation::ResultCorrupt { transform } => (
            1,
            id_hash(&transform.destination),
            json_bytes(node_fault_field::P4, &transform.mutation)?,
            0,
        ),
        InstructionMutation::Skip => (2, [0; 32], vec![0], 0),
        InstructionMutation::Replay { count } => (3, [0; 32], vec![0], count.get()),
    })
}

pub(super) fn interrupt_mutation(mutation: &InterruptMutation) -> (u32, u64, u32, u64, u32) {
    match mutation {
        InterruptMutation::Drop => (1, 0, 0, 0, 0),
        InterruptMutation::Delay { delay_nanos } => (2, delay_nanos.get(), 0, 0, 0),
        InterruptMutation::Duplicate { copies, gap_nanos } => (3, 0, copies.get(), *gap_nanos, 0),
        InterruptMutation::Replace { vector } => (4, 0, 0, 0, *vector),
    }
}

pub(super) fn memory_access_mutation(
    mutation: &MemoryAccessMutation,
) -> Result<(u32, Vec<u8>, bool, Vec<u8>), NodeFaultPayloadError> {
    Ok(match mutation {
        MemoryAccessMutation::Stuck { mask, value } => (1, mask.decode(), true, value.decode()),
        MemoryAccessMutation::ReadCorrupt { mask } => (2, mask.decode(), false, vec![0]),
        MemoryAccessMutation::LostWrite => (3, vec![0], false, vec![0]),
        MemoryAccessMutation::TornWrite { selector } => (4, vec![0], true, selector.decode()),
        MemoryAccessMutation::Poison { policy } => {
            (5, vec![0], true, json_bytes(node_fault_field::P6, policy)?)
        }
    })
}

#[allow(
    clippy::type_complexity,
    reason = "the tuple is the closed scalar/payload representation consumed immediately by the clock command encoder"
)]
pub(super) fn clock_mutation(
    mutation: &ClockMutation,
) -> Result<(u32, i64, i64, u64, u64, Vec<u8>), NodeFaultPayloadError> {
    Ok(match mutation {
        ClockMutation::Offset { offset_nanos } => (1, *offset_nanos, 1, 1, 0, vec![0]),
        ClockMutation::Drift { ratio } => {
            (2, 0, ratio.numerator(), ratio.denominator(), 0, vec![0])
        }
        ClockMutation::Jump { delta_nanos } => (3, *delta_nanos, 1, 1, 0, vec![0]),
        ClockMutation::Freeze {
            value_nanos,
            release,
        } => (
            4,
            0,
            1,
            1,
            *value_nanos,
            json_bytes(node_fault_field::P6, release)?,
        ),
        ClockMutation::Jitter {
            maximum_nanos,
            distribution_nanos,
        } => (
            5,
            0,
            1,
            1,
            maximum_nanos.get(),
            json_bytes(node_fault_field::P6, distribution_nanos)?,
        ),
        ClockMutation::Wander { process } => {
            (6, 0, 1, 1, 0, json_bytes(node_fault_field::P6, process)?)
        }
    })
}

pub(super) fn json_field<T: serde::Serialize>(
    tag: u16,
    value: &T,
) -> Result<NodeFaultFieldV1, NodeFaultPayloadError> {
    Ok(NodeFaultFieldV1::bytes(tag, json_bytes(tag, value)?))
}

pub(super) fn json_bytes<T: serde::Serialize + ?Sized>(
    tag: u16,
    value: &T,
) -> Result<Vec<u8>, NodeFaultPayloadError> {
    let canonical =
        serde_json::to_value(value).map_err(|_source| NodeFaultPayloadError::FieldValue { tag })?;
    let encoded = serde_json::to_vec(&canonical)
        .map_err(|_source| NodeFaultPayloadError::FieldValue { tag })?;
    let mut framed = Vec::with_capacity(NODE_FAULT_POLICY_JSON_MAGIC_V1.len() + encoded.len());
    framed.extend_from_slice(&NODE_FAULT_POLICY_JSON_MAGIC_V1);
    framed.extend_from_slice(&encoded);
    Ok(framed)
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
const fn cpu_service_discipline_tag(value: CpuServiceDiscipline) -> u32 {
    match value {
        CpuServiceDiscipline::WorkConserving => 1,
        CpuServiceDiscipline::StrictCap => 2,
    }
}
const fn clock_monotonicity_tag(value: ClockMonotonicityPolicy) -> u32 {
    match value {
        ClockMonotonicityPolicy::AllowBackward => 1,
        ClockMonotonicityPolicy::ClampMonotonic => 2,
        ClockMonotonicityPolicy::FaultOnBackward => 3,
    }
}
const fn overdue_timer_policy_tag(value: ClockOverdueTimerPolicy) -> u32 {
    match value {
        ClockOverdueTimerPolicy::FireAtBoundary => 1,
        ClockOverdueTimerPolicy::Drop => 2,
        ClockOverdueTimerPolicy::ReschedulePeriodic => 3,
    }
}
pub(super) fn memory_access_class_bits(value: crucible::model::MemoryAccessClasses) -> u32 {
    u32::from(value.fetch)
        | (u32::from(value.cpu_load) << 1)
        | (u32::from(value.cpu_store) << 2)
        | (u32::from(value.dma_read) << 3)
        | (u32::from(value.dma_write) << 4)
        | (u32::from(value.page_table_walk) << 5)
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
        FaultPhase::PageTableWalk => 37,
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
