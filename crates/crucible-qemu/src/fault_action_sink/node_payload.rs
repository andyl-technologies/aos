//! Translation from resolved signal actions to the public QEMU node payload.

use crucible::model::{
    AcceleratorTransition, BindingActionKind, ClockMonotonicityPolicy, ClockMutation,
    ClockOverdueTimerPolicy, ContentHash, CpuServiceDiscipline, EffectSpecification, FaultObjectId,
    FaultPhase, InstructionMutation, InterruptMutation, MemoryAccessMutation, MemoryAddressSpace,
    MemoryEccKind, MemoryRegionKind, NodeEffectSpecification, NodeHangScope,
    NodeLifecycleTransition, NodeStatePolicy, RegisterMutation, ResolvedBindingAction,
    ResolvedFaultTarget, VcpuState,
};
use crucible_shmem::{
    FaultCommandKind, NODE_FAULT_POLICY_JSON_MAGIC_V1, NodeFaultFieldV1, NodeFaultOperationV1,
    NodeFaultPayloadError, NodeFaultPayloadV1, NodeFaultTargetKindV1, fault_object_id_hash_v1,
    node_fault_field,
};
use sha2::{Digest, Sha256};

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
    if !effect_matches_target(action.effect.specification(), &action.target) {
        return Err(NodeFaultPayloadError::TargetValue);
    }
    let (node, target_kind, mut target_fields) = target_fields(&action.target)?;
    let operation = match action.kind {
        BindingActionKind::UpsertPersistent => NodeFaultOperationV1::Upsert,
        BindingActionKind::RemovePersistent => NodeFaultOperationV1::Remove,
        BindingActionKind::Apply => NodeFaultOperationV1::Apply,
    };
    let fields = payload_fields(operation, action.effect.specification(), &mut target_fields)?;
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

fn payload_fields(
    operation: NodeFaultOperationV1,
    specification: &EffectSpecification,
    target_fields: &mut Vec<NodeFaultFieldV1>,
) -> Result<Vec<NodeFaultFieldV1>, NodeFaultPayloadError> {
    if operation == NodeFaultOperationV1::Remove {
        return Ok(Vec::new());
    }
    let mut fields = effect_fields(specification)?;
    fields.append(target_fields);
    Ok(fields)
}

fn effect_matches_target(
    specification: &EffectSpecification,
    target: &ResolvedFaultTarget,
) -> bool {
    let EffectSpecification::Node(effect) = specification else {
        return false;
    };
    match (effect, target) {
        (NodeEffectSpecification::Lifecycle { .. }, ResolvedFaultTarget::Node { .. }) => true,
        (NodeEffectSpecification::Hang { scope, .. }, ResolvedFaultTarget::Node { .. }) => {
            matches!(scope, NodeHangScope::Node)
        }
        (
            NodeEffectSpecification::Hang {
                scope: NodeHangScope::Vcpus(vcpus),
                ..
            },
            ResolvedFaultTarget::Vcpu { vcpu, .. },
        ) => vcpus.binary_search(vcpu).is_ok(),
        (
            NodeEffectSpecification::Hang {
                scope: NodeHangScope::Device(selected),
                ..
            },
            ResolvedFaultTarget::Accelerator { device, .. },
        ) => selected == device,
        (NodeEffectSpecification::CpuService { .. }, ResolvedFaultTarget::Node { .. }) => true,
        (
            NodeEffectSpecification::CpuService { vcpus, .. },
            ResolvedFaultTarget::Vcpu { vcpu, .. },
        ) => vcpus.binary_search(vcpu).is_ok(),
        (NodeEffectSpecification::VcpuState { .. }, ResolvedFaultTarget::Vcpu { .. })
        | (
            NodeEffectSpecification::InstructionTransform { .. }
            | NodeEffectSpecification::CpuException { .. },
            ResolvedFaultTarget::Vcpu { .. },
        ) => true,
        (
            NodeEffectSpecification::RegisterTransform {
                register,
                first_bit,
                bit_count,
                ..
            },
            ResolvedFaultTarget::Register {
                register: target_register,
                first_bit: target_first_bit,
                bit_count: target_bit_count,
                ..
            },
        ) => {
            register == target_register
                && *first_bit == *target_first_bit
                && bit_count.get() == u32::from(*target_bit_count)
        }
        (
            NodeEffectSpecification::InterruptDisposition { .. },
            ResolvedFaultTarget::Interrupt { .. },
        ) => true,
        (
            NodeEffectSpecification::InterruptStorm { source, vector, .. },
            ResolvedFaultTarget::Interrupt {
                source: target_source,
                vector: target_vector,
                ..
            },
        ) => source == target_source && *vector == *target_vector,
        (
            NodeEffectSpecification::MemoryAccessTransform {
                range, accesses, ..
            },
            ResolvedFaultTarget::MemoryRange {
                address_space,
                guest_address,
                length_bytes,
                vcpu,
                ..
            },
        ) => {
            range.start() == *guest_address
                && range.length() == *length_bytes
                && (!accesses.page_table_walk
                    || (address_space.as_str() == "gpa" && vcpu.is_none()))
        }
        (
            NodeEffectSpecification::MemoryRegionState { range, .. },
            ResolvedFaultTarget::MemoryRange {
                guest_address,
                length_bytes,
                ..
            },
        ) => range.start() == *guest_address && range.length() == *length_bytes,
        (
            NodeEffectSpecification::MemoryEccEvent { address, .. },
            ResolvedFaultTarget::MemoryRange {
                guest_address,
                length_bytes,
                ..
            },
        ) => {
            *length_bytes > 0
                && *address >= *guest_address
                && address
                    .checked_sub(*guest_address)
                    .is_some_and(|offset| offset < *length_bytes)
        }
        (
            NodeEffectSpecification::MemoryService { .. },
            ResolvedFaultTarget::MemoryRange { .. },
        ) => true,
        (
            NodeEffectSpecification::ClockTransform { source, .. },
            ResolvedFaultTarget::ClockSource {
                source: target_source,
                ..
            },
        ) => source == target_source,
        (
            NodeEffectSpecification::ClockSourceState { sources, .. },
            ResolvedFaultTarget::ClockSource { source, .. },
        ) => sources.as_slice().binary_search(source).is_ok(),
        (
            NodeEffectSpecification::AcceleratorLifecycle { device, .. },
            ResolvedFaultTarget::Accelerator {
                device: target_device,
                ..
            },
        ) => device == target_device,
        (
            NodeEffectSpecification::AcceleratorResultTransform { .. }
            | NodeEffectSpecification::AcceleratorMemoryEvent { .. }
            | NodeEffectSpecification::AcceleratorService { .. },
            ResolvedFaultTarget::Accelerator { .. },
        ) => true,
        (
            NodeEffectSpecification::MemoryMutation {
                address_space,
                range,
                ..
            },
            ResolvedFaultTarget::MemoryRange {
                address_space: target_address_space,
                guest_address,
                length_bytes,
                vcpu,
                ..
            },
        ) => {
            let address_matches = match address_space {
                MemoryAddressSpace::GuestPhysical => {
                    target_address_space.as_str() == "gpa" && vcpu.is_none()
                }
                MemoryAddressSpace::GuestVirtual => {
                    target_address_space.as_str() == "gva" && vcpu.is_some()
                }
            };
            address_matches && range.start() == *guest_address && range.length() == *length_bytes
        }
        _ => false,
    }
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
            json_field(P3, boot_policy)?,
            NodeFaultFieldV1::u32(P4, state_policy_tag(*volatile_state_policy)),
            NodeFaultFieldV1::u32(P5, state_policy_tag(*device_state_policy)),
        ],
        NodeEffectSpecification::Hang {
            scope,
            recovery_event,
            watchdog_policy,
        } => vec![
            NodeFaultFieldV1::u32(P1, hang_scope_tag(scope)),
            json_field(P2, scope)?,
            id_field(P3, recovery_event),
            json_field(P4, watchdog_policy)?,
        ],
        NodeEffectSpecification::CpuService {
            vcpus,
            capacity,
            quantum_instructions,
            service_rule,
        } => vec![
            json_field(P1, vcpus)?,
            NodeFaultFieldV1::ratio(P2, capacity.numerator(), capacity.denominator()),
            NodeFaultFieldV1::u64(P3, quantum_instructions.get()),
            NodeFaultFieldV1::u32(P4, cpu_service_discipline_tag(*service_rule)),
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
                json_field(P8, occurrence)?,
            ]
        }
        NodeEffectSpecification::InstructionTransform { selector, mutation } => {
            let (kind, destination, transform, count) = instruction_mutation(mutation)?;
            vec![
                json_field(P1, selector)?,
                NodeFaultFieldV1::u32(P2, kind),
                NodeFaultFieldV1::hash(P3, destination),
                NodeFaultFieldV1::bytes(P4, transform),
                NodeFaultFieldV1::u32(P5, count),
            ]
        }
        NodeEffectSpecification::CpuException { exception } => {
            vec![json_field(P1, exception)?]
        }
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
            json_field(P6, routing)?,
        ],
        NodeEffectSpecification::MemoryMutation { .. } => {
            return Err(NodeFaultPayloadError::CommandKind(
                FaultCommandKind::MemoryMutation as u16,
            ));
        }
        NodeEffectSpecification::MemoryAccessTransform {
            range,
            accesses,
            dma_device,
            violate_atomicity,
            mutation,
            occurrence,
        } => {
            let (kind, mask, has_value, value) = memory_access_mutation(mutation)?;
            vec![
                NodeFaultFieldV1::u64(P1, range.start()),
                NodeFaultFieldV1::u64(P2, range.length()),
                NodeFaultFieldV1::u32(P3, kind),
                NodeFaultFieldV1::bytes(P4, mask),
                NodeFaultFieldV1::boolean(P5, has_value),
                NodeFaultFieldV1::bytes(P6, value),
                json_field(P7, occurrence)?,
                NodeFaultFieldV1::u32(P8, memory_access_class_bits(*accesses)),
                NodeFaultFieldV1::boolean(P9, *violate_atomicity),
                NodeFaultFieldV1::boolean(P10, dma_device.is_some()),
                dma_device.as_ref().map_or_else(
                    || NodeFaultFieldV1::hash(P11, [0; 32]),
                    |device| NodeFaultFieldV1::hash(P11, qemu_virtio_dma_identity(device)),
                ),
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
            json_field(P7, guest_visibility)?,
        ],
        NodeEffectSpecification::MemoryRegionState {
            range,
            kind,
            process,
        } => vec![
            NodeFaultFieldV1::u64(P1, range.start()),
            NodeFaultFieldV1::u64(P2, range.length()),
            NodeFaultFieldV1::u32(P3, memory_region_tag(*kind)),
            json_field(P4, process)?,
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
            json_field(P6, sharing_scope)?,
        ],
        NodeEffectSpecification::ClockTransform {
            source,
            mutation,
            monotonicity,
            overdue_timer_policy,
        } => {
            let (kind, signed, numerator, denominator, unsigned, process) =
                clock_mutation(mutation)?;
            vec![
                id_field(P1, source),
                NodeFaultFieldV1::u32(P2, kind),
                NodeFaultFieldV1::i64(P3, signed),
                NodeFaultFieldV1::ratio(P4, numerator, denominator),
                NodeFaultFieldV1::u64(P5, unsigned),
                NodeFaultFieldV1::bytes(P6, process),
                NodeFaultFieldV1::u32(P7, clock_monotonicity_tag(*monotonicity)),
                NodeFaultFieldV1::u32(P8, overdue_timer_policy_tag(*overdue_timer_policy)),
            ]
        }
        NodeEffectSpecification::ClockSourceState {
            sources,
            transition,
            synchronization_policy,
        } => vec![
            NodeFaultFieldV1::hash_set(P1, &id_set(sources.as_slice()))?,
            json_field(P2, transition)?,
            json_field(P3, synchronization_policy)?,
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
        } => vec![json_field(P1, job_selector)?, json_field(P2, transform)?],
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
            NodeFaultFieldV1::bytes(
                P8,
                transform
                    .as_ref()
                    .map_or_else(|| vec![0], |value| value.decode()),
            ),
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
            json_field(P6, thermal_power)?,
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
    fault_object_id_hash_v1(id.as_str())
}

fn qemu_virtio_dma_identity(id: &FaultObjectId) -> [u8; 32] {
    let mut digest = Sha256::new();

    digest.update(b"qemu.virtio.dma-id.v1");
    digest.update(id.as_str().as_bytes());
    digest.finalize().into()
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

fn register_mutation(mutation: &RegisterMutation) -> (u32, Vec<u8>, bool, Vec<u8>) {
    match mutation {
        RegisterMutation::BitFlip { mask } => (1, mask.decode(), false, vec![0]),
        RegisterMutation::Stuck { mask, value } => (2, mask.decode(), true, value.decode()),
        RegisterMutation::Replace { value } => {
            (3, vec![0xff; value.decode().len()], true, value.decode())
        }
    }
}

fn instruction_mutation(
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

fn interrupt_mutation(mutation: &InterruptMutation) -> (u32, u64, u32, u64, u32) {
    match mutation {
        InterruptMutation::Drop => (1, 0, 0, 0, 0),
        InterruptMutation::Delay { delay_nanos } => (2, delay_nanos.get(), 0, 0, 0),
        InterruptMutation::Duplicate { copies, gap_nanos } => (3, 0, copies.get(), *gap_nanos, 0),
        InterruptMutation::Replace { vector } => (4, 0, 0, 0, *vector),
    }
}

fn memory_access_mutation(
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

fn clock_mutation(
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

fn json_field<T: serde::Serialize>(
    tag: u16,
    value: &T,
) -> Result<NodeFaultFieldV1, NodeFaultPayloadError> {
    Ok(NodeFaultFieldV1::bytes(tag, json_bytes(tag, value)?))
}

fn json_bytes<T: serde::Serialize + ?Sized>(
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
fn memory_access_class_bits(value: crucible::model::MemoryAccessClasses) -> u32 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::model::{
        BindingActionCause, ByteRange, EffectLifetime, EffectRequest, FaultCoordinate,
        MemoryAccessClasses, MemoryAccessMutation, NodeBootPolicy, NodeOccurrencePolicy,
        ResolvedMappingOutput,
    };
    use serde_json::json;
    use std::sync::Arc;

    fn object_id(value: &str) -> FaultObjectId {
        FaultObjectId::parse(value)
            .unwrap_or_else(|error| panic!("test object ID must be valid: {error}"))
    }

    fn lifecycle() -> EffectSpecification {
        EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
            transition: NodeLifecycleTransition::Reset,
            downtime_nanos: 1,
            boot_policy: NodeBootPolicy::Immediate,
            volatile_state_policy: NodeStatePolicy::Clear,
            device_state_policy: NodeStatePolicy::DeviceReset,
        })
    }

    #[test]
    fn shared_object_id_hash_matches_the_model_contract() {
        let id = object_id("node-a/register/rip");

        assert_eq!(
            fault_object_id_hash_v1(id.as_str()),
            ContentHash::from_canonical_material("crucible.fault-object.v1", id.as_str()).bytes,
        );
    }

    #[test]
    fn remove_payload_discards_all_target_fields() {
        let mut target = vec![NodeFaultFieldV1::u32(node_fault_field::T1, 7)];
        assert_eq!(
            payload_fields(NodeFaultOperationV1::Remove, &lifecycle(), &mut target),
            Ok(Vec::new())
        );
    }

    #[test]
    fn effect_target_pairing_rejects_wrong_category() {
        let target = ResolvedFaultTarget::Vcpu {
            node: object_id("node-a"),
            vcpu: 0,
        };
        assert!(!effect_matches_target(&lifecycle(), &target));
    }

    #[test]
    fn effect_target_pairing_rejects_conflicting_memory_range() {
        let range = ByteRange::new(0x1000, 64)
            .unwrap_or_else(|error| panic!("test range must be valid: {error}"));
        let effect = EffectSpecification::Node(NodeEffectSpecification::MemoryAccessTransform {
            range,
            accesses: MemoryAccessClasses {
                fetch: false,
                cpu_load: false,
                cpu_store: true,
                dma_read: false,
                dma_write: false,
                page_table_walk: false,
            },
            dma_device: None,
            violate_atomicity: false,
            mutation: MemoryAccessMutation::LostWrite,
            occurrence: NodeOccurrencePolicy::Every,
        });
        let target = ResolvedFaultTarget::MemoryRange {
            node: object_id("node-a"),
            address_space: object_id("gpa"),
            guest_address: 0x2000,
            vcpu: None,
            length_bytes: 64,
        };
        assert!(!effect_matches_target(&effect, &target));
    }

    #[test]
    fn page_table_walk_rejects_a_virtual_memory_target() {
        let range = ByteRange::new(0x1000, 8)
            .unwrap_or_else(|error| panic!("test range must be valid: {error}"));
        let effect = EffectSpecification::Node(NodeEffectSpecification::MemoryAccessTransform {
            range,
            accesses: MemoryAccessClasses {
                fetch: false,
                cpu_load: false,
                cpu_store: false,
                dma_read: false,
                dma_write: false,
                page_table_walk: true,
            },
            dma_device: None,
            violate_atomicity: false,
            mutation: MemoryAccessMutation::ReadCorrupt {
                mask: crucible::model::HexBytes::parse("01", 1)
                    .unwrap_or_else(|error| panic!("test mask must be valid: {error}")),
            },
            occurrence: NodeOccurrencePolicy::Every,
        });
        let target = ResolvedFaultTarget::MemoryRange {
            node: object_id("node-a"),
            address_space: object_id("gva"),
            guest_address: 0x1000,
            vcpu: Some(0),
            length_bytes: 8,
        };

        assert!(!effect_matches_target(&effect, &target));
    }

    #[test]
    fn dma_device_identity_matches_the_qemu_wire_contract() {
        assert_eq!(
            qemu_virtio_dma_identity(&object_id("virtio-net0")),
            [
                0x73, 0x0e, 0x68, 0xf0, 0x8a, 0xfe, 0x82, 0xa7, 0x98, 0x02, 0xa9, 0xfd, 0x7c, 0xd2,
                0xb0, 0xbf, 0x32, 0x8c, 0x96, 0x5c, 0xeb, 0x4c, 0x76, 0x5f, 0xc5, 0xdb, 0x6f, 0x73,
                0x84, 0xab, 0x07, 0xe6,
            ]
        );
    }

    #[test]
    fn every_typed_node_effect_translates_to_its_closed_wire_schema() {
        let effects = [
            json!({"kind":"lifecycle","parameters":{"transition":"reset","downtime_nanos":10,"boot_policy":{"kind":"immediate"},"volatile_state_policy":"clear","device_state_policy":"device_reset"}}),
            json!({"kind":"hang","parameters":{"scope":{"kind":"node"},"recovery_event":"recover","watchdog_policy":{"kind":"disabled"}}}),
            json!({"kind":"cpu_service","parameters":{"vcpus":[0],"capacity":{"numerator":1,"denominator":2},"quantum_instructions":100,"service_rule":"strict_cap"}}),
            json!({"kind":"vcpu_state","parameters":{"state":"offline","recovery_event":"recover"}}),
            json!({"kind":"register_transform","parameters":{"register":"rax","first_bit":0,"bit_count":8,"mutation":{"kind":"bit_flip","parameters":{"mask":"01"}},"occurrence":{"kind":"every"}}}),
            json!({"kind":"instruction_transform","parameters":{"selector":{"pc_start":4096,"pc_length":4,"instruction_bytes":"90909090","opcode_class":null,"occurrence":{"kind":"every"}},"mutation":{"kind":"result_corrupt","parameters":{"transform":{"destination":"rax","mutation":{"kind":"replace","parameters":{"value":"01"}}}}}}}),
            json!({"kind":"cpu_exception","parameters":{"exception":{"architecture":"x86_64","vector":18,"syndrome":0,"fault_address":null,"before_instruction":true,"maskable":false,"record":{"kind":"architecture_default"}}}}),
            json!({"kind":"interrupt_disposition","parameters":{"mutation":{"kind":"delay","parameters":{"delay_nanos":10}}}}),
            json!({"kind":"interrupt_storm","parameters":{"source":"timer","vector":32,"period_nanos":100,"burst":2,"count":4,"routing":{"target_vcpus":[0],"priority":0,"retain_pending":true}}}),
            json!({"kind":"memory_access_transform","parameters":{"range":{"start":4096,"length":64},"accesses":{"fetch":false,"cpu_load":false,"cpu_store":true,"dma_read":false,"dma_write":false,"page_table_walk":false},"violate_atomicity":true,"mutation":{"kind":"torn_write","parameters":{"selector":"0f"}},"occurrence":{"kind":"every"}}}),
            json!({"kind":"memory_ecc_event","parameters":{"kind":"corrected","address":4096,"syndrome":1,"bank":"bank-0","channel":"channel-0","rank":"rank-0","guest_visibility":{"kind":"telemetry_only"}}}),
            json!({"kind":"memory_region_state","parameters":{"range":{"start":4096,"length":64},"kind":"retention","process":{"kind":"retention","parameters":{"interval_nanos":100,"decay_mask":"01"}}}}),
            json!({"kind":"memory_service","parameters":{"latency_nanos":10,"bandwidth_bytes_per_second":null,"operations_per_second":null,"sharing_scope":{"kind":"range"}}}),
            json!({"kind":"clock_transform","parameters":{"source":"clock-main","mutation":{"kind":"freeze","parameters":{"value_nanos":1000,"release":"resume_from_frozen"}},"monotonicity":"clamp_monotonic","overdue_timer_policy":"fire_at_boundary"}}),
            json!({"kind":"clock_source_state","parameters":{"sources":["clock-main"],"transition":{"kind":"failed","parameters":{"behavior":"read_error"}},"synchronization_policy":{"kind":"step"}}}),
            json!({"kind":"accelerator_lifecycle","parameters":{"device":"accelerator-0","transition":"reset","queue_policy":"clear","memory_policy":"device_reset"}}),
            json!({"kind":"accelerator_result_transform","parameters":{"job_selector":{"job_kind":"matrix-multiply","queue":null,"occurrence":{"kind":"every"}},"transform":{"offset":0,"mask":"01","value":"01"}}}),
            json!({"kind":"accelerator_memory_event","parameters":{"range":{"start":0,"length":1},"ecc":null,"syndrome":null,"transform":"01"}}),
            json!({"kind":"accelerator_service","parameters":{"capacity":{"numerator":1,"denominator":2},"memory_bytes_per_second":null,"jobs_per_second":null,"thermal_power":{"temperature_millikelvin":300000,"power_milliwatts":1000}}}),
        ];
        assert_eq!(effects.len(), 19);
        for encoded_effect in effects {
            let effect: NodeEffectSpecification = serde_json::from_value(encoded_effect)
                .unwrap_or_else(|error| panic!("closed node effect JSON must decode: {error}"));
            effect
                .validate()
                .unwrap_or_else(|error| panic!("closed node effect must validate: {error}"));
            let specification = EffectSpecification::Node(effect);
            let kind = specification.kind();
            let descriptor = kind.descriptor();
            let lifetime = descriptor.lifetimes[0];
            let action = ResolvedBindingAction {
                kind: if lifetime == EffectLifetime::Persistent {
                    BindingActionKind::UpsertPersistent
                } else {
                    BindingActionKind::Apply
                },
                binding: object_id("binding-a"),
                target: test_target(kind),
                phase: descriptor.phases[0],
                effect: Arc::new(
                    EffectRequest::new(descriptor.semantic_version, lifetime, specification)
                        .unwrap_or_else(|error| panic!("{kind:?} request must validate: {error}")),
                ),
                mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
                mapped_digest: ContentHash { bytes: [1; 32] },
                transition_sequence: 1,
                opportunity: None,
                coordinate: FaultCoordinate {
                    virtual_nanos: 1,
                    retired_instructions: Some(1),
                },
                cause: BindingActionCause::Signal,
                expected_precondition: None,
            };
            let encoded = encode_node_action(&action, [3; 32])
                .unwrap_or_else(|error| panic!("{kind:?} must translate: {error}"));
            let bytes = encoded
                .payload
                .encode()
                .unwrap_or_else(|error| panic!("{kind:?} wire schema must encode: {error}"));
            assert_eq!(NodeFaultPayloadV1::decode(&bytes), Ok(encoded.payload));
        }
    }

    fn test_target(kind: crucible::model::EffectKind) -> ResolvedFaultTarget {
        use crucible::model::EffectKind;
        let node = || object_id("node-a");
        match kind {
            EffectKind::NodeLifecycle | EffectKind::NodeHang | EffectKind::CpuService => {
                ResolvedFaultTarget::Node { node: node() }
            }
            EffectKind::CpuVcpuState
            | EffectKind::CpuInstructionTransform
            | EffectKind::CpuException => ResolvedFaultTarget::Vcpu {
                node: node(),
                vcpu: 0,
            },
            EffectKind::CpuRegisterTransform => ResolvedFaultTarget::Register {
                node: node(),
                vcpu: 0,
                architecture: object_id("x86-64"),
                register: object_id("rax"),
                first_bit: 0,
                bit_count: 8,
            },
            EffectKind::InterruptDisposition | EffectKind::InterruptStorm => {
                ResolvedFaultTarget::Interrupt {
                    node: node(),
                    controller: object_id("apic"),
                    source: object_id("timer"),
                    target_vcpu: 0,
                    vector: 32,
                }
            }
            EffectKind::MemoryAccessTransform
            | EffectKind::MemoryEccEvent
            | EffectKind::MemoryRegionState
            | EffectKind::MemoryService => ResolvedFaultTarget::MemoryRange {
                node: node(),
                address_space: object_id("gpa"),
                guest_address: 4096,
                vcpu: None,
                length_bytes: 64,
            },
            EffectKind::ClockTransform | EffectKind::ClockSourceState => {
                ResolvedFaultTarget::ClockSource {
                    node: node(),
                    source: object_id("clock-main"),
                }
            }
            EffectKind::AcceleratorLifecycle
            | EffectKind::AcceleratorResultTransform
            | EffectKind::AcceleratorMemoryEvent
            | EffectKind::AcceleratorService => ResolvedFaultTarget::Accelerator {
                node: node(),
                device: object_id("accelerator-0"),
            },
            _ => panic!("unexpected typed node effect {kind:?}"),
        }
    }
}
