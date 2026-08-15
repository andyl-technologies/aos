//! Typed node-effect field encoding.

use super::*;

pub(super) fn effect_fields(
    specification: &EffectSpecification,
    cause: &BindingActionCause,
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
            target_vcpu,
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
            NodeFaultFieldV1::u32(P8, *target_vcpu),
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
        } => {
            let BindingActionCause::Opportunity {
                payload:
                    OpportunityPayload::AcceleratorJob {
                        job_sequence,
                        job_digest,
                    },
                ..
            } = cause
            else {
                return Err(NodeFaultPayloadError::Operation(
                    NodeFaultOperationV1::Apply as u16,
                ));
            };
            vec![
                json_field(P1, job_selector)?,
                json_field(P2, transform)?,
                NodeFaultFieldV1::u64(P3, *job_sequence),
                NodeFaultFieldV1::hash(P4, job_digest.bytes),
            ]
        }
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
