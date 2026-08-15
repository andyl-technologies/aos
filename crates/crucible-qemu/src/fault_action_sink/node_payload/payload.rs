//! Node-effect matching and top-level payload assembly.

use super::*;

pub(super) fn payload_fields(
    operation: NodeFaultOperationV1,
    specification: &EffectSpecification,
    cause: &BindingActionCause,
    target_fields: &mut Vec<NodeFaultFieldV1>,
) -> Result<Vec<NodeFaultFieldV1>, NodeFaultPayloadError> {
    if operation == NodeFaultOperationV1::Remove {
        return Ok(Vec::new());
    }
    let mut fields = effect_fields(specification, cause)?;
    fields.append(target_fields);
    Ok(fields)
}

pub(super) fn effect_matches_target(
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

pub(super) fn command_kind(specification: &EffectSpecification) -> Option<FaultCommandKind> {
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
