//! Bounded construction of the QEMU memory-mutation payload.

use super::*;

pub(super) struct MemoryActionPayload {
    pub(super) action: ResolvedBindingAction,
    pub(super) node: NodeId,
    pub(super) payload: MemoryMutationPayloadV1,
}

pub(super) fn prepare_memory_action_payload(
    action: &ResolvedBindingAction,
    resource_limits: FaultResourceLimits,
) -> Result<MemoryActionPayload, FaultRuntimeError> {
    if action.kind != BindingActionKind::Apply || action.phase != FaultPhase::Boundary {
        return Err(FaultRuntimeError::AdapterActionMismatch);
    }
    let ResolvedFaultTarget::MemoryRange {
        node,
        address_space,
        guest_address,
        vcpu,
        length_bytes,
    } = &action.target
    else {
        return Err(FaultRuntimeError::AdapterActionMismatch);
    };
    let EffectSpecification::Node(NodeEffectSpecification::MemoryMutation {
        address_space: requested_address_space,
        range,
        mutation,
        atomicity,
    }) = action.effect.specification()
    else {
        return Err(FaultRuntimeError::AdapterActionMismatch);
    };
    let target_address_space = match (address_space.as_str(), vcpu) {
        ("gpa", None) => MemoryAddressSpace::GuestPhysical,
        ("gva", Some(_)) => MemoryAddressSpace::GuestVirtual,
        _ => return Err(FaultRuntimeError::AdapterActionMismatch),
    };
    if target_address_space != *requested_address_space
        || *atomicity != ModelMemoryMutationAtomicity::AllOrNothing
        || range.start() != *guest_address
        || range.length() != *length_bytes
    {
        return Err(FaultRuntimeError::AdapterActionMismatch);
    }
    resource_limits
        .reserve("memory_mutation_bytes_per_effect", 0, *length_bytes)
        .map_err(FaultRuntimeError::ResourceLimit)?;
    let length = usize::try_from(*length_bytes)
        .map_err(|_source| FaultRuntimeError::AdapterActionMismatch)?;
    let (transform, mask, values) = match mutation {
        MemoryMutationKind::BitFlip { mask } => {
            let pattern = mask.decode();
            let mut expanded = Vec::new();
            expanded.try_reserve_exact(length).map_err(|_| {
                FaultRuntimeError::ResourceLimit(FaultResourceLimitError::Exceeded {
                    field: "memory_mutation_bytes_per_effect",
                    current: 0,
                    requested: *length_bytes,
                    configured: resource_limits.memory_mutation_bytes_per_effect,
                    hard: FaultResourceLimits::compiled_maximum().memory_mutation_bytes_per_effect,
                })
            })?;
            expanded.extend(pattern.iter().copied().cycle().take(length));
            (MemoryMutationTransformKind::BitFlip, expanded, Vec::new())
        }
        MemoryMutationKind::Replace { bytes } => (
            MemoryMutationTransformKind::Replace,
            vec![0xff; length],
            bytes.decode(),
        ),
    };
    let (address_space, vcpu_index) = match target_address_space {
        MemoryAddressSpace::GuestPhysical => (
            MemoryMutationAddressSpace::GuestPhysical,
            MEMORY_MUTATION_NO_VCPU,
        ),
        MemoryAddressSpace::GuestVirtual => (
            MemoryMutationAddressSpace::GuestVirtual,
            (*vcpu).ok_or(FaultRuntimeError::AdapterActionMismatch)?,
        ),
    };
    let payload = MemoryMutationPayloadV1 {
        address_space,
        transform,
        atomicity: MemoryMutationAtomicity::AllOrNothing,
        vcpu_index,
        address: *guest_address,
        mask,
        values,
        expected_translation_sha256: [0; 32],
    };
    let node = NodeId {
        name: node.as_str().to_owned(),
    };
    Ok(MemoryActionPayload {
        action: action.clone(),
        node,
        payload,
    })
}
