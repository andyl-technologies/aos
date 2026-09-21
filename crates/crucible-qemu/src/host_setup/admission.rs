//! Setup-time capability query publication and authenticated result admission.

use super::*;

pub(super) fn enqueue_target_manifest_query(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    target_node_hash: [u8; 32],
    kind: FaultTargetManifestKind,
    command_sequence: u64,
) -> Result<(), QemuHostPluginSetupError> {
    let payload = FaultTargetManifestQueryV1 { kind }.encode();
    let transport = region
        .fault_command_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let mut binding_hasher = blake3::Hasher::new();
    binding_hasher.update(b"crucible.qemu-fault-target-manifest-admission.v1\0");
    binding_hasher.update(&target_node_hash);
    binding_hasher.update(&payload);
    enqueue_fault_command(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
        FaultCommandHeaderV1 {
            abi_major: FAULT_COMMAND_ABI_MAJOR,
            abi_minor: FAULT_COMMAND_ABI_MINOR,
            command_kind: FaultCommandKind::QueryTargetManifest,
            command_flags: 0,
            phase: FaultBoundaryPhase::NodeBoundary,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            command_sequence,
            target_node_hash,
            target_icount: 0,
            authorization_ceiling_icount: 0,
            binding_hash: *binding_hasher.finalize().as_bytes(),
            opportunity_hash: [0; 32],
            expected_precondition_hash: [0; 32],
            payload_hash: [0; 32],
            payload_offset: 0,
            payload_length: 0,
        },
        &payload,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })
}

pub(super) fn enqueue_capability_query(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    target_node_hash: [u8; 32],
) -> Result<(), QemuHostPluginSetupError> {
    if target_node_hash == [0; 32] {
        return Err(QemuHostPluginSetupError::AdmissionTargetIdentity);
    }
    let transport = region
        .fault_command_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let mut binding_hasher = blake3::Hasher::new();
    binding_hasher.update(b"crucible.qemu-fault-capability-admission.v1\0");
    binding_hasher.update(&target_node_hash);
    let header = FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::QueryCapabilities,
        command_flags: 0,
        phase: FaultBoundaryPhase::NodeBoundary,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: 1,
        target_node_hash,
        target_icount: 0,
        authorization_ceiling_icount: 0,
        binding_hash: *binding_hasher.finalize().as_bytes(),
        opportunity_hash: [0; 32],
        expected_precondition_hash: [0; 32],
        payload_hash: [0; 32],
        payload_offset: 0,
        payload_length: 0,
    };
    enqueue_fault_command(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
        header,
        &[],
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })
}

pub(super) fn accept_capability_result(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
) -> Result<Vec<FaultCapabilityRowV1>, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 1
        || header.command_kind != FaultCommandKind::QueryCapabilities as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    decode_fault_capability_manifest(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })
}

pub(super) fn accept_register_manifest(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    required: &crate::QemuTargetManifestRequirement,
) -> Result<FaultRegisterCapabilityManifestV1, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 2
        || header.command_kind != FaultCommandKind::QueryTargetManifest as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    let manifest = FaultRegisterCapabilityManifestV1::decode(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
    if manifest.architecture != required.architecture()
        || manifest.cpu_model != required.realized_cpu_type()
    {
        return Err(QemuHostPluginSetupError::AdmissionTargetManifestMismatch {
            required_architecture: required.architecture(),
            observed_architecture: manifest.architecture,
            required_cpu_model: required.realized_cpu_type(),
            observed_cpu_model: manifest.cpu_model.clone(),
        });
    }
    Ok(manifest)
}

pub(super) fn accept_interrupt_manifest(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    required: &crate::QemuTargetManifestRequirement,
) -> Result<FaultInterruptCapabilityManifestV1, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 3
        || header.command_kind != FaultCommandKind::QueryTargetManifest as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    let manifest = FaultInterruptCapabilityManifestV1::decode(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
    if manifest.architecture != required.architecture()
        || required
            .exact_interrupt_manifest()
            .is_some_and(|expected| expected != &manifest)
    {
        return Err(QemuHostPluginSetupError::AdmissionTargetManifestMismatch {
            required_architecture: required.architecture(),
            observed_architecture: manifest.architecture,
            required_cpu_model: required.realized_cpu_type(),
            observed_cpu_model: required.realized_cpu_type(),
        });
    }
    Ok(manifest)
}

pub(super) fn accept_clock_manifest(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    required: &crate::QemuTargetManifestRequirement,
) -> Result<FaultClockCapabilityManifestV1, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 4
        || header.command_kind != FaultCommandKind::QueryTargetManifest as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    let manifest = FaultClockCapabilityManifestV1::decode(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
    if manifest.architecture != required.architecture()
        || required
            .exact_clock_manifest()
            .is_some_and(|expected| expected != &manifest)
    {
        return Err(QemuHostPluginSetupError::AdmissionTargetManifestMismatch {
            required_architecture: required.architecture(),
            observed_architecture: manifest.architecture,
            required_cpu_model: required.realized_cpu_type(),
            observed_cpu_model: required.realized_cpu_type(),
        });
    }
    Ok(manifest)
}

pub(super) fn accept_hardware_error_manifest(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    required: &crate::QemuTargetManifestRequirement,
) -> Result<FaultHardwareErrorCapabilityManifestV1, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 5
        || header.command_kind != FaultCommandKind::QueryTargetManifest as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    let manifest = FaultHardwareErrorCapabilityManifestV1::decode(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
    if manifest.architecture != required.architecture()
        || required
            .exact_hardware_error_manifest()
            .is_some_and(|expected| expected != &manifest)
    {
        return Err(QemuHostPluginSetupError::AdmissionTargetManifestMismatch {
            required_architecture: required.architecture(),
            observed_architecture: manifest.architecture,
            required_cpu_model: required.realized_cpu_type(),
            observed_cpu_model: required.realized_cpu_type(),
        });
    }
    Ok(manifest)
}

pub(super) fn accept_accelerator_manifest(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
    required: &FaultAcceleratorCapabilityManifestV1,
) -> Result<FaultAcceleratorCapabilityManifestV1, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 7
        || header.command_kind != FaultCommandKind::QueryTargetManifest as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    let manifest = FaultAcceleratorCapabilityManifestV1::decode(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })?;
    if &manifest != required {
        return Err(QemuHostPluginSetupError::AdmissionAcceleratorManifestMismatch);
    }
    Ok(manifest)
}

pub(super) fn accept_system_manifest(
    region: &mut crucible_shmem::MappedSetupRegion,
    slot_index: u32,
) -> Result<FaultSystemCapabilityManifestV1, QemuHostPluginSetupError> {
    let transport = region
        .fault_result_transport_mut(slot_index)
        .map_err(|source| QemuHostPluginSetupError::AdmissionAccess { source })?;
    let result = dequeue_fault_result(
        transport.ring,
        transport.slots,
        transport.arena_header,
        transport.arena,
        transport.arena_region_offset,
    )
    .map_err(|source| QemuHostPluginSetupError::AdmissionTransport { source })?
    .ok_or(QemuHostPluginSetupError::AdmissionResultMissing)?;
    let (header, payload) = match result {
        DequeuedFaultResult::Valid { header, payload } => (header, payload),
        DequeuedFaultResult::Invalid {
            command_sequence,
            error,
        } => {
            return Err(QemuHostPluginSetupError::AdmissionResultInvalid {
                command_sequence,
                source: error,
            });
        }
    };
    if header.command_sequence != 6
        || header.command_kind != FaultCommandKind::QueryTargetManifest as u16
        || header.status != FaultResultStatus::Applied
        || header.phase != FaultBoundaryPhase::NodeBoundary
        || header.capability_version != 1
        || header.observed_icount != 0
        || header.applied_icount != 0
        || header.evidence_hash != *blake3::hash(&payload).as_bytes()
    {
        return Err(QemuHostPluginSetupError::AdmissionResultRejected {
            command_sequence: header.command_sequence,
            command_kind: header.command_kind,
            status: header.status,
            phase: header.phase,
            capability_version: header.capability_version,
            observed_icount: header.observed_icount,
            applied_icount: header.applied_icount,
            evidence_hash: header.evidence_hash,
        });
    }
    FaultSystemCapabilityManifestV1::decode(&payload)
        .map_err(|source| QemuHostPluginSetupError::AdmissionManifest { source })
}
