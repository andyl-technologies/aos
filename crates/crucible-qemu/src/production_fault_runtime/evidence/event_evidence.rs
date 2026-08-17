//! QEMU event-to-command matching and typed hardware evidence validation.

use super::*;
pub(crate) fn qemu_event_matches_commit(
    event: &DequeuedFaultEvent,
    action: &ResolvedBindingAction,
    commit: &CommittedQemuActionEvidence,
) -> bool {
    // An accelerator result opportunity commits by installing an armed
    // one-shot. Its later event hashes the device result mutation, not that
    // installation. The remaining fields still bind the event to the exact
    // authenticated APPLY result and issued action.
    let occurrence_hashes_match = event.header.command_kind
        == crucible_shmem::FaultCommandKind::AcceleratorResultTransform
        || (event.header.before_hash == commit.before_hash
            && event.header.after_hash == commit.after_hash);

    event.header.rule_command_sequence == commit.command_sequence
        && event.header.command_kind as u16 == commit.command_kind
        && (action.kind != BindingActionKind::Apply || occurrence_hashes_match)
}

pub(crate) fn validate_node_event_evidence(
    event: &DequeuedFaultEvent,
    action: &ResolvedBindingAction,
) -> Result<(), ProductionFaultRuntimeError> {
    let EffectSpecification::Node(effect) = action.effect.specification() else {
        return Ok(());
    };
    let expected_kind = node_effect_command_kind(effect);
    if event.header.command_kind != expected_kind {
        return Err(BackendError::Rejected {
            message: format!(
                "QEMU fault event {} command kind does not match its issued effect",
                event.header.event_sequence
            ),
        }
        .into());
    }
    let valid = if event.header.outcome == FaultEventOutcomeV1::Error
        && FaultTerminalEvidenceV1::has_magic(&event.payload)
    {
        FaultTerminalEvidenceV1::decode(&event.payload).is_ok()
    } else {
        match event.header.command_kind {
            crucible_shmem::FaultCommandKind::NodeLifecycle => {
                validate_lifecycle_evidence(event, effect)
            }
            crucible_shmem::FaultCommandKind::NodeHang
                if event.payload.get(0..8) == Some(b"CRUCLIF1") =>
            {
                validate_lifecycle_evidence(event, effect)
            }
            crucible_shmem::FaultCommandKind::NodeHang => validate_hang_evidence(event, effect),
            crucible_shmem::FaultCommandKind::CpuService => validate_cpu_service_evidence(event),
            crucible_shmem::FaultCommandKind::CpuVcpuState => validate_vcpu_state_evidence(event),
            crucible_shmem::FaultCommandKind::CpuRegisterTransform => {
                FaultRegisterMutationEvidenceV1::decode(&event.payload).is_ok_and(|evidence| {
                    evidence.model_phase == event.header.model_phase
                        && evidence.observed_icount == event.header.observed_icount
                        && evidence.before_sha256 == event.header.before_hash
                        && evidence.after_sha256 == event.header.after_hash
                })
            }
            crucible_shmem::FaultCommandKind::CpuInstructionTransform => {
                FaultInstructionEvidenceV1::decode(&event.payload).is_ok_and(|evidence| {
                    evidence.observed_icount == event.header.observed_icount
                        && evidence.before_state_sha256 == event.header.before_hash
                        && evidence.after_state_sha256 == event.header.after_hash
                })
            }
            crucible_shmem::FaultCommandKind::CpuException => {
                FaultExceptionEvidenceV1::decode(&event.payload).is_ok_and(|evidence| {
                    evidence.model_phase == event.header.model_phase
                        && evidence.delivered_icount == event.header.observed_icount
                        && evidence.before_sha256 == event.header.before_hash
                        && evidence.after_sha256 == event.header.after_hash
                })
            }
            crucible_shmem::FaultCommandKind::InterruptDisposition
            | crucible_shmem::FaultCommandKind::InterruptStorm => {
                validate_interrupt_evidence(event)
            }
            crucible_shmem::FaultCommandKind::MemoryMutation => {
                MemoryMutationEvidenceV1::decode(&event.payload).is_ok_and(|evidence| {
                    evidence.observed_icount == event.header.observed_icount
                        && evidence.before_sha256 == event.header.before_hash
                        && evidence.after_sha256 == event.header.after_hash
                })
            }
            crucible_shmem::FaultCommandKind::MemoryAccessTransform
            | crucible_shmem::FaultCommandKind::MemoryRegionState => {
                validate_memory_access_evidence(event)
            }
            crucible_shmem::FaultCommandKind::MemoryEccEvent => validate_memory_ecc_evidence(event),
            crucible_shmem::FaultCommandKind::MemoryService => {
                validate_memory_service_evidence(event)
            }
            crucible_shmem::FaultCommandKind::ClockTransform
            | crucible_shmem::FaultCommandKind::ClockSourceState => {
                FaultClockEvidenceV1::decode(&event.payload).is_ok_and(|evidence| {
                    evidence.model_phase == event.header.model_phase
                        && evidence.observed_icount == event.header.observed_icount
                        && evidence.binding_hash == event.header.binding_hash
                        && evidence.before_hash == event.header.before_hash
                        && evidence.after_hash == event.header.after_hash
                })
            }
            crucible_shmem::FaultCommandKind::AcceleratorLifecycle
            | crucible_shmem::FaultCommandKind::AcceleratorResultTransform
            | crucible_shmem::FaultCommandKind::AcceleratorMemoryEvent
            | crucible_shmem::FaultCommandKind::AcceleratorService => {
                validate_accelerator_evidence(event)
            }
            _ => false,
        }
    };
    if valid {
        Ok(())
    } else {
        Err(BackendError::Rejected {
            message: format!(
                "QEMU fault event {} contains malformed or inconsistent typed evidence",
                event.header.event_sequence
            ),
        }
        .into())
    }
}

fn node_effect_command_kind(effect: &NodeEffectSpecification) -> crucible_shmem::FaultCommandKind {
    use crucible_shmem::FaultCommandKind;
    match effect {
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
        NodeEffectSpecification::MemoryMutation { .. } => FaultCommandKind::MemoryMutation,
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
    }
}

fn validate_cpu_service_evidence(event: &DequeuedFaultEvent) -> bool {
    let bytes = event.payload.as_slice();
    if bytes.len() != 192 || bytes.get(..8) != Some(b"CRUCVCS1") {
        return false;
    }
    let before: [u8; 32] = Sha256::digest(&bytes[..64]).into();
    let after: [u8; 32] = Sha256::digest(&bytes[..160]).into();
    read_u64(bytes, 112) == Some(event.header.observed_icount)
        && before == event.header.before_hash
        && after == event.header.after_hash
}

fn validate_vcpu_state_evidence(event: &DequeuedFaultEvent) -> bool {
    let bytes = event.payload.as_slice();
    if bytes.len() != 192
        || bytes.get(..8) != Some(b"CRUCVST1")
        || read_u16(bytes, 8) != Some(1)
        || read_u64(bytes, 24) != Some(event.header.observed_icount)
        || bytes.get(160..192) != Some(event.header.binding_hash.as_slice())
    {
        return false;
    }
    let mut before = bytes.to_vec();
    before[..8].copy_from_slice(b"CRUCVSB1");
    before[20..24].copy_from_slice(&bytes[16..20]);
    let mut after = bytes.to_vec();
    after[..8].copy_from_slice(b"CRUCVSA1");
    after[16..20].copy_from_slice(&bytes[20..24]);
    <[u8; 32]>::from(Sha256::digest(before)) == event.header.before_hash
        && <[u8; 32]>::from(Sha256::digest(after)) == event.header.after_hash
}

fn validate_interrupt_evidence(event: &DequeuedFaultEvent) -> bool {
    let bytes = event.payload.as_slice();
    match bytes.get(..8) {
        Some(b"CRUCIRQ1") => {
            bytes.len() == 160
                && read_u16(bytes, 8) == Some(1)
                && read_u16(bytes, 18) == Some(event.header.model_phase)
                && read_u64(bytes, 80) == Some(event.header.observed_icount)
                && bytes.get(96..128) == Some(event.header.before_hash.as_slice())
                && bytes.get(128..160) == Some(event.header.after_hash.as_slice())
        }
        Some(b"CRUCIER1") => {
            bytes.len() == 64
                && event.header.outcome == FaultEventOutcomeV1::Error
                && read_u64(bytes, 16) == Some(event.header.observed_icount)
        }
        _ => false,
    }
}

fn validate_memory_access_evidence(event: &DequeuedFaultEvent) -> bool {
    let bytes = event.payload.as_slice();
    if bytes.len() < 480
        || bytes.get(..8) != Some(b"CRUCMEM1")
        || read_u64(bytes, 64) != Some(event.header.observed_icount)
        || read_u64(bytes, 72) != Some(event.header.generation)
        || read_u16(bytes, 304) != Some(event.header.command_kind as u16)
        || read_u16(bytes, 306) != Some(event.header.outcome as u16)
        || bytes.get(368..400) != Some(event.header.before_hash.as_slice())
        || bytes.get(400..432) != Some(event.header.after_hash.as_slice())
        || read_u32(bytes, 432) != Some(1)
    {
        return false;
    }
    let Some(inline) = read_u32(bytes, 436).map(u64::from) else {
        return false;
    };
    let Some(mutations) = read_u32(bytes, 440).map(u64::from) else {
        return false;
    };
    let Some(counters) = read_u32(bytes, 448).map(u64::from) else {
        return false;
    };
    if read_u32(bytes, 452) != Some(96) || read_u32(bytes, 456) != Some(64) {
        return false;
    }
    let expected = 480_u64
        .checked_add(inline.saturating_mul(3))
        .and_then(|length| length.checked_add(mutations.checked_mul(96)?))
        .and_then(|length| length.checked_add(counters.checked_mul(64)?));
    expected.and_then(|length| usize::try_from(length).ok()) == Some(bytes.len())
}

fn validate_memory_service_evidence(event: &DequeuedFaultEvent) -> bool {
    let bytes = event.payload.as_slice();
    bytes.len() == 576
        && bytes.get(..8) == Some(b"CRUCMEM1")
        && bytes.get(368..376) == Some(b"CRUCSVC1")
        && read_u32(bytes, 376) == Some(1)
        && read_u64(bytes, 64) == Some(event.header.observed_icount)
        && bytes.get(304..336) == Some(event.header.before_hash.as_slice())
        && bytes.get(336..368) == Some(event.header.after_hash.as_slice())
        && read_u32(bytes, 468) == Some(event.header.outcome as u32)
}

fn validate_memory_ecc_evidence(event: &DequeuedFaultEvent) -> bool {
    let bytes = event.payload.as_slice();
    bytes.len() == 1376
        && bytes.get(..8) == Some(b"CRUCHWE1")
        && read_u16(bytes, 8) == Some(1)
        && read_u64(bytes, 16) == Some(event.header.observed_icount)
        && read_u64(bytes, 40) == Some(event.header.rule_command_sequence)
        && bytes[49..52].iter().all(|byte| *byte == 0)
        && bytes[56..64].iter().all(|byte| *byte == 0)
        && bytes[288..320].iter().all(|byte| *byte == 0)
}

fn validate_accelerator_evidence(event: &DequeuedFaultEvent) -> bool {
    let bytes = event.payload.as_slice();
    if bytes.len() != 256 || event.header.outcome != FaultEventOutcomeV1::Applied {
        return false;
    }
    match (event.header.command_kind, bytes.get(..8)) {
        (crucible_shmem::FaultCommandKind::AcceleratorLifecycle, Some(b"CRUCALE1")) => {
            bytes.get(96..128) == Some(event.header.before_hash.as_slice())
                && bytes.get(128..160) == Some(event.header.after_hash.as_slice())
        }
        (crucible_shmem::FaultCommandKind::AcceleratorMemoryEvent, Some(b"CRUCAMI1")) => {
            bytes.get(72..104) == Some(event.header.before_hash.as_slice())
                && bytes.get(104..136) == Some(event.header.after_hash.as_slice())
        }
        (crucible_shmem::FaultCommandKind::AcceleratorMemoryEvent, Some(b"CRUCAME1")) => {
            bytes.get(104..136) == Some(event.header.before_hash.as_slice())
                && bytes.get(136..168) == Some(event.header.after_hash.as_slice())
        }
        (crucible_shmem::FaultCommandKind::AcceleratorResultTransform, Some(b"CRUCARE1")) => {
            bytes.get(48..80) == Some(event.header.before_hash.as_slice())
                && bytes.get(80..112) == Some(event.header.after_hash.as_slice())
        }
        (crucible_shmem::FaultCommandKind::AcceleratorService, Some(b"CRUCASE1")) => {
            <[u8; 32]>::from(Sha256::digest(&bytes[..88])) == event.header.before_hash
                && <[u8; 32]>::from(Sha256::digest(&bytes[..168])) == event.header.after_hash
        }
        _ => false,
    }
}
