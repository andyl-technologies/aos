//! Translation from admitted World-node fault declarations.

use super::*;

impl QemuFaultCapabilityRequirement {
    /// Builds the production requirement from one admitted world-node manifest.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] if the world declaration cannot be represented
    /// by the public target-manifest ABI or its declared schema digest does not
    /// equal the canonical manifest bytes.
    pub fn current_v1_for_node(node: &WorldNodeFaultCapabilities) -> Result<Self, FaultAbiError> {
        let architecture = match node.architecture {
            WorldNodeArchitecture::X86_64 => LivePluginGuestArchitecture::X86_64,
            WorldNodeArchitecture::Aarch64 => LivePluginGuestArchitecture::Aarch64,
        };
        let scope = match node.architecture {
            WorldNodeArchitecture::X86_64 => FaultCapabilityScope::X86_64,
            WorldNodeArchitecture::Aarch64 => FaultCapabilityScope::Aarch64,
        };
        let mut rows = node
            .registers
            .iter()
            .map(|row| {
                let group = match row.group {
                    WorldNodeRegisterGroup::GeneralPurpose => FaultRegisterGroupV1::GeneralPurpose,
                    WorldNodeRegisterGroup::ControlFlow => FaultRegisterGroupV1::ControlFlow,
                    WorldNodeRegisterGroup::Flags => FaultRegisterGroupV1::Flags,
                    WorldNodeRegisterGroup::Segment => FaultRegisterGroupV1::Segment,
                    WorldNodeRegisterGroup::Control => FaultRegisterGroupV1::Control,
                    WorldNodeRegisterGroup::System => FaultRegisterGroupV1::System,
                    WorldNodeRegisterGroup::Debug => FaultRegisterGroupV1::Debug,
                    WorldNodeRegisterGroup::FloatingPoint => FaultRegisterGroupV1::FloatingPoint,
                    WorldNodeRegisterGroup::Vector => FaultRegisterGroupV1::Vector,
                    WorldNodeRegisterGroup::Error => FaultRegisterGroupV1::Error,
                };
                let model_phase_mask = row.model_phases.iter().fold(0_u64, |mask, phase| {
                    let tag = match phase {
                        FaultPhase::BeforeInstruction => 11,
                        FaultPhase::AfterInstruction => 12,
                        _ => 0,
                    };
                    if tag == 0 {
                        mask
                    } else {
                        mask | (1_u64 << (tag - 1))
                    }
                });
                let side_effects = row.side_effects.iter().fold(0_u32, |mask, effect| {
                    mask | match effect {
                        WorldNodeRegisterSideEffect::TlbFlush => {
                            FAULT_REGISTER_SIDE_EFFECT_TLB_FLUSH
                        }
                        WorldNodeRegisterSideEffect::TranslationBlockFlush => {
                            FAULT_REGISTER_SIDE_EFFECT_TB_FLUSH
                        }
                        WorldNodeRegisterSideEffect::FlagsRecompute => {
                            FAULT_REGISTER_SIDE_EFFECT_CPU_FLAGS
                        }
                        WorldNodeRegisterSideEffect::InterruptReevaluate => {
                            FAULT_REGISTER_SIDE_EFFECT_INTERRUPT
                        }
                        WorldNodeRegisterSideEffect::TimerRearm => FAULT_REGISTER_SIDE_EFFECT_TIMER,
                        WorldNodeRegisterSideEffect::ControlFlowSynchronize => {
                            FAULT_REGISTER_SIDE_EFFECT_CONTROL_FLOW
                        }
                    }
                });
                let capabilities = (if row.impulse {
                    FAULT_REGISTER_CAPABILITY_IMPULSE
                } else {
                    0
                }) | (if row.persistent {
                    FAULT_REGISTER_CAPABILITY_PERSISTENT
                } else {
                    0
                }) | (if row.vmstate {
                    FAULT_REGISTER_CAPABILITY_VMSTATE
                } else {
                    0
                });
                Ok(FaultRegisterCapabilityRowV1 {
                    numeric_id: row.numeric_id,
                    name: row.name.clone(),
                    width_bits: row.width_bits,
                    group,
                    model_phase_mask,
                    side_effects,
                    capabilities,
                    writable_mask: decode_lower_hex(&row.writable_mask_hex)?,
                    reserved_mask: decode_lower_hex(&row.reserved_mask_hex)?,
                    ignored_mask: decode_lower_hex(&row.ignored_mask_hex)?,
                    read_only_mask: decode_lower_hex(&row.read_only_mask_hex)?,
                })
            })
            .collect::<Result<Vec<_>, FaultAbiError>>()?;
        rows.sort_by_key(|row| row.numeric_id);
        let manifest = FaultRegisterCapabilityManifestV1 {
            architecture: scope,
            cpu_model: node.cpu_model.clone(),
            rows,
        };
        let encoded = manifest.encode()?;
        if *blake3::hash(&encoded).as_bytes() != node.register_schema.bytes {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let interrupt_manifest = if node.interrupts.is_empty() {
            None
        } else {
            let mut rows = node
                .interrupts
                .iter()
                .map(|row| {
                    let family = match row.family {
                        WorldNodeInterruptFamily::X86LocalApicFixed => {
                            FaultInterruptFamilyV1::X86LocalApicFixed
                        }
                        WorldNodeInterruptFamily::X86Ipi => FaultInterruptFamilyV1::X86Ipi,
                        WorldNodeInterruptFamily::X86IoApic => FaultInterruptFamilyV1::X86IoApic,
                        WorldNodeInterruptFamily::X86Pic => FaultInterruptFamilyV1::X86Pic,
                        WorldNodeInterruptFamily::X86Msi => FaultInterruptFamilyV1::X86Msi,
                        WorldNodeInterruptFamily::X86MsiX => FaultInterruptFamilyV1::X86MsiX,
                        WorldNodeInterruptFamily::X86Nmi => FaultInterruptFamilyV1::X86Nmi,
                        WorldNodeInterruptFamily::X86Timer => FaultInterruptFamilyV1::X86Timer,
                        WorldNodeInterruptFamily::ArmGicSgi => FaultInterruptFamilyV1::ArmGicSgi,
                        WorldNodeInterruptFamily::ArmGicPpi => FaultInterruptFamilyV1::ArmGicPpi,
                        WorldNodeInterruptFamily::ArmGicSpi => FaultInterruptFamilyV1::ArmGicSpi,
                        WorldNodeInterruptFamily::ArmGicLpi => FaultInterruptFamilyV1::ArmGicLpi,
                        WorldNodeInterruptFamily::ArmTimer => FaultInterruptFamilyV1::ArmTimer,
                    };
                    let trigger = match row.trigger {
                        WorldNodeInterruptTrigger::Edge => FaultInterruptTriggerV1::Edge,
                        WorldNodeInterruptTrigger::Level => FaultInterruptTriggerV1::Level,
                    };
                    let polarity = match row.polarity {
                        WorldNodeInterruptPolarity::ActiveHigh => {
                            FaultInterruptPolarityV1::ActiveHigh
                        }
                        WorldNodeInterruptPolarity::ActiveLow => {
                            FaultInterruptPolarityV1::ActiveLow
                        }
                    };
                    let delivery_drop = match row.delivery_drop {
                        WorldNodeInterruptDeliveryDrop::ConsumeEdge => {
                            FaultInterruptDeliveryDropV1::ConsumeEdge
                        }
                        WorldNodeInterruptDeliveryDrop::RependAssertedLevel => {
                            FaultInterruptDeliveryDropV1::RependAssertedLevel
                        }
                    };
                    let model_phase_mask = row.model_phases.iter().fold(0_u64, |mask, phase| {
                        let tag = match phase {
                            FaultPhase::Raise => 23,
                            FaultPhase::Route => 24,
                            FaultPhase::InterruptDeliver => 26,
                            _ => 0,
                        };
                        if tag == 0 {
                            mask
                        } else {
                            mask | (1_u64 << (tag - 1))
                        }
                    });
                    FaultInterruptCapabilityRowV1 {
                        id: row.id.as_str().to_owned(),
                        controller: row.controller.as_str().to_owned(),
                        source: row.source.as_str().to_owned(),
                        controller_version: row.controller_version.clone(),
                        family,
                        vector_start: row.vector_start,
                        vector_end: row.vector_end,
                        replacement_vector_start: row.replacement_vector_start,
                        replacement_vector_end: row.replacement_vector_end,
                        trigger,
                        polarity,
                        target_vcpus: row.target_vcpus.clone(),
                        model_phase_mask,
                        priority: row.priority,
                        delivery_drop,
                        vmstate: row.vmstate,
                    }
                })
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| left.id.cmp(&right.id));
            Some(FaultInterruptCapabilityManifestV1 {
                architecture: scope,
                rows,
            })
        };
        let hardware_error_manifest = {
            let mut rows = node
                .hardware_errors
                .iter()
                .map(|row| {
                    let record_kind = match row.record_kind {
                        WorldNodeHardwareErrorRecordKind::X86MachineCheck => {
                            FaultHardwareErrorRecordKindV1::X86MachineCheck
                        }
                        WorldNodeHardwareErrorRecordKind::Aarch64Ras => {
                            FaultHardwareErrorRecordKindV1::Aarch64Ras
                        }
                        WorldNodeHardwareErrorRecordKind::MemoryEcc => {
                            FaultHardwareErrorRecordKindV1::MemoryEcc
                        }
                    };
                    let error_class = match row.error_class {
                        WorldNodeHardwareErrorClass::Corrected => {
                            FaultHardwareErrorClassV1::Corrected
                        }
                        WorldNodeHardwareErrorClass::Recoverable => {
                            FaultHardwareErrorClassV1::Recoverable
                        }
                        WorldNodeHardwareErrorClass::Fatal => FaultHardwareErrorClassV1::Fatal,
                        WorldNodeHardwareErrorClass::Synchronous => {
                            FaultHardwareErrorClassV1::Synchronous
                        }
                        WorldNodeHardwareErrorClass::Asynchronous => {
                            FaultHardwareErrorClassV1::Asynchronous
                        }
                    };
                    let mechanism = match row.mechanism {
                        WorldNodeHardwareErrorMechanism::X86Mca => {
                            FaultHardwareErrorMechanismV1::X86Mca
                        }
                        WorldNodeHardwareErrorMechanism::AcpiGhes => {
                            FaultHardwareErrorMechanismV1::AcpiGhes
                        }
                        WorldNodeHardwareErrorMechanism::Aarch64Ras => {
                            FaultHardwareErrorMechanismV1::Aarch64Ras
                        }
                    };
                    let visibility_mask = row.visibility.iter().fold(0_u16, |mask, visibility| {
                        mask | match visibility {
                            WorldNodeHardwareErrorVisibility::Telemetry => {
                                FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY
                            }
                            WorldNodeHardwareErrorVisibility::Interrupt => {
                                FAULT_HARDWARE_ERROR_VISIBILITY_INTERRUPT
                            }
                            WorldNodeHardwareErrorVisibility::Exception => {
                                FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION
                            }
                        }
                    });
                    let model_phase_mask = row.model_phases.iter().fold(0_u64, |mask, phase| {
                        let tag = match phase {
                            FaultPhase::Fetch => 9,
                            FaultPhase::BeforeInstruction => 11,
                            FaultPhase::AfterInstruction => 12,
                            FaultPhase::Load => 17,
                            FaultPhase::Store => 18,
                            FaultPhase::DmaRead => 19,
                            FaultPhase::DmaWrite => 20,
                            FaultPhase::PageTableWalk => 21,
                            FaultPhase::Refresh => 22,
                            _ => 0,
                        };
                        if tag == 0 {
                            mask
                        } else {
                            mask | (1_u64 << (tag - 1))
                        }
                    });
                    let privilege_mask = row
                        .privilege_levels
                        .iter()
                        .fold(0_u16, |mask, level| mask | (1_u16 << level));
                    FaultHardwareErrorCapabilityRowV1 {
                        id: row.id.as_str().to_owned(),
                        bank: row.bank.as_str().to_owned(),
                        channel: row.channel.as_str().to_owned(),
                        rank: row.rank.as_str().to_owned(),
                        firmware: row.firmware.as_str().to_owned(),
                        state: row.state.as_str().to_owned(),
                        record_kind,
                        error_class,
                        mechanism,
                        visibility_mask,
                        bank_number: row.bank_number,
                        bank_count: row.bank_count,
                        vector: row.vector,
                        status_required: row.status_required,
                        status_allowed: row.status_allowed,
                        syndrome_required: row.syndrome_required,
                        syndrome_allowed: row.syndrome_allowed,
                        model_phase_mask,
                        privilege_mask,
                        corrected: row.corrected,
                        maskable: row.maskable,
                        vmstate: row.vmstate,
                    }
                })
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| left.id.cmp(&right.id));
            let manifest = FaultHardwareErrorCapabilityManifestV1 {
                architecture: scope,
                rows,
            };
            manifest.encode()?;
            Some(manifest)
        };
        let mut clock_rows = node
            .clock_sources
            .iter()
            .map(|source| {
                let source_kind = match source.source_kind {
                    WorldNodeClockSourceKind::X86Tsc => 1,
                    WorldNodeClockSourceKind::X86Rtc => 2,
                    WorldNodeClockSourceKind::X86Pit => 3,
                    WorldNodeClockSourceKind::X86Hpet => 4,
                    WorldNodeClockSourceKind::X86ApicTimer => 5,
                    WorldNodeClockSourceKind::X86AcpiPmTimer => 6,
                    WorldNodeClockSourceKind::ArmCounter => 7,
                    WorldNodeClockSourceKind::ArmRtc => 8,
                    WorldNodeClockSourceKind::Device => 9,
                };
                let base_domain = match source.base_domain {
                    WorldNodeClockBaseDomain::SchedulerVirtual => 1,
                    WorldNodeClockBaseDomain::RtcEpoch => 2,
                };
                let timer_relationship = match source.timer_relationship {
                    WorldNodeClockTimerRelationship::None => 0,
                    WorldNodeClockTimerRelationship::Programmable => 1,
                };
                let model_phase_mask = source.model_phases.iter().fold(0_u64, |mask, phase| {
                    let tag = match phase {
                        FaultPhase::ClockRead => 28,
                        FaultPhase::Arm => 29,
                        FaultPhase::Fire => 30,
                        FaultPhase::Synchronize => 31,
                        FaultPhase::SourceSwitch => 32,
                        _ => 0,
                    };
                    if tag == 0 {
                        mask
                    } else {
                        mask | (1_u64 << (tag - 1))
                    }
                });
                let monotonicity = match source.monotonicity {
                    WorldNodeClockMonotonicity::AllowBackward => 1,
                    WorldNodeClockMonotonicity::ClampMonotonic => 2,
                    WorldNodeClockMonotonicity::FaultOnBackward => 3,
                };
                FaultClockCapabilityRowV2 {
                    id: source.id.as_str().to_owned(),
                    implementation: source.implementation.clone(),
                    source_kind,
                    base_domain,
                    timer_relationship,
                    width_bits: source.width_bits,
                    flags: u32::from(source.wraps) | (u32::from(source.read_error) << 1),
                    frequency_numerator: source.frequency_numerator,
                    frequency_denominator: source.frequency_denominator,
                    model_phase_mask,
                    vmstate: source.vmstate,
                    monotonicity,
                    epoch_ns: source.epoch_ns,
                }
            })
            .collect::<Vec<_>>();
        clock_rows.sort_by(|left, right| left.id.cmp(&right.id));
        let clock_manifest = FaultClockCapabilityManifestV2 {
            architecture: scope,
            rows: clock_rows,
        };
        clock_manifest.encode()?;
        let accelerator_manifest = if node.accelerators.is_empty() {
            None
        } else {
            let rows = node
                .accelerators
                .iter()
                .map(|device| {
                    let class_mask = device.classes.iter().fold(0_u16, |mask, class| {
                        mask | match class {
                            crucible::model::WorldNodeAcceleratorKind::Gpu => 1,
                            crucible::model::WorldNodeAcceleratorKind::Tpu => 2,
                            crucible::model::WorldNodeAcceleratorKind::Fpga => 4,
                        }
                    });
                    crucible_shmem::FaultAcceleratorCapabilityRowV1 {
                        id: device.id.as_str().to_owned(),
                        implementation: "virtio-crucible-accelerator-v1".to_owned(),
                        class_mask,
                        fault_family_mask: 0xf,
                        queue_start: 0,
                        queue_end: 0,
                        queue_depth: 64,
                        maximum_input_bytes: 4_608,
                        maximum_output_bytes: 4_608,
                        device_memory_bytes: 65_536,
                        ecc_mode_mask: 0x3,
                        job_kind_count: u32::from(class_mask.count_ones() as u16),
                        vmstate: true,
                    }
                })
                .collect();
            let manifest = FaultAcceleratorCapabilityManifestV1 { rows };
            let encoded = manifest.encode()?;
            if node.accelerators.len() != 1
                || *blake3::hash(&encoded).as_bytes()
                    != node.accelerators[0].capability_manifest.bytes
            {
                return Err(FaultAbiError::CapabilityInvariant);
            }
            Some(manifest)
        };
        let mut requirement = Self::current_v1(
            architecture,
            node.cpu_model.clone(),
            crate::qemu_fault_target_hash(node.node.as_str()),
        );
        let target = requirement
            .target_manifest
            .as_mut()
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        target.exact_register_manifest = Some(manifest.clone());
        target.exact_interrupt_manifest = interrupt_manifest.clone();
        target.exact_hardware_error_manifest = hardware_error_manifest.clone();
        target.exact_clock_manifest = Some(clock_manifest.clone());
        target.exact_accelerator_manifest = accelerator_manifest.clone();
        if accelerator_manifest.is_some() {
            requirement.rows.extend(accelerator_capability_rows());
        }
        requirement.rows = requirement.rows_for_manifests(
            Some(&manifest),
            interrupt_manifest.as_ref(),
            hardware_error_manifest.as_ref(),
            Some(&clock_manifest),
            accelerator_manifest.as_ref(),
        )?;
        requirement.digest = fault_capability_manifest_digest(&requirement.rows)?;
        requirement.ready_markers = node
            .ready_markers
            .iter()
            .map(|marker| FaultObjectId::parse(marker.as_str()))
            .collect::<Result<_, _>>()
            .map_err(|_error| FaultAbiError::CapabilityInvariant)?;
        requirement.world_bound = true;
        Ok(requirement)
    }
}
