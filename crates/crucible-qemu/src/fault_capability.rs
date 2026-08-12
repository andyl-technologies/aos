//! Launch-bound QEMU fault capability requirements.
//!
//! A requirement is the exact, canonically ordered manifest a QEMU process
//! must advertise before the boot barrier is released. Its digest is part of
//! launch identity and is reused unchanged for admission and replay.

use crucible::model::{
    FaultObjectId, FaultPhase, WorldNodeArchitecture, WorldNodeClockBaseDomain,
    WorldNodeClockMonotonicity, WorldNodeClockSourceKind, WorldNodeClockTimerRelationship,
    WorldNodeFaultCapabilities, WorldNodeHardwareErrorClass, WorldNodeHardwareErrorMechanism,
    WorldNodeHardwareErrorRecordKind, WorldNodeHardwareErrorVisibility,
    WorldNodeInterruptDeliveryDrop, WorldNodeInterruptFamily, WorldNodeInterruptPolarity,
    WorldNodeInterruptTrigger, WorldNodeRegisterGroup, WorldNodeRegisterSideEffect,
};
use crucible_shmem::{
    DEFAULT_FAULT_COMMAND_CAPACITY, FAULT_CAPABILITY_FEATURE_GUEST_CLOCK,
    FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR, FAULT_CAPABILITY_FEATURE_INSTRUCTION,
    FAULT_CAPABILITY_FEATURE_INTERRUPT, FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS,
    FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION, FAULT_CAPABILITY_FEATURE_NODE_LIFECYCLE,
    FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION, FAULT_CAPABILITY_FEATURE_VCPU_SERVICE,
    FAULT_COMMAND_SEMANTIC_VERSION, FAULT_HARDWARE_ERROR_VISIBILITY_EXCEPTION,
    FAULT_HARDWARE_ERROR_VISIBILITY_INTERRUPT, FAULT_HARDWARE_ERROR_VISIBILITY_TELEMETRY,
    FAULT_REGISTER_CAPABILITY_IMPULSE, FAULT_REGISTER_CAPABILITY_PERSISTENT,
    FAULT_REGISTER_CAPABILITY_VMSTATE, FAULT_REGISTER_SIDE_EFFECT_CONTROL_FLOW,
    FAULT_REGISTER_SIDE_EFFECT_CPU_FLAGS, FAULT_REGISTER_SIDE_EFFECT_INTERRUPT,
    FAULT_REGISTER_SIDE_EFFECT_TB_FLUSH, FAULT_REGISTER_SIDE_EFFECT_TIMER,
    FAULT_REGISTER_SIDE_EFFECT_TLB_FLUSH, FAULT_TARGET_MANIFEST_QUERY_V1_BYTES, FaultAbiError,
    FaultAcceleratorCapabilityManifestV1, FaultBoundaryPhase, FaultCapabilityRowV1,
    FaultCapabilityScope, FaultClockCapabilityManifestV1, FaultClockCapabilityRowV1,
    FaultCommandKind, FaultHardwareErrorCapabilityManifestV1, FaultHardwareErrorCapabilityRowV1,
    FaultHardwareErrorClassV1, FaultHardwareErrorMechanismV1, FaultHardwareErrorRecordKindV1,
    FaultInterruptCapabilityManifestV1, FaultInterruptCapabilityRowV1,
    FaultInterruptDeliveryDropV1, FaultInterruptFamilyV1, FaultInterruptPolarityV1,
    FaultInterruptTriggerV1, FaultRegisterCapabilityManifestV1, FaultRegisterCapabilityRowV1,
    FaultRegisterGroupV1, HARD_FAULT_PAYLOAD_BYTES, fault_capability_manifest_digest,
};

use crate::LivePluginGuestArchitecture;

const NODE_FAULT_PAYLOAD_SCHEMA: &[u8] =
    b"crucible.node-fault-payload.v1;page-table-walk=x86_64,aarch64";
const INSTRUCTION_FAULT_PAYLOAD_SCHEMA: &[u8] = b"crucible.node-fault-payload.v1;instruction-classes=x86.integer(89,8b,01,03,29,2b,31,33,39,3b,85,b8-bf,c7,ff/0-1),x86.control-flow(70-7f,80-8f,e8,e9,eb,c2,c3,ca,cb,cf,ff/2-5),x86.load(8b,03,2b,33,0fb6-0fb7,0fbe-0fbf,ff/6,sse-load),x86.store(89,01,29,31,c7,ff/0-1,sse-store),x86.atomic(86,87,0fb0-0fb1,0fc0-0fc1),x86.fp-simd(0f10-11,0f28-29,0f58-59,0f5c,0f5e,66-or-f3-0f6f-7f),x86.exception(cc,cd,ce,f1,0f0b),x86.device-io(e4-e7,ec-ef),aarch64.integer(data-processing),aarch64.control-flow(branch),aarch64.load-store,aarch64.atomic,aarch64.fp-simd,aarch64.exception;replay-max=256";
const EXCEPTION_FAULT_PAYLOAD_SCHEMA: &[u8] = b"crucible.node-fault-payload.v1;exception-records=architecture-default;hardware-error-classes=manifest-v1";
const MEMORY_ECC_FAULT_PAYLOAD_SCHEMA: &[u8] =
    b"crucible.node-fault-payload.v1;hardware-error-manifest=v1";

/// Exact QEMU fault capability manifest required before guest execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuFaultCapabilityRequirement {
    rows: Vec<FaultCapabilityRowV1>,
    digest: [u8; 32],
    target_manifest: Option<QemuTargetManifestRequirement>,
    ready_markers: std::collections::BTreeSet<FaultObjectId>,
    world_bound: bool,
}

/// Launch identity that an immutable QEMU target manifest must describe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuTargetManifestRequirement {
    architecture: FaultCapabilityScope,
    cpu_model: String,
    node_hash: [u8; 32],
    exact_register_manifest: Option<FaultRegisterCapabilityManifestV1>,
    exact_interrupt_manifest: Option<FaultInterruptCapabilityManifestV1>,
    exact_hardware_error_manifest: Option<FaultHardwareErrorCapabilityManifestV1>,
    exact_clock_manifest: Option<FaultClockCapabilityManifestV1>,
    exact_accelerator_manifest: Option<FaultAcceleratorCapabilityManifestV1>,
}

impl QemuTargetManifestRequirement {
    /// Returns the architecture scope expected from QEMU.
    #[must_use]
    pub const fn architecture(&self) -> FaultCapabilityScope {
        self.architecture
    }

    /// Returns the exact realized CPU-model identity expected from QEMU.
    #[must_use]
    pub fn cpu_model(&self) -> &str {
        &self.cpu_model
    }

    /// Returns the exact scenario-node identity authenticated by QEMU.
    #[must_use]
    pub const fn node_hash(&self) -> [u8; 32] {
        self.node_hash
    }

    /// Returns the exact canonical register manifest admitted by the World.
    #[must_use]
    pub const fn exact_register_manifest(&self) -> Option<&FaultRegisterCapabilityManifestV1> {
        self.exact_register_manifest.as_ref()
    }

    /// Returns the exact canonical interrupt manifest admitted by the World.
    #[must_use]
    pub const fn exact_interrupt_manifest(&self) -> Option<&FaultInterruptCapabilityManifestV1> {
        self.exact_interrupt_manifest.as_ref()
    }

    /// Returns the exact canonical hardware-error manifest admitted by the World.
    #[must_use]
    pub const fn exact_hardware_error_manifest(
        &self,
    ) -> Option<&FaultHardwareErrorCapabilityManifestV1> {
        self.exact_hardware_error_manifest.as_ref()
    }

    /// Returns the exact canonical guest-clock manifest admitted by the World.
    #[must_use]
    pub const fn exact_clock_manifest(&self) -> Option<&FaultClockCapabilityManifestV1> {
        self.exact_clock_manifest.as_ref()
    }

    /// Returns the exact canonical accelerator manifest admitted by the World.
    #[must_use]
    pub const fn exact_accelerator_manifest(
        &self,
    ) -> Option<&FaultAcceleratorCapabilityManifestV1> {
        self.exact_accelerator_manifest.as_ref()
    }

    /// Returns the canonical QOM typename expected for the realized CPU.
    #[must_use]
    pub fn realized_cpu_type(&self) -> String {
        let configured = self.cpu_model.split(',').next().unwrap_or(&self.cpu_model);
        let suffix = match self.architecture {
            FaultCapabilityScope::X86_64 => "-x86_64-cpu",
            FaultCapabilityScope::Aarch64 => "-arm-cpu",
            _ => "-invalid-cpu",
        };
        if configured.ends_with(suffix) {
            configured.to_owned()
        } else {
            format!("{configured}{suffix}")
        }
    }
}

impl QemuFaultCapabilityRequirement {
    /// Returns the complete capability set used by internal live-backend gates.
    #[must_use]
    pub(crate) fn current_v1(
        architecture: LivePluginGuestArchitecture,
        cpu_model: impl Into<String>,
        node_hash: [u8; 32],
    ) -> Self {
        let mut rows = Self::abi_boundary_v1().rows;
        let (scope, name, register_name): (FaultCapabilityScope, &[u8], &[u8]) = match architecture
        {
            LivePluginGuestArchitecture::X86_64 => (
                FaultCapabilityScope::X86_64,
                b"qemu.memory.mutate.x86_64.v1",
                b"qemu.register.mutate.x86_64.v1",
            ),
            LivePluginGuestArchitecture::Aarch64 => (
                FaultCapabilityScope::Aarch64,
                b"qemu.memory.mutate.aarch64.v1",
                b"qemu.register.mutate.aarch64.v1",
            ),
        };
        rows.push(capability_row(
            FaultCommandKind::QueryTargetManifest,
            scope,
            b"qemu.target-manifest.node.v1",
            b"crucible.target-manifest-query.v1;kinds=register,interrupt,hardware-error,clock,accelerator",
            FAULT_TARGET_MANIFEST_QUERY_V1_BYTES as u32,
            1,
            FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION | FAULT_CAPABILITY_FEATURE_GUEST_CLOCK,
        ));
        rows.extend([
            capability_row(
                FaultCommandKind::NodeLifecycle,
                FaultCapabilityScope::All,
                b"qemu.node.lifecycle.v1",
                NODE_FAULT_PAYLOAD_SCHEMA,
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_NODE_LIFECYCLE,
            ),
            capability_row(
                FaultCommandKind::NodeHang,
                FaultCapabilityScope::All,
                b"qemu.node.hang.v1",
                NODE_FAULT_PAYLOAD_SCHEMA,
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_NODE_LIFECYCLE,
            ),
            capability_row(
                FaultCommandKind::CpuService,
                FaultCapabilityScope::All,
                b"qemu.cpu.service.v1",
                NODE_FAULT_PAYLOAD_SCHEMA,
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_VCPU_SERVICE,
            ),
            capability_row(
                FaultCommandKind::CpuVcpuState,
                FaultCapabilityScope::All,
                b"qemu.cpu.vcpu-state.v1",
                NODE_FAULT_PAYLOAD_SCHEMA,
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_VCPU_SERVICE,
            ),
            capability_row(
                FaultCommandKind::CpuInstructionTransform,
                scope,
                b"qemu.cpu.instruction-transform.v1",
                INSTRUCTION_FAULT_PAYLOAD_SCHEMA,
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_INSTRUCTION,
            ),
            capability_row(
                FaultCommandKind::CpuException,
                scope,
                b"qemu.cpu.exception.v1",
                EXCEPTION_FAULT_PAYLOAD_SCHEMA,
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_INSTRUCTION | FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR,
            ),
        ]);
        let instruction_phases = FaultBoundaryPhase::NodeBoundary.bit()
            | FaultBoundaryPhase::BeforeInstruction.bit()
            | FaultBoundaryPhase::AfterInstruction.bit();
        for row in rows.iter_mut().filter(|row| {
            matches!(
                row.command_kind,
                FaultCommandKind::CpuInstructionTransform | FaultCommandKind::CpuException
            )
        }) {
            row.phase_mask = instruction_phases;
        }
        rows.push(capability_row(
            FaultCommandKind::CpuRegisterTransform,
            scope,
            register_name,
            b"crucible.node-fault-payload.v1",
            HARD_FAULT_PAYLOAD_BYTES,
            DEFAULT_FAULT_COMMAND_CAPACITY,
            FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION,
        ));
        let (interrupt_name, storm_name): (&[u8], &[u8]) = match architecture {
            LivePluginGuestArchitecture::X86_64 => (
                b"qemu.interrupt.control.x86_64.v1",
                b"qemu.interrupt.storm.x86_64.v1",
            ),
            LivePluginGuestArchitecture::Aarch64 => (
                b"qemu.interrupt.control.aarch64.v1",
                b"qemu.interrupt.storm.aarch64.v1",
            ),
        };
        rows.extend([
            capability_row(
                FaultCommandKind::InterruptDisposition,
                scope,
                interrupt_name,
                NODE_FAULT_PAYLOAD_SCHEMA,
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_INTERRUPT,
            ),
            capability_row(
                FaultCommandKind::InterruptStorm,
                scope,
                storm_name,
                NODE_FAULT_PAYLOAD_SCHEMA,
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_INTERRUPT,
            ),
        ]);
        rows.extend([
            capability_row(
                FaultCommandKind::ClockTransform,
                FaultCapabilityScope::All,
                b"qemu.clock.transform.v1",
                NODE_FAULT_PAYLOAD_SCHEMA,
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_GUEST_CLOCK,
            ),
            capability_row(
                FaultCommandKind::ClockSourceState,
                FaultCapabilityScope::All,
                b"qemu.clock.source-state.v1",
                NODE_FAULT_PAYLOAD_SCHEMA,
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_GUEST_CLOCK,
            ),
        ]);
        rows.push(capability_row(
            FaultCommandKind::MemoryMutation,
            scope,
            name,
            b"crucible.memory-mutation-batch-payload.v1",
            HARD_FAULT_PAYLOAD_BYTES,
            DEFAULT_FAULT_COMMAND_CAPACITY,
            FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION,
        ));
        rows.extend([
            capability_row(
                FaultCommandKind::MemoryAccessTransform,
                FaultCapabilityScope::All,
                b"qemu.memory.access-transform.v1",
                b"crucible.node-fault-payload.v1;atomic-widths=1,2,4,8,16;page-table-walk=x86_64,aarch64",
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS,
            ),
            capability_row(
                FaultCommandKind::MemoryRegionState,
                FaultCapabilityScope::All,
                b"qemu.memory.region-state.v1",
                b"crucible.node-fault-payload.v1;dram=2c2r16b64;page-table-walk=x86_64,aarch64",
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS,
            ),
            capability_row(
                FaultCommandKind::MemoryService,
                FaultCapabilityScope::All,
                b"qemu.memory.service.v1",
                b"crucible.node-fault-payload.v1;page-table-walk=x86_64,aarch64",
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS,
            ),
        ]);
        rows.sort_by_key(|row| {
            (
                row.command_kind as u16,
                row.semantic_version,
                row.scope as u16,
            )
        });
        let mut manifest_hasher = blake3::Hasher::new();
        manifest_hasher.update(b"crucible.qemu-fault-capabilities.v1\0");
        for row in &rows {
            manifest_hasher.update(&row.encode());
        }
        Self {
            rows,
            digest: *manifest_hasher.finalize().as_bytes(),
            target_manifest: Some(QemuTargetManifestRequirement {
                architecture: scope,
                cpu_model: cpu_model.into(),
                node_hash,
                exact_register_manifest: None,
                exact_interrupt_manifest: None,
                exact_hardware_error_manifest: None,
                exact_clock_manifest: None,
                exact_accelerator_manifest: None,
            }),
            ready_markers: std::collections::BTreeSet::new(),
            world_bound: false,
        }
    }

    /// Builds a manifest-discovery requirement for a loaded-QEMU gate.
    ///
    /// This is crate-private so production callers cannot replace the exact
    /// World manifest with whatever a process happens to advertise.
    #[must_use]
    pub(crate) fn live_gate_v1(
        architecture: LivePluginGuestArchitecture,
        cpu_model: impl Into<String>,
        node_name: &str,
    ) -> Self {
        Self::current_v1(
            architecture,
            cpu_model,
            crate::qemu_fault_target_hash(node_name),
        )
    }

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
                FaultClockCapabilityRowV1 {
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
                }
            })
            .collect::<Vec<_>>();
        clock_rows.sort_by(|left, right| left.id.cmp(&right.id));
        let clock_manifest = FaultClockCapabilityManifestV1 {
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
            let boundary = FaultBoundaryPhase::NodeBoundary.bit();
            let device = FaultBoundaryPhase::Device.bit();
            let mut rows = [
                capability_row(
                    FaultCommandKind::AcceleratorLifecycle,
                    FaultCapabilityScope::Accelerator,
                    b"qemu.accelerator.lifecycle.v1",
                    NODE_FAULT_PAYLOAD_SCHEMA,
                    HARD_FAULT_PAYLOAD_BYTES,
                    DEFAULT_FAULT_COMMAND_CAPACITY,
                    0,
                ),
                capability_row(
                    FaultCommandKind::AcceleratorResultTransform,
                    FaultCapabilityScope::Accelerator,
                    b"qemu.accelerator.result-transform.v1",
                    NODE_FAULT_PAYLOAD_SCHEMA,
                    HARD_FAULT_PAYLOAD_BYTES,
                    DEFAULT_FAULT_COMMAND_CAPACITY,
                    0,
                ),
                capability_row(
                    FaultCommandKind::AcceleratorMemoryEvent,
                    FaultCapabilityScope::Accelerator,
                    b"qemu.accelerator.memory-event.v1",
                    NODE_FAULT_PAYLOAD_SCHEMA,
                    HARD_FAULT_PAYLOAD_BYTES,
                    DEFAULT_FAULT_COMMAND_CAPACITY,
                    0,
                ),
                capability_row(
                    FaultCommandKind::AcceleratorService,
                    FaultCapabilityScope::Accelerator,
                    b"qemu.accelerator.service.v1",
                    NODE_FAULT_PAYLOAD_SCHEMA,
                    HARD_FAULT_PAYLOAD_BYTES,
                    DEFAULT_FAULT_COMMAND_CAPACITY,
                    0,
                ),
            ];
            rows[0].phase_mask = boundary | device;
            rows[1].phase_mask = device;
            rows[2].phase_mask = boundary | device;
            rows[3].phase_mask = boundary | device;
            requirement.rows.extend(rows);
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

    /// Returns the exact 0047-0048 capability set before mutation patches.
    ///
    /// This constructor is retained for the 0047-0048 boundary gate and its
    /// protocol tests. Production launch builders use
    /// [`Self::current_v1_for_node`].
    #[must_use]
    pub(crate) fn abi_boundary_v1() -> Self {
        let row = |command_kind, maximum_pending_commands, name: &[u8], schema: &[u8]| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"crucible.qemu-fault-capability.v1\0");
            hasher.update(name);
            hasher.update(&[0]);
            hasher.update(schema);
            FaultCapabilityRowV1 {
                command_kind,
                semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
                scope: FaultCapabilityScope::All,
                phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
                maximum_payload_bytes: 0,
                maximum_pending_commands,
                required_feature_bits: 0,
                capability_hash: *hasher.finalize().as_bytes(),
            }
        };
        let rows = vec![
            row(
                FaultCommandKind::QueryCapabilities,
                1,
                b"qemu.fault-command-abi.v1",
                b"empty; use capability query API",
            ),
            row(
                FaultCommandKind::BoundaryProbe,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                b"qemu.fault-boundary-probe.v1",
                b"empty",
            ),
        ];
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.qemu-fault-capabilities.v1\0");
        for row in &rows {
            hasher.update(&row.encode());
        }
        Self {
            rows,
            digest: *hasher.finalize().as_bytes(),
            target_manifest: None,
            ready_markers: std::collections::BTreeSet::new(),
            world_bound: false,
        }
    }

    /// Returns the exact required rows.
    #[must_use]
    pub fn rows(&self) -> &[FaultCapabilityRowV1] {
        &self.rows
    }

    /// Returns the canonical manifest digest bound to execution identity.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Returns the launch identity required from target-manifest queries.
    #[must_use]
    pub const fn target_manifest(&self) -> Option<&QemuTargetManifestRequirement> {
        self.target_manifest.as_ref()
    }

    /// Returns the exact guest event markers admitted for ready-policy completion.
    #[must_use]
    pub const fn ready_markers(&self) -> &std::collections::BTreeSet<FaultObjectId> {
        &self.ready_markers
    }

    /// Returns a digest of the exact ready-marker manifest.
    #[must_use]
    pub fn ready_marker_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.qemu-ready-marker-manifest.v1\0");
        for marker in &self.ready_markers {
            hasher.update(marker.as_str().as_bytes());
            hasher.update(&[0]);
        }
        *hasher.finalize().as_bytes()
    }

    /// Reports whether this requirement came from an admitted World node.
    #[must_use]
    pub(crate) const fn is_world_bound(&self) -> bool {
        self.world_bound
    }

    /// Resolves manifest-bound capability rows for exact launch admission.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] when the manifest is absent or malformed for
    /// a target-aware requirement, or when the resulting rows are not a
    /// canonical capability manifest.
    pub fn rows_for_manifests(
        &self,
        register_manifest: Option<&FaultRegisterCapabilityManifestV1>,
        interrupt_manifest: Option<&FaultInterruptCapabilityManifestV1>,
        hardware_error_manifest: Option<&FaultHardwareErrorCapabilityManifestV1>,
        clock_manifest: Option<&FaultClockCapabilityManifestV1>,
        accelerator_manifest: Option<&FaultAcceleratorCapabilityManifestV1>,
    ) -> Result<Vec<FaultCapabilityRowV1>, FaultAbiError> {
        let Some(required_target) = &self.target_manifest else {
            return Ok(self.rows.clone());
        };
        let manifest = register_manifest.ok_or(FaultAbiError::CapabilityInvariant)?;
        if manifest.architecture != required_target.architecture
            || manifest.cpu_model != required_target.realized_cpu_type()
            || required_target
                .exact_register_manifest
                .as_ref()
                .is_some_and(|required| required != manifest)
            || (self.world_bound
                && required_target.exact_interrupt_manifest.as_ref() != interrupt_manifest)
            || (self.world_bound
                && required_target.exact_hardware_error_manifest.as_ref()
                    != hardware_error_manifest)
            || hardware_error_manifest
                .is_some_and(|manifest| manifest.architecture != required_target.architecture)
            || required_target
                .exact_clock_manifest
                .as_ref()
                .is_some_and(|required| Some(required) != clock_manifest)
            || required_target.exact_accelerator_manifest.as_ref() != accelerator_manifest
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let payload = manifest.encode()?;
        let manifest_digest = *blake3::hash(&payload).as_bytes();
        let mut rows = self.rows.clone();
        if hardware_error_manifest.is_some_and(|manifest| {
            manifest
                .rows
                .iter()
                .any(|row| row.record_kind == FaultHardwareErrorRecordKindV1::MemoryEcc)
        }) {
            let mut row = capability_row(
                FaultCommandKind::MemoryEccEvent,
                manifest.architecture,
                b"qemu.memory.ecc-event.v1",
                MEMORY_ECC_FAULT_PAYLOAD_SCHEMA,
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR,
            );
            row.phase_mask = FaultBoundaryPhase::NodeBoundary.bit()
                | FaultBoundaryPhase::BeforeMemoryAccess.bit()
                | FaultBoundaryPhase::AfterMemoryAccess.bit();
            rows.push(row);
        }
        let register = rows
            .iter_mut()
            .find(|row| row.command_kind == FaultCommandKind::CpuRegisterTransform)
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        register.scope = manifest.architecture;
        register.capability_hash = register_capability_hash(manifest.architecture, manifest_digest);
        let query = rows
            .iter_mut()
            .find(|row| row.command_kind == FaultCommandKind::QueryTargetManifest)
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        query.scope = manifest.architecture;
        query.required_feature_bits = FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION
            | interrupt_manifest.map_or(0, |_manifest| FAULT_CAPABILITY_FEATURE_INTERRUPT)
            | hardware_error_manifest
                .map_or(0, |_manifest| FAULT_CAPABILITY_FEATURE_HARDWARE_ERROR)
            | clock_manifest.map_or(0, |_manifest| FAULT_CAPABILITY_FEATURE_GUEST_CLOCK);
        let interrupt_digest = interrupt_manifest
            .map(FaultInterruptCapabilityManifestV1::encode)
            .transpose()?
            .map(|payload| *blake3::hash(&payload).as_bytes());
        let clock_digest = clock_manifest
            .map(FaultClockCapabilityManifestV1::encode)
            .transpose()?
            .map(|payload| *blake3::hash(&payload).as_bytes());
        let hardware_error_digest = hardware_error_manifest
            .map(FaultHardwareErrorCapabilityManifestV1::encode)
            .transpose()?
            .map(|payload| *blake3::hash(&payload).as_bytes());
        let accelerator_digest = accelerator_manifest
            .map(FaultAcceleratorCapabilityManifestV1::encode)
            .transpose()?
            .map(|payload| *blake3::hash(&payload).as_bytes());
        query.capability_hash = target_manifest_capability_hash(
            manifest_digest,
            interrupt_digest,
            hardware_error_digest,
            clock_digest,
            accelerator_digest,
        );
        rows.sort_by_key(|row| {
            (
                row.command_kind as u16,
                row.semantic_version,
                row.scope as u16,
            )
        });
        fault_capability_manifest_digest(&rows)?;
        Ok(rows)
    }
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, FaultAbiError> {
    if !value.len().is_multiple_of(2) {
        return Err(FaultAbiError::CapabilityInvariant);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(FaultAbiError::CapabilityInvariant)?;
            let low = hex_nibble(pair[1]).ok_or(FaultAbiError::CapabilityInvariant)?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn target_manifest_capability_hash(
    register_manifest_digest: [u8; 32],
    interrupt_manifest_digest: Option<[u8; 32]>,
    hardware_error_manifest_digest: Option<[u8; 32]>,
    clock_manifest_digest: Option<[u8; 32]>,
    accelerator_manifest_digest: Option<[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.qemu-fault-capability.v1\0");
    hasher.update(b"qemu.target-manifest.node.v1\0");
    hasher.update(
        b"crucible.target-manifest-query.v1;kinds=register,interrupt,hardware-error,clock,accelerator\0",
    );
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
    *hasher.finalize().as_bytes()
}

fn register_capability_hash(
    architecture: FaultCapabilityScope,
    manifest_digest: [u8; 32],
) -> [u8; 32] {
    let name = match architecture {
        FaultCapabilityScope::X86_64 => b"qemu.register.mutate.x86_64.v1".as_slice(),
        FaultCapabilityScope::Aarch64 => b"qemu.register.mutate.aarch64.v1".as_slice(),
        _ => b"qemu.register.mutate.invalid.v1".as_slice(),
    };
    capability_hash_with_manifest(name, b"crucible.node-fault-payload.v1", manifest_digest)
}

fn capability_hash_with_manifest(
    name: &[u8],
    schema: &[u8],
    manifest_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.qemu-fault-capability.v1\0");
    hasher.update(name);
    hasher.update(&[0]);
    hasher.update(schema);
    hasher.update(&[0]);
    hasher.update(&manifest_digest);
    *hasher.finalize().as_bytes()
}

fn capability_row(
    command_kind: FaultCommandKind,
    scope: FaultCapabilityScope,
    name: &[u8],
    schema: &[u8],
    maximum_payload_bytes: u32,
    maximum_pending_commands: u32,
    required_feature_bits: u64,
) -> FaultCapabilityRowV1 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"crucible.qemu-fault-capability.v1\0");
    hasher.update(name);
    hasher.update(&[0]);
    hasher.update(schema);
    FaultCapabilityRowV1 {
        command_kind,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        scope,
        phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
        maximum_payload_bytes,
        maximum_pending_commands,
        required_feature_bits,
        capability_hash: *hasher.finalize().as_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible::model::{
        ContentHash, SignalId, WorldNodeClockSource, WorldNodeDramGeometry, WorldNodeRegister,
    };

    fn world_node_for_manifest(
        manifest: &FaultRegisterCapabilityManifestV1,
    ) -> WorldNodeFaultCapabilities {
        let encoded = manifest
            .encode()
            .unwrap_or_else(|error| panic!("test manifest should encode: {error}"));
        let id = |value: &str| {
            SignalId::parse(value)
                .unwrap_or_else(|error| panic!("test signal ID should be canonical: {error}"))
        };
        WorldNodeFaultCapabilities {
            id: id("node-capabilities"),
            node: id("vm-a"),
            architecture: WorldNodeArchitecture::X86_64,
            cpu_model: manifest.cpu_model.clone(),
            register_schema: ContentHash::from_bytes(&encoded),
            registers: vec![WorldNodeRegister {
                id: id("rax"),
                name: "rax".to_owned(),
                numeric_id: 1,
                group: WorldNodeRegisterGroup::GeneralPurpose,
                width_bits: 8,
                per_vcpu: true,
                model_phases: vec![FaultPhase::BeforeInstruction],
                side_effects: Vec::new(),
                impulse: true,
                persistent: false,
                vmstate: true,
                writable_mask_hex: "0f".to_owned(),
                reserved_mask_hex: "30".to_owned(),
                ignored_mask_hex: "40".to_owned(),
                read_only_mask_hex: "80".to_owned(),
            }],
            address_spaces: Vec::new(),
            page_bytes: 4096,
            dram_geometry: WorldNodeDramGeometry::qemu_v1(),
            interrupts: Vec::new(),
            hardware_errors: Vec::new(),
            clock_sources: vec![WorldNodeClockSource::qemu_x86_tsc_v1(id("x86-tsc-vcpu-0"))],
            accelerators: Vec::new(),
            ready_markers: Vec::new(),
            semantic_version: 1,
        }
    }

    #[test]
    fn current_manifest_is_exact_for_each_architecture() {
        for (architecture, scope) in [
            (
                LivePluginGuestArchitecture::X86_64,
                FaultCapabilityScope::X86_64,
            ),
            (
                LivePluginGuestArchitecture::Aarch64,
                FaultCapabilityScope::Aarch64,
            ),
        ] {
            let requirement = QemuFaultCapabilityRequirement::current_v1(
                architecture,
                "crucible-cpu-v1",
                [1; 32],
            );
            let row = |kind| {
                requirement
                    .rows()
                    .iter()
                    .find(|row| row.command_kind == kind)
                    .unwrap_or_else(|| panic!("current manifest should contain {kind:?}"))
            };
            let register = row(FaultCommandKind::CpuRegisterTransform);
            let mutation = row(FaultCommandKind::MemoryMutation);

            assert_eq!(requirement.rows().len(), 18);
            let target_manifest = row(FaultCommandKind::QueryTargetManifest);
            assert_eq!(target_manifest.scope, scope);
            assert_eq!(
                register.command_kind,
                FaultCommandKind::CpuRegisterTransform
            );
            assert_eq!(register.scope, scope);
            assert_eq!(
                register.required_feature_bits,
                FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION
            );
            assert_eq!(mutation.command_kind, FaultCommandKind::MemoryMutation);
            assert_eq!(
                row(FaultCommandKind::ClockTransform).required_feature_bits,
                FAULT_CAPABILITY_FEATURE_GUEST_CLOCK
            );
            assert_eq!(
                row(FaultCommandKind::ClockSourceState).required_feature_bits,
                FAULT_CAPABILITY_FEATURE_GUEST_CLOCK
            );
            assert_eq!(mutation.scope, scope);
            assert_eq!(
                mutation.required_feature_bits,
                FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION
            );
            assert_eq!(
                requirement
                    .rows()
                    .iter()
                    .filter(|row| {
                        matches!(
                            row.command_kind,
                            FaultCommandKind::InterruptDisposition
                                | FaultCommandKind::InterruptStorm
                        )
                    })
                    .map(|row| row.command_kind)
                    .collect::<Vec<_>>(),
                [
                    FaultCommandKind::InterruptDisposition,
                    FaultCommandKind::InterruptStorm,
                ]
            );
            assert!(
                requirement
                    .rows()
                    .iter()
                    .filter(|row| {
                        matches!(
                            row.command_kind,
                            FaultCommandKind::InterruptDisposition
                                | FaultCommandKind::InterruptStorm
                        )
                    })
                    .all(|row| row.required_feature_bits == FAULT_CAPABILITY_FEATURE_INTERRUPT)
            );
            assert_eq!(
                requirement
                    .rows()
                    .iter()
                    .filter(|row| {
                        matches!(
                            row.command_kind,
                            FaultCommandKind::MemoryAccessTransform
                                | FaultCommandKind::MemoryRegionState
                                | FaultCommandKind::MemoryService
                        )
                    })
                    .map(|row| row.command_kind)
                    .collect::<Vec<_>>(),
                [
                    FaultCommandKind::MemoryAccessTransform,
                    FaultCommandKind::MemoryRegionState,
                    FaultCommandKind::MemoryService,
                ]
            );
            assert!(
                requirement
                    .rows()
                    .iter()
                    .filter(|row| matches!(
                        row.command_kind,
                        FaultCommandKind::MemoryAccessTransform
                            | FaultCommandKind::MemoryRegionState
                            | FaultCommandKind::MemoryService
                    ))
                    .all(|row| row.required_feature_bits == FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS)
            );
            let digest = match fault_capability_manifest_digest(requirement.rows()) {
                Ok(digest) => digest,
                Err(error) => panic!("current capability manifest must be valid: {error}"),
            };
            assert_eq!(digest, requirement.digest());
        }
    }

    #[test]
    fn architecture_changes_the_required_manifest() {
        let x86 = QemuFaultCapabilityRequirement::current_v1(
            LivePluginGuestArchitecture::X86_64,
            "crucible-x86-64-v1",
            [1; 32],
        );
        let arm = QemuFaultCapabilityRequirement::current_v1(
            LivePluginGuestArchitecture::Aarch64,
            "crucible-aarch64-v1",
            [1; 32],
        );

        assert_ne!(
            x86.rows()
                .iter()
                .find(|row| row.command_kind == FaultCommandKind::CpuRegisterTransform),
            arm.rows()
                .iter()
                .find(|row| row.command_kind == FaultCommandKind::CpuRegisterTransform)
        );
        assert_ne!(x86.digest(), arm.digest());
    }

    #[test]
    fn world_node_binds_the_exact_register_manifest_into_launch_identity() {
        let manifest = FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            cpu_model: "crucible-x86-64-v1-x86_64-cpu".to_owned(),
            rows: vec![FaultRegisterCapabilityRowV1 {
                numeric_id: 1,
                name: "rax".to_owned(),
                width_bits: 8,
                group: FaultRegisterGroupV1::GeneralPurpose,
                model_phase_mask: 1 << (11 - 1),
                side_effects: 0,
                capabilities: FAULT_REGISTER_CAPABILITY_IMPULSE | FAULT_REGISTER_CAPABILITY_VMSTATE,
                writable_mask: vec![0x0f],
                reserved_mask: vec![0x30],
                ignored_mask: vec![0x40],
                read_only_mask: vec![0x80],
            }],
        };
        let mut node = world_node_for_manifest(&manifest);
        let baseline = QemuFaultCapabilityRequirement::current_v1_for_node(&node)
            .unwrap_or_else(|error| panic!("baseline World manifest should bind: {error}"));
        node.ready_markers.push(
            SignalId::parse("guest-ready")
                .unwrap_or_else(|error| panic!("test marker should be canonical: {error}")),
        );
        let requirement = QemuFaultCapabilityRequirement::current_v1_for_node(&node)
            .unwrap_or_else(|error| panic!("world manifest should bind: {error}"));

        assert!(requirement.is_world_bound());
        assert_eq!(
            requirement
                .target_manifest()
                .map(QemuTargetManifestRequirement::node_hash),
            Some(crate::qemu_fault_target_hash("vm-a"))
        );
        assert_eq!(
            requirement
                .target_manifest()
                .and_then(QemuTargetManifestRequirement::exact_register_manifest),
            Some(&manifest)
        );
        let clock_manifest = requirement
            .target_manifest()
            .and_then(QemuTargetManifestRequirement::exact_clock_manifest)
            .cloned()
            .unwrap_or_else(|| panic!("World requirement should retain its clock manifest"));
        let hardware_error_manifest = requirement
            .target_manifest()
            .and_then(QemuTargetManifestRequirement::exact_hardware_error_manifest)
            .cloned()
            .unwrap_or_else(|| {
                panic!("World requirement should retain its hardware-error manifest")
            });
        assert!(
            requirement
                .rows_for_manifests(
                    Some(&manifest),
                    None,
                    Some(&hardware_error_manifest),
                    Some(&clock_manifest),
                    None,
                )
                .is_ok()
        );
        assert!(requirement.ready_markers().contains(
            &FaultObjectId::parse("guest-ready").unwrap_or_else(|error| {
                panic!("test ready marker should be canonical: {error}")
            })
        ));
        assert_ne!(
            requirement.ready_marker_digest(),
            baseline.ready_marker_digest()
        );
        let mut changed = manifest.clone();
        changed.rows[0].name = "rbx".to_owned();
        assert_eq!(
            requirement.rows_for_manifests(
                Some(&changed),
                None,
                Some(&hardware_error_manifest),
                Some(&clock_manifest),
                None,
            ),
            Err(FaultAbiError::CapabilityInvariant)
        );
    }

    #[test]
    fn world_node_rejects_a_register_schema_digest_mismatch() {
        let manifest = FaultRegisterCapabilityManifestV1 {
            architecture: FaultCapabilityScope::X86_64,
            cpu_model: "crucible-x86-64-v1-x86_64-cpu".to_owned(),
            rows: vec![FaultRegisterCapabilityRowV1 {
                numeric_id: 1,
                name: "rax".to_owned(),
                width_bits: 8,
                group: FaultRegisterGroupV1::GeneralPurpose,
                model_phase_mask: 1 << (11 - 1),
                side_effects: 0,
                capabilities: FAULT_REGISTER_CAPABILITY_IMPULSE | FAULT_REGISTER_CAPABILITY_VMSTATE,
                writable_mask: vec![0x0f],
                reserved_mask: vec![0x30],
                ignored_mask: vec![0x40],
                read_only_mask: vec![0x80],
            }],
        };
        let mut node = world_node_for_manifest(&manifest);
        node.register_schema = ContentHash::default();
        assert!(matches!(
            QemuFaultCapabilityRequirement::current_v1_for_node(&node),
            Err(FaultAbiError::CapabilityInvariant)
        ));
    }
}
