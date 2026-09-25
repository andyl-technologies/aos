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
    FaultCapabilityScope, FaultClockCapabilityManifestV2, FaultClockCapabilityRowV2,
    FaultCommandKind, FaultHardwareErrorCapabilityManifestV1, FaultHardwareErrorCapabilityRowV1,
    FaultHardwareErrorClassV1, FaultHardwareErrorMechanismV1, FaultHardwareErrorRecordKindV1,
    FaultInterruptCapabilityManifestV1, FaultInterruptCapabilityRowV1,
    FaultInterruptDeliveryDropV1, FaultInterruptFamilyV1, FaultInterruptPolarityV1,
    FaultInterruptTriggerV1, FaultRegisterCapabilityManifestV1, FaultRegisterCapabilityRowV1,
    FaultRegisterGroupV1, FaultSystemCapabilityManifestV1, HARD_FAULT_PAYLOAD_BYTES,
    fault_capability_manifest_digest,
};

use crate::LivePluginGuestArchitecture;

mod world_node;

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
    exact_system_manifest: Option<FaultSystemCapabilityManifestV1>,
}

/// Exact public target manifests retained from one admitted QEMU process.
///
/// The live conformance gates use this value to require a second process to
/// reproduce the first process's complete public fault surface byte for byte.
/// Production launches continue to derive requirements exclusively from an
/// admitted [`WorldNodeFaultCapabilities`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QemuExactFaultManifests {
    pub(crate) system: FaultSystemCapabilityManifestV1,
    pub(crate) register: FaultRegisterCapabilityManifestV1,
    pub(crate) interrupt: FaultInterruptCapabilityManifestV1,
    pub(crate) hardware_error: FaultHardwareErrorCapabilityManifestV1,
    pub(crate) clock: FaultClockCapabilityManifestV2,
    pub(crate) accelerator: Option<FaultAcceleratorCapabilityManifestV1>,
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
    exact_clock_manifest: Option<FaultClockCapabilityManifestV2>,
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
    pub const fn exact_clock_manifest(&self) -> Option<&FaultClockCapabilityManifestV2> {
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
        let mut register_row = capability_row(
            FaultCommandKind::CpuRegisterTransform,
            scope,
            register_name,
            b"crucible.node-fault-payload.v1",
            HARD_FAULT_PAYLOAD_BYTES,
            DEFAULT_FAULT_COMMAND_CAPACITY,
            FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION,
        );
        register_row.phase_mask = instruction_phases;
        rows.push(register_row);
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
                b"qemu.memory.service.v2",
                b"crucible.node-fault-payload.v1;page-table-walk=x86_64,aarch64;latency-unit=ps",
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
            exact_system_manifest: None,
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
        accelerator: bool,
    ) -> Self {
        let mut requirement = Self::current_v1(
            architecture,
            cpu_model,
            crate::qemu_fault_target_hash(node_name),
        );
        if accelerator {
            let manifest = canonical_accelerator_manifest_v1();
            if let Some(target) = requirement.target_manifest.as_mut() {
                target.exact_accelerator_manifest = Some(manifest);
            }
            requirement.rows.extend(accelerator_capability_rows());
            requirement.rows.sort_by_key(|row| {
                (
                    row.command_kind as u16,
                    row.semantic_version,
                    row.scope as u16,
                )
            });
        }
        requirement
    }

    /// Builds an exact replay requirement for a loaded-QEMU conformance gate.
    ///
    /// Unlike manifest discovery, this requirement admits a process only when
    /// every public target row and derived capability row matches the supplied
    /// manifests exactly. It remains gate-only: production launch construction
    /// requires [`Self::current_v1_for_node`].
    pub(crate) fn exact_live_gate_v1(
        architecture: LivePluginGuestArchitecture,
        cpu_model: impl Into<String>,
        node_name: &str,
        manifests: &QemuExactFaultManifests,
    ) -> Result<Self, FaultAbiError> {
        let mut requirement = Self::current_v1(
            architecture,
            cpu_model,
            crate::qemu_fault_target_hash(node_name),
        );
        let target = requirement
            .target_manifest
            .as_mut()
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        target.exact_register_manifest = Some(manifests.register.clone());
        target.exact_interrupt_manifest = Some(manifests.interrupt.clone());
        target.exact_hardware_error_manifest = Some(manifests.hardware_error.clone());
        target.exact_clock_manifest = Some(manifests.clock.clone());
        target.exact_accelerator_manifest = manifests.accelerator.clone();
        requirement.exact_system_manifest = Some(manifests.system);
        requirement.rows = requirement.rows_for_manifests(
            Some(&manifests.register),
            Some(&manifests.interrupt),
            Some(&manifests.hardware_error),
            Some(&manifests.clock),
            manifests.accelerator.as_ref(),
        )?;
        requirement.digest = fault_capability_manifest_digest(&requirement.rows)?;
        Ok(requirement)
    }

    /// Returns whether this gate requirement binds all mandatory live manifests.
    pub(crate) fn is_exact_live_gate_bound(&self) -> bool {
        let Some(target) = self.target_manifest.as_ref() else {
            return false;
        };
        !self.world_bound
            && self.exact_system_manifest.is_some()
            && target.exact_register_manifest.is_some()
            && target.exact_interrupt_manifest.is_some()
            && target.exact_hardware_error_manifest.is_some()
            && target.exact_clock_manifest.is_some()
    }

    /// Returns the exact immutable system identity required during gate replay.
    pub(crate) const fn exact_system_manifest(&self) -> Option<&FaultSystemCapabilityManifestV1> {
        self.exact_system_manifest.as_ref()
    }

    /// Returns the exact 0047-0048 capability set before fault mutations.
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
            exact_system_manifest: None,
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
        clock_manifest: Option<&FaultClockCapabilityManifestV2>,
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
            || required_target
                .exact_interrupt_manifest
                .as_ref()
                .is_some_and(|required| Some(required) != interrupt_manifest)
            || (self.world_bound
                && required_target.exact_interrupt_manifest.is_none()
                && interrupt_manifest.is_some())
            || required_target
                .exact_hardware_error_manifest
                .as_ref()
                .is_some_and(|required| Some(required) != hardware_error_manifest)
            || (self.world_bound
                && required_target.exact_hardware_error_manifest.is_none()
                && hardware_error_manifest.is_some())
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
        }) && !rows
            .iter()
            .any(|row| row.command_kind == FaultCommandKind::MemoryEccEvent)
        {
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
            .map(FaultClockCapabilityManifestV2::encode)
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
        .as_chunks::<2>()
        .0
        .iter()
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

fn canonical_accelerator_manifest_v1() -> FaultAcceleratorCapabilityManifestV1 {
    FaultAcceleratorCapabilityManifestV1 {
        rows: vec![crucible_shmem::FaultAcceleratorCapabilityRowV1 {
            id: "accelerator-0".to_owned(),
            implementation: "virtio-crucible-accelerator-v1".to_owned(),
            class_mask: 0x7,
            fault_family_mask: 0xf,
            queue_start: 0,
            queue_end: 0,
            queue_depth: 64,
            maximum_input_bytes: 4_608,
            maximum_output_bytes: 4_608,
            device_memory_bytes: 65_536,
            ecc_mode_mask: 0x3,
            job_kind_count: 3,
            vmstate: true,
        }],
    }
}

fn accelerator_capability_rows() -> [FaultCapabilityRowV1; 4] {
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
    rows[1].phase_mask = boundary | device;
    rows[2].phase_mask = boundary | device;
    rows[3].phase_mask = boundary | device;
    rows
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

    fn x86_tsc_clock(id: SignalId) -> WorldNodeClockSource {
        WorldNodeClockSource {
            id,
            implementation: "target/i386/tcg".to_owned(),
            source_kind: WorldNodeClockSourceKind::X86Tsc,
            base_domain: WorldNodeClockBaseDomain::SchedulerVirtual,
            epoch_ns: 0,
            timer_relationship: WorldNodeClockTimerRelationship::None,
            width_bits: 64,
            wraps: true,
            read_error: false,
            frequency_numerator: 1_000_000_000,
            frequency_denominator: 1,
            model_phases: vec![
                FaultPhase::ClockRead,
                FaultPhase::Synchronize,
                FaultPhase::SourceSwitch,
            ],
            monotonicity: WorldNodeClockMonotonicity::ClampMonotonic,
            vmstate: true,
            semantic_version: 2,
        }
    }

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
            dram_geometry: WorldNodeDramGeometry::emulated_v1(),
            interrupts: Vec::new(),
            hardware_errors: Vec::new(),
            clock_sources: vec![x86_tsc_clock(id("x86-tsc-vcpu-0"))],
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
    fn live_gate_accelerator_attachment_is_manifest_bound() {
        let requirement = QemuFaultCapabilityRequirement::live_gate_v1(
            LivePluginGuestArchitecture::X86_64,
            "crucible-x86-64-v1",
            "vm-a",
            true,
        );
        let target = requirement
            .target_manifest()
            .unwrap_or_else(|| panic!("live gate should retain a target manifest"));

        assert_eq!(
            target.exact_accelerator_manifest(),
            Some(&canonical_accelerator_manifest_v1())
        );
        assert_eq!(
            requirement
                .rows()
                .iter()
                .filter(|row| row.scope == FaultCapabilityScope::Accelerator)
                .count(),
            4
        );
    }

    #[test]
    fn live_gate_without_accelerator_forbids_accelerator_capabilities() {
        let requirement = QemuFaultCapabilityRequirement::live_gate_v1(
            LivePluginGuestArchitecture::X86_64,
            "crucible-x86-64-v1",
            "vm-a",
            false,
        );
        let target = requirement
            .target_manifest()
            .unwrap_or_else(|| panic!("live gate should retain a target manifest"));

        assert_eq!(target.exact_accelerator_manifest(), None);
        assert!(
            requirement
                .rows()
                .iter()
                .all(|row| row.scope != FaultCapabilityScope::Accelerator)
        );
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
    fn exact_gate_manifest_resolution_is_idempotent_and_checks_every_manifest() {
        let register = FaultRegisterCapabilityManifestV1 {
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
        let world = world_node_for_manifest(&register);
        let world_requirement = QemuFaultCapabilityRequirement::current_v1_for_node(&world)
            .unwrap_or_else(|error| panic!("World manifest should bind: {error}"));
        let clock = world_requirement
            .target_manifest
            .as_ref()
            .and_then(|target| target.exact_clock_manifest.clone())
            .unwrap_or_else(|| panic!("World requirement should contain its clock manifest"));
        let manifests = QemuExactFaultManifests {
            system: FaultSystemCapabilityManifestV1 {
                semantic_version: 1,
                vmstate_format_version: 2,
                vmstate_section_count: 11,
                vmstate_sections_sha256: [1; 32],
                emulator_build_id: [2; 32],
                emulator_atomic_patch_hash: [3; 32],
                shmem_header_hash: [4; 32],
            },
            register,
            interrupt: FaultInterruptCapabilityManifestV1 {
                architecture: FaultCapabilityScope::X86_64,
                rows: Vec::new(),
            },
            hardware_error: FaultHardwareErrorCapabilityManifestV1 {
                architecture: FaultCapabilityScope::X86_64,
                rows: Vec::new(),
            },
            clock,
            accelerator: None,
        };
        let requirement = QemuFaultCapabilityRequirement::exact_live_gate_v1(
            LivePluginGuestArchitecture::X86_64,
            "crucible-x86-64-v1",
            "vm-a",
            &manifests,
        )
        .unwrap_or_else(|error| panic!("exact gate manifest should bind: {error}"));

        let resolved = requirement
            .rows_for_manifests(
                Some(&manifests.register),
                Some(&manifests.interrupt),
                Some(&manifests.hardware_error),
                Some(&manifests.clock),
                None,
            )
            .unwrap_or_else(|error| panic!("repeated exact resolution should succeed: {error}"));
        assert_eq!(resolved, requirement.rows());

        let wrong_interrupt = FaultInterruptCapabilityManifestV1 {
            architecture: FaultCapabilityScope::Aarch64,
            rows: Vec::new(),
        };
        assert!(
            requirement
                .rows_for_manifests(
                    Some(&manifests.register),
                    Some(&wrong_interrupt),
                    Some(&manifests.hardware_error),
                    Some(&manifests.clock),
                    None,
                )
                .is_err()
        );
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
