//! Launch-bound QEMU fault capability requirements.
//!
//! A requirement is the exact, canonically ordered manifest a QEMU process
//! must advertise before the boot barrier is released. Its digest is part of
//! launch identity and is reused unchanged for admission and replay.

use crucible::model::{
    FaultPhase, WorldNodeArchitecture, WorldNodeFaultCapabilities, WorldNodeRegisterGroup,
    WorldNodeRegisterSideEffect,
};
use crucible_shmem::{
    DEFAULT_FAULT_COMMAND_CAPACITY, FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS,
    FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION, FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION,
    FAULT_COMMAND_SEMANTIC_VERSION, FAULT_REGISTER_CAPABILITY_IMPULSE,
    FAULT_REGISTER_CAPABILITY_PERSISTENT, FAULT_REGISTER_CAPABILITY_VMSTATE,
    FAULT_REGISTER_SIDE_EFFECT_CONTROL_FLOW, FAULT_REGISTER_SIDE_EFFECT_CPU_FLAGS,
    FAULT_REGISTER_SIDE_EFFECT_INTERRUPT, FAULT_REGISTER_SIDE_EFFECT_TB_FLUSH,
    FAULT_REGISTER_SIDE_EFFECT_TIMER, FAULT_REGISTER_SIDE_EFFECT_TLB_FLUSH,
    FAULT_TARGET_MANIFEST_QUERY_V1_BYTES, FaultAbiError, FaultBoundaryPhase, FaultCapabilityRowV1,
    FaultCapabilityScope, FaultCommandKind, FaultRegisterCapabilityManifestV1,
    FaultRegisterCapabilityRowV1, FaultRegisterGroupV1, HARD_FAULT_PAYLOAD_BYTES,
    fault_capability_manifest_digest,
};

use crate::LivePluginGuestArchitecture;

/// Exact QEMU fault capability manifest required before guest execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuFaultCapabilityRequirement {
    rows: Vec<FaultCapabilityRowV1>,
    digest: [u8; 32],
    target_manifest: Option<QemuTargetManifestRequirement>,
    world_bound: bool,
}

/// Launch identity that an immutable QEMU target manifest must describe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuTargetManifestRequirement {
    architecture: FaultCapabilityScope,
    cpu_model: String,
    node_hash: [u8; 32],
    exact_manifest: Option<FaultRegisterCapabilityManifestV1>,
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
    pub const fn exact_manifest(&self) -> Option<&FaultRegisterCapabilityManifestV1> {
        self.exact_manifest.as_ref()
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
            b"qemu.target-manifest.register.v1",
            b"crucible.target-manifest-query.v1",
            FAULT_TARGET_MANIFEST_QUERY_V1_BYTES as u32,
            1,
            FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION,
        ));
        rows.push(capability_row(
            FaultCommandKind::CpuRegisterTransform,
            scope,
            register_name,
            b"crucible.node-fault-payload.v1",
            HARD_FAULT_PAYLOAD_BYTES,
            DEFAULT_FAULT_COMMAND_CAPACITY,
            FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION,
        ));
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
                exact_manifest: None,
            }),
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
        let mut requirement = Self::current_v1(
            architecture,
            node.cpu_model.clone(),
            crate::qemu_fault_target_hash(node.node.as_str()),
        );
        let target = requirement
            .target_manifest
            .as_mut()
            .ok_or(FaultAbiError::CapabilityInvariant)?;
        target.exact_manifest = Some(manifest.clone());
        requirement.rows = requirement.rows_for_manifest(Some(&manifest))?;
        requirement.digest = fault_capability_manifest_digest(&requirement.rows)?;
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
    pub fn rows_for_manifest(
        &self,
        manifest: Option<&FaultRegisterCapabilityManifestV1>,
    ) -> Result<Vec<FaultCapabilityRowV1>, FaultAbiError> {
        let Some(required_target) = &self.target_manifest else {
            return Ok(self.rows.clone());
        };
        let manifest = manifest.ok_or(FaultAbiError::CapabilityInvariant)?;
        if manifest.architecture != required_target.architecture
            || manifest.cpu_model != required_target.realized_cpu_type()
            || required_target
                .exact_manifest
                .as_ref()
                .is_some_and(|required| required != manifest)
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        let payload = manifest.encode()?;
        let manifest_digest = *blake3::hash(&payload).as_bytes();
        let mut rows = self.rows.clone();
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
        query.capability_hash = target_manifest_capability_hash(manifest_digest);
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
    if value.len() % 2 != 0 {
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

fn target_manifest_capability_hash(manifest_digest: [u8; 32]) -> [u8; 32] {
    capability_hash_with_manifest(
        b"qemu.target-manifest.register.v1",
        b"crucible.target-manifest-query.v1",
        manifest_digest,
    )
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
    use crucible::model::{ContentHash, SignalId, WorldNodeDramGeometry, WorldNodeRegister};

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
            clock_sources: Vec::new(),
            accelerators: Vec::new(),
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
            let register = &requirement.rows()[3];
            let mutation = &requirement.rows()[4];

            assert_eq!(requirement.rows().len(), 8);
            assert_eq!(
                requirement.rows()[2].command_kind,
                FaultCommandKind::QueryTargetManifest
            );
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
            assert_eq!(mutation.scope, scope);
            assert_eq!(
                mutation.required_feature_bits,
                FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION
            );
            assert_eq!(
                requirement.rows()[5..]
                    .iter()
                    .map(|row| row.command_kind)
                    .collect::<Vec<_>>(),
                [
                    FaultCommandKind::MemoryAccessTransform,
                    FaultCommandKind::MemoryRegionState,
                    FaultCommandKind::MemoryService,
                ]
            );
            assert!(requirement.rows()[5..].iter().all(|row| {
                row.required_feature_bits == FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS
            }));
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

        assert_ne!(x86.rows()[4], arm.rows()[4]);
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
        let node = world_node_for_manifest(&manifest);
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
                .and_then(QemuTargetManifestRequirement::exact_manifest),
            Some(&manifest)
        );
        assert!(requirement.rows_for_manifest(Some(&manifest)).is_ok());
        let mut changed = manifest.clone();
        changed.rows[0].name = "rbx".to_owned();
        assert_eq!(
            requirement.rows_for_manifest(Some(&changed)),
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
