//! Launch-bound QEMU fault capability requirements.
//!
//! A requirement is the exact, canonically ordered manifest a QEMU process
//! must advertise before the boot barrier is released. Its digest is part of
//! launch identity and is reused unchanged for admission and replay.

use crucible_shmem::{
    DEFAULT_FAULT_COMMAND_CAPACITY, FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS,
    FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION, FAULT_CAPABILITY_FEATURE_REGISTER_MUTATION,
    FAULT_COMMAND_SEMANTIC_VERSION, FAULT_TARGET_MANIFEST_QUERY_V1_BYTES, FaultAbiError,
    FaultBoundaryPhase, FaultCapabilityRowV1, FaultCapabilityScope, FaultCommandKind,
    FaultRegisterCapabilityManifestV1, HARD_FAULT_PAYLOAD_BYTES, fault_capability_manifest_digest,
};

use crate::LivePluginGuestArchitecture;

/// Exact QEMU fault capability manifest required before guest execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuFaultCapabilityRequirement {
    rows: Vec<FaultCapabilityRowV1>,
    digest: [u8; 32],
    target_manifest: Option<QemuTargetManifestRequirement>,
}

/// Launch identity that an immutable QEMU target manifest must describe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuTargetManifestRequirement {
    architecture: FaultCapabilityScope,
    cpu_model: String,
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
    /// Builds an exact, canonically ordered capability requirement.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] when rows are empty, invalid, duplicated, not
    /// in canonical `(kind, version, scope)` order, or require a target
    /// manifest without launch-bound target identity. Use [`Self::current_v1`]
    /// for the complete production requirement.
    pub fn exact(rows: Vec<FaultCapabilityRowV1>) -> Result<Self, FaultAbiError> {
        let digest = fault_capability_manifest_digest(&rows)?;
        if rows
            .iter()
            .any(|row| row.command_kind == FaultCommandKind::QueryTargetManifest)
        {
            return Err(FaultAbiError::CapabilityInvariant);
        }
        Ok(Self {
            rows,
            digest,
            target_manifest: None,
        })
    }

    /// Returns the complete capability set required by the current patch stack.
    #[must_use]
    pub fn current_v1(
        architecture: LivePluginGuestArchitecture,
        cpu_model: impl Into<String>,
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
            }),
        }
    }

    /// Returns the exact 0047-0048 capability set before mutation patches.
    ///
    /// This constructor is retained for the 0047-0048 boundary gate and its
    /// protocol tests. Production launch builders use [`Self::current_v1`].
    #[must_use]
    pub fn abi_boundary_v1() -> Self {
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
            let requirement =
                QemuFaultCapabilityRequirement::current_v1(architecture, "crucible-cpu-v1");
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
            assert_eq!(register.scope, FaultCapabilityScope::All);
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
        );
        let arm = QemuFaultCapabilityRequirement::current_v1(
            LivePluginGuestArchitecture::Aarch64,
            "crucible-aarch64-v1",
        );

        assert_ne!(x86.rows()[4], arm.rows()[4]);
        assert_ne!(x86.digest(), arm.digest());
    }
}
