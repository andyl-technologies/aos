//! Launch-bound QEMU fault capability requirements.
//!
//! A requirement is the exact, canonically ordered manifest a QEMU process
//! must advertise before the boot barrier is released. Its digest is part of
//! launch identity and is reused unchanged for admission and replay.

use crucible_shmem::{
    DEFAULT_FAULT_COMMAND_CAPACITY, FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS,
    FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION, FAULT_COMMAND_SEMANTIC_VERSION, FaultAbiError,
    FaultBoundaryPhase, FaultCapabilityRowV1, FaultCapabilityScope, FaultCommandKind,
    HARD_FAULT_PAYLOAD_BYTES, fault_capability_manifest_digest,
};

use crate::LivePluginGuestArchitecture;

/// Exact QEMU fault capability manifest required before guest execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuFaultCapabilityRequirement {
    rows: Vec<FaultCapabilityRowV1>,
    digest: [u8; 32],
}

impl QemuFaultCapabilityRequirement {
    /// Builds an exact, canonically ordered capability requirement.
    ///
    /// # Errors
    ///
    /// Returns [`FaultAbiError`] when rows are empty, invalid, duplicated, or
    /// not in canonical `(kind, version, scope)` order.
    pub fn exact(rows: Vec<FaultCapabilityRowV1>) -> Result<Self, FaultAbiError> {
        let digest = fault_capability_manifest_digest(&rows)?;
        Ok(Self { rows, digest })
    }

    /// Returns the complete capability set required by the current patch stack.
    #[must_use]
    pub fn current_v1(architecture: LivePluginGuestArchitecture) -> Self {
        let mut rows = Self::abi_boundary_v1().rows;
        let (scope, name): (FaultCapabilityScope, &[u8]) = match architecture {
            LivePluginGuestArchitecture::X86_64 => (
                FaultCapabilityScope::X86_64,
                b"qemu.memory.mutate.x86_64.v1",
            ),
            LivePluginGuestArchitecture::Aarch64 => (
                FaultCapabilityScope::Aarch64,
                b"qemu.memory.mutate.aarch64.v1",
            ),
        };
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
                b"crucible.node-fault-payload.v1;atomic-widths=1,2,4,8,16",
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS,
            ),
            capability_row(
                FaultCommandKind::MemoryRegionState,
                FaultCapabilityScope::All,
                b"qemu.memory.region-state.v1",
                b"crucible.node-fault-payload.v1;dram=2c2r16b64",
                HARD_FAULT_PAYLOAD_BYTES,
                DEFAULT_FAULT_COMMAND_CAPACITY,
                FAULT_CAPABILITY_FEATURE_MEMORY_ACCESS,
            ),
            capability_row(
                FaultCommandKind::MemoryService,
                FaultCapabilityScope::All,
                b"qemu.memory.service.v1",
                b"crucible.node-fault-payload.v1",
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
            let requirement = QemuFaultCapabilityRequirement::current_v1(architecture);
            let mutation = &requirement.rows()[2];

            assert_eq!(requirement.rows().len(), 6);
            assert_eq!(mutation.command_kind, FaultCommandKind::MemoryMutation);
            assert_eq!(mutation.scope, scope);
            assert_eq!(
                mutation.required_feature_bits,
                FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION
            );
            assert_eq!(
                requirement.rows()[3..]
                    .iter()
                    .map(|row| row.command_kind)
                    .collect::<Vec<_>>(),
                [
                    FaultCommandKind::MemoryAccessTransform,
                    FaultCommandKind::MemoryRegionState,
                    FaultCommandKind::MemoryService,
                ]
            );
            assert!(requirement.rows()[3..].iter().all(|row| {
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
        let x86 = QemuFaultCapabilityRequirement::current_v1(LivePluginGuestArchitecture::X86_64);
        let arm = QemuFaultCapabilityRequirement::current_v1(LivePluginGuestArchitecture::Aarch64);

        assert_ne!(x86.rows()[2], arm.rows()[2]);
        assert_ne!(x86.digest(), arm.digest());
    }
}
