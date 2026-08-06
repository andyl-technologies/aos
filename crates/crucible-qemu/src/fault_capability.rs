//! Launch-bound QEMU fault capability requirements.
//!
//! A requirement is the exact, canonically ordered manifest a QEMU process
//! must advertise before the boot barrier is released. Its digest is part of
//! launch identity and is reused unchanged for admission and replay.

use crucible_shmem::{
    DEFAULT_FAULT_COMMAND_CAPACITY, FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION,
    FAULT_COMMAND_SEMANTIC_VERSION, FaultAbiError, FaultBoundaryPhase, FaultCapabilityRowV1,
    FaultCapabilityScope, FaultCommandKind, HARD_FAULT_PAYLOAD_BYTES,
    fault_capability_manifest_digest,
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
        let schema = b"crucible.memory-mutation-payload.v1";
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"crucible.qemu-fault-capability.v1\0");
        hasher.update(name);
        hasher.update(&[0]);
        hasher.update(schema);
        rows.push(FaultCapabilityRowV1 {
            command_kind: FaultCommandKind::MemoryMutation,
            semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
            scope,
            phase_mask: FaultBoundaryPhase::NodeBoundary.bit(),
            maximum_payload_bytes: HARD_FAULT_PAYLOAD_BYTES,
            maximum_pending_commands: DEFAULT_FAULT_COMMAND_CAPACITY,
            required_feature_bits: FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION,
            capability_hash: *hasher.finalize().as_bytes(),
        });
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

            assert_eq!(requirement.rows().len(), 3);
            assert_eq!(mutation.command_kind, FaultCommandKind::MemoryMutation);
            assert_eq!(mutation.scope, scope);
            assert_eq!(
                mutation.required_feature_bits,
                FAULT_CAPABILITY_FEATURE_MEMORY_MUTATION
            );
            assert_eq!(
                fault_capability_manifest_digest(requirement.rows()).unwrap(),
                requirement.digest()
            );
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
