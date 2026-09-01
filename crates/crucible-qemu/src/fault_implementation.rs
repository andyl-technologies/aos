//! Production implementation registry for node and QEMU fault effects.
//!
//! A live QEMU process advertises the command kinds compiled into its GPL-side
//! registry. This host-side registry independently records the corresponding
//! model effect, command encoder, result validator, checkpoint evidence, and
//! production conformance suite. Admission uses the intersection: neither the
//! model vocabulary nor an unexpected live command can advertise support by
//! itself.

use crucible::model::{
    EffectImplementationContract, EffectImplementationRegistry, EffectImplementationRegistryError,
    EffectKind, FaultAdapter, ProductionConformanceEvidence,
};
use crucible_shmem::FaultCommandKind;

const NODE_EFFECTS: &[EffectKind] = &[
    EffectKind::NodeLifecycle,
    EffectKind::NodeHang,
    EffectKind::CpuService,
    EffectKind::CpuVcpuState,
    EffectKind::CpuRegisterTransform,
    EffectKind::CpuInstructionTransform,
    EffectKind::CpuException,
    EffectKind::InterruptDisposition,
    EffectKind::InterruptStorm,
    EffectKind::MemoryMutation,
    EffectKind::MemoryAccessTransform,
    EffectKind::MemoryEccEvent,
    EffectKind::MemoryRegionState,
    EffectKind::MemoryService,
    EffectKind::ClockTransform,
    EffectKind::ClockSourceState,
    EffectKind::AcceleratorLifecycle,
    EffectKind::AcceleratorResultTransform,
    EffectKind::AcceleratorMemoryEvent,
    EffectKind::AcceleratorService,
];

const NODE_MUTATION_EVIDENCE: &[&str] = &[
    "QEMU closed fault registry state",
    "FaultResultHeaderV1 and effect-specific result payload",
    "FaultEventHeaderV1 and effect-specific event payload",
];

/// Maps one public wire command to its closed model effect.
#[must_use]
pub(crate) const fn effect_kind_for_command(kind: FaultCommandKind) -> Option<EffectKind> {
    match kind {
        FaultCommandKind::NodeLifecycle => Some(EffectKind::NodeLifecycle),
        FaultCommandKind::NodeHang => Some(EffectKind::NodeHang),
        FaultCommandKind::CpuService => Some(EffectKind::CpuService),
        FaultCommandKind::CpuVcpuState => Some(EffectKind::CpuVcpuState),
        FaultCommandKind::CpuRegisterTransform => Some(EffectKind::CpuRegisterTransform),
        FaultCommandKind::CpuInstructionTransform => Some(EffectKind::CpuInstructionTransform),
        FaultCommandKind::CpuException => Some(EffectKind::CpuException),
        FaultCommandKind::InterruptDisposition => Some(EffectKind::InterruptDisposition),
        FaultCommandKind::InterruptStorm => Some(EffectKind::InterruptStorm),
        FaultCommandKind::MemoryMutation => Some(EffectKind::MemoryMutation),
        FaultCommandKind::MemoryAccessTransform => Some(EffectKind::MemoryAccessTransform),
        FaultCommandKind::MemoryEccEvent => Some(EffectKind::MemoryEccEvent),
        FaultCommandKind::MemoryRegionState => Some(EffectKind::MemoryRegionState),
        FaultCommandKind::MemoryService => Some(EffectKind::MemoryService),
        FaultCommandKind::ClockTransform => Some(EffectKind::ClockTransform),
        FaultCommandKind::ClockSourceState => Some(EffectKind::ClockSourceState),
        FaultCommandKind::AcceleratorLifecycle => Some(EffectKind::AcceleratorLifecycle),
        FaultCommandKind::AcceleratorResultTransform => {
            Some(EffectKind::AcceleratorResultTransform)
        }
        FaultCommandKind::AcceleratorMemoryEvent => Some(EffectKind::AcceleratorMemoryEvent),
        FaultCommandKind::AcceleratorService => Some(EffectKind::AcceleratorService),
        FaultCommandKind::QueryCapabilities
        | FaultCommandKind::BoundaryProbe
        | FaultCommandKind::QueryTargetManifest => None,
    }
}

fn executor(effect: EffectKind) -> &'static str {
    match effect {
        EffectKind::CpuRegisterTransform => {
            "qemu_plugin_crucible_fault_submit -> register mutation callback"
        }
        EffectKind::CpuInstructionTransform => {
            "qemu_plugin_crucible_fault_submit -> instruction mutation callback"
        }
        EffectKind::CpuException | EffectKind::MemoryEccEvent => {
            "qemu_plugin_crucible_fault_submit -> hardware-error injection callback"
        }
        EffectKind::InterruptDisposition | EffectKind::InterruptStorm => {
            "qemu_plugin_crucible_fault_submit -> interrupt mutation callback"
        }
        EffectKind::MemoryMutation
        | EffectKind::MemoryAccessTransform
        | EffectKind::MemoryRegionState
        | EffectKind::MemoryService => {
            "qemu_plugin_crucible_fault_submit -> memory mutation callback"
        }
        EffectKind::ClockTransform | EffectKind::ClockSourceState => {
            "qemu_plugin_crucible_fault_submit -> guest-clock mutation callback"
        }
        EffectKind::AcceleratorLifecycle
        | EffectKind::AcceleratorResultTransform
        | EffectKind::AcceleratorMemoryEvent
        | EffectKind::AcceleratorService => {
            "qemu_plugin_crucible_fault_submit -> accelerator mutation callback"
        }
        _ => "qemu_plugin_crucible_fault_submit -> node fault callback",
    }
}

fn conformance_test(effect: EffectKind) -> &'static str {
    match effect {
        EffectKind::NodeLifecycle => "tests/crucible/phase2-qemu-live-node-lifecycle-fault.nix",
        EffectKind::NodeHang => {
            "tests/crucible/phase2-qemu-node-lifecycle.nix via gate:patch-microtests"
        }
        EffectKind::CpuService | EffectKind::CpuVcpuState => {
            "tests/crucible/phase2-qemu-vcpu-service.nix via gate:patch-microtests"
        }
        EffectKind::CpuRegisterTransform => {
            "tests/crucible/phase2-qemu-register-mutation.nix via gate:patch-microtests"
        }
        EffectKind::CpuInstructionTransform => {
            "tests/crucible/phase2-qemu-instruction-faults.nix via gate:patch-microtests"
        }
        EffectKind::CpuException | EffectKind::MemoryEccEvent => {
            "tests/crucible/phase2-qemu-hardware-error-faults.nix via gate:patch-microtests"
        }
        EffectKind::InterruptDisposition | EffectKind::InterruptStorm => {
            "tests/crucible/phase2-qemu-interrupt-faults.nix via gate:patch-microtests"
        }
        EffectKind::MemoryMutation => {
            "tests/crucible/phase2-qemu-memory-mutation.nix via gate:patch-microtests"
        }
        EffectKind::MemoryAccessTransform
        | EffectKind::MemoryRegionState
        | EffectKind::MemoryService => {
            "tests/crucible/phase2-qemu-memory-access.nix via gate:patch-microtests"
        }
        EffectKind::ClockTransform | EffectKind::ClockSourceState => {
            "tests/crucible/phase2-qemu-live-fault-hardware.nix plus gate:patch-microtests/0068"
        }
        EffectKind::AcceleratorLifecycle
        | EffectKind::AcceleratorResultTransform
        | EffectKind::AcceleratorMemoryEvent
        | EffectKind::AcceleratorService => {
            "tests/crucible/phase2-qemu-live-fault-hardware.nix plus gate:patch-microtests/0069,0074"
        }
        _ => "checks.crucible.phase2.gates.patchMicrotests",
    }
}

fn production_conformance(effect: EffectKind) -> ProductionConformanceEvidence {
    let live_gate = match effect {
        EffectKind::NodeLifecycle => "gate:live-node-lifecycle-fault",
        EffectKind::NodeHang => "gate:live-node-lifecycle-matrix",
        EffectKind::ClockTransform
        | EffectKind::ClockSourceState
        | EffectKind::AcceleratorLifecycle
        | EffectKind::AcceleratorResultTransform
        | EffectKind::AcceleratorMemoryEvent
        | EffectKind::AcceleratorService => "gate:live-fault-hardware",
        _ => "gate:patch-microtests",
    };
    ProductionConformanceEvidence {
        case_id: effect.as_str(),
        harness: conformance_test(effect),
        live_gate,
        observed_state: NODE_MUTATION_EVIDENCE,
    }
}

/// Returns the complete compiled implementation registry for node/QEMU effects.
///
/// # Errors
///
/// Returns [`EffectImplementationRegistryError`] if an entry is malformed,
/// duplicated, or absent from the closed node-effect vocabulary.
pub fn node_effect_implementation_registry()
-> Result<EffectImplementationRegistry, EffectImplementationRegistryError> {
    let registry = EffectImplementationRegistry::new(
        FaultAdapter::Node,
        NODE_EFFECTS.iter().copied().map(|effect| EffectImplementationContract {
            effect,
            executor: executor(effect),
            mutation_evidence: NODE_MUTATION_EVIDENCE,
            observation_evidence: effect.descriptor().replay_evidence,
            checkpoint_evidence:
                "QEMU VMState plus ProductionFaultRuntimeCheckpoint QEMU ledgers",
            recomputed_replay_evidence:
                "resolved action identity, command result, event, and execution fingerprint",
            locked_replay_evidence:
                "authenticated live precondition, command result, event, and execution fingerprint",
            search_evidence: "canonical keyed choices recorded in SearchFrontierChoices",
            production_conformance: production_conformance(effect),
        }),
    )?;
    registry.require_complete()?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_mapping_and_registry_cover_every_node_effect_exactly() {
        let registry = node_effect_implementation_registry()
            .unwrap_or_else(|error| panic!("node registry must be complete: {error}"));
        assert_eq!(registry.contracts().len(), 20);
        for effect in NODE_EFFECTS {
            assert!(registry.get(*effect).is_some(), "{effect}");
        }
    }
}
