//! Fallible production-checkpoint fixtures for network fault tests.

use crucible_qemu::ProductionFaultRuntimeCheckpoint;

pub(super) fn clone_fault_checkpoint(
    checkpoint: &ProductionFaultRuntimeCheckpoint,
) -> ProductionFaultRuntimeCheckpoint {
    checkpoint
        .try_clone()
        .unwrap_or_else(|error| panic!("checkpoint fixture should clone: {error}"))
}
