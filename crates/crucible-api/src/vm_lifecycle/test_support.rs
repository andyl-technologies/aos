//! Shared fixtures for production VM lifecycle unit tests.

use super::ProductionFaultRuntimeCheckpoint;
use crucible::{ContentHash, model::FaultSignalPlan};

pub(super) fn duplicate_network_fault_checkpoint_fixture(
    checkpoint: &ProductionFaultRuntimeCheckpoint,
    plan: &FaultSignalPlan,
) -> ProductionFaultRuntimeCheckpoint {
    let bytes = checkpoint
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("checkpoint fixture should encode: {error}"));
    ProductionFaultRuntimeCheckpoint::from_canonical_bytes(
        &bytes,
        plan,
        ContentHash::from_bytes(b"production-availability-drop"),
    )
    .unwrap_or_else(|error| panic!("checkpoint fixture should decode: {error}"))
}
