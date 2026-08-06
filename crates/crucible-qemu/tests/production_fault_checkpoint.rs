//! Checks authenticated production fault-continuation checkpointing.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup.
#![allow(clippy::expect_used)]

use crucible::model::{ContentHash, FaultSignalPlan, SignalBoundarySnapshot};
use crucible_qemu::{ProductionFaultRuntime, QemuNodeSet};

#[test]
fn empty_production_continuation_round_trips_with_the_same_identity() {
    let plan = FaultSignalPlan::empty();
    let seed = ContentHash::from_bytes(b"production-fault-checkpoint-seed");
    let mut nodes = QemuNodeSet::new();
    let runtime = ProductionFaultRuntime::new(
        plan.clone(),
        None,
        SignalBoundarySnapshot::default(),
        seed,
        &nodes,
    )
    .expect("empty production runtime should admit");
    let checkpoint = runtime
        .checkpoint(&mut nodes)
        .expect("empty production runtime should checkpoint");
    let expected = checkpoint.id();

    let restored = ProductionFaultRuntime::restore(plan, None, seed, checkpoint, &mut nodes)
        .expect("authenticated production checkpoint should restore");
    let round_trip = restored
        .checkpoint(&mut nodes)
        .expect("restored production runtime should checkpoint");

    assert_eq!(round_trip.id(), expected);
}
