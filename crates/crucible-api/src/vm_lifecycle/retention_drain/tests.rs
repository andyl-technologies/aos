//! Tests that retention drains decline without side effects and match shutdown.

use super::*;

fn process_free_lifecycle() -> ProductionVmLifecycleLoop {
    production_permanently_failed_loop_for_test()
        .unwrap_or_else(|error| panic!("process-free lifecycle should build: {error}"))
        .1
}

#[test]
fn failed_lease_cleanup_declines_retention_without_settling() {
    let mut lifecycle = process_free_lifecycle();
    lifecycle.node_lease_cleanup_failed = true;
    let before = lifecycle.inner.loop_impl().event_log().offset();

    let drained = lifecycle
        .drain_final_boundary_for_retention()
        .unwrap_or_else(|error| panic!("an ineligible drain should not fail: {error}"));

    assert!(drained.is_none());
    assert_eq!(lifecycle.inner.loop_impl().event_log().offset(), before);
}

#[test]
fn drained_boundary_leaves_nothing_for_shutdown() {
    let mut lifecycle = process_free_lifecycle();

    let drained = lifecycle
        .drain_final_boundary_for_retention()
        .unwrap_or_else(|error| panic!("a clean boundary should drain: {error}"))
        .unwrap_or_else(|| panic!("a clean boundary should be retainable"));
    let after_drain = lifecycle.inner.loop_impl().event_log().offset();
    let shutdown = lifecycle
        .shutdown()
        .unwrap_or_else(|error| panic!("shutdown after a drain should succeed: {error}"));

    assert!(drained.is_empty());
    assert!(shutdown.is_empty());
    assert_eq!(
        lifecycle.inner.loop_impl().event_log().offset(),
        after_drain
    );
}
