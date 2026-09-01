//! Causal production-network conformance cases.

use super::*;

#[test]
fn production_resolve_availability_suppresses_the_routed_frame() {
    let (world, segment) = availability_world();
    let scenario = SchedulerLivenessScenario::from_runnable_world(
        "production-resolve-availability",
        Shift::default(),
        16,
        SimInstant { nanos: 128 },
        0,
        &world,
    );
    let mut scheduler = SingleScheduler::from_world(
        scenario,
        &world,
        &MemoryDagStore::new(),
        WorldIoLayoutPolicy::default(),
    )
    .unwrap_or_else(|error| panic!("test scheduler should build: {error}"));
    let mut nodes = ProductionNodeSet::new();
    let runtime = ProductionFaultRuntime::new(
        down_plan_at(segment, FaultPhase::Resolve),
        Some(Arc::new(NoArtifacts)),
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"production-resolve-availability"),
        super::super::super::fault_implementation::test_host_manifests(),
        &nodes,
    )
    .unwrap_or_else(|error| panic!("test fault runtime should build: {error}"));
    let mut interceptor = ProductionFaultNetworkInterceptor::new(
        runtime,
        world.fault_topology().clone(),
        world.links().to_vec(),
    );
    let mut pending_outputs = Vec::new();
    interceptor
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            &mut scheduler,
            &mut nodes,
            &mut pending_outputs,
        )
        .unwrap_or_else(|error| panic!("resolve availability should activate: {error}"));

    let source = crucible::NodeId {
        name: String::from("left"),
    };
    let destination = crucible::NodeId {
        name: String::from("right"),
    };
    let mut payload = vec![0_u8; 14];
    payload[..6].copy_from_slice(&deterministic_node_mac(&destination));
    let mut outputs = vec![BackendNetworkOutput {
        source,
        destination,
        emit_icount: Icount { retired: 0 },
        sequence: 1,
        payload,
        route: None,
        fault_continuation: Default::default(),
    }];
    interceptor
        .intercept_network_outputs(
            &mut scheduler,
            &mut nodes,
            VirtualTime { ticks: 0 },
            &mut pending_outputs,
            &mut outputs,
        )
        .unwrap_or_else(|error| panic!("resolve opportunity should execute: {error}"));
    assert!(outputs.is_empty());
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkAvailability],
        "availability-resolve-suppression",
        "active-state+exact-opportunity+routed-frame-drop",
    );
}
