//! Link, forwarder, contact-plan, and association boundary tests.

use super::*;

#[test]
fn flap_blocks_frames_until_the_exact_recovery_boundary() {
    let mut state = BoundaryNetworkState::default();
    let application = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 100,
                retired_instructions: None,
            },
            [flap_action()],
            &crucible::model::WorldFaultTopology::default(),
        )
        .unwrap_or_else(|error| panic!("test flap should apply: {error}"));
    assert_eq!(application.next_wakeup_nanos, Some(160));

    let mut blocked = crucible::ResolvedNetworkFrameEffects::default();
    state
        .apply_frame(
            &target(),
            None,
            &crucible::model::WorldFaultTopology::default(),
            159,
            &mut blocked,
        )
        .unwrap_or_else(|error| panic!("test frame should resolve: {error}"));
    assert!(blocked.is_dropped());

    let mut recovered = crucible::ResolvedNetworkFrameEffects::default();
    state
        .apply_frame(
            &target(),
            None,
            &crucible::model::WorldFaultTopology::default(),
            160,
            &mut recovered,
        )
        .unwrap_or_else(|error| panic!("test frame should resolve: {error}"));
    assert!(!recovered.is_dropped());
}

#[test]
fn negotiated_mode_trains_then_constrains_real_frame_service() {
    let mut state = BoundaryNetworkState::default();
    let application = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 100,
                retired_instructions: None,
            },
            [negotiated_mode_action()],
            &crucible::model::WorldFaultTopology::default(),
        )
        .unwrap_or_else(|error| panic!("test negotiated mode should apply: {error}"));
    assert_eq!(application.next_wakeup_nanos, Some(125));

    let mode = state
        .negotiated_modes
        .values()
        .next()
        .unwrap_or_else(|| panic!("negotiated mode should be retained"));
    assert_eq!(mode.duplex, crucible::model::NetworkDuplex::Half);
    assert_eq!(mode.lanes, 2);
    assert_eq!(mode.fec, crucible::model::NetworkFecMode::Ldpc);
    assert_eq!(mode.transition_sequence, 8);

    let mut training = crucible::ResolvedNetworkFrameEffects::default();
    state
        .apply_frame(
            &target(),
            None,
            &crucible::model::WorldFaultTopology::default(),
            124,
            &mut training,
        )
        .unwrap_or_else(|error| panic!("test training frame should resolve: {error}"));
    assert!(training.is_dropped());

    let mut active = crucible::ResolvedNetworkFrameEffects::default();
    state
        .apply_frame(
            &target(),
            None,
            &crucible::model::WorldFaultTopology::default(),
            125,
            &mut active,
        )
        .unwrap_or_else(|error| panic!("test active frame should resolve: {error}"));
    assert!(!active.is_dropped());
    assert_eq!(active.serialization_rate_cap_bps(), Some(123));
}

#[test]
fn forwarder_clear_addresses_owned_queues_and_tables() {
    let mut state = BoundaryNetworkState::default();
    let application = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 100,
                retired_instructions: None,
            },
            [forwarder_action(
                crucible::model::NetworkStatePolicy::Clear,
                crucible::model::NetworkStatePolicy::Clear,
            )],
            &forwarder_topology(),
        )
        .unwrap_or_else(|error| panic!("test lifecycle should apply: {error}"));

    assert!(application.clear_queued_targets.contains(
        &crucible::model::ResolvedFaultTarget::NetworkQueue {
            owner: id("forwarder-a"),
            queue: id("forwarder-a-egress"),
        }
    ));
    assert!(application.clear_table_targets.contains(
        &crucible::model::ResolvedFaultTarget::NetworkForwarder {
            forwarder: id("forwarder-a"),
        }
    ));
    assert!(application.drain_queued_targets.is_empty());
}

#[test]
fn forwarder_drain_defers_outage_and_clears_tables_after_recovery() {
    let target = crucible::model::ResolvedFaultTarget::NetworkForwarder {
        forwarder: id("forwarder-a"),
    };
    let mut state = BoundaryNetworkState::default();
    let application = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 100,
                retired_instructions: None,
            },
            [forwarder_action(
                crucible::model::NetworkStatePolicy::Drain,
                crucible::model::NetworkStatePolicy::Drain,
            )],
            &forwarder_topology(),
        )
        .unwrap_or_else(|error| panic!("test lifecycle should apply: {error}"));
    assert_eq!(application.drain_queued_targets.len(), 1);

    assert_eq!(
        state
            .defer_outage_until_queues_drain(&target, 150, 10)
            .unwrap_or_else(|error| panic!("test drain should defer: {error}")),
        160
    );
    let mut before_drain = crucible::ResolvedNetworkFrameEffects::default();
    state
        .apply_frame(&target, None, &forwarder_topology(), 149, &mut before_drain)
        .unwrap_or_else(|error| panic!("test frame should resolve: {error}"));
    assert!(!before_drain.is_dropped());
    let mut during_outage = crucible::ResolvedNetworkFrameEffects::default();
    state
        .apply_frame(
            &target,
            None,
            &forwarder_topology(),
            150,
            &mut during_outage,
        )
        .unwrap_or_else(|error| panic!("test frame should resolve: {error}"));
    assert!(during_outage.is_dropped());

    let completion = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 160,
                retired_instructions: None,
            },
            [],
            &forwarder_topology(),
        )
        .unwrap_or_else(|error| panic!("test drain should complete: {error}"));
    assert!(completion.clear_table_targets.contains(&target));
}

#[test]
fn contact_plan_exposes_acquisition_open_and_teardown_boundaries() {
    let contact = ContactPlanState {
        intervals: vec![crucible::model::NetworkPolicyContactInterval {
            contact: id("contact-a"),
            service_resource: id("resource-a"),
            route_cost: positive(1),
            routing_propagation_nanos: 1,
            start_nanos: 100,
            end_nanos: 200,
            source: id("satellite"),
            destination: id("ground-station"),
            beam: id("beam-a"),
            gateway: id("gateway-a"),
            minimum_range_mm: 1,
            maximum_range_mm: 2,
            capacity_profile: id("capacity"),
            acquisition_nanos: 10,
            teardown_nanos: 20,
            confidence: crucible::model::ProbabilityMillionths::new(1_000_000)
                .unwrap_or_else(|error| panic!("test confidence should be valid: {error}")),
            provenance: id("trace"),
        }],
        transition_sequence: 1,
    };
    assert_eq!(contact.next_boundary(99), Some(100));
    assert!(!contact.carries_traffic(109));
    assert_eq!(contact.next_boundary(100), Some(110));
    assert!(contact.carries_traffic(110));
    assert!(contact.carries_traffic(179));
    assert!(!contact.carries_traffic(180));
    assert_eq!(contact.next_boundary(180), Some(200));
}

#[test]
fn association_executes_residence_authentication_and_handoff_timers() {
    let policy = id("association-policy");
    let topology = association_topology(policy.clone());
    let mut state = BoundaryNetworkState::default();
    let target = association_action(policy, [10, 20]).target;

    let initial = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            [association_action(id("association-policy"), [10, 20])],
            &topology,
        )
        .unwrap_or_else(|error| panic!("initial association scan: {error}"));
    assert_eq!(initial.next_wakeup_nanos, Some(2));

    for now in [2, 4, 6, 8] {
        state
            .apply_actions(
                FaultCoordinate {
                    virtual_nanos: now,
                    retired_instructions: None,
                },
                [],
                &topology,
            )
            .unwrap_or_else(|error| panic!("association residence scan: {error}"));
    }
    let handoff = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 10,
                retired_instructions: None,
            },
            [],
            &topology,
        )
        .unwrap_or_else(|error| panic!("association handoff start: {error}"));
    assert!(handoff.clear_queued_targets.contains(&target));
    assert!(handoff.address_discontinuities.contains(&target));
    assert_eq!(handoff.next_wakeup_nanos, Some(15));

    state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 15,
                retired_instructions: None,
            },
            [],
            &topology,
        )
        .unwrap_or_else(|error| panic!("association handoff completion: {error}"));
    let association = state
        .associations
        .values()
        .next()
        .unwrap_or_else(|| panic!("association state should remain active"));
    assert_eq!(association.phase, AssociationPhase::Associated);
    assert_eq!(association.current.as_ref(), Some(&id("segment-b")));
}

#[test]
fn control_service_queues_executes_and_reports_overflow_without_bypasses() {
    let topology = control_topology();
    let mut state = BoundaryNetworkState::default();
    let queued = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            [
                control_service_action(),
                route_transition_action("route-event-a", "route-b"),
                route_transition_action("route-event-b", "route-c"),
            ],
            &topology,
        )
        .unwrap_or_else(|error| panic!("queue control events: {error}"));
    assert!(queued.ready_control_events.is_empty());
    assert_eq!(queued.next_wakeup_nanos, Some(10));
    assert_eq!(queued.control_outcomes.len(), 1);
    assert!(matches!(
        queued.control_outcomes[0].kind,
        ControlPlaneOutcomeKind::Dropped
    ));

    let mut released = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 10,
                retired_instructions: None,
            },
            [route_transition_action("route-event-c", "route-c")],
            &topology,
        )
        .unwrap_or_else(|error| panic!("release control event: {error}"));
    assert_eq!(released.ready_control_events.len(), 1);
    assert!(released.control_outcomes.is_empty());
    assert_eq!(released.next_wakeup_nanos, Some(20));
    let event = released.ready_control_events.remove(0);
    let applied = state
        .apply_ready_control_event(
            FaultCoordinate {
                virtual_nanos: 10,
                retired_instructions: None,
            },
            event,
            &topology,
        )
        .unwrap_or_else(|error| panic!("apply serviced route event: {error}"));
    assert_eq!(applied.route_transitions.len(), 1);
    assert_eq!(
        state.route_path_override(&id("route-a"), 10),
        Some(&id("route-b"))
    );
}

#[test]
fn control_service_updates_reject_conflicting_overflow_and_occupied_queue_shrink() {
    let mut topology = control_topology();
    topology
        .network_policy_artifacts
        .push(crucible::model::WorldNetworkPolicyArtifact {
            id: id("control-timeout"),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::Overflow {
                disposition: crucible::model::NetworkPolicyOverflow::Timeout,
                timeout_nanos: Some(positive(5)),
                typed_error: None,
            },
        });
    topology
        .network_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));

    let mut conflicting = BoundaryNetworkState::default();
    let error = conflicting
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            [
                control_service_action(),
                control_service_action_with("control-service-binding-b", 1, "control-timeout"),
            ],
            &topology,
        )
        .err()
        .unwrap_or_else(|| panic!("conflicting overflow policies must fail"));
    assert!(error.to_string().contains("disagree on overflow semantics"));

    let mut occupied = BoundaryNetworkState::default();
    occupied
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            [
                control_service_action_with("control-service-binding", 2, "control-overflow"),
                route_transition_action("route-event-a", "route-b"),
                route_transition_action("route-event-b", "route-c"),
            ],
            &topology,
        )
        .unwrap_or_else(|error| panic!("fill control queue: {error}"));
    let error = occupied
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            [control_service_action()],
            &topology,
        )
        .err()
        .unwrap_or_else(|| panic!("occupied queue shrink must fail"));
    assert!(
        error
            .to_string()
            .contains("shrink the queue below its occupancy")
    );
}
