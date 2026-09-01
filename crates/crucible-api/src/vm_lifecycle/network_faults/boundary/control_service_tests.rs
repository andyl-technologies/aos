//! Control-service overflow, composition, and replacement tests.

use super::*;

#[test]
fn control_overflow_executes_drop_oldest_typed_error_and_timeout_exactly() {
    let set_overflow = |topology: &mut crucible::model::WorldFaultTopology,
                        disposition,
                        timeout_nanos,
                        typed_error| {
        let declaration = topology
            .network_policy_artifacts
            .iter_mut()
            .find(|artifact| artifact.id == id("control-overflow"))
            .unwrap_or_else(|| panic!("control overflow artifact"));
        declaration.artifact = crucible::model::NetworkPolicyArtifactKind::Overflow {
            disposition,
            timeout_nanos,
            typed_error,
        };
    };
    let actions = || {
        [
            control_service_action(),
            route_transition_action("route-event-a", "route-b"),
            route_transition_action("route-event-b", "route-c"),
        ]
    };

    let mut drop_oldest_topology = control_topology();
    set_overflow(
        &mut drop_oldest_topology,
        crucible::model::NetworkPolicyOverflow::DropOldest,
        None,
        None,
    );
    let mut drop_oldest = BoundaryNetworkState::default();
    let application = drop_oldest
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            actions(),
            &drop_oldest_topology,
        )
        .unwrap_or_else(|error| panic!("drop-oldest control queue: {error}"));
    assert_eq!(application.control_outcomes.len(), 1);
    assert_eq!(
        application.control_outcomes[0].action.binding,
        id("route-event-a")
    );
    assert_eq!(
        drop_oldest
            .control_planes
            .values()
            .next()
            .and_then(|control| control.events.first())
            .map(|event| &event.action.binding),
        Some(&id("route-event-b"))
    );

    let mut typed_topology = control_topology();
    typed_topology
        .network_policy_artifacts
        .push(crucible::model::WorldNetworkPolicyArtifact {
            id: id("control-busy"),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::ControlResult {
                schema: id("network-control-error-v1"),
                bytes: b"busy".to_vec(),
            },
        });
    set_overflow(
        &mut typed_topology,
        crucible::model::NetworkPolicyOverflow::TypedError,
        None,
        Some(id("control-busy")),
    );
    typed_topology
        .network_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    let mut typed = BoundaryNetworkState::default();
    let application = typed
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            actions(),
            &typed_topology,
        )
        .unwrap_or_else(|error| panic!("typed-error control queue: {error}"));
    assert_eq!(application.control_outcomes.len(), 1);
    assert!(matches!(
        application.control_outcomes[0].kind,
        ControlPlaneOutcomeKind::TypedError
    ));
    assert_eq!(
        application.control_outcomes[0].result,
        Some(id("control-busy"))
    );

    let mut timeout_topology = control_topology();
    set_overflow(
        &mut timeout_topology,
        crucible::model::NetworkPolicyOverflow::Timeout,
        Some(positive(5)),
        None,
    );
    let mut timeout = BoundaryNetworkState::default();
    let application = timeout
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            actions(),
            &timeout_topology,
        )
        .unwrap_or_else(|error| panic!("timeout control queue: {error}"));
    assert!(application.control_outcomes.is_empty());
    assert_eq!(application.next_wakeup_nanos, Some(5));
    let application = timeout
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 5,
                retired_instructions: None,
            },
            [],
            &timeout_topology,
        )
        .unwrap_or_else(|error| panic!("expire control timeout: {error}"));
    assert_eq!(application.control_outcomes.len(), 1);
    assert!(matches!(
        application.control_outcomes[0].kind,
        ControlPlaneOutcomeKind::TimedOut
    ));
    assert_eq!(
        application.control_outcomes[0].action.binding,
        id("route-event-b")
    );
}

#[test]
fn control_contributors_compose_by_minimum_bound_and_latest_committed_finish() {
    let topology = control_topology();
    let first_service =
        control_service_action_with("control-service-binding-a", 2, "control-overflow");
    let mut slower_service =
        control_service_action_with("control-service-binding-b", 1, "control-overflow");
    slower_service.effect = Arc::new(
        EffectRequest::new(
            crucible::model::EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::ControlPlaneService {
                service_curve: id("control-service"),
                queue_bound: bounded(1),
                overflow_policy: id("control-overflow"),
                event_work_bits: positive(20),
            }),
        )
        .unwrap_or_else(|error| panic!("slower test control service: {error}")),
    );
    let mut state = BoundaryNetworkState::default();
    let application = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            [
                first_service.clone(),
                slower_service.clone(),
                route_transition_action("route-event-a", "route-b"),
                route_transition_action("route-event-b", "route-c"),
            ],
            &topology,
        )
        .unwrap_or_else(|error| panic!("compose control services: {error}"));
    assert_eq!(application.control_outcomes.len(), 1);
    assert_eq!(application.next_wakeup_nanos, Some(20));

    let mut remove_first = first_service;
    remove_first.kind = BindingActionKind::RemovePersistent;
    remove_first.coordinate.virtual_nanos = 1;
    let mut remove_second = slower_service;
    remove_second.kind = BindingActionKind::RemovePersistent;
    remove_second.coordinate.virtual_nanos = 1;
    let removed = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 1,
                retired_instructions: None,
            },
            [remove_first, remove_second],
            &topology,
        )
        .unwrap_or_else(|error| panic!("remove control services: {error}"));
    assert_eq!(removed.next_wakeup_nanos, Some(20));
    let released = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 20,
                retired_instructions: None,
            },
            [],
            &topology,
        )
        .unwrap_or_else(|error| panic!("release committed control event: {error}"));
    assert_eq!(released.ready_control_events.len(), 1);
}

#[test]
fn queued_association_operation_identity_survives_checkpoint_state_changes() {
    let policy = id("association-policy");
    let mut topology = association_topology(policy.clone());
    let control = control_topology();
    topology
        .network_policy_artifacts
        .extend(control.network_policy_artifacts);
    topology
        .network_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    let signal = |value| {
        crucible::model::SignalId::parse(value)
            .unwrap_or_else(|error| panic!("test signal ID: {error}"))
    };
    topology
        .network_attachments
        .push(crucible::model::WorldNetworkAttachment {
            id: signal("attachment-a"),
            interface: signal("interface-a"),
            candidates: vec![signal("segment-a"), signal("segment-b")],
            technology: signal("network-wireless-v1"),
            semantic_version: 1,
            authentication: signal("authentication-a"),
            address_continuity: signal("address-continuity-a"),
        });

    let association = association_action(policy.clone(), [10, 20]);
    let mut service =
        control_service_action_with("association-control-service", 2, "control-overflow");
    service.target = association.target.clone();
    let mut state = BoundaryNetworkState::default();
    state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            [service, association.clone(), association.clone()],
            &topology,
        )
        .unwrap_or_else(|error| panic!("queue association events: {error}"));
    assert!(state.control_planes.values().next().is_some_and(|control| {
        control.events.len() == 2
            && control
                .events
                .iter()
                .all(|event| event.operation == crucible::model::FaultOperation::NetworkAssociate)
    }));

    state.associations.insert(
        NetworkEffectStateKey::from_action(&association),
        AssociationState {
            policy,
            candidates: vec![(id("segment-a"), 10), (id("segment-b"), 20)],
            phase: AssociationPhase::Associated,
            current: Some(id("segment-a")),
            pending: None,
            pending_since_nanos: None,
            transfer_complete_nanos: None,
            next_scan_nanos: 2,
            preserve_queued: false,
            preserve_address: false,
            transition_sequence: 1,
        },
    );
    let encoded = serde_json::to_vec(&state)
        .unwrap_or_else(|error| panic!("encode boundary checkpoint: {error}"));
    let restored: BoundaryNetworkState = serde_json::from_slice(&encoded)
        .unwrap_or_else(|error| panic!("decode boundary checkpoint: {error}"));
    restored
        .validate_bounds()
        .unwrap_or_else(|error| panic!("restored bounds: {error}"));
    restored
        .validate_topology(&topology)
        .unwrap_or_else(|error| panic!("restored association queue: {error}"));
}

#[test]
fn typed_control_replacement_changes_the_real_serviced_route_result() {
    let topology = control_topology();
    let mut state = BoundaryNetworkState::default();
    state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            [
                control_service_action(),
                route_transition_action("route-event", "route-b"),
            ],
            &topology,
        )
        .unwrap_or_else(|error| panic!("queue route event: {error}"));
    let mut released = state
        .apply_actions(
            FaultCoordinate {
                virtual_nanos: 10,
                retired_instructions: None,
            },
            [],
            &topology,
        )
        .unwrap_or_else(|error| panic!("release route event: {error}"));
    let event = released.ready_control_events.remove(0);
    let transformed =
        apply_network_control_transforms(event, &[route_replacement_action()], &topology)
            .unwrap_or_else(|error| panic!("replace route result: {error}"))
            .unwrap_or_else(|| panic!("replacement should retain the control event"));
    state
        .apply_ready_control_event(
            FaultCoordinate {
                virtual_nanos: 10,
                retired_instructions: None,
            },
            transformed,
            &topology,
        )
        .unwrap_or_else(|error| panic!("apply replacement route result: {error}"));
    assert_eq!(
        state.route_path_override(&id("route-a"), 10),
        Some(&id("route-c"))
    );
    crate::vm_lifecycle::network_faults::record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkControlResultTransform],
        "typed-control-result-replacement",
        "request-result-identity+replacement-route",
    );
}
