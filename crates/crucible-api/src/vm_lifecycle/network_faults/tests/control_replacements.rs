//! Forwarder and contact replacement contract tests.

use super::*;

#[test]
fn forwarder_and_contact_replacements_execute_only_within_world_contracts() {
    let positive = |field, value| {
        crucible::model::PositiveU64::new(field, value)
            .unwrap_or_else(|error| panic!("test positive value: {error}"))
    };
    let forwarder_target = ResolvedFaultTarget::NetworkForwarder {
        forwarder: object_id("forwarder-a"),
    };
    let forwarder_action = ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: object_id("forwarder-event"),
        target: forwarder_target.clone(),
        phase: FaultPhase::Boundary,
        effect: Arc::new(
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::StateMachine,
                EffectSpecification::Network(NetworkEffectSpecification::ForwarderLifecycle {
                    transition: crucible::model::NetworkForwarderTransition::Restart,
                    downtime_nanos: positive("downtime", 1),
                    queue_policy: crucible::model::NetworkStatePolicy::Preserve,
                    table_policy: crucible::model::NetworkStatePolicy::Preserve,
                }),
            )
            .unwrap_or_else(|error| panic!("forwarder lifecycle: {error}")),
        ),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"forwarder"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    };
    let forwarder_event = boundary::QueuedNetworkControlEvent {
        sequence: 0,
        operation: FaultOperation::NetworkChange,
        technology: object_id("network-forwarder-v1"),
        result_schema: object_id("network-forwarder-state-v1"),
        result_digest: ContentHash::from_bytes(&[1]),
        release_nanos: 1,
        action: forwarder_action,
    };

    let contact_target = ResolvedFaultTarget::NetworkContact {
        plan: object_id("contact-plan-a"),
        endpoint_a: object_id("ground"),
        endpoint_b: object_id("satellite"),
        contact: object_id("contact-a"),
    };
    let members = |value| {
        crucible::model::ObjectIdSet::new(vec![object_id(value)])
            .unwrap_or_else(|error| panic!("test contact members: {error}"))
    };
    let contact_action = ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: object_id("contact-event"),
        target: contact_target.clone(),
        phase: FaultPhase::Boundary,
        effect: Arc::new(
            EffectRequest::new(
                EFFECT_SEMANTIC_VERSION,
                EffectLifetime::StateMachine,
                EffectSpecification::Network(NetworkEffectSpecification::Contact {
                    intervals: object_id("contact-plan-a"),
                    range_delay_lookup: object_id("range-delay"),
                    beams: members("beam-a"),
                    gateways: members("gateway-a"),
                }),
            )
            .unwrap_or_else(|error| panic!("contact effect: {error}")),
        ),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"contact"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
        expected_precondition: None,
    };
    let contact_event = boundary::QueuedNetworkControlEvent {
        sequence: 0,
        operation: FaultOperation::NetworkAcquire,
        technology: object_id("network-contact-v1"),
        result_schema: object_id("network-contact-plan-v1"),
        result_digest: ContentHash::from_bytes(b"contact-plan-a"),
        release_nanos: 1,
        action: contact_action,
    };
    let contact_interval = |beam: &str| crucible::model::NetworkPolicyContactInterval {
        contact: object_id(&format!("contact-{beam}")),
        service_resource: object_id(&format!("resource-{beam}")),
        route_cost: positive("route_cost", 1),
        routing_propagation_nanos: 1,
        start_nanos: 0,
        end_nanos: 100,
        source: object_id("ground"),
        destination: object_id("satellite"),
        beam: object_id(beam),
        gateway: object_id("gateway-a"),
        minimum_range_mm: 1,
        maximum_range_mm: 2,
        capacity_profile: object_id("capacity-a"),
        acquisition_nanos: 0,
        teardown_nanos: 0,
        confidence: crucible::model::ProbabilityMillionths::new(1_000_000)
            .unwrap_or_else(|error| panic!("contact confidence: {error}")),
        provenance: object_id("trace-a"),
    };
    let mut topology = crucible::model::WorldFaultTopology {
        network_policy_artifacts: vec![
            crucible::model::WorldNetworkPolicyArtifact {
                id: object_id("contact-plan-b"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ContactPlan {
                    intervals: vec![contact_interval("beam-a")],
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: object_id("contact-plan-invalid"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ContactPlan {
                    intervals: vec![contact_interval("beam-b")],
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: object_id("contact-result"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ControlResult {
                    schema: object_id("network-contact-plan-v1"),
                    bytes: b"contact-plan-b".to_vec(),
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: object_id("contact-result-invalid"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ControlResult {
                    schema: object_id("network-contact-plan-v1"),
                    bytes: b"contact-plan-invalid".to_vec(),
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: object_id("forwarder-result"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::ControlResult {
                    schema: object_id("network-forwarder-state-v1"),
                    bytes: vec![3],
                },
            },
        ],
        ..crucible::model::WorldFaultTopology::default()
    };
    topology
        .network_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));

    let forwarder = apply_network_control_transforms(
        forwarder_event,
        &[typed_control_transform_action(
            object_id("network-forwarder-v1"),
            FaultOperation::NetworkChange,
            crucible::model::NetworkControlResultKind::Replace,
            object_id("forwarder-result"),
            object_id("network-forwarder-state-v1"),
            forwarder_target,
        )],
        &topology,
    )
    .unwrap_or_else(|error| panic!("replace forwarder state: {error}"))
    .unwrap_or_else(|| panic!("forwarder replacement must remain active"));
    assert!(matches!(
        forwarder.action.effect.specification(),
        EffectSpecification::Network(NetworkEffectSpecification::ForwarderLifecycle {
            transition: crucible::model::NetworkForwarderTransition::PowerLoss,
            ..
        })
    ));

    let valid = apply_network_control_transforms(
        contact_event.clone(),
        &[typed_control_transform_action(
            object_id("network-contact-v1"),
            FaultOperation::NetworkAcquire,
            crucible::model::NetworkControlResultKind::Replace,
            object_id("contact-result"),
            object_id("network-contact-plan-v1"),
            contact_target.clone(),
        )],
        &topology,
    )
    .unwrap_or_else(|error| panic!("replace contact plan: {error}"))
    .unwrap_or_else(|| panic!("contact replacement must remain active"));
    assert!(matches!(
        valid.action.effect.specification(),
        EffectSpecification::Network(NetworkEffectSpecification::Contact { intervals, .. })
            if intervals == &object_id("contact-plan-b")
    ));
    let error = apply_network_control_transforms(
        contact_event,
        &[typed_control_transform_action(
            object_id("network-contact-v1"),
            FaultOperation::NetworkAcquire,
            crucible::model::NetworkControlResultKind::Replace,
            object_id("contact-result-invalid"),
            object_id("network-contact-plan-v1"),
            contact_target,
        )],
        &topology,
    )
    .err()
    .unwrap_or_else(|| panic!("undeclared contact beam must fail"));
    assert!(error.to_string().contains("undeclared beam or gateway"));
}
