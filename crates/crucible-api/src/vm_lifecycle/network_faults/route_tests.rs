//! Tests for deterministic route and forwarding fault behavior.

use std::sync::Arc;

use super::*;
use crucible::model::{
    BindingActionCause, BindingActionKind, CountLimit, EFFECT_SEMANTIC_VERSION, EffectLifetime,
    EffectRequest, NetworkInFlightPolicy, PositiveU64, ResolvedFaultTarget, ResolvedMappingOutput,
};

fn id(value: &str) -> FaultObjectId {
    FaultObjectId::parse(value)
        .unwrap_or_else(|error| panic!("test object ID should be valid: {error}"))
}

fn positive(value: u64) -> PositiveU64 {
    PositiveU64::new("test", value)
        .unwrap_or_else(|error| panic!("test positive value should be valid: {error}"))
}

fn action() -> ResolvedBindingAction {
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Network(NetworkEffectSpecification::Availability {
            state: NetworkAvailabilityState::Up,
            queued_policy: NetworkInFlightPolicy::Preserve,
            in_flight_policy: NetworkInFlightPolicy::Preserve,
        }),
    )
    .unwrap_or_else(|error| panic!("test effect should be valid: {error}"));
    ResolvedBindingAction {
        kind: BindingActionKind::UpsertPersistent,
        binding: id("network-test-binding"),
        target: ResolvedFaultTarget::NetworkSegment {
            segment: id("network-test-segment"),
            direction: crucible::model::FaultDirection::AToB,
        },
        phase: FaultPhase::Queue,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::Activation { active: true }),
        mapped_digest: ContentHash::from_bytes(b"mapped"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
    }
}

#[test]
fn multicast_recipient_selection_is_shared_across_route_copies() {
    let action = action();
    let membership = id("multicast-members-v1");
    let mut topology = crucible::model::WorldFaultTopology::default();
    topology
        .network_policy_artifacts
        .push(crucible::model::WorldNetworkPolicyArtifact {
            id: membership.clone(),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::RecipientMembership {
                members: vec![
                    crucible::model::NetworkPolicyRecipient {
                        member: id("receiver-a"),
                        joined_sequence: 1,
                    },
                    crucible::model::NetworkPolicyRecipient {
                        member: id("receiver-b"),
                        joined_sequence: 2,
                    },
                ],
            },
        });
    let retain = crucible::model::BoundedCount::new(CountLimit::DuplicatesOrInstructionReplay, 1)
        .unwrap_or_else(|error| panic!("recipient count: {error}"));
    let mut outcomes = Vec::new();
    for destination in [id("receiver-a"), id("receiver-b")] {
        let opportunity = FaultOpportunity::new(
            action.target.clone(),
            crucible::model::FaultOperation::NetworkTraverse,
            FaultPhase::Deliver,
            FaultCoordinate {
                virtual_nanos: 10,
                retired_instructions: Some(1),
            },
            7,
            Some(crucible::model::FaultDirection::AToB),
            OpportunityPayload::NetworkFrame {
                producer: id("sender"),
                destination,
                producer_sequence: 7,
                protocol_expansion_path: Vec::new(),
                generated_response_depth: 0,
                generated_response_cause: None,
                forwarding_mutation_path: Vec::new(),
                length_bytes: 64,
                payload_digest: ContentHash::from_bytes(b"multicast-frame"),
            },
        )
        .unwrap_or_else(|error| panic!("recipient opportunity: {error}"));
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        apply_network_recipient_subset(
            &mut effects,
            &action,
            &opportunity,
            ContentHash::from_bytes(b"recipient-seed"),
            &topology,
            &membership,
            None,
            Some(&crucible::model::NetworkSelection::KeyedUniform),
            Some(&retain),
        )
        .unwrap_or_else(|error| panic!("recipient selection: {error}"));
        outcomes.push(effects.is_dropped());
    }

    assert_eq!(outcomes.iter().filter(|dropped| !**dropped).count(), 1);
}

fn opportunity(sequence: u64) -> FaultOpportunity {
    FaultOpportunity::new(
        ResolvedFaultTarget::NetworkSegment {
            segment: id("network-test-segment"),
            direction: crucible::model::FaultDirection::AToB,
        },
        crucible::model::FaultOperation::NetworkTraverse,
        FaultPhase::Queue,
        FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        sequence,
        Some(crucible::model::FaultDirection::AToB),
        OpportunityPayload::NetworkFrame {
            producer: id("sender"),
            destination: id("receiver"),
            producer_sequence: sequence,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: Vec::new(),
            length_bytes: 1,
            payload_digest: ContentHash::from_bytes(&[u8::try_from(sequence).unwrap_or(0)]),
        },
    )
    .unwrap_or_else(|error| panic!("test opportunity should be valid: {error}"))
}

fn action_with_network_effect(specification: NetworkEffectSpecification) -> ResolvedBindingAction {
    let mut action = action();
    let descriptor = specification.kind().descriptor();
    let lifetime = if descriptor.lifetimes.contains(&EffectLifetime::Opportunity) {
        EffectLifetime::Opportunity
    } else if descriptor.lifetimes.contains(&EffectLifetime::Impulse) {
        EffectLifetime::Impulse
    } else {
        descriptor.lifetimes[0]
    };
    action.kind = if lifetime == EffectLifetime::Persistent {
        BindingActionKind::UpsertPersistent
    } else {
        BindingActionKind::Apply
    };
    action.phase = descriptor.phases[0];
    action.effect = Arc::new(
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            lifetime,
            EffectSpecification::Network(specification),
        )
        .unwrap_or_else(|error| panic!("test network effect: {error}")),
    );
    action
}

fn medium_action(
    resources: crucible::model::ObjectIdSet,
    policy: FaultObjectId,
    power: u64,
) -> ResolvedBindingAction {
    let mut action = action();
    action.target = ResolvedFaultTarget::NetworkMedium {
        medium: id("test-medium"),
        resource: id("test-channel"),
    };
    action.effect = Arc::new(
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::SharedMedium {
                resources,
                policy,
                transmit_power_femtowatts: positive(power),
            }),
        )
        .unwrap_or_else(|error| panic!("test shared-medium effect: {error}")),
    );
    action
}

fn medium_opportunity(producer: &str, sequence: u64, payload: &[u8]) -> FaultOpportunity {
    FaultOpportunity::new(
        ResolvedFaultTarget::NetworkMedium {
            medium: id("test-medium"),
            resource: id("test-channel"),
        },
        crucible::model::FaultOperation::NetworkTraverse,
        FaultPhase::Queue,
        FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        sequence,
        Some(crucible::model::FaultDirection::AToB),
        OpportunityPayload::NetworkFrame {
            producer: id(producer),
            destination: id("receiver"),
            producer_sequence: sequence,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: Vec::new(),
            length_bytes: u64::try_from(payload.len())
                .unwrap_or_else(|error| panic!("test payload length: {error}")),
            payload_digest: ContentHash::from_bytes(payload),
        },
    )
    .unwrap_or_else(|error| panic!("test medium opportunity: {error}"))
}

fn medium_topology(
    policy_id: FaultObjectId,
    policy: crucible::model::NetworkPolicyMediumAccess,
    additional: Vec<crucible::model::WorldNetworkPolicyArtifact>,
) -> crucible::model::WorldFaultTopology {
    let mut topology = crucible::model::WorldFaultTopology::default();
    topology
        .network_policy_artifacts
        .push(crucible::model::WorldNetworkPolicyArtifact {
            id: policy_id,
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::MediumAccess(policy),
        });
    topology.network_policy_artifacts.extend(additional);
    topology
        .network_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    topology
}

fn medium_policy(
    arbitration: crucible::model::NetworkPolicyArbitration,
    collision: crucible::model::NetworkPolicyCollision,
) -> crucible::model::NetworkPolicyMediumAccess {
    crucible::model::NetworkPolicyMediumAccess {
        arbitration,
        arbitration_key: None,
        fixed_slot_nanos: None,
        contention: (arbitration == crucible::model::NetworkPolicyArbitration::Contention)
            .then_some(crucible::model::NetworkPolicyContention {
                collision,
                capture_threshold_millionths: (collision
                    == crucible::model::NetworkPolicyCollision::Capture)
                    .then_some(positive(1_000_000)),
                undetected_transform: None,
                backoff_slot_nanos: positive(100),
                maximum_backoff_exponent: 8,
                maximum_retries: 0,
            }),
        duty_cycle_numerator: positive(1),
        duty_cycle_denominator: positive(1),
    }
}

fn pending_medium_frame(
    opportunity: &FaultOpportunity,
    release: u64,
    effects: crucible::ResolvedNetworkFrameEffects,
    payload: Vec<u8>,
) -> crucible::BackendNetworkOutput {
    let OpportunityPayload::NetworkFrame {
        producer,
        destination,
        producer_sequence,
        ..
    } = opportunity.payload()
    else {
        panic!("test medium opportunity must carry a frame");
    };
    let mut continuation = crucible::BackendNetworkFaultContinuation::default();
    continuation
        .cursor_mut()
        .defer_until(release, opportunity.id());
    continuation.set_resolved_frame_effects(effects);
    crucible::BackendNetworkOutput {
        source: crucible::NodeId {
            name: producer.as_str().to_owned(),
        },
        destination: crucible::NodeId {
            name: destination.as_str().to_owned(),
        },
        emit_icount: crucible::Icount { retired: 0 },
        sequence: *producer_sequence,
        payload,
        route: None,
        fault_continuation: continuation,
    }
}

#[test]
fn shared_medium_serial_arbitration_reschedules_by_declared_order() {
    let resources = crucible::model::ObjectIdSet::new(vec![id("sender-a"), id("sender-b")])
        .unwrap_or_else(|error| panic!("test medium resources: {error}"));
    for arbitration in [
        crucible::model::NetworkPolicyArbitration::Fifo,
        crucible::model::NetworkPolicyArbitration::StrictPriority,
        crucible::model::NetworkPolicyArbitration::CanDominantBit,
    ] {
        let policy_id = id("serial-medium-policy");
        let key_id = id("medium-arbitration-key");
        let mut policy = medium_policy(
            arbitration,
            crucible::model::NetworkPolicyCollision::DropAll,
        );
        let additional = if arbitration == crucible::model::NetworkPolicyArbitration::Fifo {
            Vec::new()
        } else {
            policy.arbitration_key = Some(key_id.clone());
            vec![crucible::model::WorldNetworkPolicyArtifact {
                id: key_id,
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::PacketKey {
                    ranges: vec![
                        crucible::model::ByteRange::new(0, 1)
                            .unwrap_or_else(|error| panic!("test packet key: {error}")),
                    ],
                },
            }]
        };
        let topology = medium_topology(policy_id.clone(), policy, additional);
        let action = medium_action(resources.clone(), policy_id, 1);
        let first_opportunity = medium_opportunity("sender-a", 1, &[0xff]);
        let mut first_payload = vec![0xff];
        let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut state = NetworkEffectRuntimeState::default();
        let first_release = apply_network_shared_medium(
            &mut first_payload,
            &mut first_effects,
            &mut state,
            &mut [],
            &topology,
            &action,
            &first_opportunity,
            ContentHash::from_bytes(b"serial-medium"),
            &resources,
            &id("serial-medium-policy"),
            1,
            Some(1_000_000_000),
        )
        .unwrap_or_else(|error| panic!("first serial contender: {error}"))
        .unwrap_or_else(|| panic!("first serial contender must defer"));
        assert_eq!(first_release, 8);
        let mut pending = vec![pending_medium_frame(
            &first_opportunity,
            first_release,
            first_effects,
            first_payload,
        )];
        let second_opportunity = medium_opportunity("sender-b", 2, &[0x00]);
        let mut second_payload = vec![0x00];
        let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
        let second_release = apply_network_shared_medium(
            &mut second_payload,
            &mut second_effects,
            &mut state,
            &mut pending,
            &topology,
            &action,
            &second_opportunity,
            ContentHash::from_bytes(b"serial-medium"),
            &resources,
            &id("serial-medium-policy"),
            1,
            Some(1_000_000_000),
        )
        .unwrap_or_else(|error| panic!("second serial contender: {error}"))
        .unwrap_or_else(|| panic!("second serial contender must defer"));
        if arbitration == crucible::model::NetworkPolicyArbitration::Fifo {
            assert_eq!(second_release, 16);
            assert_eq!(pending[0].fault_continuation.cursor().not_before_nanos(), 8);
        } else {
            assert_eq!(second_release, 8);
            assert_eq!(
                pending[0].fault_continuation.cursor().not_before_nanos(),
                16
            );
        }
        assert!(second_effects.serialization_is_accounted());
    }
}

#[test]
fn shared_medium_fixed_slots_follow_canonical_resource_order() {
    let resources = crucible::model::ObjectIdSet::new(vec![id("sender-b"), id("sender-a")])
        .unwrap_or_else(|error| panic!("test medium resources: {error}"));
    let policy_id = id("fixed-medium-policy");
    let mut policy = medium_policy(
        crucible::model::NetworkPolicyArbitration::FixedSlots,
        crucible::model::NetworkPolicyCollision::DropAll,
    );
    policy.fixed_slot_nanos = Some(positive(10));
    let topology = medium_topology(policy_id.clone(), policy, Vec::new());
    let action = medium_action(resources.clone(), policy_id.clone(), 1);
    let mut state = NetworkEffectRuntimeState::default();
    let mut pending = Vec::new();
    let mut releases = Vec::new();
    for (producer, sequence) in [("sender-a", 1), ("sender-b", 2)] {
        let opportunity = medium_opportunity(producer, sequence, &[0]);
        let mut payload = vec![0];
        let mut effects = crucible::ResolvedNetworkFrameEffects::default();
        releases.push(
            apply_network_shared_medium(
                &mut payload,
                &mut effects,
                &mut state,
                &mut pending,
                &topology,
                &action,
                &opportunity,
                ContentHash::from_bytes(b"fixed-medium"),
                &resources,
                &policy_id,
                1,
                Some(1_000_000_000),
            )
            .unwrap_or_else(|error| panic!("fixed-slot contender: {error}"))
            .unwrap_or_else(|| panic!("fixed-slot contender must defer")),
        );
    }
    assert_eq!(releases, vec![8, 18]);
}

#[test]
fn shared_medium_contention_retries_and_terminal_outcomes_are_exact() {
    let resources = crucible::model::ObjectIdSet::new(vec![id("sender-a"), id("sender-b")])
        .unwrap_or_else(|error| panic!("test medium resources: {error}"));
    let scenario_seed = ContentHash::from_bytes(b"contention-medium");
    let policy_id = id("contention-medium-policy");
    let mut retry_policy = medium_policy(
        crucible::model::NetworkPolicyArbitration::Contention,
        crucible::model::NetworkPolicyCollision::DropAll,
    );
    retry_policy
        .contention
        .as_mut()
        .unwrap_or_else(|| panic!("test contention policy must exist"))
        .maximum_retries = 1;
    let topology = medium_topology(policy_id.clone(), retry_policy, Vec::new());
    let action = medium_action(resources.clone(), policy_id.clone(), 1);
    let first_opportunity = medium_opportunity("sender-a", 1, &[1]);
    let mut first_payload = vec![1];
    let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let first_release = apply_network_shared_medium(
        &mut first_payload,
        &mut first_effects,
        &mut state,
        &mut [],
        &topology,
        &action,
        &first_opportunity,
        scenario_seed,
        &resources,
        &policy_id,
        1,
        Some(1_000_000_000),
    )
    .unwrap_or_else(|error| panic!("first contention frame: {error}"))
    .unwrap_or_else(|| panic!("first contention frame must defer"));
    let mut pending = vec![pending_medium_frame(
        &first_opportunity,
        first_release,
        first_effects,
        first_payload,
    )];
    let (second_opportunity, expected_slot) = (2_u64..=256)
        .find_map(|sequence| {
            let opportunity = medium_opportunity("sender-b", sequence, &[2]);
            let slot = uniform_inclusive(
                network_effect_draw(scenario_seed, &opportunity, &action, "medium-backoff", 1),
                1,
            );
            (slot == 1).then_some((opportunity, slot))
        })
        .unwrap_or_else(|| panic!("test must find a nonzero keyed backoff"));
    let mut second_payload = vec![2];
    let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
    let second_release = apply_network_shared_medium(
        &mut second_payload,
        &mut second_effects,
        &mut state,
        &mut pending,
        &topology,
        &action,
        &second_opportunity,
        scenario_seed,
        &resources,
        &policy_id,
        1,
        Some(1_000_000_000),
    )
    .unwrap_or_else(|error| panic!("retried contention frame: {error}"))
    .unwrap_or_else(|| panic!("retried contention frame must defer"));
    assert_eq!(expected_slot, 1);
    assert_eq!(second_release, 108);
    assert!(!second_effects.is_dropped());
    assert!(
        !pending[0]
            .fault_continuation
            .resolved_frame_effects()
            .is_dropped()
    );

    for collision in [
        crucible::model::NetworkPolicyCollision::DropAll,
        crucible::model::NetworkPolicyCollision::Capture,
        crucible::model::NetworkPolicyCollision::UndetectedTransform,
    ] {
        let policy_id = id("terminal-medium-policy");
        let transform_id = id("collision-transform");
        let mut policy = medium_policy(
            crucible::model::NetworkPolicyArbitration::Contention,
            collision,
        );
        if let Some(contention) = policy.contention.as_mut() {
            contention.capture_threshold_millionths = (collision
                == crucible::model::NetworkPolicyCollision::Capture)
                .then_some(positive(1_500_000));
        }
        let additional =
            if collision == crucible::model::NetworkPolicyCollision::UndetectedTransform {
                policy
                    .contention
                    .as_mut()
                    .unwrap_or_else(|| panic!("test contention policy must exist"))
                    .undetected_transform = Some(transform_id.clone());
                vec![crucible::model::WorldNetworkPolicyArtifact {
                    id: transform_id,
                    semantic_version: 1,
                    artifact: crucible::model::NetworkPolicyArtifactKind::ByteTemplate {
                        bytes: vec![0xff],
                    },
                }]
            } else {
                Vec::new()
            };
        let topology = medium_topology(policy_id.clone(), policy, additional);
        let action = medium_action(resources.clone(), policy_id.clone(), 2);
        let first_opportunity = medium_opportunity("sender-a", 1, &[0x0f]);
        let mut first_payload = vec![0x0f];
        let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut state = NetworkEffectRuntimeState::default();
        let release = apply_network_shared_medium(
            &mut first_payload,
            &mut first_effects,
            &mut state,
            &mut [],
            &topology,
            &action,
            &first_opportunity,
            scenario_seed,
            &resources,
            &policy_id,
            1,
            Some(1_000_000_000),
        )
        .unwrap_or_else(|error| panic!("terminal first frame: {error}"))
        .unwrap_or_else(|| panic!("terminal first frame must defer"));
        let mut pending = vec![pending_medium_frame(
            &first_opportunity,
            release,
            first_effects,
            first_payload,
        )];
        let second_opportunity = medium_opportunity("sender-b", 2, &[0xf0]);
        let mut second_payload = vec![0xf0];
        let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
        apply_network_shared_medium(
            &mut second_payload,
            &mut second_effects,
            &mut state,
            &mut pending,
            &topology,
            &action,
            &second_opportunity,
            scenario_seed,
            &resources,
            &policy_id,
            2,
            Some(1_000_000_000),
        )
        .unwrap_or_else(|error| panic!("terminal second frame: {error}"));
        match collision {
            crucible::model::NetworkPolicyCollision::DropAll => {
                assert!(second_effects.is_dropped());
                assert!(
                    pending[0]
                        .fault_continuation
                        .resolved_frame_effects()
                        .is_dropped()
                );
            }
            crucible::model::NetworkPolicyCollision::Capture => {
                assert!(!second_effects.is_dropped());
                assert!(
                    pending[0]
                        .fault_continuation
                        .resolved_frame_effects()
                        .is_dropped()
                );
            }
            crucible::model::NetworkPolicyCollision::UndetectedTransform => {
                assert_eq!(second_payload, vec![0x0f]);
                assert_eq!(pending[0].payload, vec![0xf0]);
            }
        }
    }
}

fn ethernet_ipv4_frame(data: &[u8], flags_offset: u16) -> Vec<u8> {
    const ETHERNET_HEADER: usize = 14;
    const IPV4_HEADER: usize = 20;
    let total_length = u16::try_from(IPV4_HEADER + data.len())
        .unwrap_or_else(|error| panic!("test IPv4 packet length: {error}"));
    let mut frame = vec![0_u8; ETHERNET_HEADER + IPV4_HEADER];
    frame[0..6].copy_from_slice(&[0, 1, 2, 3, 4, 5]);
    frame[6..12].copy_from_slice(&[6, 7, 8, 9, 10, 11]);
    frame[12..14].copy_from_slice(&[0x08, 0x00]);
    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&total_length.to_be_bytes());
    frame[18..20].copy_from_slice(&0x1234_u16.to_be_bytes());
    frame[20..22].copy_from_slice(&flags_offset.to_be_bytes());
    frame[22] = 64;
    frame[23] = 17;
    frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
    frame[30..34].copy_from_slice(&[198, 51, 100, 2]);
    frame.extend_from_slice(data);
    frame
}

#[test]
fn forwarding_mutations_use_selectors_canonical_recipients_and_hop_limits() {
    let selector = id("forwarding-selector");
    let mut topology = crucible::model::WorldFaultTopology::default();
    topology
        .network_policy_artifacts
        .push(crucible::model::WorldNetworkPolicyArtifact {
            id: selector.clone(),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::PacketSelector {
                matches: vec![crucible::model::NetworkPolicyByteMatch {
                    offset_bytes: 0,
                    value: vec![0xaa],
                    mask: vec![0xff],
                }],
            },
        });
    let recipients = crucible::model::ObjectIdSet::new(vec![id("receiver-b"), id("receiver-a")])
        .unwrap_or_else(|error| panic!("test recipients: {error}"));
    let flood = action_with_network_effect(NetworkEffectSpecification::ForwardingMutation {
        selector: selector.clone(),
        mutation: crucible::model::NetworkForwardingMutationKind::Flood { recipients },
    });
    let mut payload = vec![0xaa];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let application = apply_network_frame_actions(
        &mut payload,
        &mut effects,
        &[flood],
        &opportunity(1),
        ContentHash::from_bytes(b"forwarding"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("flood mutation: {error}"));
    assert_eq!(
        application.forwarding_recipients,
        Some(vec![id("receiver-a"), id("receiver-b")])
    );
    assert!(effects.is_dropped());

    let loop_action = action_with_network_effect(NetworkEffectSpecification::ForwardingMutation {
        selector,
        mutation: crucible::model::NetworkForwardingMutationKind::Loop {
            next_hop: id("receiver-a"),
            hop_limit: positive(1),
        },
    });
    let exhausted = FaultOpportunity::new(
        loop_action.target.clone(),
        crucible::model::FaultOperation::NetworkTraverse,
        FaultPhase::Resolve,
        FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        2,
        Some(crucible::model::FaultDirection::AToB),
        OpportunityPayload::NetworkFrame {
            producer: id("sender"),
            destination: id("receiver"),
            producer_sequence: 2,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: vec![ContentHash::from_bytes(b"prior-hop")],
            length_bytes: 1,
            payload_digest: ContentHash::from_bytes(&payload),
        },
    )
    .unwrap_or_else(|error| panic!("loop opportunity: {error}"));
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let application = apply_network_frame_actions(
        &mut payload,
        &mut effects,
        &[loop_action],
        &exhausted,
        ContentHash::from_bytes(b"forwarding"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("loop mutation: {error}"));
    assert_eq!(application.forwarding_recipients, Some(Vec::new()));
    assert!(effects.is_dropped());
}

#[test]
fn firewall_and_connection_state_are_bounded_exhaustive_and_timed() {
    let selector = id("stateful-selector");
    let key = id("flow-key");
    let machine = id("flow-machine");
    let event = id("packet-event");
    let transition = |from: &str, to: &str, delay_nanos| crucible::model::NetworkPolicyTransition {
        from: id(from),
        event: event.clone(),
        to: id(to),
        delay_nanos,
        traffic_policy: crucible::model::NetworkInFlightPolicy::Preserve,
    };
    let mut topology = crucible::model::WorldFaultTopology {
        network_policy_artifacts: vec![
            crucible::model::WorldNetworkPolicyArtifact {
                id: selector.clone(),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::PacketSelector {
                    matches: vec![crucible::model::NetworkPolicyByteMatch {
                        offset_bytes: 0,
                        value: vec![0xaa],
                        mask: vec![0xff],
                    }],
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: key.clone(),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::PacketKey {
                    ranges: vec![
                        crucible::model::ByteRange::new(0, 1)
                            .unwrap_or_else(|error| panic!("test packet key: {error}")),
                    ],
                },
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: machine.clone(),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::StateMachine {
                    initial: id("cold"),
                    states: vec![id("cold"), id("warm")],
                    transitions: vec![
                        transition("cold", "warm", 10),
                        transition("warm", "warm", 10),
                    ],
                },
            },
        ],
        ..Default::default()
    };
    topology
        .network_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    let firewall = action_with_network_effect(NetworkEffectSpecification::FirewallDisposition {
        action: crucible::model::NetworkFirewallAction::Drop,
        typed_reject: None,
        rule: selector,
        state_machine: machine.clone(),
        transition_event: event.clone(),
    });
    let mut payload = vec![0xaa];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let application = apply_network_frame_actions(
        &mut payload,
        &mut effects,
        &[firewall],
        &opportunity(10),
        ContentHash::from_bytes(b"stateful"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("firewall state: {error}"));
    assert!(effects.is_dropped());
    assert_eq!(application.next_wakeup_nanos, Some(10));
    assert_eq!(state.state_machines.len(), 1);

    let bound = crucible::model::BoundedCount::new(CountLimit::LargeStateEntries, 1)
        .unwrap_or_else(|error| panic!("test table bound: {error}"));
    let connection = action_with_network_effect(NetworkEffectSpecification::ConnectionState {
        kind: crucible::model::NetworkConnectionKind::Conntrack,
        table_bound: bound,
        flow_key: key,
        state_machine: machine,
        transition_event: event,
        overflow: crucible::model::NetworkConnectionOverflow::DropNewest,
    });
    let mut first = vec![0xaa];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    apply_network_frame_actions(
        &mut first,
        &mut effects,
        std::slice::from_ref(&connection),
        &opportunity(11),
        ContentHash::from_bytes(b"stateful"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("first connection: {error}"));
    assert!(!effects.is_dropped());
    let mut second = vec![0xbb];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    apply_network_frame_actions(
        &mut second,
        &mut effects,
        &[connection],
        &opportunity(12),
        ContentHash::from_bytes(b"stateful"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("overflow connection: {error}"));
    assert!(effects.is_dropped());
    assert_eq!(
        state
            .connection_tables
            .values()
            .map(BTreeMap::len)
            .sum::<usize>(),
        1
    );
}

#[test]
fn mtu_expansion_returns_real_child_frames_before_queue_service() {
    let mut action = action();
    action.phase = FaultPhase::Admit;
    action.effect = Arc::new(
        EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Persistent,
            EffectSpecification::Network(NetworkEffectSpecification::Mtu {
                mtu_bytes: positive(42),
                oversize: crucible::model::NetworkOversizeDisposition::Fragment,
                fragmentation_protocol: Some(
                    crucible::model::NetworkFragmentationProtocol::EthernetIpv4,
                ),
                typed_error: None,
            }),
        )
        .unwrap_or_else(|error| panic!("test MTU effect: {error}")),
    );
    let mut payload = ethernet_ipv4_frame(&(0_u8..40).collect::<Vec<_>>(), 0);
    let opportunity = FaultOpportunity::new(
        action.target.clone(),
        crucible::model::FaultOperation::NetworkTraverse,
        FaultPhase::Admit,
        FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        1,
        Some(crucible::model::FaultDirection::AToB),
        OpportunityPayload::NetworkFrame {
            producer: id("sender"),
            destination: id("receiver"),
            producer_sequence: 1,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: Vec::new(),
            length_bytes: u64::try_from(payload.len())
                .unwrap_or_else(|error| panic!("test frame length: {error}")),
            payload_digest: ContentHash::from_bytes(&payload),
        },
    )
    .unwrap_or_else(|error| panic!("test MTU opportunity: {error}"));
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let application = apply_network_frame_actions(
        &mut payload,
        &mut effects,
        std::slice::from_ref(&action),
        &opportunity,
        ContentHash::from_bytes(b"mtu-expansion"),
        &crucible::model::WorldFaultTopology::default(),
        &mut state,
        &mut Vec::new(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("MTU expansion: {error}"));
    assert_eq!(application.expanded_payloads.len(), 5);
    assert!(
        application
            .expanded_payloads
            .iter()
            .all(|fragment| fragment.len() <= 42)
    );
    assert!(state.queues.is_empty());
}

#[test]
fn detected_errors_execute_declared_retries_and_timed_link_reset() {
    let retry_count = |value| {
        crucible::model::BoundedCount::new(CountLimit::DuplicatesOrInstructionReplay, value)
            .unwrap_or_else(|error| panic!("test retry count: {error}"))
    };
    let retry = action_with_network_effect(NetworkEffectSpecification::DetectedFrameError {
        kind: crucible::model::DetectedFrameErrorKind::Crc,
        receiver_action: crucible::model::DetectedFrameErrorAction::Retry,
        retry_delay_nanos: Some(positive(10)),
        retry_limit: Some(retry_count(3)),
        retry_attempts: Some(retry_count(2)),
        retry_succeeds: Some(true),
        reset_nanos: None,
    });
    let opportunity = opportunity(1);
    let mut payload = vec![0_u8];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    apply_network_frame_action(
        &mut payload,
        &mut effects,
        &retry,
        &opportunity,
        ContentHash::from_bytes(b"retry-seed"),
        &crucible::model::WorldFaultTopology::default(),
        &mut state,
    )
    .unwrap_or_else(|error| panic!("retry effect: {error}"));
    assert_eq!(effects.additional_delay_nanos(), 20);
    assert!(!effects.is_dropped());

    let reset = action_with_network_effect(NetworkEffectSpecification::DetectedFrameError {
        kind: crucible::model::DetectedFrameErrorKind::FecUncorrectable,
        receiver_action: crucible::model::DetectedFrameErrorAction::LinkReset,
        retry_delay_nanos: None,
        retry_limit: None,
        retry_attempts: None,
        retry_succeeds: None,
        reset_nanos: Some(positive(50)),
    });
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    apply_network_frame_action(
        &mut payload,
        &mut effects,
        &reset,
        &opportunity,
        ContentHash::from_bytes(b"reset-seed"),
        &crucible::model::WorldFaultTopology::default(),
        &mut state,
    )
    .unwrap_or_else(|error| panic!("reset effect: {error}"));
    assert!(effects.is_dropped());
    assert_eq!(state.boundary.next_wakeup_nanos(0), Some(50));
    let mut during_reset = crucible::ResolvedNetworkFrameEffects::default();
    state
        .boundary
        .apply_frame(
            &reset.target,
            None,
            &crucible::model::WorldFaultTopology::default(),
            49,
            &mut during_reset,
        )
        .unwrap_or_else(|error| panic!("apply reset outage: {error}"));
    assert!(during_reset.is_dropped());
    let mut recovered = crucible::ResolvedNetworkFrameEffects::default();
    state
        .boundary
        .apply_frame(
            &reset.target,
            None,
            &crucible::model::WorldFaultTopology::default(),
            50,
            &mut recovered,
        )
        .unwrap_or_else(|error| panic!("apply recovered link: {error}"));
    assert!(!recovered.is_dropped());
}

#[test]
fn rf_channel_uses_geometry_tables_and_exact_sinr_profile() {
    let probability = crucible::model::ProbabilityMillionths::new(0)
        .unwrap_or_else(|error| panic!("zero probability should be valid: {error}"));
    let integer_table = |input_unit: &str, output| crucible::model::NetworkPolicyIntegerTable {
        input_unit: id(input_unit),
        output_unit: id("ratio-millionths"),
        interpolation: crucible::model::NetworkPolicyInterpolation::Step,
        outside: crucible::model::NetworkPolicyOutsideRange::Clamp,
        points: vec![crucible::model::NetworkPolicyIntegerPoint { input: 0, output }],
    };
    let profile = crucible::model::NetworkPolicyRfProfile {
        minimum_sinr: 0,
        rate_bps: positive(8_000),
        loss: probability,
        corruption: probability,
        corruption_action: crucible::model::NetworkPolicyRfCorruption::Corrected,
        maximum_retries: 0,
        retry_delay_nanos: 0,
    };
    let mut topology = crucible::model::WorldFaultTopology {
        network_policy_artifacts: vec![
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("propagation"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::RfPropagation(
                    crucible::model::NetworkPolicyRfPropagation {
                        path_gain_ratio: integer_table("millimetres", 500_000),
                        antenna_gain_ratio: integer_table("millidegrees", 1_000_000),
                        spatial_cell_mm: positive(1),
                        fading_bucket_nanos: positive(1),
                    },
                ),
            },
            crucible::model::WorldNetworkPolicyArtifact {
                id: id("transfer"),
                semantic_version: 1,
                artifact: crucible::model::NetworkPolicyArtifactKind::RfTransfer(
                    crucible::model::NetworkPolicyRfTransfer {
                        profiles: vec![profile],
                    },
                ),
            },
        ],
        ..Default::default()
    };
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Opportunity,
        EffectSpecification::Network(NetworkEffectSpecification::RfChannel {
            carrier_hz: positive(2_400_000_000),
            bandwidth_hz: positive(20_000_000),
            transmit_power_femtowatts: 100,
            receiver_noise_femtowatts: 10,
            propagation_fields: id("propagation"),
            sinr_transfer: id("transfer"),
        }),
    )
    .unwrap_or_else(|error| panic!("test RF effect should be valid: {error}"));
    let action = ResolvedBindingAction {
        kind: BindingActionKind::Apply,
        binding: id("rf-binding"),
        target: ResolvedFaultTarget::NetworkSegment {
            segment: id("network-test-segment"),
            direction: crucible::model::FaultDirection::AToB,
        },
        phase: FaultPhase::Resolve,
        effect: Arc::new(effect),
        mapping_output: Arc::new(ResolvedMappingOutput::ServiceProfile {
            service_profile: id("rf-inputs"),
            input_contracts: vec![
                crucible::model::ServiceProfileInput {
                    role: id("distance"),
                    shape: crucible::model::SignalShape {
                        value_type: crucible::model::SignalValueType::U64,
                        unit: crucible::model::SignalUnit::Millimetres,
                        scale_decimal_exponent: 0,
                    },
                },
                crucible::model::ServiceProfileInput {
                    role: id("orientation"),
                    shape: crucible::model::SignalShape {
                        value_type: crucible::model::SignalValueType::I64,
                        unit: crucible::model::SignalUnit::Millidegrees,
                        scale_decimal_exponent: 0,
                    },
                },
                crucible::model::ServiceProfileInput {
                    role: id("interference"),
                    shape: crucible::model::SignalShape {
                        value_type: crucible::model::SignalValueType::U64,
                        unit: crucible::model::SignalUnit::Femtowatts,
                        scale_decimal_exponent: 0,
                    },
                },
                crucible::model::ServiceProfileInput {
                    role: id("fading"),
                    shape: crucible::model::SignalShape {
                        value_type: crucible::model::SignalValueType::U64,
                        unit: crucible::model::SignalUnit::PartsPerMillion,
                        scale_decimal_exponent: 0,
                    },
                },
            ],
            inputs: vec![
                crucible::model::SignalValue::U64(10),
                crucible::model::SignalValue::I64(0),
                crucible::model::SignalValue::U64(5),
                crucible::model::SignalValue::U64(1_000_000),
            ],
        }),
        mapped_digest: ContentHash::from_bytes(b"rf-inputs"),
        transition_sequence: 1,
        opportunity: None,
        coordinate: FaultCoordinate {
            virtual_nanos: 0,
            retired_instructions: None,
        },
        cause: BindingActionCause::Signal,
    };
    let opportunity = FaultOpportunity::new(
        action.target.clone(),
        crucible::model::FaultOperation::NetworkTraverse,
        FaultPhase::Resolve,
        action.coordinate,
        1,
        Some(crucible::model::FaultDirection::AToB),
        OpportunityPayload::NetworkFrame {
            producer: id("sender"),
            destination: id("receiver"),
            producer_sequence: 1,
            protocol_expansion_path: Vec::new(),
            generated_response_depth: 0,
            generated_response_cause: None,
            forwarding_mutation_path: Vec::new(),
            length_bytes: 1,
            payload_digest: ContentHash::from_bytes(b"frame"),
        },
    )
    .unwrap_or_else(|error| panic!("test RF opportunity should be valid: {error}"));
    let mut payload = vec![0_u8];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    apply_network_frame_action(
        &mut payload,
        &mut effects,
        &action,
        &opportunity,
        ContentHash::from_bytes(b"scenario"),
        &topology,
        &mut state,
    )
    .unwrap_or_else(|error| panic!("RF effect should execute: {error}"));
    assert_eq!(effects.serialization_rate_cap_bps(), Some(8_000));
    assert!(!effects.is_dropped());

    let always = crucible::model::ProbabilityMillionths::new(1_000_000)
        .unwrap_or_else(|error| panic!("certain probability: {error}"));
    let transfer = topology
        .network_policy_artifacts
        .iter_mut()
        .find(|artifact| artifact.id == id("transfer"))
        .unwrap_or_else(|| panic!("test transfer artifact"));
    let crucible::model::NetworkPolicyArtifactKind::RfTransfer(transfer) = &mut transfer.artifact
    else {
        panic!("test transfer type")
    };
    transfer.profiles[0].loss = always;
    transfer.profiles[0].maximum_retries = 2;
    transfer.profiles[0].retry_delay_nanos = 7;
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    apply_network_frame_action(
        &mut payload,
        &mut effects,
        &action,
        &opportunity,
        ContentHash::from_bytes(b"scenario"),
        &topology,
        &mut state,
    )
    .unwrap_or_else(|error| panic!("RF retry exhaustion: {error}"));
    assert_eq!(effects.additional_delay_nanos(), 14);
    assert!(effects.is_dropped());

    topology
        .network_policy_artifacts
        .push(crucible::model::WorldNetworkPolicyArtifact {
            id: id("rf-xor"),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::ByteTemplate {
                bytes: vec![0xff],
            },
        });
    topology
        .network_policy_artifacts
        .sort_by(|left, right| left.id.cmp(&right.id));
    let transfer = topology
        .network_policy_artifacts
        .iter_mut()
        .find(|artifact| artifact.id == id("transfer"))
        .unwrap_or_else(|| panic!("test transfer artifact"));
    let crucible::model::NetworkPolicyArtifactKind::RfTransfer(transfer) = &mut transfer.artifact
    else {
        panic!("test transfer type")
    };
    transfer.profiles[0].loss = probability;
    transfer.profiles[0].corruption = always;
    transfer.profiles[0].corruption_action =
        crucible::model::NetworkPolicyRfCorruption::Undetected {
            transform: id("rf-xor"),
        };
    transfer.profiles[0].maximum_retries = 0;
    let mut payload = vec![0x0f, 0xf0];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    apply_network_frame_action(
        &mut payload,
        &mut effects,
        &action,
        &opportunity,
        ContentHash::from_bytes(b"scenario"),
        &topology,
        &mut state,
    )
    .unwrap_or_else(|error| panic!("RF undetected corruption: {error}"));
    assert_eq!(payload, vec![0xf0, 0x0f]);
    assert!(!effects.is_dropped());
}

fn reservation(class: &str, sequence: u64, bytes: u64) -> NetworkQueueReservation {
    NetworkQueueReservation {
        enqueue_nanos: 0,
        base_ready_nanos: 0,
        ready_nanos: 0,
        service_start_nanos: 0,
        finish_nanos: 0,
        bytes,
        payload_bits: bytes * 8,
        remaining_nano_bits: u128::from(bytes) * 8 * 1_000_000_000,
        base_rate_bps: Some(1_000_000),
        service_curves: Vec::new(),
        class: Some(id(class)),
        opportunity: ContentHash::from_bytes(&sequence.to_be_bytes()),
    }
}

fn queue_parameters() -> crucible::model::NetworkPolicyQueueDiscipline {
    crucible::model::NetworkPolicyQueueDiscipline {
        classes: vec![
            crucible::model::NetworkPolicyQueueClass {
                class: id("high"),
                selector: id("high-selector"),
                priority: 0,
                weight: positive(3),
                quantum_bytes: positive(1_500),
            },
            crucible::model::NetworkPolicyQueueClass {
                class: id("low"),
                selector: id("low-selector"),
                priority: 10,
                weight: positive(1),
                quantum_bytes: positive(500),
            },
        ],
        red_minimum_bytes: None,
        red_maximum_bytes: None,
        red_maximum_probability: None,
        red_weight_numerator: None,
        red_weight_denominator: None,
    }
}

#[test]
fn service_curve_integrates_across_rate_changes() {
    let curves = vec![NetworkServiceCurveState {
        activation_nanos: 0,
        segments: vec![
            crucible::model::NetworkServiceSegment {
                at_nanos: 0,
                rate_bps: positive(8),
            },
            crucible::model::NetworkServiceSegment {
                at_nanos: 500_000_000,
                rate_bps: positive(16),
            },
        ],
    }];
    let finish = network_service_finish(0, 8, None, &curves, &action())
        .unwrap_or_else(|error| panic!("service integration should succeed: {error}"));
    assert_eq!(finish, 750_000_000);
}

#[test]
fn queue_reschedule_preserves_exact_partially_served_work() {
    let action = action();
    let mut queued = reservation("high", 1, 1);
    queued.base_rate_bps = Some(8);
    queued.service_start_nanos = 0;
    queued.finish_nanos = 1_000_000_000;
    let mut queue = NetworkQueueState {
        configuration: Some(NetworkQueueConfiguration {
            owner: NetworkEffectStateKey::from_action(&action),
            discipline: crucible::model::NetworkQueueDiscipline::Fifo,
            discipline_parameters: None,
        }),
        reservations: vec![queued],
        ..NetworkQueueState::default()
    };
    reschedule_network_queue(
        &mut queue,
        &mut [],
        &action,
        crucible::model::NetworkQueueDiscipline::Fifo,
        None,
        500_000_000,
        None,
    )
    .unwrap_or_else(|error| panic!("partial queue reschedule: {error}"));
    assert_eq!(queue.reservations[0].remaining_nano_bits, 4_000_000_000);
    assert_eq!(queue.reservations[0].service_start_nanos, 500_000_000);
    assert_eq!(queue.reservations[0].finish_nanos, 1_000_000_000);
}

#[test]
fn class_backpressure_preempts_without_blocking_ready_siblings() {
    let owner = action();
    let parameters_id = id("queue-parameters");
    let mut topology = crucible::model::WorldFaultTopology::default();
    topology
        .network_policy_artifacts
        .push(crucible::model::WorldNetworkPolicyArtifact {
            id: parameters_id.clone(),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::QueueDiscipline(
                queue_parameters(),
            ),
        });
    let mut high = reservation("high", 1, 1);
    high.finish_nanos = 8_000;
    let mut low = reservation("low", 2, 1);
    low.service_start_nanos = 8_000;
    low.finish_nanos = 16_000;
    let mut state = NetworkEffectRuntimeState::default();
    state.queues.insert(
        owner.target.clone(),
        NetworkQueueState {
            configuration: Some(NetworkQueueConfiguration {
                owner: NetworkEffectStateKey::from_action(&owner),
                discipline: crucible::model::NetworkQueueDiscipline::StrictPriority,
                discipline_parameters: Some(parameters_id),
            }),
            reservations: vec![high, low],
            ..NetworkQueueState::default()
        },
    );
    let pause = action_with_network_effect(NetworkEffectSpecification::PauseBackpressure {
        class: id("high"),
        pause_nanos: Some(positive(100)),
    });
    let wakeup =
        apply_network_backpressure_transitions(&mut state, &mut [], &[pause], &topology, 0)
            .unwrap_or_else(|error| panic!("apply class pause: {error}"));
    assert_eq!(wakeup, Some(100));
    let queue = state
        .queues
        .get(&owner.target)
        .unwrap_or_else(|| panic!("test queue should remain"));
    assert_eq!(queue.reservations[0].class.as_ref(), Some(&id("low")));
    assert_eq!(queue.reservations[1].ready_nanos, 100);
}

#[test]
fn token_bucket_preserves_ceil_surplus_without_rate_bias() {
    let action = action();
    let mut state = NetworkEffectRuntimeState::default();
    let mut release = 0;
    for sequence in 0..3 {
        release =
            apply_network_token_bucket(&mut state, &action, &opportunity(sequence), 1, 3, 8, 0)
                .unwrap_or_else(|error| panic!("token service should succeed: {error}"));
    }
    assert_eq!(release, 8_000_000_000);
}

#[test]
fn class_queue_comparators_use_priority_weight_and_quantum() {
    let parameters = queue_parameters();
    let high = reservation("high", 1, 1_500);
    let low = reservation("low", 2, 500);
    assert_eq!(
        compare_queue_candidates(
            &high,
            &low,
            crucible::model::NetworkQueueDiscipline::StrictPriority,
            Some(&parameters),
            &BTreeMap::new(),
            &BTreeMap::new(),
        ),
        std::cmp::Ordering::Less
    );

    let projected_frames = BTreeMap::from([(id("high"), 3), (id("low"), 0)]);
    assert_eq!(
        compare_queue_candidates(
            &low,
            &high,
            crucible::model::NetworkQueueDiscipline::WeightedRoundRobin,
            Some(&parameters),
            &projected_frames,
            &BTreeMap::new(),
        ),
        std::cmp::Ordering::Less
    );

    let projected_bytes = BTreeMap::from([(id("high"), 4_500), (id("low"), 0)]);
    assert_eq!(
        compare_queue_candidates(
            &low,
            &high,
            crucible::model::NetworkQueueDiscipline::DeficitRoundRobin,
            Some(&parameters),
            &BTreeMap::new(),
            &projected_bytes,
        ),
        std::cmp::Ordering::Less
    );
}

fn custody_topology(
    disposition: crucible::model::NetworkPolicyOverflow,
    contact_start: u64,
) -> crucible::model::WorldFaultTopology {
    let timeout_nanos =
        (disposition == crucible::model::NetworkPolicyOverflow::Timeout).then_some(positive(25));
    let typed_error = (disposition == crucible::model::NetworkPolicyOverflow::TypedError)
        .then_some(id("custody-reject"));
    let mut artifacts = vec![
        crucible::model::WorldNetworkPolicyArtifact {
            id: id("contact-capacity"),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::ServiceCurve {
                segments: crucible::model::NetworkServiceSegments::new(vec![
                    crucible::model::NetworkServiceSegment {
                        at_nanos: 0,
                        rate_bps: positive(8_000_000_000),
                    },
                ])
                .unwrap_or_else(|error| panic!("contact service curve: {error}")),
            },
        },
        crucible::model::WorldNetworkPolicyArtifact {
            id: id("contact-plan"),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::ContactPlan {
                intervals: vec![crucible::model::NetworkPolicyContactInterval {
                    contact: id("contact-a"),
                    service_resource: id("resource-a"),
                    route_cost: positive(1),
                    routing_propagation_nanos: 1,
                    start_nanos: contact_start,
                    end_nanos: contact_start + 100,
                    source: id("sender"),
                    destination: id("receiver"),
                    beam: id("beam-a"),
                    gateway: id("gateway-a"),
                    minimum_range_mm: 1,
                    maximum_range_mm: 2,
                    capacity_profile: id("contact-capacity"),
                    acquisition_nanos: 10,
                    teardown_nanos: 10,
                    confidence: crucible::model::ProbabilityMillionths::new(1_000_000)
                        .unwrap_or_else(|error| panic!("contact confidence: {error}")),
                    provenance: id("contact-test"),
                }],
            },
        },
        crucible::model::WorldNetworkPolicyArtifact {
            id: id("custody-policy"),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::Overflow {
                disposition,
                timeout_nanos,
                typed_error,
            },
        },
    ];
    if disposition == crucible::model::NetworkPolicyOverflow::TypedError {
        artifacts.push(crucible::model::WorldNetworkPolicyArtifact {
            id: id("custody-reject"),
            semantic_version: 1,
            artifact: crucible::model::NetworkPolicyArtifactKind::TypedResponse(
                crucible::model::NetworkPolicyTypedResponseSet {
                    responses: vec![crucible::model::NetworkPolicyTypedResponse {
                        response: crucible::model::NetworkPolicyTypedResponseKind::TcpReset,
                        headers: crucible::model::NetworkPolicyResponseHeaders {
                            source_mac: None,
                            source_ipv4: None,
                            source_ipv6: None,
                            hop_limit: 64,
                            ipv4_identification: 1,
                            delay_nanos: None,
                        },
                    }],
                    unmatched: crucible::model::NetworkPolicyUnmatchedResponse::Suppress,
                },
            ),
        });
    }
    artifacts.sort_by(|left, right| left.id.cmp(&right.id));
    crucible::model::WorldFaultTopology {
        network_policy_artifacts: artifacts,
        ..crucible::model::WorldFaultTopology::default()
    }
}

fn custody_action() -> ResolvedBindingAction {
    action_with_network_effect(NetworkEffectSpecification::CustodyQueue {
        capacity_bytes: positive(1),
        capacity_bundles: crucible::model::BoundedCount::new(CountLimit::LargeStateEntries, 1)
            .unwrap_or_else(|error| panic!("custody bundle capacity: {error}")),
        expiry_nanos: positive(1_000),
        custody_policy: id("custody-policy"),
        route_contact_plan: id("contact-plan"),
        priority: crucible::model::NetworkBundlePriority::Normal,
        max_visited_hops: crucible::model::BoundedCount::new(
            CountLimit::DuplicatesOrInstructionReplay,
            8,
        )
        .unwrap_or_else(|error| panic!("custody hop bound: {error}")),
    })
}

fn opportunity_at(sequence: u64, now: u64) -> FaultOpportunity {
    let mut opportunity = opportunity(sequence);
    opportunity = FaultOpportunity::new(
        opportunity.target().clone(),
        opportunity.operation(),
        opportunity.phase(),
        FaultCoordinate {
            virtual_nanos: now,
            retired_instructions: None,
        },
        sequence,
        opportunity.direction(),
        opportunity.payload().clone(),
    )
    .unwrap_or_else(|error| panic!("coordinate-adjusted opportunity: {error}"));
    opportunity
}

fn pending_custody_frame(
    opportunity: &FaultOpportunity,
    release_nanos: u64,
) -> crucible::BackendNetworkOutput {
    let mut continuation = crucible::BackendNetworkFaultContinuation::default();
    continuation
        .cursor_mut()
        .defer_until(release_nanos, opportunity.id());
    let sequence = match opportunity.payload() {
        OpportunityPayload::NetworkFrame {
            producer_sequence, ..
        } => *producer_sequence,
        _ => panic!("test custody opportunity must be a frame"),
    };
    crucible::BackendNetworkOutput {
        source: crucible::NodeId {
            name: String::from("sender"),
        },
        destination: crucible::NodeId {
            name: String::from("logical-router"),
        },
        emit_icount: crucible::Icount { retired: 0 },
        sequence,
        payload: vec![u8::try_from(sequence).unwrap_or(0)],
        route: Some(crucible::BackendNetworkRoute {
            link: crucible::LinkId::from_name("custody-test-link"),
            direction: crucible::device::NetworkLinkDirection::EndpointAToEndpointB,
            destination: crucible::NodeId {
                name: String::from("receiver"),
            },
        }),
        fault_continuation: continuation,
    }
}

#[test]
fn custody_waits_for_contact_then_conserves_shared_capacity() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let action = custody_action();
    let mut state = NetworkEffectRuntimeState::default();
    let mut pending = Vec::new();
    let mut typed_response = None;
    let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
    let waiting = apply_network_custody_queue(
        &[1],
        &mut first_effects,
        &mut state,
        &mut pending,
        &topology,
        &action,
        &opportunity_at(1, 0),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("queue before contact: {error}"));
    assert_eq!(waiting.defer_until, Some(110));
    assert!(waiting.repeat_phase_on_resume);

    let service = apply_network_custody_queue(
        &[1],
        &mut first_effects,
        &mut state,
        &mut pending,
        &topology,
        &action,
        &opportunity_at(1, 110),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("reserve at contact: {error}"));
    assert_eq!(service.defer_until, Some(112));
    assert_eq!(first_effects.additional_delay_nanos(), 0);
    assert_eq!(first_effects.accounted_contact_services().len(), 1);
    let released = apply_network_custody_queue(
        &[1],
        &mut first_effects,
        &mut state,
        &mut pending,
        &topology,
        &action,
        &opportunity_at(1, 112),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("release after propagation: {error}"));
    assert_eq!(released.defer_until, None);

    let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
    let second = apply_network_custody_queue(
        &[2],
        &mut second_effects,
        &mut state,
        &mut pending,
        &topology,
        &action,
        &opportunity_at(2, 112),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("second contact reservation: {error}"));
    assert_eq!(second.defer_until, Some(114));
    apply_network_custody_queue(
        &[2],
        &mut second_effects,
        &mut state,
        &mut pending,
        &topology,
        &action,
        &opportunity_at(2, 114),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("second contact release: {error}"));
    assert_eq!(second_effects.additional_delay_nanos(), 0);
    let queue = state
        .custody_queues
        .get(&NetworkEffectStateKey::from_action(&action))
        .unwrap_or_else(|| panic!("custody queue state"));
    assert_eq!(queue.released_bundles, 2);
    assert!(queue.reservations.is_empty());
}

#[test]
fn custody_selects_and_reserves_a_bounded_multihop_contact_route() {
    let mut topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let plan = topology
        .network_policy_artifacts
        .iter_mut()
        .find(|artifact| artifact.id == id("contact-plan"))
        .unwrap_or_else(|| panic!("contact plan"));
    let crucible::model::NetworkPolicyArtifactKind::ContactPlan { intervals } = &mut plan.artifact
    else {
        panic!("contact plan type")
    };
    let mut first = intervals[0].clone();
    first.contact = id("contact-a-relay");
    first.service_resource = id("radio-a-relay");
    first.destination = id("relay");
    first.route_cost = positive(1);
    let mut second = intervals[0].clone();
    second.contact = id("contact-b-receiver");
    second.service_resource = id("radio-b-receiver");
    second.start_nanos = 120;
    second.end_nanos = 220;
    second.source = id("relay");
    second.route_cost = positive(1);
    let mut direct = intervals[0].clone();
    direct.contact = id("contact-c-direct");
    direct.service_resource = id("radio-c-direct");
    direct.route_cost = positive(10);
    *intervals = vec![first, direct, second];

    let action = custody_action();
    let mut state = NetworkEffectRuntimeState::default();
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut response = None;
    let reserved = apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &opportunity_at(1, 0),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("reserve multihop route: {error}"));
    assert_eq!(reserved.defer_until, Some(110));
    assert!(effects.accounted_contact_services().is_empty());
    assert!(state.contact_services.is_empty());
    let reserved = apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &opportunity_at(1, 110),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("commit multihop route: {error}"));
    assert_eq!(reserved.defer_until, Some(132));
    assert_eq!(effects.accounted_contact_services().len(), 2);
    let queue = state
        .custody_queues
        .get(&NetworkEffectStateKey::from_action(&action))
        .unwrap_or_else(|| panic!("custody queue"));
    assert_eq!(
        queue.reservations[0].contact_path,
        vec![id("contact-a-relay"), id("contact-b-receiver")]
    );
    assert_eq!(state.contact_services.len(), 2);

    let contact = action_with_network_effect(NetworkEffectSpecification::Contact {
        intervals: id("contact-plan"),
        range_delay_lookup: id("direct-range-delay"),
        beams: crucible::model::ObjectIdSet::new(vec![id("beam-a")])
            .unwrap_or_else(|error| panic!("contact beams: {error}")),
        gateways: crucible::model::ObjectIdSet::new(vec![id("gateway-a")])
            .unwrap_or_else(|error| panic!("contact gateways: {error}")),
    });
    apply_network_frame_action(
        &mut vec![1],
        &mut effects,
        &contact,
        &opportunity_at(1, 132),
        ContentHash::from_bytes(b"multihop-contact-composition"),
        &topology,
        &mut state,
    )
    .unwrap_or_else(|error| panic!("compose multihop custody with contact: {error}"));
    assert!(!effects.is_dropped());
    assert_eq!(effects.additional_delay_nanos(), 0);
    assert_eq!(state.contact_services.len(), 2);
}

#[test]
fn custody_checkpoint_rejects_broken_contact_graph_joins() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let action = custody_action();
    let owner = NetworkEffectStateKey::from_action(&action);
    let mut state = NetworkEffectRuntimeState::default();
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut response = None;
    let first = opportunity_at(1, 0);
    let waiting = apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &first,
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("stage custody route: {error}"));
    let service_opportunity = opportunity_at(
        1,
        waiting
            .defer_until
            .unwrap_or_else(|| panic!("custody route must wait for contact")),
    );
    let mut planned_pending = vec![pending_custody_frame(
        &first,
        service_opportunity.coordinate().virtual_nanos,
    )];
    planned_pending[0]
        .fault_continuation
        .cursor_mut()
        .defer_repeated_effect_until(
            service_opportunity.coordinate().virtual_nanos,
            first.id(),
            crucible::model::EffectKind::NetworkCustodyQueue,
            Some(crucible::model::NetworkBundlePriority::Normal.rank()),
        );
    validate_custody_contact_topology(&state, &planned_pending, &topology)
        .unwrap_or_else(|error| panic!("valid planned custody checkpoint: {error}"));
    let mut planned_extra = planned_pending.clone();
    let mut planned_effects = crucible::ResolvedNetworkFrameEffects::default();
    planned_effects
        .mark_contact_service_accounted([0x6b; 32])
        .unwrap_or_else(|error| panic!("planned extra contact: {error}"));
    planned_extra[0]
        .fault_continuation
        .set_resolved_frame_effects(planned_effects);
    assert!(validate_custody_contact_topology(&state, &planned_extra, &topology).is_err());
    let committed = apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &service_opportunity,
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("commit custody route: {error}"));
    let release = committed
        .defer_until
        .unwrap_or_else(|| panic!("committed custody route must have a release"));
    let mut pending = vec![pending_custody_frame(&service_opportunity, release)];
    pending[0]
        .fault_continuation
        .cursor_mut()
        .defer_repeated_effect_until(
            release,
            service_opportunity.id(),
            crucible::model::EffectKind::NetworkCustodyQueue,
            Some(crucible::model::NetworkBundlePriority::Normal.rank()),
        );
    pending[0]
        .fault_continuation
        .set_resolved_frame_effects(effects);
    validate_custody_contact_topology(&state, &pending, &topology)
        .unwrap_or_else(|error| panic!("valid custody checkpoint join: {error}"));

    let mut mismatched_output = pending.clone();
    mismatched_output[0].payload.push(2);
    assert!(validate_custody_contact_topology(&state, &mismatched_output, &topology).is_err());

    let mut mismatched_priority = state.clone();
    mismatched_priority
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"))
        .reservations[0]
        .bundle
        .priority = crucible::model::NetworkBundlePriority::Bulk;
    assert!(validate_custody_contact_topology(&mismatched_priority, &pending, &topology).is_err());

    let mut mismatched_bytes = state.clone();
    mismatched_bytes
        .contact_services
        .values_mut()
        .next()
        .unwrap_or_else(|| panic!("contact service"))
        .reservations[0]
        .bytes = 2;
    assert!(validate_custody_contact_topology(&mismatched_bytes, &pending, &topology).is_err());

    let mut orphaned_ledger = state.clone();
    orphaned_ledger
        .contact_services
        .values_mut()
        .next()
        .unwrap_or_else(|| panic!("contact service"))
        .reservations[0]
        .custody_owner = Some(NetworkEffectStateKey {
        binding: id("missing-custody-binding"),
        target: action.target.clone(),
        effect: crucible::model::EffectKind::NetworkCustodyQueue,
    });
    assert!(validate_custody_contact_topology(&orphaned_ledger, &pending, &topology).is_err());

    let mut overlapping_ledger = state.clone();
    let service = overlapping_ledger
        .contact_services
        .values_mut()
        .next()
        .unwrap_or_else(|| panic!("contact service"));
    let mut duplicate = service.reservations[0].clone();
    duplicate.opportunity = ContentHash::from_bytes(b"overlapping-contact-reservation");
    service.served_bundles += 1;
    service.served_bytes += duplicate.bytes;
    service.reservations.push(duplicate);
    service.reservations.sort_by(|left, right| {
        (left.start_nanos, left.finish_nanos, left.opportunity).cmp(&(
            right.start_nanos,
            right.finish_nanos,
            right.opportunity,
        ))
    });
    assert!(
        validate_network_adapter_checkpoint(&NetworkAdapterCheckpoint {
            semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
            coordinate: Some(release),
            coordinate_sequence: 0,
            journal_sequence: 1,
            effect_state: overlapping_ledger,
        })
        .is_err()
    );

    let mut mismatched_expiry = state.clone();
    mismatched_expiry
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"))
        .reservations[0]
        .expiry_nanos += 1;
    assert!(
        validate_network_adapter_checkpoint(&NetworkAdapterCheckpoint {
            semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
            coordinate: Some(release),
            coordinate_sequence: 0,
            journal_sequence: 1,
            effect_state: mismatched_expiry,
        })
        .is_err()
    );

    let mut over_byte_capacity = state.clone();
    let reservation = &mut over_byte_capacity
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"))
        .reservations[0];
    reservation.bytes = 2;
    reservation.bundle.length_bytes = 2;
    assert!(
        validate_network_adapter_checkpoint(&NetworkAdapterCheckpoint {
            semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
            coordinate: Some(release),
            coordinate_sequence: 0,
            journal_sequence: 1,
            effect_state: over_byte_capacity,
        })
        .is_err()
    );

    let mut over_bundle_capacity = state.clone();
    let queue = over_bundle_capacity
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"));
    let mut second = queue.reservations[0].clone();
    second.bundle.producer_sequence = 2;
    second.bundle.payload_digest = ContentHash::from_bytes(&[2]);
    second.opportunity = ContentHash::from_bytes(b"second-capacity-bundle");
    second.enqueue_nanos = 1;
    second.expiry_nanos = 1_001;
    queue.reservations.push(second);
    queue.reservations.sort_by(|left, right| {
        (
            left.bundle.priority.rank(),
            left.enqueue_nanos,
            &left.bundle,
        )
            .cmp(&(
                right.bundle.priority.rank(),
                right.enqueue_nanos,
                &right.bundle,
            ))
    });
    assert!(
        validate_network_adapter_checkpoint(&NetworkAdapterCheckpoint {
            semantic_version: NETWORK_ADAPTER_CHECKPOINT_VERSION,
            coordinate: Some(release),
            coordinate_sequence: 0,
            journal_sequence: 1,
            effect_state: over_bundle_capacity,
        })
        .is_err()
    );

    let mut missing_contact = state.clone();
    missing_contact
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"))
        .reservations[0]
        .contact_path[0] = id("missing-contact");
    assert!(validate_custody_contact_topology(&missing_contact, &pending, &topology).is_err());

    let mut missing_frame_accounting = pending.clone();
    let mut stripped_effects = missing_frame_accounting[0]
        .fault_continuation
        .resolved_frame_effects()
        .clone();
    stripped_effects.require_serialization();
    missing_frame_accounting[0]
        .fault_continuation
        .set_resolved_frame_effects(stripped_effects);
    assert!(
        validate_custody_contact_topology(&state, &missing_frame_accounting, &topology,).is_err()
    );

    let mut extra_frame_accounting = pending.clone();
    let mut extra_effects = extra_frame_accounting[0]
        .fault_continuation
        .resolved_frame_effects()
        .clone();
    extra_effects
        .mark_contact_service_accounted([0x5a; 32])
        .unwrap_or_else(|error| panic!("extra contact accounting: {error}"));
    extra_frame_accounting[0]
        .fault_continuation
        .set_resolved_frame_effects(extra_effects);
    assert!(
        validate_custody_contact_topology(&state, &extra_frame_accounting, &topology,).is_err()
    );

    let mut missing_priority = pending.clone();
    missing_priority[0]
        .fault_continuation
        .cursor_mut()
        .defer_repeated_effect_until(
            release,
            service_opportunity.id(),
            crucible::model::EffectKind::NetworkCustodyQueue,
            None,
        );
    assert!(validate_custody_contact_topology(&state, &missing_priority, &topology).is_err());

    let mut mismatched_cursor = pending.clone();
    mismatched_cursor[0]
        .fault_continuation
        .cursor_mut()
        .defer_repeated_effect_until(
            release + 1,
            service_opportunity.id(),
            crucible::model::EffectKind::NetworkCustodyQueue,
            Some(crucible::model::NetworkBundlePriority::Normal.rank()),
        );
    assert!(validate_custody_contact_topology(&state, &mismatched_cursor, &topology).is_err());

    let mut mismatched_release = state.clone();
    let reservation = &mut mismatched_release
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"))
        .reservations[0];
    reservation.release_nanos = reservation.release_nanos.saturating_add(1);
    assert!(validate_custody_contact_topology(&mismatched_release, &pending, &topology,).is_err());

    let mut service_before_enqueue = state.clone();
    let reservation = &mut service_before_enqueue
        .custody_queues
        .get_mut(&owner)
        .unwrap_or_else(|| panic!("custody queue"))
        .reservations[0];
    reservation.enqueue_nanos = 111;
    reservation.expiry_nanos = 1_111;
    assert!(
        validate_custody_contact_topology(&service_before_enqueue, &pending, &topology).is_err()
    );
}

#[test]
fn completed_contact_ledgers_fold_into_the_settled_cursor() {
    let key = NetworkContactServiceKey {
        plan: id("contact-plan"),
        contact: id("contact-a"),
        service_resource: id("resource-a"),
        source: id("sender"),
        destination: id("receiver"),
        start_nanos: 100,
        end_nanos: 200,
    };
    let mut state = NetworkEffectRuntimeState::default();
    state.contact_services.insert(
        key,
        NetworkContactServiceState {
            settled_cursor_nanos: 100,
            service_cursor_nanos: 112,
            served_bundles: 1,
            served_bytes: 1,
            reservations: vec![NetworkContactServiceReservation {
                custody_owner: None,
                opportunity: ContentHash::from_bytes(b"settled-contact"),
                start_nanos: 110,
                finish_nanos: 112,
                arrival_nanos: 112,
                bytes: 1,
            }],
        },
    );

    prune_network_contact_services(&mut state, 112);
    let service = state
        .contact_services
        .values()
        .next()
        .unwrap_or_else(|| panic!("contact service"));
    assert!(service.reservations.is_empty());
    assert_eq!(service.settled_cursor_nanos, 112);
    assert_eq!(service.service_cursor_nanos, 112);
    assert_eq!(service.served_bundles, 1);
    assert_eq!(service.served_bytes, 1);
}

#[test]
fn direct_contact_counter_overflow_fails_before_mutation() {
    assert!(network_contact_service_state_capacity_allows(
        HARD_CONTACT_SERVICE_STATES - 1,
        1,
    ));
    assert!(!network_contact_service_state_capacity_allows(
        HARD_CONTACT_SERVICE_STATES,
        1,
    ));
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let plan = topology
        .network_policy_artifact(&id("contact-plan"))
        .unwrap_or_else(|| panic!("contact plan"));
    let crucible::model::NetworkPolicyArtifactKind::ContactPlan { intervals } = &plan.artifact
    else {
        panic!("contact plan type")
    };
    let interval = intervals[0].clone();
    let action = custody_action();
    for (served_bundles, served_bytes) in [(u64::MAX, 0), (0, u64::MAX)] {
        let key = NetworkContactServiceKey {
            plan: id("contact-plan"),
            contact: interval.contact.clone(),
            service_resource: interval.service_resource.clone(),
            source: interval.source.clone(),
            destination: interval.destination.clone(),
            start_nanos: interval.start_nanos,
            end_nanos: interval.end_nanos,
        };
        let mut state = NetworkEffectRuntimeState::default();
        state.contact_services.insert(
            key.clone(),
            NetworkContactServiceState {
                settled_cursor_nanos: 100,
                service_cursor_nanos: 100,
                served_bundles,
                served_bytes,
                reservations: Vec::new(),
            },
        );
        let error = match reserve_network_contact_service(
            &mut state,
            &topology,
            &id("contact-plan"),
            &interval,
            &id("sender"),
            &id("receiver"),
            110,
            1,
            ContentHash::from_bytes(b"overflow-direct-contact"),
            &action,
        ) {
            Ok(_) => panic!("direct contact counter overflow must fail"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("before direct reservation"));
        let service = state
            .contact_services
            .get(&key)
            .unwrap_or_else(|| panic!("contact service"));
        assert_eq!(service.service_cursor_nanos, 100);
        assert_eq!(service.served_bundles, served_bundles);
        assert_eq!(service.served_bytes, served_bytes);
        assert!(service.reservations.is_empty());
    }
}

#[test]
fn custody_accounting_skips_direct_contact_propagation_and_revalidation() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let action = action_with_network_effect(NetworkEffectSpecification::Contact {
        intervals: id("contact-plan"),
        range_delay_lookup: id("direct-range-delay"),
        beams: crucible::model::ObjectIdSet::new(vec![id("beam-a")])
            .unwrap_or_else(|error| panic!("contact beams: {error}")),
        gateways: crucible::model::ObjectIdSet::new(vec![id("gateway-a")])
            .unwrap_or_else(|error| panic!("contact gateways: {error}")),
    });
    let key = NetworkContactServiceKey {
        plan: id("contact-plan"),
        contact: id("contact-a"),
        service_resource: id("resource-a"),
        source: id("sender"),
        destination: id("receiver"),
        start_nanos: 100,
        end_nanos: 200,
    };
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    effects
        .mark_contact_service_accounted(network_contact_service_identity(&key))
        .unwrap_or_else(|error| panic!("account custody contact: {error}"));

    apply_network_frame_action(
        &mut vec![1],
        &mut effects,
        &action,
        &opportunity_at(1, 250),
        ContentHash::from_bytes(b"accounted-contact"),
        &topology,
        &mut NetworkEffectRuntimeState::default(),
    )
    .unwrap_or_else(|error| panic!("skip direct contact after custody: {error}"));
    assert!(!effects.is_dropped());
    assert_eq!(effects.additional_delay_nanos(), 0);
}

#[test]
fn custody_priority_arbitrates_equal_contact_release_coordinates() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let bulk = custody_action();
    let mut critical = custody_action();
    critical.binding = id("critical-custody-binding");
    let mut state = NetworkEffectRuntimeState::default();
    let mut response = None;
    let mut bulk_effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut critical_effects = crucible::ResolvedNetworkFrameEffects::default();
    for (sequence, action, priority, effects) in [
        (
            1,
            &bulk,
            crucible::model::NetworkBundlePriority::Bulk,
            &mut bulk_effects,
        ),
        (
            2,
            &critical,
            crucible::model::NetworkBundlePriority::Critical,
            &mut critical_effects,
        ),
    ] {
        let waiting = apply_network_custody_queue(
            &[u8::try_from(sequence).unwrap_or(0)],
            effects,
            &mut state,
            &mut Vec::new(),
            &topology,
            action,
            &opportunity_at(sequence, 0),
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            priority,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("stage priority bundle: {error}"));
        assert_eq!(waiting.defer_until, Some(110));
    }
    let critical_service = apply_network_custody_queue(
        &[2],
        &mut critical_effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &critical,
        &opportunity_at(2, 110),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Critical,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("serve critical bundle: {error}"));
    let bulk_service = apply_network_custody_queue(
        &[1],
        &mut bulk_effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &bulk,
        &opportunity_at(1, 110),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Bulk,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("serve bulk bundle: {error}"));
    assert_eq!(critical_service.defer_until, Some(112));
    assert_eq!(bulk_service.defer_until, Some(113));
}

#[test]
fn custody_expiry_precedes_an_unreachable_future_contact() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 2_000);
    let action = custody_action();
    let mut state = NetworkEffectRuntimeState::default();
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut typed_response = None;
    let waiting = apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &opportunity_at(1, 0),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("queue until expiry: {error}"));
    assert_eq!(waiting.defer_until, Some(1_000));
    apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &opportunity_at(1, 1_000),
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut typed_response,
    )
    .unwrap_or_else(|error| panic!("expire custody bundle: {error}"));
    assert!(effects.is_dropped());
}

#[test]
fn custody_overflow_executes_every_closed_disposition() {
    for disposition in [
        crucible::model::NetworkPolicyOverflow::DropNewest,
        crucible::model::NetworkPolicyOverflow::DropOldest,
        crucible::model::NetworkPolicyOverflow::TypedError,
        crucible::model::NetworkPolicyOverflow::Timeout,
    ] {
        let topology = custody_topology(disposition, 500);
        let action = custody_action();
        let mut state = NetworkEffectRuntimeState::default();
        let first = opportunity_at(1, 0);
        let mut pending = Vec::new();
        let mut first_effects = crucible::ResolvedNetworkFrameEffects::default();
        let mut response = None;
        let first_application = apply_network_custody_queue(
            &[1],
            &mut first_effects,
            &mut state,
            &mut pending,
            &topology,
            &action,
            &first,
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("first custody admission: {error}"));
        let first_release = first_application
            .defer_until
            .unwrap_or_else(|| panic!("first bundle must wait"));
        pending.push(pending_custody_frame(&first, first_release));

        let second = opportunity_at(2, 1);
        let mut second_effects = crucible::ResolvedNetworkFrameEffects::default();
        let second_application = apply_network_custody_queue(
            &[2],
            &mut second_effects,
            &mut state,
            &mut pending,
            &topology,
            &action,
            &second,
            1,
            1,
            1_000,
            &id("custody-policy"),
            &id("contact-plan"),
            crucible::model::NetworkBundlePriority::Normal,
            8,
            &mut response,
        )
        .unwrap_or_else(|error| panic!("custody overflow: {error}"));
        match disposition {
            crucible::model::NetworkPolicyOverflow::DropNewest => {
                assert!(second_effects.is_dropped());
                assert_eq!(pending.len(), 1);
            }
            crucible::model::NetworkPolicyOverflow::DropOldest => {
                assert!(!second_effects.is_dropped());
                assert!(second_application.repeat_phase_on_resume);
                assert!(pending.is_empty());
                let queue = state
                    .custody_queues
                    .get(&NetworkEffectStateKey::from_action(&action))
                    .unwrap_or_else(|| panic!("custody queue"));
                assert_eq!(queue.reservations[0].bundle.producer_sequence, 2);
            }
            crucible::model::NetworkPolicyOverflow::TypedError => {
                assert!(second_effects.is_dropped());
                assert_eq!(response, Some(id("custody-reject")));
            }
            crucible::model::NetworkPolicyOverflow::Timeout => {
                assert_eq!(second_application.defer_until, Some(26));
                let mut timed_out = crucible::ResolvedNetworkFrameEffects::default();
                apply_network_custody_queue(
                    &[2],
                    &mut timed_out,
                    &mut state,
                    &mut pending,
                    &topology,
                    &action,
                    &opportunity_at(2, 26),
                    1,
                    1,
                    1_000,
                    &id("custody-policy"),
                    &id("contact-plan"),
                    crucible::model::NetworkBundlePriority::Normal,
                    8,
                    &mut response,
                )
                .unwrap_or_else(|error| panic!("custody overflow timeout: {error}"));
                assert!(timed_out.is_dropped());
            }
        }
    }
}

#[test]
fn custody_removal_releases_the_real_pending_frame_at_the_boundary() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 500);
    let action = custody_action();
    let first = opportunity_at(1, 0);
    let mut state = NetworkEffectRuntimeState::default();
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut response = None;
    let waiting = apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &first,
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("queue custody frame: {error}"));
    let release = waiting
        .defer_until
        .unwrap_or_else(|| panic!("custody frame must be pending"));
    assert_eq!(release, 510);
    let service_opportunity = opportunity_at(1, release);
    let service = apply_network_custody_queue(
        &[1],
        &mut effects,
        &mut state,
        &mut Vec::new(),
        &topology,
        &action,
        &service_opportunity,
        1,
        1,
        1_000,
        &id("custody-policy"),
        &id("contact-plan"),
        crucible::model::NetworkBundlePriority::Normal,
        8,
        &mut response,
    )
    .unwrap_or_else(|error| panic!("commit custody contact: {error}"));
    let service_release = service
        .defer_until
        .unwrap_or_else(|| panic!("committed custody frame must be pending"));
    let mut pending = vec![pending_custody_frame(&first, service_release)];
    pending[0]
        .fault_continuation
        .cursor_mut()
        .defer_repeated_effect_until(
            service_release,
            service_opportunity.id(),
            crucible::model::EffectKind::NetworkCustodyQueue,
            Some(crucible::model::NetworkBundlePriority::Normal.rank()),
        );
    pending[0]
        .fault_continuation
        .set_resolved_frame_effects(effects);
    let mut removal = action;
    removal.kind = BindingActionKind::RemovePersistent;
    removal.coordinate.virtual_nanos = 510;
    assert!(
        apply_network_custody_removals(&mut state, &mut pending, &[removal], 510)
            .unwrap_or_else(|error| panic!("remove custody binding: {error}"))
    );
    assert!(state.custody_queues.is_empty());
    assert!(
        state
            .contact_services
            .values()
            .all(|service| service.reservations.is_empty() && service.served_bundles == 0)
    );
    assert_eq!(
        pending[0].fault_continuation.cursor().not_before_nanos(),
        510
    );
    assert!(
        pending[0]
            .fault_continuation
            .resolved_frame_effects()
            .accounted_contact_services()
            .is_empty()
    );
    assert!(
        !pending[0]
            .fault_continuation
            .resolved_frame_effects()
            .serialization_is_accounted()
    );
}

#[test]
fn simultaneous_custody_queues_fail_before_state_mutation() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let first = custody_action();
    let mut second = custody_action();
    second.binding = id("second-custody-binding");
    let mut payload = vec![1];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let error = match apply_network_frame_actions(
        &mut payload,
        &mut effects,
        &[first, second],
        &opportunity_at(1, 0),
        ContentHash::from_bytes(b"custody-conflict"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
    ) {
        Ok(_) => panic!("two custody queues must conflict"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("multiple custody queues"));
    assert!(state.custody_queues.is_empty());
    assert!(state.contact_services.is_empty());
}

#[test]
fn custody_resume_does_not_charge_other_queue_effects_twice() {
    let topology = custody_topology(crucible::model::NetworkPolicyOverflow::DropNewest, 100);
    let token = action_with_network_effect(NetworkEffectSpecification::TokenBucket {
        rate_bps: positive(8),
        burst_bits: positive(16),
        initial_bits: 16,
    });
    let custody = custody_action();
    let actions = vec![token, custody];
    let mut payload = vec![1];
    let mut effects = crucible::ResolvedNetworkFrameEffects::default();
    let mut state = NetworkEffectRuntimeState::default();
    let first = apply_network_frame_actions(
        &mut payload,
        &mut effects,
        &actions,
        &opportunity_at(1, 0),
        ContentHash::from_bytes(b"custody-repeat"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        None,
    )
    .unwrap_or_else(|error| panic!("first queue evaluation: {error}"));
    assert_eq!(
        first.repeat_effect_on_resume,
        Some(crucible::model::EffectKind::NetworkCustodyQueue)
    );
    let token_state = state
        .token_buckets
        .values()
        .next()
        .map(|bucket| {
            (
                bucket.tokens_nano_bits,
                bucket.last_refill_nanos,
                bucket.transition_sequence,
            )
        })
        .unwrap_or_else(|| panic!("token bucket state"));
    let release = first
        .defer_until
        .unwrap_or_else(|| panic!("custody release"));
    let resumed = apply_network_frame_actions(
        &mut payload,
        &mut effects,
        &actions,
        &opportunity_at(1, release),
        ContentHash::from_bytes(b"custody-repeat"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        Some(crucible::model::EffectKind::NetworkCustodyQueue),
    )
    .unwrap_or_else(|error| panic!("custody resume: {error}"));
    assert_eq!(
        resumed.repeat_effect_on_resume,
        Some(crucible::model::EffectKind::NetworkCustodyQueue)
    );
    let final_release = resumed
        .defer_until
        .unwrap_or_else(|| panic!("committed custody release"));
    let finalized = apply_network_frame_actions(
        &mut payload,
        &mut effects,
        &actions,
        &opportunity_at(1, final_release),
        ContentHash::from_bytes(b"custody-repeat"),
        &topology,
        &mut state,
        &mut Vec::new(),
        None,
        Some(crucible::model::EffectKind::NetworkCustodyQueue),
    )
    .unwrap_or_else(|error| panic!("custody finalize: {error}"));
    assert_eq!(finalized.repeat_effect_on_resume, None);
    let resumed_token_state = state
        .token_buckets
        .values()
        .next()
        .map(|bucket| {
            (
                bucket.tokens_nano_bits,
                bucket.last_refill_nanos,
                bucket.transition_sequence,
            )
        })
        .unwrap_or_else(|| panic!("resumed token bucket state"));
    assert_eq!(resumed_token_state, token_state);
}
