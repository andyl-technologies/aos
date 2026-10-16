//! Shared-medium scheduling and policy route tests.

use super::*;

pub(super) fn medium_action(
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

pub(super) fn medium_opportunity(
    producer: &str,
    sequence: u64,
    payload: &[u8],
) -> FaultOpportunity {
    FaultOpportunity::new(
        ResolvedFaultTarget::NetworkMedium {
            medium: id("test-medium"),
            resource: id("test-channel"),
        },
        crucible::model::FaultOperation::NetworkTraverse,
        FaultPhase::Queue,
        FaultCoordinate {
            virtual_ticks: 0,
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

pub(super) fn medium_topology(
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

pub(super) fn medium_policy(
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

pub(super) fn pending_medium_frame(
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
        assert_eq!(first_release, 8_000);
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
            assert_eq!(second_release, 16_000);
            assert_eq!(
                pending[0].fault_continuation.cursor().not_before_ticks(),
                8_000
            );
        } else {
            assert_eq!(second_release, 8_000);
            assert_eq!(
                pending[0].fault_continuation.cursor().not_before_ticks(),
                16_000
            );
        }
        assert!(second_effects.serialization_is_accounted());
    }
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkSharedMedium],
        "shared-medium-arbitration",
        "resource-order+release-coordinate+serialization",
    );
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
    assert_eq!(releases, vec![8_000, 18_000]);
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
    assert_eq!(second_release, 108_000);
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

#[path = "medium/protocol.rs"]
mod protocol;
