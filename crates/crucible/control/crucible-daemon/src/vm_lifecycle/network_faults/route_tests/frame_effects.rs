//! Production-path frame mutation tests.

use super::*;

#[test]
fn frame_effect_variants_mutate_production_frame_outcomes() {
    let mut payload = vec![0x55];
    let profile = apply_frame_effect(
        NetworkEffectSpecification::ProfileDelta {
            latency_nanos: Some(-5),
            rate_cap_bps: Some(positive(1_000)),
            loss_hazard: None,
            corruption_hazard: None,
            technology_metrics: None,
        },
        1,
        &mut payload,
    );
    assert_eq!(profile.latency_delta_ticks(), -5_000);
    assert_eq!(profile.serialization_rate_cap_bps(), Some(1_000));

    let propagation = apply_frame_effect(
        NetworkEffectSpecification::PropagationDelay {
            delay_nanos: Some(positive(11)),
            distance_velocity_lookup: None,
        },
        2,
        &mut payload,
    );
    assert_eq!(propagation.additional_delay_ticks(), 11_000);

    let access = apply_frame_effect(
        NetworkEffectSpecification::AccessDelay {
            delay_nanos: positive(13),
            cause: id("test-access-contention"),
        },
        3,
        &mut payload,
    );
    assert_eq!(access.additional_delay_ticks(), 13_000);

    let jitter = apply_frame_effect(
        NetworkEffectSpecification::Jitter {
            maximum_nanos: positive(17),
            distribution: crucible_engine::model::NetworkDistribution::Uniform,
            distribution_lookup: None,
        },
        4,
        &mut payload,
    );
    assert!(jitter.additional_delay_ticks() <= 17_000);

    let loss = apply_frame_effect(
        NetworkEffectSpecification::FrameLoss {
            probability: None,
            outcome: Some(crucible_engine::model::NetworkLossDecision::Drop),
        },
        5,
        &mut payload,
    );
    assert!(loss.is_dropped());

    let duplicate = apply_frame_effect(
        NetworkEffectSpecification::Duplicate {
            probability: crucible_engine::model::ProbabilityMillionths::new(1_000_000)
                .unwrap_or_else(|error| panic!("test duplicate probability: {error}")),
            gap_nanos: 7,
            copies: crucible_engine::model::BoundedCount::new(
                CountLimit::DuplicatesOrInstructionReplay,
                2,
            )
            .unwrap_or_else(|error| panic!("test duplicate count: {error}")),
        },
        6,
        &mut payload,
    );
    assert_eq!(duplicate.duplicate_gaps_ticks(), &[7_000, 14_000]);

    let reorder = apply_frame_effect(
        NetworkEffectSpecification::Reorder {
            window_nanos: positive(19),
            selection: crucible_engine::model::NetworkSelection::Newest,
        },
        7,
        &mut payload,
    );
    assert_eq!(reorder.additional_delay_ticks(), 19_000);

    let mut transformed_payload = vec![0x55];
    let transformed = apply_frame_effect(
        NetworkEffectSpecification::PayloadTransform {
            mutation: crucible_engine::model::NetworkPayloadMutation::BitFlip {
                offset_bytes: 0,
                length_bytes: positive(1),
                mask: 0x0f,
            },
        },
        8,
        &mut transformed_payload,
    );
    assert_eq!(transformed_payload, vec![0x5a]);
    assert!(!transformed.is_dropped());

    let membership_version = id("test-membership-v1");
    let dropped_members = crucible_engine::model::ObjectIdSet::new(vec![id("receiver")])
        .unwrap_or_else(|error| panic!("test dropped recipient set: {error}"));
    let mut topology = crucible_engine::model::WorldFaultTopology::default();
    topology
        .network_policy_artifacts
        .push(crucible_engine::model::WorldNetworkPolicyArtifact {
            id: membership_version.clone(),
            semantic_version: 1,
            artifact: crucible_engine::model::NetworkPolicyArtifactKind::RecipientMembership {
                members: vec![crucible_engine::model::NetworkPolicyRecipient {
                    member: id("receiver"),
                    joined_sequence: 1,
                }],
            },
        });
    let recipient = apply_frame_effect_with_topology(
        NetworkEffectSpecification::RecipientSubset {
            membership_version,
            drop_members: Some(dropped_members),
            selection: None,
            retain_count: None,
        },
        9,
        &mut payload,
        &topology,
    );
    assert!(recipient.is_dropped());

    crate::vm_lifecycle::network_faults::record_production_effect_rows(
        &[
            crucible_engine::model::EffectKind::NetworkProfileDelta,
            crucible_engine::model::EffectKind::NetworkPropagationDelay,
            crucible_engine::model::EffectKind::NetworkAccessDelay,
            crucible_engine::model::EffectKind::NetworkJitter,
            crucible_engine::model::EffectKind::NetworkFrameLoss,
            crucible_engine::model::EffectKind::NetworkDuplicate,
            crucible_engine::model::EffectKind::NetworkReorder,
            crucible_engine::model::EffectKind::NetworkPayloadTransform,
            crucible_engine::model::EffectKind::NetworkRecipientSubset,
        ],
        "frame-effect-outcome-matrix",
        "delay+loss+duplication+ordering+payload+recipient-evidence",
    );
}
