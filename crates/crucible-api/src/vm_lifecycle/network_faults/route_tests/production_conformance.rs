//! Focused production route conformance cases.

use super::*;

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
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkPauseBackpressure],
        "class-backpressure-preemption",
        "class-order+pause-boundary+sibling-progress",
    );
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
    record_production_effect_rows(
        &[crucible::model::EffectKind::NetworkTokenBucket],
        "token-bucket-ceil-surplus",
        "token-ledger+release-coordinate",
    );
}
