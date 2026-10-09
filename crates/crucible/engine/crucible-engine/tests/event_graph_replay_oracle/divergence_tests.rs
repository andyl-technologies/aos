//! Replay-oracle divergence and localization controls.

use super::*;

#[test]
fn event_graph_replay_oracle_rejects_condition_script_schedule_drift() {
    let mut artifact = EventGraphReplayArtifact::capture_converged();
    assert!(artifact.condition_script_matches_recorded_schedule());

    artifact.condition_script = vec![ReplayStep::Observations(readiness_observations())];

    assert!(!artifact.condition_script_matches_recorded_schedule());
    assert_ne!(
        condition_script_hash(&artifact.condition_script),
        artifact.condition_script_hash
    );
}

#[test]
fn event_graph_replay_oracle_localizes_first_differing_firing() {
    let artifact = EventGraphReplayArtifact::capture_converged();
    let online = replay_event_graph_artifact(&artifact);
    let mut corrupt_recorded_firings = online.trigger_firings.clone();
    corrupt_recorded_firings[2] = TriggerFiringRecord {
        event: event_id("fail-on-property-violation"),
        at: time(50),
        action: Action::fail("cluster-safe assertion violated"),
    };

    let mismatch = check_event_graph_replay_oracle(&artifact, &corrupt_recorded_firings)
        .expect_err("corrupt recorded trigger firing should diverge from replay");
    let divergence = mismatch.divergence;

    assert_eq!(divergence.index, 2);
    assert_eq!(
        divergence
            .expected
            .as_ref()
            .map(|firing| firing.event.clone()),
        Some(event_id("fail-on-property-violation"))
    );
    assert_eq!(
        divergence
            .actual
            .as_ref()
            .map(|firing| firing.event.clone()),
        Some(event_id("pass-on-black-box-convergence"))
    );
    assert_eq!(
        &corrupt_recorded_firings[..divergence.index],
        &online.trigger_firings[..divergence.index],
        "replay oracle must preserve the identical prefix before reporting divergence"
    );
}
