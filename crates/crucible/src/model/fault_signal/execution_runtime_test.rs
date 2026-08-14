//! Checkpoint and network-outcome tests for fault execution.

use super::test_support::*;
use super::*;

#[test]
fn execution_checkpoint_restores_the_same_adapter_contributions() {
    let plan = test_plan();
    let seed = ContentHash::from_bytes(b"scenario-seed");
    let mut runtime = FaultExecutionRuntime::new(
        &plan,
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("execution runtime: {error}"));
    let evaluation = runtime
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            0,
        )
        .unwrap_or_else(|error| panic!("boundary: {error}"));
    assert_eq!(evaluation.actions.len(), 1);
    let checkpoint = runtime
        .checkpoint()
        .unwrap_or_else(|error| panic!("checkpoint: {error}"));
    let restored =
        FaultExecutionRuntime::restore(&plan, &NoArtifacts, seed, manifests(), &checkpoint)
            .unwrap_or_else(|error| panic!("restore: {error}"));
    assert_eq!(
        restored.adapter(FaultAdapter::Network).composition_groups(),
        runtime.adapter(FaultAdapter::Network).composition_groups()
    );
}

#[test]
fn recorded_effects_execute_in_every_network_replay_mode() {
    let plan = test_plan();
    let seed = ContentHash::from_bytes(b"replay-seed");
    let coordinate = FaultCoordinate {
        virtual_nanos: 0,
        retired_instructions: None,
    };
    let mut recorder = FaultExecutionRuntime::new(
        &plan,
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("recording runtime: {error}"));
    recorder
        .evaluate_boundary(coordinate, 0)
        .unwrap_or_else(|error| panic!("recording boundary: {error}"));

    for mode in [
        FaultReplayMode::RecomputedCause,
        FaultReplayMode::LockedEffect,
    ] {
        let trace = recorder
            .recorded_trace(mode)
            .unwrap_or_else(|error| panic!("recorded trace: {error}"));
        let mut replay = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("replay runtime: {error}"));
        replay
            .install_replay(trace)
            .unwrap_or_else(|error| panic!("install replay: {error}"));
        let evaluation = replay
            .evaluate_boundary(coordinate, 0)
            .unwrap_or_else(|error| panic!("replay boundary: {error}"));
        assert_eq!(evaluation.actions.len(), 1);
        replay
            .verify_replay_exhausted()
            .unwrap_or_else(|error| panic!("replay exhaustion: {error}"));
        replay
            .checkpoint()
            .unwrap_or_else(|error| panic!("replay checkpoint: {error}"));
    }
}

#[test]
fn outcome_replay_aligns_a_frame_without_rederiving_its_model() {
    let plan = network_outcome_plan();
    let seed = ContentHash::from_bytes(b"network-outcome-replay");
    let coordinate = FaultCoordinate {
        virtual_nanos: 10,
        retired_instructions: None,
    };
    let opportunity = frame_opportunity(coordinate, 7);
    let mut recorder = FaultExecutionRuntime::new(
        &plan,
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("recording runtime: {error}"));
    recorder
        .evaluate_boundary(coordinate, 0)
        .unwrap_or_else(|error| panic!("recording boundary: {error}"));
    let pass = frame_opportunity_with_operation(coordinate, 6, FaultOperation::NetworkReceive);
    let passed = recorder
        .evaluate_opportunity(&pass, 1)
        .unwrap_or_else(|error| panic!("recording pass opportunity: {error}"));
    assert!(passed.actions.is_empty());
    let recorded = recorder
        .evaluate_opportunity(&opportunity, 2)
        .unwrap_or_else(|error| panic!("recording opportunity: {error}"));
    assert_eq!(recorded.actions.len(), 1);
    for alignment in [
        NetworkOutcomeAlignment::ExactFrameKey,
        NetworkOutcomeAlignment::ProducerDirectionSequence,
        NetworkOutcomeAlignment::ExactEventCoordinate,
        NetworkOutcomeAlignment::OrderedTimeBucket { width_nanos: 100 },
    ] {
        let trace = recorder
            .recorded_trace(FaultReplayMode::OutcomeOnlyNetwork(alignment))
            .unwrap_or_else(|error| panic!("outcome trace: {error}"));
        assert_eq!(trace.work_items.len(), 2);
        assert!(trace.work_items[0].records.is_empty());
        let replay_coordinate = if alignment == NetworkOutcomeAlignment::ExactEventCoordinate {
            coordinate
        } else {
            FaultCoordinate {
                virtual_nanos: 20,
                retired_instructions: None,
            }
        };
        let replay_opportunity = frame_opportunity(replay_coordinate, 7);
        let mut replay = FaultExecutionRuntime::new(
            &plan,
            &NoArtifacts,
            SignalBoundarySnapshot::default(),
            seed,
            manifests(),
        )
        .unwrap_or_else(|error| panic!("replay runtime: {error}"));
        replay
            .install_replay(trace)
            .unwrap_or_else(|error| panic!("install replay: {error}"));
        replay
            .evaluate_boundary(replay_coordinate, 0)
            .unwrap_or_else(|error| panic!("replay boundary: {error}"));
        let replay_pass =
            frame_opportunity_with_operation(replay_coordinate, 6, FaultOperation::NetworkReceive);
        let passed = replay
            .evaluate_opportunity(&replay_pass, 1)
            .unwrap_or_else(|error| panic!("replay pass opportunity: {error}"));
        assert!(passed.actions.is_empty());
        let outcome = replay
            .evaluate_opportunity(&replay_opportunity, 2)
            .unwrap_or_else(|error| panic!("replay opportunity: {error}"));
        assert_eq!(outcome.actions.len(), 1);
        assert_eq!(outcome.actions[0].effect, recorded.actions[0].effect);
        assert_eq!(
            outcome.actions[0].mapping_output,
            recorded.actions[0].mapping_output
        );
        assert_eq!(outcome.actions[0].coordinate, replay_coordinate);
        replay
            .verify_replay_exhausted()
            .unwrap_or_else(|error| panic!("replay exhaustion: {error}"));
    }
}
