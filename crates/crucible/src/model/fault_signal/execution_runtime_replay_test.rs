//! Replay authentication and checkpoint-capacity tests for fault execution.

use super::test_support::*;
use super::*;

#[test]
fn recomputed_replay_rejects_a_derivation_continuation_mismatch() {
    let plan = test_plan();
    let seed = ContentHash::from_bytes(b"recomputed-derivation-mismatch");
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
    .unwrap_or_else(|error| panic!("recorder: {error}"));
    recorder
        .evaluate_boundary(coordinate, 0)
        .unwrap_or_else(|error| panic!("recording boundary: {error}"));
    let mut trace = recorder
        .recorded_trace(FaultReplayMode::RecomputedCause)
        .unwrap_or_else(|error| panic!("trace: {error}"));
    let tampered = ContentHash::from_bytes(b"tampered");
    trace.work_items[0].derivation_fingerprint = tampered;
    for record in &mut trace.work_items[0].records {
        record.derivation_fingerprint = tampered;
    }
    let mut replay = FaultExecutionRuntime::new(
        &plan,
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("replay: {error}"));
    replay
        .install_replay(trace)
        .unwrap_or_else(|error| panic!("install: {error}"));
    assert!(matches!(
        replay.evaluate_boundary(coordinate, 0),
        Err(FaultExecutionError::Binding(BindingRuntimeError::Runtime(
            FaultRuntimeError::ReplayMismatch { .. }
        )))
    ));
    assert_eq!(replay.replay.as_ref().map(|trace| trace.cursor), Some(0));
}

#[test]
fn recomputed_replay_authenticates_a_zero_action_work_item() {
    let plan = network_outcome_plan();
    let seed = ContentHash::from_bytes(b"zero-action-recomputed-replay");
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
    .unwrap_or_else(|error| panic!("recorder: {error}"));
    let evaluation = recorder
        .evaluate_boundary(coordinate, 0)
        .unwrap_or_else(|error| panic!("zero-action boundary: {error}"));
    assert!(evaluation.actions.is_empty());
    let mut trace = recorder
        .recorded_trace(FaultReplayMode::RecomputedCause)
        .unwrap_or_else(|error| panic!("trace: {error}"));
    assert_eq!(trace.work_items.len(), 1);
    assert!(trace.work_items[0].records.is_empty());
    trace.work_items[0].derivation_fingerprint = ContentHash::from_bytes(b"tampered");

    let mut replay = FaultExecutionRuntime::new(
        &plan,
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("replay: {error}"));
    replay
        .install_replay(trace)
        .unwrap_or_else(|error| panic!("install: {error}"));
    assert!(matches!(
        replay.evaluate_boundary(coordinate, 0),
        Err(FaultExecutionError::Binding(BindingRuntimeError::Runtime(
            FaultRuntimeError::ReplayMismatch { .. }
        )))
    ));
}

#[test]
fn complete_checkpoint_identity_and_aggregate_limit_cover_nested_state() {
    let plan = test_plan();
    let seed = ContentHash::from_bytes(b"checkpoint-identity-seed");
    let mut runtime = FaultExecutionRuntime::new(
        &plan,
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("runtime: {error}"));
    runtime
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            0,
        )
        .unwrap_or_else(|error| panic!("boundary: {error}"));
    let checkpoint = runtime
        .checkpoint()
        .unwrap_or_else(|error| panic!("checkpoint: {error}"));
    let identity = checkpoint
        .content_id()
        .unwrap_or_else(|error| panic!("identity: {error}"));
    let bytes = checkpoint
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("checkpoint bytes: {error}"));
    let restored = FaultRuntimeCheckpoint::from_canonical_bytes(&bytes, &plan, seed)
        .unwrap_or_else(|error| panic!("checkpoint decode: {error}"));
    assert_eq!(restored, checkpoint);
    assert_eq!(
        restored
            .canonical_bytes()
            .unwrap_or_else(|error| panic!("restored bytes: {error}")),
        bytes
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert!(FaultRuntimeCheckpoint::from_canonical_bytes(&trailing, &plan, seed).is_err());

    let mut mutated = checkpoint.clone();
    mutated.poisoned = true;
    assert_ne!(
        mutated
            .content_id()
            .unwrap_or_else(|error| panic!("mutated identity: {error}")),
        identity
    );
    let mut mutated = checkpoint.clone();
    mutated.binding_runtime.scheduler_cursor = Some(FaultSchedulerCursor {
        virtual_nanos: 1,
        same_coordinate_sequence: 0,
    });
    assert_ne!(
        mutated
            .content_id()
            .unwrap_or_else(|error| panic!("mutated identity: {error}")),
        identity
    );
    let mut mutated = checkpoint.clone();
    mutated.recorded_work_items[0].records[0].evidence_digest = ContentHash::from_bytes(b"changed");
    assert_ne!(
        mutated
            .content_id()
            .unwrap_or_else(|error| panic!("mutated identity: {error}")),
        identity
    );
    let mut mutated = checkpoint;
    mutated.resource_limits.fat_checkpoint_bytes = 1;
    assert!(matches!(
        mutated.canonical_bytes(),
        Err(FaultRuntimeError::ResourceLimit(_))
    ));
}

#[test]
fn failed_replay_installation_leaves_the_owned_continuation_unchanged() {
    let base = test_plan();
    let seed = ContentHash::from_bytes(b"atomic-replay-install");
    let initial = OwnedFaultExecutionRuntime::new(
        base.clone(),
        Arc::new(NoArtifacts),
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("initial owner: {error}"));
    let initial_size = initial
        .checkpoint()
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("initial bytes: {error}"))
        .len();
    let limits = FaultResourceLimits {
        fat_checkpoint_bytes: u64::try_from(initial_size + 256)
            .unwrap_or_else(|error| panic!("test checkpoint size: {error}")),
        ..FaultResourceLimits::default()
    };
    let plan = FaultSignalPlan::new(base.programs().to_vec(), base.bindings().to_vec(), limits)
        .unwrap_or_else(|error| panic!("limited plan: {error}"));
    let mut owner = OwnedFaultExecutionRuntime::new(
        plan,
        Arc::new(NoArtifacts),
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("limited owner: {error}"));
    let before = owner
        .checkpoint()
        .content_id()
        .unwrap_or_else(|error| panic!("before identity: {error}"));
    let mut recorder = FaultExecutionRuntime::new(
        &base,
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("recorder: {error}"));
    recorder
        .evaluate_boundary(
            FaultCoordinate {
                virtual_nanos: 0,
                retired_instructions: None,
            },
            0,
        )
        .unwrap_or_else(|error| panic!("recording boundary: {error}"));
    let work_item = recorder
        .recorded_work_items
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("recording must contain one action"));
    let trace = ResolvedEffectTrace {
        mode: FaultReplayMode::LockedEffect,
        work_items: vec![work_item; 8],
        cursor: 0,
    };
    assert!(owner.install_replay(trace).is_err());
    assert!(owner.checkpoint().replay.is_none());
    assert_eq!(
        owner
            .checkpoint()
            .content_id()
            .unwrap_or_else(|error| panic!("after identity: {error}")),
        before
    );
}

#[test]
fn checkpoint_growth_is_rejected_before_the_live_backend_commits() {
    let base = test_plan();
    let seed = ContentHash::from_bytes(b"precommit-checkpoint-capacity");
    let initial = OwnedFaultExecutionRuntime::new(
        base.clone(),
        Arc::new(NoArtifacts),
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("initial owner: {error}"));
    let initial_size = initial
        .checkpoint()
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("initial bytes: {error}"))
        .len();
    let limits = FaultResourceLimits {
        fat_checkpoint_bytes: u64::try_from(initial_size + 64)
            .unwrap_or_else(|error| panic!("test checkpoint size: {error}")),
        ..FaultResourceLimits::default()
    };
    let plan = FaultSignalPlan::new(base.programs().to_vec(), base.bindings().to_vec(), limits)
        .unwrap_or_else(|error| panic!("limited plan: {error}"));
    let mut owner = OwnedFaultExecutionRuntime::new(
        plan,
        Arc::new(NoArtifacts),
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("limited owner: {error}"));
    let before = owner
        .checkpoint()
        .content_id()
        .unwrap_or_else(|error| panic!("before identity: {error}"));
    let mut backend = HostFaultActionSink::new(limits);
    assert!(
        owner
            .evaluate_boundary_with_backend(
                FaultCoordinate {
                    virtual_nanos: 0,
                    retired_instructions: None,
                },
                0,
                &mut backend,
            )
            .is_err()
    );
    assert!(backend.state().is_empty());
    assert_eq!(
        owner
            .checkpoint()
            .content_id()
            .unwrap_or_else(|error| panic!("after identity: {error}")),
        before
    );
}
