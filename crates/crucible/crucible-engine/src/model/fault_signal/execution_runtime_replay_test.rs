//! Replay authentication and checkpoint-capacity tests for fault execution.

use super::test_support::*;
use super::*;

#[test]
fn resolved_effect_trace_bundles_round_trip_nonempty_and_apply_authored_limits() {
    let plan = test_plan();
    let seed = ContentHash::from_bytes(b"resolved-trace-public-decode");
    let mut recorder = FaultExecutionRuntime::new(
        &plan,
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        manifests(),
    )
    .unwrap_or_else(|error| panic!("recorder: {error}"));
    recorder
        .evaluate_boundary(
            FaultCoordinate {
                virtual_ticks: 0,
                retired_instructions: None,
            },
            0,
        )
        .unwrap_or_else(|error| panic!("recording boundary: {error}"));
    let item = first_recorded(&recorder);
    assert_eq!(item.records.len(), 1);

    let trace = trace_of(FaultReplayMode::LockedEffect, [item.clone()]);
    let bytes = trace
        .to_bundle_bytes(usize::MAX)
        .unwrap_or_else(|error| panic!("nonempty trace should bundle: {error}"));
    let decoded = ResolvedEffectTrace::from_bundle_bytes(&bytes, usize::MAX)
        .unwrap_or_else(|error| panic!("bundle should decode: {error}"));
    assert_eq!(decoded, trace);
    assert_eq!(trace_items(&decoded), vec![item.clone()]);

    let limits = FaultResourceLimits {
        thin_replay_events: 2,
        resolved_effect_records: 1,
        ..FaultResourceLimits::default()
    };
    assert!(matches!(
        ResolvedEffectTrace::from_items(
            FaultReplayMode::LockedEffect,
            [item.clone(), item.clone()],
            limits,
        ),
        Err(FaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "resolved_effect_records",
                current: 1,
                requested: 1,
                configured: 1,
                ..
            }
        ))
    ));
    let oversized = trace_of(FaultReplayMode::LockedEffect, [item.clone(), item]);
    assert!(matches!(
        ResolvedEffectTraceReader::new(oversized, limits),
        Err(FaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "resolved_effect_records",
                current: 0,
                requested: 2,
                configured: 1,
                ..
            }
        ))
    ));
}

#[test]
fn signal_preflight_charges_campaign_records_against_one_authored_limit() {
    let base = test_plan();
    let limits = FaultResourceLimits {
        resolved_effect_records: 2,
        ..FaultResourceLimits::default()
    };
    let plan = FaultSignalPlan::new(base.programs().to_vec(), base.bindings().to_vec(), limits)
        .unwrap_or_else(|error| panic!("limited plan: {error}"));
    let mut owner = OwnedFaultExecutionRuntime::new(
        plan,
        Arc::new(NoArtifacts),
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"shared-effect-budget"),
        manifests(),
    )
    .unwrap_or_else(|error| panic!("owner: {error}"));
    let mut backend = HostFaultActionSink::new(limits);
    owner.set_external_effect_count(2);
    assert!(matches!(
        owner.evaluate_boundary_with_backend(
            FaultCoordinate {
                virtual_ticks: 0,
                retired_instructions: None,
            },
            0,
            &mut backend,
        ),
        Err(FaultExecutionError::Runtime(
            FaultRuntimeError::ResourceLimit(FaultResourceLimitError::Exceeded {
                field: "resolved_effect_records",
                current: 2,
                requested: 1,
                configured: 2,
                ..
            })
        ))
    ));
    assert_eq!(owner.recorded_effect_count(), 0);
    assert!(backend.state().is_empty());

    owner.set_external_effect_count(1);
    owner
        .evaluate_boundary_with_backend(
            FaultCoordinate {
                virtual_ticks: 0,
                retired_instructions: None,
            },
            0,
            &mut backend,
        )
        .unwrap_or_else(|error| panic!("one remaining record should admit: {error}"));
    assert_eq!(owner.recorded_effect_count(), 1);
}

#[test]
fn recomputed_replay_rejects_a_derivation_continuation_mismatch() {
    let plan = test_plan();
    let seed = ContentHash::from_bytes(b"recomputed-derivation-mismatch");
    let coordinate = FaultCoordinate {
        virtual_ticks: 0,
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
    let recorded = recorder
        .recorded_trace(FaultReplayMode::RecomputedCause)
        .unwrap_or_else(|error| panic!("trace: {error}"));
    let mut items = trace_items(&recorded);
    let tampered = ContentHash::from_bytes(b"tampered");
    items[0].derivation_fingerprint = tampered;
    for record in &mut items[0].records {
        record.derivation_fingerprint = tampered;
    }
    let trace = trace_of(FaultReplayMode::RecomputedCause, items);
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
    assert_eq!(
        replay
            .trace
            .replay
            .as_ref()
            .map(ResolvedEffectTraceReader::cursor),
        Some(0)
    );
}

#[test]
fn recomputed_replay_authenticates_a_zero_action_work_item() {
    let plan = network_outcome_plan();
    let seed = ContentHash::from_bytes(b"zero-action-recomputed-replay");
    let coordinate = FaultCoordinate {
        virtual_ticks: 0,
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
    let recorded = recorder
        .recorded_trace(FaultReplayMode::RecomputedCause)
        .unwrap_or_else(|error| panic!("trace: {error}"));
    let mut items = trace_items(&recorded);
    assert_eq!(items.len(), 1);
    assert!(items[0].records.is_empty());
    items[0].derivation_fingerprint = ContentHash::from_bytes(b"tampered");
    let trace = trace_of(FaultReplayMode::RecomputedCause, items);

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
                virtual_ticks: 0,
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

    let mut noncurrent = checkpoint.clone();
    noncurrent.semantic_version = 0;
    noncurrent.binding_runtime.semantic_version = 0;
    let noncurrent_bytes = noncurrent
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("noncurrent checkpoint fixture: {error}"));
    assert_eq!(
        FaultRuntimeCheckpoint::from_canonical_bytes(&noncurrent_bytes, &plan, seed),
        Err(FaultRuntimeError::VersionOrIdentityMismatch)
    );

    let mut trailing = bytes;
    trailing.push(0);
    assert!(FaultRuntimeCheckpoint::from_canonical_bytes(&trailing, &plan, seed).is_err());

    let limited_bytes = checkpoint
        .canonical_bytes()
        .unwrap_or_else(|error| panic!("limited checkpoint fixture: {error}"));
    let configured = u64::try_from(limited_bytes.len() - 1)
        .unwrap_or_else(|error| panic!("limited checkpoint length: {error}"));
    let limited_plan = FaultSignalPlan::new(
        plan.programs().to_vec(),
        plan.bindings().to_vec(),
        FaultResourceLimits {
            fat_checkpoint_bytes: configured,
            ..plan.resource_limits()
        },
    )
    .unwrap_or_else(|error| panic!("limited checkpoint plan: {error}"));
    assert_eq!(
        FaultRuntimeCheckpoint::from_canonical_bytes(&limited_bytes, &limited_plan, seed),
        Err(FaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "fat_checkpoint_bytes",
                current: 0,
                requested: configured + 1,
                configured,
                hard: FaultResourceLimits::compiled_maximum().fat_checkpoint_bytes,
            }
        ))
    );

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
        virtual_ticks: 1,
        same_coordinate_sequence: 0,
    });
    assert_ne!(
        mutated
            .content_id()
            .unwrap_or_else(|error| panic!("mutated identity: {error}")),
        identity
    );
    let mut mutated = checkpoint.clone();
    mutated.recorded.tail_mut()[0].records[0].evidence_digest = ContentHash::from_bytes(b"changed");
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
fn fault_runtime_checkpoint_admits_authored_record_count_on_decode() {
    let base = test_plan();
    let limits = FaultResourceLimits {
        thin_replay_events: 2,
        resolved_effect_records: 1,
        ..base.resource_limits()
    };
    let plan = FaultSignalPlan::new(base.programs().to_vec(), base.bindings().to_vec(), limits)
        .unwrap_or_else(|error| panic!("limited plan: {error}"));
    let seed = ContentHash::from_bytes(b"durable-checkpoint-record-preflight");
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
                virtual_ticks: 0,
                retired_instructions: None,
            },
            0,
        )
        .unwrap_or_else(|error| panic!("boundary: {error}"));
    let mut checkpoint = runtime
        .checkpoint()
        .unwrap_or_else(|error| panic!("checkpoint: {error}"));
    let item = checkpoint
        .recorded
        .tail()
        .first()
        .cloned()
        .unwrap_or_else(|| panic!("recording must produce one work item"));
    assert_eq!(item.records.len(), 1);
    checkpoint.recorded.push_tail_unchecked(item);

    let mut hostile = Vec::new();
    ciborium::ser::into_writer(&checkpoint, &mut hostile)
        .unwrap_or_else(|error| panic!("hostile checkpoint fixture: {error}"));
    assert!(matches!(
        FaultRuntimeCheckpoint::from_canonical_bytes(&hostile, &plan, seed),
        Err(FaultRuntimeError::ResourceLimit(
            FaultResourceLimitError::Exceeded {
                field: "resolved_effect_records",
                current: 0,
                requested: 2,
                configured: 1,
                ..
            }
        ))
    ));
}

#[test]
fn failed_replay_installation_leaves_the_owned_continuation_unchanged() {
    let base = test_plan();
    let seed = ContentHash::from_bytes(b"atomic-replay-install");
    let limits = FaultResourceLimits {
        thin_replay_events: 4,
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
        .and_then(|checkpoint| Ok(checkpoint.content_id()?))
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
                virtual_ticks: 0,
                retired_instructions: None,
            },
            0,
        )
        .unwrap_or_else(|error| panic!("recording boundary: {error}"));
    let work_item = first_recorded(&recorder);
    let trace = trace_of(FaultReplayMode::LockedEffect, vec![work_item; 8]);
    assert!(matches!(
        owner.install_replay(trace),
        Err(FaultExecutionError::Runtime(
            FaultRuntimeError::ResourceLimit(FaultResourceLimitError::Exceeded {
                field: "thin_replay_events",
                ..
            })
        ))
    ));
    let after = owner
        .checkpoint()
        .unwrap_or_else(|error| panic!("after checkpoint: {error}"));
    assert!(after.replay.is_none());
    assert_eq!(
        after
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
        .unwrap_or_else(|error| panic!("initial checkpoint: {error}"))
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
        .unwrap_or_else(|error| panic!("before checkpoint: {error}"))
        .content_id()
        .unwrap_or_else(|error| panic!("before identity: {error}"));
    let mut backend = HostFaultActionSink::new(limits);
    assert!(
        owner
            .evaluate_boundary_with_backend(
                FaultCoordinate {
                    virtual_ticks: 0,
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
            .unwrap_or_else(|error| panic!("after checkpoint: {error}"))
            .content_id()
            .unwrap_or_else(|error| panic!("after identity: {error}")),
        before
    );
}
