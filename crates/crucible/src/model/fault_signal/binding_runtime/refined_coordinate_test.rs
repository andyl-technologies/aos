//! Backend-refined coordinate recording and locked-replay tests.

use super::*;

struct RefineCoordinateActions {
    retired_instructions: u64,
    expected_prepared_retired: Option<u64>,
    live_precondition: ContentHash,
    commits: usize,
    prepared: Option<PreparedActionBatch>,
}

impl FaultActionSink for RefineCoordinateActions {
    fn prepare_batch(
        &mut self,
        actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        if let Some(expected) = self.expected_prepared_retired {
            assert!(
                actions
                    .iter()
                    .all(|action| action.coordinate.retired_instructions == Some(expected))
            );
        }
        if let Some(action) = actions.iter().find(|action| {
            action
                .expected_precondition
                .is_some_and(|expected| expected != self.live_precondition)
        }) {
            let expected = action
                .expected_precondition
                .unwrap_or_else(|| panic!("mismatched replay action must carry a precondition"));
            return Err(Box::new(RejectedActionBatch {
                error: FaultRuntimeError::ReplayPreconditionMismatch {
                    action: action.id(),
                    expected,
                    observed: self.live_precondition,
                },
                observations: vec![FaultObservation {
                    semantic_version: FAULT_RUNTIME_STATE_VERSION,
                    kind: FaultObservationKind::EffectRejected,
                    coordinate: action.coordinate,
                    binding: Some(action.binding.clone()),
                    target: Some(action.target.clone()),
                    opportunity: action.opportunity,
                    evidence: self.live_precondition,
                }],
                rejected_action: Some(action.id()),
            }));
        }
        let mut prepared = prepared_actions(actions);
        for result in &mut prepared.results {
            result.precondition = Some(self.live_precondition);
        }
        self.prepared = Some(prepared.clone());
        Ok(prepared)
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        self.commits += 1;
        let mut prepared = self
            .prepared
            .take()
            .filter(|prepared| prepared.transaction == transaction)
            .ok_or(FaultActionCommitError::Fatal(
                FaultRuntimeError::UnknownAdapterTransaction,
            ))?;
        for result in &mut prepared.results {
            result.observation.coordinate.retired_instructions = Some(self.retired_instructions);
        }
        Ok(prepared)
    }

    fn abort_batch(&mut self, _transaction: ContentHash) -> Result<(), FaultRuntimeError> {
        Ok(())
    }
}

fn node_target_set() -> ResolvedTargetSet {
    ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::Node {
            node: object_id("node-a"),
        }],
        false,
    )
    .unwrap_or_else(|error| panic!("invalid node target: {error}"))
}

fn node_service_effect() -> EffectRequest {
    EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Persistent,
        EffectSpecification::Node(NodeEffectSpecification::CpuService {
            vcpus: vec![0],
            capacity: ExactRatio::new(1, 1)
                .unwrap_or_else(|error| panic!("invalid node capacity: {error}")),
            quantum_instructions: PositiveU64::new("quantum_instructions", 1)
                .unwrap_or_else(|error| panic!("invalid node quantum: {error}")),
            service_rule: CpuServiceDiscipline::WorkConserving,
        }),
    )
    .unwrap_or_else(|error| panic!("invalid node service effect: {error}"))
}

fn recorded_precondition() -> ContentHash {
    ContentHash::from_bytes(b"refined-coordinate-precondition")
}

#[test]
fn locked_replay_retains_and_enforces_a_backend_refined_coordinate() {
    let program = constant_program(
        SignalValue::Bool(true),
        SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let binding = FaultBinding::new(
        object_id("binding-refined-coordinate"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(node_target_set()),
        [FaultPhase::Run].into_iter().collect(),
        node_service_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid coordinate binding: {error}"));
    let seed = ContentHash::from_bytes(b"refined-coordinate-seed");

    let mut preview_runtime = FaultBindingRuntime::new(
        &program,
        vec![binding.clone()],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid coordinate preview: {error}"));
    let preview = preview_runtime
        .preview_boundary_traced(coordinate(0), 0, &mut AcceptActions::default(), None)
        .unwrap_or_else(|error| panic!("coordinate preview failed: {error}"));
    assert_eq!(preview.actions.len(), 1);
    assert_eq!(preview.actions[0].coordinate.retired_instructions, None);

    let mut unrefined_runtime = FaultBindingRuntime::new(
        &program,
        vec![binding.clone()],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid unrefined coordinate runtime: {error}"));
    assert!(matches!(
        unrefined_runtime.evaluate_boundary_traced(
            coordinate(0),
            0,
            &mut AcceptActions::default(),
            None,
            &mut Vec::new(),
        ),
        Err(BindingRuntimeError::AdapterCommit(
            FaultRuntimeError::IncompleteAdapterState
        ))
    ));

    let mut recorder = FaultBindingRuntime::new(
        &program,
        vec![binding.clone()],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid coordinate recorder: {error}"));
    let mut recorded = Vec::new();
    let evaluation = recorder
        .evaluate_boundary_traced(
            coordinate(0),
            0,
            &mut RefineCoordinateActions {
                retired_instructions: 73,
                expected_prepared_retired: None,
                live_precondition: recorded_precondition(),
                commits: 0,
                prepared: None,
            },
            None,
            &mut recorded,
        )
        .unwrap_or_else(|error| panic!("coordinate recording failed: {error}"));
    assert_eq!(recorded[0].coordinate.retired_instructions, None);
    assert_eq!(
        recorded[0].records[0].coordinate.retired_instructions,
        Some(73)
    );
    assert!(recorded[0].records[0].matches_recomputed_action(&evaluation.actions[0]));
    let mut incomplete_node_record = recorded[0].records[0].clone();
    incomplete_node_record.coordinate.retired_instructions = None;
    assert_eq!(
        incomplete_node_record.validate(),
        Err(FaultContractError::InvalidPayload)
    );
    assert!(
        !evaluation.actions[0].accepts_observation_coordinate(evaluation.actions[0].coordinate)
    );
    let mut host_action = evaluation.actions[0].clone();
    host_action.effect = Arc::new(availability_effect());
    let mut illicit_host_coordinate = host_action.coordinate;
    illicit_host_coordinate.retired_instructions = Some(73);
    assert!(!host_action.accepts_observation_coordinate(illicit_host_coordinate));

    let trace = ResolvedEffectTrace {
        mode: FaultReplayMode::LockedEffect,
        work_items: recorded,
        cursor: 0,
    };
    let mut replay = FaultBindingRuntime::new(
        &program,
        vec![binding.clone()],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid coordinate replay: {error}"));
    let mut mismatched_trace = trace.clone();
    assert!(matches!(
        replay.evaluate_boundary_traced(
            coordinate(0),
            0,
            &mut RefineCoordinateActions {
                retired_instructions: 74,
                expected_prepared_retired: Some(73),
                live_precondition: recorded_precondition(),
                commits: 0,
                prepared: None,
            },
            Some(&mut mismatched_trace),
            &mut Vec::new(),
        ),
        Err(BindingRuntimeError::AdapterCommit(
            FaultRuntimeError::IncompleteAdapterState
        ))
    ));
    assert_eq!(mismatched_trace.cursor, 0);

    let mut matching_replay = FaultBindingRuntime::new(
        &program,
        vec![binding.clone()],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid matching coordinate replay: {error}"));
    let mut matching_trace = trace.clone();
    matching_replay
        .evaluate_boundary_traced(
            coordinate(0),
            0,
            &mut RefineCoordinateActions {
                retired_instructions: 73,
                expected_prepared_retired: Some(73),
                live_precondition: recorded_precondition(),
                commits: 0,
                prepared: None,
            },
            Some(&mut matching_trace),
            &mut Vec::new(),
        )
        .unwrap_or_else(|error| panic!("matching coordinate replay failed: {error}"));
    assert_eq!(matching_trace.cursor, 1);

    let mut recomputed_trace = trace;
    recomputed_trace.mode = FaultReplayMode::RecomputedCause;
    let mut divergent_replay = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid divergent-state replay: {error}"));
    let mut divergent_sink = RefineCoordinateActions {
        retired_instructions: 73,
        expected_prepared_retired: Some(73),
        live_precondition: ContentHash::from_bytes(b"divergent-live-precondition"),
        commits: 0,
        prepared: None,
    };
    assert!(matches!(
        divergent_replay.evaluate_boundary_traced(
            coordinate(0),
            0,
            &mut divergent_sink,
            Some(&mut recomputed_trace),
            &mut Vec::new(),
        ),
        Err(BindingRuntimeError::AdapterRejected(rejected))
            if matches!(rejected.error, FaultRuntimeError::ReplayPreconditionMismatch { .. })
    ));
    assert_eq!(divergent_sink.commits, 0);
    assert_eq!(recomputed_trace.cursor, 0);
}
