//! Backend-refined coordinate recording and locked-replay tests.

use super::*;

struct RefineCoordinateActions {
    retired_instructions: u64,
    expected_prepared_retired: Option<u64>,
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
        let mut prepared = prepared_actions(actions);
        for result in &mut prepared.results {
            result.precondition = Some(ContentHash::from_bytes(b"refined-coordinate-precondition"));
        }
        self.prepared = Some(prepared.clone());
        Ok(prepared)
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
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
    let mut mismatched_trace = trace;
    assert!(matches!(
        replay.evaluate_boundary_traced(
            coordinate(0),
            0,
            &mut RefineCoordinateActions {
                retired_instructions: 74,
                expected_prepared_retired: Some(73),
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
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        seed,
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid matching coordinate replay: {error}"));
    let mut matching_trace = mismatched_trace;
    matching_replay
        .evaluate_boundary_traced(
            coordinate(0),
            0,
            &mut RefineCoordinateActions {
                retired_instructions: 73,
                expected_prepared_retired: Some(73),
                prepared: None,
            },
            Some(&mut matching_trace),
            &mut Vec::new(),
        )
        .unwrap_or_else(|error| panic!("matching coordinate replay failed: {error}"));
    assert_eq!(matching_trace.cursor, 1);
}
