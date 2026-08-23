//! Atomic adapter rollback and terminal ambiguity regressions.

use super::*;

#[derive(Default)]
struct MismatchedActions {
    prepared: bool,
    aborted: bool,
    committed: bool,
    abort_fails: bool,
}

struct RollbackRejectActions;

impl FaultActionSink for MismatchedActions {
    fn prepare_batch(
        &mut self,
        _actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        self.prepared = true;
        Ok(PreparedActionBatch {
            transaction: ContentHash::from_bytes(b"malformed-transaction"),
            results: Vec::new(),
        })
    }

    fn commit_batch(
        &mut self,
        transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        self.committed = true;
        self.prepared = false;
        Ok(PreparedActionBatch {
            transaction,
            results: Vec::new(),
        })
    }

    fn abort_batch(&mut self, _transaction: ContentHash) -> Result<(), FaultRuntimeError> {
        self.prepared = false;
        self.aborted = true;
        if self.abort_fails {
            Err(FaultRuntimeError::AdapterTransactionRollback)
        } else {
            Ok(())
        }
    }
}

impl FaultActionSink for RollbackRejectActions {
    fn prepare_batch(
        &mut self,
        _actions: &[ResolvedBindingAction],
    ) -> Result<PreparedActionBatch, Box<RejectedActionBatch>> {
        Err(Box::new(RejectedActionBatch {
            error: FaultRuntimeError::AdapterTransactionRollback,
            observations: Vec::new(),
            rejected_action: None,
        }))
    }

    fn commit_batch(
        &mut self,
        _transaction: ContentHash,
    ) -> Result<PreparedActionBatch, FaultActionCommitError> {
        Err(FaultActionCommitError::Fatal(
            FaultRuntimeError::AdapterTransactionRollback,
        ))
    }

    fn abort_batch(&mut self, _transaction: ContentHash) -> Result<(), FaultRuntimeError> {
        Err(FaultRuntimeError::AdapterTransactionRollback)
    }
}

#[test]
fn malformed_adapter_success_rolls_back_the_entire_boundary() {
    let program = constant_program(
        SignalValue::Bool(true),
        SignalShape::new(SignalValueType::Bool, SignalUnit::Dimensionless, 0)
            .unwrap_or_else(|error| panic!("invalid test shape: {error}")),
    );
    let binding = FaultBinding::new(
        object_id("binding-result-mismatch"),
        vec![signal_id("output")],
        BindingSampling::AtBoundary,
        BindingMapping::ActiveWhenTrue { invert: false },
        TargetSelector::Exact(target_set()),
        [FaultPhase::Admit].into_iter().collect(),
        availability_effect(),
        None,
        BindingSearchPolicy::Fixed,
        observability(),
        &program,
    )
    .unwrap_or_else(|error| panic!("invalid test binding: {error}"));
    let mut runtime = FaultBindingRuntime::new(
        &program,
        vec![binding.clone()],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("invalid test runtime: {error}"));

    let mut sink = MismatchedActions::default();
    let result = runtime.evaluate_boundary(coordinate(0), 0, &mut sink);
    assert!(sink.aborted);
    assert!(!sink.committed);
    assert!(matches!(result, Err(BindingRuntimeError::AdapterResult)));
    assert!(!sink.prepared);
    assert!(runtime.active().entries().is_empty());
    assert!(runtime.states().values().all(|state| !state.active));
    assert!(
        runtime
            .evaluate_boundary(coordinate(1), 0, &mut AcceptActions::default())
            .is_ok()
    );

    let mut abort_failure_runtime = FaultBindingRuntime::new(
        &program,
        vec![binding.clone()],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"abort-failure-seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("abort failure runtime: {error}"));
    let mut abort_failure = MismatchedActions {
        abort_fails: true,
        ..MismatchedActions::default()
    };
    assert!(matches!(
        abort_failure_runtime.evaluate_boundary(coordinate(0), 0, &mut abort_failure),
        Err(BindingRuntimeError::AdapterAbort(
            FaultRuntimeError::AdapterTransactionRollback
        ))
    ));
    assert!(matches!(
        abort_failure_runtime.evaluate_boundary(coordinate(1), 0, &mut AcceptActions::default()),
        Err(BindingRuntimeError::Poisoned)
    ));

    let mut sink_reported_runtime = FaultBindingRuntime::new(
        &program,
        vec![binding],
        &NoArtifacts,
        SignalBoundarySnapshot::default(),
        ContentHash::from_bytes(b"sink-reported-rollback-seed"),
        FaultResourceLimits::default(),
    )
    .unwrap_or_else(|error| panic!("sink-reported rollback runtime: {error}"));
    assert!(matches!(
        sink_reported_runtime.evaluate_boundary(coordinate(0), 0, &mut RollbackRejectActions),
        Err(BindingRuntimeError::AdapterAbort(
            FaultRuntimeError::AdapterTransactionRollback
        ))
    ));
    assert!(matches!(
        sink_reported_runtime.evaluate_boundary(coordinate(1), 0, &mut AcceptActions::default()),
        Err(BindingRuntimeError::Poisoned)
    ));
}
