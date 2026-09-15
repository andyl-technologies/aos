//! Crash-boundary tests for individual operation state-machine calls.

use std::cell::Cell;
use std::io;
use std::num::NonZeroU32;
use std::rc::Rc;

use aos_ability_model::{
    AbilityValue, LocalKey, Operation, OperationId, PlanId, ScopePath, ScopedOperationKey,
    TransactionId,
};
use aos_contract::Sha256Digest;
use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::adapter::{AdapterRecord, ResourceHandle};
use crate::execution::{CompensationState, ExecutionEvent, OperationHistory, RecoveryAction};
use crate::journal::{FileJournal, JournalLimits};

fn allow_dispatch<Adapter>(_adapter: &Adapter) -> Result<(), ExecutionError> {
    Ok(())
}

#[test]
fn halt_after_intent_never_dispatches_and_recovers_by_reconciliation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut journal = fixture.journal_with_admission()?;
    let clock = TestClock::default();
    let cancellation = CancellationToken::default();
    let mut hook = StopAt::new(Boundary::EffectIntentDurable, clock.now.clone(), None);
    let mut adapter = TestAdapter::completed(fixture.evidence()?);
    let request_value = AbilityValue::new(json!({"revision": 2}))?;
    let request = PreparedRequest::new(request_value.clone(), request_value);

    let error = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook)
        .execute(
            &mut journal,
            fixture.context(),
            &request,
            &mut allow_dispatch,
        )
        .expect_err("fault injection must halt immediately after durable intent");
    assert!(matches!(
        error,
        ExecutionError::BoundaryHalt(Boundary::EffectIntentDurable)
    ));
    assert_eq!(adapter.execute_calls, 0);
    drop(journal);

    let recovered = fixture.recover_history()?;
    assert!(matches!(
        recovered.recovery_action(&aos_ability_model::RetryPolicy::Disabled, 100),
        RecoveryAction::ReconcileBeforeRetry { .. }
    ));
    Ok(())
}

#[test]
fn deadline_expiring_while_syncing_intent_prevents_adapter_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut journal = fixture.journal_with_admission()?;
    let clock = TestClock::default();
    let cancellation = CancellationToken::default();
    let mut hook = StopAt::new(
        Boundary::ReconciliationOutcomeDurable,
        clock.now.clone(),
        Some(20),
    );
    let mut adapter = TestAdapter::completed(fixture.evidence()?);
    let request_value = AbilityValue::new(json!({"revision": 2}))?;
    let request = PreparedRequest::new(request_value.clone(), request_value);

    let step = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook).execute(
        &mut journal,
        fixture.context(),
        &request,
        &mut allow_dispatch,
    )?;
    assert_eq!(step, ExecutionStep::RejectedBeforeEffect);
    assert_eq!(adapter.execute_calls, 0);
    drop(journal);

    let recovered = fixture.recover_history()?;
    assert!(matches!(
        recovered.state(),
        crate::execution::OperationState::DispatchAborted {
            reason: DispatchAbortReason::DeadlineExpired,
            ..
        }
    ));
    Ok(())
}

#[test]
fn cancellation_after_intent_records_runtime_abort_without_adapter_evidence()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut journal = fixture.journal_with_admission()?;
    let clock = TestClock::default();
    let cancellation = CancellationToken::default();
    let mut hook = CancelAtEffectIntent(cancellation.clone());
    let mut adapter = TestAdapter::completed(AbilityValue::new(json!(true))?);
    let request_value = AbilityValue::new(json!(2))?;
    let request = PreparedRequest::new(request_value.clone(), request_value);

    let step = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook).execute(
        &mut journal,
        fixture.context(),
        &request,
        &mut allow_dispatch,
    )?;

    assert_eq!(step, ExecutionStep::RejectedBeforeEffect);
    assert_eq!(adapter.execute_calls, 0);
    drop(journal);

    let recovered = fixture.recover_history()?;
    assert!(matches!(
        recovered.state(),
        crate::execution::OperationState::DispatchAborted {
            reason: DispatchAbortReason::Cancelled,
            ..
        }
    ));
    Ok(())
}

#[test]
fn crash_after_external_return_cannot_publish_completion_to_dependents()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut journal = fixture.journal_with_admission()?;
    let clock = TestClock::default();
    let cancellation = CancellationToken::default();
    let mut hook = StopAt::new(Boundary::EffectReturned, clock.now.clone(), None);
    let mut adapter = TestAdapter::completed(fixture.evidence()?);
    let request_value = AbilityValue::new(json!({"revision": 2}))?;
    let request = PreparedRequest::new(request_value.clone(), request_value);

    let error = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook)
        .execute(
            &mut journal,
            fixture.context(),
            &request,
            &mut allow_dispatch,
        )
        .expect_err("fault injection must halt before completion persistence");
    assert!(matches!(
        error,
        ExecutionError::BoundaryHalt(Boundary::EffectReturned)
    ));
    assert_eq!(adapter.execute_calls, 1);
    drop(journal);

    let recovered = fixture.recover_history()?;
    assert!(matches!(
        recovered.recovery_action(&aos_ability_model::RetryPolicy::Disabled, 100),
        RecoveryAction::ReconcileBeforeRetry { .. }
    ));
    Ok(())
}

#[test]
fn deadline_expiring_while_syncing_reconciliation_intent_prevents_observation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut journal = fixture.journal_with_intent()?;
    let clock = TestClock::default();
    let cancellation = CancellationToken::default();
    let mut hook = StopAt::new(Boundary::EffectOutcomeDurable, clock.now.clone(), Some(20));
    let mut adapter = TestAdapter::completed(fixture.evidence()?);
    let request = AbilityValue::new(json!({"revision": 2}))?;

    let error = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook)
        .reconcile(
            &mut journal,
            fixture.context(),
            &request,
            &mut allow_dispatch,
        )
        .expect_err("expired recovery budget must stop reconciliation dispatch");

    assert!(matches!(error, ExecutionError::RecoveryDeadlineExpired));
    assert_eq!(adapter.reconcile_calls, 0);
    Ok(())
}

#[test]
fn deadline_expiring_while_syncing_cancellation_intent_prevents_adapter_call()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut journal = fixture.journal_with_intent()?;
    let clock = TestClock::default();
    let cancellation = CancellationToken::default();
    let mut hook = StopAt::new(Boundary::EffectOutcomeDurable, clock.now.clone(), Some(20));
    let mut adapter = TestAdapter::completed(fixture.evidence()?);
    let request = AbilityValue::new(json!({"revision": 2}))?;

    let error = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook)
        .cancel(
            &mut journal,
            fixture.context(),
            &request,
            &mut allow_dispatch,
        )
        .expect_err("expired recovery budget must stop cancellation dispatch");

    assert!(matches!(error, ExecutionError::RecoveryDeadlineExpired));
    assert_eq!(adapter.cancel_calls, 0);
    Ok(())
}

#[test]
fn cancellation_adapter_receives_usable_control_with_live_budgets()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut journal = fixture.journal_with_intent()?;
    let clock = TestClock::default();
    let cancellation = CancellationToken::default();
    cancellation.cancel();
    let mut hook = RecordingControlHook::default();
    let mut adapter = TestAdapter::completed(fixture.evidence()?);
    let request = AbilityValue::new(json!({"revision": 2}))?;
    let context = AttemptContext {
        elapsed_millis: 7,
        attempt_timeout_millis: 40,
        total_recovery_millis: 90,
        ..fixture.context()
    };

    let step = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook).cancel(
        &mut journal,
        context,
        &request,
        &mut allow_dispatch,
    )?;

    assert_eq!(step, ExecutionStep::Indeterminate);
    assert_eq!(adapter.cancel_control, Some((false, 7, 40, 83)));
    assert_eq!(
        hook.observations,
        [
            (Boundary::CancellationIntentDurable, true),
            (Boundary::FinalDispatch, true),
            (Boundary::CancellationReturned, true),
            (Boundary::CancellationOutcomeDurable, true),
        ]
    );
    Ok(())
}

#[test]
fn compensation_deadline_after_intent_records_durable_intervention()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let mut journal = fixture.journal_with_compensation_admission()?;
    let clock = TestClock::default();
    let cancellation = CancellationToken::default();
    let mut hook = AdvanceAtEffectIntent {
        clock: clock.now.clone(),
        now: 100,
    };
    let mut adapter = TestAdapter::completed(fixture.evidence()?);
    let request_value = AbilityValue::new(json!({"revision": 2}))?;
    let request = PreparedRequest::new(request_value.clone(), request_value);

    let step = OperationExecutor::new(&mut adapter, &clock, &cancellation, &mut hook).compensate(
        &mut journal,
        fixture.context(),
        &request,
        &mut allow_dispatch,
    )?;
    assert_eq!(step, ExecutionStep::InterventionRequired);
    assert_eq!(adapter.execute_calls, 0);
    drop(journal);

    let recovered = fixture.recover_history()?;
    assert!(matches!(
        recovered.compensation_state(),
        Some(CompensationState::InterventionRequired {
            reason: CompensationInterventionReason::DeadlineAfterIntent,
            evidence: None,
        })
    ));
    assert_eq!(
        recovered.recovery_action(&aos_ability_model::RetryPolicy::Disabled, 100),
        RecoveryAction::CompensationInterventionRequired
    );
    Ok(())
}

#[derive(Default)]
struct TestClock {
    now: Rc<Cell<u64>>,
}

impl MonotonicClock for TestClock {
    fn now_millis(&self) -> u64 {
        self.now.get()
    }

    fn restart_stable_millis(&self) -> u64 {
        self.now.get()
    }
}

struct StopAt {
    boundary: Boundary,
    clock: Rc<Cell<u64>>,
    advance_at_intent: Option<u64>,
}

impl StopAt {
    fn new(boundary: Boundary, clock: Rc<Cell<u64>>, advance_at_intent: Option<u64>) -> Self {
        Self {
            boundary,
            clock,
            advance_at_intent,
        }
    }
}

impl BoundaryHook for StopAt {
    fn observe(
        &mut self,
        boundary: Boundary,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        if matches!(
            boundary,
            Boundary::EffectIntentDurable
                | Boundary::ReconciliationIntentDurable
                | Boundary::CancellationIntentDurable
        ) {
            if let Some(now) = self.advance_at_intent {
                self.clock.set(now);
            }
        }
        Ok(if boundary == self.boundary {
            ExecutionBoundaryControl::Halt
        } else {
            ExecutionBoundaryControl::Continue
        })
    }
}

struct CancelAtEffectIntent(CancellationToken);

impl BoundaryHook for CancelAtEffectIntent {
    fn observe(
        &mut self,
        boundary: Boundary,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        if boundary == Boundary::EffectIntentDurable {
            self.0.cancel();
        }
        Ok(ExecutionBoundaryControl::Continue)
    }
}

#[derive(Default)]
struct RecordingControlHook {
    observations: Vec<(Boundary, bool)>,
}

impl BoundaryHook for RecordingControlHook {
    fn observe(
        &mut self,
        boundary: Boundary,
        control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        self.observations.push((boundary, control.is_cancelled()));
        Ok(ExecutionBoundaryControl::Continue)
    }
}

struct AdvanceAtEffectIntent {
    clock: Rc<Cell<u64>>,
    now: u64,
}

impl BoundaryHook for AdvanceAtEffectIntent {
    fn observe(
        &mut self,
        boundary: Boundary,
        _control: &dyn RuntimeControl,
    ) -> anyhow::Result<ExecutionBoundaryControl> {
        if boundary == Boundary::EffectIntentDurable {
            self.clock.set(self.now);
        }
        Ok(ExecutionBoundaryControl::Continue)
    }
}

struct TestRecord {
    durable: AbilityValue,
    outputs: BTreeMap<aos_ability_model::LocalKey, AbilityValue>,
}

fn test_record(durable: AbilityValue) -> TestRecord {
    TestRecord {
        durable,
        outputs: BTreeMap::new(),
    }
}

impl AdapterRecord for TestRecord {
    fn durable(&self) -> &AbilityValue {
        &self.durable
    }
}

impl AdapterCompletion for TestRecord {
    fn outputs(&self) -> &BTreeMap<aos_ability_model::LocalKey, AbilityValue> {
        &self.outputs
    }
}

struct TestAdapter {
    completion: Option<TestRecord>,
    execute_calls: usize,
    reconcile_calls: usize,
    cancel_calls: usize,
    cancel_control: Option<(bool, u64, u64, u64)>,
}

impl TestAdapter {
    fn completed(value: AbilityValue) -> Self {
        Self {
            completion: Some(test_record(value)),
            execute_calls: 0,
            reconcile_calls: 0,
            cancel_calls: 0,
            cancel_control: None,
        }
    }
}

impl TrustedAdapter for TestAdapter {
    type Request = AbilityValue;
    type Completion = TestRecord;
    type Observation = TestRecord;
    type Handle = ();
    type PrepareError = io::Error;

    fn prepare_durable(
        &self,
        _operation: &Operation,
        _inputs: &AbilityValue,
        _resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<AbilityValue, Self::PrepareError> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "not used by this operation-machine test",
        ))
    }

    fn recover_request(
        &self,
        durable: &AbilityValue,
        _resources: &[ResourceHandle<Self::Handle>],
    ) -> Result<Self::Request, Self::PrepareError> {
        Ok(durable.clone())
    }

    fn execute(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> EffectDisposition<Self::Completion, Self::Observation> {
        self.execute_calls += 1;
        match self.completion.take() {
            Some(completion) => EffectDisposition::Completed(completion),
            None => EffectDisposition::Indeterminate(test_record(
                AbilityValue::new(json!({"reason": "duplicate-dispatch"}))
                    .expect("test observation must be bounded"),
            )),
        }
    }

    fn reconcile(
        &mut self,
        _request: &Self::Request,
        _control: &dyn RuntimeControl,
    ) -> ReconcileDisposition<Self::Completion, Self::Observation> {
        self.reconcile_calls += 1;
        ReconcileDisposition::InterventionRequired(test_record(
            AbilityValue::new(json!({"reason": "test-only"}))
                .expect("test observation must be bounded"),
        ))
    }

    fn cancel(
        &mut self,
        _request: &Self::Request,
        control: &dyn RuntimeControl,
    ) -> CancellationDisposition<Self::Completion, Self::Observation> {
        self.cancel_calls += 1;
        self.cancel_control = Some((
            control.is_cancelled(),
            control.elapsed_millis(),
            control.attempt_remaining_millis(),
            control.recovery_remaining_millis(),
        ));
        CancellationDisposition::Indeterminate(test_record(
            AbilityValue::new(json!({"reason": "test-only"}))
                .expect("test observation must be bounded"),
        ))
    }
}

struct Fixture {
    directory: TempDir,
    transaction: TransactionId,
    operation: OperationId,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let plan = PlanId(Sha256Digest::of_bytes("plan"));
        Ok(Self {
            directory: TempDir::new()?,
            transaction: TransactionId(LocalKey::new("transaction-1")?),
            operation: OperationId {
                plan,
                operation: ScopedOperationKey {
                    scope: ScopePath::root(),
                    key: LocalKey::new("publish")?,
                },
            },
        })
    }

    fn journal_with_admission(
        &self,
    ) -> Result<FileJournal<ExecutionEvent>, Box<dyn std::error::Error>> {
        let opened = FileJournal::open(self.path(), JournalLimits::default())?;
        let mut journal = opened.journal;
        journal.append(&ExecutionEvent::new(
            ExecutionEventKind::TransactionPlanned {
                transaction: self.transaction.clone(),
                plan: self.operation.plan,
                plan_bundle: Sha256Digest::of_bytes("checked-plan-bundle"),
                retained_roots: Vec::new(),
                total_recovery_millis: 100,
            },
        ))?;
        journal.append(&ExecutionEvent::new(
            ExecutionEventKind::OperationAdmitted {
                transaction: self.transaction.clone(),
                operation: self.operation.clone(),
                attempt: NonZeroU32::new(1).expect("test attempt must be nonzero"),
                resources: Vec::new(),
                elapsed_millis: 0,
            },
        ))?;
        Ok(journal)
    }

    fn context(&self) -> AttemptContext<'_> {
        AttemptContext {
            transaction: &self.transaction,
            operation: &self.operation,
            attempt: NonZeroU32::new(1).expect("test attempt must be nonzero"),
            idempotency_key: Sha256Digest::of_bytes("logical-operation"),
            elapsed_millis: 0,
            attempt_timeout_millis: 10,
            total_recovery_millis: 100,
        }
    }

    fn journal_with_intent(
        &self,
    ) -> Result<FileJournal<ExecutionEvent>, Box<dyn std::error::Error>> {
        let mut journal = self.journal_with_admission()?;
        let request = AbilityValue::new(json!({"revision": 2}))?;
        journal.append(&ExecutionEvent::new(ExecutionEventKind::EffectIntent {
            transaction: self.transaction.clone(),
            operation: self.operation.clone(),
            attempt: NonZeroU32::new(1).expect("test attempt must be nonzero"),
            request,
            idempotency_key: Sha256Digest::of_bytes("logical-operation"),
            attempt_timeout_millis: 10,
            elapsed_millis: 0,
        }))?;
        Ok(journal)
    }

    fn journal_with_compensation_admission(
        &self,
    ) -> Result<FileJournal<ExecutionEvent>, Box<dyn std::error::Error>> {
        let mut journal = self.journal_with_intent()?;
        journal.append(&ExecutionEvent::new(ExecutionEventKind::EffectCompleted {
            transaction: self.transaction.clone(),
            operation: self.operation.clone(),
            attempt: NonZeroU32::MIN,
            evidence: self.evidence()?,
            outputs: BTreeMap::new(),
            elapsed_millis: 0,
        }))?;
        journal.append(&ExecutionEvent::new(
            ExecutionEventKind::CompensationRequested {
                transaction: self.transaction.clone(),
                operation: self.operation.clone(),
                reason: AbilityValue::new(json!("test rollback"))?,
                elapsed_millis: 0,
            },
        ))?;
        journal.append(&ExecutionEvent::new(
            ExecutionEventKind::CompensationAdmitted {
                transaction: self.transaction.clone(),
                operation: self.operation.clone(),
                resources: Vec::new(),
                elapsed_millis: 0,
            },
        ))?;
        Ok(journal)
    }

    fn evidence(&self) -> Result<AbilityValue, Box<dyn std::error::Error>> {
        Ok(AbilityValue::new(
            json!({"revision": 2, "status": "ready"}),
        )?)
    }

    fn recover_history(&self) -> Result<OperationHistory, Box<dyn std::error::Error>> {
        let records = FileJournal::<ExecutionEvent>::open(self.path(), JournalLimits::default())?
            .recovery
            .into_records();
        Ok(OperationHistory::replay(
            self.transaction.clone(),
            self.operation.clone(),
            &records,
        )?)
    }

    fn path(&self) -> std::path::PathBuf {
        self.directory.path().join("execution.journal")
    }
}
