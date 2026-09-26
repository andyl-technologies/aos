//! State replay and recovery tests over exact durable event prefixes.

use std::num::NonZeroU32;

use aos_ability_model::{
    AbilityValue, EnvironmentId, ExecutionStage, InstanceId, LocalKey, PlanId, ResourceId,
    ScopePath, ScopedOperationKey, TransactionId,
};
use aos_contract::Sha256Digest;
use serde_json::json;
use tempfile::TempDir;

use super::*;
use crate::execution::{ExecutionEvent, ExecutionEventKind, ReconciliationResult};
use crate::journal::{FileJournal, JournalLimits};

#[test]
fn crash_after_intent_requires_reconciliation_before_retry()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let records = fixture.write(&[
        fixture.planned(),
        fixture.admitted(1, 2),
        fixture.intent(1, 3),
    ])?;

    let history = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )?;
    assert!(matches!(
        history.recovery_action(&bounded_retry(3), 100),
        RecoveryAction::ReconcileBeforeRetry { attempt } if attempt.get() == 1
    ));
    Ok(())
}

#[test]
fn reconciliation_must_explicitly_authorize_the_next_attempt()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let evidence = fixture.evidence()?;
    let records = fixture.write(&[
        fixture.planned(),
        fixture.admitted(1, 2),
        fixture.intent(1, 3),
        fixture.indeterminate(1, 4, evidence.clone()),
        ExecutionEvent::new(ExecutionEventKind::ReconciliationIntent {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            call_timeout_millis: 20,
            elapsed_millis: 5,
        }),
        ExecutionEvent::new(ExecutionEventKind::ReconciliationObserved {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            result: ReconciliationResult::SafeToRetry,
            evidence,
            outputs: BTreeMap::new(),
            elapsed_millis: 6,
        }),
    ])?;

    let history = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )?;
    assert_eq!(
        history.recovery_action(&bounded_retry(3), 100),
        RecoveryAction::Retry {
            attempt: attempt(2)
        }
    );
    Ok(())
}

#[test]
fn completion_without_durable_intent_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let records = fixture.write(&[
        fixture.planned(),
        fixture.admitted(1, 2),
        ExecutionEvent::new(ExecutionEventKind::EffectCompleted {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            evidence: fixture.evidence()?,
            outputs: BTreeMap::new(),
            elapsed_millis: 3,
        }),
    ])?;

    let error = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )
    .expect_err("completion cannot exist without a preceding durable intent");
    assert_eq!(error.sequence(), 3);
    Ok(())
}

#[test]
fn expired_indeterminate_attempt_requires_intervention() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let evidence = fixture.evidence()?;
    let records = fixture.write(&[
        fixture.planned(),
        fixture.admitted(1, 2),
        fixture.intent(1, 3),
        fixture.indeterminate(1, 100, evidence),
    ])?;

    let history = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )?;
    assert_eq!(
        history.recovery_action(&bounded_retry(3), 100),
        RecoveryAction::InterventionRequired
    );
    Ok(())
}

#[test]
fn interrupted_calls_conservatively_consume_budget_across_restarts()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let records = fixture.write(&[
        fixture.planned(),
        fixture.admitted(1, 2),
        fixture.intent(1, 3),
        ExecutionEvent::new(ExecutionEventKind::ReconciliationIntent {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            call_timeout_millis: 20,
            elapsed_millis: 23,
        }),
    ])?;

    let history = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )?;

    assert_eq!(history.elapsed_millis(), 43);
    assert_eq!(
        history.recovery_action(&bounded_retry(3), 40),
        RecoveryAction::InterventionRequired
    );
    Ok(())
}

#[test]
fn a_new_call_cannot_erase_an_interrupted_budget_reservation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let records = fixture.write(&[
        fixture.planned(),
        fixture.admitted(1, 0),
        fixture.intent(1, 0),
        ExecutionEvent::new(ExecutionEventKind::ReconciliationIntent {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            call_timeout_millis: 20,
            elapsed_millis: 0,
        }),
    ])?;

    let error = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )
    .expect_err("a new call must include the preceding interrupted reservation");

    assert_eq!(error.sequence(), 4);
    assert_eq!(
        error.reason(),
        "new recovery call did not charge the preceding interrupted reservation"
    );
    Ok(())
}

#[test]
fn safe_retry_releases_reservations_before_fresh_admission()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let owned = resource("owned")?;
    let evidence = fixture.evidence()?;
    let mut events = vec![
        fixture.planned(),
        fixture.admitted_with_resources(1, 2, vec![owned.clone()]),
        fixture.intent(1, 3),
        fixture.indeterminate(1, 4, evidence.clone()),
        ExecutionEvent::new(ExecutionEventKind::ReconciliationIntent {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            call_timeout_millis: 20,
            elapsed_millis: 5,
        }),
        ExecutionEvent::new(ExecutionEventKind::ReconciliationObserved {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            result: ReconciliationResult::SafeToRetry,
            evidence,
            outputs: BTreeMap::new(),
            elapsed_millis: 6,
        }),
    ];
    let records = fixture.write(&events)?;
    let history = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )?;
    assert_eq!(
        history.recovery_action(&bounded_retry(3), 100),
        RecoveryAction::ReleaseResources
    );

    events.push(ExecutionEvent::new(ExecutionEventKind::ResourcesReleased {
        transaction: fixture.transaction.clone(),
        operation: fixture.operation.clone(),
        resources: vec![owned],
        elapsed_millis: 7,
    }));
    let records = fixture.write_fresh(&events)?;
    let history = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )?;
    assert_eq!(
        history.recovery_action(&bounded_retry(3), 100),
        RecoveryAction::Retry {
            attempt: attempt(2)
        }
    );
    Ok(())
}

#[test]
fn replay_rejects_retry_eligibility_observed_before_the_durable_gate()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let evidence = fixture.evidence()?;
    let records = fixture.write(&[
        fixture.planned(),
        fixture.admitted(1, 2),
        fixture.intent(1, 3),
        fixture.indeterminate(1, 4, evidence.clone()),
        ExecutionEvent::new(ExecutionEventKind::ReconciliationIntent {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            call_timeout_millis: 20,
            elapsed_millis: 5,
        }),
        ExecutionEvent::new(ExecutionEventKind::ReconciliationObserved {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            result: ReconciliationResult::SafeToRetry,
            evidence,
            outputs: BTreeMap::new(),
            elapsed_millis: 6,
        }),
        ExecutionEvent::new(ExecutionEventKind::RetryBackoffScheduled {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            observed_at_millis: 100,
            eligible_at_millis: 150,
            elapsed_millis: 6,
        }),
        ExecutionEvent::new(ExecutionEventKind::RetryBackoffElapsed {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            observed_at_millis: 149,
            elapsed_millis: 55,
        }),
    ])?;

    let error = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )
    .expect_err("eligibility before the persisted timestamp must fail replay");
    assert_eq!(error.sequence(), 8);
    Ok(())
}

#[test]
fn replay_rejects_compensation_request_substitution() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let records = fixture.write(&[
        fixture.planned(),
        fixture.admitted(1, 2),
        fixture.intent(1, 3),
        ExecutionEvent::new(ExecutionEventKind::EffectCompleted {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            evidence: fixture.evidence()?,
            outputs: BTreeMap::new(),
            elapsed_millis: 4,
        }),
        ExecutionEvent::new(ExecutionEventKind::CompensationRequested {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            reason: fixture.evidence()?,
            elapsed_millis: 4,
        }),
        ExecutionEvent::new(ExecutionEventKind::CompensationAdmitted {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            resources: Vec::new(),
            elapsed_millis: 5,
        }),
        ExecutionEvent::new(ExecutionEventKind::CompensationIntent {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            request: AbilityValue::new(json!({"revision": 8}))?,
            idempotency_key: Sha256Digest::of_bytes("compensation"),
            attempt_timeout_millis: 20,
            elapsed_millis: 6,
        }),
    ])?;

    let error = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )
    .expect_err("compensation must reuse the retained primary request");
    assert_eq!(error.sequence(), 7);
    Ok(())
}

#[test]
fn release_must_exactly_match_admitted_ownership() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let owned = resource("owned")?;
    let unrelated = resource("unrelated")?;
    let records = fixture.write(&[
        fixture.planned(),
        fixture.admitted_with_resources(1, 2, vec![owned]),
        fixture.intent(1, 3),
        ExecutionEvent::new(ExecutionEventKind::EffectCompleted {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            attempt: attempt(1),
            evidence: fixture.evidence()?,
            outputs: BTreeMap::new(),
            elapsed_millis: 4,
        }),
        ExecutionEvent::new(ExecutionEventKind::ResourcesReleased {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            resources: vec![unrelated],
            elapsed_millis: 5,
        }),
    ])?;

    let error = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )
    .expect_err("release of an unrelated resource must fail replay");

    assert_eq!(error.sequence(), 5);
    assert_eq!(
        error.reason(),
        "released resources do not exactly match retained ownership"
    );
    Ok(())
}

#[test]
fn transferred_resource_cannot_also_be_recorded_as_released()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let owned = resource("owned")?;
    let evidence = fixture.evidence()?;
    let records = fixture.write(&[
        fixture.planned(),
        fixture.admitted_with_resources(1, 2, vec![owned.clone()]),
        fixture.intent(1, 3),
        fixture.indeterminate(1, 4, evidence.clone()),
        ExecutionEvent::new(ExecutionEventKind::OwnershipTransferred {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            resources: vec![owned.clone()],
            evidence,
            elapsed_millis: 5,
        }),
        ExecutionEvent::new(ExecutionEventKind::ResourcesReleased {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            resources: vec![owned],
            elapsed_millis: 6,
        }),
    ])?;

    let error = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )
    .expect_err("transferred ownership must not also be released locally");

    assert_eq!(error.sequence(), 6);
    Ok(())
}

#[test]
fn transferred_responsibility_stops_the_old_controller() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let first = resource("alpha")?;
    let second = resource("beta")?;
    let evidence = fixture.evidence()?;
    let base = vec![
        fixture.planned(),
        fixture.admitted_with_resources(1, 2, vec![first.clone(), second.clone()]),
        fixture.intent(1, 3),
        fixture.indeterminate(1, 4, evidence.clone()),
    ];

    let mut partial = base.clone();
    partial.push(ExecutionEvent::new(
        ExecutionEventKind::OwnershipTransferred {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            resources: vec![first.clone()],
            evidence: evidence.clone(),
            elapsed_millis: 5,
        },
    ));
    let records = fixture.write(&partial)?;
    let history = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )?;
    assert_eq!(
        history.recovery_action(&bounded_retry(3), 100),
        RecoveryAction::InterventionRequired
    );

    let mut complete = base;
    complete.push(ExecutionEvent::new(
        ExecutionEventKind::OwnershipTransferred {
            transaction: fixture.transaction.clone(),
            operation: fixture.operation.clone(),
            resources: vec![first, second],
            evidence,
            elapsed_millis: 5,
        },
    ));
    let records = fixture.write_fresh(&complete)?;
    let history = OperationHistory::replay(
        fixture.transaction.clone(),
        fixture.operation.clone(),
        &records,
    )?;
    assert_eq!(
        history.recovery_action(&bounded_retry(3), 100),
        RecoveryAction::None
    );
    Ok(())
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

    fn planned(&self) -> ExecutionEvent {
        ExecutionEvent::new(ExecutionEventKind::TransactionPlanned {
            transaction: self.transaction.clone(),
            plan: self.operation.plan,
            plan_bundle: Sha256Digest::of_bytes("checked-plan-bundle"),
            retained_roots: vec![Sha256Digest::of_bytes("adapter")],
            total_recovery_millis: 100,
        })
    }

    fn admitted(&self, attempt: u32, elapsed_millis: u64) -> ExecutionEvent {
        self.admitted_with_resources(attempt, elapsed_millis, Vec::new())
    }

    fn admitted_with_resources(
        &self,
        attempt: u32,
        elapsed_millis: u64,
        resources: Vec<ResourceId>,
    ) -> ExecutionEvent {
        ExecutionEvent::new(ExecutionEventKind::OperationAdmitted {
            transaction: self.transaction.clone(),
            operation: self.operation.clone(),
            attempt: super::tests::attempt(attempt),
            resources,
            elapsed_millis,
        })
    }

    fn intent(&self, attempt: u32, elapsed_millis: u64) -> ExecutionEvent {
        ExecutionEvent::new(ExecutionEventKind::EffectIntent {
            transaction: self.transaction.clone(),
            operation: self.operation.clone(),
            attempt: super::tests::attempt(attempt),
            request: AbilityValue::new(json!({"revision": 7}))
                .expect("fixture request must be bounded"),
            idempotency_key: Sha256Digest::of_bytes("logical-operation"),
            attempt_timeout_millis: 20,
            elapsed_millis,
        })
    }

    fn indeterminate(
        &self,
        attempt: u32,
        elapsed_millis: u64,
        evidence: AbilityValue,
    ) -> ExecutionEvent {
        ExecutionEvent::new(ExecutionEventKind::EffectIndeterminate {
            transaction: self.transaction.clone(),
            operation: self.operation.clone(),
            attempt: super::tests::attempt(attempt),
            evidence,
            elapsed_millis,
        })
    }

    fn evidence(&self) -> Result<AbilityValue, Box<dyn std::error::Error>> {
        Ok(AbilityValue::new(json!({"observed": "unknown"}))?)
    }

    fn write(
        &self,
        events: &[ExecutionEvent],
    ) -> Result<Vec<JournalRecord<ExecutionEvent>>, Box<dyn std::error::Error>> {
        let path = self.directory.path().join("execution.journal");
        let opened = FileJournal::<ExecutionEvent>::open(&path, JournalLimits::default())?;
        let mut journal = opened.journal;
        for event in events {
            journal.append(event)?;
        }
        drop(journal);

        Ok(
            FileJournal::<ExecutionEvent>::open(&path, JournalLimits::default())?
                .recovery
                .into_records(),
        )
    }

    fn write_fresh(
        &self,
        events: &[ExecutionEvent],
    ) -> Result<Vec<JournalRecord<ExecutionEvent>>, Box<dyn std::error::Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("execution.journal");
        let opened = FileJournal::<ExecutionEvent>::open(&path, JournalLimits::default())?;
        let mut journal = opened.journal;
        for event in events {
            journal.append(event)?;
        }
        drop(journal);

        Ok(
            FileJournal::<ExecutionEvent>::open(&path, JournalLimits::default())?
                .recovery
                .into_records(),
        )
    }
}

fn attempt(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("test attempt must be nonzero")
}

fn resource(key: &str) -> Result<ResourceId, Box<dyn std::error::Error>> {
    Ok(ResourceId {
        provider: InstanceId {
            environment: EnvironmentId {
                authority: LocalKey::new("test-authority")?,
                key: LocalKey::new("test-environment")?,
                stage: ExecutionStage::Host,
            },
            key: LocalKey::new("provider")?,
        },
        key: LocalKey::new(key)?,
    })
}

fn bounded_retry(max_attempts: u32) -> RetryPolicy {
    RetryPolicy::Bounded {
        max_attempts: NonZeroU32::new(max_attempts).expect("test retry count must be nonzero"),
        backoff_millis: 0,
    }
}
