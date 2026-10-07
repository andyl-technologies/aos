//! Late operational refusal leaves the entire assertion pass unpublished.

use super::*;
use crate::owned_decode::{DecodeAdmissionError, DecodeResourceAuthority};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

struct Authority(Arc<AtomicU64>);
struct Credit(Arc<AtomicU64>, u64);

impl Drop for Credit {
    fn drop(&mut self) {
        self.0.fetch_sub(self.1, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.0.load(Ordering::SeqCst) > 1024 * 1024 {
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "original component accounting is invalid",
            )));
        }
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.0
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes)
                    .filter(|total| *total <= 1024 * 1024)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other("fixture authority exhausted"))
            })?;
        Ok(Arc::new(Credit(Arc::clone(&self.0), bytes)))
    }
}

#[test]
fn late_refusal_rolls_back_lifecycles_once_latches_and_verdict() -> Result<(), Box<dyn Error>> {
    for finalize in [false, true] {
        let used = Arc::new(AtomicU64::new(0));
        let budget = DecodeBudget::new(Arc::new(Authority(Arc::clone(&used))), 1024 * 1024)?;
        let scope = budget.enter();
        let first = AssertionDef {
            id: AssertionId::from_name("a-first"),
            message: "first succeeds provisionally".into(),
            property: Property::Sometimes {
                predicate: Condition::once(Condition::Named {
                    name: "first".into(),
                    nodes: Vec::new(),
                }),
            },
        };
        let second = AssertionDef {
            id: AssertionId::from_name("b-second"),
            message: "later original-owner refusal".into(),
            property: Property::Sometimes {
                predicate: Condition::Named {
                    name: "second".into(),
                    nodes: Vec::new(),
                },
            },
        };
        let mut evaluator = HostAssertionEvaluator::new(&Properties::empty())?;
        crate::owned_decode::charge_array::<HostAssertionState>(2)?;
        evaluator.states = vec![
            HostAssertionState::new(&first)?,
            HostAssertionState::new(&second)?,
        ];
        let before = evaluator.checkpoint()?.canonical_bytes()?;
        let calls = AtomicU64::new(0);
        let mut oracle = crate::test_support::unchecked_host_assertion_oracle_for_test(
            |_: ObservedState<'_>, _: ConditionLeaf<'_>| {
                if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                    let budget = crate::owned_decode::current_budget()
                        .unwrap_or_else(|| panic!("fixture requires original account"));
                    assert!(budget.charge_bytes(u64::MAX).is_err());
                }
                true
            },
        );
        let prefix = ConditionEventLogPrefix::from_scheduler_event_log_entries(vec![
            SchedulerEventLogEntry::evaluation_boundary(
                0,
                VirtualTime { ticks: 1 },
                SchedulerEvaluationBoundaryKind::Quantum,
            )?,
        ])?;
        let baseline = used.load(Ordering::SeqCst);
        let result = if finalize {
            evaluator.finalize_prefix(&prefix, &mut oracle).map(|_| ())
        } else {
            evaluator.observe_prefix(&prefix, &mut oracle).map(|_| ())
        };
        assert!(matches!(
            result,
            Err(EngineError::ArtifactDecodeAdmission { .. })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(evaluator.checkpoint()?.canonical_bytes()?, before);
        assert_eq!(used.load(Ordering::SeqCst), baseline);
        drop(prefix);
        drop(before);
        drop(evaluator);
        drop(scope);
        drop(budget);
        assert_eq!(used.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
