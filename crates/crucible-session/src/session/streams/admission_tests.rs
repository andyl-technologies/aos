//! Independent returned reproduction copies under one finite original authority.

use super::*;
use crucible::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use std::sync::atomic::{AtomicU64, Ordering};

struct Authority {
    used: Arc<AtomicU64>,
    maximum: u64,
}

struct Credit {
    used: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Credit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.used.load(Ordering::SeqCst) > self.maximum {
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "original component accounting is invalid",
            )));
        }
        Ok(())
    }

    fn reserve(
        &self,
        bytes: u64,
    ) -> Result<crucible::owned_decode::ResourceLoan, DecodeAdmissionError> {
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| {
                DecodeAdmissionError::new(std::io::Error::other("finite snapshot allowance"))
            })?;
        Ok(crucible::owned_decode::ResourceLoan::new(Credit {
            used: self.used.clone(),
            bytes,
        }))
    }
}

fn log() -> SessionReproductionLog {
    let log = SessionReproductionLog::new();
    log.lock_entries().push(SessionControlLogEntry {
        sequence: 1,
        command: SessionCommandKind::SetBreakpoint,
        payload: SessionControlPayload::SetBreakpoint {
            spec: BreakpointSpec {
                predicate: Condition::Not {
                    predicate: Box::new(Condition::named("quoted\né")),
                },
                disposition: BreakpointDisposition::Action(Action::Group(vec![
                    Action::Fail {
                        reason: String::from("reason\n水"),
                    },
                    Action::CreateSavepoint {
                        label: Some(String::from("copy")),
                    },
                ])),
                policy: BreakpointPolicy::OneShot,
            },
        },
        frontier: VirtualTime { ticks: 13 },
        quanta: 2,
        event_log_sequence_before: 9,
        result: SessionControlResult::Accepted,
        scheduler_batch: 3,
        scheduler_control: Some(ControlOperationKind::Pause),
    });
    log
}

#[test]
fn snapshots_release_child_accounts_without_retaining_previous_copies()
-> Result<(), Box<dyn std::error::Error>> {
    let log = log();
    let expected = log.lock_entries().clone();
    let owner = Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        maximum: 1024 * 1024,
    });
    let budget = DecodeBudget::new(owner.clone(), owner.maximum)?;
    let _scope = budget.enter();
    let baseline = owner.used.load(Ordering::SeqCst);
    let first = log.snapshot_admitted()?;
    assert_eq!(first.entries(), expected);
    let one = owner.used.load(Ordering::SeqCst) - baseline;
    assert!(one > 0);
    let second = log.snapshot_admitted()?;
    assert_eq!(owner.used.load(Ordering::SeqCst), baseline + one * 2);
    drop(first);
    assert_eq!(owner.used.load(Ordering::SeqCst), baseline + one);
    drop(second);
    assert_eq!(owner.used.load(Ordering::SeqCst), baseline);
    for _ in 0..20 {
        let copy = log.snapshot_admitted()?;
        assert_eq!(copy.entries(), expected);
        drop(copy);
        assert_eq!(owner.used.load(Ordering::SeqCst), baseline);
    }
    Ok(())
}

#[test]
fn snapshot_refusal_releases_partial_copy_and_preserves_source_log()
-> Result<(), Box<dyn std::error::Error>> {
    let log = log();
    let expected = log.lock_entries().clone();
    let owner = Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        maximum: 4096,
    });
    let budget = DecodeBudget::new(owner.clone(), owner.maximum)?;
    let _scope = budget.enter();
    let baseline = owner.used.load(Ordering::SeqCst);
    let held = owner.reserve(owner.maximum - baseline - 1)?;
    let saturated = owner.used.load(Ordering::SeqCst);
    assert!(matches!(
        log.snapshot_admitted(),
        Err(EngineError::ArtifactDecodeAdmission { .. })
    ));
    assert_eq!(owner.used.load(Ordering::SeqCst), saturated);
    assert_eq!(log.lock_entries().clone(), expected);
    drop(held);
    assert_eq!(owner.used.load(Ordering::SeqCst), baseline);
    Ok(())
}

/// Builds the finite original account for session snapshot component fixtures.
pub(crate) fn fixture_budget() -> Result<DecodeBudget, DecodeAdmissionError> {
    Ok(tracked_fixture_budget()?.0)
}

pub(crate) fn tracked_fixture_budget()
-> Result<(DecodeBudget, Arc<AtomicU64>), DecodeAdmissionError> {
    let owner = Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        maximum: 1024 * 1024,
    });
    Ok((
        DecodeBudget::new(owner.clone(), owner.maximum)?,
        owner.used.clone(),
    ))
}
