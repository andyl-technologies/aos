//! Empty and populated scratch loans under a finite original authority.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::*;

struct Authority {
    used: Arc<AtomicU64>,
    calls: AtomicU64,
    verifications: AtomicU64,
    revoked: AtomicBool,
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
        self.verifications.fetch_add(1, Ordering::SeqCst);
        if self.revoked.load(Ordering::SeqCst) {
            return Err(DecodeAdmissionError::new(RevokedFixtureAuthority));
        }
        if self.used.load(Ordering::SeqCst) > self.maximum {
            return Err(DecodeAdmissionError::new(std::io::Error::other(
                "original component accounting is invalid",
            )));
        }
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.verify_live()?;
        if bytes == 0 {
            return Err(refusal("fixture allocator rejects empty contracts"));
        }
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                used.checked_add(bytes).filter(|next| *next <= self.maximum)
            })
            .map_err(|_| refusal("fixture original allowance exhausted"))?;
        Ok(Arc::new(Credit {
            used: Arc::clone(&self.used),
            bytes,
        }))
    }
}

fn authority() -> Arc<Authority> {
    Arc::new(Authority {
        used: Arc::new(AtomicU64::new(0)),
        calls: AtomicU64::new(0),
        verifications: AtomicU64::new(0),
        revoked: AtomicBool::new(false),
        maximum: 4096,
    })
}

fn used_bytes(budget: &DecodeBudget) -> Result<u64, DecodeAdmissionError> {
    Ok(budget
        .0
        .state
        .lock()
        .map_err(|_| refusal("fixture accounting lock is poisoned"))?
        .used)
}

#[test]
fn empty_scratch_keeps_original_account_without_an_empty_allocator_contract()
-> Result<(), DecodeAdmissionError> {
    let authority = authority();
    let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let initial = authority.used.load(Ordering::SeqCst);
    let calls = authority.calls.load(Ordering::SeqCst);

    let empty = budget.reserve_scratch_array::<u64>(0)?;
    let populated = budget.reserve_scratch_bytes(512)?;
    assert_eq!(authority.calls.load(Ordering::SeqCst), calls + 1);
    assert_eq!(authority.used.load(Ordering::SeqCst), initial + 512);
    assert_eq!(used_bytes(&budget)?, initial + 512);

    drop(populated);
    assert_eq!(authority.used.load(Ordering::SeqCst), initial);
    assert_eq!(used_bytes(&budget)?, initial);
    drop(budget);
    assert_eq!(authority.used.load(Ordering::SeqCst), initial);
    drop(empty);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn empty_scratch_preserves_a_prior_typed_refusal() -> Result<(), DecodeAdmissionError> {
    let authority = authority();
    let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let failure = budget
        .reserve_scratch_bytes(authority.maximum)
        .err()
        .unwrap_or_else(|| panic!("scratch beyond the remaining allowance must refuse"));
    let calls = authority.calls.load(Ordering::SeqCst);

    let repeated = budget
        .reserve_scratch_bytes(0)
        .err()
        .unwrap_or_else(|| panic!("empty scratch must retain the original refusal"));
    assert_eq!(repeated, failure);
    assert_eq!(authority.calls.load(Ordering::SeqCst), calls);
    Ok(())
}

#[test]
fn empty_scratch_refuses_a_poisoned_original_account() -> Result<(), DecodeAdmissionError> {
    let authority = authority();
    let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let poison = budget.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _state = poison
            .0
            .state
            .lock()
            .unwrap_or_else(|_| panic!("fixture account should initially be available"));
        panic!("intentional original-account poisoning");
    }));
    assert!(result.is_err());
    let calls = authority.calls.load(Ordering::SeqCst);

    let error = budget
        .reserve_scratch_bytes(0)
        .err()
        .unwrap_or_else(|| panic!("poisoned empty scratch must refuse"));
    assert_eq!(error.to_string(), "decoded metadata account is poisoned");
    assert_eq!(authority.calls.load(Ordering::SeqCst), calls);
    Ok(())
}

#[derive(Debug, thiserror::Error)]
#[error("original finite fixture authority was revoked")]
struct RevokedFixtureAuthority;

#[test]
fn live_verification_keeps_original_usage_and_failure_precedence()
-> Result<(), DecodeAdmissionError> {
    let authority = authority();
    let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let child = budget.child()?;
    let baseline = authority.used.load(Ordering::SeqCst);
    let reservations = authority.calls.load(Ordering::SeqCst);
    let verifications = authority.verifications.load(Ordering::SeqCst);

    child.verify_live()?;
    budget.verify_live()?;
    assert_eq!(authority.used.load(Ordering::SeqCst), baseline);
    assert_eq!(authority.calls.load(Ordering::SeqCst), reservations);
    assert_eq!(
        authority.verifications.load(Ordering::SeqCst),
        verifications + 2
    );

    authority.revoked.store(true, Ordering::SeqCst);
    let error = child
        .verify_live()
        .err()
        .ok_or_else(|| refusal("revocation was ignored"))?;
    assert!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<RevokedFixtureAuthority>())
            .is_some()
    );
    child.check()?;
    budget.check()?;
    assert_eq!(authority.used.load(Ordering::SeqCst), baseline);
    assert_eq!(authority.calls.load(Ordering::SeqCst), reservations);
    drop(error);

    // A refused record child remains isolated; an earlier sticky refusal still
    // wins before any later live-authority check or original resource callback.
    authority.revoked.store(false, Ordering::SeqCst);
    let sticky = child
        .charge_bytes(authority.maximum)
        .err()
        .ok_or_else(|| refusal("expected finite refusal"))?;
    authority.revoked.store(true, Ordering::SeqCst);
    let before = authority.verifications.load(Ordering::SeqCst);
    assert_eq!(child.verify_live().err(), Some(sticky));
    assert_eq!(authority.verifications.load(Ordering::SeqCst), before);
    budget.check()?;

    drop(child);
    drop(budget);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}
