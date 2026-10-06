//! Empty and populated scratch loans under a finite original authority.

use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

struct Authority {
    used: Arc<AtomicU64>,
    calls: AtomicU64,
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
    fn reserve(&self, bytes: u64) -> Result<Arc<dyn Send + Sync>, DecodeAdmissionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
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
