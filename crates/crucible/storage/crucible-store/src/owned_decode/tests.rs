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

    fn reserve(
        &self,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, DecodeAdmissionError> {
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
        Ok(crate::owned_decode::ResourceLoan::new(Credit {
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

#[test]
fn bulk_btree_bound_is_one_target_request_and_overflow_is_sticky()
-> Result<(), DecodeAdmissionError> {
    let authority = authority();
    let budget = DecodeBudget::new(authority.clone(), 4096)?;
    let initial = used_bytes(&budget)?;
    let calls = authority.calls.load(Ordering::SeqCst);
    budget.charge_btree_entries::<u8, ()>(2)?;
    assert_eq!(authority.calls.load(Ordering::SeqCst), calls + 1);
    assert_eq!(
        used_bytes(&budget)? - initial,
        2 * btree_entry_bytes::<u8, ()>()? + (4 * std::mem::size_of::<ResourceLoan>()) as u64
    );

    let error = budget
        .charge_btree_entries::<u64, u64>(usize::MAX)
        .unwrap_err();
    assert_eq!(budget.failure()?, Some(error.clone()));
    let calls = authority.calls.load(Ordering::SeqCst);
    assert_eq!(budget.charge_btree_entries::<u8, ()>(0), Err(error));
    assert_eq!(authority.calls.load(Ordering::SeqCst), calls);
    Ok(())
}

#[test]
fn btree_geometry_query_does_not_debit_and_matches_actual_admission()
-> Result<(), DecodeAdmissionError> {
    let authority = authority();
    let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let used = authority.used.load(Ordering::SeqCst);
    let calls = authority.calls.load(Ordering::SeqCst);
    let bytes = DecodeBudget::btree_control_bytes::<u8, ()>(1)?;
    assert_eq!(bytes, btree_entry_bytes::<u8, ()>()?);
    assert_eq!(DecodeBudget::btree_control_bytes::<u8, ()>(0)?, 0);
    assert!(DecodeBudget::btree_control_bytes::<u64, u64>(usize::MAX).is_err());
    assert_eq!(authority.calls.load(Ordering::SeqCst), calls);
    assert_eq!(authority.used.load(Ordering::SeqCst), used);
    budget.charge_btree_entries::<u8, ()>(1)?;
    assert_eq!(authority.calls.load(Ordering::SeqCst), calls + 1);
    assert!(authority.used.load(Ordering::SeqCst) >= used + bytes);
    Ok(())
}

#[test]
fn exhausted_account_reports_its_prepaid_cause_without_allocating()
-> Result<(), DecodeAdmissionError> {
    use crucible_host_resources::test_support::TestAllocationObserver;

    for scratch in [false, true] {
        let authority = authority();
        let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
        let reservations = authority.calls.load(Ordering::SeqCst);

        let (error, counts) = TestAllocationObserver::count(|| {
            if scratch {
                budget.reserve_scratch_bytes(authority.maximum).err()
            } else {
                budget.charge_bytes(authority.maximum).err()
            }
        });
        let error = error.unwrap_or_else(|| panic!("the original finite account must refuse"));

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(authority.calls.load(Ordering::SeqCst), reservations);
        assert_eq!(error.to_string(), "decoded metadata allowance exhausted");
        assert!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<AccountingRefusal>())
                .is_some()
        );
        assert_eq!(budget.failure()?, Some(error.clone()));
        assert_eq!(budget.charge_bytes(0), Err(error));
    }
    Ok(())
}

#[test]
fn prepaid_refusals_keep_account_identity_and_do_not_retain_the_account()
-> Result<(), DecodeAdmissionError> {
    let authority = authority();
    let left = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let right = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let left_error = left.charge_bytes(authority.maximum).unwrap_err();
    let right_error = right.charge_bytes(authority.maximum).unwrap_err();
    let clone = left_error.clone();

    assert_eq!(left_error, clone);
    assert_ne!(left_error, right_error);
    drop(left);
    drop(right);
    assert_eq!(
        authority.used.load(Ordering::SeqCst),
        2 * PrepaidRefusals::peak_bytes()
    );
    drop(left_error);
    drop(right_error);
    assert_eq!(
        authority.used.load(Ordering::SeqCst),
        PrepaidRefusals::peak_bytes()
    );
    drop(clone);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn final_prepaid_refusal_control_frees_before_its_original_loan() -> Result<(), DecodeAdmissionError>
{
    use crucible_host_resources::test_support::TestAllocationObserver;

    let authority = authority();
    let extent = prepaid_refusal::allocation_bytes_for_test();
    let (budget, identities) =
        TestAllocationObserver::capture_controls([extent, usize::MAX, usize::MAX], || {
            DecodeBudget::new(authority.clone(), authority.maximum)
        });
    let budget = budget?;
    let error = budget.charge_bytes(authority.maximum).unwrap_err();
    drop(budget);
    let retained = authority.used.load(Ordering::SeqCst);
    assert_eq!(retained, PrepaidRefusals::peak_bytes());

    let ((), observed) = TestAllocationObserver::observe_atomic_after_free(
        &authority.used,
        identities[0]
            .unwrap_or_else(|| panic!("the actual prepaid refusal control was not observed")),
        || drop(error),
    );

    assert_eq!(observed, Some(retained));
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn poisoned_account_reports_from_prepaid_storage_without_allocating()
-> Result<(), DecodeAdmissionError> {
    use crucible_host_resources::test_support::TestAllocationObserver;

    let authority = authority();
    let budget = DecodeBudget::new(authority.clone(), authority.maximum)?;
    let poisoned = budget.clone();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _locked = poisoned.0.state.lock().unwrap();
            panic!("intentional accounting poison");
        }))
        .is_err()
    );

    let (error, counts) = TestAllocationObserver::count(|| budget.check().unwrap_err());

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(error.to_string(), "decoded metadata account is poisoned");
    drop(budget);
    assert_eq!(
        authority.used.load(Ordering::SeqCst),
        PrepaidRefusals::peak_bytes()
    );
    drop(error);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn unused_prepaid_refusal_control_frees_before_its_original_loan()
-> Result<(), DecodeAdmissionError> {
    use crucible_host_resources::test_support::TestAllocationObserver;

    let authority = authority();
    let extent = prepaid_refusal::allocation_bytes_for_test();
    let (budget, identities) =
        TestAllocationObserver::capture_controls([extent, usize::MAX, usize::MAX], || {
            DecodeBudget::new(authority.clone(), authority.maximum)
        });
    let budget = budget?;
    let retained = authority.used.load(Ordering::SeqCst);

    let ((), observed) = TestAllocationObserver::observe_atomic_after_free(
        &authority.used,
        identities[0]
            .unwrap_or_else(|| panic!("the actual unused refusal control was not observed")),
        || drop(budget),
    );

    assert_eq!(observed, Some(retained));
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn refusal_storage_is_not_born_when_its_original_credit_refuses() {
    use crucible_host_resources::test_support::TestAllocationObserver;

    let authority = Arc::new(Authority {
        maximum: DecodeBudget::account_bytes(),
        ..Arc::try_unwrap(authority())
            .unwrap_or_else(|_| panic!("the fresh fixture authority was shared"))
    });
    let extent = prepaid_refusal::allocation_bytes_for_test();

    let (result, identities) =
        TestAllocationObserver::capture_controls([extent, usize::MAX, usize::MAX], || {
            DecodeBudget::new(authority.clone(), 4096)
        });

    assert!(result.is_err());
    assert!(identities.iter().all(Option::is_none));
    assert_eq!(authority.calls.load(Ordering::SeqCst), 2);
    assert_eq!(authority.used.load(Ordering::SeqCst), 0);
}
