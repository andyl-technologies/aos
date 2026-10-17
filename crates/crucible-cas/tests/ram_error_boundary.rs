//! First-refusal and complete-storage semantics at the prepaid RAM boundary.

use std::error::Error;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crucible_cas::owned_decode::{DecodeAdmissionError, DecodeBudget, DecodeResourceAuthority};
use crucible_cas::ram::{PreparedRamFailure, RamOperationFailure, RamStoreError};

struct Authority;

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        Ok(())
    }

    fn reserve(
        &self,
        _bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, DecodeAdmissionError> {
        Ok(crucible_cas::owned_decode::ResourceLoan::new(()))
    }
}

#[derive(Debug)]
struct First(usize);

impl fmt::Display for First {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "original refusal {}", self.0)
    }
}

impl Error for First {}

fn prepare() -> Result<PreparedRamFailure<First>, crucible_cas::ram::RamFailureAdmission> {
    let original = DecodeBudget::new(Arc::new(Authority), 16 * 1024)
        .map_err(crucible_cas::ram::RamFailureAdmission::Original)?;
    PreparedRamFailure::new(&original)
}

#[test]
fn repeated_requested_polls_do_not_replace_the_first_refusal() {
    let mut calls = 0;
    let error = prepare()
        .unwrap()
        .run(
            &mut || {
                calls += 1;
                Err(First(calls))
            },
            |boundary| {
                assert!(matches!(boundary(), Err(RamStoreError::Canceled)));
                assert!(matches!(boundary(), Err(RamStoreError::Canceled)));
                Err::<(), _>(RamStoreError::Invalid("complete original storage failure"))
            },
        )
        .unwrap_err();

    let RamOperationFailure::Retained(cause) = error else {
        panic!("storage owner was discarded");
    };
    assert_eq!(calls, 1);
    assert_eq!(cause.first_boundary().map(|first| first.0), Some(1));
    assert!(matches!(
        cause.storage_failure(),
        RamStoreError::Invalid("complete original storage failure")
    ));
}

#[test]
fn direct_canceled_marker_returns_first_error_inline() {
    let error = prepare()
        .unwrap()
        .run(&mut || Err(First(19)), |boundary| boundary())
        .unwrap_err();

    assert!(matches!(error, RamOperationFailure::Boundary(First(19))));
}

#[test]
fn ordinary_storage_error_remains_typed_without_a_boundary_refusal() {
    let error = prepare()
        .unwrap()
        .run(&mut || Ok(()), |_boundary| {
            Err::<(), _>(RamStoreError::Invalid("original"))
        })
        .unwrap_err();

    let RamOperationFailure::Retained(cause) = error else {
        panic!("storage owner was discarded");
    };
    assert!(cause.first_boundary().is_none());
    assert!(matches!(
        cause.storage_failure(),
        RamStoreError::Invalid("original")
    ));
}

struct ReturnedOwner(Arc<AtomicUsize>);

impl Drop for ReturnedOwner {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn success_after_refusal_closes_returned_owner_and_remains_refused() {
    let drops = Arc::new(AtomicUsize::new(0));
    let result = prepare().unwrap().run(&mut || Err(First(23)), |boundary| {
        let _ = boundary();
        Ok(ReturnedOwner(drops.clone()))
    });

    assert!(matches!(
        result,
        Err(RamOperationFailure::Boundary(First(23)))
    ));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

struct RefusingAuthority {
    failure: DecodeAdmissionError,
    live: std::sync::atomic::AtomicBool,
    reserves: AtomicUsize,
    checks: AtomicUsize,
}

impl RefusingAuthority {
    fn new() -> Self {
        Self {
            failure: DecodeAdmissionError::new(First(31)),
            live: std::sync::atomic::AtomicBool::new(true),
            reserves: AtomicUsize::new(0),
            checks: AtomicUsize::new(0),
        }
    }
}

impl DecodeResourceAuthority for RefusingAuthority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        self.checks.fetch_add(1, Ordering::SeqCst);
        if self.live.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(self.failure.clone())
        }
    }

    fn reserve(
        &self,
        _bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, DecodeAdmissionError> {
        self.reserves.fetch_add(1, Ordering::SeqCst);
        Ok(crucible_cas::owned_decode::ResourceLoan::new(()))
    }
}

#[test]
fn refused_original_account_precedes_new_credit_and_ignores_unrelated_scope() {
    let authority_a = Arc::new(RefusingAuthority::new());
    let original_a = DecodeBudget::new(authority_a.clone(), 16 * 1024).unwrap();
    let authority_b = Arc::new(RefusingAuthority::new());
    let unrelated_b = DecodeBudget::new(authority_b.clone(), 16 * 1024).unwrap();
    let _scope_b = unrelated_b.enter();
    authority_a.live.store(false, Ordering::SeqCst);
    let effects = AtomicUsize::new(0);

    let admission = PreparedRamFailure::<First>::new(&original_a);
    let failure = match admission {
        Ok(prepared) => {
            let _ = prepared.run(&mut || Ok(()), |_| {
                effects.fetch_add(1, Ordering::SeqCst);
                Ok(())
            });
            panic!("original account must refuse before operation");
        }
        Err(failure) => failure,
    };

    assert!(
        matches!(failure, crucible_cas::ram::RamFailureAdmission::Original(source) if source == authority_a.failure)
    );
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        authority_a.reserves.load(Ordering::SeqCst),
        1,
        "no loan after original refusal"
    );
    assert_eq!(authority_a.checks.load(Ordering::SeqCst), 1);
    assert_eq!(
        authority_b.reserves.load(Ordering::SeqCst),
        1,
        "unrelated account only constructed"
    );
    assert_eq!(
        authority_b.checks.load(Ordering::SeqCst),
        0,
        "unrelated account never consulted"
    );
}

#[test]
fn delayed_original_refusal_precedes_all_callbacks_and_effects_without_new_credit() {
    let authority_a = Arc::new(RefusingAuthority::new());
    let original_a = DecodeBudget::new(authority_a.clone(), 16 * 1024).unwrap();
    let prepared = PreparedRamFailure::<First>::new(&original_a).unwrap();
    let authority_b = Arc::new(RefusingAuthority::new());
    let unrelated_b = DecodeBudget::new(authority_b.clone(), 16 * 1024).unwrap();
    let _scope_b = unrelated_b.enter();
    authority_a.live.store(false, Ordering::SeqCst);
    let callbacks = AtomicUsize::new(0);
    let effects = AtomicUsize::new(0);

    let result = prepared.run(
        &mut || {
            callbacks.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        |_| {
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
    );

    assert!(
        matches!(result, Err(RamOperationFailure::Admission(source)) if source == authority_a.failure)
    );
    assert_eq!(callbacks.load(Ordering::SeqCst), 0);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    assert_eq!(
        authority_a.reserves.load(Ordering::SeqCst),
        2,
        "only original account and earlier prepayment"
    );
    assert_eq!(
        authority_a.checks.load(Ordering::SeqCst),
        2,
        "new and delayed operation verify same original"
    );
    assert_eq!(
        authority_b.reserves.load(Ordering::SeqCst),
        1,
        "unrelated account only constructed"
    );
    assert_eq!(
        authority_b.checks.load(Ordering::SeqCst),
        0,
        "unrelated account never consulted"
    );
}

#[test]
fn already_produced_failures_remain_retainable_after_original_refusal() {
    let authority = Arc::new(RefusingAuthority::new());
    let original = DecodeBudget::new(authority.clone(), 16 * 1024).unwrap();
    let prepared = PreparedRamFailure::<First>::new(&original).unwrap();
    authority.live.store(false, Ordering::SeqCst);
    let checks = authority.checks.load(Ordering::SeqCst);

    let cause = prepared.retain(
        Some(First(41)),
        RamStoreError::Invalid("complete cleanup failure"),
    );

    assert_eq!(cause.first_boundary().map(|first| first.0), Some(41));
    assert!(matches!(
        cause.storage_failure(),
        RamStoreError::Invalid("complete cleanup failure")
    ));
    assert_eq!(
        authority.checks.load(Ordering::SeqCst),
        checks,
        "retaining already paid failure makes no new liveness decision"
    );
    assert_eq!(
        authority.reserves.load(Ordering::SeqCst),
        2,
        "retention makes no new admission"
    );
}
