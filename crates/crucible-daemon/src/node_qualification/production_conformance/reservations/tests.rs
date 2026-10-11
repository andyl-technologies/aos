//! Checks attempt retention and private reservation identity without native work.

use std::cell::Cell;

use super::*;
use crate::node_qualification::production_conformance::OriginalCollectionAttempts;

fn reservation(owner: &Rc<()>) -> Result<OriginalRealizedCaseReservation, QualificationError> {
    Ok(OriginalRealizedCaseReservation {
        owner: Rc::clone(owner),
        case: "original-before-ack".into(),
        oracle: crucible_node_contract::canonical::content_ref(
            b"fixed independent semantic template",
            "application/octet-stream",
        )?,
        maximum_bytes: 512,
    })
}

#[test]
fn original_reservation_refuses_foreign_runner_case_oracle_and_credit()
-> Result<(), QualificationError> {
    let owner = Rc::new(());
    let original = reservation(&owner)?;
    let foreign_owner = Rc::new(());
    let foreign_oracle = crucible_node_contract::canonical::content_ref(
        b"different independent template",
        "application/octet-stream",
    )?;

    assert!(original.matches(&owner, original.case(), &original.oracle, 512));
    assert!(!original.matches(&foreign_owner, original.case(), &original.oracle, 512));
    assert!(!original.matches(&owner, "original-after-ack", &original.oracle, 512));
    assert!(!original.matches(&owner, original.case(), &foreign_oracle, 512));
    assert!(!original.matches(&owner, original.case(), &original.oracle, 513));
    Ok(())
}

#[test]
fn abandoned_pre_begin_reservation_keeps_attempt_and_refuses_issuance()
-> Result<(), QualificationError> {
    let owner = Rc::new(());
    let original = reservation(&owner)?;
    let mut attempts = OriginalCollectionAttempts::default();
    attempts.begin(original.case().to_owned());
    drop(original);
    let issuance_called = Cell::new(false);

    let (retained, issued) = attempts.finish(|| {
        issuance_called.set(true);
        Ok(())
    });
    assert!(!issuance_called.get());
    assert!(issued.is_err());
    assert!(retained.attempted_cases().contains("original-before-ack"));
    assert!(retained.authenticated_cases().is_empty());
    Ok(())
}

#[test]
fn authenticated_original_reservation_uses_one_attempt_and_keeps_issuance_result()
-> Result<(), QualificationError> {
    let owner = Rc::new(());
    let original = reservation(&owner)?;
    let mut attempts = OriginalCollectionAttempts::default();
    attempts.begin(original.case().to_owned());
    attempts.authenticate(original.case())?;
    assert!(attempts.authenticate(original.case()).is_err());
    drop(original);

    let (retained, issued) =
        attempts.finish(|| Err::<(), _>(QualificationError::Refused("original encoding refused")));
    assert!(matches!(
        issued,
        Err(QualificationError::Refused("original encoding refused"))
    ));
    assert_eq!(retained.attempted_cases().len(), 1);
    assert_eq!(retained.attempted_cases(), retained.authenticated_cases());
    Ok(())
}

#[test]
fn pre_effect_credit_refuses_zero_overflow_and_aggregate_exhaustion()
-> Result<(), QualificationError> {
    let limits = QualificationLimits {
        maximum_claim_bytes: 100_000,
        maximum_evidence_bytes: 100_000,
        maximum_total_evidence_bytes: 100_000,
        ..QualificationLimits::default()
    };
    assert_eq!(reserve_credit(100, 512, limits)?, 100 + 512 * 6 + 16_384);
    assert!(reserve_credit(100, 0, limits).is_err());
    assert!(reserve_credit(100, u64::MAX, limits).is_err());
    assert!(reserve_credit(u64::MAX, 512, limits).is_err());
    assert!(reserve_credit(90_000, 512, limits).is_err());
    Ok(())
}
