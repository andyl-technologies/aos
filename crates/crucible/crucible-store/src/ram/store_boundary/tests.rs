//! Saved-original supervision at checked store callback boundaries.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::{DecodeAdmissionError, DecodeResourceAuthority, ResourceLoan};

#[derive(Debug, thiserror::Error)]
#[error("the adapter fixture original was revoked")]
struct RevokedOriginal;

struct Authority {
    resources: FixtureResourceBudget,
    revoked: AtomicBool,
    refusal: DecodeAdmissionError,
}

impl Authority {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            resources: FixtureResourceBudget::new(0, 1024 * 1024),
            revoked: AtomicBool::new(false),
            refusal: DecodeAdmissionError::new(RevokedOriginal),
        })
    }
}

impl DecodeResourceAuthority for Authority {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(self.refusal.clone())
        } else {
            Ok(())
        }
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.verify_live()?;
        self.resources
            .reserve(0, bytes)
            .map_err(DecodeAdmissionError::new)
    }
}

fn assert_revoked_original(error: &RamStoreError, expected: &DecodeAdmissionError) {
    let RamStoreError::Store(StoreError::DecodeAdmission {
        source,
        custody: Some(_),
    }) = error
    else {
        panic!("adapter must retain the typed original refusal and custody");
    };
    assert_eq!(source, expected);
}

#[test]
fn adapter_rechecks_original_after_successful_callback_and_retains_custody() {
    let authority = Authority::new();
    let original =
        DecodeBudget::new(authority.clone(), 1024 * 1024).expect("finite adapter original");
    let baseline = authority.resources.usage().expect("baseline credit");

    let error = super::super::with_store_operation_boundary(
        &original,
        &mut || {
            authority.revoked.store(true, Ordering::SeqCst);
            Ok(())
        },
        |checked_boundary| {
            checked_boundary()?;
            Ok(())
        },
    )
    .expect_err("revoked original cannot complete the checked operation");
    assert_revoked_original(&error, &authority.refusal);
    assert_eq!(
        authority.resources.usage().expect("post-operation credit"),
        baseline,
        "unused failure prepayments close before the error is returned"
    );

    drop(original);
    assert_ne!(
        authority.resources.usage().expect("error custody credit"),
        (0, 0),
        "the returned refusal keeps its original account alive"
    );
    drop(error);
    assert_eq!(authority.resources.usage().expect("closed credit"), (0, 0));
}

#[test]
fn adapter_refuses_success_after_operation_swallows_original_failure() {
    let authority = Authority::new();
    let original =
        DecodeBudget::new(authority.clone(), 1024 * 1024).expect("finite adapter original");

    let error = super::super::with_store_operation_boundary(
        &original,
        &mut || {
            authority.revoked.store(true, Ordering::SeqCst);
            Ok(())
        },
        |checked_boundary| {
            let refused = checked_boundary().expect_err("post-callback original refusal");
            assert!(matches!(
                refused,
                StoreError::DecodeAdmission { ref source, .. } if source == &authority.refusal
            ));
            Ok(())
        },
    )
    .expect_err("an operation cannot swallow original revocation and report success");
    assert_revoked_original(&error, &authority.refusal);
}

#[test]
fn original_refusal_stays_first_with_distinct_provider_cleanup() {
    let authority = Authority::new();
    let original =
        DecodeBudget::new(authority.clone(), 1024 * 1024).expect("finite adapter original");

    let error = super::super::with_store_operation_boundary(
        &original,
        &mut || {
            authority.revoked.store(true, Ordering::SeqCst);
            Ok(())
        },
        |checked_boundary| {
            assert!(checked_boundary().is_err());
            Err::<(), _>(StoreError::Unavailable)
        },
    )
    .expect_err("original refusal must retain later provider cleanup");
    let RamStoreError::Store(StoreError::RamReadValidation { source }) = error else {
        panic!("validation and provider cleanup require their prepaid joint carrier");
    };
    assert_revoked_original(source.first_validation(), &authority.refusal);
    assert!(matches!(
        source.storage_failure(),
        RamStoreError::Store(StoreError::Unavailable)
    ));
}

#[test]
fn callback_refusal_stays_first_when_it_also_revokes_before_cleanup_failure() {
    let authority = Authority::new();
    let original =
        DecodeBudget::new(authority.clone(), 1024 * 1024).expect("finite adapter original");

    let error = super::super::with_store_operation_boundary(
        &original,
        &mut || {
            authority.revoked.store(true, Ordering::SeqCst);
            Err(RamStoreError::Canceled)
        },
        |checked_boundary| {
            assert!(checked_boundary().is_err());
            Err::<(), _>(StoreError::Unavailable)
        },
    )
    .expect_err("callback refusal must retain later cleanup failure");
    let RamStoreError::Boundary(cause) = error else {
        panic!("caller callback remains the first typed boundary");
    };
    assert!(matches!(
        cause.first_boundary(),
        Some(RamStoreError::Canceled)
    ));
    assert!(matches!(
        cause.storage_failure(),
        RamStoreError::Store(StoreError::Unavailable)
    ));
}
