//! Same-original descriptor admission, first refusal, and terminal pin custody.
//!
//! Finite portable counters model descriptor and resident entitlements. These
//! controls do not prove installed filesystem quota, bootstrap control funding,
//! or the ownership of every descriptor used by the surrounding test harness.

use super::*;
use crate::content_store::StorePhysicalQuotaGuard;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::content_store::{StoreError, batch};
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const DESCRIPTORS: u64 = 8;
const RESIDENT_BYTES: u64 = 4 * 1024 * 1024;

struct Quota {
    resources: FixtureResourceBudget,
    descriptor_calls: AtomicU64,
    closed: AtomicBool,
    revoke_after_reservation: AtomicBool,
}

impl Quota {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            resources: FixtureResourceBudget::new(DESCRIPTORS, RESIDENT_BYTES),
            descriptor_calls: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            revoke_after_reservation: AtomicBool::new(false),
        })
    }
}

impl StorePhysicalQuotaGuard for Quota {
    fn verify(&self) -> Result<(), StoreError> {
        if self.closed.load(Ordering::SeqCst) {
            Err(StoreError::Unauthorized)
        } else {
            Ok(())
        }
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(RESIDENT_BYTES)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        let loan = self.resources.reserve(descriptors, bytes)?;
        if descriptors != 0 {
            self.descriptor_calls.fetch_add(1, Ordering::SeqCst);
            if self.revoke_after_reservation.load(Ordering::SeqCst) {
                self.closed.store(true, Ordering::SeqCst);
            }
        }
        Ok(loan)
    }
}

struct ByteOnly {
    resources: FixtureResourceBudget,
}

impl DecodeResourceAuthority for ByteOnly {
    fn verify_live(&self) -> Result<(), DecodeAdmissionError> {
        Ok(())
    }

    fn reserve(&self, bytes: u64) -> Result<ResourceLoan, DecodeAdmissionError> {
        self.resources
            .reserve(0, bytes)
            .map_err(DecodeAdmissionError::new)
    }
}

#[test]
fn byte_only_authority_refuses_descriptor_dispatch_without_substituting_resident_bytes() {
    let authority = Arc::new(ByteOnly {
        resources: FixtureResourceBudget::new(DESCRIPTORS, RESIDENT_BYTES),
    });
    let original = DecodeBudget::new(authority.clone(), RESIDENT_BYTES).expect("finite byte owner");
    let before = authority.resources.usage().expect("original usage");

    let refused = original
        .reserve_descriptors(1)
        .err()
        .expect("no descriptor capability");
    assert!(matches!(
        refused
            .source()
            .and_then(|cause| cause.downcast_ref::<StoreError>()),
        Some(StoreError::Unsupported {
            capability: "original-decode-descriptors"
        })
    ));
    assert_eq!(
        authority.resources.usage().expect("unchanged usage"),
        before
    );
    assert_eq!(original.check(), Err(refused.clone()));
    assert_eq!(original.reserve_descriptors(1).err(), Some(refused));
}

#[test]
fn descriptor_loans_use_the_same_guard_and_exhaustion_stays_sticky_after_refund() {
    let quota = Quota::new();
    let original = DecodeBudget::for_store(quota.clone()).expect("saved original");
    let resident = quota.resources.usage().expect("original usage").1;

    let loan = original
        .reserve_descriptors(DESCRIPTORS)
        .expect("original descriptors");
    assert_eq!(
        quota.resources.usage().expect("retained usage"),
        (DESCRIPTORS, resident)
    );
    let refused = original
        .reserve_descriptors(1)
        .err()
        .expect("same guard is exhausted");
    assert!(matches!(
        refused
            .source()
            .and_then(|cause| cause.downcast_ref::<StoreError>()),
        Some(StoreError::Quota)
    ));
    assert_eq!(quota.descriptor_calls.load(Ordering::SeqCst), 1);

    drop(loan);
    assert_eq!(
        quota.resources.usage().expect("descriptors refunded"),
        (0, resident)
    );
    assert_eq!(original.reserve_descriptors(1).err(), Some(refused));
    assert_eq!(quota.descriptor_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn original_refusal_precedes_reservation_and_post_reservation_revocation_rolls_back() {
    for revoke_after in [false, true] {
        let quota = Quota::new();
        let original = DecodeBudget::for_store(quota.clone()).expect("saved original");
        let resident = quota.resources.usage().expect("original usage").1;
        quota.closed.store(!revoke_after, Ordering::SeqCst);
        quota
            .revoke_after_reservation
            .store(revoke_after, Ordering::SeqCst);

        let refused = original
            .reserve_descriptors(1)
            .err()
            .expect("original revoked");
        assert_eq!(
            quota
                .resources
                .usage()
                .expect("no opened fd credit survives"),
            (0, resident)
        );
        assert_eq!(
            quota.descriptor_calls.load(Ordering::SeqCst),
            u64::from(revoke_after)
        );
        quota.closed.store(false, Ordering::SeqCst);
        assert_eq!(original.reserve_descriptors(1).err(), Some(refused));
        assert_eq!(
            quota.descriptor_calls.load(Ordering::SeqCst),
            u64::from(revoke_after)
        );
    }
}

#[test]
fn failed_open_releases_the_original_descriptor_reservation() {
    let quota = Quota::new();
    let original = DecodeBudget::for_store(quota.clone()).expect("saved original");
    let root = tempfile::tempdir().expect("fixture root");
    let missing = root.path().join("missing");
    let result = (|| {
        let _descriptors = original
            .reserve_descriptors(1)
            .map_err(|cause| batch::admission_under(&original, cause))?;
        assert_eq!(
            quota
                .resources
                .usage()
                .expect("pre-open descriptor credit")
                .0,
            1
        );
        File::open(&missing).map_err(|source| StoreError::StreamIo {
            operation: "test-missing-open",
            source,
        })?;
        Ok::<_, StoreError>(())
    })();

    assert!(matches!(result, Err(StoreError::StreamIo { .. })));
    assert_eq!(quota.resources.usage().expect("failed-open rollback").0, 0);
    original
        .verify_live()
        .expect("failed filesystem open does not renew or poison an admission");
}
