//! Borrowed full-read ownership, bounded work and callback-account regressions.

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Quota {
    resources: FixtureResourceBudget,
    revoked: AtomicBool,
    loans: AtomicUsize,
}

impl StorePhysicalQuotaGuard for Quota {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 * 1024 * 1024)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        bytes: u64,
    ) -> Result<crate::owned_decode::ResourceLoan, StoreError> {
        self.verify()?;
        let loan = self.resources.reserve(descriptors, bytes)?;
        self.loans.fetch_add(1, Ordering::SeqCst);
        Ok(loan)
    }

    fn verify(&self) -> Result<(), StoreError> {
        if self.revoked.load(Ordering::SeqCst) {
            Err(StoreError::Unauthorized)
        } else {
            Ok(())
        }
    }
}

fn account() -> (Arc<Quota>, DecodeBudget) {
    let quota = Arc::new(Quota {
        resources: FixtureResourceBudget::new(8, 4 * 1024 * 1024),
        revoked: AtomicBool::new(false),
        loans: AtomicUsize::new(0),
    });
    let account = DecodeBudget::for_store(quota.clone()).expect("finite original fixture");
    (quota, account)
}

#[test]
fn full_bytes_reads_borrow_body_and_pay_only_output_under_saved_caller() {
    for length in [0, 1, 64 * 1024, 64 * 1024 + 1] {
        let (quota, caller) = account();
        let (foreign_quota, foreign) = account();
        let bytes: Arc<[u8]> = vec![0x61; length].into();
        let handle = BlobHandle::new(BytesBlobSource {
            bytes: bytes.clone(),
        });
        let body_owners = Arc::strong_count(&bytes);
        let retained = quota.resources.usage().unwrap().1;
        let loans = quota.loans.load(Ordering::SeqCst);
        let foreign_retained = foreign_quota.resources.usage().unwrap();
        let foreign_loans = foreign_quota.loans.load(Ordering::SeqCst);
        let mut switched_scope = None;
        let mut calls = 0;

        let output = handle
            .read_all_with_boundary(&caller, length as u64, &mut || {
                calls += 1;
                assert_eq!(
                    Arc::strong_count(&bytes),
                    body_owners,
                    "no cursor body clone"
                );
                if switched_scope.is_none() {
                    switched_scope = Some(foreign.enter());
                }
                Ok(())
            })
            .expect("borrowed complete stream");

        assert_eq!(&*output, &*bytes);
        assert_eq!(calls, 7 + 2 * length.div_ceil(64 * 1024));
        assert_eq!(
            quota.resources.usage().unwrap(),
            (0, retained + length as u64)
        );
        assert_eq!(
            quota.loans.load(Ordering::SeqCst),
            loans + usize::from(length != 0)
        );
        assert_eq!(foreign_quota.loans.load(Ordering::SeqCst), foreign_loans);
        assert_eq!(foreign_quota.resources.usage().unwrap(), foreign_retained);
        assert_eq!(Arc::strong_count(&bytes), body_owners);

        drop(switched_scope);
        drop(caller);
        assert_eq!(
            quota.resources.usage().unwrap(),
            (0, retained + length as u64)
        );
        drop(output);
        assert_eq!(quota.resources.usage().unwrap(), (0, 0));
    }
}

#[test]
fn every_full_bytes_boundary_refuses_revocation_and_closes_output_credit() {
    for refused_call in 1..=9 {
        let (quota, caller) = account();
        let retained = quota.resources.usage().unwrap();
        let handle = BlobHandle::from_bytes([7]);
        let mut calls = 0;

        let error = handle
            .read_all_with_boundary(&caller, 1, &mut || {
                calls += 1;
                if calls == refused_call {
                    quota.revoked.store(true, Ordering::SeqCst);
                }
                Ok(())
            })
            .expect_err("every ingress, chunk, EOF and outer boundary is authoritative");

        assert_eq!(calls, refused_call);
        assert!(matches!(error.original_failure(), StoreError::Unauthorized));
        assert_eq!(quota.resources.usage().unwrap(), retained);
        drop(caller);
        assert_eq!(
            quota.resources.usage().unwrap(),
            retained,
            "refusal retains its genuine caller"
        );
        drop(error);
        assert_eq!(quota.resources.usage().unwrap(), (0, 0));
    }
}

#[derive(Clone)]
struct OpaqueSource(Arc<AtomicUsize>);

impl BlobSource for OpaqueSource {
    fn logical_length(&self) -> u64 {
        1
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Cursor::new([7])))
    }
}

#[test]
fn ordinary_opaque_open_never_grants_checked_full_dispatch() {
    let (_, caller) = account();
    let source = OpaqueSource(Arc::new(AtomicUsize::new(0)));
    let handle = BlobHandle::new(source.clone());

    let error = handle
        .read_all_with_boundary(&caller, 1, &mut || Ok(()))
        .expect_err("ordinary I/O is not a checked capability");

    assert!(matches!(
        error.original_failure(),
        StoreError::Unsupported { .. }
    ));
    assert_eq!(source.0.load(Ordering::SeqCst), 0);
}

#[test]
fn reverified_visible_range_still_authenticates_hidden_full_stream() {
    let (_, caller) = account();
    let _scope = caller.enter();
    let mut bytes = vec![7; 64 * 1024 + 9];
    let (id, source, verified) = super::tests::generic(&bytes);
    let range = verified
        .read_with_boundary(
            &caller,
            id,
            Some(ByteRange {
                offset: 3,
                length: 5,
            }),
            &mut || Ok(()),
        )
        .unwrap();
    let visible_id = ContentId::for_bytes(ObjectKind::Trace, 1, &[7; 5]);
    let range = range.verified_as(visible_id).unwrap();
    *bytes.last_mut().unwrap() = 8;
    *source.bytes.lock().unwrap() = bytes.into();

    let error = range
        .read_all_with_boundary(&caller, 5, &mut || Ok(()))
        .unwrap_err();
    assert!(
        matches!(error.original_failure(), StoreError::Corrupt { id: rejected } if *rejected == id)
    );
}
