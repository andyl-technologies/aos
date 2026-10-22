//! Actual paid Whole publication, independent accounts and retained refusals.

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::content_store::test_resources::FixtureResourceBudget;
use crate::owned_decode::ResourceLoan;

struct Quota {
    resources: FixtureResourceBudget,
    revoked: AtomicBool,
    denied: AtomicBool,
}

impl StorePhysicalQuotaGuard for Quota {
    fn verify(&self) -> Result<(), StoreError> {
        if self.revoked.load(Ordering::SeqCst) {
            return Err(StoreError::Unauthorized);
        }
        Ok(())
    }

    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(4 * 1024 * 1024)
    }

    fn reserve_resources(&self, descriptors: u64, bytes: u64) -> Result<ResourceLoan, StoreError> {
        self.verify()?;
        if self.denied.load(Ordering::SeqCst) {
            return Err(StoreError::Quota);
        }
        self.resources.reserve(descriptors, bytes)
    }
}

fn quota() -> Arc<Quota> {
    Arc::new(Quota {
        resources: FixtureResourceBudget::new(8, 4 * 1024 * 1024),
        revoked: AtomicBool::new(false),
        denied: AtomicBool::new(false),
    })
}

fn paid_source(original: &DecodeBudget, bytes: &[u8]) -> BlobHandle {
    let output =
        OwnedBlobBytes::write_with_boundary(original, bytes.len(), &mut || Ok(()), |out| {
            out.copy_from_slice(bytes);
            Ok(out.len())
        })
        .expect("same original paid body");
    BlobHandle::from_owned_bytes(output).expect("same original paid source control")
}

#[test]
fn whole_only_source_publishes_durably_and_reopens_under_the_callers_account() {
    let root = tempfile::tempdir().expect("Directory publication");
    let backend = DirectoryBlobBackend::new("whole-publication", root.path());
    let caller_quota = quota();
    let source_quota = quota();
    let caller = DecodeBudget::for_store(caller_quota.clone()).expect("caller original");
    let payer = DecodeBudget::for_store(source_quota.clone()).expect("independent source original");
    let bytes = vec![0x19; 64 * 1024 + 3];
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let payer_usage = source_quota
        .resources
        .usage()
        .expect("source account baseline");
    let source = paid_source(&payer, &bytes);
    assert_eq!(source.checked_read_access(), CheckedReadAccess::Whole);
    let source_usage = source_quota.resources.usage().expect("live source");
    let caller_usage = caller_quota.resources.usage().expect("caller baseline");

    let receipt = backend
        .put_many_if_absent_with_boundary(&caller, &[(id, source.clone())], &mut || Ok(()))
        .expect("Whole source uses actual Directory transaction");
    let receipt = receipt
        .accept_with_boundary(&mut || Ok(()))
        .expect("durable receipt");
    drop(receipt);
    let reopened = backend
        .read_with_boundary(&caller, id, None, &mut || Ok(()))
        .expect("fresh Directory metadata");
    let output = reopened
        .read_all_with_boundary(&caller, bytes.len() as u64, &mut || Ok(()))
        .expect("complete fresh body");
    assert_eq!(&*output, bytes);
    drop(output);
    drop(reopened);

    assert_eq!(
        source_quota.resources.usage().expect("source retained"),
        source_usage
    );
    assert_eq!(
        caller_quota.resources.usage().expect("caller refunded"),
        caller_usage
    );
    drop(source);
    assert_eq!(
        source_quota
            .resources
            .usage()
            .expect("body and control closed"),
        payer_usage
    );

    drop(payer);
    assert_eq!(
        source_quota
            .resources
            .usage()
            .expect("original account closed"),
        (0, 0)
    );
}

#[test]
fn mismatched_content_identity_refuses_before_whole_staging_writes() {
    let original = DecodeBudget::for_store(quota()).expect("original");
    let source = paid_source(&original, b"corrupt");
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"correct");
    let mut sink = Vec::new();

    let error = copy_checked(
        &original,
        id,
        &source,
        &mut sink,
        Path::new(""),
        &mut || Ok(()),
    )
    .expect_err("every Whole body authenticates independently");
    assert!(matches!(error, StoreError::Corrupt { id: observed } if observed == id));
    assert!(sink.is_empty());
}

struct WrongLength(BlobHandle);

impl BlobSource for WrongLength {
    fn logical_length(&self) -> u64 {
        self.0.logical_length() + 1
    }

    fn checked_read_access(&self) -> CheckedReadAccess {
        CheckedReadAccess::Whole
    }

    fn open(&self) -> Result<Box<dyn Read + Send>, StoreError> {
        Err(StoreError::Unsupported {
            capability: "test-whole-only",
        })
    }

    fn read_all_with_boundary(
        &self,
        original: &DecodeBudget,
        maximum: u64,
        boundary: &mut dyn FnMut() -> Result<(), StoreError>,
    ) -> Result<OwnedBlobBytes, StoreError> {
        self.0.read_all_with_boundary(original, maximum, boundary)
    }
}

#[test]
fn wrong_whole_length_refuses_before_writing() {
    let original = DecodeBudget::for_store(quota()).expect("original");
    let source = BlobHandle::new(WrongLength(paid_source(&original, b"body")));
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"body");
    let mut sink = Vec::new();

    let error = copy_checked(
        &original,
        id,
        &source,
        &mut sink,
        Path::new(""),
        &mut || Ok(()),
    )
    .expect_err("returned length is not declared length");
    assert!(matches!(
        error,
        StoreError::InvalidSourceLength {
            declared: 5,
            observed: 4
        }
    ));
    assert!(sink.is_empty());
}

#[test]
fn source_account_denial_is_not_replaced_by_caller_credit() {
    let source_quota = quota();
    let payer = DecodeBudget::for_store(source_quota.clone()).expect("source original");
    let caller = DecodeBudget::for_store(quota()).expect("independent caller");
    let source = paid_source(&payer, b"body");
    let baseline = source_quota.resources.usage().expect("retained source");
    source_quota.denied.store(true, Ordering::SeqCst);
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"body");
    let mut sink = Vec::new();

    let error = copy_checked(&caller, id, &source, &mut sink, Path::new(""), &mut || {
        Ok(())
    })
    .expect_err("only the source account funds its output");
    assert!(matches!(error, StoreError::DecodeAdmission { .. }));
    assert!(sink.is_empty());
    assert_eq!(
        source_quota.resources.usage().expect("no new credit"),
        baseline
    );
}

struct RevokingSink<'a> {
    source: &'a Quota,
    fail: bool,
    calls: usize,
}

impl Write for RevokingSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        self.source.revoked.store(true, Ordering::SeqCst);
        if self.fail {
            Err(io::ErrorKind::BrokenPipe.into())
        } else {
            Ok(bytes.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn retained_source_revocation_is_observed_after_the_first_write() {
    let source_quota = quota();
    let payer = DecodeBudget::for_store(source_quota.clone()).expect("source original");
    let caller = DecodeBudget::for_store(quota()).expect("caller original");
    let bytes = vec![0x17; 64 * 1024 + 1];
    let source = paid_source(&payer, &bytes);
    let baseline = source_quota.resources.usage().expect("source baseline");
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let mut sink = RevokingSink {
        source: &source_quota,
        fail: false,
        calls: 0,
    };

    let error = copy_checked(&caller, id, &source, &mut sink, Path::new(""), &mut || {
        Ok(())
    })
    .expect_err("source original remains live through writes");
    assert!(matches!(error, StoreError::DecodeAdmission { .. }));
    assert_eq!(sink.calls, 1);
    assert_eq!(
        source_quota.resources.usage().expect("output closed"),
        baseline
    );
}

#[test]
fn final_success_callback_still_checks_the_independent_source_original() {
    let source_quota = quota();
    let payer = DecodeBudget::for_store(source_quota.clone()).expect("source original");
    let caller = DecodeBudget::for_store(quota()).expect("caller original");
    let source = paid_source(&payer, b"body");
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"body");
    let baseline = source_quota.resources.usage().expect("source baseline");
    let mut sink = Vec::new();
    let mut total = 0;
    copy_checked(&caller, id, &source, &mut sink, Path::new(""), &mut || {
        total += 1;
        Ok(())
    })
    .expect("count actual successful callback cuts");

    sink.clear();
    let mut seen = 0;
    let error = copy_checked(&caller, id, &source, &mut sink, Path::new(""), &mut || {
        seen += 1;
        if seen == total {
            source_quota.revoked.store(true, Ordering::SeqCst);
        }
        Ok(())
    })
    .expect_err("the final callback cannot revoke the source unnoticed");
    assert!(matches!(error, StoreError::DecodeAdmission { .. }));
    assert_eq!(seen, total);
    assert_eq!(sink, b"body");
    assert_eq!(
        source_quota.resources.usage().expect("output closed"),
        baseline
    );
}

#[test]
fn initiating_write_error_precedes_later_source_revocation() {
    let source_quota = quota();
    let payer = DecodeBudget::for_store(source_quota.clone()).expect("source original");
    let caller = DecodeBudget::for_store(quota()).expect("caller original");
    let source = paid_source(&payer, b"body");
    let id = ContentId::for_bytes(ObjectKind::Trace, 1, b"body");
    let mut sink = RevokingSink {
        source: &source_quota,
        fail: true,
        calls: 0,
    };

    let error = copy_checked(&caller, id, &source, &mut sink, Path::new(""), &mut || {
        Ok(())
    })
    .expect_err("initiating IO stays first");
    assert!(
        matches!(error, StoreError::Io { operation: "write-object-staging", source, .. }
        if source.kind() == io::ErrorKind::BrokenPipe)
    );
    assert_eq!(sink.calls, 1);
}
