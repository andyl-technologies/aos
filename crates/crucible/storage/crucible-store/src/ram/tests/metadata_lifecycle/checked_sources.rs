//! Checked encoded-source opens retain the stored original V5 account.

use super::*;
use std::io::Read;

#[test]
fn deferred_encoded_source_keeps_its_reader_after_creating_handles_close() {
    let quota = ObservedQuota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    let codec = original.child().unwrap();
    codec.charge_array::<u8>(17).unwrap();
    let source =
        crate::ram::codec_ownership::encoded_source(vec![7; 17], &codec, &original).unwrap();
    let mut reader = source.open().unwrap();

    drop(source);
    drop(codec);
    drop(original);
    assert!(quota.used() > 17);
    let mut bytes = [0; 17];
    reader.read_exact(&mut bytes).unwrap();
    assert_eq!(bytes, [7; 17]);
    assert_eq!(reader.read(&mut [0]).unwrap(), 0);
    drop(reader);
    assert_eq!(quota.used(), 0);
}

fn deferred_source_refusal(revoke_during_reader_credit: bool) {
    let quota = ObservedQuota::new();
    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    original.charge_bytes(8197).unwrap();
    let admitted_original = quota.used();
    let codec = original.child().unwrap();
    codec.charge_array::<u8>(17).unwrap();
    let source =
        crate::ram::codec_ownership::encoded_source(vec![7; 17], &codec, &original).unwrap();
    let foreign_quota = ObservedQuota::new();
    let foreign = DecodeBudget::for_store(foreign_quota.clone()).unwrap();
    foreign.charge_bytes(239).unwrap();
    let foreign_requests = foreign_quota.reservations.load(Ordering::SeqCst);
    let foreign_scope = foreign.enter();

    if revoke_during_reader_credit {
        // Observe the real child-admission prefix; revoke at its next original
        // verification, when the actual deferred open asks for reader storage.
        let before = quota.verifications.load(Ordering::SeqCst);
        let child = original.child().unwrap();
        let prefix = quota.verifications.load(Ordering::SeqCst) - before;
        assert!(prefix > 0);
        drop(child);
        quota
            .revoke_after_verifications
            .store(prefix + 1, Ordering::SeqCst);
    } else {
        quota.revoked.store(true, Ordering::SeqCst);
    }
    let error = source.open().err().unwrap();
    assert!(quota.revoked.load(Ordering::SeqCst));
    let mut cause = Some(&error as &(dyn Error + 'static));
    let mut actual_revocation = false;
    while let Some(current) = cause {
        if current.is::<RevokedOriginalAuthority>() {
            actual_revocation = true;
            break;
        }
        cause = current.source();
    }
    assert!(
        actual_revocation,
        "the actual original refusal remains typed"
    );
    let funded = matches!(&error, StoreError::DecodeAdmission { .. });
    assert_eq!(
        foreign_quota.reservations.load(Ordering::SeqCst),
        foreign_requests
    );

    drop(foreign_scope);
    drop(foreign);
    assert_eq!(foreign_quota.used(), 0);
    drop(source);
    drop(codec);
    drop(original);
    let retained = quota.used();
    drop(error);
    assert_eq!(quota.used(), 0);
    assert!(
        funded && retained >= admitted_original,
        "deferred-open refusal must retain its actual original: funded={funded}, retained={retained}, admitted={admitted_original}"
    );
}

#[test]
fn deferred_encoded_source_admission_refusal_retains_original_without_foreign_credit() {
    deferred_source_refusal(false);
}

#[test]
fn deferred_encoded_source_reader_credit_refusal_retains_original_without_foreign_credit() {
    deferred_source_refusal(true);
}

#[test]
fn checked_encoded_source_opens_after_creating_scope_and_refuses_original_revocation() {
    let quota = ObservedQuota::new();
    let parent = DecodeBudget::for_store(quota.clone()).unwrap();
    let codec = parent.child().unwrap();
    let scope = codec.enter();
    codec.charge_array::<u8>(128 * 1024).unwrap();
    let source =
        crate::ram::codec_ownership::encoded_source(vec![9; 128 * 1024], &codec, &parent).unwrap();
    drop(scope);
    drop(codec);
    drop(parent);

    let caller_quota = ObservedQuota::new();
    let caller = DecodeBudget::for_store(caller_quota).unwrap();
    let _caller_scope = caller.enter();
    let mut reader = source.open_with_boundary(&mut || Ok(())).unwrap();
    drop(source);
    let mut bytes = vec![0; 128 * 1024];
    let count = reader
        .read_with_boundary(&mut bytes, &mut || Ok(()))
        .unwrap();
    assert_eq!(
        count,
        64 * 1024,
        "checked cursor never exceeds one bounded chunk"
    );
    assert_eq!(&bytes[..count], vec![9; count]);
    assert!(
        quota.used() > 128 * 1024,
        "encoded body and reader remain admitted"
    );
    quota.revoked.store(true, Ordering::SeqCst);
    let error = reader
        .read_with_boundary(&mut bytes, &mut || Ok(()))
        .unwrap_err();
    assert!(
        error.source().is_some(),
        "original typed refusal remains visible"
    );
    quota.revoked.store(false, Ordering::SeqCst);
    assert!(
        reader
            .read_with_boundary(&mut bytes, &mut || Ok(()))
            .is_err(),
        "failed cursor cannot reset"
    );
    drop(reader);
    drop(error);
    assert_eq!(
        quota.used(),
        0,
        "last source/reader/error closes original credit"
    );
}

fn encoded_account() -> (Arc<ObservedQuota>, DecodeBudget) {
    let quota = ObservedQuota::new();
    let account = DecodeBudget::for_store(quota.clone()).unwrap();
    (quota, account)
}

#[test]
fn full_encoded_read_pays_source_original_and_never_ambient_or_caller() {
    let (source_quota, source_original) = encoded_account();
    let source_baseline = source_quota.used();
    let codec = source_original.child().unwrap();
    let bytes = vec![0x29; 64 * 1024 + 3];
    codec.charge_array::<u8>(bytes.len()).unwrap();
    let handle =
        crate::ram::codec_ownership::encoded_source(bytes.clone(), &codec, &source_original)
            .unwrap();
    let retained = source_quota.used();
    let loans = source_quota.reservations.load(Ordering::SeqCst);
    let (caller_quota, caller) = encoded_account();
    let (foreign_quota, foreign) = encoded_account();
    let caller_loans = caller_quota.reservations.load(Ordering::SeqCst);
    let foreign_loans = foreign_quota.reservations.load(Ordering::SeqCst);
    let mut switched_scope = None;
    let mut calls = 0;

    let output = handle
        .read_all_with_boundary(&caller, bytes.len() as u64, &mut || {
            calls += 1;
            if switched_scope.is_none() {
                switched_scope = Some(foreign.enter());
            }
            Ok(())
        })
        .unwrap();

    assert_eq!(&*output, &bytes);
    assert_eq!(calls, 11);
    assert_eq!(source_quota.reservations.load(Ordering::SeqCst), loans + 1);
    assert_eq!(source_quota.used(), retained + bytes.len() as u64);
    assert_eq!(
        caller_quota.reservations.load(Ordering::SeqCst),
        caller_loans
    );
    assert_eq!(
        foreign_quota.reservations.load(Ordering::SeqCst),
        foreign_loans
    );
    source_quota.revoked.store(true, Ordering::SeqCst);
    assert!(
        output.original_account().verify_live().is_err(),
        "output exposes its actual source payer"
    );

    drop(switched_scope);
    drop(handle);
    drop(codec);
    drop(source_original);
    assert_eq!(source_quota.used(), source_baseline + bytes.len() as u64);
    drop(output);
    assert_eq!(source_quota.resources.usage().unwrap(), (0, 0));
}

#[test]
fn caller_refusal_precedes_callback_and_source_funding() {
    let (source_quota, source_original) = encoded_account();
    let codec = source_original.child().unwrap();
    codec.charge_array::<u8>(1).unwrap();
    let handle =
        crate::ram::codec_ownership::encoded_source(vec![7], &codec, &source_original).unwrap();
    let loans = source_quota.reservations.load(Ordering::SeqCst);
    let (caller_quota, caller) = encoded_account();
    caller_quota.revoked.store(true, Ordering::SeqCst);
    let mut calls = 0;

    let error = handle
        .read_all_with_boundary(&caller, 1, &mut || {
            calls += 1;
            Err(StoreError::Quota)
        })
        .unwrap_err();

    assert_eq!(calls, 0);
    assert!(error.source().is_some());
    assert_eq!(source_quota.reservations.load(Ordering::SeqCst), loans);
}

#[test]
fn caller_revoked_at_terminal_callback_cannot_publish_source_paid_output() {
    let (source_quota, source_original) = encoded_account();
    let codec = source_original.child().unwrap();
    codec.charge_array::<u8>(1).unwrap();
    let handle =
        crate::ram::codec_ownership::encoded_source(vec![7], &codec, &source_original).unwrap();
    let retained = source_quota.resources.usage().unwrap();
    let (caller_quota, caller) = encoded_account();
    let mut calls = 0;

    let error = handle
        .read_all_with_boundary(&caller, 1, &mut || {
            calls += 1;
            if calls == 9 {
                caller_quota.revoked.store(true, Ordering::SeqCst);
            }
            Ok(())
        })
        .unwrap_err();

    assert_eq!(calls, 9, "last outer terminal acceptance refuses");
    assert!(error.source().is_some());
    assert_eq!(
        source_quota.resources.usage().unwrap(),
        retained,
        "raw output credit closes on refusal"
    );
}
