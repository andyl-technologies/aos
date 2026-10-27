//! Original-account custody when closed-record entry points refuse child admission.
//!
//! Finite storage accounts and an unrelated ambient scope distinguish the real
//! caller's error lifetime from foreign credit and transient operation storage.

use super::*;
use crate::content_envelope::ContentEnvelope;
use crate::ram::codec::{SCHEMA_VERSION, prepare_envelope_read};
use std::collections::BTreeSet;

enum EntryPoint {
    Envelope,
    Page,
    Tree,
    Root,
    Read,
}

fn refuses_with_original_custody(entry: EntryPoint) {
    let directory = tempfile::tempdir().unwrap();
    let quota = ObservedQuota::new();
    let store = directory_store(directory.path(), &quota);
    let root = store
        .capture(
            topology(4096),
            Scope::Exact,
            &mut patterned,
            &Retention::default(),
            &fixture_original(&store),
            &mut || Ok(()),
        )
        .unwrap();
    let baseline = quota.used();

    let bytes = [7; 17];
    let digest = crucible_ram::PageDigest::hash(&bytes).unwrap();
    let mut body = digest.as_bytes().to_vec();
    body.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    body.extend_from_slice(&bytes);
    let envelope =
        ContentEnvelope::new(PAGE_SCHEMA, SCHEMA_VERSION, BTreeSet::new(), body).unwrap();
    let page = ContentId::for_bytes(ObjectKind::RamExtent, SCHEMA_VERSION, b"unopened page");

    let original = DecodeBudget::for_store(quota.clone()).unwrap();
    original.charge_bytes(4099).unwrap();
    let retained = quota.used();
    let mut boundaries = 0;
    let mut boundary = || {
        boundaries += 1;
        Ok(())
    };
    let mut work = Work::new(store.limits, &original, &mut boundary).unwrap();
    let retention = Retention::default();
    let reservations = quota.reservations.load(Ordering::SeqCst);

    let foreign_quota = ObservedQuota::new();
    let foreign = DecodeBudget::for_store(foreign_quota.clone()).unwrap();
    foreign.charge_bytes(239).unwrap();
    let foreign_reservations = foreign_quota.reservations.load(Ordering::SeqCst);
    let foreign_verifications = foreign_quota.verifications.load(Ordering::SeqCst);
    let scope = foreign.enter();
    quota.revoked.store(true, Ordering::SeqCst);

    let refusal = match entry {
        EntryPoint::Envelope => store
            .put_envelope(&envelope, ObjectKind::RamExtent, &retention, &mut work)
            .map(|_| ()),
        EntryPoint::Page => store.put_page(&bytes, &retention, &mut work).map(|_| ()),
        EntryPoint::Tree => store
            .put_tree(&TreeNode::Padding, 0, 0, &retention, &mut work)
            .map(|_| ()),
        EntryPoint::Root => store
            .put_root(root.record(), &root.regions, &retention, &mut work)
            .map(|_| ()),
        EntryPoint::Read => prepare_envelope_read(page, &mut work).map(|_| ()),
    }
    .unwrap_err();

    let mut cause = Some(&refusal as &(dyn Error + 'static));
    let mut original_refusal = false;
    while let Some(current) = cause {
        original_refusal |= current.is::<RevokedOriginalAuthority>();
        cause = current.source();
    }
    assert!(original_refusal);
    assert_eq!(quota.reservations.load(Ordering::SeqCst), reservations);
    assert_eq!(
        foreign_quota.reservations.load(Ordering::SeqCst),
        foreign_reservations
    );
    assert_eq!(
        foreign_quota.verifications.load(Ordering::SeqCst),
        foreign_verifications
    );
    assert!(retention.objects.lock().unwrap().is_empty());

    drop(scope);
    drop(foreign);
    drop(envelope);
    drop(work);
    assert_eq!(boundaries, 0);
    drop(original);
    let before_error_close = (quota.used(), foreign_quota.used());
    drop(refusal);

    assert_eq!((quota.used(), foreign_quota.used()), (baseline, 0));
    assert_eq!(before_error_close, (retained, 0));
}

#[test]
fn envelope_child_refusal_retains_explicit_original_until_error_close() {
    refuses_with_original_custody(EntryPoint::Envelope);
}

#[test]
fn page_child_refusal_retains_explicit_original_until_error_close() {
    refuses_with_original_custody(EntryPoint::Page);
}

#[test]
fn tree_child_refusal_retains_explicit_original_until_error_close() {
    refuses_with_original_custody(EntryPoint::Tree);
}

#[test]
fn root_child_refusal_retains_explicit_original_until_error_close() {
    refuses_with_original_custody(EntryPoint::Root);
}

#[test]
fn read_child_refusal_retains_explicit_original_until_error_close() {
    refuses_with_original_custody(EntryPoint::Read);
}
