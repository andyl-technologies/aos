//! Checks direct original source roots and finite lifetime reservations as data.
#![cfg(test)]
// crucible-lint: allow panic-shortcut -- Data-only durable source fixtures panic on setup failures.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_cas::content_store::{DirectoryBlobBackend, DirectoryRefBackend};

#[test]
fn complete_source_reopens_and_refuses_changed_member_or_root() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = DirectoryBlobBackend::new("failure-source-test", directory.path().join("blobs"));
    let refs = DirectoryRefBackend::new(directory.path().join("refs"));
    let bytes = b"original source definition".to_vec();
    let reference = canonical::content_ref(&bytes, "text/plain").unwrap();
    let credit_body = b"data-only original finite source credit".to_vec();
    let credit = canonical::content_ref(&credit_body, "text/plain").unwrap();
    let original = FailureRetirementPreparation {
        world: reference.hash.clone(),
        archive_credit: credit.clone(),
        members: vec![OriginalMember {
            reference: reference.clone(),
            body: SourceBody::Definition { bytes },
        }],
        reference: credit,
        body: credit_body,
        total_bytes: 1024,
    };

    let mut durable = original
        .persist_sources("data-only-source", &blobs, &refs)
        .unwrap();
    original
        .authenticate_durable_sources(&durable, &blobs, &refs)
        .unwrap();

    // Matching digests cannot erase the original media-qualified role.
    durable.members[0].reference.media_type = "application/octet-stream".into();
    assert!(
        original
            .authenticate_durable_sources(&durable, &blobs, &refs)
            .is_err()
    );
    durable.members[0].reference = reference;
    original
        .authenticate_durable_sources(&durable, &blobs, &refs)
        .unwrap();

    let root = index_root("data-only-source").unwrap();
    let foreign = ContentId::for_bytes(ObjectKind::Trace, 1, b"foreign root");
    refs.compare_exchange(&root, Some(durable.identity), foreign)
        .unwrap();
    assert!(
        original
            .authenticate_durable_sources(&durable, &blobs, &refs)
            .is_err()
    );
}

#[test]
fn lifetime_root_credit_refuses_exhaustion_and_malformed_original() {
    let directory = tempfile::tempdir().unwrap();
    let blobs = DirectoryBlobBackend::new("failure-quota-test", directory.path().join("blobs"));
    let refs = DirectoryRefBackend::new(directory.path().join("refs"));
    assert!(reserve_roots(&blobs, &refs, 0).is_err());
    assert!(reserve_roots(&blobs, &refs, 4099 + HISTORY_ROOTS).is_err());
    for _ in 0..15 {
        reserve_roots(&blobs, &refs, 4098 + HISTORY_ROOTS).unwrap();
    }
    assert!(reserve_roots(&blobs, &refs, 4098 + HISTORY_ROOTS).is_err());

    let name = RefName::new("node-capability-failure-source-quota").unwrap();
    let current = refs.read_ref(&name).unwrap().unwrap();
    let bytes = b"{\"consumed\":0}".to_vec();
    let identity = ContentId::for_bytes(ObjectKind::Trace, 1, &bytes);
    let malformed = BlobHandle::from_bytes(bytes);
    blobs.put_if_absent(identity, &malformed).unwrap();
    refs.compare_exchange(&name, Some(current), identity)
        .unwrap();
    assert!(reserve_roots(&blobs, &refs, 1).is_err());
}
