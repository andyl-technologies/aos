//! Canonical durable-cell and source-preserving range transition refusals.

use super::*;

fn progress(bytes: &[u8]) -> OciInventoryProgress {
    let digest = Sha256Digest::digest(bytes);
    OciInventoryProgress {
        version: 1,
        generation_id: format!("ociinv-{}", "a".repeat(32)),
        next_provider_cursor: Some("oci-blobs-v1:next".into()),
        object: OciInventoryObjectProgress::initial(
            1,
            2,
            Some("oci-blobs-v1:current".into()),
            &format!("oci/blobs/sha256/{}", digest.encoded()),
            digest,
            bytes.len() as u64,
            "\"etag\"".into(),
            None,
        )
        .unwrap(),
    }
}

#[test]
fn canonical_progress_roundtrips_without_invented_provider_version() {
    let value = progress(b"bounded source");
    let encoded = value.encode().unwrap();

    assert_eq!(OciInventoryProgress::decode(&encoded).unwrap(), value);
    assert!(!encoded.contains("provider_version"));
    assert!(!encoded.contains("guarded_source"));
    assert!(encoded.len() < MAX_OCI_INVENTORY_PROGRESS_BYTES);
}

#[test]
fn unknown_fields_and_noncanonical_cells_refuse_before_use() {
    let encoded = progress(b"bounded source").encode().unwrap();
    let unknown = encoded.replacen("{", "{\"extension\":1,", 1);

    assert!(OciInventoryProgress::decode(&unknown).is_err());
    assert!(OciInventoryProgress::decode(&format!(" {encoded}")).is_err());
    assert!(OciInventoryProgress::decode("").is_err());
    let mut unscoped = progress(b"bounded source");
    unscoped.object.provider_cursor = Some("current".into());
    assert!(unscoped.validate().is_err());
    assert!(
        OciInventoryProgress::decode(&"x".repeat(MAX_OCI_INVENTORY_PROGRESS_BYTES + 1)).is_err()
    );
}

#[test]
fn key_hash_geometry_and_initial_state_cannot_be_substituted() {
    let value = progress(b"bounded source");
    let mut wrong_key = value.clone();
    wrong_key.object.object_key.push('a');
    let mut wrong_offset = value.clone();
    wrong_offset.object.next_offset = 1;
    let mut wrong_initial = value;
    wrong_initial.object.sha_words[0] ^= 1;

    assert!(wrong_key.validate().is_err());
    assert!(wrong_offset.validate().is_err());
    assert!(wrong_initial.validate().is_err());
}

#[test]
fn successor_advances_only_the_same_exact_source_and_page() {
    let previous = progress(b"bounded source");
    let mut next = previous.clone();
    let mut state = next.object.sha_state().unwrap();
    state.update(b"bounded ").unwrap();
    next.object.next_offset = state.total_bytes;
    next.object.set_sha_state(&state).unwrap();

    previous.validate_successor(&next).unwrap();
    assert!(previous.validate_successor(&previous).is_err());
    let mut changed_source = next.clone();
    changed_source.object.strong_etag = "\"replacement\"".into();
    assert!(previous.validate_successor(&changed_source).is_err());
    let mut changed_page = next;
    changed_page.next_provider_cursor = Some("oci-blobs-v1:other".into());
    assert!(previous.validate_successor(&changed_page).is_err());
}

#[test]
fn successor_cannot_persist_more_than_one_admitted_hash_range() {
    let bytes = vec![0; crate::storage_work::MAX_OCI_HASH_RANGE_BYTES + 1];
    let previous = progress(&bytes);
    let mut next = previous.clone();
    let mut state = next.object.sha_state().unwrap();
    state.update(&bytes).unwrap();
    next.object.next_offset = state.total_bytes;
    next.object.set_sha_state(&state).unwrap();

    assert!(previous.validate_successor(&next).is_err());
}

#[test]
fn guarded_progress_preserves_the_closed_incarnation_across_ranges() {
    use crate::storage_authority::control::StorageAuthorityObjectScope;
    use crate::storage_authority::external_object::copy::source::CopySourceClosure;
    use crate::storage_authority::lease::LeaseInteger;
    use crate::storage_authority::{
        GuardIncarnation, PhysicalStorageAuthorityId, StorageGuardStamp,
    };

    let mut previous = progress(b"bounded source");
    let authority =
        PhysicalStorageAuthorityId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    previous.object.guarded_source = Some(ProtectedInspectionSource {
        version: 1,
        scope: StorageAuthorityObjectScope {
            guard_namespace_id: "controlled-inventory-namespace".into(),
            physical_authority_id: authority.clone(),
            full_key: format!("binding/placement/{}", previous.object.object_key),
        },
        closure: CopySourceClosure {
            guard_stamp: StorageGuardStamp {
                physical_authority_id: authority,
                incarnation: GuardIncarnation::parse("1").unwrap(),
            },
            receipt_digest: "a".repeat(64),
            sha256: Sha256Digest::parse(&previous.object.object_digest)
                .unwrap()
                .encoded()
                .into(),
            bytes: LeaseInteger::new(previous.object.expected_size as i64).unwrap(),
            etag: Some(previous.object.strong_etag.clone()),
        },
    });
    previous.validate().unwrap();
    let encoded = previous.encode().unwrap();
    assert_eq!(OciInventoryProgress::decode(&encoded).unwrap(), previous);

    let mut next = previous.clone();
    let mut state = next.object.sha_state().unwrap();
    state.update(b"bounded ").unwrap();
    next.object.next_offset = state.total_bytes;
    next.object.set_sha_state(&state).unwrap();
    previous.validate_successor(&next).unwrap();

    let source = next.object.guarded_source.as_mut().unwrap();
    source.closure.guard_stamp.incarnation = GuardIncarnation::parse("2").unwrap();
    assert!(previous.validate_successor(&next).is_err());
    next = previous.clone();
    next.object.guarded_source.as_mut().unwrap().scope.full_key =
        format!("sibling{}", next.object.object_key);
    assert!(next.validate().is_err());
}
