//! Shared closure consistency and same-provider-metadata incarnation changes.

use super::*;
use crate::storage_authority::lease::LeaseInteger;
use crate::storage_authority::{GuardIncarnation, PhysicalStorageAuthorityId, StorageGuardStamp};

pub(crate) fn fixture() -> ProtectedInspectionSource {
    let authority =
        PhysicalStorageAuthorityId::parse("11111111-1111-4111-8111-111111111111").unwrap();
    ProtectedInspectionSource {
        version: 1,
        scope: StorageAuthorityObjectScope {
            guard_namespace_id: "controlled-external-namespace".into(),
            physical_authority_id: authority.clone(),
            full_key: "binding/placement/object".into(),
        },
        closure: CopySourceClosure {
            guard_stamp: StorageGuardStamp {
                physical_authority_id: authority,
                incarnation: GuardIncarnation::parse("1").unwrap(),
            },
            receipt_digest: "a".repeat(64),
            sha256: "b".repeat(64),
            bytes: LeaseInteger::new(8).unwrap(),
            etag: Some("\"actual-tag\"".into()),
        },
    }
}

#[test]
fn exact_key_size_tag_and_authority_are_independent_fences() {
    let source = fixture();
    source
        .validate_for(&source.scope.full_key, 8, "\"actual-tag\"")
        .unwrap();
    assert!(
        source
            .validate_for("binding/other/object", 8, "\"actual-tag\"")
            .is_err()
    );
    assert!(
        source
            .validate_for(&source.scope.full_key, 9, "\"actual-tag\"")
            .is_err()
    );
    assert!(
        source
            .validate_for(&source.scope.full_key, 8, "\"other\"")
            .is_err()
    );

    let mut changed = source;
    changed.closure.guard_stamp.physical_authority_id =
        PhysicalStorageAuthorityId::parse("22222222-2222-4222-8222-222222222222").unwrap();
    assert!(changed.validate().is_err());
}

#[test]
fn guarded_cursor_changes_with_receipt_or_incarnation_while_legacy_bytes_stay_exact() {
    let source = StorageObjectIdentity {
        key: "placement/object".into(),
        size: 8,
        etag: "\"actual-tag\"".into(),
        provider_version: None,
    };
    let original = fixture();
    let old = crate::tree_projection::source_commitment(&source).unwrap();
    assert_eq!(
        old,
        crate::tree_projection::guarded_source_commitment(&source, None).unwrap()
    );
    let first =
        crate::tree_projection::guarded_source_commitment(&source, Some(&original)).unwrap();
    assert_ne!(old, first);

    let mut replaced = original.clone();
    replaced.closure.guard_stamp.incarnation = GuardIncarnation::parse("2").unwrap();
    assert_ne!(
        first,
        crate::tree_projection::guarded_source_commitment(&source, Some(&replaced)).unwrap()
    );
    replaced = original;
    replaced.closure.receipt_digest = "c".repeat(64);
    assert_ne!(
        first,
        crate::tree_projection::guarded_source_commitment(&source, Some(&replaced)).unwrap()
    );
}

#[test]
fn empty_closed_objects_keep_real_evidence_and_unknown_wire_fields_refuse() {
    let mut source = fixture();
    source.closure.bytes = LeaseInteger::new(0).unwrap();
    source.validate().unwrap();
    let mut encoded = serde_json::to_value(&source).unwrap();
    encoded["permission"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ProtectedInspectionSource>(encoded).is_err());
}
