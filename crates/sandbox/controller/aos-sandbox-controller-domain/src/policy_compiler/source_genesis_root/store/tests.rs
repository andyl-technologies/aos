//! Root receipt comparison regressions using existing protected-Source fixtures.
//!
//! These exercise a private DATA-only leaf, not a Root authority constructor,
//! authenticated observation, currentness proof, or live mutation flight.

use super::*;
use crate::JournalLimits;
use crate::hierarchy::source_genesis::tests as source_fixture;

fn receipt_and_intent() -> (SourceTreeGenesisReceiptV1, RootSourceGenesisIntentRecordV1) {
    let directory = source_fixture::directory();
    let mut journal = source_fixture::open(directory.path(), JournalLimits::default());
    let receipt = source_fixture::append(&mut journal);
    let intent = RootSourceGenesisIntentRecordV1::new(
        receipt.instance(),
        journal.protected_owner_uid().unwrap(),
        [11; 16],
        source_fixture::acceptance(receipt.project()),
        ObjectDigest::from_bytes([15; 32]),
    )
    .unwrap();

    (receipt, intent)
}

#[test]
fn retained_intent_requires_original_digest_and_exact_instance() {
    let (receipt, intent) = receipt_and_intent();
    let roles = intent.roles();
    assert!(require_receipt_matches_retained_root(&receipt, Some(&intent), None, roles).is_ok());

    // A fresh observation challenge cannot replace the durable prepare nonce.
    let other_intent = RootSourceGenesisIntentRecordV1::new(
        intent.instance(),
        intent.source_uid(),
        [12; 16],
        intent.accepted_input().clone(),
        roles,
    )
    .unwrap();
    assert!(matches!(
        require_receipt_matches_retained_root(&receipt, Some(&other_intent), None, roles),
        Err(SourceGenesisErrorV1::Conflict)
    ));

    // Keep the intent commitment unchanged to exercise the instance comparison.
    let mut bytes = receipt.encode();
    bytes[16..48].copy_from_slice(&[10; 32]);
    let foreign_instance = SourceTreeGenesisReceiptV1::decode(&bytes).unwrap();
    assert!(matches!(
        require_receipt_matches_retained_root(&foreign_instance, Some(&intent), None, roles),
        Err(SourceGenesisErrorV1::Conflict)
    ));
}

#[test]
fn retained_floor_requires_exact_receipt_and_pinned_roles() {
    let (receipt, intent) = receipt_and_intent();
    let roles = intent.roles();
    let floor = SourceHierarchyFloorRecordV1::new(receipt.clone(), roles).unwrap();
    assert!(require_receipt_matches_retained_root(&receipt, None, Some(&floor), roles).is_ok());
    assert!(matches!(
        require_receipt_matches_retained_root(
            &receipt,
            None,
            Some(&floor),
            ObjectDigest::from_bytes([16; 32]),
        ),
        Err(SourceGenesisErrorV1::Conflict)
    ));

    // Preserve candidate construction errors rather than normalizing them away.
    assert!(matches!(
        require_receipt_matches_retained_root(
            &receipt,
            None,
            Some(&floor),
            ObjectDigest::from_bytes([0; 32]),
        ),
        Err(SourceGenesisErrorV1::NonCanonical)
    ));
}

#[test]
fn retained_floor_rejects_foreign_receipt_fields() {
    let (receipt, intent) = receipt_and_intent();
    let roles = intent.roles();
    let floor = SourceHierarchyFloorRecordV1::new(receipt.clone(), roles).unwrap();

    // Decoded DATA is not an authentic observation. Alter each immutable join
    // independently to ensure floor comparison requires the full receipt.
    for offset in [16, 48, 80, 576, 608, 640] {
        let mut bytes = receipt.encode();
        bytes[offset] ^= 1;
        let foreign = SourceTreeGenesisReceiptV1::decode(&bytes).unwrap();
        assert!(matches!(
            require_receipt_matches_retained_root(&foreign, None, Some(&floor), roles),
            Err(SourceGenesisErrorV1::Conflict)
        ));
    }
}

#[test]
fn retained_receipt_requires_one_root_context_without_fallback() {
    let (receipt, intent) = receipt_and_intent();
    let roles = intent.roles();
    let floor = SourceHierarchyFloorRecordV1::new(receipt.clone(), roles).unwrap();

    assert!(matches!(
        require_receipt_matches_retained_root(&receipt, None, None, roles),
        Err(SourceGenesisErrorV1::Conflict)
    ));
    assert!(matches!(
        require_receipt_matches_retained_root(&receipt, Some(&intent), Some(&floor), roles),
        Err(SourceGenesisErrorV1::Conflict)
    ));
}
