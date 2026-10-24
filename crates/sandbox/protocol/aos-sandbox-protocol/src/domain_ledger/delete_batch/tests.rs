//! Exercises the complete canonical Delete DATA grammar.

use super::*;
use aos_sandbox_model::SandboxId;

#[test]
fn bounded_batch_and_pending_tombstone_round_trip() {
    let bytes = fixture_batch_v1(b"projection", b"retained before", 1);
    let batch = LifecycleDeleteBatchV1::from_bytes(&bytes).unwrap();
    let view = batch.view().unwrap();
    let row = view.rows(0).next().unwrap();
    let pending = tombstone(view, row);

    assert_eq!(batch.as_bytes(), bytes);
    assert_eq!(view.count(4), 1);
    assert!(validate_tombstone(&pending).is_ok());
    assert_eq!(native_value_digest(&pending), row[68..100]);
}

#[test]
fn batch_rejects_reserved_counts_lengths_and_resealed_generation() {
    let bytes = fixture_batch_v1(b"projection", b"retained before", 1);
    for (offset, value) in [(11, 1), (299, 2), (675, 3)] {
        let mut wrong = bytes.clone();
        wrong[offset] = value;
        seal(&mut wrong, BATCH_DOMAIN);
        assert!(DeleteBatchViewV1::decode(&wrong).is_err());
    }
    assert!(DeleteBatchViewV1::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes;
    trailing.push(0);
    assert!(DeleteBatchViewV1::decode(&trailing).is_err());
}

#[test]
fn selected_outcome_has_exact_state_dependent_native_data() {
    let bytes = fixture_batch_v1(b"projection", b"retained before", 1);
    let mut payload = vec![1, 0, 0, 0];
    payload.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&bytes);
    payload.extend_from_slice(&[0; 64]);
    let planned = LifecycleDeleteBatchRecordV1::from_bytes(&payload).unwrap();

    assert_eq!(planned.encode().unwrap(), payload);
    payload[0] = 2;
    assert!(LifecycleDeleteBatchRecordV1::from_bytes(&payload).is_err());
    let start = payload.len() - 64;
    payload[start..start + 16].fill(6);
    payload[start + 16..start + 48].fill(9);
    payload[start + 48..start + 56].copy_from_slice(&9_u64.to_be_bytes());
    payload[start + 56..].copy_from_slice(&1000_u64.to_be_bytes());
    let committed = LifecycleDeleteBatchRecordV1::from_bytes(&payload).unwrap();
    assert!(committed.can_follow(&planned));
    assert!(!planned.can_follow(&committed));
    payload[start] = 7;
    assert!(LifecycleDeleteBatchRecordV1::from_bytes(&payload).is_err());
}

#[test]
fn handoff_is_exact_non_authorizing_dependency_data() {
    let bytes = fixture_batch_v1(b"projection", b"retained before", 1);
    let batch = DeleteBatchViewV1::decode(&bytes).unwrap();
    let mut marker = [0; 160];
    marker[..8].copy_from_slice(b"AOSDHF01");
    marker[9] = 1;
    marker[10] = 1;
    marker[16..32].copy_from_slice(batch.project().as_bytes());
    marker[32..48].copy_from_slice(batch.operation().as_bytes());
    marker[48..64].copy_from_slice(&batch.transaction());
    marker[64..96].copy_from_slice(&batch.checksum());
    marker[96..128].fill(21);
    seal(&mut marker, HANDOFF_DOMAIN);

    assert!(validate_handoff(&marker, batch).is_ok());
    assert_eq!(handoff_key(batch.project(), batch.operation()).len(), 54);
    for offset in [10, 11, 16, 48, 64, 96] {
        let mut wrong = marker;
        wrong[offset] = if offset == 11 { 1 } else { 0 };
        if offset == 96 {
            wrong[96..128].fill(0);
        }
        seal(&mut wrong, HANDOFF_DOMAIN);
        assert!(validate_handoff(&wrong, batch).is_err());
    }
}

#[test]
fn handoff_commits_every_original_source_pending_coordinate() {
    let bytes = fixture_batch_v1(b"projection", b"retained before", 1);
    let batch = DeleteBatchViewV1::decode(&bytes).unwrap();
    let mut native = [0; 64];
    native[..16].fill(2);
    native[16..48].fill(3);
    native[48..56].copy_from_slice(&7_u64.to_be_bytes());
    native[56..64].copy_from_slice(&2000_u64.to_be_bytes());

    let handoff = encode_handoff_from_source_pending_data_v2(batch, &native).unwrap();
    assert!(validate_handoff(&handoff, batch).is_ok());
    assert_eq!(&handoff[96..128], &source_pending_handoff_commitment_data_v2(&native));
    for offset in [0, 16, 55, 63] {
        let mut changed = native;
        changed[offset] ^= 1;
        assert_ne!(source_pending_handoff_commitment_data_v2(&changed), handoff[96..128]);
    }
    for (start, end) in [(0, 16), (16, 48), (48, 56), (56, 64)] {
        let mut missing = native;
        missing[start..end].fill(0);
        assert!(encode_handoff_from_source_pending_data_v2(batch, &missing).is_err());
    }
}

#[test]
fn canonical_ready_order_does_not_accept_caller_tie_order() {
    let first = LifecycleResourceV1::Sandbox(aos_sandbox_model::SandboxId::from_bytes([1; 16]));
    let second = LifecycleResourceV1::Sandbox(aos_sandbox_model::SandboxId::from_bytes([2; 16]));
    let root = LifecycleResourceV1::Sandbox(aos_sandbox_model::SandboxId::from_bytes([3; 16]));
    let edges = [
        LifecycleDependencyEdgeV1::new(first, root).unwrap(),
        LifecycleDependencyEdgeV1::new(second, root).unwrap(),
    ];

    assert!(canonical_dependency_postorder_is_complete(
        &edges,
        &[first, second, root]
    ));
    assert!(!canonical_dependency_postorder_is_complete(
        &edges,
        &[second, first, root]
    ));
}

#[test]
fn collection_fold_keeps_tombstone_data_but_excludes_native_metadata_and_own_hash() {
    let project = ProjectId::from_bytes([4; 16]);
    let owner = LifecycleResourceV1::Sandbox(SandboxId::from_bytes([7; 16]));
    let key = tombstone_key(project, &[1; 17]);
    let members = [DeleteCollectionMemberV1 {
        owner: 7,
        namespace: 1,
        key: &key,
        value: b"complete pending overlay",
    }];
    let populated = collection_root(project, owner, 1, &members).unwrap();

    assert_ne!(populated, collection_root(project, owner, 1, &[]).unwrap());
    for namespace in 2..=4 {
        assert!(
            collection_root(
                project,
                owner,
                1,
                &[DeleteCollectionMemberV1 {
                    owner: 7,
                    namespace,
                    key: b"metadata",
                    value: b"value",
                }]
            )
            .is_err()
        );
    }
    assert!(
        collection_root(
            project,
            owner,
            1,
            &[DeleteCollectionMemberV1 {
                owner: 7,
                namespace: 1,
                key: COLLECTION_PREFIX,
                value: b"own root",
            }]
        )
        .is_err()
    );
}
