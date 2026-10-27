//! Checks additive key-7 bytes and case-3 immutable owner selection.

use super::*;
use crate::gc::retirement::{
    BarrierArtifact, CopiedRetirementAuthorization, CopiedRetirementPlan,
    CopiedRetirementPreparation, Exclusion, OperationPhase, OwnershipSlot,
    PermanentDeleteAuthorization, PermanentDeleteOperation, PreparationPhase, RecordPointer,
    RemoteArtifact,
};

fn authorization() -> Vec<u8> {
    let tombstone = crate::bucket::Tombstone {
        pack_id: [1; 16],
        cycle: 3,
        epoch: 2,
        tombstoned_at: 4,
        removed_entries: 0,
    }
    .encode();
    PermanentDeleteAuthorization::Copied(CopiedRetirementAuthorization {
        nonce: [8; 32],
        backend: BackendBinding::Remote {
            provider: RemoteProvider::S3,
            endpoint: "e".into(),
            bucket: "b".into(),
            prefix: vec![],
            resource_nonce: [1; 32],
            coordination_key: vec![1],
            coordination_nonce: [2; 32],
        },
        exclusion: Exclusion {
            pack: [1; 16],
            cycle: 3,
            epoch: 2,
        },
        lease: crate::gc::GcLease {
            holder: "A".into(),
            epoch: 2,
            expiry: 100,
        },
        deletion_seconds: 2,
        barrier: BarrierArtifact::Remote(RemoteArtifact {
            key: format!("trash/3/{}", "01".repeat(16)),
            digest: *blake3::hash(&tombstone).as_bytes(),
            size: tombstone.len() as u64,
        }),
        tombstone,
        deletion_elapsed_nanos: 2_000_000_000,
        fence: RecordPointer {
            key: "gc/3/fence/1".into(),
            digest: [3; 32],
        },
        grace_seconds: 1,
        grace_elapsed_nanos: 1_000_000_000,
        genesis: OwnershipSlot {
            revision: 0,
            digest: [4; 32],
        },
        preparation: OwnershipSlot {
            revision: 1,
            digest: [5; 32],
        },
        lineage_fence: None,
    })
    .encode()
    .unwrap()
}

fn preparing(authorization: &CopiedRetirementAuthorization) -> CopiedRetirementPreparation {
    CopiedRetirementPreparation {
        revision: 0,
        phase: PreparationPhase::Preparing,
        plan: CopiedRetirementPlan {
            nonce: authorization.nonce,
            backend: authorization.backend.clone(),
            exclusion: authorization.exclusion,
            lease: authorization.lease.clone(),
            deletion_seconds: authorization.deletion_seconds,
            tombstone: authorization.tombstone.clone(),
            fence: RecordPointer {
                key: "gc/3/fence/0".into(),
                digest: [6; 32],
            },
            grace_seconds: authorization.grace_seconds,
            genesis: authorization.genesis,
        },
    }
}

fn local_v1_operation() -> Vec<u8> {
    let lease = crate::gc::GcLease {
        holder: "A".into(),
        epoch: 2,
        expiry: 100,
    }
    .encode()
    .unwrap();
    let tombstone = crate::bucket::Tombstone {
        pack_id: [1; 16],
        cycle: 3,
        epoch: 2,
        tombstoned_at: 4,
        removed_entries: 0,
    }
    .encode();
    let mut witness = b"TRPK\x01\0\0\0".to_vec();
    witness.extend_from_slice(&[1; 16]);
    witness.extend_from_slice(b"TRIX\0\0\0\0\0\0\0\0");
    let mut index_hash = blake3::Hasher::new();
    index_hash.update(b"terrane-index-v1\0");
    index_hash.update(&witness);

    let mut bytes = vec![0xa5, 0, 1, 1, 0xa7, 0];
    cbor::write_bytes(&mut bytes, &[8; 32]);
    bytes.extend_from_slice(&[1, 0x83]);
    cbor::write_bytes(&mut bytes, &[1; 16]);
    bytes.extend_from_slice(&[3, 2, 2]);
    bytes.extend_from_slice(&lease);
    bytes.extend_from_slice(&[3, 2, 4, 0x83]);
    for (kind, suffix, digest, size) in [
        (0, "pack", [7; 32], 52),
        (
            1,
            "idx",
            *index_hash.finalize().as_bytes(),
            witness.len() as u64,
        ),
    ] {
        bytes.push(0x84);
        cbor::write_text(
            &mut bytes,
            &format!("objects/pack/01/{}.{suffix}", "01".repeat(16)),
        );
        cbor::write_bytes(&mut bytes, &[8; 32]);
        bytes.extend_from_slice(&[0x83, kind]);
        cbor::write_bytes(&mut bytes, &digest);
        cbor::write_uint(&mut bytes, size);
        cbor::write_bytes(&mut bytes, &[1]);
    }
    bytes.push(0x84);
    cbor::write_text(&mut bytes, &format!("trash/3/{}", "01".repeat(16)));
    cbor::write_bytes(&mut bytes, &[8; 32]);
    bytes.extend_from_slice(&[0x82, 2]);
    cbor::write_bytes(&mut bytes, &tombstone);
    cbor::write_bytes(&mut bytes, &[1]);
    bytes.push(5);
    cbor::write_bytes(&mut bytes, &witness);
    bytes.push(6);
    cbor::write_uint(&mut bytes, 2_000_000_000);
    bytes.extend_from_slice(&[2, 0, 3, 0, 4]);
    bytes.extend_from_slice(&lease);
    bytes
}

#[test]
fn publication_burn_owner_key7_preserves_legacy_and_known_empty_bytes() {
    let legacy = vec![
        0xa7, 0, 1, 1, 0, 2, 0, 3, 0x80, 4, 0x86, 0, 0x42, b'/', b'a', 1, 2, 3, 4, 5, 0x80, 6, 0xf6,
    ];
    let decoded = PublicationState::decode(&legacy).unwrap();
    assert_eq!(decoded.burn_owners, None);
    assert_eq!(decoded.encode().unwrap(), legacy);
    let mut known_empty = legacy;
    known_empty[0] = 0xa8;
    known_empty.extend_from_slice(&[7, 0x80]);
    let decoded = PublicationState::decode(&known_empty).unwrap();
    assert_eq!(decoded.burn_owners, Some(vec![]));
    assert_eq!(decoded.encode().unwrap(), known_empty);
    let mut visibility = known_empty;
    visibility.pop();
    visibility.extend_from_slice(&[0x81, 0x82, 0x50]);
    visibility.extend_from_slice(&[1; 16]);
    visibility.extend_from_slice(&[0x81, 0]);
    let decoded = PublicationState::decode(&visibility).unwrap();
    assert_eq!(
        decoded.burn_owners.as_ref().unwrap()[0].selection,
        PermanentOwnerSelection::CopiedVisibility
    );
    assert_eq!(decoded.encode().unwrap(), visibility);
    let mut nullable = visibility.clone();
    nullable.truncate(nullable.len() - 2);
    nullable.push(0xf6);
    assert!(PublicationState::decode(&nullable).is_err());
    let mut invalid = decoded;
    let duplicate = invalid.burn_owners.as_ref().unwrap()[0].clone();
    invalid.burn_owners.as_mut().unwrap().push(duplicate);
    assert!(invalid.encode().is_err());
}

#[test]
fn publication_burn_owner_headers_validate_rows_before_growing_storage() {
    let mut malformed = state(0).encode().unwrap();
    malformed[0] = 0xa8;
    malformed.push(7);
    cbor::write_array(&mut malformed, 16_000_000);
    malformed.resize(16 * 1024 * 1024, 0);

    // The count fits the byte bound but the uint first row is not an owner.
    // A header-sized typed reservation would require gigabytes before refusal.
    assert_eq!(
        PublicationState::decode(&malformed),
        Err(PublicationError::Schema)
    );

    let mut valid = state(0).encode().unwrap();
    valid[0] = 0xa8;
    valid.extend_from_slice(&[7, 0x82]);
    for pack in [[0x7f; 16], [0x80; 16]] {
        valid.extend_from_slice(&[0x82, 0x50]);
        valid.extend_from_slice(&pack);
        valid.extend_from_slice(&[0x81, 0]);
    }
    let decoded = PublicationState::decode(&valid).unwrap();
    assert_eq!(decoded.burn_owners.as_ref().unwrap().len(), 2);
    assert_eq!(decoded.encode().unwrap(), valid);
}

#[test]
fn permanent_retirement_proof_case3_has_independent_shape_and_no_copy_lineage_guess() {
    let authorization = authorization();
    let proof = PublicationProof::PermanentRetirement {
        authorization: authorization.clone(),
        carried: vec![],
    };
    let mut bytes = vec![0x83, 3];
    cbor::write_bytes(&mut bytes, &authorization);
    bytes.push(0x80);
    assert_eq!(proof.encode().unwrap(), bytes);
    assert_eq!(PublicationProof::decode(&bytes).unwrap(), proof);
    let mut invalid = proof.clone();
    if let PublicationProof::PermanentRetirement { carried, .. } = &mut invalid {
        carried.push(SourceLineage {
            name: "refs/heads/_/main".into(),
            digest: [6; 32],
        });
    }
    assert!(invalid.encode().is_err());
    let mut invalid = proof;
    if let PublicationProof::PermanentRetirement { authorization, .. } = &mut invalid {
        authorization.push(0);
    }
    assert!(invalid.encode().is_err());
}

fn retirement_transaction() -> PublicationTransaction {
    let authorization = authorization();
    let decoded = PermanentDeleteAuthorization::decode(&authorization).unwrap();
    let owner = PermanentBurnOwner {
        pack: [1; 16],
        selection: PermanentOwnerSelection::Permanent(RecordPointer {
            key: format!("gc/3/delete/{}/{}", "01".repeat(16), "08".repeat(32)),
            digest: *blake3::hash(&authorization).as_bytes(),
        }),
    };
    let mut transaction = transaction();
    transaction.old.as_mut().unwrap().revision = 1;
    transaction.new.revision = 2;
    transaction.predecessor.as_mut().unwrap().revision = 1;
    transaction.predecessor.as_mut().unwrap().digest = [5; 32];
    transaction.snapshot = pointer(2);
    transaction.old.as_mut().unwrap().guard = Some([3; 32]);
    transaction.new.guard = Some([3; 32]);
    transaction.old.as_mut().unwrap().binding = decoded.backend().clone();
    transaction.new.binding = decoded.backend().clone();
    transaction.old.as_mut().unwrap().burn_owners = Some(vec![PermanentBurnOwner {
        pack: [1; 16],
        selection: PermanentOwnerSelection::CopiedVisibility,
    }]);
    transaction.new.burn_owners = Some(vec![owner.clone()]);
    transaction.new.loss_generation = 1;
    let PermanentDeleteAuthorization::Copied(copied) = &decoded else {
        unreachable!()
    };
    transaction.changes = vec![LogicalChange {
        key: format!("gc/3/delete/{}/{}", "01".repeat(16), "08".repeat(32)),
        expected: Some(preparing(copied).encode().unwrap()),
        new: Some(
            PermanentDeleteOperation {
                revision: 1,
                phase: OperationPhase::Proposed,
                authorization: decoded.clone(),
                owner: None,
                pass: None,
            }
            .encode()
            .unwrap(),
        ),
    }];
    transaction.proof = PublicationProof::PermanentRetirement {
        authorization,
        carried: vec![],
    };
    transaction
}

#[test]
fn case3_promotes_copied_visibility_once_and_all_later_proofs_preserve_owner() {
    let mut transaction = retirement_transaction();
    let decoded =
        PermanentDeleteOperation::decode(transaction.changes[0].new.as_ref().unwrap()).unwrap();
    let owner = transaction.new.burn_owners.as_ref().unwrap()[0].clone();
    transaction.encode().unwrap();
    assert_ne!(*decoded.authorization.nonce(), transaction.nonce);
    let mut invalid = transaction.clone();
    invalid.changes.clear();
    assert!(invalid.encode().is_err());
    let mut invalid = transaction.clone();
    invalid.new.loss_generation = 0;
    assert!(invalid.encode().is_err());
    invalid = transaction.clone();
    invalid.proof = PublicationProof::Raw;
    assert!(invalid.encode().is_err());
    invalid = transaction.clone();
    invalid.old.as_mut().unwrap().burn_owners = Some(vec![owner.clone()]);
    assert!(invalid.encode().is_err());
    transaction.old = Some(transaction.new.clone());
    transaction.new.revision += 1;
    transaction.predecessor.as_mut().unwrap().revision += 1;
    transaction.snapshot = pointer(transaction.new.revision);
    transaction.proof = PublicationProof::Raw;
    transaction.changes.clear();
    transaction.encode().unwrap();
    invalid = transaction.clone();
    invalid.new.burn_owners = None;
    assert!(invalid.encode().is_err());
    invalid = transaction.clone();
    invalid.new.burn_owners = Some(vec![]);
    assert!(invalid.encode().is_err());
    invalid = transaction;
    if let PermanentOwnerSelection::Permanent(pointer) =
        &mut invalid.new.burn_owners.as_mut().unwrap()[0].selection
    {
        pointer.digest[0] ^= 1;
    }
    assert!(invalid.encode().is_err());
}

#[test]
fn selected_permanent_progress_keeps_owner_and_uses_fresh_transaction_pass_nonce() {
    let mut transaction = retirement_transaction();
    let proposed =
        PermanentDeleteOperation::decode(transaction.changes[0].new.as_ref().unwrap()).unwrap();
    transaction.old = Some(transaction.new.clone());
    transaction.new.revision = 3;
    transaction.predecessor = Some(PredecessorSlot {
        revision: 2,
        digest: [7; 32],
    });
    transaction.snapshot = pointer(3);
    transaction.proof = PublicationProof::Raw;
    transaction.changes[0].expected = transaction.changes[0].new.clone();
    let mut owned = proposed;
    owned.revision = 2;
    owned.phase = OperationPhase::Owned;
    owned.owner = Some(OwnershipSlot {
        revision: 2,
        digest: [7; 32],
    });
    owned.pass = Some(RecordPointer {
        key: format!("gc/3/reconcile/{}/2", "00".repeat(32)),
        digest: [9; 32],
    });
    transaction.changes[0].new = Some(owned.encode().unwrap());

    let bytes = transaction.encode().unwrap();
    assert_eq!(PublicationTransaction::decode(&bytes).unwrap(), transaction);
    let mut invalid = transaction.clone();
    invalid.predecessor.as_mut().unwrap().digest[0] ^= 1;
    assert!(invalid.encode().is_err());
    invalid = transaction.clone();
    let mut wrong_nonce = owned.clone();
    wrong_nonce.pass.as_mut().unwrap().key = format!("gc/3/reconcile/{}/2", "08".repeat(32));
    invalid.changes[0].new = Some(wrong_nonce.encode().unwrap());
    assert!(invalid.encode().is_err());

    invalid = transaction.clone();
    let mut cancellation = owned.clone();
    cancellation.phase = OperationPhase::Cancelled;
    cancellation.owner = None;
    cancellation.pass = None;
    invalid.changes[0].new = Some(cancellation.encode().unwrap());
    assert!(invalid.encode().is_err());
    invalid = transaction.clone();
    invalid.changes[0].new.as_mut().unwrap()[3] = 3;
    assert!(invalid.encode().is_err());
    invalid = transaction;
    invalid.new.loss_generation += 1;
    assert!(invalid.encode().is_err());
}

#[test]
fn selected_v2_preparation_checks_whole_plan_key_and_preserves_portable_exclusion() {
    let PermanentDeleteAuthorization::Copied(copied) =
        PermanentDeleteAuthorization::decode(&authorization()).unwrap()
    else {
        unreachable!()
    };
    let preparation = preparing(&copied);
    let key = format!("gc/3/delete/{}/{}", "01".repeat(16), "08".repeat(32));
    let mut transaction = transaction();
    transaction.old.as_mut().unwrap().binding = copied.backend.clone();
    transaction.new.binding = copied.backend.clone();
    transaction.old.as_mut().unwrap().guard = Some([3; 32]);
    transaction.new.guard = Some([3; 32]);
    transaction.old.as_mut().unwrap().burn_owners = Some(vec![PermanentBurnOwner {
        pack: [1; 16],
        selection: PermanentOwnerSelection::CopiedVisibility,
    }]);
    transaction.new.burn_owners = transaction.old.as_ref().unwrap().burn_owners.clone();
    transaction.changes = vec![LogicalChange {
        key: key.clone(),
        expected: None,
        new: Some(preparation.encode().unwrap()),
    }];

    let bytes = transaction.encode().unwrap();
    assert_eq!(PublicationTransaction::decode(&bytes).unwrap(), transaction);
    let snapshot = PortableSnapshot {
        revision: 1,
        origin: copied.backend,
        projection: vec![ProjectionEntry {
            key,
            value: transaction.changes[0].new.clone(),
        }],
        predecessor: Some(pointer(0)),
    };
    assert!(snapshot.encode().is_err());

    let mut invalid = transaction.clone();
    invalid.changes[0].key = invalid.changes[0].key.replace("/3/", "/4/");
    assert!(invalid.encode().is_err());
    invalid = transaction.clone();
    invalid.changes[0].new.as_mut().unwrap().push(0);
    assert!(invalid.encode().is_err());
    invalid = transaction.clone();
    invalid.changes[0].new = None;
    assert!(invalid.encode().is_err());
    invalid = transaction.clone();
    // This independently assembled ordinary local-v1 schema stays outside the
    // selected v2 control path even though its CBOR is canonical.
    let local_v1 = local_v1_operation();
    cbor::Decoder::new(&local_v1).skip_value(4096).unwrap();
    invalid.changes[0].new = Some(local_v1);
    assert!(invalid.encode().is_err());

    transaction.old = Some(transaction.new.clone());
    transaction.new.revision = 2;
    transaction.predecessor.as_mut().unwrap().revision = 1;
    transaction.snapshot = pointer(2);
    transaction.changes[0].expected = transaction.changes[0].new.clone();
    let mut abandoned = preparation;
    abandoned.revision = 1;
    abandoned.phase = PreparationPhase::Abandoned;
    transaction.changes[0].new = Some(abandoned.encode().unwrap());
    transaction.encode().unwrap();
    abandoned.plan.deletion_seconds += 1;
    transaction.changes[0].new = Some(abandoned.encode().unwrap());
    assert!(transaction.encode().is_err());
}
