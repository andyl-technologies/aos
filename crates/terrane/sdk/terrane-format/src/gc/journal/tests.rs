//! Checks canonical journal ownership, incarnation mismatch and recovery intent.

#![allow(
    clippy::unwrap_used,
    reason = "invalid test fixtures must fail visibly"
)]

use super::*;
use alloc::vec;

fn authorization() -> DeleteAuthorization {
    let pack_id = [0xab; 16];
    let header = pack_format::Header::new(pack_id, false, false);
    let mut witness = header.encode();
    witness.extend(pack_format::encode_index(&[]));
    let index_digest = TERRANE_V1
        .calculate(IdentityKind::Index, &witness)
        .unwrap()
        .terrane_v1_digest()
        .unwrap();
    let trash = Tombstone {
        pack_id,
        cycle: 8,
        epoch: 2,
        tombstoned_at: 5,
        removed_entries: 0,
    };
    let pack = hex(&pack_id);
    DeleteAuthorization {
        nonce: [7; 32],
        pack_id,
        cycle: 8,
        epoch: 2,
        original_lease: GcLease {
            holder: String::from("owner"),
            epoch: 2,
            expiry: 100,
        },
        deletion_seconds: 4,
        elapsed_ns: 4_000_000_000,
        artifacts: [
            ArtifactVersion {
                key: format!("objects/pack/ab/{pack}.pack"),
                nonce: [1; 32],
                binding: ArtifactBinding::Pack {
                    digest: [9; 32],
                    size: 52,
                },
                file_identity: vec![1],
            },
            ArtifactVersion {
                key: format!("objects/pack/ab/{pack}.idx"),
                nonce: [2; 32],
                binding: ArtifactBinding::Index {
                    digest: index_digest,
                    size: witness.len() as u64,
                },
                file_identity: vec![2],
            },
            ArtifactVersion {
                key: format!("trash/8/{pack}"),
                nonce: [3; 32],
                binding: ArtifactBinding::Trash(trash.encode()),
                file_identity: vec![3],
            },
        ],
        index_witness: witness,
    }
}

#[test]
fn canonical_journals_preserve_exact_owner_and_reject_reincarnation() {
    let authorization = authorization();
    for version in &authorization.artifacts {
        let journal = CreationJournal {
            key: version.key.clone(),
            nonce: version.nonce,
            state: JournalState::Committed {
                binding: version.binding.clone(),
                file_identity: version.file_identity.clone(),
            },
        };
        assert_eq!(
            CreationJournal::decode(&journal.encode().unwrap()).unwrap(),
            journal
        );
        let owned = journal.own(&authorization).unwrap();
        assert_eq!(
            CreationJournal::decode(&owned.encode().unwrap()).unwrap(),
            owned
        );
        let mut replacement = journal.clone();
        replacement.nonce[0] ^= 1;
        assert_eq!(replacement.own(&authorization), Err(GcError::Schema));
        assert!(owned.own(&authorization).is_err());
    }
}

#[test]
fn recovery_progress_preserves_immutable_authorization_across_new_epoch() {
    let authorization = authorization();
    let mut operation = DeleteOperation {
        current_lease: authorization.original_lease.clone(),
        authorization,
        phase: DeletePhase::Authorized,
        revision: 0,
    };
    let original = operation.authorization.digest().unwrap();
    let current = GcLease {
        holder: String::from("recovery"),
        epoch: 3,
        expiry: 200,
    };
    assert!(
        operation
            .advance(DeletePhase::PackAbsent, current.clone())
            .is_err()
    );
    for phase in [
        DeletePhase::Invalidated,
        DeletePhase::PackAbsent,
        DeletePhase::IndexAbsent,
        DeletePhase::ContainersConfirmed,
        DeletePhase::Done,
    ] {
        operation = operation.advance(phase, current.clone()).unwrap();
        operation = DeleteOperation::decode(
            &operation.encode().unwrap(),
            &operation.authorization.operation_key(),
        )
        .unwrap();
        assert_eq!(operation.authorization.digest().unwrap(), original);
        assert_eq!(operation.current_lease, current);
    }
    assert!(operation.advance(DeletePhase::Cancelled, current).is_err());
}

#[test]
fn authorization_rejects_association_wait_and_witness_changes() {
    let original = authorization();
    let mutations: [fn(&mut DeleteAuthorization); 7] = [
        |a| a.artifacts.swap(0, 1),
        |a| a.artifacts[0].key.push('x'),
        |a| a.artifacts[2].key = a.artifacts[2].key.replace("trash/8/", "trash/08/"),
        |a| a.elapsed_ns -= 1,
        |a| a.deletion_seconds = u64::MAX,
        |a| a.index_witness[0] ^= 1,
        |a| a.epoch += 1,
    ];
    for mutate in mutations {
        let mut altered = original.clone();
        mutate(&mut altered);
        assert!(altered.encode().is_err());
    }
    let operation = DeleteOperation {
        authorization: original.clone(),
        phase: DeletePhase::Authorized,
        revision: u64::MAX,
        current_lease: original.original_lease.clone(),
    };
    assert_eq!(
        operation.advance(DeletePhase::Invalidated, operation.current_lease.clone()),
        Err(GcError::Exhausted)
    );
    assert!(
        DeleteOperation::decode(
            &operation.encode().unwrap(),
            "gc/08/delete/not-an-operation"
        )
        .is_err()
    );
}

#[test]
fn field_combinations_and_noncanonical_encodings_fail_closed() {
    let original = authorization();
    let pending = CreationJournal {
        key: original.artifacts[0].key.clone(),
        nonce: [1; 32],
        state: JournalState::Pending,
    };
    let bytes = pending.encode().unwrap();
    assert_eq!(CreationJournal::decode(&bytes).unwrap(), pending);
    for end in 0..bytes.len() {
        assert!(CreationJournal::decode(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(CreationJournal::decode(&trailing).is_err());
    let mut wrong_state = bytes.clone();
    *wrong_state.last_mut().unwrap() = 1;
    assert!(CreationJournal::decode(&wrong_state).is_err());
    let mut noncanonical = bytes.clone();
    noncanonical.splice(2..3, [0x18, 1]);
    assert!(CreationJournal::decode(&noncanonical).is_err());
    let mut missing = pending.clone();
    missing.key = String::from("objects/pack/AB/abababababababababababababababab.pack");
    assert!(missing.encode().is_err());
}

#[test]
fn operation_truncation_and_cancellation_preserve_exact_intent() {
    let authorization = authorization();
    let operation = DeleteOperation {
        current_lease: authorization.original_lease.clone(),
        authorization,
        phase: DeletePhase::Authorized,
        revision: 0,
    };
    let bytes = operation.encode().unwrap();
    let key = operation.authorization.operation_key();
    for end in 0..bytes.len() {
        assert!(DeleteOperation::decode(&bytes[..end], &key).is_err());
    }
    let cancelled = operation
        .advance(DeletePhase::Cancelled, operation.current_lease.clone())
        .unwrap();
    assert_eq!(cancelled.authorization, operation.authorization);
    assert!(
        cancelled
            .advance(DeletePhase::Invalidated, operation.current_lease.clone())
            .is_err()
    );
    let mut wrong_bound = operation.authorization.clone();
    if let ArtifactBinding::Pack { size, .. } = &mut wrong_bound.artifacts[0].binding {
        *size = 1;
    }
    assert!(wrong_bound.encode().is_err());
}

#[test]
fn new_intent_lease_does_not_rewrite_existing_exclusion_epoch() {
    let mut authorization = authorization();
    authorization.original_lease.epoch = 3;
    let operation = DeleteOperation {
        current_lease: authorization.original_lease.clone(),
        authorization,
        phase: DeletePhase::Authorized,
        revision: 0,
    };
    let recovered = DeleteOperation::decode(
        &operation.encode().unwrap(),
        &operation.authorization.operation_key(),
    )
    .unwrap();
    assert_eq!(recovered.authorization.epoch, 2);
    assert_eq!(recovered.authorization.original_lease.epoch, 3);
}
