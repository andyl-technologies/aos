//! Source-only signatures from actual protected read-only journal fixtures.

use super::*;
use crate::JournalLimits;
use crate::hierarchy::source_genesis::tests as fixture;
use crate::journal::source_tree_genesis::SourceGenesisTransitionV1;
use crate::journal::{JournalRecord, JournalTransaction, RecordNamespace};
use crate::policy_compiler::source_hold_readback::encode_source_hold_readback_signer_credential_v1;
use crate::policy_compiler::source_signer_readback::sign_genesis_readback_from_view;

fn signer(key: &SigningKey) -> PinnedSourceHoldReadbackSignerV1 {
    PinnedSourceHoldReadbackSignerV1::decode(
        &encode_source_hold_readback_signer_credential_v1(3, &key.verifying_key()).unwrap(),
    )
    .unwrap()
}

#[test]
fn source_genesis_exact_pending_recovery_keeps_original_nonce_and_fresh_correlation() {
    let key = SigningKey::from_bytes(&[20; 32]);
    let pin = signer(&key);

    // The original canonical intent is prepared before append. Reopening the
    // Source writer does not replace its nonce, even when append occurs only
    // after reconnecting Root. These are row/codec fixtures, not live proofs.
    for append_before_restart in [false, true] {
        let directory = fixture::directory();
        let mut journal = fixture::open(directory.path(), JournalLimits::default());
        let (transaction, receipt, original_pending) = fixture::prepared(&mut journal);
        let context = fixture::intent_context(&journal, receipt.project());
        if append_before_restart {
            journal
                .commit_source_tree_genesis_v1(&transaction, SourceGenesisTransitionV1::Append)
                .unwrap();
        }
        drop(journal);
        let mut journal = fixture::open(directory.path(), JournalLimits::default());
        if !append_before_restart {
            journal
                .commit_source_tree_genesis_v1(&transaction, SourceGenesisTransitionV1::Append)
                .unwrap();
        }
        let before = journal.source_tree_genesis_rows_v1().unwrap();
        let sequence = journal.snapshot_sequence();

        // The original intent may already be deleted by Root's floor CAS.
        // Its exact floor plus original acceptance still supplies comparison
        // data; only Source's pending row supplies the retained nonce.
        let floor = crate::policy_compiler::SourceHierarchyFloorRecordV1::new(
            receipt.clone(),
            ObjectDigest::from_bytes([15; 32]),
        )
        .unwrap();
        let floor_context = SourceTreeGenesisIntentContextV1::new(
            journal.protected_owner_uid().unwrap(),
            floor.roles(),
            fixture::acceptance(floor.project()),
        )
        .unwrap();
        assert_eq!(floor_context, context);

        for fresh_nonce in [[51; 16], [52; 16], [53; 16]] {
            assert_ne!(fresh_nonce, original_pending.nonce);
            let challenge =
                SourceTreeGenesisChallengeV1::new(fresh_nonce, Some(receipt.intent_digest()))
                    .unwrap();
            let mut reader = fixture::reader(directory.path(), JournalLimits::default());
            let packet = sign_genesis_readback_from_view(
                &mut reader,
                Some(receipt.project()),
                challenge,
                Some(&floor_context),
                3,
                &key,
            )
            .unwrap();
            reader.check_named_currentness_at_uid_for_test().unwrap();
            let verified =
                verify_source_tree_genesis_readback_v1(&packet, &pin, challenge).unwrap();
            assert_eq!(verified.state(), SourceTreeGenesisStateV1::Prepared);
            assert_eq!(verified.receipt(), Some(&receipt));
            let old_correlation =
                SourceTreeGenesisChallengeV1::new(original_pending.nonce, challenge.intent())
                    .unwrap();
            assert!(
                verify_source_tree_genesis_readback_v1(&packet, &pin, old_correlation).is_err()
            );
        }
        assert_eq!(journal.source_tree_genesis_rows_v1().unwrap(), before);
        assert_eq!(journal.snapshot_sequence(), sequence);
        assert_eq!(before.pending.as_ref(), Some(&original_pending));
    }
}

#[test]
fn source_genesis_pending_recovery_rejects_rebound_original_nonce_and_context() {
    let key = SigningKey::from_bytes(&[20; 32]);
    for wrong_original_nonce in [false, true] {
        let directory = fixture::directory();
        let mut journal = fixture::open(directory.path(), JournalLimits::default());
        let (transaction, receipt, mut pending) = fixture::prepared(&mut journal);
        let context = fixture::intent_context(&journal, receipt.project());
        let mut records = transaction.records().to_vec();
        if wrong_original_nonce {
            pending.nonce = [54; 16];
            // The structural journal contract accepts this consistent frame;
            // independent reconstruction must still reject its wrong identity.
            records[3] = JournalRecord::put(
                RecordNamespace::DesiredState,
                crate::journal::source_tree_genesis::PENDING_KEY.to_vec(),
                pending.encode().to_vec(),
            );
        }
        let transaction = JournalTransaction::new([55; 16], records).unwrap();
        journal
            .commit_source_tree_genesis_v1(&transaction, SourceGenesisTransitionV1::Append)
            .unwrap();
        drop(journal);
        let journal = fixture::open(directory.path(), JournalLimits::default());
        let sequence = journal.snapshot_sequence();
        let challenge =
            SourceTreeGenesisChallengeV1::new([56; 16], Some(receipt.intent_digest())).unwrap();

        let mut contexts = vec![context.clone()];
        for offset in [16, 24, 632] {
            // UID, Root roles, administrative acceptance roles.
            let mut bytes = context.encode();
            bytes[offset] ^= 1;
            contexts.push(SourceTreeGenesisIntentContextV1::decode(&bytes).unwrap());
        }
        for (index, context) in contexts.iter().enumerate() {
            let mut reader = fixture::reader(directory.path(), JournalLimits::default());
            let result = sign_genesis_readback_from_view(
                &mut reader,
                Some(receipt.project()),
                challenge,
                Some(context),
                3,
                &key,
            );
            assert_eq!(result.is_err(), wrong_original_nonce || index != 0);
        }
        let mut reader = fixture::reader(directory.path(), JournalLimits::default());
        assert!(
            sign_genesis_readback_from_view(
                &mut reader,
                Some(receipt.project()),
                challenge,
                None,
                3,
                &key,
            )
            .is_err()
        );
        assert_eq!(journal.snapshot_sequence(), sequence);
    }
}

#[test]
fn source_genesis_global_empty_rejects_every_unrelated_source_row() {
    let key = SigningKey::from_bytes(&[20; 32]);
    for namespace in [RecordNamespace::DesiredState, RecordNamespace::Effect] {
        let directory = fixture::directory();
        let mut journal = fixture::open(directory.path(), JournalLimits::default());
        let transaction = JournalTransaction::new(
            [57; 16],
            vec![JournalRecord::put(
                namespace,
                b"unrelated-source-row".to_vec(),
                vec![1],
            )],
        )
        .unwrap();
        journal.commit(&transaction).unwrap();
        let mut reader = fixture::reader(directory.path(), JournalLimits::default());
        let empty = SourceTreeGenesisChallengeV1::new([58; 16], None).unwrap();
        assert!(sign_genesis_readback_from_view(&mut reader, None, empty, None, 3, &key).is_err());
    }
}

#[test]
fn source_genesis_anchored_context_requires_exact_ack_role_commitment() {
    let directory = fixture::directory();
    let mut journal = fixture::open(directory.path(), JournalLimits::default());
    let receipt = fixture::append(&mut journal);
    let context = fixture::intent_context(&journal, receipt.project());
    let floor = crate::policy_compiler::SourceHierarchyFloorRecordV1::new(
        receipt.clone(),
        ObjectDigest::from_bytes([15; 32]),
    )
    .unwrap();
    fixture::anchor_with_floors(
        &mut journal,
        &receipt,
        floor.digest(),
        fixture::ack(&receipt).controller_floor,
    );
    let key = SigningKey::from_bytes(&[20; 32]);
    let challenge =
        SourceTreeGenesisChallengeV1::new([59; 16], Some(receipt.intent_digest())).unwrap();
    let mut reader = fixture::reader(directory.path(), JournalLimits::default());
    assert!(
        sign_genesis_readback_from_view(
            &mut reader,
            Some(receipt.project()),
            challenge,
            Some(&context),
            3,
            &key,
        )
        .is_ok()
    );

    let mut bytes = context.encode();
    bytes[24] ^= 1;
    let rebound = SourceTreeGenesisIntentContextV1::decode(&bytes).unwrap();
    assert!(
        sign_genesis_readback_from_view(
            &mut reader,
            Some(receipt.project()),
            challenge,
            Some(&rebound),
            3,
            &key,
        )
        .is_err()
    );
}

#[test]
fn source_genesis_intent_context_rejects_noncanonical_data_and_foreign_fixed_uid() {
    let directory = fixture::directory();
    let journal = fixture::open(directory.path(), JournalLimits::default());
    let context =
        fixture::intent_context(&journal, aos_sandbox_core::ProjectId::from_bytes([1; 16]));
    let bytes = context.encode();
    assert_eq!(
        SourceTreeGenesisIntentContextV1::decode(&bytes).unwrap(),
        context
    );
    for length in [0, 56, 663] {
        assert!(SourceTreeGenesisIntentContextV1::decode(&bytes[..length]).is_err());
    }
    for range in [8..10, 16..20, 24..56, 56..64, 632..664] {
        let mut changed = bytes;
        changed[range].fill(0);
        assert!(SourceTreeGenesisIntentContextV1::decode(&changed).is_err());
    }
    for offset in [0, 10, 20, 56] {
        let mut changed = bytes;
        changed[offset] ^= 1;
        assert!(SourceTreeGenesisIntentContextV1::decode(&changed).is_err());
    }
    let mut changed = bytes;
    changed[16] ^= 1;
    let foreign = SourceTreeGenesisIntentContextV1::decode(&changed).unwrap();
    let challenge =
        SourceTreeGenesisChallengeV1::new([60; 16], Some(ObjectDigest::from_bytes([61; 32])))
            .unwrap();
    // The real entry checks privileged UID configuration before opening any
    // fixed mount or attempting to treat the context as original custody.
    assert!(matches!(
        crate::policy_compiler::source_signer_readback::sign_fixed_source_tree_genesis_readback_v2(
            context.source_uid(),
            Some(context.project()),
            challenge,
            Some(&foreign),
            3,
            &SigningKey::from_bytes(&[20; 32]),
        ),
        Err(
            crate::policy_compiler::source_signer_readback::SourceSignerReadbackErrorV1::Signing(_)
        )
    ));
}

#[test]
fn source_genesis_readback_actual_empty_prepared_anchored_are_distinct() {
    let directory = fixture::directory();
    let mut journal = fixture::open(directory.path(), JournalLimits::default());
    let key = SigningKey::from_bytes(&[20; 32]);
    let pin = signer(&key);
    let empty = SourceTreeGenesisChallengeV1::new([21; 16], None).unwrap();
    let mut reader = fixture::reader(directory.path(), JournalLimits::default());
    let packet = sign_genesis_readback_from_view(&mut reader, None, empty, None, 3, &key).unwrap();
    reader.check_named_currentness_at_uid_for_test().unwrap();
    let verified = verify_source_tree_genesis_readback_v1(&packet, &pin, empty).unwrap();
    assert_eq!(verified.state(), SourceTreeGenesisStateV1::Empty);
    assert!(verified.receipt().is_none());
    assert_eq!(verified.journal_sequence(), 1);
    drop(reader);

    let receipt = fixture::append(&mut journal);
    let context = fixture::intent_context(&journal, receipt.project());
    let challenge =
        SourceTreeGenesisChallengeV1::new([11; 16], Some(receipt.intent_digest())).unwrap();
    let mut reader = fixture::reader(directory.path(), JournalLimits::default());
    assert!(sign_genesis_readback_from_view(&mut reader, None, empty, None, 3, &key).is_err());
    let packet = sign_genesis_readback_from_view(
        &mut reader,
        Some(receipt.project()),
        challenge,
        Some(&context),
        3,
        &key,
    )
    .unwrap();
    reader.check_named_currentness_at_uid_for_test().unwrap();
    let verified = verify_source_tree_genesis_readback_v1(&packet, &pin, challenge).unwrap();
    assert_eq!(verified.state(), SourceTreeGenesisStateV1::Prepared);
    assert_eq!(verified.receipt(), Some(&receipt));
    assert_eq!(verified.journal_sequence(), 7);
    assert!(verified.ack_floor_digest().is_none());
    assert!(verified.ack_record_digest().is_none());
    drop(reader);

    let floor = crate::policy_compiler::SourceHierarchyFloorRecordV1::new(
        receipt.clone(),
        ObjectDigest::from_bytes([15; 32]),
    )
    .unwrap();
    fixture::anchor_with_floors(
        &mut journal,
        &receipt,
        floor.digest(),
        fixture::ack(&receipt).controller_floor,
    );
    let mut reader = fixture::reader(directory.path(), JournalLimits::default());
    let fresh = SourceTreeGenesisChallengeV1::new([22; 16], Some(receipt.intent_digest())).unwrap();
    let packet = sign_genesis_readback_from_view(
        &mut reader,
        Some(receipt.project()),
        fresh,
        Some(&context),
        3,
        &key,
    )
    .unwrap();
    reader.check_named_currentness_at_uid_for_test().unwrap();
    let verified = verify_source_tree_genesis_readback_v1(&packet, &pin, fresh).unwrap();
    assert_eq!(verified.state(), SourceTreeGenesisStateV1::Anchored);
    assert_eq!(verified.receipt(), Some(&receipt));
    assert_eq!(verified.journal_sequence(), 11);
    assert_eq!(verified.ack_floor_digest(), Some(floor.digest()));
    assert_eq!(
        verified.ack_record_digest(),
        Some(
            journal
                .source_tree_genesis_rows_v1()
                .unwrap()
                .acks
                .get(&receipt.project())
                .unwrap()
                .digest()
        )
    );
}

#[test]
fn source_genesis_readback_rejects_legacy_unreceipted_tree_and_foreign_project() {
    let directory = fixture::directory();
    let mut journal = fixture::open(directory.path(), JournalLimits::default());
    let (transaction, receipt, _) = fixture::prepared(&mut journal);
    let context = fixture::intent_context(&journal, receipt.project());
    let legacy = JournalTransaction::new([23; 16], transaction.records()[..2].to_vec()).unwrap();
    journal.commit(&legacy).unwrap();
    let mut reader = fixture::reader(directory.path(), JournalLimits::default());
    let key = SigningKey::from_bytes(&[20; 32]);
    let empty = SourceTreeGenesisChallengeV1::new([21; 16], None).unwrap();
    let challenge =
        SourceTreeGenesisChallengeV1::new([11; 16], Some(receipt.intent_digest())).unwrap();
    assert!(sign_genesis_readback_from_view(&mut reader, None, empty, None, 3, &key).is_err());
    assert!(
        sign_genesis_readback_from_view(
            &mut reader,
            Some(receipt.project()),
            challenge,
            Some(&context),
            3,
            &key,
        )
        .is_err()
    );
    drop(reader);
    drop(journal);

    let directory = fixture::directory();
    let mut journal = fixture::open(directory.path(), JournalLimits::default());
    let receipt = fixture::append(&mut journal);
    let mut reader = fixture::reader(directory.path(), JournalLimits::default());
    let foreign = aos_sandbox_core::ProjectId::from_bytes([24; 16]);
    assert!(
        sign_genesis_readback_from_view(
            &mut reader,
            Some(foreign),
            challenge,
            Some(&context),
            3,
            &key,
        )
        .is_err()
    );
    let stale =
        SourceTreeGenesisChallengeV1::new([25; 16], Some(ObjectDigest::from_bytes([25; 32])))
            .unwrap();
    assert!(
        sign_genesis_readback_from_view(
            &mut reader,
            Some(receipt.project()),
            stale,
            Some(&context),
            3,
            &key,
        )
        .is_err()
    );
    assert!(
        journal
            .commit_source_tree_genesis_v1(&transaction, SourceGenesisTransitionV1::Append,)
            .is_err()
    );
}

#[test]
fn source_genesis_readback_signature_correlation_names_and_phase_padding_fail_closed() {
    let directory = fixture::directory();
    let mut journal = fixture::open(directory.path(), JournalLimits::default());
    let receipt = fixture::append(&mut journal);
    let context = fixture::intent_context(&journal, receipt.project());
    let mut reader = fixture::reader(directory.path(), JournalLimits::default());
    let key = SigningKey::from_bytes(&[20; 32]);
    let pin = signer(&key);
    let challenge =
        SourceTreeGenesisChallengeV1::new([11; 16], Some(receipt.intent_digest())).unwrap();
    let packet = sign_genesis_readback_from_view(
        &mut reader,
        Some(receipt.project()),
        challenge,
        Some(&context),
        3,
        &key,
    )
    .unwrap();
    assert!(
        verify_source_tree_genesis_readback_v1(
            &packet,
            &signer(&SigningKey::from_bytes(&[26; 32])),
            challenge
        )
        .is_err()
    );
    for offset in [0, 8, 11, 16, 32, 64, 72, 80, 128, 800, 832, 864] {
        let mut changed = packet;
        changed[offset] ^= 1;
        assert!(verify_source_tree_genesis_readback_v1(&changed, &pin, challenge).is_err());
    }
    for phase in [0, 2, 3] {
        let mut changed = packet;
        changed[10] = phase;
        let signature = key.sign(&signature_preimage(&changed[..BODY_BYTES]));
        changed[BODY_BYTES..].copy_from_slice(&signature.to_bytes());
        assert!(verify_source_tree_genesis_readback_v1(&changed, &pin, challenge).is_err());
    }
    let foreign = SourceTreeGenesisChallengeV1::new([27; 16], challenge.intent()).unwrap();
    assert!(verify_source_tree_genesis_readback_v1(&packet, &pin, foreign).is_err());
    assert!(SourceTreeGenesisChallengeV1::new([0; 16], None).is_err());
    assert!(
        SourceTreeGenesisChallengeV1::new([1; 16], Some(ObjectDigest::from_bytes([0; 32])))
            .is_err()
    );
}
