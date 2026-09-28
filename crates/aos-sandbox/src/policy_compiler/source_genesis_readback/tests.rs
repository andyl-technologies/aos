//! Source-only signatures from actual protected read-only journal fixtures.

use super::*;
use crate::JournalLimits;
use crate::hierarchy::source_genesis::tests as fixture;
use crate::journal::JournalTransaction;
use crate::journal::source_tree_genesis::SourceGenesisTransitionV1;
use crate::policy_compiler::source_hold_readback::encode_source_hold_readback_signer_credential_v1;
use crate::policy_compiler::source_signer_readback::sign_genesis_readback_from_view;

fn signer(key: &SigningKey) -> PinnedSourceHoldReadbackSignerV1 {
    PinnedSourceHoldReadbackSignerV1::decode(
        &encode_source_hold_readback_signer_credential_v1(3, &key.verifying_key()).unwrap(),
    )
    .unwrap()
}

#[test]
fn source_genesis_readback_actual_empty_prepared_anchored_are_distinct() {
    let directory = fixture::directory();
    let mut journal = fixture::open(directory.path(), JournalLimits::default());
    let key = SigningKey::from_bytes(&[20; 32]);
    let pin = signer(&key);
    let empty = SourceTreeGenesisChallengeV1::new([21; 16], None).unwrap();
    let mut reader = fixture::reader(directory.path(), JournalLimits::default());
    let packet = sign_genesis_readback_from_view(&mut reader, None, empty, 3, &key).unwrap();
    reader.check_named_currentness_at_uid_for_test().unwrap();
    let verified = verify_source_tree_genesis_readback_v1(&packet, &pin, empty).unwrap();
    assert_eq!(verified.state(), SourceTreeGenesisStateV1::Empty);
    assert!(verified.receipt().is_none());
    assert_eq!(verified.journal_sequence(), 1);
    drop(reader);

    let receipt = fixture::append(&mut journal);
    let challenge =
        SourceTreeGenesisChallengeV1::new([11; 16], Some(receipt.intent_digest())).unwrap();
    let mut reader = fixture::reader(directory.path(), JournalLimits::default());
    assert!(sign_genesis_readback_from_view(&mut reader, None, empty, 3, &key).is_err());
    let packet =
        sign_genesis_readback_from_view(&mut reader, Some(receipt.project()), challenge, 3, &key)
            .unwrap();
    reader.check_named_currentness_at_uid_for_test().unwrap();
    let verified = verify_source_tree_genesis_readback_v1(&packet, &pin, challenge).unwrap();
    assert_eq!(verified.state(), SourceTreeGenesisStateV1::Prepared);
    assert_eq!(verified.receipt(), Some(&receipt));
    assert_eq!(verified.journal_sequence(), 7);
    assert!(verified.ack_floor_digest().is_none());
    assert!(verified.ack_record_digest().is_none());
    drop(reader);

    fixture::anchor(&mut journal, &receipt);
    let mut reader = fixture::reader(directory.path(), JournalLimits::default());
    let fresh = SourceTreeGenesisChallengeV1::new([22; 16], Some(receipt.intent_digest())).unwrap();
    let packet =
        sign_genesis_readback_from_view(&mut reader, Some(receipt.project()), fresh, 3, &key)
            .unwrap();
    reader.check_named_currentness_at_uid_for_test().unwrap();
    let verified = verify_source_tree_genesis_readback_v1(&packet, &pin, fresh).unwrap();
    assert_eq!(verified.state(), SourceTreeGenesisStateV1::Anchored);
    assert_eq!(verified.receipt(), Some(&receipt));
    assert_eq!(verified.journal_sequence(), 11);
    assert_eq!(
        verified.ack_floor_digest(),
        Some(fixture::ack(&receipt).root_floor)
    );
    assert_eq!(
        verified.ack_record_digest(),
        Some(fixture::ack(&receipt).digest())
    );
}

#[test]
fn source_genesis_readback_rejects_legacy_unreceipted_tree_and_foreign_project() {
    let directory = fixture::directory();
    let mut journal = fixture::open(directory.path(), JournalLimits::default());
    let (transaction, receipt, _) = fixture::prepared(&mut journal);
    let legacy = JournalTransaction::new([23; 16], transaction.records()[..2].to_vec()).unwrap();
    journal.commit(&legacy).unwrap();
    let mut reader = fixture::reader(directory.path(), JournalLimits::default());
    let key = SigningKey::from_bytes(&[20; 32]);
    let empty = SourceTreeGenesisChallengeV1::new([21; 16], None).unwrap();
    let challenge =
        SourceTreeGenesisChallengeV1::new([11; 16], Some(receipt.intent_digest())).unwrap();
    assert!(sign_genesis_readback_from_view(&mut reader, None, empty, 3, &key).is_err());
    assert!(
        sign_genesis_readback_from_view(&mut reader, Some(receipt.project()), challenge, 3, &key,)
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
        sign_genesis_readback_from_view(&mut reader, Some(foreign), challenge, 3, &key,).is_err()
    );
    let stale = SourceTreeGenesisChallengeV1::new([25; 16], Some(receipt.intent_digest())).unwrap();
    assert!(
        sign_genesis_readback_from_view(&mut reader, Some(receipt.project()), stale, 3, &key,)
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
    let mut reader = fixture::reader(directory.path(), JournalLimits::default());
    let key = SigningKey::from_bytes(&[20; 32]);
    let pin = signer(&key);
    let challenge =
        SourceTreeGenesisChallengeV1::new([11; 16], Some(receipt.intent_digest())).unwrap();
    let packet =
        sign_genesis_readback_from_view(&mut reader, Some(receipt.project()), challenge, 3, &key)
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
