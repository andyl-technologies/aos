//! Actual Source row/signature regressions, not a production Root owner factory.
//!
//! The shared join leaf is exercised with canonical protected Source append,
//! ACK, compaction and cold replay. No test installs Root credentials, creates
//! a current Root token, or proves the original normal daemon/client flight.

use ed25519_dalek::SigningKey;

use super::*;
use crate::JournalLimits;
use crate::hierarchy::source_genesis::tests as source_fixture;
use crate::journal::Journal;
use crate::policy_compiler::source_genesis_readback::{
    SourceTreeGenesisChallengeV1, verify_source_tree_genesis_readback_v1,
};
use crate::policy_compiler::source_hold_readback::{
    PinnedSourceHoldReadbackSignerV1, encode_source_hold_readback_signer_credential_v1,
};
use crate::policy_compiler::source_signer_readback::sign_genesis_readback_from_view;
use aos_sandbox_core::ObjectDigest;

struct Fixture {
    directory: tempfile::TempDir,
    journal: Journal,
    floor: SourceHierarchyFloorRecordV1,
    context: crate::policy_compiler::SourceTreeGenesisIntentContextV1,
    key: SigningKey,
    pin: PinnedSourceHoldReadbackSignerV1,
}

impl Fixture {
    fn prepared() -> Self {
        let directory = source_fixture::directory();
        let mut journal = source_fixture::open(directory.path(), JournalLimits::default());
        let receipt = source_fixture::append(&mut journal);
        let context = source_fixture::intent_context(&journal, receipt.project());
        let floor =
            SourceHierarchyFloorRecordV1::new(receipt, ObjectDigest::from_bytes([15; 32])).unwrap();
        let key = SigningKey::from_bytes(&[31; 32]);
        let pin = PinnedSourceHoldReadbackSignerV1::decode(
            &encode_source_hold_readback_signer_credential_v1(3, &key.verifying_key()).unwrap(),
        )
        .unwrap();
        Self {
            directory,
            journal,
            floor,
            context,
            key,
            pin,
        }
    }

    fn anchor(&mut self) {
        source_fixture::anchor_with_floors(
            &mut self.journal,
            self.floor.receipt(),
            self.floor.digest(),
            ObjectDigest::from_bytes([32; 32]),
        );
    }

    fn challenge(&self, nonce: [u8; 16]) -> SourceTreeGenesisChallengeV1 {
        SourceTreeGenesisChallengeV1::new(nonce, Some(self.floor.receipt().intent_digest()))
            .unwrap()
    }

    fn packet(
        &self,
        challenge: SourceTreeGenesisChallengeV1,
    ) -> [u8; SOURCE_TREE_GENESIS_READBACK_BYTES_V1] {
        let mut reader = source_fixture::reader(self.directory.path(), JournalLimits::default());
        let packet = sign_genesis_readback_from_view(
            &mut reader,
            Some(self.floor.project()),
            challenge,
            Some(&self.context),
            3,
            &self.key,
        )
        .unwrap();
        reader.check_named_currentness_at_uid_for_test().unwrap();
        packet
    }
}

#[test]
fn root_source_current_floor_requires_actual_anchored_rows_not_prepared_receipt() {
    let mut fixture = Fixture::prepared();
    let challenge = fixture.challenge([11; 16]);
    let packet = fixture.packet(challenge);
    let prepared =
        verify_source_tree_genesis_readback_v1(&packet, &fixture.pin, challenge).unwrap();
    assert_eq!(prepared.receipt(), Some(fixture.floor.receipt()));
    assert!(require_anchored_observation(&prepared, &fixture.floor).is_err());
    assert!(fixture.journal.compact().is_err());

    fixture.anchor();
    let challenge = fixture.challenge([33; 16]);
    let packet = fixture.packet(challenge);
    let anchored =
        verify_source_tree_genesis_readback_v1(&packet, &fixture.pin, challenge).unwrap();
    assert!(require_anchored_observation(&anchored, &fixture.floor).is_ok());
}

#[test]
fn root_source_current_floor_rejoins_semantic_ack_after_compaction_and_cold_reopen() {
    let mut fixture = Fixture::prepared();
    fixture.anchor();
    let before = fixture.journal.snapshot_sequence();
    fixture.journal.compact().unwrap();
    let Fixture {
        directory,
        journal,
        floor,
        context,
        key,
        pin,
    } = fixture;
    drop(journal);
    let journal = source_fixture::open(directory.path(), JournalLimits::default());
    let fixture = Fixture {
        directory,
        journal,
        floor,
        context,
        key,
        pin,
    };
    let challenge = fixture.challenge([34; 16]);
    let packet = fixture.packet(challenge);
    let anchored =
        verify_source_tree_genesis_readback_v1(&packet, &fixture.pin, challenge).unwrap();

    assert!(require_anchored_observation(&anchored, &fixture.floor).is_ok());
    assert_eq!(anchored.ack_floor_digest(), Some(fixture.floor.digest()));
    assert_eq!(fixture.floor.semantic_revision(), 1);
    assert!(fixture.floor.predecessor().is_none());
    // Frame sequence remains diagnostic: semantic matching never orders by it.
    assert_ne!(fixture.journal.snapshot_sequence(), before);
}

#[test]
fn root_source_current_floor_rejects_changed_floor_even_with_exact_signed_receipt() {
    let mut fixture = Fixture::prepared();
    fixture.anchor();
    let challenge = fixture.challenge([35; 16]);
    let packet = fixture.packet(challenge);
    let anchored =
        verify_source_tree_genesis_readback_v1(&packet, &fixture.pin, challenge).unwrap();
    let foreign = SourceHierarchyFloorRecordV1::new(
        fixture.floor.receipt().clone(),
        ObjectDigest::from_bytes([36; 32]),
    )
    .unwrap();

    assert_eq!(anchored.receipt(), Some(foreign.receipt()));
    assert_ne!(foreign.digest(), fixture.floor.digest());
    assert!(require_anchored_observation(&anchored, &foreign).is_err());
}

#[test]
fn root_source_current_floor_observation_rejects_old_nonce_rotated_pin_and_packet_substitution() {
    let mut fixture = Fixture::prepared();
    fixture.anchor();
    let challenge = fixture.challenge([37; 16]);
    let mut packet = fixture.packet(challenge);
    assert!(
        verify_source_tree_genesis_readback_v1(&packet, &fixture.pin, fixture.challenge([38; 16]))
            .is_err()
    );
    let other = SigningKey::from_bytes(&[39; 32]);
    let rotated = PinnedSourceHoldReadbackSignerV1::decode(
        &encode_source_hold_readback_signer_credential_v1(3, &other.verifying_key()).unwrap(),
    )
    .unwrap();
    assert!(verify_source_tree_genesis_readback_v1(&packet, &rotated, challenge).is_err());
    let last = packet.len() - 1;
    packet[last] ^= 1;
    assert!(verify_source_tree_genesis_readback_v1(&packet, &fixture.pin, challenge).is_err());
}
