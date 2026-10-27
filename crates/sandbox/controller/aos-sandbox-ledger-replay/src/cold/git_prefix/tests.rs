//! Observes real canonical file COMMITs; catalog fixtures remain passive DATA.

use std::collections::BTreeMap;
use std::io::Write as _;

use aos_sandbox_broker::canonical_journal::{
    CanonicalReplayOriginalV1,
    coordinator::indexed_replay::{CanonicalIndexedReplayV1, CanonicalReplayIndexOriginalsV1},
};
use aos_sandbox_journal::protected_storage::FileIdentity;
use aos_sandbox_protocol::domain_ledger::transaction::{
    JournalLimits, JournalRecord, JournalTransaction, encode_transaction,
};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::cold::ColdReplayOriginalV1;

fn catalog_for(transaction: &JournalTransaction, encoded: &[u8]) -> Vec<u8> {
    let [record] = transaction.records() else { panic!("one catalogued fixture row"); };
    let mut member = [0_u8; 140];
    member[0] = 7; // The existing Mount owner kind, unit and journal profile.
    member[1] = 2;
    member[4..6].copy_from_slice(&5_u16.to_be_bytes());
    member[6..8].copy_from_slice(&7_u16.to_be_bytes());
    member[8..24].fill(1);
    member[24..40].fill(2);
    member[72..104].fill(6);
    let prefix = Sha256::new()
        .chain_update(b"aos.sandbox.git-upload.native-prefix.v1\0")
        .chain_update(encoded)
        .finalize();
    member[104..136].copy_from_slice(&prefix);
    member[136..140].copy_from_slice(&1_u32.to_be_bytes());

    let mut row = [0_u8; 300];
    row[0] = 7;
    row[1] = 1;
    row[4..6].copy_from_slice(&(record.key().len() as u16).to_be_bytes());
    row[8..8 + record.key().len()].copy_from_slice(record.key());
    row[168..184].copy_from_slice(transaction.id());
    row[184..192].copy_from_slice(&2_u64.to_be_bytes());
    row[192..224].copy_from_slice(&Sha256::digest(record.value().unwrap()));
    row[224..256].fill(6);
    row[256..288].copy_from_slice(&Sha256::new()
        .chain_update(b"aos.sandbox.git-upload.catalog-member.v1\0")
        .chain_update(member)
        .finalize());

    let mut bytes = vec![0_u8; 148];
    bytes[..8].copy_from_slice(b"AOSGUOC1");
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[12..28].fill(1);
    bytes[28..44].fill(2);
    bytes[44..76].fill(3);
    bytes[76..108].fill(4);
    bytes[108..110].copy_from_slice(&1_u16.to_be_bytes());
    bytes[110..112].copy_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&member);
    bytes.extend_from_slice(&row);
    let checksum = Sha256::new()
        .chain_update(b"aos.sandbox.git-upload.owner-catalog.v1\0")
        .chain_update(&bytes[..116])
        .chain_update(&bytes[148..])
        .finalize();
    bytes[116..148].copy_from_slice(&checksum);
    bytes
}

fn transaction(namespace: RecordNamespace, value: Vec<u8>) -> JournalTransaction {
    JournalTransaction::new([5; 16], vec![
        JournalRecord::put(namespace, b"provisioned".to_vec(), value),
    ]).unwrap()
}

fn observe(transaction: JournalTransaction, omit_commit: bool) -> bool {
    let frames = encode_transaction(&transaction, 1).unwrap();
    let catalog_bytes = catalog_for(&transaction, &frames.concat());
    let catalog = GitCoverageCatalogV1::decode(&catalog_bytes).unwrap();
    let mut comparison = MountGitPrefixReplayDataV1::new(&catalog).unwrap();
    let mut file = tempfile::tempfile().unwrap();
    let count = frames.len() - usize::from(omit_commit);
    for frame in &frames[..count] {
        file.write_all(frame).unwrap();
    }
    let identity = FileIdentity::of::<CanonicalJournalMechanicalErrorV1>(&file).unwrap();
    let limits = JournalLimits::default();
    let mut native = CanonicalReplayOriginalV1::new();
    let mut index = BTreeMap::new();
    let mut indexed_original = CanonicalReplayIndexOriginalsV1::new();
    let cursor = native.begin_ordinary_semantic_cursor_once(
        &file, limits, identity.byte_len(),
    ).unwrap();
    let mut indexed = CanonicalIndexedReplayV1::from_supplied_data_v1(
        cursor, &mut index, &mut indexed_original,
    );
    let mut semantic = ColdReplayOriginalV1::new();

    let observed = semantic.observe_indexed_with_mount_git_prefix_once_v1(
        &mut indexed, identity, limits, &mut comparison,
    );
    let complete = observed.is_ok() && comparison.require_origin_v1([6; 32]).is_ok();
    if complete {
        assert_eq!(comparison.prefix_data_v1().counts_v1(), (1, 1));
        assert_eq!(comparison.prefix_data_v1().last_commit_v1(), Some(([5; 16], 3)));
        assert!(indexed.completed_prefix().is_some());
        assert!(semantic.take_remainder_once().is_some());
    } else {
        assert!(semantic.take_remainder_once().is_none());
    }
    complete
}

#[test]
fn catalog_binds_actual_commit_coordinates_and_requires_complete_native_eof() {
    assert!(observe(transaction(RecordNamespace::DesiredState, b"value".to_vec()), false));
    assert!(!observe(transaction(RecordNamespace::DesiredState, b"value".to_vec()), true));
}

#[test]
fn a_catalog_cannot_relabel_another_owners_canonical_row_as_mount_infrastructure() {
    // This is a complete, canonical idempotency value, not malformed DATA.
    // The ordinary all-family replay admits its schema, while Mount's existing
    // fixed Git catalog comparison still refuses the foreign infrastructure.
    let mut decision = vec![8; 32];
    decision.extend_from_slice(&[9; 16]);

    assert!(!observe(transaction(RecordNamespace::Idempotency, decision), false));
}
