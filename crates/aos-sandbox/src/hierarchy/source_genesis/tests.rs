//! Real protected-journal atomicity fixtures, not live Root/Controller authority.
//!
//! These tests deliberately call the internal structural append/anchor leaf.
//! They cannot construct either production opaque owner proof or certify the
//! installed same-flight sender, administrative admission or public readiness.

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};

use super::*;
use crate::JournalLimits;
use crate::hierarchy::genesis_profile::ControllerSourceGenesisAcceptanceRecordV1;
use crate::hierarchy::model::TreeLimitsV1;
use crate::hierarchy::protected_journal::recover_hierarchy_replay_validator_v1;
use crate::hierarchy::source_seed::{
    ControllerSourceTreeSeedV1, sign_controller_source_tree_seed_v1,
};
use crate::journal::{JournalError, ReadOnlyProtectedJournal, encoded_transaction_append_bytes};

pub(crate) fn directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

pub(crate) fn open(directory: &Path, limits: JournalLimits) -> Journal {
    let uid = fs::metadata(directory).unwrap().uid();
    Journal::open_protected_at_uid(directory, PROTECTED_SOURCE_DOMAIN_JOURNAL, limits, uid)
        .unwrap()
        .0
}

pub(crate) fn reader(directory: &Path, limits: JournalLimits) -> ReadOnlyProtectedJournal {
    let uid = fs::metadata(directory).unwrap().uid();
    Journal::open_read_only_protected_at_uid_for_test(
        directory,
        PROTECTED_SOURCE_DOMAIN_JOURNAL,
        limits,
        uid,
    )
    .unwrap()
    .0
}

pub(crate) fn acceptance(project: ProjectId) -> ControllerSourceGenesisAcceptanceRecordV1 {
    let limits = TreeLimitsV1::new(1, 8, 7, 6, 5, 4, 3).unwrap();
    let publisher_pointer = ObjectDigest::from_bytes([2; 32]);
    let authorization_head = ObjectDigest::from_bytes([3; 32]);
    let request = [4; 16];
    let publisher_generation = 5;
    let epoch = 9;
    let seed = sign_controller_source_tree_seed_v1(
        ControllerSourceTreeSeedV1::new(
            project,
            limits,
            publisher_generation,
            publisher_pointer,
            authorization_head,
            request,
            epoch,
        )
        .unwrap(),
        7,
        &SigningKey::from_bytes(&[41; 32]),
    )
    .unwrap();

    let publisher_revision = ObjectDigest::from_bytes([6; 32]);
    let mut authorization = [0; 224];
    authorization[..8].copy_from_slice(b"AOSPSC02");
    authorization[8..10].copy_from_slice(&2_u16.to_be_bytes());
    authorization[12..20].copy_from_slice(&8_u64.to_be_bytes());
    authorization[20..36].copy_from_slice(project.as_bytes());
    authorization[36..44].copy_from_slice(&publisher_generation.to_be_bytes());
    authorization[44..76].copy_from_slice(publisher_pointer.as_bytes());
    authorization[76..108].copy_from_slice(publisher_revision.as_bytes());
    authorization[108..124].copy_from_slice(&request);
    authorization[124..132].copy_from_slice(&epoch.to_be_bytes());
    for (index, limit) in [1_u32, 8, 7, 6, 5, 4, 3].into_iter().enumerate() {
        authorization[132 + index * 4..136 + index * 4].copy_from_slice(&limit.to_be_bytes());
    }
    let mut preimage = b"aos.sandbox.publisher-project-authorization-source.v2\0/var/lib/aos/sandboxd/controller.journal\0".to_vec();
    preimage.extend_from_slice(&authorization[..160]);
    authorization[160..]
        .copy_from_slice(&SigningKey::from_bytes(&[42; 32]).sign(&preimage).to_bytes());
    ControllerSourceGenesisAcceptanceRecordV1::new(
        seed,
        authorization,
        publisher_pointer,
        publisher_revision,
        authorization_head,
        ObjectDigest::from_bytes([7; 32]),
    )
    .unwrap()
}

/// Builds actual canonical members through the same typed planner as production.
pub(crate) fn prepared(
    journal: &mut Journal,
) -> (
    JournalTransaction,
    SourceTreeGenesisReceiptV1,
    SourceGenesisPendingV1,
) {
    prepared_project(journal, ProjectId::from_bytes([1; 16]), [9; 32])
}

fn prepared_project(
    journal: &mut Journal,
    project: ProjectId,
    instance: [u8; 32],
) -> (
    JournalTransaction,
    SourceTreeGenesisReceiptV1,
    SourceGenesisPendingV1,
) {
    let acceptance = acceptance(project);
    #[cfg(target_os = "linux")]
    let intent = crate::policy_compiler::RootSourceGenesisIntentRecordV1::new(
        instance,
        journal.protected_owner_uid().unwrap(),
        [11; 16],
        acceptance.clone(),
        ObjectDigest::from_bytes([15; 32]),
    )
    .unwrap()
    .digest();
    #[cfg(not(target_os = "linux"))]
    let intent = ObjectDigest::from_bytes(
        Sha256::new()
            .chain_update(b"source-genesis-test-intent\0")
            .chain_update(project.as_bytes())
            .finalize()
            .into(),
    );
    let transaction_id = transaction_id(b"append", intent);
    let pair =
        prepare_source_tree_genesis_pair_v1(journal, *acceptance.seed_packet(), transaction_id)
            .unwrap();
    let receipt = SourceTreeGenesisReceiptV1::from_owner_fields(
        instance,
        intent,
        &acceptance,
        pair.tree_head,
        pair.lineage_head,
        pair.records[0].value().unwrap(),
        pair.records[1].value().unwrap(),
    )
    .unwrap();
    let pending = SourceGenesisPendingV1 {
        instance: receipt.instance(),
        project: receipt.project(),
        intent: receipt.intent_digest(),
        receipt: receipt.digest(),
        nonce: [11; 16],
        names: journal.protected_writer_physical_names_v1().unwrap(),
    };
    let mut records = pair.records;
    records.push(JournalRecord::put(
        RecordNamespace::DesiredState,
        receipt_key(receipt.project()),
        receipt.encode().to_vec(),
    ));
    records.push(JournalRecord::put(
        RecordNamespace::DesiredState,
        PENDING_KEY.to_vec(),
        pending.encode().to_vec(),
    ));
    (
        JournalTransaction::new(transaction_id, records).unwrap(),
        receipt,
        pending,
    )
}

/// Supplies comparison data for canonical fixture intents, never a live owner.
#[cfg(target_os = "linux")]
pub(crate) fn intent_context(
    journal: &Journal,
    project: ProjectId,
) -> crate::policy_compiler::SourceTreeGenesisIntentContextV1 {
    crate::policy_compiler::SourceTreeGenesisIntentContextV1::new(
        journal.protected_owner_uid().unwrap(),
        ObjectDigest::from_bytes([15; 32]),
        acceptance(project),
    )
    .unwrap()
}

pub(crate) fn ack(receipt: &SourceTreeGenesisReceiptV1) -> SourceGenesisAckV1 {
    SourceGenesisAckV1 {
        instance: receipt.instance(),
        project: receipt.project(),
        receipt: receipt.digest(),
        root_floor: ObjectDigest::from_bytes([12; 32]),
        controller_floor: ObjectDigest::from_bytes([13; 32]),
    }
}

pub(crate) fn append(journal: &mut Journal) -> SourceTreeGenesisReceiptV1 {
    let (transaction, receipt, _) = prepared(journal);
    journal
        .preflight_source_tree_genesis_v1(
            &[
                transaction.clone(),
                ack_transaction(&ack(&receipt)).unwrap(),
            ],
            &[
                SourceGenesisTransitionV1::Append,
                SourceGenesisTransitionV1::Anchor,
            ],
        )
        .unwrap();
    journal
        .commit_source_tree_genesis_v1(&transaction, SourceGenesisTransitionV1::Append)
        .unwrap();
    receipt
}

pub(crate) fn anchor(journal: &mut Journal, receipt: &SourceTreeGenesisReceiptV1) {
    anchor_with_controller_floor(journal, receipt, ack(receipt).controller_floor);
}

pub(crate) fn anchor_with_controller_floor(
    journal: &mut Journal,
    receipt: &SourceTreeGenesisReceiptV1,
    controller_floor: ObjectDigest,
) {
    anchor_with_floors(journal, receipt, ack(receipt).root_floor, controller_floor);
}

pub(crate) fn anchor_with_floors(
    journal: &mut Journal,
    receipt: &SourceTreeGenesisReceiptV1,
    root_floor: ObjectDigest,
    controller_floor: ObjectDigest,
) {
    let mut actual_ack = ack(receipt);
    actual_ack.root_floor = root_floor;
    actual_ack.controller_floor = controller_floor;
    journal
        .commit_source_tree_genesis_v1(
            &ack_transaction(&actual_ack).unwrap(),
            SourceGenesisTransitionV1::Anchor,
        )
        .unwrap();
}

fn unrelated() -> JournalTransaction {
    JournalTransaction::new(
        [14; 16],
        vec![JournalRecord::put(
            RecordNamespace::DesiredState,
            b"unrelated".to_vec(),
            vec![1],
        )],
    )
    .unwrap()
}

#[test]
fn source_genesis_atomic_append_cold_pending_blocks_mutation_and_compaction() {
    let directory = directory();
    let mut journal = open(directory.path(), JournalLimits::default());
    let receipt = append(&mut journal);
    assert_eq!(journal.snapshot_sequence(), 7); // Begin + four members + Commit.
    let rows = validate_actual_rows(&mut journal).unwrap();
    assert_eq!(rows.receipts.get(&receipt.project()), Some(&receipt));
    assert!(rows.pending.is_some());
    assert!(rows.acks.is_empty());
    assert!(recover_hierarchy_replay_validator_v1(&journal).is_err());
    assert!(journal.commit(&unrelated()).is_err());
    assert!(journal.compact().is_err());
    drop(journal);

    let mut reopened = open(directory.path(), JournalLimits::default());
    assert_eq!(validate_actual_rows(&mut reopened).unwrap(), rows);
    assert_eq!(reopened.snapshot_sequence(), 7);
    assert!(reopened.commit(&unrelated()).is_err());
    assert!(reopened.compact().is_err());
    anchor(&mut reopened, &receipt);
    assert_eq!(reopened.snapshot_sequence(), 11); // Exact delete + ACK transaction.
    assert!(
        validate_actual_rows(&mut reopened)
            .unwrap()
            .pending
            .is_none()
    );
    assert_eq!(
        reopened
            .source_tree_genesis_rows_v1()
            .unwrap()
            .acks
            .get(&receipt.project()),
        Some(&ack(&receipt))
    );
    assert!(recover_hierarchy_replay_validator_v1(&reopened).is_err());
}

#[test]
fn source_genesis_ack_suffix_capacity_is_reserved_before_any_append() {
    let directory = directory();
    let mut journal = open(directory.path(), JournalLimits::default());
    let (transaction, receipt, _) = prepared(&mut journal);
    let anchor = ack_transaction(&ack(&receipt)).unwrap();
    let bound = encoded_transaction_append_bytes(&transaction).unwrap()
        + encoded_transaction_append_bytes(&anchor).unwrap();
    drop(journal);

    let limits = JournalLimits {
        maximum_journal_bytes: bound - 1,
        ..JournalLimits::default()
    };
    let mut journal = open(directory.path(), limits);
    assert!(matches!(
        journal.preflight_source_tree_genesis_v1(
            &[transaction.clone(), anchor.clone()],
            &[
                SourceGenesisTransitionV1::Append,
                SourceGenesisTransitionV1::Anchor
            ],
        ),
        Err(JournalError::JournalTooLarge)
    ));
    assert_eq!(journal.snapshot_sequence(), 1);
    assert!(
        journal
            .source_tree_genesis_rows_v1()
            .unwrap()
            .receipts
            .is_empty()
    );
    assert_eq!(
        fs::metadata(directory.path().join(PROTECTED_SOURCE_DOMAIN_JOURNAL))
            .unwrap()
            .len(),
        0
    );
    drop(journal);

    let limits = JournalLimits {
        maximum_journal_bytes: bound,
        ..JournalLimits::default()
    };
    let mut journal = open(directory.path(), limits);
    journal
        .preflight_source_tree_genesis_v1(
            &[transaction.clone(), anchor.clone()],
            &[
                SourceGenesisTransitionV1::Append,
                SourceGenesisTransitionV1::Anchor,
            ],
        )
        .unwrap();
    journal
        .commit_source_tree_genesis_v1(&transaction, SourceGenesisTransitionV1::Append)
        .unwrap();
    journal
        .commit_source_tree_genesis_v1(&anchor, SourceGenesisTransitionV1::Anchor)
        .unwrap();
    assert_eq!(
        fs::metadata(directory.path().join(PROTECTED_SOURCE_DOMAIN_JOURNAL))
            .unwrap()
            .len(),
        bound
    );
}

#[test]
fn source_genesis_partial_append_and_ack_tails_recover_only_committed_materialization() {
    let directory = directory();
    let mut journal = open(directory.path(), JournalLimits::default());
    let receipt = append(&mut journal);
    drop(journal);
    let path = directory.path().join(PROTECTED_SOURCE_DOMAIN_JOURNAL);
    let append_boundary = fs::metadata(&path).unwrap().len();
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b"partial-ACK-tail").unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(
        Journal::open_read_only_protected_at_uid_for_test(
            directory.path(),
            PROTECTED_SOURCE_DOMAIN_JOURNAL,
            JournalLimits::default(),
            fs::metadata(directory.path()).unwrap().uid(),
        )
        .is_err()
    );

    let mut journal = open(directory.path(), JournalLimits::default());
    assert_eq!(fs::metadata(&path).unwrap().len(), append_boundary);
    assert!(
        journal
            .source_tree_genesis_rows_v1()
            .unwrap()
            .pending
            .is_some()
    );
    assert!(journal.commit(&unrelated()).is_err());
    anchor(&mut journal, &receipt);
    let complete = fs::read(&path).unwrap();
    drop(journal);

    // Cutting one byte before either Commit excludes that whole transaction.
    for cut in [append_boundary - 1, complete.len() as u64 - 1] {
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(0).unwrap();
        drop(file);
        fs::write(&path, &complete[..cut as usize]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut recovered = open(directory.path(), JournalLimits::default());
        let rows = validate_actual_rows(&mut recovered).unwrap();
        if cut < append_boundary {
            assert!(rows.receipts.is_empty());
            assert!(rows.pending.is_none());
        } else {
            assert_eq!(rows.receipts.get(&receipt.project()), Some(&receipt));
            assert!(rows.pending.is_some());
            assert!(rows.acks.is_empty());
            assert!(recovered.commit(&unrelated()).is_err());
        }
        drop(recovered);
    }
}

#[test]
fn source_genesis_compaction_keeps_semantic_receipt_and_original_signed_packets() {
    let directory = directory();
    let mut journal = open(directory.path(), JournalLimits::default());
    let receipt = append(&mut journal);
    anchor(&mut journal, &receipt);
    let before = validate_actual_rows(&mut journal).unwrap();
    journal.commit(&unrelated()).unwrap();
    let before_sequence = journal.snapshot_sequence();
    journal.compact().unwrap();
    assert_ne!(journal.snapshot_sequence(), before_sequence);
    assert_eq!(validate_actual_rows(&mut journal).unwrap(), before);
    drop(journal);

    let mut reopened = open(directory.path(), JournalLimits::default());
    assert_eq!(validate_actual_rows(&mut reopened).unwrap(), before);
    assert_eq!(
        before.receipts.get(&receipt.project()).unwrap().encode(),
        receipt.encode()
    );
    // Compaction never turns structural genesis into normal ancestry authority.
    assert!(recover_hierarchy_replay_validator_v1(&reopened).is_err());
}

#[test]
fn source_genesis_rejects_member_receipt_and_pending_substitution_before_write() {
    let directory = directory();
    let mut journal = open(directory.path(), JournalLimits::default());
    let (transaction, receipt, pending) = prepared(&mut journal);
    for mutation in 0..8 {
        let mut records = transaction.records().to_vec();
        if mutation >= 5 {
            let mut changed = pending.clone();
            match mutation {
                5 => changed.instance[0] ^= 1,
                6 => changed.intent = ObjectDigest::from_bytes([20; 32]),
                _ => changed.receipt = ObjectDigest::from_bytes([21; 32]),
            }
            records[3] = JournalRecord::put(
                RecordNamespace::DesiredState,
                PENDING_KEY.to_vec(),
                changed.encode().to_vec(),
            );
        } else {
            let index = if mutation < 2 { mutation } else { 2 };
            let mut value = records[index].value().unwrap().to_vec();
            let offset = if mutation < 2 {
                value.len() - 1
            } else {
                [16, 48, 640][mutation - 2]
            };
            value[offset] ^= 1;
            records[index] = JournalRecord::put(
                records[index].namespace(),
                records[index].key().to_vec(),
                value,
            );
        }
        let altered = JournalTransaction::new([15; 16], records).unwrap();
        assert!(
            journal
                .commit_source_tree_genesis_v1(&altered, SourceGenesisTransitionV1::Append)
                .is_err()
        );
        assert_eq!(journal.snapshot_sequence(), 1);
    }
    // An ordinary append cannot write protected keys, even without a pending row.
    assert!(journal.commit(&transaction).is_err());
    assert!(
        journal
            .source_tree_genesis_rows_v1()
            .unwrap()
            .receipts
            .is_empty()
    );
    assert!(receipt.materialization().as_bytes() != &[0; 32]);
    for key in [
        b"\0aos-source-tree-genesis-pending-v1\0suffix".as_slice(),
        b"\0aos-source-tree-genesis-unknown-v2\0".as_slice(),
    ] {
        let unknown = JournalTransaction::new(
            [26; 16],
            vec![JournalRecord::put(
                RecordNamespace::DesiredState,
                key.to_vec(),
                vec![1],
            )],
        )
        .unwrap();
        assert!(journal.commit(&unknown).is_err());
        assert_eq!(journal.snapshot_sequence(), 1);
    }
}

#[test]
fn source_genesis_foreign_ack_and_generic_protected_key_writes_leave_fence_intact() {
    let directory = directory();
    let mut journal = open(directory.path(), JournalLimits::default());
    let receipt = append(&mut journal);
    let before = journal.source_tree_genesis_rows_v1().unwrap();
    for mutation in 0..3 {
        let mut foreign = ack(&receipt);
        match mutation {
            0 => foreign.instance[0] ^= 1,
            1 => foreign.project = ProjectId::from_bytes([16; 16]),
            _ => foreign.receipt = ObjectDigest::from_bytes([17; 32]),
        }
        assert!(
            journal
                .commit_source_tree_genesis_v1(
                    &ack_transaction(&foreign).unwrap(),
                    SourceGenesisTransitionV1::Anchor,
                )
                .is_err()
        );
        assert_eq!(journal.source_tree_genesis_rows_v1().unwrap(), before);
    }
    assert!(
        journal
            .commit(&ack_transaction(&ack(&receipt)).unwrap())
            .is_err()
    );
    anchor(&mut journal, &receipt);
    for namespace in [RecordNamespace::DesiredState, RecordNamespace::Operation] {
        let forged = JournalTransaction::new(
            [18; 16],
            vec![JournalRecord::put(
                namespace,
                receipt_key(receipt.project()),
                receipt.encode().to_vec(),
            )],
        )
        .unwrap();
        assert!(journal.commit(&forged).is_err());
    }
    assert!(journal.compact().is_ok());
}

#[test]
fn source_genesis_borrowed_global_empty_rejects_unrelated_records() {
    for namespace in [RecordNamespace::DesiredState, RecordNamespace::Effect] {
        let directory = directory();
        let mut journal = open(directory.path(), JournalLimits::default());
        let uid = journal.protected_owner_uid().unwrap();
        journal
            .commit(
                &JournalTransaction::new(
                    [70; 16],
                    vec![JournalRecord::put(
                        namespace,
                        b"unrelated-source-row".to_vec(),
                        vec![1],
                    )],
                )
                .unwrap(),
            )
            .unwrap();

        assert!(
            observation_at(
                &mut journal,
                uid,
                None,
                SourceGenesisLocationV1::Test(directory.path().to_path_buf())
            )
            .is_err()
        );
    }
}

#[test]
fn source_genesis_borrowed_observation_checks_actual_names_and_never_confuses_absence() {
    let directory = directory();
    let mut journal = open(directory.path(), JournalLimits::default());
    let uid = fs::metadata(directory.path()).unwrap().uid();
    let observed = observation_at(
        &mut journal,
        uid,
        None,
        SourceGenesisLocationV1::Test(directory.path().to_path_buf()),
    )
    .unwrap();
    assert_eq!(observed.state(), SourceTreeGenesisStateV1::Empty);
    assert_eq!(observed.snapshot_sequence(), 1);
    assert_eq!(observed.source_uid(), uid);
    assert!(observed.receipt().is_none());
    observed.recheck().unwrap();
    drop(observed);

    let receipt = append(&mut journal);
    assert!(
        observation_at(
            &mut journal,
            uid,
            None,
            SourceGenesisLocationV1::Test(directory.path().to_path_buf()),
        )
        .is_err()
    );
    assert!(
        observation_at(
            &mut journal,
            uid,
            Some(ProjectId::from_bytes([19; 16])),
            SourceGenesisLocationV1::Test(directory.path().to_path_buf()),
        )
        .is_err()
    );
    let observed = observation_at(
        &mut journal,
        uid,
        Some(receipt.project()),
        SourceGenesisLocationV1::Test(directory.path().to_path_buf()),
    )
    .unwrap();
    assert_eq!(observed.state(), SourceTreeGenesisStateV1::Prepared);
    assert_eq!(observed.receipt(), Some(&receipt));
    assert_eq!(observed.snapshot_sequence(), 7);
    assert!(observed.ack_floor_digest().is_none());
    let path = directory.path().join(PROTECTED_SOURCE_DOMAIN_JOURNAL);
    let saved = directory.path().join("retained-original.journal");
    fs::rename(&path, &saved).unwrap();
    fs::write(&path, []).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(observed.recheck().is_err());
    drop(observed);
    fs::rename(&saved, &path).unwrap();

    anchor(&mut journal, &receipt);
    let observed = observation_at(
        &mut journal,
        uid,
        Some(receipt.project()),
        SourceGenesisLocationV1::Test(directory.path().to_path_buf()),
    )
    .unwrap();
    assert_eq!(observed.state(), SourceTreeGenesisStateV1::Anchored);
    assert_eq!(observed.ack_floor_digest(), Some(ack(&receipt).root_floor));
    assert_eq!(observed.ack_record_digest(), Some(ack(&receipt).digest()));
    let lock = directory
        .path()
        .join(format!("{PROTECTED_SOURCE_DOMAIN_JOURNAL}.lock"));
    let saved = directory.path().join("retained-original.lock");
    fs::rename(&lock, &saved).unwrap();
    fs::write(&lock, []).unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(observed.recheck().is_err());
    drop(observed);
    fs::rename(&saved, &lock).unwrap();
}

#[test]
fn source_genesis_receipt_requires_matching_actual_seven_limit_packet_claims() {
    let directory = directory();
    let mut journal = open(directory.path(), JournalLimits::default());
    let (_, receipt, _) = prepared(&mut journal);
    for offset in [20, 36, 44, 108, 124, 132, 136, 140, 144, 148, 152, 156] {
        let mut bytes = receipt.encode();
        bytes[352 + offset] ^= 1;
        // This negative is structurally signed by the fixture administrative
        // key; it still cannot substitute another seed/authorization join.
        let mut preimage = b"aos.sandbox.publisher-project-authorization-source.v2\0/var/lib/aos/sandboxd/controller.journal\0".to_vec();
        preimage.extend_from_slice(&bytes[352..512]);
        bytes[512..576]
            .copy_from_slice(&SigningKey::from_bytes(&[42; 32]).sign(&preimage).to_bytes());
        assert!(SourceTreeGenesisReceiptV1::decode(&bytes).is_err());
    }
    assert_eq!(
        SourceTreeGenesisReceiptV1::decode(&receipt.encode()).unwrap(),
        receipt
    );
}

#[test]
fn source_genesis_second_project_vacancy_is_existing_instance_data_not_global_empty() {
    let directory = directory();
    let mut journal = open(directory.path(), JournalLimits::default());
    let uid = fs::metadata(directory.path()).unwrap().uid();
    let target = ProjectId::from_bytes([22; 16]);
    let location = || SourceGenesisLocationV1::Test(directory.path().to_path_buf());
    assert!(
        capture_observation(
            &mut journal,
            uid,
            SourceGenesisSelectionV1::Vacant(target),
            location(),
        )
        .is_err()
    );

    let first = append(&mut journal);
    assert!(
        capture_observation(
            &mut journal,
            uid,
            SourceGenesisSelectionV1::Vacant(target),
            location(),
        )
        .is_err()
    );
    anchor(&mut journal, &first);
    assert!(
        capture_observation(
            &mut journal,
            uid,
            SourceGenesisSelectionV1::Vacant(first.project()),
            location(),
        )
        .is_err()
    );
    let vacant = capture_observation(
        &mut journal,
        uid,
        SourceGenesisSelectionV1::Vacant(target),
        location(),
    )
    .unwrap();
    assert_eq!(vacant.state(), SourceTreeGenesisStateV1::VacantProject);
    assert_eq!(vacant.project(), Some(target));
    assert_eq!(vacant.instance(), Some(first.instance()));
    assert!(vacant.receipt().is_none());
    assert!(vacant.ack_floor_digest().is_none());
    assert!(vacant.ack_record_digest().is_none());
    vacant.recheck().unwrap();
    drop(vacant);

    let before = journal.source_tree_genesis_rows_v1().unwrap();
    let (foreign, _, _) = prepared_project(&mut journal, target, [23; 32]);
    assert!(
        journal
            .commit_source_tree_genesis_v1(&foreign, SourceGenesisTransitionV1::Append)
            .is_err()
    );
    assert_eq!(journal.source_tree_genesis_rows_v1().unwrap(), before);
    let (second, receipt, _) = prepared_project(&mut journal, target, first.instance());
    journal
        .preflight_source_tree_genesis_v1(
            &[second.clone(), ack_transaction(&ack(&receipt)).unwrap()],
            &[
                SourceGenesisTransitionV1::Append,
                SourceGenesisTransitionV1::Anchor,
            ],
        )
        .unwrap();
    journal
        .commit_source_tree_genesis_v1(&second, SourceGenesisTransitionV1::Append)
        .unwrap();
    assert!(
        capture_observation(
            &mut journal,
            uid,
            SourceGenesisSelectionV1::Vacant(ProjectId::from_bytes([24; 16])),
            location(),
        )
        .is_err()
    );
    anchor(&mut journal, &receipt);
    assert_eq!(
        validate_actual_rows(&mut journal).unwrap().receipts.len(),
        2
    );
    drop(journal);

    let mut reopened = open(directory.path(), JournalLimits::default());
    assert_eq!(
        validate_actual_rows(&mut reopened).unwrap().receipts.len(),
        2
    );
    assert!(observation_at(&mut reopened, uid, None, location()).is_err());
    assert!(
        capture_observation(
            &mut reopened,
            uid,
            SourceGenesisSelectionV1::Vacant(target),
            location(),
        )
        .is_err()
    );
    assert!(
        capture_observation(
            &mut reopened,
            uid,
            SourceGenesisSelectionV1::Vacant(ProjectId::from_bytes([0; 16])),
            location(),
        )
        .is_err()
    );
}

#[test]
fn source_genesis_vacant_project_cut_rechecks_original_named_writer() {
    let directory = directory();
    let mut journal = open(directory.path(), JournalLimits::default());
    let uid = fs::metadata(directory.path()).unwrap().uid();
    let receipt = append(&mut journal);
    anchor(&mut journal, &receipt);
    let vacant = capture_observation(
        &mut journal,
        uid,
        SourceGenesisSelectionV1::Vacant(ProjectId::from_bytes([25; 16])),
        SourceGenesisLocationV1::Test(directory.path().to_path_buf()),
    )
    .unwrap();
    let path = directory.path().join(PROTECTED_SOURCE_DOMAIN_JOURNAL);
    let saved = directory.path().join("vacant-original.journal");
    fs::rename(&path, &saved).unwrap();
    fs::write(&path, []).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(vacant.recheck().is_err());
    drop(vacant);
    fs::rename(&saved, &path).unwrap();
}
