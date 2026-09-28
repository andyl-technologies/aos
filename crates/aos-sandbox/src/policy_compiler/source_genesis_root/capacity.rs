//! Closed Root-only capacity binding for the initial semantic floor cut.
//!
//! The reservation and immutable intent enter together. Settlement must write
//! exactly their joined initial floor and delete that intent and capacity row;
//! an arbitrary DesiredState transaction is never a genesis settlement.

use std::path::Path;

use aos_sandbox_core::ObjectDigest;

use crate::hierarchy::genesis_profile::hash;
use crate::journal::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1, Journal, JournalError,
    JournalRecord, JournalTransaction, RecordNamespace, RootSourceGenesisTransitionV1,
    capacity_reservation_identity_is_exact_v1,
};

use super::super::protected_owner::{
    POLICY_AUTHORITY_JOURNAL, PROTECTED_POLICY_ROOT, policy_authority_journal_limits,
};
use super::records::{
    FLOOR_PREFIX, INSTANCE_KEY, INTENT_PREFIX, PINS_KEY, RootSourceGenesisIntentRecordV1,
    SourceHierarchyFloorRecordV1, decode_instance,
};

const OWNER_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.capacity-owner.v1\0";
const ADMISSION_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.capacity-admission.v1\0";
const FLOOR_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.floor-transaction.v1\0";
const TERMINAL_RECORDS: u32 = 3;
const TERMINAL_BYTES: u64 = 4096;

pub(crate) fn require_owner(journal: &Journal) -> Result<(), JournalError> {
    journal.require_protected_named_location(
        Path::new(PROTECTED_POLICY_ROOT),
        POLICY_AUTHORITY_JOURNAL,
        0,
        policy_authority_journal_limits(),
    )
}

pub(crate) fn require_mutation(
    journal: &Journal,
    transaction: &JournalTransaction,
    transition: RootSourceGenesisTransitionV1,
    allow_capacity_records: bool,
    settling: Option<[u8; 32]>,
) -> Result<(), JournalError> {
    let owns_records = transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::DesiredState
            && (record.key() == INSTANCE_KEY
                || record.key() == PINS_KEY
                || record.key().starts_with(INTENT_PREFIX)
                || record.key().starts_with(FLOOR_PREFIX))
    });
    if transition == RootSourceGenesisTransitionV1::Initialize {
        return validate_initialization(journal, transaction);
    }
    if !owns_records {
        return Ok(());
    }
    if !allow_capacity_records {
        return Err(JournalError::ProtectedBoundary);
    }
    if let Some(identity) = settling {
        let reservation = journal.recover_global_capacity_reservation_v1(identity)?;
        return validate_settlement(journal, transaction, &reservation.request(), identity);
    }
    let mut capacities = transaction
        .records()
        .iter()
        .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation);
    let record = capacities.next().ok_or(JournalError::ProtectedBoundary)?;
    if capacities.next().is_some() {
        return Err(JournalError::ProtectedBoundary);
    }
    let (request, _, _) = crate::journal::decode_capacity_reservation_request_v1(record)?;
    validate_admission(journal, transaction, &request)
}

fn validate_initialization(
    journal: &Journal,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    require_owner(journal)?;
    if journal
        .records(RecordNamespace::DesiredState)
        .any(|(key, _)| {
            key == INSTANCE_KEY
                || key == PINS_KEY
                || key.starts_with(INTENT_PREFIX)
                || key.starts_with(FLOOR_PREFIX)
        })
        || !journal.root_source_genesis_capacity_ids_v1()?.is_empty()
        || transaction.records().len() != 2
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let records = transaction.records();
    if records[0].namespace() != RecordNamespace::DesiredState
        || records[0].key() != INSTANCE_KEY
        || records[1].namespace() != RecordNamespace::DesiredState
        || records[1].key() != PINS_KEY
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let instance = records[0].value().ok_or(JournalError::ProtectedBoundary)?;
    decode_instance(instance).map_err(|_| JournalError::ProtectedBoundary)?;
    let pins = super::pins::RootGenesisRolePinsV1::load(journal)
        .map_err(|_| JournalError::ProtectedBoundary)?;
    if records[1].value() != Some(pins.record_bytes().as_slice()) {
        return Err(JournalError::ProtectedBoundary);
    }
    let digest = hash(super::store::INSTANCE_TRANSACTION_DOMAIN, instance);
    if transaction.id().as_slice() != &digest.as_bytes()[..16] {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub(super) fn intent_key(intent: &RootSourceGenesisIntentRecordV1) -> Vec<u8> {
    [INTENT_PREFIX, intent.project().as_bytes()].concat()
}

pub(super) fn floor_key(floor: &SourceHierarchyFloorRecordV1) -> Vec<u8> {
    [FLOOR_PREFIX, floor.project().as_bytes()].concat()
}

pub(super) fn admission_id(intent: &RootSourceGenesisIntentRecordV1) -> [u8; 16] {
    transaction_id(ADMISSION_DOMAIN, intent.digest())
}

pub(super) fn floor_transaction_id(floor: &SourceHierarchyFloorRecordV1) -> [u8; 16] {
    transaction_id(FLOOR_TRANSACTION_DOMAIN, floor.digest())
}

pub(super) fn request(
    intent: &RootSourceGenesisIntentRecordV1,
) -> GlobalCapacityReservationRequestV1 {
    let owner = hash(
        OWNER_DOMAIN,
        &[intent.instance().as_slice(), intent.project().as_bytes()].concat(),
    );
    GlobalCapacityReservationRequestV1 {
        purpose: GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor,
        owner_namespace: RecordNamespace::DesiredState,
        owner_id: *owner.as_bytes(),
        owner_digest: *intent.digest().as_bytes(),
        operation_id: intent.nonce(),
        artifact_digest: *intent.acceptance().as_bytes(),
        checkpoint_digest: intent.instance(),
        chain_head_digest: *intent.roles().as_bytes(),
        future_transactions: 1,
        terminal_records: TERMINAL_RECORDS,
        terminal_bytes: TERMINAL_BYTES,
        poison_records: TERMINAL_RECORDS,
        poison_bytes: TERMINAL_BYTES,
    }
}

pub(crate) fn validate_admission(
    journal: &Journal,
    transaction: &JournalTransaction,
    reservation: &GlobalCapacityReservationRequestV1,
) -> Result<(), JournalError> {
    require_owner(journal)?;
    if reservation.purpose != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor
        || transaction.records().len() != 2
    {
        return Err(JournalError::InvalidTransaction);
    }
    let intent_record = transaction
        .records()
        .iter()
        .find(|record| {
            record.namespace() == RecordNamespace::DesiredState
                && record.key().starts_with(INTENT_PREFIX)
        })
        .ok_or(JournalError::InvalidTransaction)?;
    let intent = RootSourceGenesisIntentRecordV1::from_record_bytes(
        intent_record
            .value()
            .ok_or(JournalError::InvalidTransaction)?,
    )
    .map_err(|_| JournalError::InvalidTransaction)?;
    require_instance_and_roles(journal, &intent)?;
    if intent_record.key() != intent_key(&intent)
        || journal
            .get(RecordNamespace::DesiredState, intent_record.key())
            .is_some()
        || journal
            .get(
                RecordNamespace::DesiredState,
                &[FLOOR_PREFIX, intent.project().as_bytes()].concat(),
            )
            .is_some()
        || transaction.id() != &admission_id(&intent)
        || reservation != &request(&intent)
    {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    Ok(())
}

pub(crate) fn validate_settlement(
    journal: &Journal,
    transaction: &JournalTransaction,
    reservation: &GlobalCapacityReservationRequestV1,
    capacity_id: [u8; 32],
) -> Result<(), JournalError> {
    require_owner(journal)?;
    let key = [INTENT_PREFIX, reservation_project(journal, reservation)?].concat();
    let intent = RootSourceGenesisIntentRecordV1::from_record_bytes(
        journal
            .get(RecordNamespace::DesiredState, &key)
            .ok_or(JournalError::AuthorityPreflightMismatch)?,
    )
    .map_err(|_| JournalError::AuthorityPreflightMismatch)?;
    require_instance_and_roles(journal, &intent)?;
    if reservation != &request(&intent)
        || !capacity_reservation_identity_is_exact_v1(
            reservation,
            admission_id(&intent),
            capacity_id,
        )
    {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    let floor_record = transaction
        .records()
        .iter()
        .find(|record| {
            record.namespace() == RecordNamespace::DesiredState
                && record.key().starts_with(FLOOR_PREFIX)
        })
        .ok_or(JournalError::InvalidTransaction)?;
    let floor = SourceHierarchyFloorRecordV1::from_record_bytes(
        floor_record
            .value()
            .ok_or(JournalError::InvalidTransaction)?,
    )
    .map_err(|_| JournalError::InvalidTransaction)?;
    if floor.instance() != intent.instance()
        || floor.project() != intent.project()
        || floor.roles() != intent.roles()
        || floor.receipt().intent_digest() != intent.digest()
        || floor.receipt().acceptance_digest() != intent.acceptance()
        || &floor.receipt().seed_packet() != intent.accepted_input().seed_packet()
        || &floor.receipt().auth_packet() != intent.accepted_input().auth_packet()
        || journal
            .get(RecordNamespace::DesiredState, &floor_key(&floor))
            .is_some()
        || transaction.id() != &floor_transaction_id(&floor)
        || transaction.records().len() != 3
    {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    let expected_floor = JournalRecord::put(
        RecordNamespace::DesiredState,
        floor_key(&floor),
        floor.record_bytes().to_vec(),
    );
    let expected_delete = JournalRecord::delete(RecordNamespace::DesiredState, key);
    if transaction
        .records()
        .iter()
        .filter(|record| record.namespace() == RecordNamespace::DesiredState)
        .ne([&expected_floor, &expected_delete])
    {
        return Err(JournalError::InvalidTransaction);
    }
    Ok(())
}

fn require_instance_and_roles(
    journal: &Journal,
    intent: &RootSourceGenesisIntentRecordV1,
) -> Result<(), JournalError> {
    let instance = decode_instance(
        journal
            .get(RecordNamespace::DesiredState, INSTANCE_KEY)
            .ok_or(JournalError::AuthorityPreflightMismatch)?,
    )
    .map_err(|_| JournalError::AuthorityPreflightMismatch)?;
    let pins = journal
        .get(RecordNamespace::DesiredState, PINS_KEY)
        .ok_or(JournalError::AuthorityPreflightMismatch)?;
    if instance != intent.instance()
        || super::pins::role_tuple_digest(pins)
            .map_err(|_| JournalError::AuthorityPreflightMismatch)?
            != intent.roles()
    {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    Ok(())
}

fn reservation_project<'journal>(
    journal: &'journal Journal,
    reservation: &GlobalCapacityReservationRequestV1,
) -> Result<&'journal [u8], JournalError> {
    let mut matching = journal
        .records(RecordNamespace::DesiredState)
        .filter(|(key, value)| {
            key.starts_with(INTENT_PREFIX)
                && RootSourceGenesisIntentRecordV1::from_record_bytes(value)
                    .is_ok_and(|intent| request(&intent) == *reservation)
        });
    let (key, _) = matching
        .next()
        .ok_or(JournalError::AuthorityPreflightMismatch)?;
    if matching.next().is_some() {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    key.get(INTENT_PREFIX.len()..)
        .ok_or(JournalError::AuthorityPreflightMismatch)
}

fn transaction_id(domain: &[u8], commitment: ObjectDigest) -> [u8; 16] {
    let digest = hash(domain, commitment.as_bytes());
    let mut id = [0; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::JournalLimits;

    #[test]
    fn generic_genesis_key_writes_are_refused_before_append_and_after_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.journal");
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let before = journal.snapshot_sequence();
        let length = std::fs::metadata(&path).unwrap().len();
        let keys = [
            INSTANCE_KEY.to_vec(),
            PINS_KEY.to_vec(),
            [INTENT_PREFIX, &[1; 16]].concat(),
            [FLOOR_PREFIX, &[1; 16]].concat(),
        ];

        for (index, key) in keys.iter().enumerate() {
            for record in [
                JournalRecord::put(RecordNamespace::DesiredState, key.clone(), vec![1]),
                JournalRecord::delete(RecordNamespace::DesiredState, key.clone()),
            ] {
                let transaction =
                    JournalTransaction::new([index as u8 + 1; 16], vec![record]).unwrap();
                assert!(matches!(
                    journal.commit(&transaction),
                    Err(JournalError::ProtectedBoundary)
                ));
                assert_eq!(journal.snapshot_sequence(), before);
                assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
            }
        }
        drop(journal);

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert_eq!(journal.snapshot_sequence(), before);
        assert!(
            keys.iter()
                .all(|key| journal.get(RecordNamespace::DesiredState, key).is_none())
        );
    }

    #[test]
    fn foreign_capacity_cannot_carry_a_genesis_intent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.journal");
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let request = GlobalCapacityReservationRequestV1 {
            purpose: GlobalCapacityReservationPurposeV1::RuntimeExecution,
            owner_namespace: RecordNamespace::Effect,
            owner_id: [1; 32],
            owner_digest: [2; 32],
            operation_id: [3; 16],
            artifact_digest: [4; 32],
            checkpoint_digest: [5; 32],
            chain_head_digest: [6; 32],
            future_transactions: 1,
            terminal_records: 3,
            terminal_bytes: 4096,
            poison_records: 3,
            poison_bytes: 4096,
        };
        let prepared = journal
            .prepare_global_capacity_reservation_v1(request, [7; 16])
            .unwrap();
        let transaction = JournalTransaction::new(
            [7; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    [INTENT_PREFIX, &[1; 16]].concat(),
                    vec![1],
                ),
                prepared.record().clone(),
            ],
        )
        .unwrap();
        let before = journal.snapshot_sequence();
        let length = std::fs::metadata(&path).unwrap().len();

        assert!(
            journal
                .commit_global_capacity_reservation_v1(prepared, &transaction)
                .is_err()
        );
        assert_eq!(journal.snapshot_sequence(), before);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        assert_eq!(
            journal
                .records(RecordNamespace::GlobalCapacityReservation)
                .count(),
            0
        );
    }
}
