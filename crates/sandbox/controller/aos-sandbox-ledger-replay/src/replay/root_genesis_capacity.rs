//! Compares the complete Root-genesis capacity envelope as historical DATA.
//!
//! Actual native callers retain their own fixed writer, independent credential
//! originals, prepared/retained reservation and final crossing. These pure
//! functions neither claim a capacity purpose nor issue settlement authority.

use aos_sandbox_model::{ObjectDigest, RecordNamespace};
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};
use aos_sandbox_protocol::domain_ledger::capacity::{GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1, capacity_reservation_identity_is_exact_v1};
use crate::data::hash;
use super::root_genesis_records::{FLOOR_PREFIX, INSTANCE_KEY, INTENT_PREFIX, PINS_KEY, RootSourceGenesisIntentRecordV1, SourceHierarchyFloorRecordV1, decode_instance};

const OWNER_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.capacity-owner.v1\0";
const ADMISSION_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.capacity-admission.v1\0";
const FLOOR_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.floor-transaction.v1\0";
const INSTANCE_TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.source-genesis.root-instance-transaction.v1\0";
const TERMINAL_RECORDS: u32 = 3;
const TERMINAL_BYTES: u64 = 4096;

/// Refuses ordinary writes to the existing Root-genesis record family.
///
/// This comparison does not open a native journal or admit a Root transition.
/// The native commit recipe invokes it at its existing ordinary guard slot.
///
/// # Errors
/// Returns `ProtectedBoundary` when any record touches that family.
pub fn require_no_mutation_v1(transaction: &JournalTransaction) -> Result<(), JournalError> {
    if crate::ordinary_mutation::transaction_touches_root_genesis_v1(transaction) {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

/// Checks the original initial-record shape before native pin capture.
///
/// # Errors
/// Refuses existing genesis rows/capacity, another record order or bad instance.
pub fn require_initialization_shape_v1<'transaction>(
    rows: HistoricalLedgerReadViewV1<'_>,
    transaction: &'transaction JournalTransaction,
) -> Result<&'transaction [u8], JournalError> {
    if rows.records(RecordNamespace::DesiredState).any(|(key, _)| {
        key == INSTANCE_KEY
            || key == PINS_KEY
            || key.starts_with(INTENT_PREFIX)
            || key.starts_with(FLOOR_PREFIX)
    }) || {
        // The original capacity-ID accessor checks this same retained poison
        // bit only after the existing-row fast refusal, before family decode.
        if rows.is_poisoned() {
            return Err(JournalError::Poisoned);
        }
        !aos_sandbox_protocol::domain_ledger::capacity_family::legacy_capacity_ids_for_purpose(
            rows.materialized_state_v1(),
            GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor,
        )
        .map_err(JournalError::from)?
        .is_empty()
    } || transaction.records().len() != 2
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
    Ok(instance)
}

/// Compares actual captured pin DATA only after the initial shape check.
///
/// # Errors
/// Refuses a foreign whole tuple or another exact instance transaction ID.
pub fn require_initialization_pins_v1(
    transaction: &JournalTransaction,
    instance: &[u8],
    pins: &[u8; 488],
) -> Result<(), JournalError> {
    if transaction.records().get(1).and_then(JournalRecord::value) != Some(pins.as_slice()) {
        return Err(JournalError::ProtectedBoundary);
    }
    let digest = hash(INSTANCE_TRANSACTION_DOMAIN, instance);
    if transaction.id().as_slice() != &digest.as_bytes()[..16] {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

pub fn intent_key(intent: &RootSourceGenesisIntentRecordV1) -> Vec<u8> {
    [INTENT_PREFIX, intent.project().as_bytes()].concat()
}

pub fn floor_key(floor: &SourceHierarchyFloorRecordV1) -> Vec<u8> {
    [FLOOR_PREFIX, floor.project().as_bytes()].concat()
}

pub fn admission_id(intent: &RootSourceGenesisIntentRecordV1) -> [u8; 16] {
    transaction_id(ADMISSION_DOMAIN, intent.digest())
}

pub fn floor_transaction_id(floor: &SourceHierarchyFloorRecordV1) -> [u8; 16] {
    transaction_id(FLOOR_TRANSACTION_DOMAIN, floor.digest())
}

pub fn request(
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

pub fn validate_admission(
    rows: HistoricalLedgerReadViewV1<'_>,
    transaction: &JournalTransaction,
    reservation: &GlobalCapacityReservationRequestV1,
) -> Result<(), JournalError> {

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
    require_instance_and_roles(rows, &intent)?;
    if intent_record.key() != intent_key(&intent)
        || rows.get(RecordNamespace::DesiredState, intent_record.key())
            .is_some()
        || rows.get(
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

pub fn validate_settlement(
    rows: HistoricalLedgerReadViewV1<'_>,
    transaction: &JournalTransaction,
    reservation: &GlobalCapacityReservationRequestV1,
    capacity_id: [u8; 32],
) -> Result<(), JournalError> {

    let key = [INTENT_PREFIX, reservation_project(rows, reservation)?].concat();
    let intent = RootSourceGenesisIntentRecordV1::from_record_bytes(
        rows.get(RecordNamespace::DesiredState, &key)
            .ok_or(JournalError::AuthorityPreflightMismatch)?,
    )
    .map_err(|_| JournalError::AuthorityPreflightMismatch)?;
    require_instance_and_roles(rows, &intent)?;
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
        || floor.receipt().auth_packet() != intent.accepted_input().auth_packet()
        || rows.get(RecordNamespace::DesiredState, &floor_key(&floor))
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
    rows: HistoricalLedgerReadViewV1<'_>,
    intent: &RootSourceGenesisIntentRecordV1,
) -> Result<(), JournalError> {
    let instance = decode_instance(
        rows.get(RecordNamespace::DesiredState, INSTANCE_KEY)
            .ok_or(JournalError::AuthorityPreflightMismatch)?,
    )
    .map_err(|_| JournalError::AuthorityPreflightMismatch)?;
    let pins = rows.get(RecordNamespace::DesiredState, PINS_KEY)
        .ok_or(JournalError::AuthorityPreflightMismatch)?;
    if instance != intent.instance()
        || crate::replay::root_genesis_pins::role_tuple_digest(pins)
            .map_err(|_| JournalError::AuthorityPreflightMismatch)?
            != intent.roles()
    {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    Ok(())
}

fn reservation_project<'journal>(
    rows: HistoricalLedgerReadViewV1<'journal>,
    reservation: &GlobalCapacityReservationRequestV1,
) -> Result<&'journal [u8], JournalError> {
    let mut matching = rows.records(RecordNamespace::DesiredState)
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
