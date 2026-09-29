//! Closed, nonauthorizing Controller resource-preparation records.
//!
//! ```text
//! AOSCRP01 | phase:1 | reserved:7 | request:80 | resource-source:680 |
//! predecessor:32 | capacity-reservation:32 | checksum:32
//! ```
//!
//! All integers are big endian. The exact 872-byte value contains references
//! to existing protected resources, never View bodies, descriptors or signed
//! authority copies. ResourcePrepared has a zero predecessor. Quarantine
//! commits the reconstructed Prepared checksum as predecessor and preserves
//! every original field. Both phases are DATA; neither decodes into a guard.

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use super::ConsumerResourceErrorV1;
use super::source::{ResourceSource, SOURCE_BYTES};
use crate::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1, Journal, JournalRecord,
    JournalTransaction, PreparedGlobalCapacityReservationV1, ProtectedJournalPreflight,
    RecordNamespace,
};

const NAMESPACE: RecordNamespace = RecordNamespace::ControllerConsumerReadAttempt;
const PURPOSE: GlobalCapacityReservationPurposeV1 =
    GlobalCapacityReservationPurposeV1::ControllerConsumerResource;
const REQUEST_BYTES: usize = 80;
const RECORD_BYTES: usize = 16 + REQUEST_BYTES + SOURCE_BYTES + 32 + 32 + 32;
const _: () = assert!(RECORD_BYTES <= 4096);
const MAGIC: &[u8; 8] = b"AOSCRP01";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.controller-consumer-resource-attempt.v1\0";
const REQUEST_DOMAIN: &[u8] = b"aos.sandbox.controller-consumer-request-data.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.controller-consumer-resource-transaction.v1\0";

/// Contains bounded kernel-read comparison input, without proving its origin.
///
/// A genuine Ready-worker/kernel-request owner must independently authenticate
/// these fields before a later read admission. This DTO can only prepare local
/// resource custody; it cannot construct a Ready or disclosure guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsumerReadRequestDataV1 {
    /// Stable Controller preparation lookup identity.
    pub request_id: [u8; 16],
    /// Claimed original connection/worker instance, to be joined by its owner.
    pub connection_instance: [u8; 16],
    /// Original kernel request identity, not an independently verified claim.
    pub kernel_unique: u64,
    /// Claimed immutable-index node selector.
    pub node: u64,
    /// Claimed original open-file handle.
    pub file_handle: u64,
    /// Requested byte offset.
    pub offset: u64,
    /// Requested byte length, including a zero-length semantic read.
    pub length: u32,
    /// One exclusive absolute BOOTTIME cutoff, never renewed on replay.
    pub deadline: u64,
}

impl ConsumerReadRequestDataV1 {
    fn validate(self) -> Result<(), ConsumerResourceErrorV1> {
        if self.request_id == [0; 16]
            || self.connection_instance == [0; 16]
            || self.kernel_unique == 0
            || self.node == 0
            || self.file_handle == 0
            || self.deadline == 0
            || self.offset.checked_add(u64::from(self.length)).is_none()
        {
            return Err(ConsumerResourceErrorV1::Invalid);
        }
        Ok(())
    }

    fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.connection_instance);
        for value in [self.kernel_unique, self.node, self.file_handle, self.offset] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes.extend_from_slice(&self.length.to_be_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&self.deadline.to_be_bytes());
    }

    fn digest(self) -> [u8; 32] {
        let mut bytes = Vec::with_capacity(REQUEST_BYTES);
        self.encode(&mut bytes);
        hash(REQUEST_DOMAIN, &bytes)
    }
}

/// Selects resource-specific ceilings no greater than the actual journal limits.
#[derive(Clone, Copy, Debug)]
pub struct ConsumerResourceAttemptLimitsV1 {
    /// Maximum retained preparation rows, including quarantined history.
    pub maximum_attempts: usize,
    /// Maximum retained key/value bytes in this preparation family.
    pub maximum_materialized_bytes: usize,
    /// Maximum length admitted as comparison input for one read.
    pub maximum_read_bytes: u32,
}

/// Selects only the presently implemented local, nonauthorizing phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConsumerResourceAttemptPhaseV1 {
    /// Retains exact resource/request data before any Ready/read join.
    ResourcePrepared = 1,
    /// Permanently refuses this local preparation, retaining original data.
    ResourceQuarantined = 2,
}

/// Exposes historical comparison data, never a live consumer-read capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableConsumerResourceAttemptV1 {
    record: Record,
}

impl DurableConsumerResourceAttemptV1 {
    /// Returns the original immutable request comparison input.
    #[must_use]
    pub const fn request(&self) -> ConsumerReadRequestDataV1 {
        self.record.request
    }

    /// Returns the closed local preparation phase.
    #[must_use]
    pub const fn phase(&self) -> ConsumerResourceAttemptPhaseV1 {
        self.record.phase
    }

    /// Returns the structural checksum, which conveys no authority.
    #[must_use]
    pub const fn record_digest(&self) -> ObjectDigest {
        ObjectDigest::from_bytes(self.record.digest)
    }

    /// Returns the complete exact-width nonauthorizing record bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.record.encode()
    }

    /// Decodes comparison data without reconstructing an owner or deadline guard.
    ///
    /// # Errors
    ///
    /// Rejects unknown phases, reserved/trailing bytes, sentinel fields, altered
    /// checksums or a quarantine predecessor differing from the original row.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ConsumerResourceErrorV1> {
        Ok(Self {
            record: Record::decode(bytes)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Record {
    phase: ConsumerResourceAttemptPhaseV1,
    request: ConsumerReadRequestDataV1,
    source: ResourceSource,
    predecessor: [u8; 32],
    reservation: [u8; 32],
    digest: [u8; 32],
}

impl Record {
    fn body(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.push(self.phase as u8);
        bytes.extend_from_slice(&[0; 7]);
        self.request.encode(&mut bytes);
        bytes.extend_from_slice(&self.source.bytes);
        bytes.extend_from_slice(&self.predecessor);
        bytes.extend_from_slice(&self.reservation);
        bytes
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    fn update_digest(&mut self) {
        self.digest = hash(RECORD_DOMAIN, &self.body());
    }

    fn quarantine(&self) -> Result<Self, ConsumerResourceErrorV1> {
        if self.phase != ConsumerResourceAttemptPhaseV1::ResourcePrepared {
            return Err(ConsumerResourceErrorV1::Changed);
        }
        let mut successor = self.clone();
        successor.phase = ConsumerResourceAttemptPhaseV1::ResourceQuarantined;
        successor.predecessor = self.digest;
        successor.update_digest();
        Ok(successor)
    }

    fn decode(mut bytes: &[u8]) -> Result<Self, ConsumerResourceErrorV1> {
        if bytes.len() != RECORD_BYTES || take::<8>(&mut bytes)? != *MAGIC {
            return Err(ConsumerResourceErrorV1::Invalid);
        }
        let phase = match take::<1>(&mut bytes)?[0] {
            1 => ConsumerResourceAttemptPhaseV1::ResourcePrepared,
            2 => ConsumerResourceAttemptPhaseV1::ResourceQuarantined,
            _ => return Err(ConsumerResourceErrorV1::Invalid),
        };
        if take::<7>(&mut bytes)? != [0; 7] {
            return Err(ConsumerResourceErrorV1::Invalid);
        }
        let request = ConsumerReadRequestDataV1 {
            request_id: take(&mut bytes)?,
            connection_instance: take(&mut bytes)?,
            kernel_unique: u64::from_be_bytes(take(&mut bytes)?),
            node: u64::from_be_bytes(take(&mut bytes)?),
            file_handle: u64::from_be_bytes(take(&mut bytes)?),
            offset: u64::from_be_bytes(take(&mut bytes)?),
            length: u32::from_be_bytes(take(&mut bytes)?),
            deadline: {
                if take::<4>(&mut bytes)? != [0; 4] {
                    return Err(ConsumerResourceErrorV1::Invalid);
                }
                u64::from_be_bytes(take(&mut bytes)?)
            },
        };
        request.validate()?;
        let source = ResourceSource {
            bytes: take(&mut bytes)?,
        };
        source.validate()?;
        source.validate_request_deadline(request.deadline)?;
        let record = Self {
            phase,
            request,
            source,
            predecessor: take(&mut bytes)?,
            reservation: take(&mut bytes)?,
            digest: take(&mut bytes)?,
        };
        if !bytes.is_empty()
            || record.reservation == [0; 32]
            || hash(RECORD_DOMAIN, &record.body()) != record.digest
        {
            return Err(ConsumerResourceErrorV1::Invalid);
        }
        let mut original = record.clone();
        original.phase = ConsumerResourceAttemptPhaseV1::ResourcePrepared;
        original.predecessor = [0; 32];
        original.update_digest();
        let expected = if phase == ConsumerResourceAttemptPhaseV1::ResourcePrepared {
            [0; 32]
        } else {
            original.digest
        };
        if record.predecessor != expected {
            return Err(ConsumerResourceErrorV1::Invalid);
        }
        Ok(record)
    }

    fn put(&self) -> JournalRecord {
        JournalRecord::put(NAMESPACE, self.request.request_id.to_vec(), self.encode())
    }
}

pub(super) enum Prepared {
    Replay(DurableConsumerResourceAttemptV1),
    Append {
        record: DurableConsumerResourceAttemptV1,
        capacity: PreparedGlobalCapacityReservationV1,
        transaction: JournalTransaction,
        preflight: ProtectedJournalPreflight,
    },
}

fn load(journal: &Journal) -> Result<Vec<Record>, ConsumerResourceErrorV1> {
    journal.ensure_protected_authority()?;
    let mut result = Vec::new();
    let limits = journal.configured_limits();
    let mut bytes = 0usize;
    for (key, value) in journal.records(NAMESPACE) {
        bytes = bytes
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(ConsumerResourceErrorV1::Capacity)?;
        if result.len() >= limits.maximum_materialized_records
            || bytes > limits.maximum_materialized_bytes
        {
            return Err(ConsumerResourceErrorV1::Capacity);
        }
        let record = Record::decode(value)?;
        if key != record.request.request_id {
            return Err(ConsumerResourceErrorV1::Invalid);
        }
        result.push(record);
    }
    Ok(result)
}

pub(super) fn require_retained_prepared(
    journal: &Journal,
    request: ConsumerReadRequestDataV1,
    source: &ResourceSource,
) -> Result<(), ConsumerResourceErrorV1> {
    let record = load(journal)?
        .into_iter()
        .find(|record| record.request.request_id == request.request_id)
        .ok_or(ConsumerResourceErrorV1::Changed)?;
    require_prepared_record(journal, &record, request, source)
}

fn require_prepared_record(
    journal: &Journal,
    record: &Record,
    request: ConsumerReadRequestDataV1,
    source: &ResourceSource,
) -> Result<(), ConsumerResourceErrorV1> {
    if record.phase != ConsumerResourceAttemptPhaseV1::ResourcePrepared
        || record.request != request
        || &record.source != source
    {
        return Err(ConsumerResourceErrorV1::Changed);
    }
    let capacity = journal.recover_global_capacity_reservation_v1(record.reservation)?;
    if !capacity.matches_request(
        &capacity_request(request, source, capacity.request().terminal_bytes),
        transaction_id(1, request),
    ) {
        return Err(ConsumerResourceErrorV1::Changed);
    }
    Ok(())
}

pub(super) fn prepare(
    journal: &mut Journal,
    request: ConsumerReadRequestDataV1,
    source: &ResourceSource,
    limits: ConsumerResourceAttemptLimitsV1,
) -> Result<Prepared, ConsumerResourceErrorV1> {
    request.validate()?;
    let actual = journal.configured_limits();
    if limits.maximum_attempts == 0
        || limits.maximum_attempts > actual.maximum_materialized_records
        || limits.maximum_materialized_bytes == 0
        || limits.maximum_materialized_bytes > actual.maximum_materialized_bytes
        || limits.maximum_read_bytes == 0
        || request.length > limits.maximum_read_bytes
    {
        return Err(ConsumerResourceErrorV1::Capacity);
    }
    let history = load(journal)?;
    let retained_bytes = history
        .len()
        .checked_mul(16 + RECORD_BYTES)
        .ok_or(ConsumerResourceErrorV1::Capacity)?;
    if history.len() > limits.maximum_attempts || retained_bytes > limits.maximum_materialized_bytes
    {
        return Err(ConsumerResourceErrorV1::Capacity);
    }
    if let Some(existing) = history
        .iter()
        .find(|record| record.request.request_id == request.request_id)
    {
        require_prepared_record(journal, existing, request, source)?;
        return Ok(Prepared::Replay(DurableConsumerResourceAttemptV1 {
            record: existing.clone(),
        }));
    }
    let materialized = history
        .len()
        .checked_add(1)
        .and_then(|count| count.checked_mul(16 + RECORD_BYTES))
        .ok_or(ConsumerResourceErrorV1::Capacity)?;
    if history.len() >= limits.maximum_attempts || materialized > limits.maximum_materialized_bytes
    {
        return Err(ConsumerResourceErrorV1::Capacity);
    }
    let mut authority = journal.claim_global_capacity_reservation_authority(PURPOSE)?;
    let preview = authority.prepare_global_capacity_reservation_v1(
        capacity_request(request, source, 1),
        transaction_id(1, request),
    )?;
    let mut record = Record {
        phase: ConsumerResourceAttemptPhaseV1::ResourcePrepared,
        request,
        source: source.clone(),
        predecessor: [0; 32],
        reservation: preview.reservation_id(),
        digest: [0; 32],
    };
    record.update_digest();
    // Reserve the complete terminal append, including BEGIN/COMMIT and record
    // frames. The preview is discarded without appending any record.
    let terminal = JournalTransaction::new(
        transaction_id(2, request),
        vec![
            record.quarantine()?.put(),
            JournalRecord::delete(
                RecordNamespace::GlobalCapacityReservation,
                preview.record().key().to_vec(),
            ),
        ],
    )?;
    let bytes = crate::journal::encoded_transaction_append_bytes(&terminal)?;
    let capacity = authority.prepare_global_capacity_reservation_v1(
        capacity_request(request, source, bytes),
        transaction_id(1, request),
    )?;
    record.reservation = capacity.reservation_id();
    record.update_digest();
    let transaction = JournalTransaction::new(
        transaction_id(1, request),
        vec![record.put(), capacity.record().clone()],
    )?;
    let preflight = authority.preflight_global_capacity_reservation_v1(&capacity, &transaction)?;
    Ok(Prepared::Append {
        record: DurableConsumerResourceAttemptV1 { record },
        capacity,
        transaction,
        preflight,
    })
}

pub(super) fn commit(
    journal: &mut Journal,
    prepared: Prepared,
) -> Result<DurableConsumerResourceAttemptV1, ConsumerResourceErrorV1> {
    match prepared {
        Prepared::Replay(record) => Ok(record),
        Prepared::Append {
            record,
            capacity,
            transaction,
            preflight,
        } => {
            journal
                .claim_global_capacity_reservation_authority(PURPOSE)?
                .commit_global_capacity_reservation_v1(&preflight, capacity, &transaction)?;
            let current = load(journal)?
                .into_iter()
                .find(|item| item.request.request_id == record.request().request_id)
                .ok_or(ConsumerResourceErrorV1::Changed)?;
            if current != record.record {
                return Err(ConsumerResourceErrorV1::Changed);
            }
            Ok(record)
        }
    }
}

pub(super) fn quarantine(
    journal: &mut Journal,
    request_id: [u8; 16],
) -> Result<DurableConsumerResourceAttemptV1, ConsumerResourceErrorV1> {
    let original = load(journal)?
        .into_iter()
        .find(|record| record.request.request_id == request_id)
        .ok_or(ConsumerResourceErrorV1::Changed)?;
    if original.phase == ConsumerResourceAttemptPhaseV1::ResourceQuarantined {
        if journal
            .lookup_global_capacity_reservation_v1(original.reservation)?
            .is_some()
        {
            return Err(ConsumerResourceErrorV1::Changed);
        }
        return Ok(DurableConsumerResourceAttemptV1 { record: original });
    }
    let successor = original.quarantine()?;
    let mut authority = journal.claim_global_capacity_reservation_authority(PURPOSE)?;
    let capacity = authority.recover_global_capacity_reservation_v1(original.reservation)?;
    if !capacity.matches_request(
        &capacity_request(
            original.request,
            &original.source,
            capacity.request().terminal_bytes,
        ),
        transaction_id(1, original.request),
    ) {
        return Err(ConsumerResourceErrorV1::Changed);
    }
    let transaction = JournalTransaction::new(
        transaction_id(2, original.request),
        vec![successor.put(), capacity.settlement_record()],
    )?;
    let preflight = authority.preflight_reserved_terminal_v1(&capacity, &transaction)?;
    authority.commit_reserved_terminal_v1(&preflight, capacity, &transaction)?;
    let actual = load(journal)?
        .into_iter()
        .find(|record| record.request.request_id == request_id)
        .ok_or(ConsumerResourceErrorV1::Changed)?;
    if actual != successor {
        return Err(ConsumerResourceErrorV1::Changed);
    }
    Ok(DurableConsumerResourceAttemptV1 { record: successor })
}

fn capacity_request(
    request: ConsumerReadRequestDataV1,
    source: &ResourceSource,
    bytes: u64,
) -> GlobalCapacityReservationRequestV1 {
    GlobalCapacityReservationRequestV1 {
        purpose: PURPOSE,
        owner_namespace: NAMESPACE,
        owner_id: request.digest(),
        owner_digest: source.digest(),
        operation_id: request.request_id,
        artifact_digest: request.digest(),
        checkpoint_digest: source.digest(),
        chain_head_digest: source.digest(),
        future_transactions: 1,
        terminal_records: 2,
        terminal_bytes: bytes,
        poison_records: 2,
        poison_bytes: bytes,
    }
}

fn transaction_id(phase: u8, request: ConsumerReadRequestDataV1) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(TRANSACTION_DOMAIN)
        .chain_update([phase])
        .chain_update(request.digest())
        .finalize()
        .into();
    let mut result = [0; 16];
    result.copy_from_slice(&digest[..16]);
    result[0] |= 1;
    result
}

fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(domain)
        .chain_update(bytes)
        .finalize()
        .into()
}

/// Refuses generic mutations and checks the exact closed owner/capacity graph.
pub(super) fn require_transition(
    journal: &Journal,
    transaction: &JournalTransaction,
    allow_capacity: bool,
    settling: Option<[u8; 32]>,
) -> Result<(), crate::JournalError> {
    use crate::JournalError;
    let resources: Vec<_> = transaction
        .records()
        .iter()
        .filter(|record| record.namespace() == NAMESPACE)
        .collect();
    let capacities: Vec<_> = transaction
        .records()
        .iter()
        .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
        .collect();
    if resources.is_empty() && !allow_capacity {
        // The existing generic-commit boundary rejects every capacity write.
        // Preserve its diagnostics/order for unrelated malformed transactions.
        return Ok(());
    }
    let touches_our_capacity = capacities.iter().try_fold(false, |found, record| {
        let stored;
        let capacity = if record.value().is_some() {
            *record
        } else if let Some(value) =
            journal.get(RecordNamespace::GlobalCapacityReservation, record.key())
        {
            stored = JournalRecord::put(
                RecordNamespace::GlobalCapacityReservation,
                record.key().to_vec(),
                value.to_vec(),
            );
            &stored
        } else {
            return Ok::<_, JournalError>(found);
        };
        // Decode each row before combining matches: a preceding purpose-7
        // match must not hide a later malformed or unknown capacity family.
        let matches = crate::journal::capacity_record_has_legacy_purpose(capacity, PURPOSE)?;
        Ok(found || matches)
    })?;
    if resources.is_empty() && !touches_our_capacity {
        return Ok(());
    }
    let validate = || -> Result<(), ConsumerResourceErrorV1> {
        if !allow_capacity
            || resources.len() != 1
            || capacities.len() != 1
            || transaction.records().len() != 2
        {
            return Err(ConsumerResourceErrorV1::Invalid);
        }
        let record = Record::decode(
            resources[0]
                .value()
                .ok_or(ConsumerResourceErrorV1::Invalid)?,
        )?;
        if resources[0].key() != record.request.request_id {
            return Err(ConsumerResourceErrorV1::Invalid);
        }
        match record.phase {
            ConsumerResourceAttemptPhaseV1::ResourcePrepared => {
                if settling.is_some() || journal.get(NAMESPACE, resources[0].key()).is_some() {
                    return Err(ConsumerResourceErrorV1::Changed);
                }
                let (request, admission, reservation) =
                    crate::journal::decode_capacity_reservation_request_v1(capacities[0])?;
                if admission != transaction_id(1, record.request)
                    || transaction.id() != &admission
                    || reservation != record.reservation
                    || request
                        != capacity_request(record.request, &record.source, request.terminal_bytes)
                {
                    return Err(ConsumerResourceErrorV1::Changed);
                }
                let terminal = JournalTransaction::new(
                    transaction_id(2, record.request),
                    vec![
                        record.quarantine()?.put(),
                        JournalRecord::delete(
                            RecordNamespace::GlobalCapacityReservation,
                            capacities[0].key().to_vec(),
                        ),
                    ],
                )?;
                if crate::journal::encoded_transaction_append_bytes(&terminal)?
                    != request.terminal_bytes
                {
                    return Err(ConsumerResourceErrorV1::Changed);
                }
                record.source.validate_current_graph(journal)
            }
            ConsumerResourceAttemptPhaseV1::ResourceQuarantined => {
                if settling != Some(record.reservation) || capacities[0].value().is_some() {
                    return Err(ConsumerResourceErrorV1::Changed);
                }
                let original = journal
                    .get(NAMESPACE, resources[0].key())
                    .ok_or(ConsumerResourceErrorV1::Changed)
                    .and_then(Record::decode)?;
                let capacity =
                    journal.recover_global_capacity_reservation_v1(record.reservation)?;
                if original.quarantine()? != record
                    || transaction.id() != &transaction_id(2, record.request)
                    || capacities[0] != &capacity.settlement_record()
                    || !capacity.matches_request(
                        &capacity_request(
                            original.request,
                            &original.source,
                            capacity.request().terminal_bytes,
                        ),
                        transaction_id(1, original.request),
                    )
                {
                    return Err(ConsumerResourceErrorV1::Changed);
                }
                Ok(())
            }
        }
    };
    validate().map_err(|_| JournalError::ProtectedBoundary)
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], ConsumerResourceErrorV1> {
    let (prefix, remaining) = bytes
        .split_at_checked(N)
        .ok_or(ConsumerResourceErrorV1::Invalid)?;
    let result = prefix
        .try_into()
        .map_err(|_| ConsumerResourceErrorV1::Invalid)?;
    *bytes = remaining;
    Ok(result)
}
