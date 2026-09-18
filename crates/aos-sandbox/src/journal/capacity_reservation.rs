//! Durable global journal-capacity reservations.
//!
//! Reservations are ordinary replayed records in a closed namespace, but only
//! the methods in this module may append or remove them. Every journal commit
//! accounts for their worst-case retained-record and append-byte budgets.

use sha2::{Digest as _, Sha256};

use super::{
    CommitResult, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
};

const KEY_PREFIX: &[u8] = b"aos.journal.global-capacity-reservation.v1\0";
const RECORD_DOMAIN: &[u8] = b"aos.sandbox.journal.global-capacity-reservation.v1\0";
const VALUE_BYTES: usize = 262;

/// Selects one closed cross-namespace admission and settlement protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GlobalCapacityReservationPurposeV1 {
    /// Publisher permit issuance and terminal publication settlement.
    PublisherCompletion = 1,
    /// Runtime execution admission and terminal effect settlement.
    RuntimeExecution = 2,
}

impl GlobalCapacityReservationPurposeV1 {
    pub(super) const fn owner_namespace(self) -> RecordNamespace {
        match self {
            Self::PublisherCompletion => RecordNamespace::PublisherAuthority,
            Self::RuntimeExecution => RecordNamespace::Effect,
        }
    }

    pub(super) const fn permits(self, namespace: RecordNamespace) -> bool {
        match self {
            Self::PublisherCompletion => matches!(
                namespace,
                RecordNamespace::PublisherAuthority
                    | RecordNamespace::AuthorityPublication
                    | RecordNamespace::Effect
                    | RecordNamespace::GlobalCapacityReservation
            ),
            Self::RuntimeExecution => matches!(
                namespace,
                RecordNamespace::Effect | RecordNamespace::GlobalCapacityReservation
            ),
        }
    }

    fn from_byte(value: u8) -> Result<Self, JournalError> {
        match value {
            1 => Ok(Self::PublisherCompletion),
            2 => Ok(Self::RuntimeExecution),
            _ => Err(JournalError::MalformedRecord(
                "unknown global capacity reservation purpose",
            )),
        }
    }
}

/// Describes one exact operation whose terminal capacity must remain available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalCapacityReservationRequestV1 {
    /// Closed transaction protocol that owns this reservation.
    pub purpose: GlobalCapacityReservationPurposeV1,
    /// Namespace that owns the terminal operation.
    pub owner_namespace: RecordNamespace,
    /// Stable owner identity within that namespace.
    pub owner_id: [u8; 32],
    /// Exact owner or permit commitment.
    pub owner_digest: [u8; 32],
    /// Stable operation identity.
    pub operation_id: [u8; 16],
    /// Exact admitted artifact commitment.
    pub artifact_digest: [u8; 32],
    /// Exact admission checkpoint commitment.
    pub checkpoint_digest: [u8; 32],
    /// Exact predecessor or chain-head commitment.
    pub chain_head_digest: [u8; 32],
    /// Maximum records in the successful terminal transaction.
    pub terminal_records: u32,
    /// Maximum encoded bytes in the successful terminal transaction.
    pub terminal_bytes: u64,
    /// Maximum records in the poison terminal transaction.
    pub poison_records: u32,
    /// Maximum encoded bytes in the poison terminal transaction.
    pub poison_bytes: u64,
}

/// Identifies a replayed reservation without trusting its retained owner digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalCapacityReservationRecoveryBindingV1 {
    /// Closed transaction protocol that owns this reservation.
    pub purpose: GlobalCapacityReservationPurposeV1,
    /// Stable operation identity.
    pub operation_id: [u8; 16],
    /// Exact admitted artifact commitment.
    pub artifact_digest: [u8; 32],
    /// Exact admission checkpoint commitment.
    pub checkpoint_digest: [u8; 32],
    /// Exact predecessor or chain-head commitment.
    pub chain_head_digest: [u8; 32],
    /// Maximum successful terminal record count.
    pub terminal_records: u32,
    /// Maximum successful terminal byte count.
    pub terminal_bytes: u64,
    /// Maximum poison terminal record count.
    pub poison_records: u32,
    /// Maximum poison terminal byte count.
    pub poison_bytes: u64,
}

/// Carries the exact reservation record that must join its admission transaction.
#[must_use = "a prepared capacity reservation must be committed or discarded before admission"]
pub struct PreparedGlobalCapacityReservationV1 {
    pub(super) request: GlobalCapacityReservationRequestV1,
    pub(super) admission_transaction_id: [u8; 16],
    pub(super) reservation_id: [u8; 32],
    pub(super) record: JournalRecord,
}

/// Authorizes exactly one terminal settlement against retained global capacity.
#[must_use = "capacity remains reserved until this authority is settled"]
pub struct GlobalCapacityReservationV1 {
    pub(super) request: GlobalCapacityReservationRequestV1,
    pub(super) admission_transaction_id: [u8; 16],
    pub(super) reservation_id: [u8; 32],
    pub(super) record_digest: [u8; 32],
}

#[derive(Clone, Copy)]
pub(super) struct DecodedCapacityReservationV1 {
    pub reservation_id: [u8; 32],
    pub maximum_records: usize,
    pub maximum_bytes: u64,
}

impl PreparedGlobalCapacityReservationV1 {
    /// Borrows the exact record callers must include in the admission transaction.
    #[must_use]
    pub const fn record(&self) -> &JournalRecord {
        &self.record
    }

    /// Returns the deterministic reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> [u8; 32] {
        self.reservation_id
    }
}

impl GlobalCapacityReservationV1 {
    /// Returns the deterministic reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> [u8; 32] {
        self.reservation_id
    }

    /// Returns the owner namespace and stable owner identity.
    #[must_use]
    pub const fn owner(&self) -> (RecordNamespace, [u8; 32]) {
        (self.request.owner_namespace, self.request.owner_id)
    }

    /// Checks every immutable request field and the admission transaction identity.
    #[must_use]
    pub fn matches_request(
        &self,
        request: &GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
    ) -> bool {
        self.request == *request && self.admission_transaction_id == admission_transaction_id
    }

    /// Returns the authenticated full request retained in namespace 46.
    #[must_use]
    pub const fn request(&self) -> GlobalCapacityReservationRequestV1 {
        self.request
    }

    /// Returns the exact durable admission transaction identity.
    #[must_use]
    pub const fn admission_transaction_id(&self) -> [u8; 16] {
        self.admission_transaction_id
    }

    /// Returns the exact deletion that must join the terminal transaction.
    #[must_use]
    pub fn settlement_record(&self) -> JournalRecord {
        JournalRecord::delete(
            RecordNamespace::GlobalCapacityReservation,
            reservation_key(self.reservation_id),
        )
    }

    pub(super) fn matches_recovery_binding(
        &self,
        binding: &GlobalCapacityReservationRecoveryBindingV1,
    ) -> bool {
        self.request.purpose == binding.purpose
            && self.request.owner_namespace == binding.purpose.owner_namespace()
            && self.request.operation_id == binding.operation_id
            && self.request.artifact_digest == binding.artifact_digest
            && self.request.checkpoint_digest == binding.checkpoint_digest
            && self.request.chain_head_digest == binding.chain_head_digest
            && self.request.terminal_records == binding.terminal_records
            && self.request.terminal_bytes == binding.terminal_bytes
            && self.request.poison_records == binding.poison_records
            && self.request.poison_bytes == binding.poison_bytes
    }
}

impl Journal {
    /// Prepares a durable reservation record for an exact admission transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for sentinel bindings, zero or oversized budgets,
    /// duplicate reservation identity, or an invalid admission transaction ID.
    pub(crate) fn prepare_global_capacity_reservation_v1(
        &self,
        request: GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
    ) -> Result<PreparedGlobalCapacityReservationV1, JournalError> {
        self.ensure_healthy()?;
        validate_request(&request, self)?;
        if admission_transaction_id == [0; 16] {
            return Err(JournalError::InvalidTransaction);
        }
        let reservation_id = reservation_id(&request, admission_transaction_id);
        let key = reservation_key(reservation_id);
        if self
            .state
            .contains_key(&(RecordNamespace::GlobalCapacityReservation, key.clone()))
        {
            return Err(JournalError::DuplicateRecordKey);
        }
        let value = encode_reservation(&request, admission_transaction_id, reservation_id);
        Ok(PreparedGlobalCapacityReservationV1 {
            request,
            admission_transaction_id,
            reservation_id,
            record: JournalRecord::put(RecordNamespace::GlobalCapacityReservation, key, value),
        })
    }

    /// Commits admission and its capacity reservation atomically.
    ///
    /// # Errors
    ///
    /// Returns an error unless the transaction ID and exact reservation record
    /// match the prepared authority and all journal and reserved-capacity bounds hold.
    pub(crate) fn commit_global_capacity_reservation_v1(
        &mut self,
        prepared: PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<(CommitResult, GlobalCapacityReservationV1), JournalError> {
        if transaction.id != prepared.admission_transaction_id
            || transaction
                .records
                .iter()
                .filter(|record| record.namespace == RecordNamespace::GlobalCapacityReservation)
                .ne([&prepared.record])
        {
            return Err(JournalError::InvalidTransaction);
        }
        let result = self.commit_with_capacity_scope(transaction, None, true)?;
        let record_digest = digest_bytes(
            prepared
                .record
                .value
                .as_deref()
                .ok_or(JournalError::InvalidTransaction)?,
        );
        Ok((
            result,
            GlobalCapacityReservationV1 {
                request: prepared.request,
                admission_transaction_id: prepared.admission_transaction_id,
                reservation_id: prepared.reservation_id,
                record_digest,
            },
        ))
    }

    /// Recovers the one-shot settlement authority from an exact replayed reservation.
    ///
    /// # Errors
    ///
    /// Returns an error when the reservation is absent, malformed, or names a
    /// different admission transaction or record digest.
    pub(crate) fn recover_global_capacity_reservation_v1(
        &self,
        reservation_id: [u8; 32],
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        self.lookup_global_capacity_reservation_v1(reservation_id)?
            .ok_or(JournalError::MalformedRecord(
                "capacity reservation is absent",
            ))
    }

    /// Looks up one reservation without conflating authenticated absence with
    /// malformed state or failed provenance validation.
    pub(crate) fn lookup_global_capacity_reservation_v1(
        &self,
        expected_reservation_id: [u8; 32],
    ) -> Result<Option<GlobalCapacityReservationV1>, JournalError> {
        self.ensure_healthy()?;
        let Some(value) = self.state.get(&(
            RecordNamespace::GlobalCapacityReservation,
            reservation_key(expected_reservation_id),
        )) else {
            return Ok(None);
        };
        let (request, admission_transaction_id, decoded_id) = decode_reservation(value)?;
        // The record's deterministic ID commits the original admission ID and
        // full request. Initial append enforces their atomic transaction; after
        // compaction this materialized self-binding is the durable provenance.
        if decoded_id != expected_reservation_id
            || reservation_id(&request, admission_transaction_id) != expected_reservation_id
        {
            return Err(JournalError::MalformedRecord(
                "capacity reservation provenance is invalid",
            ));
        }
        Ok(Some(GlobalCapacityReservationV1 {
            request,
            admission_transaction_id,
            reservation_id: expected_reservation_id,
            record_digest: digest_bytes(value),
        }))
    }

    /// Recovers the unique reservation matching one complete stable binding.
    pub(crate) fn recover_unique_global_capacity_reservation_v1(
        &self,
        binding: &GlobalCapacityReservationRecoveryBindingV1,
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        self.ensure_healthy()?;
        let mut matching = None;
        for (key, value) in self.records(RecordNamespace::GlobalCapacityReservation) {
            let (request, admission_transaction_id, decoded_id) = decode_reservation(value)?;
            if key != reservation_key(decoded_id).as_slice()
                || reservation_id(&request, admission_transaction_id) != decoded_id
            {
                return Err(JournalError::MalformedRecord(
                    "capacity reservation provenance is invalid",
                ));
            }
            let reservation = GlobalCapacityReservationV1 {
                request,
                admission_transaction_id,
                reservation_id: decoded_id,
                record_digest: digest_bytes(value),
            };
            if !reservation.matches_recovery_binding(binding) {
                continue;
            }
            if matching.replace(reservation).is_some() {
                return Err(JournalError::MalformedRecord(
                    "capacity recovery binding is not unique",
                ));
            }
        }
        matching.ok_or(JournalError::MalformedRecord(
            "capacity reservation is absent",
        ))
    }

    pub(super) fn settle_global_capacity_reservation_v1(
        &mut self,
        reservation: GlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        validate_settlement_shape(self, &reservation, transaction)?;
        self.commit_with_capacity_scope(transaction, Some(reservation.reservation_id), true)
    }
}

pub(super) fn validate_settlement_shape(
    journal: &Journal,
    reservation: &GlobalCapacityReservationV1,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    let key = reservation_key(reservation.reservation_id);
    let current = journal
        .state
        .get(&(RecordNamespace::GlobalCapacityReservation, key.clone()))
        .ok_or(JournalError::MalformedRecord(
            "capacity reservation is absent",
        ))?;
    if digest_bytes(current) != reservation.record_digest
        || decode_reservation(current)?
            != (
                reservation.request,
                reservation.admission_transaction_id,
                reservation.reservation_id,
            )
    {
        return Err(JournalError::MalformedRecord(
            "capacity reservation changed before settlement",
        ));
    }
    let reservation_records = transaction
        .records
        .iter()
        .filter(|record| record.namespace == RecordNamespace::GlobalCapacityReservation)
        .collect::<Vec<_>>();
    if reservation_records
        != [&JournalRecord::delete(
            RecordNamespace::GlobalCapacityReservation,
            key,
        )]
    {
        return Err(JournalError::InvalidTransaction);
    }
    let encoded_bytes = super::encoded_transaction_record_bytes(transaction)?;
    let terminal_fits = transaction.records.len()
        <= usize::try_from(reservation.request.terminal_records)
            .map_err(|_| JournalError::InvalidTransaction)?
        && encoded_bytes <= reservation.request.terminal_bytes;
    let poison_fits = transaction.records.len()
        <= usize::try_from(reservation.request.poison_records)
            .map_err(|_| JournalError::InvalidTransaction)?
        && encoded_bytes <= reservation.request.poison_bytes;
    if !terminal_fits && !poison_fits {
        return Err(JournalError::LimitExceeded(
            "capacity-reserved terminal transaction",
        ));
    }
    Ok(())
}

pub(super) fn decode_capacity_record(
    key: &[u8],
    value: &[u8],
) -> Result<DecodedCapacityReservationV1, JournalError> {
    let (request, admission, decoded_reservation_id) = decode_reservation(value)?;
    if key != reservation_key(decoded_reservation_id).as_slice()
        || reservation_id(&request, admission) != decoded_reservation_id
        || request.owner_namespace != request.purpose.owner_namespace()
    {
        return Err(JournalError::MalformedRecord(
            "capacity reservation key or digest is invalid",
        ));
    }
    Ok(DecodedCapacityReservationV1 {
        reservation_id: decoded_reservation_id,
        maximum_records: usize::try_from(request.terminal_records.max(request.poison_records))
            .map_err(|_| JournalError::LimitExceeded("reserved record count"))?,
        maximum_bytes: request.terminal_bytes.max(request.poison_bytes),
    })
}

pub(super) fn all_reservations_owned_by(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    namespace: RecordNamespace,
) -> Result<bool, JournalError> {
    for ((record_namespace, key), value) in state {
        if *record_namespace != RecordNamespace::GlobalCapacityReservation {
            continue;
        }
        let (request, admission, identifier) = decode_reservation(value)?;
        if key.as_slice() != reservation_key(identifier).as_slice()
            || reservation_id(&request, admission) != identifier
            || request.owner_namespace != namespace
            || request.owner_namespace != request.purpose.owner_namespace()
        {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn validate_all_reservations(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
) -> Result<(), JournalError> {
    for ((record_namespace, key), value) in state {
        if *record_namespace != RecordNamespace::GlobalCapacityReservation {
            continue;
        }
        let (request, admission, identifier) = decode_reservation(value)?;
        if key.as_slice() != reservation_key(identifier).as_slice()
            || reservation_id(&request, admission) != identifier
            || request.owner_namespace != request.purpose.owner_namespace()
        {
            return Err(JournalError::MalformedRecord(
                "capacity reservation provenance is invalid",
            ));
        }
    }
    Ok(())
}

fn validate_request(
    request: &GlobalCapacityReservationRequestV1,
    journal: &Journal,
) -> Result<(), JournalError> {
    let records = request.terminal_records.max(request.poison_records);
    let bytes = request.terminal_bytes.max(request.poison_bytes);
    if request.owner_namespace != request.purpose.owner_namespace()
        || request.owner_id == [0; 32]
        || request.owner_digest == [0; 32]
        || request.operation_id == [0; 16]
        || request.artifact_digest == [0; 32]
        || request.checkpoint_digest == [0; 32]
        || request.chain_head_digest == [0; 32]
        || request.terminal_records == 0
        || request.poison_records == 0
        || request.terminal_bytes == 0
        || request.poison_bytes == 0
        || usize::try_from(records).ok().is_none_or(|value| {
            value > journal.limits.maximum_records_per_transaction
                || value > journal.limits.maximum_materialized_records
        })
        || bytes
            > journal
                .limits
                .maximum_journal_bytes
                .min(journal.limits.maximum_transaction_bytes as u64)
    {
        return Err(JournalError::LimitExceeded(
            "invalid global capacity reservation",
        ));
    }
    Ok(())
}

fn reservation_key(reservation_id: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_PREFIX.len() + reservation_id.len());
    key.extend_from_slice(KEY_PREFIX);
    key.extend_from_slice(&reservation_id);
    key
}

pub(super) fn reservation_key_for_validation(reservation_id: [u8; 32]) -> Vec<u8> {
    reservation_key(reservation_id)
}

fn reservation_id(
    request: &GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update([request.purpose as u8]);
    hasher.update([request.owner_namespace as u8]);
    hasher.update(request.owner_id);
    hasher.update(request.owner_digest);
    hasher.update(request.operation_id);
    hasher.update(request.artifact_digest);
    hasher.update(request.checkpoint_digest);
    hasher.update(request.chain_head_digest);
    hasher.update(request.terminal_records.to_be_bytes());
    hasher.update(request.terminal_bytes.to_be_bytes());
    hasher.update(request.poison_records.to_be_bytes());
    hasher.update(request.poison_bytes.to_be_bytes());
    hasher.update(admission_transaction_id);
    hasher.finalize().into()
}

pub(crate) fn capacity_reservation_identity_is_exact_v1(
    request: &GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
    candidate_reservation_id: [u8; 32],
) -> bool {
    reservation_id(request, admission_transaction_id) == candidate_reservation_id
}

fn encode_reservation(
    request: &GlobalCapacityReservationRequestV1,
    admission_transaction_id: [u8; 16],
    reservation_id: [u8; 32],
) -> Vec<u8> {
    let mut value = Vec::with_capacity(VALUE_BYTES);
    value.extend_from_slice(b"AOSJCR01");
    value.extend_from_slice(&1_u16.to_be_bytes());
    value.push(request.owner_namespace as u8);
    value.push(request.purpose as u8);
    value.extend_from_slice(&[0; 2]);
    value.extend_from_slice(&request.owner_id);
    value.extend_from_slice(&request.owner_digest);
    value.extend_from_slice(&request.operation_id);
    value.extend_from_slice(&request.artifact_digest);
    value.extend_from_slice(&request.checkpoint_digest);
    value.extend_from_slice(&request.chain_head_digest);
    value.extend_from_slice(&request.terminal_records.to_be_bytes());
    value.extend_from_slice(&request.terminal_bytes.to_be_bytes());
    value.extend_from_slice(&request.poison_records.to_be_bytes());
    value.extend_from_slice(&request.poison_bytes.to_be_bytes());
    value.extend_from_slice(&admission_transaction_id);
    value.extend_from_slice(&reservation_id);
    value
}

pub(super) fn decode_reservation(
    value: &[u8],
) -> Result<(GlobalCapacityReservationRequestV1, [u8; 16], [u8; 32]), JournalError> {
    if value.len() != VALUE_BYTES
        || &value[..8] != b"AOSJCR01"
        || value[8..10] != 1_u16.to_be_bytes()
        || value[12..14] != [0; 2]
    {
        return Err(JournalError::MalformedRecord(
            "invalid capacity reservation envelope",
        ));
    }
    let namespace = RecordNamespace::from_byte(value[10])?;
    let purpose = GlobalCapacityReservationPurposeV1::from_byte(value[11])?;
    let mut offset = 14;
    let owner_id = take::<32>(value, &mut offset);
    let owner_digest = take::<32>(value, &mut offset);
    let operation_id = take::<16>(value, &mut offset);
    let artifact_digest = take::<32>(value, &mut offset);
    let checkpoint_digest = take::<32>(value, &mut offset);
    let chain_head_digest = take::<32>(value, &mut offset);
    let terminal_records = u32::from_be_bytes(take::<4>(value, &mut offset));
    let terminal_bytes = u64::from_be_bytes(take::<8>(value, &mut offset));
    let poison_records = u32::from_be_bytes(take::<4>(value, &mut offset));
    let poison_bytes = u64::from_be_bytes(take::<8>(value, &mut offset));
    let admission_transaction_id = take::<16>(value, &mut offset);
    let reservation_id = take::<32>(value, &mut offset);
    if offset != value.len() {
        return Err(JournalError::MalformedRecord(
            "capacity reservation has trailing bytes",
        ));
    }
    Ok((
        GlobalCapacityReservationRequestV1 {
            purpose,
            owner_namespace: namespace,
            owner_id,
            owner_digest,
            operation_id,
            artifact_digest,
            checkpoint_digest,
            chain_head_digest,
            terminal_records,
            terminal_bytes,
            poison_records,
            poison_bytes,
        },
        admission_transaction_id,
        reservation_id,
    ))
}

fn take<const N: usize>(value: &[u8], offset: &mut usize) -> [u8; N] {
    let mut bytes = [0; N];
    bytes.copy_from_slice(&value[*offset..*offset + N]);
    *offset += N;
    bytes
}

fn digest_bytes(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}
