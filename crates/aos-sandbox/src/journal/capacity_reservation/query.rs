//! Original-root Inventory capacity floors as nonauthorizing version-6 DATA.
//!
//! ```text
//! AOSJCR01 | version:u16be=6 | namespace:u8=40 | purpose:u8=10
//! kind:u8=7 (OriginalRootInventory) | profile:u8=1|2 | reserved[2]=0
//! owner[32] | original_owner_cut[32] | operation[16] | artifact[32]
//! admission_owner_put_map[32] | admission_native_union[32]
//! transactions:u32be | record_frames:u32be | append:u64be
//! growth_entries:u32be | growth_bytes:u64be
//! admission[16] | remaining_profile[32] | identity[32]
//! ```
//!
//! The unchanged capacity key is 75 bytes; the value is exactly 300 bytes.
//! Identity is SHA-256 of the exact domain
//! `aos.journal.root-recovery-query-capacity.v6.floor-identity\0`, u32be(268),
//! and the first 268 value bytes. Kind 7 means OriginalRootInventory only in
//! this version; the ordinary v4 RecoveryInventory meaning is unchanged.
//!
//! The closed profiles retain a conservative historical future envelope:
//! status transfer plus a four-owner envelope, or that envelope alone. They
//! grant no permission to emit those owner changes. The actual ordinary
//! Inventory Complete edge has two owner PUTs and needs a separate validated
//! writer. Scalar commitments do not prove their preimages, signed custody,
//! currentness, owner/replay rejoin, admission under the eight opened limits,
//! sequence headroom, protected readback, or any append/signer authority.
//! The named writer separately rejoins the canonical query and original rows;
//! generic admission continues to refuse this family.

use aos_sandbox_protocol::mount_source_acquisition_state::format::{
    MAXIMUM_ACQUISITION_VALUE_BYTES, MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES,
    MAXIMUM_PROVIDER_HEAD_VALUE_BYTES,
};
use aos_sandbox_protocol::mount_source_acquisition_state::{
    acquisition_key, provider_attempt_key, provider_head_key,
};

use super::super::{
    JournalError, JournalLimits, JournalRecord, JournalTransaction, RecordNamespace,
    encode_record, encoded_transaction_append_bytes,
};
use super::fixed300::{FixedCapacityBody, VALUE_BYTES, floor_identity};
use super::{reservation_key, take};

const IDENTITY_DOMAIN: &[u8] =
    b"aos.journal.root-recovery-query-capacity.v6.floor-identity\0";
const ORIGINAL_ROOT_INVENTORY_KIND: u8 = 7;

/// Selects a closed conservative future suffix without admitting a producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(in crate::journal) enum QueryCapacityProfileV6 {
    /// Reserves a response transfer and its retained uncertain suffix.
    StatusOrComplete = 1,
    /// Retains the original query's unresolved future suffix.
    RetainedUncertain = 2,
}

impl QueryCapacityProfileV6 {
    /// Returns the closed count, independent of the enum discriminator.
    #[must_use]
    pub(in crate::journal) const fn remaining_transactions(self) -> u32 {
        match self {
            Self::StatusOrComplete => 2,
            Self::RetainedUncertain => 1,
        }
    }

    /// Returns record frames only, excluding transaction Begin and Commit.
    #[must_use]
    pub(in crate::journal) const fn remaining_record_frames(self) -> u32 {
        match self {
            Self::StatusOrComplete => 9,
            Self::RetainedUncertain => 5,
        }
    }

    /// Measures the fixed conservative envelope from the actual DATA encoder.
    ///
    /// With today's canonical value bounds this is 25,167,849 bytes for
    /// StatusOrComplete and 16,778,150 bytes for RetainedUncertain. These are
    /// future append budgets; admission's actual retained query/floor bytes
    /// must be charged separately by the eventual named writer.
    ///
    /// # Errors
    ///
    /// Rejects an unrepresentable canonical key, framing, or aggregate bound.
    pub(in crate::journal) fn remaining_append_bytes(self) -> Result<u64, JournalError> {
        let retained = retained_envelope()?;
        let retained_bytes = framed_envelope_bytes(
            &retained,
            &[
                MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES,
                MAXIMUM_PROVIDER_HEAD_VALUE_BYTES,
                MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES,
                MAXIMUM_ACQUISITION_VALUE_BYTES,
            ],
        )?;

        match self {
            Self::RetainedUncertain => Ok(retained_bytes),
            Self::StatusOrComplete => {
                let status = status_envelope()?;
                let status_bytes = framed_envelope_bytes(
                    &status,
                    &[
                        MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES,
                        MAXIMUM_PROVIDER_HEAD_VALUE_BYTES,
                    ],
                )?;
                status_bytes
                    .checked_add(retained_bytes)
                    .ok_or(JournalError::JournalTooLarge)
            }
        }
    }

    /// Checks every promised envelope against the opened per-record/TX bounds.
    ///
    /// # Errors
    /// Rejects opened key, payload, record-count or aggregate TX-byte limits
    /// below either required future envelope, including framing overflow.
    pub(in crate::journal) fn validate_limits(self, limits: JournalLimits) -> Result<(), JournalError> {
        validate_envelope_limits(
            &retained_envelope()?,
            &[
                MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES,
                MAXIMUM_PROVIDER_HEAD_VALUE_BYTES,
                MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES,
                MAXIMUM_ACQUISITION_VALUE_BYTES,
            ],
            limits,
        )?;
        if self == Self::StatusOrComplete {
            validate_envelope_limits(
                &status_envelope()?,
                &[MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES, MAXIMUM_PROVIDER_HEAD_VALUE_BYTES],
                limits,
            )?;
        }
        Ok(())
    }

    fn from_byte(value: u8) -> Result<Self, JournalError> {
        match value {
            1 => Ok(Self::StatusOrComplete),
            2 => Ok(Self::RetainedUncertain),
            _ => Err(invalid("unknown query capacity profile")),
        }
    }
}

/// Holds input commitments and closed conservative accounting as DATA only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::journal) struct QueryCapacityDataV6 {
    /// Closed remaining suffix discriminator; never a transaction count.
    pub profile: QueryCapacityProfileV6,
    /// Original Inventory query Attempt identity.
    pub owner_id: [u8; 32],
    /// Historical original owner-before-cut commitment.
    pub original_owner_cut_digest: [u8; 32],
    /// Exact original signed Inventory request identity.
    pub operation_id: [u8; 16],
    /// Complete original signed-request artifact commitment.
    pub original_artifact_digest: [u8; 32],
    /// Complete original admission owner PUT-map commitment, excluding floors.
    pub admission_owner_mutation_digest: [u8; 32],
    /// Historical complete admission native-union commitment.
    pub admission_native_preservation_union_digest: [u8; 32],
    /// Exact closed remaining transaction count: two or one.
    pub remaining_transactions: u32,
    /// Exact conservative record-frame count: nine or five.
    pub remaining_record_frames: u32,
    /// Exact conservative future fully framed append-byte envelope.
    pub remaining_append_bytes: u64,
    /// Zero future positive entry growth; admission is charged separately.
    pub maximum_retained_growth_entries: u32,
    /// Conservative retained byte-growth envelope, equal to append bytes.
    pub maximum_retained_growth_bytes: u64,
    /// Original actual admission TX identity, never renewed by a later query.
    pub admission_transaction: [u8; 16],
    /// Original closed profile/reference descriptor commitment.
    pub remaining_profile_digest: [u8; 32],
}

impl QueryCapacityDataV6 {
    fn validate(&self) -> Result<(), JournalError> {
        if self.owner_id == [0; 32]
            || self.original_owner_cut_digest == [0; 32]
            || self.operation_id == [0; 16]
            || self.original_artifact_digest == [0; 32]
            || self.admission_owner_mutation_digest == [0; 32]
            || self.admission_native_preservation_union_digest == [0; 32]
            || self.admission_transaction == [0; 16]
            || self.remaining_profile_digest == [0; 32]
        {
            return Err(invalid("query capacity bindings"));
        }

        if self.remaining_transactions != self.profile.remaining_transactions()
            || self.remaining_record_frames != self.profile.remaining_record_frames()
            || self.remaining_append_bytes != self.profile.remaining_append_bytes()?
            || self.maximum_retained_growth_entries != 0
            || self.maximum_retained_growth_bytes != self.remaining_append_bytes
        {
            return Err(invalid("query capacity remaining geometry"));
        }
        Ok(())
    }

    fn identity_payload(&self) -> Vec<u8> {
        let mut bytes = b"AOSJCR01".to_vec();
        bytes.extend_from_slice(&6_u16.to_be_bytes());
        bytes.extend_from_slice(&[
            40, 10, ORIGINAL_ROOT_INVENTORY_KIND, self.profile as u8, 0, 0,
        ]);
        FixedCapacityBody {
            owner_id: self.owner_id,
            original_owner_cut_digest: self.original_owner_cut_digest,
            operation_id: self.operation_id,
            original_artifact_digest: self.original_artifact_digest,
            admission_owner_mutation_digest: self.admission_owner_mutation_digest,
            admission_native_preservation_union_digest: self
                .admission_native_preservation_union_digest,
            remaining_transactions: self.remaining_transactions,
            remaining_record_frames: self.remaining_record_frames,
            remaining_append_bytes: self.remaining_append_bytes,
            maximum_retained_growth_entries: self.maximum_retained_growth_entries,
            maximum_retained_growth_bytes: self.maximum_retained_growth_bytes,
            admission_transaction: self.admission_transaction,
            remaining_profile_digest: self.remaining_profile_digest,
        }
        .encode_into(&mut bytes);
        bytes
    }
}

/// Retains self-bound query DATA without protected writer or settlement trust.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::journal) struct QueryCapacityRecordV6 {
    data: QueryCapacityDataV6,
    identity: [u8; 32],
}

impl QueryCapacityRecordV6 {
    /// Constructs self-bound DATA from explicit commitments and fixed geometry.
    ///
    /// # Errors
    ///
    /// Rejects any zero binding, noncanonical count/framing/growth geometry,
    /// or unrepresentable profile envelope. Commitments remain opaque input.
    pub(in crate::journal) fn new(data: QueryCapacityDataV6) -> Result<Self, JournalError> {
        data.validate()?;
        let identity = floor_identity(
            &data.identity_payload(),
            IDENTITY_DOMAIN,
            "query identity payload width",
        )?;
        Ok(Self { data, identity })
    }

    /// Returns the exact DATA bindings without proving their preimages.
    #[must_use]
    pub(in crate::journal) const fn data(&self) -> QueryCapacityDataV6 {
        self.data
    }

    /// Returns the version-6 domain-separated self-binding identity.
    #[must_use]
    pub(in crate::journal) const fn reservation_id(&self) -> [u8; 32] {
        self.identity
    }

    /// Encodes canonical Query6 DATA without granting generic admission.
    ///
    /// Global family dispatch recognizes this DATA for accounting; named
    /// authority and owner/reference rejoin remain separately required.
    #[must_use]
    pub(in crate::journal) fn to_journal_record(&self) -> JournalRecord {
        let mut value = self.data.identity_payload();
        value.extend_from_slice(&self.identity);
        JournalRecord::put(
            RecordNamespace::GlobalCapacityReservation,
            reservation_key(self.identity),
            value,
        )
    }

    /// Decodes one exact self-bound query DATA PUT.
    ///
    /// # Errors
    ///
    /// Rejects a foreign namespace, DELETE, wrong header/width/reserved bytes,
    /// unknown kind/profile, zero binding, noncanonical geometry, or substituted
    /// key/domain/identity. Does not validate owner or request preimages.
    pub(in crate::journal) fn from_journal_record(
        record: &JournalRecord,
    ) -> Result<Self, JournalError> {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Self::decode(
            record.key(),
            record.value().ok_or(JournalError::InvalidTransaction)?,
        )
    }

    /// Decodes exact Query6 DATA for canonical family dispatch and accounting.
    ///
    /// Generic admission remains closed; named authority and owner/reference
    /// rejoin are separate from this key/value validation.
    ///
    /// # Errors
    ///
    /// Rejects a wrong envelope, kind/profile, binding, geometry, or identity.
    pub(in crate::journal) fn decode(key: &[u8], value: &[u8]) -> Result<Self, JournalError> {
        if value.len() != VALUE_BYTES
            || &value[..8] != b"AOSJCR01"
            || value[8..12] != [0, 6, 40, 10]
            || value[14..16] != [0; 2]
        {
            return Err(invalid("query capacity envelope"));
        }
        if value[12] != ORIGINAL_ROOT_INVENTORY_KIND {
            return Err(invalid("unknown query capacity kind"));
        }

        let profile = QueryCapacityProfileV6::from_byte(value[13])?;
        let mut offset = 16;
        let body = FixedCapacityBody::decode(value, &mut offset);
        let data = QueryCapacityDataV6 {
            profile,
            owner_id: body.owner_id,
            original_owner_cut_digest: body.original_owner_cut_digest,
            operation_id: body.operation_id,
            original_artifact_digest: body.original_artifact_digest,
            admission_owner_mutation_digest: body.admission_owner_mutation_digest,
            admission_native_preservation_union_digest: body
                .admission_native_preservation_union_digest,
            remaining_transactions: body.remaining_transactions,
            remaining_record_frames: body.remaining_record_frames,
            remaining_append_bytes: body.remaining_append_bytes,
            maximum_retained_growth_entries: body.maximum_retained_growth_entries,
            maximum_retained_growth_bytes: body.maximum_retained_growth_bytes,
            admission_transaction: body.admission_transaction,
            remaining_profile_digest: body.remaining_profile_digest,
        };
        let candidate = take::<32>(value, &mut offset);
        let decoded = Self::new(data)?;
        if candidate != decoded.identity || key != reservation_key(candidate).as_slice() {
            return Err(invalid("query capacity key or identity"));
        }
        Ok(decoded)
    }
}

/// Measures empty owner values, then adds their existing canonical ceilings.
fn framed_envelope_bytes(
    transaction: &JournalTransaction,
    value_bounds: &[usize],
) -> Result<u64, JournalError> {
    value_bounds.iter().try_fold(
        encoded_transaction_append_bytes(transaction)?,
        |total, bound| {
            let bytes = u64::try_from(*bound).map_err(|_| JournalError::JournalTooLarge)?;
            total.checked_add(bytes).ok_or(JournalError::JournalTooLarge)
        },
    )
}

fn validate_envelope_limits(
    transaction: &JournalTransaction,
    owner_bounds: &[usize],
    limits: JournalLimits,
) -> Result<(), JournalError> {
    if transaction.records().len() > limits.maximum_records_per_transaction {
        return Err(JournalError::LimitExceeded("query promised records per transaction"));
    }
    let mut bounds = owner_bounds.iter();
    let mut total = 0_usize;
    for record in transaction.records() {
        let bound = if record.namespace() == RecordNamespace::MountSourceAcquisition {
            *bounds.next().ok_or_else(|| invalid("query envelope owner bounds"))?
        } else {
            0
        };
        let bytes = encode_record(record)?.len().checked_add(bound)
            .ok_or(JournalError::JournalTooLarge)?;
        if record.key().len() > limits.maximum_key_bytes || bytes > limits.maximum_record_bytes {
            return Err(JournalError::LimitExceeded("query promised record geometry"));
        }
        total = total.checked_add(bytes).ok_or(JournalError::JournalTooLarge)?;
    }
    if bounds.next().is_some() || total > limits.maximum_transaction_bytes {
        return Err(JournalError::LimitExceeded("query promised transaction geometry"));
    }
    Ok(())
}

// These framing templates contain no canonical owner values or valid floor.
// They describe the conservative promised DATA envelope only; they cannot be
// submitted as a validated owner transaction or fund a real writer.
fn status_envelope() -> Result<JournalTransaction, JournalError> {
    JournalTransaction::new(
        [1; 16],
        vec![
            owner_put(provider_attempt_key([1; 32])),
            owner_put(provider_head_key([2; 16], [3; 16])),
            JournalRecord::delete(
                RecordNamespace::GlobalCapacityReservation,
                reservation_key([4; 32]),
            ),
            JournalRecord::put(
                RecordNamespace::GlobalCapacityReservation,
                reservation_key([5; 32]),
                vec![0; VALUE_BYTES],
            ),
        ],
    )
}

fn retained_envelope() -> Result<JournalTransaction, JournalError> {
    JournalTransaction::new(
        [2; 16],
        vec![
            owner_put(provider_attempt_key([1; 32])),
            owner_put(provider_head_key([2; 16], [3; 16])),
            owner_put(provider_attempt_key([6; 32])),
            owner_put(acquisition_key([7; 32])),
            JournalRecord::delete(
                RecordNamespace::GlobalCapacityReservation,
                reservation_key([5; 32]),
            ),
        ],
    )
}

fn owner_put(key: Vec<u8>) -> JournalRecord {
    JournalRecord::put(RecordNamespace::MountSourceAcquisition, key, Vec::new())
}

fn invalid(reason: &'static str) -> JournalError {
    JournalError::MalformedRecord(reason)
}

#[cfg(test)]
mod tests;
