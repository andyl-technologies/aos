//! Native-only capacity record data and complete append geometry.
//!
//! ```text
//! AOSJCR01 | version:u16be=3 | namespace:u8 | purpose:u8 | reserved[2]
//! owner[32] | owner_digest[32] | operation[16] | artifact[32]
//! checkpoint[32] | chain_head[32] | terminal_records:u32be
//! terminal_bytes:u64be | closed_records:u32be | closed_bytes:u64be
//! remaining_transactions:u32be | admission[16] | identity[32]
//! ```
//!
//! Version 3 always carries its count, including one. These plain records and
//! measurements cannot be converted to a legacy prepared reservation, protected
//! journal claim, dispatch permission, or current-owner proof. Actual native
//! owner integration must validate each canonical row graph before using them.

use sha2::{Digest as _, Sha256};

use super::super::{JournalError, JournalRecord, RecordNamespace};
use super::{reservation_key, take};

pub(in crate::journal) use super::family::{require_legacy_owner, require_legacy_transaction};

mod admission;
mod profile;
mod root;

pub use admission::{
    NativeHeldProviderAdmissionDataV3, provider_native_capacity_admission_v3,
    provider_native_capacity_transition_v3,
};
pub use profile::{
    NativeHeldCapacityAppendV3, NativeHeldCapacityChangeV3, NativeHeldCapacityGeometryV3,
    NativeHeldCapacityPathV3, NativeHeldCapacityStepV3, NativeHeldCapacitySuffixV3,
    NativeHeldCapacityUsageV3,
};
pub use root::{
    root_native_capacity_admission_v3, root_native_capacity_append_v3,
    root_native_capacity_transition_v3,
};

/// Fixes the exact native capacity value width, independently of legacy widths.
pub const NATIVE_HELD_CAPACITY_VALUE_BYTES_V3: usize = 266;

const DOMAIN: &[u8] = b"aos.sandbox.journal.global-capacity-reservation.v3\0";

/// Selects the fixed native journal owner without granting an append scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NativeHeldCapacityPurposeV3 {
    /// Root's original native completion and local FD-acceptance journal.
    Root = 8,
    /// Provider's original completion, recovery, and final cleanup journal.
    Provider = 9,
}

impl NativeHeldCapacityPurposeV3 {
    /// Returns the sole owner namespace described by this data profile.
    #[must_use]
    pub const fn owner_namespace(self) -> RecordNamespace {
        match self {
            Self::Root => RecordNamespace::MountSourceAcquisition,
            Self::Provider => RecordNamespace::SourceProviderAuthority,
        }
    }

    /// Returns the native-only maximum remaining transaction count.
    #[must_use]
    pub const fn maximum_future_transactions(self) -> u32 {
        match self {
            Self::Root => 7,
            Self::Provider => 19,
        }
    }

    fn from_byte(value: u8) -> Result<Self, JournalError> {
        match value {
            8 => Ok(Self::Root),
            9 => Ok(Self::Provider),
            _ => Err(invalid("unknown native capacity purpose")),
        }
    }
}

/// Describes a complete remaining native suffix as nonauthorizing record data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeHeldCapacityRequestV3 {
    /// Fixed native owner; it never converts an old no-dispatch lineage.
    pub purpose: NativeHeldCapacityPurposeV3,
    /// Exact stable Mount-attempt or Source acquisition owner identity.
    pub owner_id: [u8; 32],
    /// Commitment to the actual canonical owner before-image.
    pub owner_digest: [u8; 32],
    /// Original operation identity, not a truncated commitment.
    pub operation_id: [u8; 16],
    /// Exact original admitted artifact commitment.
    pub artifact_digest: [u8; 32],
    /// Exact original admission checkpoint commitment.
    pub checkpoint_digest: [u8; 32],
    /// Exact original predecessor or chain-head commitment.
    pub chain_head_digest: [u8; 32],
    /// Remaining complete durable appends, including eventual retirement.
    pub future_transactions: u32,
    /// Aggregate record frames in the complete normal suffix.
    pub terminal_records: u32,
    /// Aggregate fully framed append bytes in the complete normal suffix.
    pub terminal_bytes: u64,
    /// Aggregate record frames in the complete Closed/recovery suffix.
    pub poison_records: u32,
    /// Aggregate fully framed append bytes in the complete Closed/recovery suffix.
    pub poison_bytes: u64,
}

impl NativeHeldCapacityRequestV3 {
    fn validate(&self) -> Result<(), JournalError> {
        if self.owner_id == [0; 32]
            || self.owner_digest == [0; 32]
            || self.operation_id == [0; 16]
            || self.artifact_digest == [0; 32]
            || self.checkpoint_digest == [0; 32]
            || self.chain_head_digest == [0; 32]
            || self.future_transactions == 0
            || self.future_transactions > self.purpose.maximum_future_transactions()
            || self.terminal_records == 0
            || self.terminal_bytes == 0
            || self.poison_records == 0
            || self.poison_bytes == 0
        {
            return Err(invalid("invalid native capacity bindings or budgets"));
        }
        Ok(())
    }
}

/// Retains one canonical native capacity record, without settlement authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHeldCapacityRecordV3 {
    request: NativeHeldCapacityRequestV3,
    admission: [u8; 16],
    identity: [u8; 32],
}

impl NativeHeldCapacityRecordV3 {
    /// Derives complete native budgets from both measured legal continuations.
    ///
    /// The input request supplies immutable DATA bindings only; its count and
    /// record/byte budgets are replaced by measurements of exact owner proposal
    /// bytes. The original owner must independently validate every proposal and
    /// any excluded branch before using this data at a future effect boundary.
    ///
    /// # Errors
    ///
    /// Rejects a foreign owner, wrong continuation classes, invalid bindings,
    /// malformed suffix, or any unchanged journal ceiling violation.
    pub fn from_suffixes(
        mut request: NativeHeldCapacityRequestV3,
        admission: [u8; 16],
        normal: &NativeHeldCapacitySuffixV3,
        closed_or_recovery: &NativeHeldCapacitySuffixV3,
        limits: super::super::JournalLimits,
    ) -> Result<Self, JournalError> {
        if normal.purpose() != request.purpose
            || closed_or_recovery.purpose() != request.purpose
            || normal.path() != NativeHeldCapacityPathV3::Normal
            || closed_or_recovery.path() == NativeHeldCapacityPathV3::Normal
        {
            return Err(invalid("native capacity owner or continuation classes"));
        }
        let terminal = normal.measure(limits)?;
        let poison = closed_or_recovery.measure(limits)?;
        request.future_transactions = terminal.transactions.max(poison.transactions);
        request.terminal_records = terminal.records;
        request.terminal_bytes = terminal.append_bytes;
        request.poison_records = poison.records;
        request.poison_bytes = poison.append_bytes;
        Self::new(request, admission)
    }

    /// Constructs canonical data after checking the closed native bindings.
    ///
    /// # Errors
    ///
    /// Rejects zero bindings, a zero admission ID, empty budgets, or a count
    /// outside this native owner's range. It does not validate an owner graph.
    pub fn new(
        request: NativeHeldCapacityRequestV3,
        admission: [u8; 16],
    ) -> Result<Self, JournalError> {
        request.validate()?;
        if admission == [0; 16] {
            return Err(invalid("zero native capacity admission"));
        }
        let identity = identity(&request, admission);
        Ok(Self {
            request,
            admission,
            identity,
        })
    }

    /// Returns the exact native-only plain request.
    #[must_use]
    pub const fn request(&self) -> NativeHeldCapacityRequestV3 {
        self.request
    }

    /// Returns the original admission transaction identity.
    #[must_use]
    pub const fn admission_transaction_id(&self) -> [u8; 16] {
        self.admission
    }

    /// Returns the version-3 domain-separated record identity.
    #[must_use]
    pub const fn reservation_id(&self) -> [u8; 32] {
        self.identity
    }

    /// Encodes ordinary record data; no live journal method accepts it as a permit.
    #[must_use]
    pub fn to_journal_record(&self) -> JournalRecord {
        let mut value = b"AOSJCR01".to_vec();
        value.extend_from_slice(&3_u16.to_be_bytes());
        value.extend_from_slice(&[
            self.request.purpose.owner_namespace() as u8,
            self.request.purpose as u8,
        ]);
        value.extend_from_slice(&[0; 2]);
        value.extend_from_slice(&binding_bytes(&self.request));
        value.extend_from_slice(&self.admission);
        value.extend_from_slice(&self.identity);
        JournalRecord::put(
            RecordNamespace::GlobalCapacityReservation,
            reservation_key(self.identity),
            value,
        )
    }

    /// Decodes exact version-3 record data with its original key and identity.
    ///
    /// # Errors
    ///
    /// Rejects another namespace, deletion, wrong version/width/padding,
    /// substituted key/identity, invalid bindings, or an out-of-range count.
    pub fn from_journal_record(record: &JournalRecord) -> Result<Self, JournalError> {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let value = record.value().ok_or(JournalError::InvalidTransaction)?;
        Self::decode(record.key(), value)
    }

    pub(super) fn decode(key: &[u8], value: &[u8]) -> Result<Self, JournalError> {
        if value.len() != NATIVE_HELD_CAPACITY_VALUE_BYTES_V3
            || &value[..8] != b"AOSJCR01"
            || value[8..10] != 3_u16.to_be_bytes()
            || value[12..14] != [0; 2]
        {
            return Err(invalid("invalid native capacity envelope"));
        }
        let purpose = NativeHeldCapacityPurposeV3::from_byte(value[11])?;
        if value[10] != purpose.owner_namespace() as u8 {
            return Err(invalid("native capacity owner namespace"));
        }
        let mut offset = 14;
        let request = NativeHeldCapacityRequestV3 {
            purpose,
            owner_id: take::<32>(value, &mut offset),
            owner_digest: take::<32>(value, &mut offset),
            operation_id: take::<16>(value, &mut offset),
            artifact_digest: take::<32>(value, &mut offset),
            checkpoint_digest: take::<32>(value, &mut offset),
            chain_head_digest: take::<32>(value, &mut offset),
            terminal_records: u32::from_be_bytes(take::<4>(value, &mut offset)),
            terminal_bytes: u64::from_be_bytes(take::<8>(value, &mut offset)),
            poison_records: u32::from_be_bytes(take::<4>(value, &mut offset)),
            poison_bytes: u64::from_be_bytes(take::<8>(value, &mut offset)),
            future_transactions: u32::from_be_bytes(take::<4>(value, &mut offset)),
        };
        let admission = take::<16>(value, &mut offset);
        let candidate = take::<32>(value, &mut offset);
        let decoded = Self::new(request, admission)?;
        if candidate != decoded.identity || key != reservation_key(candidate).as_slice() {
            return Err(invalid("native capacity key or identity"));
        }
        Ok(decoded)
    }
}

fn binding_bytes(request: &NativeHeldCapacityRequestV3) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(204);
    bytes.extend_from_slice(&request.owner_id);
    bytes.extend_from_slice(&request.owner_digest);
    bytes.extend_from_slice(&request.operation_id);
    bytes.extend_from_slice(&request.artifact_digest);
    bytes.extend_from_slice(&request.checkpoint_digest);
    bytes.extend_from_slice(&request.chain_head_digest);
    bytes.extend_from_slice(&request.terminal_records.to_be_bytes());
    bytes.extend_from_slice(&request.terminal_bytes.to_be_bytes());
    bytes.extend_from_slice(&request.poison_records.to_be_bytes());
    bytes.extend_from_slice(&request.poison_bytes.to_be_bytes());
    bytes.extend_from_slice(&request.future_transactions.to_be_bytes());
    bytes
}

fn identity(request: &NativeHeldCapacityRequestV3, admission: [u8; 16]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update([
        request.purpose as u8,
        request.purpose.owner_namespace() as u8,
    ]);
    digest.update(binding_bytes(request));
    digest.update(admission);
    digest.finalize().into()
}

fn invalid(reason: &'static str) -> JournalError {
    JournalError::MalformedRecord(reason)
}

#[cfg(test)]
mod tests;
