//! Ordinary Root capacity floors as nonauthorizing version-4 DATA.
//!
//! ```text
//! AOSJCR01 | version:u16be=4 | namespace:u8=40 | purpose:u8=10
//! kind:u8 | profile:u8 | reserved[2]=0
//! owner[32] | original_owner_cut[32] | operation[16] | artifact[32]
//! admission_owner_mutation[32] | admission_native_union[32]
//! transactions:u32be | frames:u32be | append:u64be
//! growth_entries:u32be | growth_bytes:u64be
//! admission[16] | remaining_profile[32] | identity[32]
//! ```
//!
//! The exact 300-byte value binds its first 268 bytes using SHA-256 over
//! `aos.journal.root-ordinary-capacity.v4.r1.floor-identity\0`, a big-endian
//! u32 payload length, and those bytes. Its 75-byte key uses the unchanged
//! capacity prefix. Decoding validates syntax and accounting geometry only;
//! supplied commitments do not prove a canonical owner graph, current writer,
//! retained references, installation, settlement, signer, or effect authority.
//! There is no ordinary producer or append exception in this module.

use super::super::{JournalError, JournalRecord, RecordNamespace};
use super::fixed300::{FixedCapacityBody, floor_identity as fixed_floor_identity};
use super::{reservation_key, take};

/// Fixes the exact ordinary floor value width.
pub const ORDINARY_CAPACITY_VALUE_BYTES_V4: usize = 300;

const IDENTITY_DOMAIN: &[u8] = b"aos.journal.root-ordinary-capacity.v4.r1.floor-identity\0";

/// Names one closed ordinary operation as DATA, without admitting its producer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OrdinaryCapacityKindV4 {
    /// Installs a successor idle Session.
    IdleReplacement = 1,
    /// Installs a successor Session with a barrier witness.
    BarrierIdleReplacement = 2,
    /// Supersedes an acquisition-owned backend Attempt.
    BackendRecoveryReplacement = 3,
    /// Supersedes an Inventory Attempt.
    InventoryReplacement = 4,
    /// Abandons the original dead Attempt.
    DeadReplacement = 5,
    /// Retains an original ordinary Inventory query.
    OrdinaryInventory = 6,
    /// Retains an original recovery Inventory query.
    RecoveryInventory = 7,
    /// Records Acquisition descriptor custody.
    DescriptorCustody = 8,
    /// Records Acquisition activation.
    Activation = 9,
    /// Records the full four-namespace Consumption edge.
    Consumption = 10,
    /// Records Acquisition release completion.
    FinishRelease = 11,
    /// Retains an original Release Attempt and its cleanup obligation.
    ReleaseRequest = 12,
}

impl OrdinaryCapacityKindV4 {
    fn from_byte(value: u8) -> Result<Self, JournalError> {
        match value {
            1 => Ok(Self::IdleReplacement),
            2 => Ok(Self::BarrierIdleReplacement),
            3 => Ok(Self::BackendRecoveryReplacement),
            4 => Ok(Self::InventoryReplacement),
            5 => Ok(Self::DeadReplacement),
            6 => Ok(Self::OrdinaryInventory),
            7 => Ok(Self::RecoveryInventory),
            8 => Ok(Self::DescriptorCustody),
            9 => Ok(Self::Activation),
            10 => Ok(Self::Consumption),
            11 => Ok(Self::FinishRelease),
            12 => Ok(Self::ReleaseRequest),
            _ => Err(invalid("unknown ordinary capacity kind")),
        }
    }

    fn permits(self, profile: OrdinaryCapacityProfileV4) -> bool {
        use OrdinaryCapacityProfileV4 as Profile;

        match self {
            Self::OrdinaryInventory | Self::RecoveryInventory => {
                profile == Profile::InventoryResponse
            }
            Self::ReleaseRequest => matches!(
                profile,
                Profile::ReleaseOutcomeAndNegativeCustody | Profile::ReleaseNegativeCustody
            ),
            Self::IdleReplacement
            | Self::BarrierIdleReplacement
            | Self::BackendRecoveryReplacement
            | Self::InventoryReplacement
            | Self::DeadReplacement
            | Self::DescriptorCustody
            | Self::Activation
            | Self::Consumption
            | Self::FinishRelease => profile == Profile::LocalCommittedReadback,
        }
    }
}

/// Selects one finite remaining suffix as DATA, without a terminal permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OrdinaryCapacityProfileV4 {
    /// Deletes the own floor after independently validated local installation.
    LocalCommittedReadback = 1,
    /// Completes the original Inventory query with its own floor deletion.
    InventoryResponse = 2,
    /// Transfers the original Release floor, then completes negative custody.
    ReleaseOutcomeAndNegativeCustody = 3,
    /// Completes the independently proved Release cleanup suffix.
    ReleaseNegativeCustody = 4,
}

impl OrdinaryCapacityProfileV4 {
    /// Returns the immutable closed transaction count for this profile.
    #[must_use]
    pub const fn remaining_transactions(self) -> u32 {
        match self {
            Self::ReleaseOutcomeAndNegativeCustody => 2,
            Self::LocalCommittedReadback
            | Self::InventoryResponse
            | Self::ReleaseNegativeCustody => 1,
        }
    }

    fn from_byte(value: u8) -> Result<Self, JournalError> {
        match value {
            1 => Ok(Self::LocalCommittedReadback),
            2 => Ok(Self::InventoryResponse),
            3 => Ok(Self::ReleaseOutcomeAndNegativeCustody),
            4 => Ok(Self::ReleaseNegativeCustody),
            _ => Err(invalid("unknown ordinary capacity profile")),
        }
    }
}

/// Retains explicit commitments and conservative remaining accounting DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrdinaryCapacityDataV4 {
    /// Closed operation discriminator, independent of Protocol mutation tags.
    pub kind: OrdinaryCapacityKindV4,
    /// Closed remaining suffix discriminator.
    pub profile: OrdinaryCapacityProfileV4,
    /// Raw typed primary Session, Attempt, or Acquisition ID selected by kind.
    pub owner_id: [u8; 32],
    /// Historical original before/read commitment; never cold currentness.
    pub original_owner_cut_digest: [u8; 32],
    /// Original owner TX for local kinds, immutable request ID for requests.
    pub operation_id: [u8; 16],
    /// Original exact signed-request or complete local-mutation commitment.
    pub original_artifact_digest: [u8; 32],
    /// Complete original owner PUT-map commitment, excluding the floor.
    pub admission_owner_mutation_digest: [u8; 32],
    /// Historical admission union; never a permanent pin on independent floors.
    pub admission_native_preservation_union_digest: [u8; 32],
    /// Complete remaining append count, exactly the selected profile's count.
    pub remaining_transactions: u32,
    /// Conservative aggregate record frames, including every own capacity edge.
    pub remaining_record_frames: u32,
    /// Conservative aggregate fully framed append bytes.
    pub remaining_append_bytes: u64,
    /// Conservative peak positive retained entry growth from a consistent state.
    pub maximum_retained_growth_entries: u32,
    /// Conservative peak positive retained key/value byte growth.
    pub maximum_retained_growth_bytes: u64,
    /// Original actual atomic owner-plus-floor admission TX, never renewed.
    pub admission_transaction: [u8; 16],
    /// Closed reconstructible suffix/reference descriptor commitment.
    pub remaining_profile_digest: [u8; 32],
}

impl OrdinaryCapacityDataV4 {
    fn validate(&self) -> Result<(), JournalError> {
        if !self.kind.permits(self.profile)
            || self.remaining_transactions != self.profile.remaining_transactions()
            || self.owner_id == [0; 32]
            || self.operation_id == [0; 16]
            || self.admission_transaction == [0; 16]
            || self.original_owner_cut_digest == [0; 32]
            || self.original_artifact_digest == [0; 32]
            || self.admission_owner_mutation_digest == [0; 32]
            || self.admission_native_preservation_union_digest == [0; 32]
            || self.remaining_profile_digest == [0; 32]
        {
            return Err(invalid("ordinary capacity bindings or profile"));
        }

        if self.profile == OrdinaryCapacityProfileV4::LocalCommittedReadback {
            if self.operation_id != self.admission_transaction
                || self.remaining_record_frames != 1
                || self.remaining_append_bytes != 338
                || self.maximum_retained_growth_entries != 0
                || self.maximum_retained_growth_bytes != 0
            {
                return Err(invalid("ordinary local readback geometry"));
            }
            return Ok(());
        }

        // Fixed keys include the own DELETE, and Release profile 3 includes
        // the distinct successor's 300-byte value. Future owner values and
        // canonical envelopes require the separate owning producer.
        let (minimum_frames, required_key_and_value_bytes) = match self.profile {
            OrdinaryCapacityProfileV4::InventoryResponse => {
                if self.kind == OrdinaryCapacityKindV4::RecoveryInventory {
                    (4, 291)
                } else {
                    (3, 216)
                }
            }
            OrdinaryCapacityProfileV4::ReleaseOutcomeAndNegativeCustody => (7, 794),
            OrdinaryCapacityProfileV4::ReleaseNegativeCustody => (2, 139),
            OrdinaryCapacityProfileV4::LocalCommittedReadback => {
                return Err(invalid("ordinary profile geometry"));
            }
        };
        let framing_bytes = u64::from(self.remaining_transactions) * 184
            + u64::from(self.remaining_record_frames) * 79
            + required_key_and_value_bytes;
        if self.remaining_record_frames < minimum_frames
            || self.remaining_append_bytes < framing_bytes
            || (self.maximum_retained_growth_entries != 0
                && self.maximum_retained_growth_bytes == 0)
        {
            return Err(invalid("ordinary capacity remaining geometry"));
        }
        Ok(())
    }

    fn identity_payload(&self) -> Vec<u8> {
        let mut bytes = b"AOSJCR01".to_vec();
        bytes.extend_from_slice(&4_u16.to_be_bytes());
        bytes.extend_from_slice(&[40, 10, self.kind as u8, self.profile as u8, 0, 0]);
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

/// Retains a canonical ordinary floor without protected settlement authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrdinaryCapacityRecordV4 {
    data: OrdinaryCapacityDataV4,
    identity: [u8; 32],
}

impl OrdinaryCapacityRecordV4 {
    /// Constructs self-bound DATA from explicit bindings and structural geometry.
    ///
    /// # Errors
    ///
    /// Rejects sentinel bindings, an illegal kind/profile/count, local TX mismatch,
    /// or impossible framing geometry. Does not validate the owner commitments.
    pub fn new(data: OrdinaryCapacityDataV4) -> Result<Self, JournalError> {
        data.validate()?;
        let identity = floor_identity(&data.identity_payload())?;
        Ok(Self { data, identity })
    }

    /// Returns the exact ordinary DATA bindings.
    #[must_use]
    pub const fn data(&self) -> OrdinaryCapacityDataV4 {
        self.data
    }

    /// Returns the R1 domain-separated self-binding identity.
    #[must_use]
    pub const fn reservation_id(&self) -> [u8; 32] {
        self.identity
    }

    /// Encodes floor DATA; generic Journal admission remains closed.
    #[must_use]
    pub fn to_journal_record(&self) -> JournalRecord {
        let mut value = self.data.identity_payload();
        value.extend_from_slice(&self.identity);
        JournalRecord::put(
            RecordNamespace::GlobalCapacityReservation,
            reservation_key(self.identity),
            value,
        )
    }

    /// Decodes an exact self-bound ordinary DATA row.
    ///
    /// # Errors
    ///
    /// Rejects foreign namespace, DELETE, wrong width/version/purpose/owner,
    /// padding/tail, unknown kind/profile, sentinel bindings, invalid geometry,
    /// or substituted key/domain/identity.
    pub fn from_journal_record(record: &JournalRecord) -> Result<Self, JournalError> {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        Self::decode(
            record.key(),
            record.value().ok_or(JournalError::InvalidTransaction)?,
        )
    }

    pub(in crate::journal) fn decode(key: &[u8], value: &[u8]) -> Result<Self, JournalError> {
        if value.len() != ORDINARY_CAPACITY_VALUE_BYTES_V4
            || &value[..8] != b"AOSJCR01"
            || value[8..12] != [0, 4, 40, 10]
            || value[14..16] != [0; 2]
        {
            return Err(invalid("ordinary capacity envelope"));
        }

        let mut offset = 16;
        let kind = OrdinaryCapacityKindV4::from_byte(value[12])?;
        let profile = OrdinaryCapacityProfileV4::from_byte(value[13])?;
        let body = FixedCapacityBody::decode(value, &mut offset);
        let data = OrdinaryCapacityDataV4 {
            kind,
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
            return Err(invalid("ordinary capacity key or identity"));
        }
        Ok(decoded)
    }
}

fn floor_identity(payload: &[u8]) -> Result<[u8; 32], JournalError> {
    fixed_floor_identity(payload, IDENTITY_DOMAIN, "ordinary identity payload width")
}

fn invalid(reason: &'static str) -> JournalError {
    JournalError::MalformedRecord(reason)
}

#[cfg(test)]
mod tests;
