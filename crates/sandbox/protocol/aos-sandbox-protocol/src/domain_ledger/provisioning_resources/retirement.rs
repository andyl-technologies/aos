//! Describes one closed Delete retirement of the three real companion rows.
//!
//! This is passive bounded DATA. Both logical Other IDs, all original keys and
//! values and the exact parent lookup derive from the sole original codec.
//! Actual accepted Delete/C17/Source/Root/native completion remains upper.
//!
//! ```text
//! AOSPCD02 | canonical-original-Parent346 | Delete-operation16 |
//!           batch-transaction16 | domain-checksum32
//! ```

use super::*;
use super::super::lifecycle_model::LifecycleResourceV1;

const DESCRIPTOR_MAGIC: &[u8; 8] = b"AOSPCD02";
const DESCRIPTOR_DOMAIN: &[u8] = b"aos.sandbox.provisioning-companion-delete.v2\0";
/// Gives the exact width of one complete original three-row retirement descriptor.
pub const PROVISIONING_COMPANION_DESCRIPTOR_BYTES_V2: usize =
    8 + PROVISIONING_RESOURCE_ROW_BYTES_V1 + 16 + 16 + 32;
const OPERATION_OFFSET: usize = 8 + PROVISIONING_RESOURCE_ROW_BYTES_V1;
const TRANSACTION_OFFSET: usize = OPERATION_OFFSET + 16;
const CHECKSUM_OFFSET: usize = TRANSACTION_OFFSET + 16;

/// Reports noncanonical or incomplete passive companion retirement DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProvisioningCompanionRetirementErrorV2 {
    /// The fixed shape, checksum, identities or batch context differs.
    #[error("provisioning companion retirement is not canonical")]
    NonCanonical,
    /// The exact original live companion set is absent or differs.
    #[error(transparent)]
    Original(#[from] ProvisioningResourceDataErrorV1),
}

/// Describes retirement of exactly one original parent/assignment/reservation set.
///
/// This value contains no native completion or journal authority. It cannot
/// supply arbitrary extra rows, a bank identity or another resource family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProvisioningCompanionRetirementDataV2 {
    original: ProvisioningResourceRecordsV1,
    operation: OperationId,
    transaction: [u8; 16],
}

impl ProvisioningCompanionRetirementDataV2 {
    /// Binds an already canonical original set to one Delete batch's identities.
    ///
    /// # Errors
    /// Refuses zero identities or reuse of either original operation identity.
    pub fn from_data_v2(
        original: ProvisioningResourceRecordsV1,
        operation: OperationId,
        transaction: [u8; 16],
    ) -> Result<Self, ProvisioningCompanionRetirementErrorV2> {
        let fields = original.fields_v1();
        if operation.as_bytes() == &[0; 16] || transaction == [0; 16]
            || operation == fields.parent || operation == fields.publication_operation
        {
            return Err(ProvisioningCompanionRetirementErrorV2::NonCanonical);
        }
        Ok(Self { original, operation, transaction })
    }

    /// Borrows the exact canonical original set as nonauthorizing comparison DATA.
    #[must_use]
    pub const fn original_v1(self) -> ProvisioningResourceRecordsV1 { self.original }

    /// Returns the actual batch operation comparison identity.
    #[must_use]
    pub const fn operation_v2(self) -> OperationId { self.operation }

    /// Returns the batch transaction comparison identity.
    #[must_use]
    pub const fn transaction_v2(self) -> [u8; 16] { self.transaction }

    /// Returns both real logical resource identities in their fixed kind order.
    #[must_use]
    pub fn resources_v2(self) -> [LifecycleResourceV1; 2] {
        let fields = self.original.fields_v1();
        [LifecycleResourceV1::Other(fields.assignment), LifecycleResourceV1::Other(fields.reservation)]
    }

    /// Requires the exact original three live rows from the protected predecessor.
    ///
    /// # Errors
    /// Refuses missing, substituted, retired or partially replaced companions.
    pub fn require_original_state_v2(self, state: &State)
        -> Result<(), ProvisioningCompanionRetirementErrorV2>
    {
        self.original.require_companions_v1(state).map_err(Into::into)
    }

    /// Encodes the bounded descriptor through the sole original row codec.
    #[must_use]
    pub fn encode_v2(self) -> [u8; PROVISIONING_COMPANION_DESCRIPTOR_BYTES_V2] {
        let mut bytes = [0; PROVISIONING_COMPANION_DESCRIPTOR_BYTES_V2];
        bytes[..8].copy_from_slice(DESCRIPTOR_MAGIC);
        bytes[8..OPERATION_OFFSET].copy_from_slice(
            &self.original.encode_v1(ProvisioningResourceRowKindV1::Parent));
        bytes[OPERATION_OFFSET..TRANSACTION_OFFSET].copy_from_slice(self.operation.as_bytes());
        bytes[TRANSACTION_OFFSET..CHECKSUM_OFFSET].copy_from_slice(&self.transaction);
        let checksum = descriptor_checksum_v2(&bytes[..CHECKSUM_OFFSET]);
        bytes[CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        bytes
    }

    /// Decodes one complete bounded descriptor without allocating.
    ///
    /// # Errors
    /// Refuses malformed extents, checksum, original row, keys or operation context.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, ProvisioningCompanionRetirementErrorV2> {
        if bytes.len() != PROVISIONING_COMPANION_DESCRIPTOR_BYTES_V2
            || &bytes[..8] != DESCRIPTOR_MAGIC
            || bytes[CHECKSUM_OFFSET..] != descriptor_checksum_v2(&bytes[..CHECKSUM_OFFSET])
        {
            return Err(ProvisioningCompanionRetirementErrorV2::NonCanonical);
        }
        let (kind, original) = decode_original_value_v1(&bytes[8..OPERATION_OFFSET])?;
        if kind != ProvisioningResourceRowKindV1::Parent {
            return Err(ProvisioningCompanionRetirementErrorV2::NonCanonical);
        }
        Self::from_data_v2(original,
            OperationId::from_bytes(fixed(&bytes[OPERATION_OFFSET..TRANSACTION_OFFSET])?),
            fixed(&bytes[TRANSACTION_OFFSET..CHECKSUM_OFFSET])?)
    }
}

fn descriptor_checksum_v2(bytes: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update(DESCRIPTOR_DOMAIN).chain_update(bytes).finalize().into()
}
