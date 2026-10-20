//! Owns the shared historical lifecycle Effect receipt grammar.
//!
//! ```text
//! AOSLIF01 | public-operation:16 | Source-lifecycle-record:32
//! AOSLIF04 | V1-fields-without-magic:48 | QuiescentIncomplete:424
//! AOSLIF02 | V1-fields-without-magic:48 | publication-operation:16 |
//!           applied-child-Effect:32 | typed-resource-set:32 | Root6-receipt:380
//! ```
//!
//! These are comparison bytes inside an Effect receipt, not Source lifecycle
//! record formats or native completion grants. Native callers separately prove
//! the actual applied workspace child, complete Source terminal, same original
//! Root6/C10/U, currentness, and atomic public STOPPED terminal transition.

use aos_sandbox_core::{ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

use super::EffectHistoryDataError;
use crate::domain_ledger::create_storage_history::continuation::{
    ContinuationKindV1, ContinuationNativeReceiptDataV1,
};
use crate::domain_ledger::provisioning_resources::{
    ProvisioningModeDataV1, ProvisioningResourceRecordsV1,
};

const ORDINARY_MAGIC: &[u8; 8] = b"AOSLIF01";
const STOP_RESIDUAL_MAGIC: &[u8; 8] = b"AOSLIF04";
const CREATE_MAGIC: &[u8; 8] = b"AOSLIF02";
/// Gives the unchanged ordinary lifecycle Effect receipt extent.
pub const LIFECYCLE_EFFECT_RECEIPT_BYTES_V1: usize = 8 + 16 + 32;
/// Gives the complete Create STOPPED receipt, including its actual Root6 return.
pub const CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1: usize =
    LIFECYCLE_EFFECT_RECEIPT_BYTES_V1 + 16 + 32 + 32 + ContinuationKindV1::Closed.receipt_bytes();
/// Bounds the purpose-closed Stop residual comparison receipt.
pub const STOP_RESIDUAL_LIFECYCLE_RECEIPT_BYTES_V4: usize =
    LIFECYCLE_EFFECT_RECEIPT_BYTES_V1
        + crate::storage_capture_session::stop_cleanup::CAPTURE_STOP_RECEIPT_BYTES_V4;

/// Carries historical Stop residual DATA without granting native completion.
#[derive(Clone, Copy)]
pub struct StopResidualLifecycleReceiptDataV4 {
    operation: OperationId,
    source: ObjectDigest,
    residual: crate::storage_capture_session::stop_cleanup::CaptureQuiescentIncompleteReceiptDataV4,
}

impl StopResidualLifecycleReceiptDataV4 {
    /// Returns the original public Stop identity.
    #[must_use]
    pub const fn operation_v4(self) -> OperationId { self.operation }

    /// Returns the exact protected Source residual record commitment.
    #[must_use]
    pub const fn source_v4(self) -> ObjectDigest { self.source }

    /// Borrows the canonical native-result comparison DATA.
    #[must_use]
    pub const fn residual_v4(&self)
        -> &crate::storage_capture_session::stop_cleanup::CaptureQuiescentIncompleteReceiptDataV4 {
        &self.residual
    }
}

/// Encodes the closed Stop residual comparison shape without granting completion.
///
/// Actual emitters require the opaque current Source residual witness and all
/// native/currentness posts; these supplied DATA alone authorize no append.
///
/// # Errors
/// Refuses sentinel operation/Source commitments or noncanonical receipt DATA.
pub fn encode_stop_residual_lifecycle_receipt_v4(operation: OperationId, source: ObjectDigest,
    residual: &crate::storage_capture_session::stop_cleanup::CaptureQuiescentIncompleteReceiptDataV4,
) -> Result<[u8; STOP_RESIDUAL_LIFECYCLE_RECEIPT_BYTES_V4], EffectHistoryDataError> {
    if operation.as_bytes() == &[0; 16] || source.as_bytes() == &[0; 32] {
        return Err(invalid());
    }
    let mut bytes = [0; STOP_RESIDUAL_LIFECYCLE_RECEIPT_BYTES_V4];
    bytes[..8].copy_from_slice(STOP_RESIDUAL_MAGIC);
    bytes[8..24].copy_from_slice(operation.as_bytes());
    bytes[24..56].copy_from_slice(source.as_bytes());
    bytes[56..].copy_from_slice(residual.canonical_bytes_v4());
    Ok(bytes)
}

const ROOT_OFFSET: usize = LIFECYCLE_EFFECT_RECEIPT_BYTES_V1 + 16 + 32 + 32;

/// Encodes the unchanged ordinary receipt without adding validation or authority.
#[must_use]
pub fn encode_lifecycle_effect_receipt_v1(operation: OperationId, source: ObjectDigest)
    -> [u8; LIFECYCLE_EFFECT_RECEIPT_BYTES_V1]
{
    let mut bytes = [0; LIFECYCLE_EFFECT_RECEIPT_BYTES_V1];
    bytes[..8].copy_from_slice(ORDINARY_MAGIC);
    bytes[8..24].copy_from_slice(operation.as_bytes());
    bytes[24..].copy_from_slice(source.as_bytes());
    bytes
}

/// Commits complete canonical child Effect bytes without claiming they applied.
///
/// Native producers and cold validators must independently decode the same
/// actual child, require its original Apply plan and successful stored outcome,
/// and bind the exact internal operation before comparing this commitment.
#[must_use]
pub fn lifecycle_child_effect_commitment_v1(encoded: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::new()
        .chain_update(b"aos.sandbox.lifecycle.applied-child-effect.v1\0")
        .chain_update(encoded).finalize().into())
}

/// Borrows the complete Create-specific historical relation without native rights.
#[derive(Clone, Copy)]
pub struct CreateStoppedLifecycleReceiptDataV1<'bytes> {
    operation: OperationId,
    source: ObjectDigest,
    publication_operation: OperationId,
    child_effect: ObjectDigest,
    resources: ObjectDigest,
    root_closed: ContinuationNativeReceiptDataV1<'bytes>,
}

impl<'bytes> CreateStoppedLifecycleReceiptDataV1<'bytes> {
    /// Binds actual typed resource DATA and a strict Root6 receipt shape.
    ///
    /// # Errors
    /// Refuses another mode/parent, zero commitments, or malformed Root6 DATA.
    pub fn from_data_v1(operation: OperationId, source: ObjectDigest,
        child_effect: ObjectDigest, resources: ProvisioningResourceRecordsV1,
        root_closed: ContinuationNativeReceiptDataV1<'bytes>, lane: [u8; 16],
    ) -> Result<Self, EffectHistoryDataError> {
        let fields = resources.fields_v1();
        if fields.mode != ProvisioningModeDataV1::CreateStopped || fields.parent != operation {
            return Err(invalid());
        }
        let value = Self { operation, source, publication_operation: fields.publication_operation,
            child_effect, resources: resources.commitment_v1(), root_closed };
        value.require_shape_v1(lane)?;
        Ok(value)
    }

    fn require_shape_v1(&self, lane: [u8; 16]) -> Result<(), EffectHistoryDataError> {
        if self.operation.as_bytes() == &[0; 16]
            || self.publication_operation.as_bytes() == &[0; 16]
            || self.operation == self.publication_operation
            || [self.source, self.child_effect, self.resources].iter()
                .any(|digest| digest.as_bytes() == &[0; 32]) {
            return Err(invalid());
        }
        self.root_closed.record_data(lane, ContinuationKindV1::Closed)
            .map_err(|_| invalid())?;
        Ok(())
    }

    /// Encodes this fixed receipt through the same Root continuation codec.
    ///
    /// # Errors
    /// Refuses inconsistent fields, another lane, or malformed Root6 DATA.
    pub fn encode_v1(&self, lane: [u8; 16])
        -> Result<[u8; CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1], EffectHistoryDataError>
    {
        self.require_shape_v1(lane)?;
        let mut bytes = [0; CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1];
        bytes[..8].copy_from_slice(CREATE_MAGIC);
        bytes[8..24].copy_from_slice(self.operation.as_bytes());
        bytes[24..56].copy_from_slice(self.source.as_bytes());
        bytes[56..72].copy_from_slice(self.publication_operation.as_bytes());
        bytes[72..104].copy_from_slice(self.child_effect.as_bytes());
        bytes[104..ROOT_OFFSET].copy_from_slice(self.resources.as_bytes());
        self.root_closed.encode_into(lane, ContinuationKindV1::Closed, &mut bytes[ROOT_OFFSET..])
            .map_err(|_| invalid())?;
        Ok(bytes)
    }

    /// Requires the same complete typed three-resource relation.
    ///
    /// # Errors
    /// Refuses another mode, public/internal operation, or any companion field.
    pub fn require_resources_v1(&self, resources: ProvisioningResourceRecordsV1)
        -> Result<(), EffectHistoryDataError>
    {
        let fields = resources.fields_v1();
        if fields.mode != ProvisioningModeDataV1::CreateStopped
            || fields.parent != self.operation
            || fields.publication_operation != self.publication_operation
            || resources.commitment_v1() != self.resources {
            return Err(invalid());
        }
        Ok(())
    }

    /// Returns the original public operation comparison identity.
    #[must_use]
    pub const fn operation_v1(self) -> OperationId { self.operation }
    /// Returns the terminal Source lifecycle record commitment.
    #[must_use]
    pub const fn source_v1(self) -> ObjectDigest { self.source }
    /// Returns the distinct internal workspace publication operation.
    #[must_use]
    pub const fn publication_operation_v1(self) -> OperationId { self.publication_operation }
    /// Returns the exact encoded applied child Effect commitment.
    #[must_use]
    pub const fn child_effect_v1(self) -> ObjectDigest { self.child_effect }
    /// Borrows the original strict Root6 receipt DATA.
    #[must_use]
    pub const fn root_closed_v1(self) -> ContinuationNativeReceiptDataV1<'bytes> { self.root_closed }
}

/// Distinguishes unchanged ordinary history from a complete Create relation.
#[derive(Clone, Copy)]
pub enum LifecycleEffectReceiptDataV1<'bytes> {
    /// Carries ordinary operation and Source-record comparison commitments.
    Ordinary {
        /// The public operation identity.
        operation: OperationId,
        /// The terminal Source lifecycle record digest.
        source: ObjectDigest,
    },
    /// Carries the complete Create STOPPED comparison relation.
    CreateStopped(CreateStoppedLifecycleReceiptDataV1<'bytes>),
    /// Carries incomplete Capture cleanup after genuine stopped containment.
    StopResidual(StopResidualLifecycleReceiptDataV4),
}

/// Borrows either closed receipt grammar without decoding another native format.
///
/// # Errors
/// Rejects an unknown magic/extent, noncanonical Create fields, or any Root6
/// lane, body, head, position or checksum substitution. Ordinary bytes preserve
/// their original grammar; Native callers still check their actual association.
pub fn decode_lifecycle_effect_receipt_v1(bytes: &[u8], lane: [u8; 16])
    -> Result<LifecycleEffectReceiptDataV1<'_>, EffectHistoryDataError>
{
    if bytes.len() == LIFECYCLE_EFFECT_RECEIPT_BYTES_V1 && bytes.get(..8) == Some(ORDINARY_MAGIC) {
        return Ok(LifecycleEffectReceiptDataV1::Ordinary {
            operation: OperationId::from_bytes(array(&bytes[8..24])?),
            source: ObjectDigest::from_bytes(array(&bytes[24..56])?),
        });
    }
    if bytes.len() == STOP_RESIDUAL_LIFECYCLE_RECEIPT_BYTES_V4
        && bytes.get(..8) == Some(STOP_RESIDUAL_MAGIC) {
        let operation = OperationId::from_bytes(array(&bytes[8..24])?);
        let source = ObjectDigest::from_bytes(array(&bytes[24..56])?);
        if operation.as_bytes() == &[0; 16] || source.as_bytes() == &[0; 32] { return Err(invalid()); }
        let residual = crate::storage_capture_session::stop_cleanup::CaptureQuiescentIncompleteReceiptDataV4::decode_v4(
            &bytes[56..],
        ).map_err(|_| invalid())?;
        return Ok(LifecycleEffectReceiptDataV1::StopResidual(StopResidualLifecycleReceiptDataV4 {
            operation, source, residual,
        }));
    }
    if bytes.len() != CREATE_STOPPED_LIFECYCLE_RECEIPT_BYTES_V1
        || bytes.get(..8) != Some(CREATE_MAGIC) {
        return Err(invalid());
    }
    let value = CreateStoppedLifecycleReceiptDataV1 {
        operation: OperationId::from_bytes(array(&bytes[8..24])?),
        source: ObjectDigest::from_bytes(array(&bytes[24..56])?),
        publication_operation: OperationId::from_bytes(array(&bytes[56..72])?),
        child_effect: ObjectDigest::from_bytes(array(&bytes[72..104])?),
        resources: ObjectDigest::from_bytes(array(&bytes[104..ROOT_OFFSET])?),
        root_closed: ContinuationNativeReceiptDataV1::decode(&bytes[ROOT_OFFSET..], lane,
            ContinuationKindV1::Closed).map_err(|_| invalid())?,
    };
    value.require_shape_v1(lane)?;
    Ok(LifecycleEffectReceiptDataV1::CreateStopped(value))
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], EffectHistoryDataError> {
    bytes.try_into().map_err(|_| invalid())
}

fn invalid() -> EffectHistoryDataError {
    EffectHistoryDataError::CorruptLedger("invalid lifecycle Effect receipt")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_core::{AssignmentEpoch, ProjectId, ResourceId, Revision, SandboxId};
    use crate::domain_ledger::create_storage_history::{
        KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordCoordinatesV1, RecordEnvelopeV1,
    };
    use crate::domain_ledger::create_storage_history::outcome::RootClosedBodyDataV1;
    use crate::domain_ledger::protected_names::ProtectedJournalNamesV1;
    use crate::domain_ledger::provisioning_resources::ProvisioningResourceFieldsV1;

    const LANE: [u8; 16] = [1; 16];

    fn resources() -> ProvisioningResourceRecordsV1 {
        ProvisioningResourceRecordsV1::from_data_v1(ProvisioningResourceFieldsV1 {
            mode: ProvisioningModeDataV1::CreateStopped,
            parent: OperationId::from_bytes([2; 16]),
            publication_operation: OperationId::from_bytes([3; 16]),
            sandbox: SandboxId::from_bytes([4; 16]), project: ProjectId::from_bytes([5; 16]),
            assignment: ResourceId::from_bytes([6; 16]), reservation: ResourceId::from_bytes([7; 16]),
            epoch: AssignmentEpoch::new(1), reservation_revision: Revision::new(1),
            public_request: ObjectDigest::from_bytes([8; 32]), manifest: ObjectDigest::from_bytes([9; 32]),
            source_draft: ObjectDigest::from_bytes([10; 32]), root_plan: ObjectDigest::from_bytes([11; 32]),
            child_head: ObjectDigest::from_bytes([12; 32]), inclusive_grant: ObjectDigest::from_bytes([13; 32]),
        }).unwrap()
    }

    // Only inert canonical bytes are manufactured here. No bank, Native
    // owner, Session or currentness result is constructed by these fixtures.
    fn root_receipt() -> Vec<u8> {
        let kind = ContinuationKindV1::Closed;
        let mut record = vec![0; kind.record_bytes()];
        let body = RootClosedBodyDataV1 { handoff_retained: [14; 32], source_released: [15; 32],
            cache_released: [16; 32], committed_use_claim: [17; 32] }.encode().unwrap();
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key: KeyV1::new(LANE, OwnerV1::Root, 6).unwrap(),
            phase: PhaseV1::new(OwnerV1::Root, 6).unwrap(),
            predecessor: [18; 32], correlation: [19; 32],
        }, &body, &mut record).unwrap();
        let receipt = ContinuationNativeReceiptDataV1 {
            record: &record, latest_head: LatestHeadV1::new(6, checksum).unwrap().encode(),
            names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            after_next: 100, after_end: 2000,
        };
        let mut bytes = vec![0; kind.receipt_bytes()];
        receipt.encode_into(LANE, kind, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn ordinary_receipt_keeps_every_original_byte() {
        let operation = OperationId::from_bytes([0; 16]);
        let source = ObjectDigest::from_bytes([0; 32]);
        let expected = [b"AOSLIF01".as_slice(), operation.as_bytes(), source.as_bytes()].concat();

        let encoded = encode_lifecycle_effect_receipt_v1(operation, source);

        assert_eq!(encoded.as_slice(), expected);
        assert!(matches!(decode_lifecycle_effect_receipt_v1(&encoded, LANE).unwrap(),
            LifecycleEffectReceiptDataV1::Ordinary { operation: actual, source: digest }
                if actual == operation && digest == source));
    }

    #[test]
    fn create_receipt_borrows_root6_and_binds_every_resource_companion() {
        let root_bytes = root_receipt();
        let root = ContinuationNativeReceiptDataV1::decode(&root_bytes, LANE,
            ContinuationKindV1::Closed).unwrap();
        let records = resources();
        let receipt = CreateStoppedLifecycleReceiptDataV1::from_data_v1(
            records.fields_v1().parent, ObjectDigest::from_bytes([20; 32]),
            lifecycle_child_effect_commitment_v1(b"actual applied Effect"), records, root, LANE,
        ).unwrap();
        let bytes = receipt.encode_v1(LANE).unwrap();
        assert_eq!(bytes.len(), 516);

        let LifecycleEffectReceiptDataV1::CreateStopped(decoded) =
            decode_lifecycle_effect_receipt_v1(&bytes, LANE).unwrap() else { panic!("wrong kind") };

        decoded.require_resources_v1(records).unwrap();
        assert_eq!(decoded.root_closed_v1().record.as_ptr(), bytes[ROOT_OFFSET..].as_ptr());
        assert_eq!(decoded.encode_v1(LANE).unwrap(), bytes);
        let mut fields = records.fields_v1();
        fields.reservation = ResourceId::from_bytes([21; 16]);
        let substituted = ProvisioningResourceRecordsV1::from_data_v1(fields).unwrap();
        assert!(decoded.require_resources_v1(substituted).is_err());
        fields = records.fields_v1();
        fields.mode = ProvisioningModeDataV1::StartRunning;
        let substituted = ProvisioningResourceRecordsV1::from_data_v1(fields).unwrap();
        assert!(CreateStoppedLifecycleReceiptDataV1::from_data_v1(
            fields.parent, ObjectDigest::from_bytes([20; 32]), decoded.child_effect_v1(),
            substituted, root, LANE).is_err());

        for end in 0..bytes.len() {
            assert!(decode_lifecycle_effect_receipt_v1(&bytes[..end], LANE).is_err());
        }
        assert!(decode_lifecycle_effect_receipt_v1(&bytes, [22; 16]).is_err());
        let mut changed = bytes;
        changed[ROOT_OFFSET + ContinuationKindV1::Closed.record_bytes() - 1] ^= 1;
        assert!(decode_lifecycle_effect_receipt_v1(&changed, LANE).is_err());
    }

    #[test]
    fn child_commitment_covers_the_complete_encoded_effect() {
        let original = lifecycle_child_effect_commitment_v1(b"plan|dispatch|actual Applied receipt");

        assert_ne!(original, lifecycle_child_effect_commitment_v1(b"plan|dispatch|other receipt"));
        assert_ne!(original, lifecycle_child_effect_commitment_v1(b"other plan|dispatch|actual Applied receipt"));
    }
}

#[cfg(test)]
mod stop_residual_tests;
