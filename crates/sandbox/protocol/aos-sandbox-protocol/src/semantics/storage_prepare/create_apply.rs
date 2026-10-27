//! Derives the separate Create Apply meaning from original Prepare inputs.
//!
//! The broker-minted catalog and exact assignment/specification bytes join the
//! original requested quota through the existing Storage semantic encoder.
//! The output is unsigned comparison DATA, never Apply or dispatch authority.

use aos_sandbox_api::aos::sandbox::local::v1::{
    ApplyStorageRequest, AssignmentFence, Audience, RequestHeader, StorageAction,
};
use aos_sandbox_model::{BrokerArgumentCommitment, BrokerAssignment, OperationId};
use buffa::Message as _;

use super::ProtectedStorageCreatePreparationV1;
use crate::semantics::{CatalogBindingV1, StorageOperation, StorageSemanticsError};

/// Borrows the original Create operands for independently authorized Apply.
///
/// Construction validates portable semantics only. The issuer must retain the
/// actual authenticated Prepare, verify its catalog and unchanged expiry, fund
/// all construction, and authorize this distinct method before any signing or
/// native effect. Neither this type nor its canonical bytes supplies that grant.
#[derive(Clone, Copy)]
pub struct ProtectedStorageCreateApplyDataV1<'original> {
    preparation: &'original ProtectedStorageCreatePreparationV1,
    catalog: CatalogBindingV1,
    assignment_manifest: &'original [u8],
    sandbox_spec: &'original [u8],
    commitment: BrokerArgumentCommitment,
}

impl<'original> ProtectedStorageCreateApplyDataV1<'original> {
    /// Returns the exact deadline-free Create Apply body width before encoding.
    ///
    /// The same request encoder checks this count against its actual output.
    /// It allocates no metadata, parses no object and grants no authority.
    ///
    /// # Errors
    /// Rejects checked overflow or a body above the existing request ceiling.
    pub fn encoded_body_bytes_from_lengths_v1(
        preparation: &ProtectedStorageCreatePreparationV1,
        manifest_bytes: usize,
        specification_bytes: usize,
    ) -> Result<usize, StorageSemanticsError> {
        use buffa::encoding::varint_len;
        let invalid = || StorageSemanticsError::CanonicalEncodingTooLarge;
        let bytes = |length: usize| -> Result<usize, StorageSemanticsError> {
            1usize.checked_add(varint_len(u64::try_from(length).map_err(|_| invalid())?))
                .and_then(|prefix| prefix.checked_add(length)).ok_or_else(invalid)
        };
        // Header: protocol major, fixed request ID, Controller audience and
        // response bound. Minor and deadline are zero and therefore absent.
        let header = 2usize.checked_add(bytes(16)?)
            .and_then(|size| size.checked_add(2))
            .and_then(|size| size.checked_add(1 + varint_len(4096)))
            .ok_or_else(invalid)?;
        let assignment = preparation.assignment;
        let fence = bytes(16)?.checked_add(bytes(16)?)
            .and_then(|size| size.checked_add(1 + varint_len(assignment.epoch().get())))
            .and_then(|size| size.checked_add(1 + varint_len(assignment.desired_generation().get())))
            .and_then(|size| size.checked_add(bytes(32).ok()?))
            .ok_or_else(invalid)?;
        let total = bytes(header)?.checked_add(bytes(fence)?)
            .and_then(|size| size.checked_add(2)) // nonzero Create action
            .and_then(|size| size.checked_add(1 + varint_len(preparation.quota_bytes)))
            .and_then(|size| size.checked_add(bytes(16).ok()?))
            .and_then(|size| size.checked_add(if manifest_bytes == 0 { 0 } else { bytes(manifest_bytes).ok()? }))
            .and_then(|size| size.checked_add(if specification_bytes == 0 { 0 } else { bytes(specification_bytes).ok()? }))
            .ok_or_else(invalid)?;
        if total > crate::MAXIMUM_REQUEST_BYTES { return Err(invalid()); }
        Ok(total)
    }

    /// Derives the exact Apply commitment using the sole Storage metadata codec.
    ///
    /// The supplied catalog remains nonauthorizing DATA. Only the actual
    /// authenticated Prepare owner may establish its provenance; this pure
    /// constructor deliberately makes no claim about that live association.
    ///
    /// # Errors
    /// Rejects noncanonical or cross-bound manifest/specification bytes using
    /// the existing Storage workspace semantics and unchanged schema ceilings.
    pub fn from_preparation_data_v1(
        preparation: &'original ProtectedStorageCreatePreparationV1,
        catalog: CatalogBindingV1,
        assignment_manifest: &'original [u8],
        sandbox_spec: &'original [u8],
    ) -> Result<Self, StorageSemanticsError> {
        let commitment = StorageOperation::CreateWorkspace {
            quota_bytes: preparation.quota_bytes,
        }.persisted_workspace_argument_commitment(
            preparation.assignment,
            preparation.operation_id.into_bytes(),
            catalog,
            assignment_manifest,
            sandbox_spec,
        )?;
        Ok(Self {
            preparation, catalog, assignment_manifest, sandbox_spec, commitment,
        })
    }

    /// Returns the original complete assignment fence.
    #[must_use]
    pub const fn assignment(self) -> BrokerAssignment {
        self.preparation.assignment
    }

    /// Returns the original public Create operation identity.
    #[must_use]
    pub const fn operation_id(self) -> OperationId {
        self.preparation.operation_id
    }

    /// Returns the original requested quota bound by this Apply.
    #[must_use]
    pub const fn quota_bytes(self) -> u64 {
        self.preparation.quota_bytes
    }

    /// Returns the original Prepare expiry, which a later Apply cannot renew.
    #[must_use]
    pub const fn preparation_expires_boottime_nanoseconds(self) -> u64 {
        self.preparation.expires_boottime_nanoseconds
    }

    /// Returns the independently obtained broker catalog binding as DATA.
    #[must_use]
    pub const fn catalog(self) -> CatalogBindingV1 {
        self.catalog
    }

    /// Borrows the exact original manifest bytes in the Apply commitment.
    #[must_use]
    pub const fn assignment_manifest(self) -> &'original [u8] {
        self.assignment_manifest
    }

    /// Borrows the exact original specification bytes in the Apply commitment.
    #[must_use]
    pub const fn sandbox_spec(self) -> &'original [u8] {
        self.sandbox_spec
    }

    /// Returns the method-separated commitment produced by the existing codec.
    #[must_use]
    pub const fn argument_commitment(self) -> BrokerArgumentCommitment {
        self.commitment
    }

    /// Encodes an inert, deadline-free Create Apply template.
    ///
    /// No lease, signature or authenticated request is constructed. The actual
    /// session engine alone may later inject its admitted unchanged deadline.
    ///
    /// # Errors
    /// Rejects a reserved request identity or a body above the existing request
    /// ceiling. Callers must pay for the complete encoding before this call.
    pub fn deadline_free_request_body_v1(
        self,
        request_id: [u8; 16],
    ) -> Result<Vec<u8>, StorageSemanticsError> {
        if request_id == [0; 16] {
            return Err(StorageSemanticsError::InvalidActionShape);
        }
        let assignment = self.assignment();
        let request = ApplyStorageRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 0,
                request_id: request_id.to_vec(),
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                maximum_response_bytes: 4096,
                ..Default::default()
            }).into(),
            fence: Some(AssignmentFence {
                sandbox_id: assignment.sandbox().as_bytes().to_vec(),
                incarnation_id: assignment.incarnation().as_bytes().to_vec(),
                assignment_epoch: assignment.epoch().get(),
                desired_generation: assignment.desired_generation().get(),
                assignment_digest: assignment.digest().as_bytes().to_vec(),
                ..Default::default()
            }).into(),
            action: StorageAction::STORAGE_ACTION_CREATE_WORKSPACE.into(),
            operation_id: self.operation_id().as_bytes().to_vec(),
            quota_bytes: self.quota_bytes(),
            assignment_manifest: self.assignment_manifest.to_vec(),
            sandbox_spec: self.sandbox_spec.to_vec(),
            ..Default::default()
        };
        let bytes = request.encode_to_vec();
        let expected = Self::encoded_body_bytes_from_lengths_v1(
            self.preparation, self.assignment_manifest.len(), self.sandbox_spec.len(),
        )?;
        if bytes.len() != expected || bytes.len() > crate::MAXIMUM_REQUEST_BYTES {
            return Err(StorageSemanticsError::CanonicalEncodingTooLarge);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod encoded_length_tests {
    use super::*;
    use aos_sandbox_model::{AssignmentEpoch, BrokerAssignment, BrokerArgumentCommitment,
        DesiredGeneration, IncarnationId, ObjectDigest, SandboxId};

    #[test]
    fn exact_counter_tracks_actual_protobuf_boundaries_without_decoding_metadata() {
        let assignment = BrokerAssignment::new(SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]), AssignmentEpoch::new(128),
            DesiredGeneration::new(16_384), ObjectDigest::from_bytes([3; 32])).unwrap();
        let catalog = CatalogBindingV1::from_publisher(1, ObjectDigest::from_bytes([4; 32])).unwrap();
        let preparation = ProtectedStorageCreatePreparationV1::from_protected_inputs(
            assignment, OperationId::from_bytes([5; 16]), u64::MAX, 0, catalog, catalog, 100,
        ).unwrap();

        for width in [1, 127, 128, 16_383, 16_384] {
            let manifest = vec![7; width];
            let spec = vec![8; width + 1];
            // This test exercises framing only. Canonical metadata validation
            // remains the separate unchanged from_preparation_data_v1 entry.
            let data = ProtectedStorageCreateApplyDataV1 {
                preparation: &preparation, catalog, assignment_manifest: &manifest,
                sandbox_spec: &spec,
                commitment: BrokerArgumentCommitment::for_canonical_bytes(b"framing"),
            };
            let body = data.deadline_free_request_body_v1([9; 16]).unwrap();
            assert_eq!(body.len(), ProtectedStorageCreateApplyDataV1::
                encoded_body_bytes_from_lengths_v1(&preparation, width, width + 1).unwrap());
        }
        assert!(ProtectedStorageCreateApplyDataV1::encoded_body_bytes_from_lengths_v1(
            &preparation, usize::MAX, 1,
        ).is_err());
    }
}
