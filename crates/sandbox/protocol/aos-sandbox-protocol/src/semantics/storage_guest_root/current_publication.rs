//! Compares an admitted current publication with its immutable creation root.
//!
//! The protected Storage attempt authenticates this entire record before the
//! physical worker runs. Signed Inventory lends it only beside the exact old
//! workspace and physical proof. Its codec issues no permission or native loan.
//!
//! ```text
//! AOSGRC02 | canonical-AOSSGR01[152] | creation-resource-digest[32]
//!          | sealed-effect-digest[32] | sealed-operation-fence-digest[32]
//!          | ownership-lease-digest[32] | request-id[16]
//! ```

use super::CanonicalStorageGuestRootArgumentsV1 as Arguments;
use crate::{ProtocolValidationError, storage_inventory::ValidatedStorageWorkspace};
use aos_sandbox_guest_protocol::guest_root_publication::GuestRootPublicationProofV1;
use aos_sandbox_model::BrokerAssignment;

/// Fixes the complete current-publication comparison record width.
pub const STORAGE_GUEST_ROOT_CURRENT_PUBLICATION_BYTES_V2: usize = 304;
const MAGIC: &[u8; 8] = b"AOSGRC02";

/// Keeps the current signed publication distinct from immutable creation DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageGuestRootCurrentPublicationDataV2 {
    arguments: Arguments,
    creation_resource_digest: [u8; 32],
    sealed_effect_digest: [u8; 32],
    operation_fence_digest: [u8; 32],
    ownership_lease_digest: [u8; 32],
    request_id: [u8; 16],
}

impl StorageGuestRootCurrentPublicationDataV2 {
    /// Constructs canonical comparison DATA without authenticating its origin.
    ///
    /// Actual producers must first admit method31 and join the protected old
    /// creation, physical pin and current signed assignment. The resulting
    /// record is durably sealed in that same native attempt before publication.
    ///
    /// # Errors
    /// Refuses sentinel identities or malformed canonical argument DATA.
    pub fn from_data_v2(arguments: Arguments, creation_resource_digest: [u8; 32],
        sealed_effect_digest: [u8; 32], operation_fence_digest: [u8; 32],
        ownership_lease_digest: [u8; 32], request_id: [u8; 16],
    ) -> Result<Self, ProtocolValidationError> {
        Arguments::decode_data_v1(arguments.canonical_bytes())?;
        if creation_resource_digest == [0; 32] || sealed_effect_digest == [0; 32]
            || operation_fence_digest == [0; 32] || ownership_lease_digest == [0; 32]
            || request_id == [0; 16] {
            return Err(refused());
        }
        Ok(Self { arguments, creation_resource_digest, sealed_effect_digest,
            operation_fence_digest, ownership_lease_digest, request_id })
    }

    /// Returns the unchanged exact current method31 arguments.
    #[must_use]
    pub const fn arguments_v2(&self) -> &Arguments { &self.arguments }

    /// Returns the exact current assignment as passive comparison DATA.
    ///
    /// # Errors
    /// Refuses a malformed canonical broker assignment.
    pub fn current_assignment_v2(&self) -> Result<BrokerAssignment, ProtocolValidationError> {
        self.arguments.assignment_data_v1()
    }

    /// Returns the immutable physical workspace observation commitment.
    #[must_use]
    pub const fn creation_resource_digest_v2(&self) -> &[u8; 32] { &self.creation_resource_digest }

    /// Returns the exact admitted request identity.
    #[must_use]
    pub const fn request_id_v2(&self) -> &[u8; 16] { &self.request_id }

    /// Returns the authenticated sealed-effect comparison commitment.
    #[must_use]
    pub const fn sealed_effect_digest_v2(&self) -> &[u8; 32] { &self.sealed_effect_digest }

    /// Returns the authenticated operation-fence comparison commitment.
    #[must_use]
    pub const fn operation_fence_digest_v2(&self) -> &[u8; 32] { &self.operation_fence_digest }

    /// Returns the current verified lease comparison commitment.
    #[must_use]
    pub const fn ownership_lease_digest_v2(&self) -> &[u8; 32] { &self.ownership_lease_digest }

    /// Encodes the complete fixed current-publication preimage.
    #[must_use]
    pub fn encode_v2(&self) -> [u8; STORAGE_GUEST_ROOT_CURRENT_PUBLICATION_BYTES_V2] {
        let mut bytes = [0; STORAGE_GUEST_ROOT_CURRENT_PUBLICATION_BYTES_V2];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..160].copy_from_slice(self.arguments.canonical_bytes());
        bytes[160..192].copy_from_slice(&self.creation_resource_digest);
        bytes[192..224].copy_from_slice(&self.sealed_effect_digest);
        bytes[224..256].copy_from_slice(&self.operation_fence_digest);
        bytes[256..288].copy_from_slice(&self.ownership_lease_digest);
        bytes[288..304].copy_from_slice(&self.request_id);
        bytes
    }

    /// Decodes only the complete current version, without granting authority.
    ///
    /// # Errors
    /// Refuses wrong width/purpose, malformed arguments or sentinel commitments.
    pub fn decode_v2(bytes: &[u8]) -> Result<Self, ProtocolValidationError> {
        if bytes.len() != STORAGE_GUEST_ROOT_CURRENT_PUBLICATION_BYTES_V2
            || bytes.get(..8) != Some(MAGIC.as_slice()) { return Err(refused()); }
        Self::from_data_v2(Arguments::decode_data_v1(&bytes[8..160])?,
            field(bytes, 160)?, field(bytes, 192)?, field(bytes, 224)?,
            field(bytes, 256)?, field(bytes, 288)?)
    }

    /// Compares a signed method31 result with its entire admitted request.
    ///
    /// The physical proof keeps its immutable creation digest. Its full
    /// creation fence/resource relation is checked separately against the
    /// actual workspace; this comparison binds the new request and selectors.
    ///
    /// # Errors
    /// Refuses another request, assignment domain or immutable workspace.
    pub fn require_request_data_v2(
        &self,
        physical: GuestRootPublicationProofV1,
        arguments: &Arguments,
        request_id: &[u8; 16],
    ) -> Result<(), ProtocolValidationError> {
        let current = self.current_assignment_v2()?;
        let args = arguments.canonical_bytes();
        if &self.arguments != arguments
            || &self.request_id != request_id
            || physical.sandbox != *current.sandbox().as_bytes()
            || physical.incarnation != *current.incarnation().as_bytes()
            || physical.assignment_epoch != current.epoch().get()
            || args[104..136] != physical.workspace_handle
            || args[136..152] != physical.creation_operation
            || physical.encode().is_err()
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Compares both assignments and the immutable physical proof once.
    ///
    /// This is the shared passive relation used by Storage's protected producer,
    /// worker and cold observer. It does not authenticate either assignment,
    /// compare node/authority origins or establish a current lease. Those checks
    /// remain on each actual held native admission and its protected creation.
    ///
    /// # Errors
    /// Refuses another sandbox/incarnation/epoch, a backward generation,
    /// equivocation at the creation generation, or any substituted physical root.
    pub fn require_creation_data_v2(&self, creation: BrokerAssignment,
        physical: GuestRootPublicationProofV1, creation_resource_digest: &[u8; 32],
    ) -> Result<(), ProtocolValidationError> {
        let current = self.current_assignment_v2()?;
        self.require_request_data_v2(physical, &self.arguments, &self.request_id)?;
        if current.sandbox() != creation.sandbox()
            || current.incarnation() != creation.incarnation()
            || current.epoch() != creation.epoch()
            || current.desired_generation() < creation.desired_generation()
            || current.desired_generation() == creation.desired_generation() && current != creation
            || physical.sandbox != *creation.sandbox().as_bytes()
            || physical.incarnation != *creation.incarnation().as_bytes()
            || physical.assignment_epoch != creation.epoch().get()
            || physical.assignment_digest != *creation.digest().as_bytes()
            || &self.creation_resource_digest != creation_resource_digest { return Err(refused()); }
        Ok(())
    }

    /// Compares a signed Inventory's current binding to its whole old workspace.
    ///
    /// # Errors
    /// Refuses missing physical publication, replaced creation identity or a
    /// different root image/GUID. Signed/current native origin remains external.
    pub fn require_workspace_v2(&self, workspace: &ValidatedStorageWorkspace)
        -> Result<(), ProtocolValidationError> {
        let physical = workspace.guest_root_publication_proof().ok_or_else(refused)?;
        self.require_creation_data_v2(workspace.fence().broker_assignment().map_err(|_| refused())?,
            physical, workspace.resource_digest())?;
        if physical.workspace_handle != *workspace.workspace_handle()
            || physical.creation_operation != *workspace.creation_operation_id()
            || physical.dataset_guid != workspace.dataset_guid()
            || physical.root_image_digest != *workspace.root_image().digest().as_bytes() {
            return Err(refused());
        }
        Ok(())
    }
}

fn field<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ProtocolValidationError> {
    bytes.get(offset..offset + N).ok_or_else(refused)?.try_into().map_err(|_| refused())
}

fn refused() -> ProtocolValidationError {
    ProtocolValidationError::InvalidField("guest root current publication binding")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_model::{AssignmentEpoch, DesiredGeneration, IncarnationId, ObjectDigest, SandboxId};

    fn assignment(generation: u64, digest: u8) -> BrokerAssignment {
        BrokerAssignment::new(SandboxId::from_bytes([1; 16]), IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3), DesiredGeneration::new(generation), ObjectDigest::from_bytes([digest; 32])).unwrap()
    }

    fn proof() -> GuestRootPublicationProofV1 {
        GuestRootPublicationProofV1 {
            sandbox: [1; 16], incarnation: [2; 16], assignment_epoch: 3, assignment_digest: [4; 32],
            creation_operation: [5; 16], workspace_handle: [6; 32], dataset_guid: 7,
            root_image_digest: [8; 32], package_binding: [9; 32], root_tree_digest: [10; 32], feature_mask: 0x003f,
        }
    }

    fn publication(generation: u64, digest: u8) -> StorageGuestRootCurrentPublicationDataV2 {
        let args = Arguments::from_protected_assignment(assignment(generation, digest),
            [11; 16], [6; 32], [5; 16]).unwrap();
        StorageGuestRootCurrentPublicationDataV2::from_data_v2(args,
            [12; 32], [13; 32], [14; 32], [15; 32], [16; 16]).unwrap()
    }

    #[test]
    fn advanced_publication_preserves_the_exact_creation_proof() {
        let physical = proof();
        let current = publication(2, 17);
        current.require_creation_data_v2(assignment(1, 4), physical, &[12; 32]).unwrap();
        assert_eq!(physical.assignment_digest, [4; 32]);
        assert_eq!(*current.current_assignment_v2().unwrap().digest().as_bytes(), [17; 32]);
        assert_eq!(StorageGuestRootCurrentPublicationDataV2::decode_v2(&current.encode_v2()).unwrap(), current);
    }

    #[test]
    fn signed_current_response_binds_new_request_without_rewriting_creation() {
        use buffa::Message as _;
        use aos_sandbox_api::aos::sandbox::local::v1::PopulateStorageGuestRootResponseV1;

        let physical = proof();
        let current = publication(2, 17);
        let request = *current.arguments_v2();
        current.require_request_data_v2(physical, &request, &[16; 16]).unwrap();
        assert_eq!(physical.assignment_digest, [4; 32]);
        assert!(current.require_request_data_v2(physical, &request, &[18; 16]).is_err());
        let other = publication(2, 18);
        assert!(current.require_request_data_v2(physical, other.arguments_v2(), &[16; 16]).is_err());

        let mut response = PopulateStorageGuestRootResponseV1 {
            publication_proof: physical.encode().unwrap().to_vec(),
            current_publication_v2: current.encode_v2().to_vec(),
            ..Default::default()
        };
        let decoded = super::super::decode_storage_guest_root_response_v2(
            &response.encode_to_vec(), 4096,
        ).unwrap();
        assert_eq!(decoded.proof_v1(), physical);
        assert_eq!(decoded.current_publication_v2(), &current);
        response.current_publication_v2.clear();
        assert!(super::super::decode_storage_guest_root_response_v2(
            &response.encode_to_vec(), 4096,
        ).is_err());
    }

    #[test]
    fn current_binding_cannot_replace_creation_or_equivocate_at_its_generation() {
        let creation = assignment(1, 4);
        assert!(publication(1, 18).require_creation_data_v2(creation, proof(), &[12; 32]).is_err());
        assert!(publication(2, 17).require_creation_data_v2(creation, proof(), &[19; 32]).is_err());

        let mut replaced = proof();
        replaced.workspace_handle = [20; 32];
        assert!(publication(2, 17).require_creation_data_v2(creation, replaced, &[12; 32]).is_err());
        replaced = proof();
        replaced.assignment_digest = [17; 32];
        assert!(publication(2, 17).require_creation_data_v2(creation, replaced, &[12; 32]).is_err());
    }

    #[test]
    fn current_codec_refuses_old_physical_proof_and_unknown_versions() {
        assert!(StorageGuestRootCurrentPublicationDataV2::decode_v2(&proof().encode().unwrap()).is_err());
        let mut bytes = publication(2, 17).encode_v2();
        bytes[..8].copy_from_slice(b"AOSGRC01");
        assert!(StorageGuestRootCurrentPublicationDataV2::decode_v2(&bytes).is_err());
        bytes = publication(2, 17).encode_v2();
        bytes[160..192].fill(0);
        assert!(StorageGuestRootCurrentPublicationDataV2::decode_v2(&bytes).is_err());
    }
}
