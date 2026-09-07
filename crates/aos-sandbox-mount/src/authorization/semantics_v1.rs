//! Mount compatibility facade plus node-local catalog commitment construction.
//!
//! Portable request canonicalization is owned by
//! [`aos_sandbox_protocol::semantics::mount`]. This module retains only the
//! mount broker's protected hashing of already-verified local catalog facts
//! and adapts that opaque digest to the shared compiler.

use aos_proto::aos::sandbox::local::v1::BrokerDescriptorRole;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::ValidatedMountRequest;
use sha2::{Digest as _, Sha256};

pub(crate) use aos_sandbox_protocol::semantics::mount::CanonicalMountSemanticsV1;
use aos_sandbox_protocol::semantics::mount::{
    MountCatalogBindingV1, MountSemanticError as PortableMountSemanticError,
};

const CATALOG_COMMITMENT_DOMAIN: &[u8] = b"aos-sandbox-mount-catalog-semantics-v1\0";
const MAXIMUM_CATALOG_SEMANTIC_BYTES: usize = 16 * 1024;

/// Reports local catalog hashing or portable mount semantic failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum MountSemanticError {
    /// The catalog entry semantics exceed their fixed pre-hash ceiling.
    #[error("mount catalog semantic bytes exceed the V1 ceiling")]
    CatalogTooLarge,
    /// The catalog commitment is missing, unexpected, or a reserved zero digest.
    #[error("mount catalog commitment does not match the action")]
    CatalogCommitmentMismatch,
    /// The descriptor-role sequence is oversized or contains the sentinel role.
    #[error("mount descriptor-role semantics are invalid")]
    InvalidDescriptorRoles,
    /// A validated request unexpectedly contains an unknown action or target shape.
    #[error("mount action target semantics are invalid")]
    InvalidTarget,
    /// The canonical encoding exceeded its invariant V1 ceiling.
    #[error("mount canonical semantic encoding exceeds the V1 ceiling")]
    EncodingTooLarge,
}

impl From<PortableMountSemanticError> for MountSemanticError {
    fn from(value: PortableMountSemanticError) -> Self {
        match value {
            PortableMountSemanticError::CatalogCommitmentMismatch => {
                Self::CatalogCommitmentMismatch
            }
            PortableMountSemanticError::InvalidDescriptorRoles => Self::InvalidDescriptorRoles,
            PortableMountSemanticError::InvalidTarget => Self::InvalidTarget,
            PortableMountSemanticError::EncodingTooLarge => Self::EncodingTooLarge,
        }
    }
}

/// Commits one already-verified catalog entry without exposing host paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MountCatalogCommitmentV1(ObjectDigest);

impl MountCatalogCommitmentV1 {
    /// Hashes a bounded canonical local catalog-entry representation.
    ///
    /// # Errors
    ///
    /// Returns [`MountSemanticError::CatalogTooLarge`] above the V1 ceiling.
    pub(crate) fn for_verified_canonical_bytes(bytes: &[u8]) -> Result<Self, MountSemanticError> {
        if bytes.len() > MAXIMUM_CATALOG_SEMANTIC_BYTES {
            return Err(MountSemanticError::CatalogTooLarge);
        }
        let mut hasher = Sha256::new();
        hasher.update(CATALOG_COMMITMENT_DOMAIN);
        hasher.update(bytes);
        Ok(Self(ObjectDigest::from_bytes(hasher.finalize().into())))
    }

    /// Adopts a nonzero digest produced by a separately verified local codec.
    ///
    /// # Errors
    ///
    /// Returns [`MountSemanticError::CatalogCommitmentMismatch`] for zero.
    pub(crate) fn from_verified_digest(digest: ObjectDigest) -> Result<Self, MountSemanticError> {
        MountCatalogBindingV1::from_verified_digest(digest)
            .map(|_| Self(digest))
            .map_err(Into::into)
    }

    pub(crate) const fn digest(self) -> ObjectDigest {
        self.0
    }
}

/// Delegates byte-exact portable semantics after local catalog verification.
pub(crate) fn canonical_mount_semantics_v1(
    request: &ValidatedMountRequest,
    catalog: Option<MountCatalogCommitmentV1>,
    descriptor_roles: &[BrokerDescriptorRole],
) -> Result<CanonicalMountSemanticsV1, MountSemanticError> {
    let catalog = catalog
        .map(MountCatalogCommitmentV1::digest)
        .map(MountCatalogBindingV1::from_verified_digest)
        .transpose()
        .map_err(MountSemanticError::from)?;
    aos_sandbox_protocol::semantics::mount::canonical_mount_semantics_v1(
        request,
        catalog,
        descriptor_roles,
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{
        ApplyMountRequest, AssignmentFence, Audience, Descriptor, MountAction, MountAttributes,
        MountSourceConsistency, RequestHeader,
    };
    use aos_sandbox_core::{BrokerGrantTarget, BrokerVerb};
    use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_mount_request};
    use buffa::Message as _;

    use super::*;

    fn request() -> ValidatedMountRequest {
        let wire = ApplyMountRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 10_000,
                maximum_response_bytes: 4096,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![2; 16],
                incarnation_id: vec![3; 16],
                assignment_epoch: 4,
                desired_generation: 5,
                assignment_digest: vec![6; 32],
                ..Default::default()
            })
            .into(),
            action: MountAction::MOUNT_ACTION_CREATE_DETACHED.into(),
            attachment_id: vec![7; 16],
            destination_slot_id: vec![8; 16],
            view_revision: Some(Descriptor {
                media_type: "application/vnd.aos.sandbox.view.v1+cbor".to_owned(),
                sha256: vec![9; 32],
                encoded_size: 10,
                ..Default::default()
            })
            .into(),
            attributes: Some(MountAttributes {
                read_only: true,
                no_exec: true,
                no_suid: true,
                no_device: true,
                no_atime: true,
                ..Default::default()
            })
            .into(),
            source_generation: 13,
            namespace_generation: 14,
            desired_attachment_generation: 15,
            resource_attachment_generation: 15,
            source_view_id: vec![16; 16],
            source_consistency: MountSourceConsistency::MOUNT_SOURCE_CONSISTENCY_IMMUTABLE_REVISION
                .into(),
            attachment_lease_id: vec![17; 16],
            attachment_lease_issued_seconds: 18,
            attachment_lease_expires_seconds: 19,
            ..Default::default()
        };
        decode_mount_request(
            &wire.encode_to_vec(),
            PeerCredentials {
                uid: 100,
                gid: 101,
                pid: Some(102),
            },
            PeerPolicy {
                uid: 100,
                gid: Some(101),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            1,
        )
        .unwrap()
    }

    #[test]
    fn facade_and_protocol_are_byte_exact_and_preserve_the_golden() {
        let request = request();
        let local = MountCatalogCommitmentV1::for_verified_canonical_bytes(&[15; 32]).unwrap();
        let facade = canonical_mount_semantics_v1(&request, Some(local), &[]).unwrap();
        let binding = MountCatalogBindingV1::from_verified_digest(local.digest()).unwrap();
        let portable = aos_sandbox_protocol::semantics::mount::canonical_mount_semantics_v1(
            &request,
            Some(binding),
            &[],
        )
        .unwrap();
        assert_eq!(facade, portable);
        assert_eq!(facade.verb(), BrokerVerb::MountCreate);
        assert_eq!(facade.target(), BrokerGrantTarget::Assignment);
        assert_eq!(
            facade.commitment().digest(),
            ObjectDigest::from_bytes([
                0xfd, 0x21, 0xc8, 0x2a, 0x93, 0x79, 0xe2, 0x88, 0x2d, 0xf3, 0x25, 0x4e, 0x0a, 0xfa,
                0x0c, 0xa1, 0x2e, 0x9d, 0x24, 0x7c, 0x32, 0x89, 0x3b, 0x7b, 0xb2, 0x7e, 0x6d, 0xdb,
                0x8b, 0x1f, 0x08, 0x86,
            ])
        );
        assert_eq!(facade.canonical_bytes(), portable.canonical_bytes());
    }

    #[test]
    fn local_catalog_commitment_remains_bounded_and_nonzero() {
        assert_eq!(
            MountCatalogCommitmentV1::for_verified_canonical_bytes(&vec![
                0;
                MAXIMUM_CATALOG_SEMANTIC_BYTES
                    + 1
            ]),
            Err(MountSemanticError::CatalogTooLarge)
        );
        assert_eq!(
            MountCatalogCommitmentV1::from_verified_digest(ObjectDigest::from_bytes([0; 32])),
            Err(MountSemanticError::CatalogCommitmentMismatch)
        );
    }
}
