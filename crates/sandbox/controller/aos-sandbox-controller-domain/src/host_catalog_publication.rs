//! Holds canonical catalog drafts for the protected Host Session publisher.
//!
//! Trusted reconciliation derives the physical projection before publication.
//! This module binds the expected generation and exact catalog bytes; it does
//! not create a transport, current Host identity or effect authority. Installed
//! callers use the authenticated Broker Session publication engine.

use std::os::fd::OwnedFd;

use aos_sandbox_api::aos::sandbox::local::v1::{BrokerErrorCode, BrokerMethod,
    BrokerDescriptorEntry, BrokerRequestEnvelope, PublishHostCatalogRequest, RequestHeader};
use aos_sandbox_linux::immutable_file::{SealedReadOnlyCredential, ImmutableFileError};
use buffa::Message as _;
use aos_sandbox_model::ObjectDigest;
use aos_sandbox_linux::seqpacket::SeqpacketError;
use aos_sandbox_protocol::host_catalog::{MAXIMUM_HOST_CATALOG_BYTES, HOST_CATALOG_PUBLICATION_DESCRIPTOR_ROLES};
use aos_sandbox_protocol::ProtocolValidationError;
use sha2::{Digest as _, Sha256};

/// Holds a complete proposed catalog and its independently expected receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostCatalogPublicationDraftV1 {
    canonical_catalog: Vec<u8>,
    expected_generation: u64,
    expected_digest: ObjectDigest,
}

impl HostCatalogPublicationDraftV1 {
    /// Constructs a bounded publication draft produced by trusted reconciliation.
    ///
    /// This constructor computes the byte commitment but deliberately does not
    /// interpret the Host-owned catalog schema. Host performs the authoritative
    /// decode and continuity checks. The expected generation must be derived
    /// from the same snapshot and is checked against Host's protected receipt.
    ///
    /// # Errors
    ///
    /// Returns [`HostCatalogPublicationError::InvalidDraft`] when the generation
    /// is zero or the catalog is empty or larger than sixteen MiB.
    pub fn new(
        canonical_catalog: Vec<u8>,
        expected_generation: u64,
    ) -> Result<Self, HostCatalogPublicationError> {
        if expected_generation == 0
            || canonical_catalog.is_empty()
            || canonical_catalog.len() > MAXIMUM_HOST_CATALOG_BYTES
        {
            return Err(HostCatalogPublicationError::InvalidDraft);
        }
        let expected_digest = ObjectDigest::from_bytes(Sha256::digest(&canonical_catalog).into());
        Ok(Self {
            canonical_catalog,
            expected_generation,
            expected_digest,
        })
    }

    /// Returns the complete canonical bytes sent to Host.
    #[must_use]
    pub fn canonical_catalog(&self) -> &[u8] {
        &self.canonical_catalog
    }

    /// Returns the generation trusted reconciliation expects Host to confirm.
    #[must_use]
    pub const fn expected_generation(&self) -> u64 {
        self.expected_generation
    }

    /// Returns the exact SHA-256 commitment expected in Host's receipt.
    #[must_use]
    pub const fn expected_digest(&self) -> ObjectDigest {
        self.expected_digest
    }

    /// Constructs only the canonical publication envelope from supplied Header DATA.
    ///
    /// The protected Session owns request coordinates, signing and admission.
    /// This pure builder creates no validated Header or publication authority;
    /// the same source descriptor must be independently joined by its sender.
    #[doc(hidden)]
    #[must_use]
    pub fn request_envelope_data_v2(&self, header: RequestHeader) -> BrokerRequestEnvelope {
        let request = PublishHostCatalogRequest {
            header: Some(header).into(),
            catalog_generation: self.expected_generation(),
            // Construction already bounds this value to sixteen MiB.
            catalog_bytes: self.canonical_catalog().len() as u64,
            catalog_sha256: self.expected_digest().as_bytes().to_vec(),
            ..Default::default()
        };
        BrokerRequestEnvelope {
            method: BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG.into(),
            body: request.encode_to_vec(),
            descriptors: vec![BrokerDescriptorEntry {
                index: 0, role: HOST_CATALOG_PUBLICATION_DESCRIPTOR_ROLES[0].into(),
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    /// Creates an immutable transfer descriptor containing the exact catalog bytes.
    ///
    /// The descriptor is sealed against writes, resizing, and seal changes.
    /// It carries no publication authority; the protected transport must bind
    /// it to the signed request's catalog length and digest.
    ///
    /// # Errors
    ///
    /// Returns an error if creating, populating, or sealing the memfd fails.
    pub fn sealed_transfer_descriptor(&self) -> Result<OwnedFd, HostCatalogPublicationError> {
        Ok(SealedReadOnlyCredential::create("aos-host-catalog", self.canonical_catalog(),
            MAXIMUM_HOST_CATALOG_BYTES)?.into_owned_fd_v2())
    }
}

/// Reports a rejected or indeterminate Host catalog publication.
#[derive(Debug, thiserror::Error)]
pub enum HostCatalogPublicationError {
    /// The proposed bytes or expected generation violate fixed draft bounds.
    #[error("invalid Host catalog publication draft")]
    InvalidDraft,
    /// Kernel randomness for the request identity is unavailable.
    #[error("Host catalog publication request entropy is unavailable")]
    EntropyUnavailable,
    /// The request or bounded exchange deadline elapsed or overflowed.
    #[error("Host catalog publication deadline elapsed or clock is invalid")]
    Deadline,
    /// A response's kernel-nominated subject mismatches configured Host policy.
    #[error("Host catalog response subject does not match configured Host policy")]
    HostIdentity,
    /// Host confirmed a different generation or byte commitment.
    #[error("Host catalog publication receipt differs from the proposed snapshot")]
    ReceiptMismatch,
    /// Host rejected or could not complete the publication.
    #[error("Host rejected catalog publication with {code:?} (retryable: {retryable})")]
    BrokerRejected {
        /// Closed broker error code.
        code: BrokerErrorCode,
        /// Whether the same publication may succeed on a later attempt.
        retryable: bool,
    },
    /// Negotiation, request binding, or Host response validation failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    /// A local socket operation failed.
    #[error(transparent)]
    Transport(#[from] SeqpacketError),
    /// The sealed catalog transfer file could not be written.
    #[error("Host catalog transfer file failed: {0}")]
    CatalogFile(#[from] std::io::Error),
    /// The shared sealed read-only creation/readback engine failed.
    #[error(transparent)]
    Immutable(#[from] ImmutableFileError),
    /// A polling syscall failed.
    #[error("Host catalog publication I/O failed: {0}")]
    Io(#[from] rustix::io::Errno),
    /// Configured service-subject or cgroup correlation failed.
    #[error(transparent)]
    Kernel(#[from] aos_sandbox_linux::Error),
}

#[cfg(test)]
fn validate_receipt(
    draft: &HostCatalogPublicationDraftV1,
    receipt: aos_sandbox_protocol::host_catalog::ValidatedHostCatalogPublicationResponse,
) -> Result<(), HostCatalogPublicationError> {
    if receipt.generation() != draft.expected_generation
        || receipt.catalog_digest() != draft.expected_digest
    {
        return Err(HostCatalogPublicationError::ReceiptMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_api::aos::sandbox::local::v1::{
        HostCatalogPublicationStatus, PublishHostCatalogResponse,
    };
    use aos_sandbox_protocol::host_catalog::decode_host_catalog_publication_response;
    use buffa::Message as _;

    #[test]
    fn draft_commits_exact_bytes_and_generation() {
        let draft = HostCatalogPublicationDraftV1::new(b"{\"generation\":7}".to_vec(), 7).unwrap();
        assert_eq!(draft.canonical_catalog(), b"{\"generation\":7}");
        assert_eq!(draft.expected_generation(), 7);
        assert_eq!(
            draft.expected_digest(),
            ObjectDigest::from_bytes(Sha256::digest(draft.canonical_catalog()).into())
        );
    }

    #[test]
    fn receipt_must_confirm_exact_draft() {
        let draft = HostCatalogPublicationDraftV1::new(b"{}".to_vec(), 7).unwrap();
        let matching = decode_host_catalog_publication_response(
            &PublishHostCatalogResponse {
                status: HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_PUBLISHED
                    .into(),
                generation: 7,
                catalog_sha256: draft.expected_digest().as_bytes().to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .unwrap();
        assert!(validate_receipt(&draft, matching).is_ok());

        let changed = decode_host_catalog_publication_response(
            &PublishHostCatalogResponse {
                status: HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_REPLAY.into(),
                generation: 8,
                catalog_sha256: draft.expected_digest().as_bytes().to_vec(),
                ..Default::default()
            }
            .encode_to_vec(),
        )
        .unwrap();
        assert!(matches!(
            validate_receipt(&draft, changed),
            Err(HostCatalogPublicationError::ReceiptMismatch)
        ));
    }

}
