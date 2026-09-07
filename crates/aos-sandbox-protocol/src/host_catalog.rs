//! Host 1.4 launch-catalog publication messages.
//!
//! The fixed node-controller peer sends one sealed memfd containing a complete
//! canonical Host catalog. The request binds its generation, byte length, and
//! SHA-256 digest; hostd checks those facts, the catalog schema, and physical-
//! identity continuity against protected current state before it returns the
//! digest of the exact bytes made visible.

use aos_proto::aos::sandbox::local::v1::{
    BrokerDescriptorRole, HostCatalogPublicationStatus, PublishHostCatalogRequest,
    PublishHostCatalogResponse,
};
use aos_sandbox_core::{ObjectDigest, ProtocolId};
use buffa::Message as _;

use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, validate_request_header,
};

/// Maximum canonical Host catalog carried by protocol 1.4.
pub const MAXIMUM_HOST_CATALOG_BYTES: usize = 16 * 1024 * 1024;
/// Maximum protobuf request body describing one sealed catalog memfd.
pub const MAXIMUM_HOST_CATALOG_PUBLICATION_BODY_BYTES: usize = 64 * 1024;
/// Maximum enveloped Host 1.4 publication packet.
pub const MAXIMUM_HOST_CATALOG_PUBLICATION_PACKET_BYTES: usize =
    MAXIMUM_HOST_CATALOG_PUBLICATION_BODY_BYTES + 64 * 1024;
/// Exact ancillary descriptor sequence for Host catalog publication.
pub const HOST_CATALOG_PUBLICATION_DESCRIPTOR_ROLES: [BrokerDescriptorRole; 1] =
    [BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_HOST_CATALOG];

/// Carries a peer-checked complete Host catalog publication request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostCatalogPublication {
    header: ValidatedHeader,
    catalog_generation: u64,
    catalog_bytes: u64,
    catalog_digest: ObjectDigest,
}

impl ValidatedHostCatalogPublication {
    /// Returns the request header bound to the accepted controller peer.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the proposed nonzero catalog generation.
    #[must_use]
    pub const fn catalog_generation(&self) -> u64 {
        self.catalog_generation
    }

    /// Returns the exact nonzero sealed catalog length.
    #[must_use]
    pub const fn catalog_bytes(&self) -> u64 {
        self.catalog_bytes
    }

    /// Returns the SHA-256 commitment to the sealed canonical catalog.
    #[must_use]
    pub const fn catalog_digest(&self) -> ObjectDigest {
        self.catalog_digest
    }
}

/// Reports the durable outcome of one exact Host catalog publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostCatalogPublicationStatusV1 {
    /// The proposed generation became visible.
    Published,
    /// The exact proposed bytes were already visible.
    Replay,
}

/// Carries a validated publication receipt from Host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedHostCatalogPublicationResponse {
    status: HostCatalogPublicationStatusV1,
    generation: u64,
    catalog_digest: ObjectDigest,
}

impl ValidatedHostCatalogPublicationResponse {
    /// Returns whether Host published the generation or accepted exact replay.
    #[must_use]
    pub const fn status(self) -> HostCatalogPublicationStatusV1 {
        self.status
    }

    /// Returns the nonzero visible catalog generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the SHA-256 digest of the exact visible canonical catalog bytes.
    #[must_use]
    pub const fn catalog_digest(self) -> ObjectDigest {
        self.catalog_digest
    }
}

/// Decodes a hostile Host catalog publication request.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized or malformed message,
/// unknown fields, a non-1.4 Host header, peer/audience mismatch, elapsed
/// deadline, generation zero, an empty or oversized catalog length, or a
/// digest not exactly 32 bytes.
pub fn decode_host_catalog_publication_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostCatalogPublication, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_HOST_CATALOG_PUBLICATION_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = PublishHostCatalogRequest::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let header = validate_request_header(
        request
            .header
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("header"))?,
        peer,
        policy,
        ProtocolId::HostBroker,
        now_boottime_nanoseconds,
    )?;
    if header.protocol_version().minor() < 4 {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    if request.catalog_generation == 0 {
        return Err(ProtocolValidationError::InvalidField("catalog_generation"));
    }
    let catalog_bytes = usize::try_from(request.catalog_bytes)
        .map_err(|_| ProtocolValidationError::InvalidField("catalog_bytes"))?;
    if catalog_bytes == 0 || catalog_bytes > MAXIMUM_HOST_CATALOG_BYTES {
        return Err(ProtocolValidationError::InvalidField("catalog_bytes"));
    }
    let catalog_digest = request
        .catalog_sha256
        .as_slice()
        .try_into()
        .map(ObjectDigest::from_bytes)
        .map_err(|_| ProtocolValidationError::InvalidField("catalog_sha256"))?;

    Ok(ValidatedHostCatalogPublication {
        header,
        catalog_generation: request.catalog_generation,
        catalog_bytes: request.catalog_bytes,
        catalog_digest,
    })
}

/// Decodes a hostile Host catalog publication response.
///
/// # Errors
///
/// Returns [`ProtocolValidationError`] for an oversized or malformed response,
/// unknown fields or status, generation zero, or a digest not exactly 32 bytes.
pub fn decode_host_catalog_publication_response(
    bytes: &[u8],
) -> Result<ValidatedHostCatalogPublicationResponse, ProtocolValidationError> {
    if bytes.len() > crate::MAXIMUM_RESPONSE_BYTES as usize {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = PublishHostCatalogResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let status = match response.status.as_known() {
        Some(HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_PUBLISHED) => {
            HostCatalogPublicationStatusV1::Published
        }
        Some(HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_REPLAY) => {
            HostCatalogPublicationStatusV1::Replay
        }
        Some(HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_UNSPECIFIED) | None => {
            return Err(ProtocolValidationError::UnknownAction);
        }
    };
    if response.generation == 0 {
        return Err(ProtocolValidationError::InvalidField("generation"));
    }
    let digest = response
        .catalog_sha256
        .as_slice()
        .try_into()
        .map_err(|_| ProtocolValidationError::InvalidField("catalog_sha256"))?;

    Ok(ValidatedHostCatalogPublicationResponse {
        status,
        generation: response.generation,
        catalog_digest: ObjectDigest::from_bytes(digest),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aos_proto::aos::sandbox::local::v1::{Audience, RequestHeader};

    use super::*;

    fn credentials() -> PeerCredentials {
        PeerCredentials {
            uid: 100,
            gid: 101,
            pid: Some(102),
        }
    }

    fn policy() -> PeerPolicy {
        PeerPolicy {
            uid: 100,
            gid: Some(101),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        }
    }

    fn request() -> PublishHostCatalogRequest {
        PublishHostCatalogRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 4,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 20,
                maximum_response_bytes: 4096,
                ..Default::default()
            })
            .into(),
            catalog_generation: 7,
            catalog_bytes: 2,
            catalog_sha256: vec![3; 32],
            ..Default::default()
        }
    }

    #[test]
    fn request_requires_host_one_four_and_bounded_catalog_commitment() {
        let valid = request().encode_to_vec();
        let decoded =
            decode_host_catalog_publication_request(&valid, credentials(), policy(), 10).unwrap();
        assert_eq!(decoded.catalog_generation(), 7);
        assert_eq!(decoded.catalog_bytes(), 2);
        assert_eq!(decoded.catalog_digest(), ObjectDigest::from_bytes([3; 32]));

        let mut legacy = request();
        legacy.header.get_or_insert_default().protocol_minor = 3;
        assert!(
            decode_host_catalog_publication_request(
                &legacy.encode_to_vec(),
                credentials(),
                policy(),
                10,
            )
            .is_err()
        );
        let mut empty = request();
        empty.catalog_bytes = 0;
        assert!(
            decode_host_catalog_publication_request(
                &empty.encode_to_vec(),
                credentials(),
                policy(),
                10,
            )
            .is_err()
        );

        let mut malformed_digest = request();
        malformed_digest.catalog_sha256.pop();
        assert!(
            decode_host_catalog_publication_request(
                &malformed_digest.encode_to_vec(),
                credentials(),
                policy(),
                10,
            )
            .is_err()
        );
    }

    #[test]
    fn response_rejects_unspecified_status_and_malformed_digest() {
        let valid = PublishHostCatalogResponse {
            status: HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_REPLAY.into(),
            generation: 7,
            catalog_sha256: vec![9; 32],
            ..Default::default()
        };
        let decoded = decode_host_catalog_publication_response(&valid.encode_to_vec()).unwrap();
        assert_eq!(decoded.status(), HostCatalogPublicationStatusV1::Replay);
        assert_eq!(decoded.generation(), 7);
        assert_eq!(decoded.catalog_digest(), ObjectDigest::from_bytes([9; 32]));

        let mut invalid = valid.clone();
        invalid.status =
            HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_UNSPECIFIED.into();
        assert!(decode_host_catalog_publication_response(&invalid.encode_to_vec()).is_err());
        invalid = valid;
        invalid.catalog_sha256.pop();
        assert!(decode_host_catalog_publication_response(&invalid.encode_to_vec()).is_err());
    }
}
