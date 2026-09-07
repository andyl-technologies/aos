//! Read-only Mount catalog preparation from an authenticated Host scope.
//!
//! A preparation request contains a complete prospective Mount request and a
//! complete authorized Host 1.3 `ObserveMountScope` envelope. The controller
//! supplies neither paths nor descriptors. Mount validates both nested
//! requests, acquires the Host-owned descriptors itself, and returns only an
//! opaque node-local catalog commitment.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerMethod, PrepareMountCatalogRequest, PrepareMountCatalogResponse,
};
use aos_sandbox_core::{ObjectDigest, ProtocolId};
use buffa::Message as _;

use crate::mount_scope::{ValidatedMountScopeRequest, decode_mount_scope_request};
use crate::session::MAXIMUM_HOST_QUERY_PACKET_BYTES;
use crate::session::ValidatedUntrustedAuthorizationArtifacts;
use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedHeader, ValidatedMountRequest,
    decode_mount_request, decode_request_envelope, exact_nonzero, validate_request_header,
};

/// Bounds the fixed prospective Apply body nested in a preparation request.
pub const MAXIMUM_MOUNT_CATALOG_INTENT_BYTES: usize = 16 * 1024;
/// Bounds Mount 1.2 preparation above the largest authorized Host packet.
pub const MOUNT_CATALOG_PREPARATION_OVERHEAD_BYTES: usize = 32 * 1024;
/// Maximum encoded Mount 1.2 preparation packet accepted before decoding.
pub const MAXIMUM_MOUNT_CATALOG_PREPARATION_PACKET_BYTES: usize =
    MAXIMUM_HOST_QUERY_PACKET_BYTES + MOUNT_CATALOG_PREPARATION_OVERHEAD_BYTES;

/// Carries one structurally validated, non-authorizing preparation request.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedMountCatalogPreparation {
    header: ValidatedHeader,
    mount_request: ValidatedMountRequest,
    host_request: ValidatedMountScopeRequest,
    host_request_body: Vec<u8>,
    host_authorization: ValidatedUntrustedAuthorizationArtifacts,
}

impl ValidatedMountCatalogPreparation {
    /// Returns the peer-checked outer Mount request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the complete prospective Mount request semantics.
    #[must_use]
    pub const fn mount_request(&self) -> &ValidatedMountRequest {
        &self.mount_request
    }

    /// Returns the exact validated Host scope request.
    #[must_use]
    pub const fn host_request(&self) -> &ValidatedMountScopeRequest {
        &self.host_request
    }

    /// Returns the exact Host request body forwarded after local validation.
    #[must_use]
    pub fn host_request_body(&self) -> &[u8] {
        &self.host_request_body
    }

    /// Returns the structurally checked Host authorization quartet.
    #[must_use]
    pub fn host_authorization(&self) -> &ValidatedUntrustedAuthorizationArtifacts {
        &self.host_authorization
    }
}

/// Carries one validated opaque catalog commitment and its scope deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedMountCatalogPreparationResponse {
    catalog_commitment: ObjectDigest,
    valid_until_boottime_nanoseconds: u64,
}

impl ValidatedMountCatalogPreparationResponse {
    /// Returns the exact node-local catalog commitment for Mount authorization.
    #[must_use]
    pub const fn catalog_commitment(self) -> ObjectDigest {
        self.catalog_commitment
    }

    /// Returns the exclusive deadline of the retained Host observation.
    #[must_use]
    pub const fn valid_until_boottime_nanoseconds(self) -> u64 {
        self.valid_until_boottime_nanoseconds
    }
}

/// Decodes a bounded Mount 1.2 catalog preparation request.
///
/// # Errors
///
/// Rejects malformed or oversized fields, old Mount sessions, a release
/// action, missing Host authorization, non-Host-scope nested methods, or any
/// request ID, deadline, or assignment substitution between the three layers.
pub fn decode_mount_catalog_preparation(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedMountCatalogPreparation, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_MOUNT_CATALOG_PREPARATION_PACKET_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let request = PrepareMountCatalogRequest::decode_from_slice(bytes)
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
        ProtocolId::MountBroker,
        now_boottime_nanoseconds,
    )?;
    if header.protocol_version().minor() < 2 {
        return Err(ProtocolValidationError::MethodMismatch);
    }

    let mount_wire = request
        .mount_request
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("mount_request"))?;
    let mount_bytes = mount_wire.encode_to_vec();
    if mount_bytes.len() > MAXIMUM_MOUNT_CATALOG_INTENT_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let mount_request = decode_mount_request(&mount_bytes, peer, policy, now_boottime_nanoseconds)?;
    if mount_request.header() != &header
        || mount_request.action()
            == aos_proto::aos::sandbox::local::v1::MountAction::MOUNT_ACTION_RELEASE
    {
        return Err(ProtocolValidationError::InvalidField(
            "mount preparation intent",
        ));
    }

    let host_envelope =
        decode_request_envelope(&request.host_request_packet, ProtocolId::HostBroker, 0)?;
    if host_envelope.method() != BrokerMethod::BROKER_METHOD_HOST_OBSERVE_MOUNT_SCOPE
        || !host_envelope.descriptors().is_empty()
    {
        return Err(ProtocolValidationError::InvalidField("host_request_packet"));
    }
    let host_authorization =
        host_envelope
            .authorization()
            .cloned()
            .ok_or(ProtocolValidationError::InvalidField(
                "host_request_packet.authorization",
            ))?;
    let host_request = decode_mount_scope_request(
        host_envelope.body(),
        PeerCredentials {
            uid: 0,
            gid: 0,
            pid: Some(1),
        },
        PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_ROOT_MOUNT,
        },
        now_boottime_nanoseconds,
    )?;
    if host_request.header().request_id() != header.request_id()
        || host_request.header().deadline_boottime_nanoseconds()
            != header.deadline_boottime_nanoseconds()
        || host_request.fence() != mount_request.fence()
    {
        return Err(ProtocolValidationError::InvalidField(
            "mount and Host preparation binding",
        ));
    }

    Ok(ValidatedMountCatalogPreparation {
        header,
        mount_request,
        host_request,
        host_request_body: host_envelope.body().to_vec(),
        host_authorization,
    })
}

/// Encodes a successful preparation result for one exact request.
///
/// # Errors
///
/// Rejects a zero commitment or a deadline differing from the retained Host
/// request whose descriptors produced that commitment.
pub fn encode_mount_catalog_preparation_response(
    request: &ValidatedMountCatalogPreparation,
    catalog_commitment: ObjectDigest,
    valid_until_boottime_nanoseconds: u64,
) -> Result<Vec<u8>, ProtocolValidationError> {
    if catalog_commitment.as_bytes() == &[0; 32]
        || valid_until_boottime_nanoseconds
            != request
                .host_request()
                .header()
                .deadline_boottime_nanoseconds()
    {
        return Err(ProtocolValidationError::InvalidField(
            "mount catalog preparation response",
        ));
    }
    Ok(PrepareMountCatalogResponse {
        catalog_commitment: catalog_commitment.as_bytes().to_vec(),
        valid_until_boottime_nanoseconds,
        ..Default::default()
    }
    .encode_to_vec())
}

/// Decodes a preparation result against its exact Host observation deadline.
///
/// # Errors
///
/// Rejects malformed, unknown, sentinel, or substituted response fields.
pub fn decode_mount_catalog_preparation_response(
    bytes: &[u8],
    request: &ValidatedMountCatalogPreparation,
) -> Result<ValidatedMountCatalogPreparationResponse, ProtocolValidationError> {
    let response = PrepareMountCatalogResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty()
        || response.valid_until_boottime_nanoseconds
            != request
                .host_request()
                .header()
                .deadline_boottime_nanoseconds()
    {
        return Err(ProtocolValidationError::InvalidField(
            "mount catalog preparation response",
        ));
    }
    let catalog_commitment = ObjectDigest::from_bytes(exact_nonzero::<32>(
        &response.catalog_commitment,
        "catalog_commitment",
    )?);
    Ok(ValidatedMountCatalogPreparationResponse {
        catalog_commitment,
        valid_until_boottime_nanoseconds: response.valid_until_boottime_nanoseconds,
    })
}
