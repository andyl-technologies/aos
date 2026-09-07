//! RootMount-only acquisition of a Host-retained namespace and root scope.
//!
//! The exact opaque payload scope is part of the signed query, not an optional
//! hint. A reboot replacing that scope requires a new query and authority.
//! Successful replies carry the following closed descriptor table:
//!
//! ```text
//! SCM_RIGHTS = [payload pidfd, payload cgroup, root, mount namespace, user namespace]
//! ```
//!
//! Structural validation here does not authenticate the Host process, prove
//! descriptor identities, or authorize any Mount effect.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerDescriptorRole, ObserveMountScopeRequest,
};
use aos_sandbox_core::ProtocolId;
use buffa::Message as _;

use crate::payload_scope::{
    MAXIMUM_PAYLOAD_SCOPE_BODY_BYTES, ValidatedPayloadScopeResponse, decode_payload_scope_response,
    encode_payload_scope_response, validate_runtime_handle,
};
use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedAssignmentFence,
    ValidatedHeader, exact_nonzero, validate_fence, validate_request_header,
};

/// Fixes the complete successful RootMount response descriptor order.
pub const MOUNT_SCOPE_DESCRIPTOR_ROLES: [BrokerDescriptorRole; 5] = [
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_LEADER_PIDFD,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_CGROUP,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_TARGET_ROOT,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_MOUNT_NAMESPACE,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_USER_NAMESPACE,
];

/// Carries a structurally checked exact-scope query without signed authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMountScopeRequest {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    runtime_handle: [u8; 32],
    payload_scope_handle: [u8; 32],
}

impl ValidatedMountScopeRequest {
    /// Returns the peer-checked RootMount request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact assignment fence requested for observation.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the deterministic runtime handle bound to the assignment.
    #[must_use]
    pub const fn runtime_handle(&self) -> &[u8; 32] {
        &self.runtime_handle
    }

    /// Returns the exact required retained payload scope, not standalone authority.
    #[must_use]
    pub const fn payload_scope_handle(&self) -> &[u8; 32] {
        &self.payload_scope_handle
    }
}

/// Decodes a bounded RootMount query for one exact retained Host scope.
///
/// # Errors
///
/// Rejects malformed, unknown, or oversized fields, a non-RootMount peer policy,
/// invalid headers, Host versions before 1.3, and sentinel or mismatched handles.
pub fn decode_mount_scope_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedMountScopeRequest, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_PAYLOAD_SCOPE_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    if policy.audience != Audience::AUDIENCE_ROOT_MOUNT || policy.uid != 0 || peer.uid != 0 {
        return Err(ProtocolValidationError::MethodMismatch);
    }

    let request = ObserveMountScopeRequest::decode_from_slice(bytes)
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
    if header.protocol_version().minor() < 3 {
        return Err(ProtocolValidationError::MethodMismatch);
    }

    let fence = validate_fence(
        request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    let runtime_handle = validate_runtime_handle(&fence, &request.runtime_handle)?;
    let payload_scope_handle =
        exact_nonzero::<32>(&request.payload_scope_handle, "payload_scope_handle")?;

    Ok(ValidatedMountScopeRequest {
        header,
        fence,
        runtime_handle,
        payload_scope_handle,
    })
}

/// Encodes response metadata for the exact requested retained scope.
///
/// The two scope response messages deliberately share the same field layout;
/// the envelope method and its closed descriptor roles distinguish them.
///
/// # Errors
///
/// Rejects invalid or excessive relative leader-cgroup hints.
pub fn encode_mount_scope_response(
    request: &ValidatedMountScopeRequest,
    leader_cgroup_hint: &[u8],
) -> Result<Vec<u8>, ProtocolValidationError> {
    encode_payload_scope_response(
        request.fence(),
        request.runtime_handle(),
        request.payload_scope_handle(),
        leader_cgroup_hint,
    )
}

/// Decodes metadata without permitting substitution of a replacement scope.
///
/// # Errors
///
/// Rejects malformed or oversized metadata, unknown fields, and any assignment,
/// runtime, or payload-scope handle differing from the exact request.
pub fn decode_mount_scope_response(
    bytes: &[u8],
    request: &ValidatedMountScopeRequest,
) -> Result<ValidatedPayloadScopeResponse, ProtocolValidationError> {
    let response = decode_payload_scope_response(bytes, request.fence(), request.runtime_handle())?;
    if response.payload_scope_handle() != request.payload_scope_handle() {
        return Err(ProtocolValidationError::InvalidField(
            "mount scope response binding",
        ));
    }

    Ok(response)
}

#[cfg(test)]
mod tests;
