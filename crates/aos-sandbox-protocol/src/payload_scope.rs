//! Bounded authority-bearing Host payload-scope request and response bodies.
//!
//! The response has the following closed descriptor order; metadata never
//! substitutes for validating the received kernel objects:
//!
//! ```text
//! SCM_RIGHTS[0] = retained payload leader pidfd
//! SCM_RIGHTS[1] = retained payload-subtree cgroup O_PATH descriptor
//! leader_cgroup_hint = empty (exact) or strict relative descendant path
//! ```

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, BrokerDescriptorRole, ObservePayloadScopeRequest, ObservePayloadScopeResponse,
};
use aos_sandbox_core::ProtocolId;
use buffa::Message as _;

use crate::semantics::host::runtime_handle_v1;
use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedAssignmentFence,
    ValidatedHeader, exact_nonzero, validate_fence, validate_request_header,
};

/// Bounds either protobuf body before decoding or allocating its fields.
pub const MAXIMUM_PAYLOAD_SCOPE_BODY_BYTES: usize = 8192;
/// Bounds the raw relative leader-cgroup locator independently of the body.
pub const MAXIMUM_LEADER_CGROUP_HINT_BYTES: usize = 4096;
/// Fixes the complete successful response descriptor order.
pub const PAYLOAD_SCOPE_DESCRIPTOR_ROLES: [BrokerDescriptorRole; 2] = [
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_LEADER_PIDFD,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_CGROUP,
];

/// Carries a structurally checked request, without proving signed authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPayloadScopeRequest {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    runtime_handle: [u8; 32],
}

impl ValidatedPayloadScopeRequest {
    /// Returns the peer-checked request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }
    /// Returns the exact requested assignment fence.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }
    /// Returns the checked deterministic runtime handle.
    #[must_use]
    pub const fn runtime_handle(&self) -> &[u8; 32] {
        &self.runtime_handle
    }
}

/// Carries response metadata linked to the expected runtime, not kernel authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPayloadScopeResponse {
    fence: ValidatedAssignmentFence,
    runtime_handle: [u8; 32],
    payload_scope_handle: [u8; 32],
    leader_cgroup_hint: Vec<u8>,
}

impl ValidatedPayloadScopeResponse {
    /// Returns the exact echoed assignment fence.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }
    /// Returns the exact echoed runtime handle.
    #[must_use]
    pub const fn runtime_handle(&self) -> &[u8; 32] {
        &self.runtime_handle
    }
    /// Returns the broker's opaque retained-pin handle, not standalone authority.
    #[must_use]
    pub const fn payload_scope_handle(&self) -> &[u8; 32] {
        &self.payload_scope_handle
    }
    /// Returns the bounded raw locator requiring strict kernel resolution.
    #[must_use]
    pub fn leader_cgroup_hint(&self) -> &[u8] {
        &self.leader_cgroup_hint
    }
}

/// Decodes an exact payload-scope request under a fixed allocation ceiling.
///
/// # Errors
///
/// Rejects oversized or malformed bodies, unknown fields, invalid peer/header
/// bindings, carriers older than Host 1.2, or an inconsistent fence/handle.
pub fn decode_payload_scope_request(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedPayloadScopeRequest, ProtocolValidationError> {
    check_body_bound(bytes)?;
    let request = ObservePayloadScopeRequest::decode_from_slice(bytes)
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
    if header.protocol_version().minor() < 2 {
        return Err(ProtocolValidationError::MethodMismatch);
    }
    let fence = validate_fence(
        request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    let runtime_handle = validate_runtime_handle(&fence, &request.runtime_handle)?;
    Ok(ValidatedPayloadScopeRequest {
        header,
        fence,
        runtime_handle,
    })
}

/// Encodes one closed response without transferring or validating descriptors.
///
/// # Errors
///
/// Rejects sentinel or inconsistent handles and invalid or excessive hints.
pub fn encode_payload_scope_response(
    fence: &ValidatedAssignmentFence,
    runtime_handle: &[u8; 32],
    payload_scope_handle: &[u8; 32],
    leader_cgroup_hint: &[u8],
) -> Result<Vec<u8>, ProtocolValidationError> {
    validate_runtime_handle(fence, runtime_handle)?;
    exact_nonzero::<32>(payload_scope_handle, "payload_scope_handle")?;
    validate_hint(leader_cgroup_hint)?;
    let response = ObservePayloadScopeResponse {
        fence: Some(AssignmentFence {
            sandbox_id: fence.sandbox_id().to_vec(),
            incarnation_id: fence.incarnation_id().to_vec(),
            assignment_epoch: fence.assignment_epoch(),
            desired_generation: fence.desired_generation(),
            assignment_digest: fence.assignment_digest().to_vec(),
            ..Default::default()
        })
        .into(),
        runtime_handle: runtime_handle.to_vec(),
        payload_scope_handle: payload_scope_handle.to_vec(),
        leader_cgroup_hint: leader_cgroup_hint.to_vec(),
        ..Default::default()
    };
    let bytes = response.encode_to_vec();
    check_body_bound(&bytes)?;
    Ok(bytes)
}

/// Decodes response metadata against the request's exact expected assignment.
///
/// # Errors
///
/// Rejects malformed, unknown, oversized, substituted, or invalid fields.
/// Successful decoding does not authenticate descriptors or current ownership.
pub fn decode_payload_scope_response(
    bytes: &[u8],
    expected_fence: &ValidatedAssignmentFence,
    expected_runtime_handle: &[u8; 32],
) -> Result<ValidatedPayloadScopeResponse, ProtocolValidationError> {
    check_body_bound(bytes)?;
    let response = ObservePayloadScopeResponse::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let fence = validate_fence(
        response
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    let runtime_handle = validate_runtime_handle(&fence, &response.runtime_handle)?;
    if &fence != expected_fence || &runtime_handle != expected_runtime_handle {
        return Err(ProtocolValidationError::InvalidField(
            "payload scope response binding",
        ));
    }
    let payload_scope_handle =
        exact_nonzero::<32>(&response.payload_scope_handle, "payload_scope_handle")?;
    validate_hint(&response.leader_cgroup_hint)?;
    Ok(ValidatedPayloadScopeResponse {
        fence,
        runtime_handle,
        payload_scope_handle,
        leader_cgroup_hint: response.leader_cgroup_hint,
    })
}

fn check_body_bound(bytes: &[u8]) -> Result<(), ProtocolValidationError> {
    if bytes.len() > MAXIMUM_PAYLOAD_SCOPE_BODY_BYTES {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    Ok(())
}

pub(crate) fn validate_runtime_handle(
    fence: &ValidatedAssignmentFence,
    bytes: &[u8],
) -> Result<[u8; 32], ProtocolValidationError> {
    let handle = exact_nonzero::<32>(bytes, "runtime_handle")?;
    if handle
        != runtime_handle_v1(
            fence.incarnation_id(),
            fence.assignment_epoch(),
            fence.assignment_digest(),
        )
    {
        return Err(ProtocolValidationError::InvalidField("runtime_handle"));
    }
    Ok(handle)
}

fn validate_hint(hint: &[u8]) -> Result<(), ProtocolValidationError> {
    if hint.len() > MAXIMUM_LEADER_CGROUP_HINT_BYTES
        || hint.contains(&0)
        || (!hint.is_empty()
            && hint
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b".."))
    {
        return Err(ProtocolValidationError::InvalidField("leader_cgroup_hint"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantics::payload_scope::canonical_payload_scope_semantics_v1;
    use aos_proto::aos::sandbox::local::v1::{Audience, RequestHeader};

    fn fixture() -> ObservePayloadScopeRequest {
        ObservePayloadScopeRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 2,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
                deadline_boottime_nanoseconds: 101,
                maximum_response_bytes: 8192,
                ..Default::default()
            })
            .into(),
            fence: Some(AssignmentFence {
                sandbox_id: vec![2; 16],
                incarnation_id: vec![3; 16],
                assignment_epoch: 1,
                desired_generation: 2,
                assignment_digest: vec![4; 32],
                ..Default::default()
            })
            .into(),
            runtime_handle: runtime_handle_v1(&[3; 16], 1, &[4; 32]).to_vec(),
            ..Default::default()
        }
    }

    fn decode(bytes: &[u8]) -> Result<ValidatedPayloadScopeRequest, ProtocolValidationError> {
        decode_payload_scope_request(
            bytes,
            PeerCredentials {
                uid: 100,
                gid: 200,
                pid: Some(7),
            },
            PeerPolicy {
                uid: 100,
                gid: Some(200),
                audience: Audience::AUDIENCE_NODE_CONTROLLER,
            },
            100,
        )
    }

    #[test]
    fn strict_requests_bind_full_fence_and_carrier() {
        let raw = fixture();
        let request = decode(&raw.encode_to_vec()).unwrap();
        let original = canonical_payload_scope_semantics_v1(&request).unwrap();
        assert_eq!(
            original.commitment().digest().as_bytes(),
            &[
                0xf9, 0x6d, 0x22, 0x3f, 0x42, 0x6f, 0xc3, 0x50, 0xb0, 0x7d, 0x36, 0x07, 0xa4, 0x6b,
                0x8e, 0xbb, 0x1a, 0xc8, 0x87, 0xa9, 0xe4, 0x37, 0x6f, 0x42, 0x80, 0x07, 0xce, 0xc8,
                0x9a, 0x4b, 0xf7, 0x5e,
            ]
        );
        for mutate in [
            (|r: &mut ObservePayloadScopeRequest| {
                r.header.get_or_insert_default().protocol_minor = 1
            }) as fn(&mut ObservePayloadScopeRequest),
            |r| r.fence.get_or_insert_default().assignment_epoch = 0,
            |r| r.fence.get_or_insert_default().desired_generation = 0,
            |r| r.runtime_handle[0] ^= 1,
            |r| r.header.get_or_insert_default().request_id = vec![0; 16],
        ] {
            let mut changed = raw.clone();
            mutate(&mut changed);
            assert!(decode(&changed.encode_to_vec()).is_err());
        }
        let mut unknown = raw.encode_to_vec();
        unknown.extend_from_slice(&[0x78, 1]);
        assert_eq!(
            decode(&unknown),
            Err(ProtocolValidationError::UnknownFields)
        );
        assert!(decode(&vec![0; MAXIMUM_PAYLOAD_SCOPE_BODY_BYTES + 1]).is_err());
        let mut changed = raw.clone();
        changed.fence.get_or_insert_default().desired_generation += 1;
        assert_ne!(
            original.commitment(),
            canonical_payload_scope_semantics_v1(&decode(&changed.encode_to_vec()).unwrap())
                .unwrap()
                .commitment()
        );
        let mut changed = raw;
        changed
            .header
            .get_or_insert_default()
            .maximum_response_bytes += 1;
        assert_eq!(
            original,
            canonical_payload_scope_semantics_v1(&decode(&changed.encode_to_vec()).unwrap())
                .unwrap()
        );
    }

    #[test]
    fn response_hints_are_raw_bounded_relative_locators() {
        let request = decode(&fixture().encode_to_vec()).unwrap();
        for hint in [
            b"".as_slice(),
            b"init.scope",
            b"nested/service.scope",
            &[0xff],
        ] {
            let bytes = encode_payload_scope_response(
                request.fence(),
                request.runtime_handle(),
                &[5; 32],
                hint,
            )
            .unwrap();
            let response =
                decode_payload_scope_response(&bytes, request.fence(), request.runtime_handle())
                    .unwrap();
            assert_eq!(response.leader_cgroup_hint(), hint);
            assert_eq!(response.payload_scope_handle(), &[5; 32]);
            let mut unknown = bytes.clone();
            unknown.extend_from_slice(&[0x78, 1]);
            assert!(
                decode_payload_scope_response(&unknown, request.fence(), request.runtime_handle())
                    .is_err()
            );
            let mut wrong = *request.fence();
            wrong.desired_generation += 1;
            assert!(
                decode_payload_scope_response(&bytes, &wrong, request.runtime_handle()).is_err()
            );
        }
        for hint in [
            b"/init.scope".as_slice(),
            b".",
            b"..",
            b"a/../b",
            b"a/./b",
            b"a//b",
            b"a/",
            b"a\0b",
        ] {
            assert!(
                encode_payload_scope_response(
                    request.fence(),
                    request.runtime_handle(),
                    &[5; 32],
                    hint
                )
                .is_err()
            );
        }
        assert!(
            encode_payload_scope_response(request.fence(), request.runtime_handle(), &[0; 32], b"")
                .is_err()
        );
        assert!(
            encode_payload_scope_response(
                request.fence(),
                request.runtime_handle(),
                &[5; 32],
                &vec![b'a'; 4096]
            )
            .is_ok()
        );
        assert!(
            encode_payload_scope_response(
                request.fence(),
                request.runtime_handle(),
                &[5; 32],
                &vec![b'a'; 4097]
            )
            .is_err()
        );
    }
}
