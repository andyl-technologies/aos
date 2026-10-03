//! Storage-only query for an exact Host-retained consumer cgroup.
//!
//! ```text
//! Host method 34, Storage audience 6
//! request: current assignment fence + runtime handle + retained scope handle
//! success SCM_RIGHTS: [payload leader pidfd, exact leader cgroup-v2 O_PATH]
//! ```
//!
//! This is a read-only physical observation. It does not assert a named View,
//! Attachment, RootMount holder, Storage lease, or kernel grant.

use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, Audience, BrokerDescriptorRole, ObserveConsumerCgroupRequestV1,
    ObserveConsumerCgroupResponseV1,
};
use aos_sandbox_core::ProtocolId;
use buffa::Message as _;

use crate::payload_scope::validate_runtime_handle;
use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedAssignmentFence,
    ValidatedHeader, exact_nonzero, validate_fence, validate_request_header,
};

/// Bounds the complete protobuf request and reply before decoding.
pub const MAXIMUM_CONSUMER_CGROUP_BODY_BYTES_V1: usize = 8192;

/// Fixes the only successful descriptor order for Host method 34.
pub const CONSUMER_CGROUP_DESCRIPTOR_ROLES_V1: [BrokerDescriptorRole; 2] = [
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_LEADER_PIDFD,
    BrokerDescriptorRole::BROKER_DESCRIPTOR_ROLE_PAYLOAD_CGROUP,
];

/// Retains a structurally validated Storage query, without effect authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedConsumerCgroupRequestV1 {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    runtime_handle: [u8; 32],
    payload_scope_handle: [u8; 32],
}

impl ValidatedConsumerCgroupRequestV1 {
    /// Returns the peer-checked request header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the exact current assignment requested.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the assignment-derived runtime handle.
    #[must_use]
    pub const fn runtime_handle(&self) -> &[u8; 32] {
        &self.runtime_handle
    }

    /// Returns the exact retained Host scope handle.
    #[must_use]
    pub const fn payload_scope_handle(&self) -> &[u8; 32] {
        &self.payload_scope_handle
    }
}

/// Decodes method 34 only for the exact Storage audience and root account.
///
/// # Errors
///
/// Rejects oversized or noncanonical bodies, invalid peer/header binding,
/// expired deadline, or inconsistent fence and runtime/scope handles.
pub fn decode_consumer_cgroup_request_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedConsumerCgroupRequestV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_CONSUMER_CGROUP_BODY_BYTES_V1 {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    if policy.audience != Audience::AUDIENCE_STORAGE_BROKER || policy.uid != 0 || peer.uid != 0 {
        return Err(ProtocolValidationError::MethodMismatch);
    }

    let request = ObserveConsumerCgroupRequestV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !request.__buffa_unknown_fields.is_empty() || request.encode_to_vec() != bytes {
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
    let fence = validate_fence(
        request
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    let runtime_handle = validate_runtime_handle(&fence, &request.runtime_handle)?;
    let payload_scope_handle =
        exact_nonzero::<32>(&request.payload_scope_handle, "payload_scope_handle")?;

    Ok(ValidatedConsumerCgroupRequestV1 {
        header,
        fence,
        runtime_handle,
        payload_scope_handle,
    })
}

/// Retains response comparison facts, not the received kernel objects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedConsumerCgroupResponseV1 {
    boot_id: [u8; 16],
    cgroup_kernfs_id: u64,
}

impl ValidatedConsumerCgroupResponseV1 {
    /// Returns Host's current boot UUID for comparison to local procfs.
    #[must_use]
    pub const fn boot_id(self) -> [u8; 16] {
        self.boot_id
    }

    /// Returns Host's full cgroup-v2 kernfs ID for FD readback comparison.
    #[must_use]
    pub const fn cgroup_kernfs_id(self) -> u64 {
        self.cgroup_kernfs_id
    }
}

/// Encodes Host-owned boot and exact cgroup identity for one checked request.
///
/// # Errors
///
/// Rejects nil boot identity, zero cgroup ID, or an excessive encoded body.
pub fn encode_consumer_cgroup_response_v1(
    request: &ValidatedConsumerCgroupRequestV1,
    boot_id: [u8; 16],
    cgroup_kernfs_id: u64,
) -> Result<Vec<u8>, ProtocolValidationError> {
    if boot_id == [0; 16] || cgroup_kernfs_id == 0 {
        return Err(ProtocolValidationError::InvalidField(
            "consumer cgroup identity",
        ));
    }
    let body = ObserveConsumerCgroupResponseV1 {
        fence: Some(AssignmentFence {
            sandbox_id: request.fence().sandbox_id().to_vec(),
            incarnation_id: request.fence().incarnation_id().to_vec(),
            assignment_epoch: request.fence().assignment_epoch(),
            desired_generation: request.fence().desired_generation(),
            assignment_digest: request.fence().assignment_digest().to_vec(),
            ..Default::default()
        })
        .into(),
        runtime_handle: request.runtime_handle().to_vec(),
        payload_scope_handle: request.payload_scope_handle().to_vec(),
        boot_id: boot_id.to_vec(),
        cgroup_kernfs_id,
        ..Default::default()
    }
    .encode_to_vec();
    if body.len() > MAXIMUM_CONSUMER_CGROUP_BODY_BYTES_V1 {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    Ok(body)
}

/// Decodes and binds Host metadata to the exact request before adopting FDs.
///
/// # Errors
///
/// Rejects malformed/unknown fields, substituted assignment or handles, nil
/// boot identity, zero cgroup ID, or oversized body.
pub fn decode_consumer_cgroup_response_v1(
    bytes: &[u8],
    request: &ValidatedConsumerCgroupRequestV1,
) -> Result<ValidatedConsumerCgroupResponseV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_CONSUMER_CGROUP_BODY_BYTES_V1 {
        return Err(ProtocolValidationError::RequestTooLarge);
    }
    let response = ObserveConsumerCgroupResponseV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let fence = validate_fence(
        response
            .fence
            .as_option()
            .ok_or(ProtocolValidationError::MissingField("fence"))?,
    )?;
    let boot_id = exact_nonzero::<16>(&response.boot_id, "boot_id")?;
    if &fence != request.fence()
        || response.runtime_handle.as_slice() != request.runtime_handle()
        || response.payload_scope_handle.as_slice() != request.payload_scope_handle()
        || response.cgroup_kernfs_id == 0
    {
        return Err(ProtocolValidationError::InvalidField(
            "consumer cgroup response binding",
        ));
    }
    Ok(ValidatedConsumerCgroupResponseV1 {
        boot_id,
        cgroup_kernfs_id: response.cgroup_kernfs_id,
    })
}

#[cfg(test)]
mod tests {
    use crate::semantics::host::runtime_handle_v1;
    use aos_proto::aos::sandbox::local::v1::{AssignmentFence, RequestHeader};

    use super::*;

    fn fixture() -> (Vec<u8>, PeerCredentials, PeerPolicy) {
        let peer = PeerCredentials {
            uid: 0,
            gid: 0,
            pid: Some(47),
        };
        let policy = PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_STORAGE_BROKER,
        };
        let fence = AssignmentFence {
            sandbox_id: vec![1; 16],
            incarnation_id: vec![2; 16],
            assignment_epoch: 3,
            desired_generation: 4,
            assignment_digest: vec![5; 32],
            ..Default::default()
        };
        let request = ObserveConsumerCgroupRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![6; 16],
                audience: Audience::AUDIENCE_STORAGE_BROKER.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 8192,
                ..Default::default()
            })
            .into(),
            runtime_handle: runtime_handle_v1(&[2; 16], 3, &[5; 32]).to_vec(),
            fence: Some(fence).into(),
            payload_scope_handle: vec![7; 32],
            ..Default::default()
        };
        (request.encode_to_vec(), peer, policy)
    }

    #[test]
    fn exact_storage_role_and_deadline_are_required() {
        let (body, peer, policy) = fixture();
        assert!(decode_consumer_cgroup_request_v1(&body, peer, policy, 99).is_ok());
        assert!(decode_consumer_cgroup_request_v1(&body, peer, policy, 100).is_err());
        assert!(
            decode_consumer_cgroup_request_v1(
                &body,
                peer,
                PeerPolicy {
                    audience: Audience::AUDIENCE_ROOT_MOUNT,
                    ..policy
                },
                99,
            )
            .is_err()
        );
    }

    #[test]
    fn response_binds_boot_cgroup_and_exact_scope() {
        let (body, peer, policy) = fixture();
        let request = decode_consumer_cgroup_request_v1(&body, peer, policy, 99).unwrap();
        let response = encode_consumer_cgroup_response_v1(&request, [8; 16], 4711).unwrap();
        let validated = decode_consumer_cgroup_response_v1(&response, &request).unwrap();
        assert_eq!(validated.boot_id(), [8; 16]);
        assert_eq!(validated.cgroup_kernfs_id(), 4711);

        let mut forged = ObserveConsumerCgroupResponseV1::decode_from_slice(&response).unwrap();
        forged.payload_scope_handle[0] ^= 1;
        assert!(decode_consumer_cgroup_response_v1(&forged.encode_to_vec(), &request).is_err());
        forged.payload_scope_handle[0] ^= 1;
        forged.cgroup_kernfs_id = 0;
        assert!(decode_consumer_cgroup_response_v1(&forged.encode_to_vec(), &request).is_err());
        forged.cgroup_kernfs_id = 4711;
        forged.boot_id = vec![0; 16];
        assert!(decode_consumer_cgroup_response_v1(&forged.encode_to_vec(), &request).is_err());
    }

    #[test]
    fn duplicate_or_reordered_known_fields_are_not_canonical() {
        let (body, peer, policy) = fixture();
        let request = decode_consumer_cgroup_request_v1(&body, peer, policy, 99).unwrap();
        let response = encode_consumer_cgroup_response_v1(&request, [8; 16], 4711).unwrap();

        let mut duplicate_request = body.clone();
        duplicate_request.extend_from_slice(&[0x22, 32]);
        duplicate_request.extend_from_slice(&[7; 32]);
        assert!(decode_consumer_cgroup_request_v1(&duplicate_request, peer, policy, 99).is_err());
        assert!(
            decode_consumer_cgroup_request_v1(&swap_first_two_fields(&body), peer, policy, 99)
                .is_err()
        );

        let mut duplicate_response = response.clone();
        duplicate_response.extend_from_slice(&[0x28, 0xe7, 0x24]);
        assert!(decode_consumer_cgroup_response_v1(&duplicate_response, &request).is_err());
        assert!(
            decode_consumer_cgroup_response_v1(&swap_first_two_fields(&response), &request)
                .is_err()
        );
    }

    fn swap_first_two_fields(bytes: &[u8]) -> Vec<u8> {
        let first_end = length_delimited_field_end(bytes, 0);
        let second_end = length_delimited_field_end(bytes, first_end);
        let mut swapped = Vec::with_capacity(bytes.len());
        swapped.extend_from_slice(&bytes[first_end..second_end]);
        swapped.extend_from_slice(&bytes[..first_end]);
        swapped.extend_from_slice(&bytes[second_end..]);
        swapped
    }

    fn length_delimited_field_end(bytes: &[u8], start: usize) -> usize {
        assert_eq!(bytes[start] & 7, 2);
        let mut cursor = start + 1;
        let mut length = 0_usize;
        let mut shift = 0;
        loop {
            let byte = bytes[cursor];
            cursor += 1;
            length |= usize::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        cursor + length
    }
}
