//! Defines the closed Host-origin namespace-identity readback body.
//!
//! A future separate authenticated RootMount method carries the same five
//! descriptors as Host ObserveMountScope, with additional Host-observed
//! identities in its response:
//!
//! ```text
//! assignment fence | runtime handle | payload-scope handle | cgroup hint |
//! Host boot ID | runtime invocation ID | mount nsfs dev/ino | user nsfs dev/ino
//! ```
//!
//! This structural codec does not authenticate a Host response or inspect an
//! FD. The Host producer must derive the values from retained type-checked
//! namespace pins under its current claim. Mount must compare the readback to
//! the actual received FDs and to a separately signed Controller target cut.

use aos_proto::aos::sandbox::local::v1::{
    ObserveMountScopeIdentityResponseV1, ObserveMountScopeResponse,
};
use buffa::Message as _;

use crate::mount_scope::{
    ValidatedMountScopeRequest, decode_mount_scope_response, encode_mount_scope_response,
};
use crate::payload_scope::ValidatedPayloadScopeResponse;
use crate::{ProtocolValidationError, exact_nonzero};

const MAXIMUM_IDENTITY_RESPONSE_BYTES: usize = 16 * 1024;

/// Records one nonzero Host-observed `nsfs` device and inode pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostNamespaceIdentityV1 {
    device: u64,
    inode: u64,
}

impl HostNamespaceIdentityV1 {
    /// Constructs a structurally valid namespace identity candidate.
    ///
    /// # Errors
    ///
    /// Rejects zero device or inode values. This does not inspect a descriptor.
    pub fn new(device: u64, inode: u64) -> Result<Self, ProtocolValidationError> {
        if device == 0 || inode == 0 {
            return Err(ProtocolValidationError::InvalidField(
                "Host namespace identity",
            ));
        }
        Ok(Self { device, inode })
    }

    /// Returns the observed `nsfs` device number.
    #[must_use]
    pub const fn device(self) -> u64 {
        self.device
    }

    /// Returns the observed namespace inode number.
    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }
}

/// Retains a structurally checked Host response without granting Mount authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMountScopeIdentityResponseV1 {
    scope: ValidatedPayloadScopeResponse,
    host_boot_id: [u8; 16],
    runtime_invocation_id: [u8; 16],
    mount_namespace: HostNamespaceIdentityV1,
    user_namespace: HostNamespaceIdentityV1,
}

impl ValidatedMountScopeIdentityResponseV1 {
    /// Returns the exact assignment, runtime, and Host-minted scope echoed by the response.
    #[must_use]
    pub const fn scope(&self) -> &ValidatedPayloadScopeResponse {
        &self.scope
    }

    /// Returns the claimed Host kernel boot epoch.
    #[must_use]
    pub const fn host_boot_id(&self) -> &[u8; 16] {
        &self.host_boot_id
    }

    /// Returns the claimed retained runtime invocation epoch.
    #[must_use]
    pub const fn runtime_invocation_id(&self) -> &[u8; 16] {
        &self.runtime_invocation_id
    }

    /// Returns the claimed mount namespace identity.
    #[must_use]
    pub const fn mount_namespace(&self) -> HostNamespaceIdentityV1 {
        self.mount_namespace
    }

    /// Returns the claimed user namespace identity.
    #[must_use]
    pub const fn user_namespace(&self) -> HostNamespaceIdentityV1 {
        self.user_namespace
    }
}

/// Encodes a bounded candidate from values supplied by a future Host producer.
///
/// The future producer must extract identities from retained `NamespaceFd`
/// pins after Host authorization and kernel rechecks. This function itself
/// cannot establish their origin.
///
/// # Errors
///
/// Rejects zero Host epochs, invalid cgroup hints, or an oversized response.
pub fn encode_mount_scope_identity_response_v1(
    request: &ValidatedMountScopeRequest,
    leader_cgroup_hint: &[u8],
    host_boot_id: &[u8; 16],
    runtime_invocation_id: &[u8; 16],
    mount_namespace: HostNamespaceIdentityV1,
    user_namespace: HostNamespaceIdentityV1,
) -> Result<Vec<u8>, ProtocolValidationError> {
    exact_nonzero::<16>(host_boot_id, "host_boot_id")?;
    exact_nonzero::<16>(runtime_invocation_id, "runtime_invocation_id")?;
    let scope = encode_mount_scope_response(request, leader_cgroup_hint)?;
    let scope = ObserveMountScopeResponse::decode_from_slice(&scope)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    let response = ObserveMountScopeIdentityResponseV1 {
        fence: scope.fence,
        runtime_handle: scope.runtime_handle,
        payload_scope_handle: scope.payload_scope_handle,
        leader_cgroup_hint: scope.leader_cgroup_hint,
        host_boot_id: host_boot_id.to_vec(),
        runtime_invocation_id: runtime_invocation_id.to_vec(),
        mount_namespace_device: mount_namespace.device(),
        mount_namespace_inode: mount_namespace.inode(),
        user_namespace_device: user_namespace.device(),
        user_namespace_inode: user_namespace.inode(),
        ..Default::default()
    };
    let bytes = response.encode_to_vec();
    if bytes.len() > MAXIMUM_IDENTITY_RESPONSE_BYTES {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    Ok(bytes)
}

/// Decodes the exact readback metadata expected for one RootMount scope query.
///
/// The result must still come from a separately authenticated Host method and
/// must be compared to the actual five received descriptors before use.
///
/// # Errors
///
/// Rejects oversized or malformed packets, unknown fields, substituted scope
/// or assignment, zero Host epochs, and invalid namespace identities.
pub fn decode_mount_scope_identity_response_v1(
    bytes: &[u8],
    request: &ValidatedMountScopeRequest,
) -> Result<ValidatedMountScopeIdentityResponseV1, ProtocolValidationError> {
    if bytes.len() > MAXIMUM_IDENTITY_RESPONSE_BYTES {
        return Err(ProtocolValidationError::ResponseTooLarge);
    }
    let response = ObserveMountScopeIdentityResponseV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let scope = ObserveMountScopeResponse {
        fence: response.fence,
        runtime_handle: response.runtime_handle,
        payload_scope_handle: response.payload_scope_handle,
        leader_cgroup_hint: response.leader_cgroup_hint,
        ..Default::default()
    };
    let scope = decode_mount_scope_response(&scope.encode_to_vec(), request)?;

    Ok(ValidatedMountScopeIdentityResponseV1 {
        scope,
        host_boot_id: exact_nonzero::<16>(&response.host_boot_id, "host_boot_id")?,
        runtime_invocation_id: exact_nonzero::<16>(
            &response.runtime_invocation_id,
            "runtime_invocation_id",
        )?,
        mount_namespace: HostNamespaceIdentityV1::new(
            response.mount_namespace_device,
            response.mount_namespace_inode,
        )?,
        user_namespace: HostNamespaceIdentityV1::new(
            response.user_namespace_device,
            response.user_namespace_inode,
        )?,
    })
}

#[cfg(test)]
mod tests {
    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Audience, ObserveMountScopeRequest, RequestHeader,
    };

    use super::*;
    use crate::mount_scope::decode_mount_scope_request;
    use crate::semantics::host::runtime_handle_v1;
    use crate::{PeerCredentials, PeerPolicy};

    fn request() -> ValidatedMountScopeRequest {
        let raw = ObserveMountScopeRequest {
            header: Some(RequestHeader {
                protocol_major: 1,
                protocol_minor: 0,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_ROOT_MOUNT.into(),
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
            payload_scope_handle: vec![5; 32],
            ..Default::default()
        };
        decode_mount_scope_request(
            &raw.encode_to_vec(),
            PeerCredentials {
                uid: 0,
                gid: 0,
                pid: Some(7),
            },
            PeerPolicy {
                uid: 0,
                gid: Some(0),
                audience: Audience::AUDIENCE_ROOT_MOUNT,
            },
            100,
        )
        .unwrap()
    }

    fn response(request: &ValidatedMountScopeRequest) -> Vec<u8> {
        encode_mount_scope_identity_response_v1(
            request,
            b"init.scope",
            &[6; 16],
            &[7; 16],
            HostNamespaceIdentityV1::new(8, 9).unwrap(),
            HostNamespaceIdentityV1::new(10, 11).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn versioned_readback_is_distinct_from_legacy_scope_response() {
        let request = request();
        let bytes = response(&request);
        let decoded = decode_mount_scope_identity_response_v1(&bytes, &request).unwrap();

        assert_eq!(decoded.scope().fence(), request.fence());
        assert_eq!(decoded.scope().payload_scope_handle(), &[5; 32]);
        assert_eq!(decoded.host_boot_id(), &[6; 16]);
        assert_eq!(decoded.runtime_invocation_id(), &[7; 16]);
        assert_eq!(decoded.mount_namespace().device(), 8);
        assert_eq!(decoded.mount_namespace().inode(), 9);
        assert_eq!(decoded.user_namespace().device(), 10);
        assert_eq!(decoded.user_namespace().inode(), 11);
        assert!(decode_mount_scope_response(&bytes, &request).is_err());
        let legacy = encode_mount_scope_response(&request, b"init.scope").unwrap();
        assert!(decode_mount_scope_identity_response_v1(&legacy, &request).is_err());
    }

    #[test]
    fn substituted_scope_epoch_and_namespace_identities_fail_closed() {
        let request = request();
        let raw =
            ObserveMountScopeIdentityResponseV1::decode_from_slice(&response(&request)).unwrap();
        let mut cases = Vec::new();

        let mut wrong_scope = raw.clone();
        wrong_scope.payload_scope_handle[0] ^= 1;
        cases.push(wrong_scope);

        let mut wrong_assignment = raw.clone();
        wrong_assignment
            .fence
            .get_or_insert_default()
            .assignment_epoch += 1;
        cases.push(wrong_assignment);

        let mut wrong_runtime = raw.clone();
        wrong_runtime.runtime_handle[0] ^= 1;
        cases.push(wrong_runtime);

        let mut no_boot = raw.clone();
        no_boot.host_boot_id.fill(0);
        cases.push(no_boot);

        let mut no_invocation = raw.clone();
        no_invocation.runtime_invocation_id.clear();
        cases.push(no_invocation);

        let mut no_mount_inode = raw.clone();
        no_mount_inode.mount_namespace_inode = 0;
        cases.push(no_mount_inode);

        let mut no_user_device = raw;
        no_user_device.user_namespace_device = 0;
        cases.push(no_user_device);

        for candidate in cases {
            assert!(
                decode_mount_scope_identity_response_v1(&candidate.encode_to_vec(), &request)
                    .is_err()
            );
        }

        let mut unknown = response(&request);
        unknown.extend_from_slice(&[0x98, 0x06, 0x01]);
        assert!(decode_mount_scope_identity_response_v1(&unknown, &request).is_err());
        assert!(
            decode_mount_scope_identity_response_v1(
                &vec![0; MAXIMUM_IDENTITY_RESPONSE_BYTES + 1],
                &request,
            )
            .is_err()
        );
    }
}
