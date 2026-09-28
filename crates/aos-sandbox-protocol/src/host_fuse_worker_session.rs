//! Structural method-49 comparison carriers for the closed fixed worker role.
//!
//! ```text
//! Host 1.0 / RootMount / fuse-worker-session 1.0
//! request SCM_RIGHTS: [plan, fresh-original FUSE duplicate, records, cancel]
//! success SCM_RIGHTS: [actual Host-retained worker pidfd, cgroup]
//! ```
//!
//! These decoded coordinates never establish reservation, assignment or lease
//! currentness, fresh FUSE provenance, process custody, or backing authority.
//! Host must independently retain its actual launch owner; Mount must retain
//! its original held request and kernel objects through fresh worker proof.

use aos_proto::aos::sandbox::local::v1::{
    Audience, PrepareHostFuseWorkerSessionRequestV1, PrepareHostFuseWorkerSessionResponseV1,
};
use aos_sandbox_core::ProtocolId;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::{
    PeerCredentials, PeerPolicy, ProtocolValidationError, ValidatedAssignmentFence,
    ValidatedHeader, exact_nonzero, validate_fence, validate_request_header,
};

/// Bounds either comparison body before protobuf allocation.
pub const HOST_FUSE_WORKER_SESSION_BODY_MAXIMUM_BYTES_V1: usize = 4096;
const REQUEST_DOMAIN: &[u8] = b"aos-sandbox-host-fuse-worker-session-request-v1\0";
const CGROUP_PREFIX: &str = "/aos.slice/aos-view.slice/aos-view-workers.slice/aos-view-worker@";

/// Retains peer-checked comparison coordinates without a launch permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostFuseWorkerSessionRequestV1 {
    header: ValidatedHeader,
    fence: ValidatedAssignmentFence,
    worker: [u8; 16],
    plan: [u8; 32],
    reservation: [u8; 32],
    request_commitment: [u8; 32],
}

impl ValidatedHostFuseWorkerSessionRequestV1 {
    /// Returns the checked original RootMount header.
    #[must_use]
    pub const fn header(&self) -> &ValidatedHeader {
        &self.header
    }

    /// Returns the original structural assignment fence, not a live owner cut.
    #[must_use]
    pub const fn fence(&self) -> &ValidatedAssignmentFence {
        &self.fence
    }

    /// Returns the original worker locator for exact comparisons.
    #[must_use]
    pub const fn worker_instance(&self) -> [u8; 16] {
        self.worker
    }

    /// Returns the exact sealed-plan commitment for original-object joining.
    #[must_use]
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan
    }

    /// Returns the original held-reservation comparison commitment.
    #[must_use]
    pub const fn reservation_commitment(&self) -> [u8; 32] {
        self.reservation
    }

    /// Returns the method-separated commitment to the complete canonical body.
    #[must_use]
    pub const fn request_commitment(&self) -> [u8; 32] {
        self.request_commitment
    }
}

/// Decodes only the exact bounded RootMount request shape.
///
/// The deadline bounds this dispatch, not the accepted attachment's lifetime.
/// Decoding does not authenticate the signed ownership lease or retain its
/// producer. Those remain mandatory independent Host/Mount owner operations.
///
/// # Errors
///
/// Rejects noncanonical, oversized or unknown fields, non-root or foreign
/// audience/header, expired dispatch, malformed assignment or zero coordinates.
pub fn decode_host_fuse_worker_session_request_v1(
    bytes: &[u8],
    peer: PeerCredentials,
    policy: PeerPolicy,
    now_boottime_nanoseconds: u64,
) -> Result<ValidatedHostFuseWorkerSessionRequestV1, ProtocolValidationError> {
    bound_body(bytes)?;
    if policy.audience != Audience::AUDIENCE_ROOT_MOUNT || policy.uid != 0 || peer.uid != 0 {
        return Err(ProtocolValidationError::MethodMismatch);
    }

    let request = PrepareHostFuseWorkerSessionRequestV1::decode_from_slice(bytes)
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
    let worker = exact_nonzero::<16>(&request.worker_instance_id, "worker_instance_id")?;
    let plan = exact_nonzero::<32>(&request.preparation_plan_digest, "preparation_plan_digest")?;
    let reservation = exact_nonzero::<32>(
        &request.mount_reservation_commitment,
        "mount_reservation_commitment",
    )?;

    let mut digest = Sha256::new();
    digest.update(REQUEST_DOMAIN);
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    Ok(ValidatedHostFuseWorkerSessionRequestV1 {
        header,
        fence,
        worker,
        plan,
        reservation,
        request_commitment: digest.finalize().into(),
    })
}

/// Retains only response comparison facts, never the worker kernel objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedHostFuseWorkerSessionResponseV1 {
    boot: [u8; 16],
    invocation: [u8; 16],
    pid: u32,
    cgroup: String,
}

impl ValidatedHostFuseWorkerSessionResponseV1 {
    /// Returns Host's observed boot for actual local-kernel comparison.
    #[must_use]
    pub const fn boot_id(&self) -> [u8; 16] {
        self.boot
    }

    /// Returns the original fixed-unit invocation comparison coordinate.
    #[must_use]
    pub const fn invocation_id(&self) -> [u8; 16] {
        self.invocation
    }

    /// Returns the PID to compare with the genuine retained process and record.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the sole instance-derived cgroup comparison path.
    #[must_use]
    pub fn cgroup(&self) -> &str {
        &self.cgroup
    }
}

/// Decodes a comparison response cross-linked to the exact original request.
///
/// A successful decode cannot adopt returned descriptors as a live worker
/// lease. Actual Host custody, Mount custody and fresh per-record proof are
/// required independently; ambiguous delivery retains their original escrow.
///
/// # Errors
///
/// Rejects noncanonical, oversized or unknown fields, zero process identity,
/// foreign cgroup, or substitution of worker, plan, reservation or request.
pub fn decode_host_fuse_worker_session_response_v1(
    bytes: &[u8],
    request: &ValidatedHostFuseWorkerSessionRequestV1,
) -> Result<ValidatedHostFuseWorkerSessionResponseV1, ProtocolValidationError> {
    bound_body(bytes)?;
    let response = PrepareHostFuseWorkerSessionResponseV1::decode_from_slice(bytes)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !response.__buffa_unknown_fields.is_empty() || response.encode_to_vec() != bytes {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let boot = exact_nonzero::<16>(&response.kernel_boot_id, "kernel_boot_id")?;
    let invocation = exact_nonzero::<16>(&response.host_invocation_id, "host_invocation_id")?;
    let expected_cgroup = worker_cgroup(request.worker);
    if response.worker_pid == 0
        || response.worker_cgroup != expected_cgroup
        || response.worker_instance_id != request.worker
        || response.preparation_plan_digest != request.plan
        || response.mount_reservation_commitment != request.reservation
        || response.launch_request_commitment != request.request_commitment
    {
        return Err(ProtocolValidationError::InvalidField(
            "original worker preparation response",
        ));
    }

    Ok(ValidatedHostFuseWorkerSessionResponseV1 {
        boot,
        invocation,
        pid: response.worker_pid,
        cgroup: expected_cgroup,
    })
}

fn bound_body(bytes: &[u8]) -> Result<(), ProtocolValidationError> {
    if bytes.len() > HOST_FUSE_WORKER_SESSION_BODY_MAXIMUM_BYTES_V1 {
        Err(ProtocolValidationError::RequestTooLarge)
    } else {
        Ok(())
    }
}

fn worker_cgroup(worker: [u8; 16]) -> String {
    use std::fmt::Write as _;

    let mut path = CGROUP_PREFIX.to_owned();
    for byte in worker {
        // Formatting into String is infallible; no caller-selected component.
        let _ = write!(path, "{byte:02x}");
    }
    path.push_str(".service");
    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_proto::aos::sandbox::local::v1::{AssignmentFence, RequestHeader};

    fn fixture() -> (
        PrepareHostFuseWorkerSessionRequestV1,
        PeerCredentials,
        PeerPolicy,
    ) {
        let peer = PeerCredentials {
            uid: 0,
            gid: 0,
            pid: Some(47),
        };
        let policy = PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_ROOT_MOUNT,
        };
        let request = PrepareHostFuseWorkerSessionRequestV1 {
            header: Some(RequestHeader {
                protocol_major: 1,
                request_id: vec![1; 16],
                audience: Audience::AUDIENCE_ROOT_MOUNT.into(),
                deadline_boottime_nanoseconds: 100,
                maximum_response_bytes: 8192,
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
            worker_instance_id: vec![7; 16],
            preparation_plan_digest: vec![8; 32],
            mount_reservation_commitment: vec![9; 32],
            ..Default::default()
        };
        (request, peer, policy)
    }

    #[test]
    fn original_request_is_bounded_root_mount_and_deadline_checked() {
        let (wire, peer, policy) = fixture();
        let body = wire.encode_to_vec();
        assert!(decode_host_fuse_worker_session_request_v1(&body, peer, policy, 99).is_ok());
        assert!(decode_host_fuse_worker_session_request_v1(&body, peer, policy, 100).is_err());
        assert!(
            decode_host_fuse_worker_session_request_v1(
                &body,
                peer,
                PeerPolicy {
                    audience: Audience::AUDIENCE_NODE_CONTROLLER,
                    ..policy
                },
                99
            )
            .is_err()
        );
        assert!(
            decode_host_fuse_worker_session_request_v1(&vec![0; 4097], peer, policy, 99).is_err()
        );

        let mut duplicate = body;
        duplicate.extend_from_slice(&[0x12, 16]);
        duplicate.extend_from_slice(&[7; 16]);
        assert!(decode_host_fuse_worker_session_request_v1(&duplicate, peer, policy, 99).is_err());
    }

    #[test]
    fn response_rejects_substituted_original_custody_coordinates() {
        let (wire, peer, policy) = fixture();
        let request =
            decode_host_fuse_worker_session_request_v1(&wire.encode_to_vec(), peer, policy, 99)
                .unwrap();
        let response = PrepareHostFuseWorkerSessionResponseV1 {
            kernel_boot_id: vec![10; 16],
            worker_instance_id: request.worker.to_vec(),
            host_invocation_id: vec![11; 16],
            worker_pid: 123,
            worker_cgroup: worker_cgroup(request.worker),
            preparation_plan_digest: request.plan.to_vec(),
            mount_reservation_commitment: request.reservation.to_vec(),
            launch_request_commitment: request.request_commitment.to_vec(),
            ..Default::default()
        };
        assert!(
            decode_host_fuse_worker_session_response_v1(&response.encode_to_vec(), &request)
                .is_ok()
        );

        for field in 0..6 {
            let mut changed = response.clone();
            match field {
                0 => changed.worker_instance_id[0] ^= 1,
                1 => changed.preparation_plan_digest[0] ^= 1,
                2 => changed.mount_reservation_commitment[0] ^= 1,
                3 => changed.launch_request_commitment[0] ^= 1,
                4 => changed.worker_cgroup.push('/'),
                _ => changed.worker_pid = 0,
            }
            assert!(
                decode_host_fuse_worker_session_response_v1(&changed.encode_to_vec(), &request)
                    .is_err()
            );
        }
    }

    #[test]
    fn changed_assignment_cannot_reuse_an_original_request_reply() {
        let (mut wire, peer, policy) = fixture();
        let original =
            decode_host_fuse_worker_session_request_v1(&wire.encode_to_vec(), peer, policy, 99)
                .unwrap();
        wire.fence.as_option_mut().unwrap().desired_generation += 1;
        let successor =
            decode_host_fuse_worker_session_request_v1(&wire.encode_to_vec(), peer, policy, 99)
                .unwrap();

        assert_ne!(
            original.request_commitment(),
            successor.request_commitment()
        );
    }
}
