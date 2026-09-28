//! Distinct portable purpose-56 semantics for fixed worker preparation.
//!
//! ```text
//! domain || method:u16=49 || purpose:u32=56 || protocol:u16[2]=[1,0]
//! || audience:u16=5 || feature-length:u16 || feature || feature:u16[2]=[1,0]
//! || sandbox:16 || incarnation:16 || epoch:u64 || desired:u64 || assignment:32
//! || worker:16 || plan:32 || reservation:32 || original-request:32
//! || input-count:u16=4 || input-roles:u16[4]=[13,14,15,16]
//! || output-count:u16=2 || output-roles:u16[2]=[17,18]
//! || disposition-count:u16=4 || closed:u16[4]=[3,3,3,3]
//! ```
//!
//! All integers use network byte order. The tuple is nonauthorizing: only the
//! real held Mount owner can issue this exact preparation under current
//! assignment and ownership-lease custody. It grants no metadata or backing.

use aos_sandbox_core::{
    BrokerArgumentCommitment, BrokerGrantTarget, BrokerResourceHandle, BrokerVerb,
    HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE,
};

use super::host::HostSemanticError;
use crate::host_fuse_worker_session::ValidatedHostFuseWorkerSessionRequestV1;

const DOMAIN: &[u8] = b"aos.sandbox.host.fuse-worker-session.v1\0";

/// Compares the exact preparation purpose without creating a launch permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalHostFuseWorkerSessionSemanticsV1 {
    bytes: Vec<u8>,
    commitment: BrokerArgumentCommitment,
    target: BrokerGrantTarget,
}

impl CanonicalHostFuseWorkerSessionSemanticsV1 {
    /// Returns the distinct purpose, never an existing Observe or Launch verb.
    #[must_use]
    pub const fn verb(&self) -> BrokerVerb {
        BrokerVerb::HostPrepareFuseWorkerSession
    }

    /// Returns only the original reservation's resource comparison target.
    #[must_use]
    pub const fn target(&self) -> BrokerGrantTarget {
        self.target
    }

    /// Returns the exact domain-separated signed-plan comparison commitment.
    #[must_use]
    pub const fn commitment(&self) -> BrokerArgumentCommitment {
        self.commitment
    }

    /// Borrows the full versioned comparison encoding for canonical vectors.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Commits the entire original request and fixed role/version contract.
///
/// The reservation digest is a comparison handle, not proof of a live
/// reservation. An authenticated signed plan and lease still cannot substitute
/// for genuine held Mount/Host custody or independently pinned image admission.
///
/// # Errors
///
/// Rejects a sentinel original reservation or an unrepresentable feature name.
pub fn canonical_host_fuse_worker_session_semantics_v1(
    request: &ValidatedHostFuseWorkerSessionRequestV1,
) -> Result<CanonicalHostFuseWorkerSessionSemanticsV1, HostSemanticError> {
    let target = BrokerResourceHandle::from_bytes(request.reservation_commitment())
        .map_err(|_| HostSemanticError::InvalidTarget)?;
    let feature = HOST_FUSE_WORKER_SESSION_FEATURE_NAMESPACE.as_bytes();
    let feature_length =
        u16::try_from(feature.len()).map_err(|_| HostSemanticError::InvalidTarget)?;

    let mut bytes = Vec::with_capacity(DOMAIN.len() + feature.len() + 256);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&49_u16.to_be_bytes());
    bytes.extend_from_slice(&56_u32.to_be_bytes());
    for value in [1_u16, 0, 5, feature_length] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(feature);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());

    let fence = request.fence();
    bytes.extend_from_slice(fence.sandbox_id());
    bytes.extend_from_slice(fence.incarnation_id());
    bytes.extend_from_slice(&fence.assignment_epoch().to_be_bytes());
    bytes.extend_from_slice(&fence.desired_generation().to_be_bytes());
    bytes.extend_from_slice(fence.assignment_digest());
    bytes.extend_from_slice(&request.worker_instance());
    bytes.extend_from_slice(&request.plan_digest());
    bytes.extend_from_slice(&request.reservation_commitment());
    bytes.extend_from_slice(&request.request_commitment());

    for value in [4_u16, 13, 14, 15, 16, 2, 17, 18, 4, 3, 3, 3, 3] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    let commitment = BrokerArgumentCommitment::for_canonical_bytes(&bytes);
    Ok(CanonicalHostFuseWorkerSessionSemanticsV1 {
        bytes,
        commitment,
        target: BrokerGrantTarget::Resource(target),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_fuse_worker_session::decode_host_fuse_worker_session_request_v1;
    use crate::{PeerCredentials, PeerPolicy};
    use aos_proto::aos::sandbox::local::v1::{
        AssignmentFence, Audience, PrepareHostFuseWorkerSessionRequestV1, RequestHeader,
    };
    use buffa::Message as _;

    fn fixture() -> PrepareHostFuseWorkerSessionRequestV1 {
        PrepareHostFuseWorkerSessionRequestV1 {
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
        }
    }

    fn compile(
        wire: &PrepareHostFuseWorkerSessionRequestV1,
    ) -> CanonicalHostFuseWorkerSessionSemanticsV1 {
        let request = decode_host_fuse_worker_session_request_v1(
            &wire.encode_to_vec(),
            PeerCredentials {
                uid: 0,
                gid: 0,
                pid: Some(47),
            },
            PeerPolicy {
                uid: 0,
                gid: Some(0),
                audience: Audience::AUDIENCE_ROOT_MOUNT,
            },
            99,
        )
        .unwrap();
        canonical_host_fuse_worker_session_semantics_v1(&request).unwrap()
    }

    #[test]
    fn canonical_vector_commits_distinct_purpose_versions_and_all_roles() {
        let exact = compile(&fixture());
        // Independent protobuf/preimage reference encoding, not a live grant.
        let expected = [
            0x49, 0x4e, 0xa7, 0xfe, 0x30, 0xbf, 0x3b, 0xb6, 0x38, 0x34, 0x2a, 0xcb, 0x9b, 0x04,
            0x51, 0xf3, 0x1b, 0x5e, 0x18, 0x35, 0x60, 0x7d, 0xad, 0x36, 0x2d, 0xe6, 0xba, 0x10,
            0x2b, 0xcd, 0xa7, 0xa9,
        ];

        assert_eq!(exact.verb().get(), 56);
        assert_eq!(exact.canonical_bytes().len(), 312);
        assert_eq!(*exact.commitment().digest().as_bytes(), expected);
        assert_eq!(
            exact.target(),
            BrokerGrantTarget::Resource(BrokerResourceHandle::from_bytes([9; 32]).unwrap(),)
        );
    }

    #[test]
    fn original_worker_plan_assignment_and_reservation_cannot_be_substituted() {
        let original = fixture();
        let expected = compile(&original).commitment();

        for coordinate in 0..5 {
            let mut changed = original.clone();
            match coordinate {
                0 => changed.worker_instance_id[0] ^= 1,
                1 => changed.preparation_plan_digest[0] ^= 1,
                2 => changed.mount_reservation_commitment[0] ^= 1,
                3 => changed.fence.as_option_mut().unwrap().desired_generation += 1,
                _ => changed.header.as_option_mut().unwrap().request_id[0] ^= 1,
            }
            assert_ne!(compile(&changed).commitment(), expected);
        }
    }
}
