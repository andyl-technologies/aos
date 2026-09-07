//! Exact-scope, audience, version, and canonical-authority regression tests.

use super::*;
use crate::semantics::{host::runtime_handle_v1, mount_scope::canonical_mount_scope_semantics_v1};
use aos_proto::aos::sandbox::local::v1::{
    AssignmentFence, ObserveMountScopeResponse, RequestHeader,
};
use aos_sandbox_core::ObjectDigest;

fn fixture() -> ObserveMountScopeRequest {
    ObserveMountScopeRequest {
        header: Some(RequestHeader {
            protocol_major: 1,
            protocol_minor: 3,
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
    }
}

fn decode(bytes: &[u8]) -> Result<ValidatedMountScopeRequest, ProtocolValidationError> {
    decode_mount_scope_request(
        bytes,
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
}

#[test]
fn request_requires_root_mount_new_carrier_and_nonzero_exact_scope() {
    let raw = fixture();
    assert!(decode(&raw.encode_to_vec()).is_ok());

    for mutate in [
        (|r: &mut ObserveMountScopeRequest| r.header.get_or_insert_default().protocol_minor = 2)
            as fn(&mut ObserveMountScopeRequest),
        |r| r.header.get_or_insert_default().audience = Audience::AUDIENCE_NODE_CONTROLLER.into(),
        |r| r.payload_scope_handle = vec![0; 32],
        |r| r.payload_scope_handle.pop().map(|_| ()).unwrap_or_default(),
        |r| r.runtime_handle[0] ^= 1,
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

    for (uid, audience) in [
        (100, Audience::AUDIENCE_ROOT_MOUNT),
        (0, Audience::AUDIENCE_NODE_CONTROLLER),
    ] {
        let mut changed = raw.clone();
        changed.header.get_or_insert_default().audience = audience.into();

        assert!(
            decode_mount_scope_request(
                &changed.encode_to_vec(),
                PeerCredentials {
                    uid,
                    gid: 0,
                    pid: Some(7)
                },
                PeerPolicy {
                    uid,
                    gid: Some(0),
                    audience
                },
                100
            )
            .is_err()
        );
    }
}

#[test]
fn scope_and_assignment_changes_require_new_signed_commitments() {
    let raw = fixture();
    let original =
        canonical_mount_scope_semantics_v1(&decode(&raw.encode_to_vec()).unwrap()).unwrap();
    assert_eq!(
        original.commitment().digest(),
        ObjectDigest::from_bytes([
            0xff, 0x2f, 0x60, 0xa9, 0xdd, 0xab, 0xb9, 0xcb, 0xee, 0xde, 0x89, 0xd2, 0x25, 0x1d,
            0x91, 0xcc, 0xa8, 0x8a, 0x64, 0x87, 0x8d, 0xd0, 0xb8, 0xd0, 0x42, 0xcf, 0x87, 0xf4,
            0xb3, 0x51, 0x0f, 0xee,
        ])
    );

    for mutate in [
        (|r: &mut ObserveMountScopeRequest| r.payload_scope_handle[0] ^= 1)
            as fn(&mut ObserveMountScopeRequest),
        |r| r.fence.get_or_insert_default().desired_generation += 1,
        |r| r.fence.get_or_insert_default().sandbox_id[0] ^= 1,
    ] {
        let mut changed = raw.clone();
        mutate(&mut changed);
        let semantics =
            canonical_mount_scope_semantics_v1(&decode(&changed.encode_to_vec()).unwrap()).unwrap();

        assert_ne!(original.commitment(), semantics.commitment());
    }

    let mut changed = raw;
    changed
        .header
        .get_or_insert_default()
        .maximum_response_bytes += 1;

    assert_eq!(
        original,
        canonical_mount_scope_semantics_v1(&decode(&changed.encode_to_vec()).unwrap()).unwrap()
    );
}

#[test]
fn response_layout_matches_schema_and_rejects_replacement_scope() {
    let request = decode(&fixture().encode_to_vec()).unwrap();
    let bytes = encode_mount_scope_response(&request, b"init.scope").unwrap();
    let raw = ObserveMountScopeResponse::decode_from_slice(&bytes).unwrap();

    assert_eq!(raw.payload_scope_handle, request.payload_scope_handle());
    assert_eq!(raw.leader_cgroup_hint, b"init.scope");
    assert!(decode_mount_scope_response(&raw.encode_to_vec(), &request).is_ok());

    let mut changed = raw;
    changed.payload_scope_handle[0] ^= 1;

    assert!(decode_mount_scope_response(&changed.encode_to_vec(), &request).is_err());
    assert!(encode_mount_scope_response(&request, b"../init.scope").is_err());
}
