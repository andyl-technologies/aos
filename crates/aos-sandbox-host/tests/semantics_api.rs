//! Exercises the controller-facing host semantics API from outside the crate.

#![allow(clippy::unwrap_used)]

use aos_proto::aos::sandbox::local::v1::{ApplyRuntimeRequest, Audience, RuntimeAction};
use aos_sandbox_core::{BrokerGrant, BrokerGrantTarget, BrokerVerb};
use aos_sandbox_host::authorization::semantics_v1::canonical_host_semantics_v1;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_runtime_request};
use buffa::Message as _;

#[test]
fn controller_can_build_a_lifecycle_grant_without_reimplementing_host_canonicalization() {
    let mut wire = ApplyRuntimeRequest::default();
    let header = wire.header.get_or_insert_default();
    header.protocol_major = 1;
    header.protocol_minor = 0;
    header.request_id = vec![1; 16];
    header.audience = Audience::AUDIENCE_NODE_CONTROLLER.into();
    header.deadline_boottime_nanoseconds = 1_000;
    header.maximum_response_bytes = 4_096;
    let fence = wire.fence.get_or_insert_default();
    fence.sandbox_id = vec![2; 16];
    fence.incarnation_id = vec![3; 16];
    fence.assignment_epoch = 4;
    fence.desired_generation = 5;
    fence.assignment_digest = vec![6; 32];
    wire.action = RuntimeAction::RUNTIME_ACTION_FREEZE.into();

    let body = wire.encode_to_vec();
    let validated = decode_runtime_request(
        &body,
        PeerCredentials {
            uid: 100,
            gid: 200,
            pid: Some(300),
        },
        PeerPolicy {
            uid: 100,
            gid: Some(200),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
        100,
    )
    .unwrap();
    let semantics = canonical_host_semantics_v1(&validated).unwrap();
    let protocol_semantics =
        aos_sandbox_protocol::semantics::host::canonical_host_semantics_v1(&validated).unwrap();
    let grant = BrokerGrant::new(
        semantics.verb(),
        semantics.target(),
        semantics.commitment(),
        u32::try_from(body.len()).unwrap(),
        0,
    )
    .unwrap();

    assert_eq!(grant.verb(), BrokerVerb::HostFreeze);
    assert!(matches!(grant.target(), BrokerGrantTarget::Resource(_)));
    assert_eq!(grant.argument_commitment(), semantics.commitment());
    assert_eq!(semantics, protocol_semantics);
    assert_eq!(
        semantics.commitment().digest().as_bytes(),
        &[
            148, 169, 10, 184, 154, 62, 141, 193, 241, 186, 55, 227, 126, 30, 58, 201, 149, 149,
            218, 38, 174, 145, 39, 95, 195, 220, 143, 66, 85, 160, 176, 114,
        ]
    );
}
