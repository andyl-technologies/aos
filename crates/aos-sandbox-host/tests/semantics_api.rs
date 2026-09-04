//! Exercises the controller-facing host semantics API from outside the crate.

#![allow(clippy::unwrap_used)]

use aos_proto::aos::sandbox::local::v1::{
    ApplyRuntimeRequest, Audience, Feature, ResourceLimit, RuntimeAction,
};
use aos_sandbox_core::{BrokerGrant, BrokerGrantTarget, BrokerVerb};
use aos_sandbox_host::authorization::semantics_v1::canonical_host_semantics_v1;
use aos_sandbox_protocol::{PeerCredentials, PeerPolicy, decode_runtime_request};
use buffa::Message as _;

#[test]
fn controller_can_build_a_grant_without_reimplementing_host_canonicalization() {
    let mut wire = ApplyRuntimeRequest::default();
    let header = wire.header.get_or_insert_default();
    header.protocol_major = 1;
    header.protocol_minor = 1;
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
    wire.action = RuntimeAction::RUNTIME_ACTION_LAUNCH.into();
    let plan = wire.launch_plan.get_or_insert_default();
    let root = plan.root_image.get_or_insert_default();
    root.media_type = "application/vnd.aos.sandbox.view.v1+cbor".to_owned();
    root.sha256 = vec![7; 32];
    root.encoded_size = 8;
    plan.workspace_handle = vec![9; 32];
    plan.network_handle = vec![10; 32];
    plan.uid_range_start = 65_536;
    plan.uid_range_size = 65_536;
    plan.limits = [(2, 128), (3, 1 << 30), (4, 100), (9, 1_024)]
        .into_iter()
        .map(|(dimension, value)| ResourceLimit {
            dimension,
            value,
            ..Default::default()
        })
        .collect();
    plan.required_features.push(Feature {
        namespace: "aos.sandbox.runtime.linux-systemd".to_owned(),
        major: 1,
        minor: 0,
        ..Default::default()
    });

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
    let grant = BrokerGrant::new(
        semantics.verb(),
        semantics.target(),
        semantics.commitment(),
        u32::try_from(body.len()).unwrap(),
        0,
    )
    .unwrap();

    assert_eq!(grant.verb(), BrokerVerb::HostLaunch);
    assert_eq!(grant.target(), BrokerGrantTarget::Assignment);
    assert_eq!(grant.argument_commitment(), semantics.commitment());
}
