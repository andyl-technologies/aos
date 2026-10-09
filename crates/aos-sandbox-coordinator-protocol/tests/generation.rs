//! Verifies the selected wire owner and its direct shared DATA references.

#[path = "../../aos-proto/build_support/coordinator_descriptor.rs"]
mod coordinator_descriptor;

use aos_proto::aos::sandbox::coordinator::v1 as shared;
use aos_sandbox_coordinator_protocol::aos::sandbox::coordinator::v1 as wire;
use buffa::Message;
use buffa_codegen::generated::descriptor::{FileDescriptorProto, FileDescriptorSet};
use coordinator_descriptor::{
    COORDINATOR_FILE, COORDINATOR_PACKAGE, complete_schema_fingerprint, validate_descriptor,
};

const TRANSPORT_FILE: &str = "aos/sandbox/coordinator/v1/coordinator_transport.proto";
const ORIGINAL: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/aos-coordinator-transport-descriptor.bin"
));
const MODULE: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/aos.sandbox.coordinator.v1.mod.rs"
));
const DATA: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/aos.sandbox.coordinator.v1.coordinator_transport.rs"
));

fn decode<M: Message>(bytes: &[u8]) -> M {
    buffa_codegen::tooling_decode_options()
        .unwrap()
        .decode_from_slice(bytes)
        .unwrap()
}

fn file<'a>(descriptor: &'a FileDescriptorSet, name: &str) -> &'a FileDescriptorProto {
    descriptor
        .file
        .iter()
        .find(|file| file.name.as_deref() == Some(name))
        .unwrap()
}

fn with_unknown<M: Message>(message: &M) -> M {
    let mut encoded = message.encode_to_vec();
    encoded.extend_from_slice(&[0xa0, 0x1f, 0x07]);
    let extended: M = decode(&encoded);
    assert_ne!(message.encode_to_vec(), extended.encode_to_vec());
    extended
}

#[test]
fn selected_descriptor_retains_the_shared_import_and_original_service() {
    let original: FileDescriptorSet = decode(ORIGINAL);
    assert_eq!(original.file.len(), 2);
    let transport = file(&original, TRANSPORT_FILE);
    assert_eq!(transport.package.as_deref(), Some(COORDINATOR_PACKAGE));
    assert_eq!(transport.dependency, [COORDINATOR_FILE.to_owned()]);
    assert_eq!(transport.message_type.len(), 5);
    assert_eq!(transport.enum_type.len(), 1);
    assert_eq!(transport.service.len(), 1);
    assert_eq!(
        transport.service[0].name.as_deref(),
        Some("CoordinatorNode")
    );
    assert_eq!(transport.service[0].method.len(), 2);
    assert!(file(&original, COORDINATOR_FILE).service.is_empty());
    assert!(
        original
            .file
            .iter()
            .all(|file| !file.source_code_info.location.is_empty())
    );
}

#[test]
fn malformed_missing_duplicate_and_wrong_package_descriptors_fail_closed() {
    let original: FileDescriptorSet = decode(ORIGINAL);
    for name in [COORDINATOR_FILE, TRANSPORT_FILE] {
        let mut missing = original.clone();
        missing
            .file
            .retain(|file| file.name.as_deref() != Some(name));
        assert!(validate_descriptor(&missing.encode_to_vec(), name).is_err());

        let mut duplicate = original.clone();
        duplicate.file.push(file(&original, name).clone());
        assert!(validate_descriptor(&duplicate.encode_to_vec(), name).is_err());

        let mut wrong_package = original.clone();
        wrong_package
            .file
            .iter_mut()
            .find(|file| file.name.as_deref() == Some(name))
            .unwrap()
            .package = Some("unexpected.package".to_owned());
        assert!(validate_descriptor(&wrong_package.encode_to_vec(), name).is_err());
        assert!(validate_descriptor(&[0xff], name).is_err());
    }
}

#[test]
fn descriptor_validation_preserves_service_source_information_and_unknowns() {
    let mut original: FileDescriptorSet = decode(ORIGINAL);
    let transport = original
        .file
        .iter_mut()
        .find(|file| file.name.as_deref() == Some(TRANSPORT_FILE))
        .unwrap();
    transport.service[0] = with_unknown(&transport.service[0]);
    let source_info = transport.source_code_info.as_option_mut().unwrap();
    *source_info = with_unknown(source_info);
    *transport = with_unknown(transport);
    original = with_unknown(&original);
    let bytes = original.encode_to_vec();

    validate_descriptor(&bytes, COORDINATOR_FILE).unwrap();
    validate_descriptor(&bytes, TRANSPORT_FILE).unwrap();
    assert_eq!(decode::<FileDescriptorSet>(&bytes), original);
}

#[test]
fn both_complete_schema_owners_remain_pinned() {
    assert_eq!(
        complete_schema_fingerprint(include_str!(
            "../../aos-proto/src/proto/aos/sandbox/coordinator/v1/coordinator.proto"
        )),
        0x2898_7641_eee4_10f1,
    );
    assert_eq!(
        complete_schema_fingerprint(include_str!(
            "../src/proto/aos/sandbox/coordinator/v1/coordinator_transport.proto"
        )),
        0x9741_bfae_c3fa_6c09,
    );
}

#[test]
fn selected_client_server_views_json_and_response_helpers_compile() {
    fn _require_server<T: wire::CoordinatorNode>() {}
    fn require_data<T: buffa::HasMessageView + serde::Serialize>() {}

    require_data::<wire::AuthenticatedSessionBinding>();
    require_data::<wire::CoordinatorNodeRequest>();
    require_data::<wire::CoordinatorNodeResponse>();
    require_data::<wire::OrderedWatchRequest>();
    require_data::<wire::OrderedWatchBatch>();
    let _: Option<wire::SemanticEncoding> = None;
    let _: Option<wire::CoordinatorNodeClient<()>> = None;
    let _: Option<wire::OwnedCoordinatorNodeRequestView> = None;
    let _: Option<wire::OwnedCoordinatorNodeResponseView> = None;
    let _: Option<wire::OwnedOrderedWatchRequestView> = None;
    let _: Option<wire::OwnedOrderedWatchBatchView> = None;
    assert!(MODULE.contains(".__connect.rs"));
    for name in [
        "ProtocolVersion",
        "SemanticEnvelope",
        "WatchCursor",
        "WatchEvent",
        "WatchBinding",
    ] {
        assert!(!DATA.contains(&format!("pub struct {name} ")));
    }
}

fn assert_round_trip<M>(value: M)
where
    M: Message + std::fmt::Debug + PartialEq + serde::Serialize + serde::de::DeserializeOwned,
{
    let bytes = value.encode_to_vec();
    assert_eq!(decode::<M>(&bytes), value);
    let json = serde_json::to_vec(&value).unwrap();
    assert_eq!(serde_json::from_slice::<M>(&json).unwrap(), value);

    let mut extended = bytes;
    extended.extend_from_slice(&[0xa0, 0x1f, 0x07]);
    assert_eq!(decode::<M>(&extended).encode_to_vec(), extended);
}

#[test]
fn all_transport_codecs_retain_direct_shared_fields_and_unknowns() {
    // These are inert serializer values, not authenticated session evidence.
    let session = wire::AuthenticatedSessionBinding {
        node_uid: vec![1; 16],
        node_boot_uid: vec![2; 16],
        node_boot_generation: 3,
        channel_binding_sha256: vec![4; 32],
        audience_sha256: vec![5; 32],
        disclosure_domain_sha256: vec![6; 32],
        coordinator_epoch: 7,
        authenticated_at_unix_seconds: 8,
        valid_until_unix_seconds: 9,
        protocol: Some(shared::ProtocolVersion {
            major: 1,
            minor: 0,
            ..Default::default()
        })
        .into(),
        maximum_request_bytes: 11,
        maximum_response_bytes: 12,
        replay_fence_sha256: vec![13; 32],
        lineage_sha256: vec![14; 32],
        predecessor_boot_uid: vec![15; 16],
        predecessor_lineage_sha256: vec![16; 32],
        semantic_encoding: 1.into(),
        ..Default::default()
    };
    assert_round_trip(session.clone());
    assert_round_trip(wire::CoordinatorNodeRequest {
        request_uid: vec![17; 16],
        session: Some(session.clone()).into(),
        semantic: Some(shared::SemanticEnvelope::default()).into(),
        ..Default::default()
    });
    assert_round_trip(wire::CoordinatorNodeResponse {
        request_uid: vec![18; 16],
        session: Some(session).into(),
        semantic: Some(shared::SemanticEnvelope::default()).into(),
        ..Default::default()
    });
    assert_round_trip(wire::OrderedWatchRequest {
        cursor: Some(shared::WatchCursor::default()).into(),
        maximum_events: 19,
        ..Default::default()
    });
    assert_round_trip(wire::OrderedWatchBatch {
        events: vec![shared::WatchEvent::default()],
        next_cursor: Some(shared::WatchCursor::default()).into(),
        resync_binding: Some(shared::WatchBinding::default()).into(),
        ..Default::default()
    });
}
