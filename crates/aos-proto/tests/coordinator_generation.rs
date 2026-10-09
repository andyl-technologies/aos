//! Verifies shared descriptor integrity and default local DATA generation.

#[path = "../build_support/coordinator_descriptor.rs"]
mod coordinator_descriptor;

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::coordinator::v1 as wire;
use buffa::Message;
use buffa_codegen::generated::descriptor::{FileDescriptorProto, FileDescriptorSet};
use coordinator_descriptor::{
    complete_schema_fingerprint, validate_descriptor, COORDINATOR_FILE, COORDINATOR_PACKAGE,
};

const ORIGINAL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aos-original-descriptor.bin"));
const COORDINATOR_MODULE: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/aos.sandbox.coordinator.v1.mod.rs"
));

fn decode<M: Message>(bytes: &[u8]) -> M {
    buffa_codegen::tooling_decode_options()
        .unwrap()
        .decode_from_slice(bytes)
        .unwrap()
}

fn coordinator(descriptor: &FileDescriptorSet) -> &FileDescriptorProto {
    descriptor
        .file
        .iter()
        .find(|file| file.name.as_deref() == Some(COORDINATOR_FILE))
        .unwrap()
}

fn with_unknown<M: Message>(message: &M) -> M {
    let mut encoded = message.encode_to_vec();
    // Descriptor field 500 is an unknown varint, independent of schema DATA.
    encoded.extend_from_slice(&[0xa0, 0x1f, 0x07]);
    let extended: M = decode(&encoded);
    assert_ne!(message.encode_to_vec(), extended.encode_to_vec());
    extended
}

#[test]
fn descriptor_validation_preserves_messages_options_source_information_and_unknowns() {
    let mut original: FileDescriptorSet = decode(ORIGINAL);
    assert_eq!(original.file.len(), 8);
    assert!(original
        .file
        .iter()
        .all(|file| !file.source_code_info.location.is_empty()));

    let file = original
        .file
        .iter_mut()
        .find(|file| file.name.as_deref() == Some(COORDINATOR_FILE))
        .unwrap();
    assert_eq!(file.package.as_deref(), Some(COORDINATOR_PACKAGE));
    assert!(file.service.is_empty());
    file.message_type[0] = with_unknown(&file.message_type[0]);
    let source_info = file.source_code_info.as_option_mut().unwrap();
    *source_info = with_unknown(source_info);
    *file = with_unknown(file);
    original = with_unknown(&original);
    let original_bytes = original.encode_to_vec();

    validate_descriptor(&original_bytes, COORDINATOR_FILE).unwrap();
    assert_eq!(decode::<FileDescriptorSet>(&original_bytes), original);
    assert_eq!(generated_data(&original), generated_data(&decode(ORIGINAL)));
}

fn generated_data(descriptor: &FileDescriptorSet) -> BTreeMap<String, String> {
    let names = descriptor
        .file
        .iter()
        .map(|file| file.name.clone().unwrap())
        .collect::<Vec<_>>();
    // These are the existing connectrpc-build DATA generation defaults.
    let mut config = buffa_codegen::CodeGenConfig::default();
    config.generate_json = true;
    config.generate_views = true;
    buffa_codegen::generate(&descriptor.file, &names, &config)
        .unwrap()
        .into_iter()
        .map(|file| (file.name, file.content))
        .collect()
}

#[test]
fn messages_enums_views_json_and_module_layout_match_the_active_generator() {
    let original: FileDescriptorSet = decode(ORIGINAL);
    let generated = generated_data(&original);
    let active = BTreeMap::from([
        (
            "aos.sandbox.coordinator.v1.coordinator.rs".to_owned(),
            include_str!(concat!(
                env!("OUT_DIR"),
                "/aos.sandbox.coordinator.v1.coordinator.rs"
            ))
            .to_owned(),
        ),
        (
            "aos.sandbox.coordinator.v1.coordinator.__view.rs".to_owned(),
            include_str!(concat!(
                env!("OUT_DIR"),
                "/aos.sandbox.coordinator.v1.coordinator.__view.rs"
            ))
            .to_owned(),
        ),
        (
            "aos.sandbox.coordinator.v1.coordinator.__oneof.rs".to_owned(),
            include_str!(concat!(
                env!("OUT_DIR"),
                "/aos.sandbox.coordinator.v1.coordinator.__oneof.rs"
            ))
            .to_owned(),
        ),
        (
            "aos.sandbox.coordinator.v1.coordinator.__view_oneof.rs".to_owned(),
            include_str!(concat!(
                env!("OUT_DIR"),
                "/aos.sandbox.coordinator.v1.coordinator.__view_oneof.rs"
            ))
            .to_owned(),
        ),
        (
            "aos.sandbox.coordinator.v1.mod.rs".to_owned(),
            COORDINATOR_MODULE.to_owned(),
        ),
    ]);
    let coordinator_data = generated
        .into_iter()
        .filter(|(name, _)| name.starts_with("aos.sandbox.coordinator.v1."))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(coordinator_data, active);
}

#[test]
fn malformed_shared_descriptor_fails_closed() {
    let original: FileDescriptorSet = decode(ORIGINAL);
    let mut missing = original.clone();
    missing
        .file
        .retain(|file| file.name.as_deref() != Some(COORDINATOR_FILE));
    assert!(validate_descriptor(&missing.encode_to_vec(), COORDINATOR_FILE).is_err());

    let mut duplicate = original.clone();
    duplicate.file.push(coordinator(&original).clone());
    assert!(validate_descriptor(&duplicate.encode_to_vec(), COORDINATOR_FILE).is_err());

    let mut wrong_package = original.clone();
    wrong_package
        .file
        .iter_mut()
        .find(|file| file.name.as_deref() == Some(COORDINATOR_FILE))
        .unwrap()
        .package = Some("unexpected.package".to_owned());
    assert!(validate_descriptor(&wrong_package.encode_to_vec(), COORDINATOR_FILE).is_err());
    assert!(validate_descriptor(&[0xff], COORDINATOR_FILE).is_err());
}

#[test]
fn complete_shared_schema_remains_pinned() {
    let source = include_str!("../src/proto/aos/sandbox/coordinator/v1/coordinator.proto");
    assert_eq!(complete_schema_fingerprint(source), 0x2898_7641_eee4_10f1);
}

#[test]
fn local_recovery_data_and_views_compile_without_remote_services() {
    fn require_data<T: buffa::HasMessageView + serde::Serialize>() {}

    require_data::<wire::AssignmentLease>();
    require_data::<wire::AssignmentInventory>();
    require_data::<wire::CapabilitySnapshot>();
    require_data::<wire::SnapshotTransferEffect>();
    require_data::<wire::SnapshotTransferRecovery>();
    require_data::<wire::SemanticEnvelope>();
    let _: Option<wire::AssignmentLeaseView<'_>> = None;
    let _: Option<wire::SnapshotTransferRecoveryView<'_>> = None;
}

#[test]
fn default_generated_module_has_no_coordinator_transport_or_rpc_owner() {
    let original: FileDescriptorSet = decode(ORIGINAL);
    let shared = coordinator(&original);
    assert!(shared.service.is_empty());
    for name in [
        "AuthenticatedSessionBinding",
        "CoordinatorNodeRequest",
        "CoordinatorNodeResponse",
        "OrderedWatchRequest",
        "OrderedWatchBatch",
    ] {
        assert!(!shared
            .message_type
            .iter()
            .any(|message| message.name.as_deref() == Some(name)));
    }
    assert!(!shared
        .enum_type
        .iter()
        .any(|value| value.name.as_deref() == Some("SemanticEncoding")));
    // Inspect the active stitcher, not stale output files from earlier builds.
    assert!(!COORDINATOR_MODULE.contains(".__connect.rs"));
}
