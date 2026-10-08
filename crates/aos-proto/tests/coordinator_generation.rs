//! Verifies descriptor preservation and explicit coordinator RPC selection.

#[path = "../build_support/coordinator_descriptor.rs"]
mod coordinator_descriptor;

use std::collections::BTreeMap;

use aos_proto::aos::sandbox::coordinator::v1 as wire;
use buffa::Message;
use buffa_codegen::generated::descriptor::{FileDescriptorProto, FileDescriptorSet};
use coordinator_descriptor::{select_descriptor, COORDINATOR_FILE, COORDINATOR_PACKAGE};

const ORIGINAL: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aos-original-descriptor.bin"));
const SELECTED: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/aos-selected-descriptor.bin"));
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
fn default_filter_changes_only_the_coordinator_service_vector() {
    let mut original: FileDescriptorSet = decode(ORIGINAL);
    assert_eq!(original.file.len(), 8);
    assert!(original
        .file
        .iter()
        .all(|file| !file.source_code_info.location.is_empty()));

    // Exercise retained unknowns at every descriptor level touched by the
    // filter, including source information and the vector restored below.
    let file = original
        .file
        .iter_mut()
        .find(|file| file.name.as_deref() == Some(COORDINATOR_FILE))
        .unwrap();
    assert_eq!(file.package.as_deref(), Some(COORDINATOR_PACKAGE));
    assert_eq!(file.service.len(), 1);
    assert_eq!(file.service[0].name.as_deref(), Some("CoordinatorNode"));
    assert_eq!(file.service[0].method.len(), 2);
    file.service[0] = with_unknown(&file.service[0]);
    let source_info = file.source_code_info.as_option_mut().unwrap();
    *source_info = with_unknown(source_info);
    *file = with_unknown(file);
    original = with_unknown(&original);
    let original_bytes = original.encode_to_vec();

    let selected_bytes = select_descriptor(&original_bytes, false).unwrap();
    let mut selected: FileDescriptorSet = decode(&selected_bytes);
    assert!(coordinator(&selected).service.is_empty());

    let services = coordinator(&original).service.clone();
    selected
        .file
        .iter_mut()
        .find(|file| file.name.as_deref() == Some(COORDINATOR_FILE))
        .unwrap()
        .service = services;
    assert_eq!(selected, original);
    assert_eq!(
        select_descriptor(&original_bytes, true).unwrap(),
        original_bytes
    );
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
fn messages_enums_views_json_and_module_layout_are_identical() {
    let original: FileDescriptorSet = decode(ORIGINAL);
    let selected: FileDescriptorSet = decode(&select_descriptor(ORIGINAL, false).unwrap());

    assert_eq!(generated_data(&selected), generated_data(&original));
}

#[test]
fn malformed_coordinator_descriptor_fails_closed_in_both_modes() {
    let original: FileDescriptorSet = decode(ORIGINAL);
    for multi_node in [false, true] {
        let mut missing = original.clone();
        missing
            .file
            .retain(|file| file.name.as_deref() != Some(COORDINATOR_FILE));
        assert!(select_descriptor(&missing.encode_to_vec(), multi_node).is_err());

        let mut duplicate = original.clone();
        duplicate.file.push(coordinator(&original).clone());
        assert!(select_descriptor(&duplicate.encode_to_vec(), multi_node).is_err());

        let mut wrong_package = original.clone();
        wrong_package
            .file
            .iter_mut()
            .find(|file| file.name.as_deref() == Some(COORDINATOR_FILE))
            .unwrap()
            .package = Some("unexpected.package".to_owned());
        assert!(select_descriptor(&wrong_package.encode_to_vec(), multi_node).is_err());
        assert!(select_descriptor(&[0xff], multi_node).is_err());
    }
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

#[cfg(not(feature = "multi-node"))]
#[test]
fn default_generated_module_has_no_coordinator_rpc_client_or_server() {
    let selected: FileDescriptorSet = decode(SELECTED);
    assert!(coordinator(&selected).service.is_empty());
    // Inspect the active stitcher, not stale output files from earlier builds.
    // Both the client and server are generated only in this companion.
    assert!(!COORDINATOR_MODULE.contains(".__connect.rs"));
}

#[cfg(feature = "multi-node")]
#[test]
fn explicit_multi_node_restores_original_client_server_and_helpers() {
    // An unused bound names the server without fabricating an implementation.
    fn _require_server<T: wire::CoordinatorNode>() {}

    // Naming both generated APIs is a compile guard; no transport is opened.
    let _: Option<wire::CoordinatorNodeClient<()>> = None;
    let _: Option<wire::OwnedCoordinatorNodeRequestView> = None;
    let _: Option<wire::OwnedCoordinatorNodeResponseView> = None;
    let _: Option<wire::OwnedOrderedWatchRequestView> = None;
    let _: Option<wire::OwnedOrderedWatchBatchView> = None;

    assert_eq!(SELECTED, ORIGINAL);
    assert!(COORDINATOR_MODULE.contains(".__connect.rs"));
}
