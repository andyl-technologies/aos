//! Verifies shared descriptor integrity and default local DATA generation.

#[path = "../build_support/coordinator_descriptor.rs"]
mod coordinator_descriptor;

use std::collections::BTreeMap;

use aos_sandbox_api::aos::sandbox::coordinator::v1 as wire;
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
    assert_eq!(original.file.len(), 3);
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
    let source = include_str!("../../../../../api/proto/aos/sandbox/coordinator/v1/coordinator.proto");
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

#[test]
fn complete_local_schema_preserves_reviewed_cleanup_lineage_baseline() {
    let source = include_str!("../../../../../api/proto/aos/sandbox/local/v1/brokers.proto");

    assert_eq!(complete_schema_fingerprint(source), 0xf26b_6973_6ea0_3a99);

    let lineage = "  repeated bytes cleanup_lineages_v1 = 6;\n";
    assert_eq!(source.matches(lineage).count(), 1);
    let without_lineage = source.replace(lineage, "");
    assert_eq!(complete_schema_fingerprint(&without_lineage), 0x9ef1_88c8_2090_ff19);

    let present = "  repeated bytes present_stop_cleanup_candidates_v1 = 5;\n";
    assert_eq!(source.matches(present).count(), 1);
    let without_present = without_lineage.replace(present, "");
    assert_eq!(complete_schema_fingerprint(&without_present), 0xb38f_8700_7529_4d7d);

    let cleanup = "  bytes host_stop_cleanup_v1 = 6;\n";
    assert_eq!(source.matches(cleanup).count(), 1);
    let without_cleanup = without_present.replace(cleanup, "");
    assert_eq!(complete_schema_fingerprint(&without_cleanup), 0x927d_edd4_cca9_724e);

    // The sole historical observation field restores the previous complete
    // schema. The older availability transition remains independently checked.
    let recovery = "  repeated bytes recovered_namespaces_v7 = 4;\n";
    assert_eq!(without_cleanup.matches(recovery).count(), 1);
    let mut prior = without_cleanup.replace(recovery, "");
    assert_eq!(complete_schema_fingerprint(&prior), 0x4ba9_75f1_c7fe_5113);

    // Exactly the two new method numbers and new phase/request/response scopes
    // may be removed to recover the previous complete schema baseline.
    for method in [
        "  BROKER_METHOD_HOST_PREPARE_EXECUTION_AVAILABILITY_V2 = 64;\n",
        "  BROKER_METHOD_STORAGE_PREPARE_EXECUTION_AVAILABILITY_V2 = 65;\n",
    ] {
        assert_eq!(prior.matches(method).count(), 1);
        prior = prior.replace(method, "");
    }
    let start = prior.find("// Both phases borrow one actual retained native receiver").unwrap();
    let end = prior.find("// One canonical zero-descriptor DATA carrier").unwrap();
    assert!(start < end);
    prior.replace_range(start..end, "");
    assert_eq!(complete_schema_fingerprint(&prior), 0x113a_964f_81f1_2a81);

    let declaration = "  bytes native_absence_v2 = 6; // Optional exact AOSNIC02 no-active native census companion.\n";
    assert_eq!(prior.matches(declaration).count(), 1);
    assert_eq!(complete_schema_fingerprint(&prior.replace(declaration, "")),
        0x57ca_1234_3727_0fe6);

    let stop = "  bytes capture_stop_residual_v4 = 7;\n";
    assert_eq!(prior.matches(stop).count(), 1);
    assert_eq!(complete_schema_fingerprint(&prior.replace(stop, "")),
        0x0e84_4da8_186a_79dd);
}

#[test]
fn inventory_cleanup_lineage_field_roundtrips_without_reinterpreting_legacy_fields() {
    use aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse;
    use buffa::Message as _;

    let original = InventoryRuntimeResponse {
        cleanup_lineages_v1: vec![vec![1, 2, 3]],
        ..Default::default()
    };
    let encoded = original.encode_to_vec();
    let decoded = InventoryRuntimeResponse::decode_from_slice(&encoded).unwrap();
    assert_eq!(decoded.cleanup_lineages_v1, original.cleanup_lineages_v1);
    assert!(decoded.recovered_namespaces_v7.is_empty());
    assert!(decoded.native_absence_v5.is_empty());
}

#[test]
fn host_historical_inventory_has_explicit_field_four() {
    use aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse;
    use buffa::Message as _;

    let ordinary = InventoryRuntimeResponse::default();
    assert!(ordinary.encode_to_vec().is_empty());

    let extended = InventoryRuntimeResponse {
        recovered_namespaces_v7: vec![vec![1, 2, 3]],
        ..Default::default()
    };
    assert_eq!(extended.encode_to_vec(), vec![0x22, 3, 1, 2, 3]);
    assert_eq!(InventoryRuntimeResponse::decode_from_slice(&extended.encode_to_vec())
        .unwrap().recovered_namespaces_v7, vec![vec![1, 2, 3]]);
}

#[test]
fn host_stop_cleanup_has_explicit_field_six() {
    use aos_sandbox_api::aos::sandbox::local::v1::ApplyRuntimeRequest;
    use buffa::Message as _;

    assert!(ApplyRuntimeRequest::default().encode_to_vec().is_empty());
    let request = ApplyRuntimeRequest { host_stop_cleanup_v1: vec![1, 2, 3], ..Default::default() };
    let bytes = request.encode_to_vec();
    assert_eq!(bytes, vec![0x32, 3, 1, 2, 3]);
    assert_eq!(ApplyRuntimeRequest::decode_from_slice(&bytes).unwrap().host_stop_cleanup_v1, vec![1, 2, 3]);
}

#[test]
fn host_present_cleanup_candidate_has_explicit_field_five() {
    use aos_sandbox_api::aos::sandbox::local::v1::InventoryRuntimeResponse;
    use buffa::Message as _;

    let inventory = InventoryRuntimeResponse {
        present_stop_cleanup_candidates_v1: vec![vec![1, 2, 3]], ..Default::default()
    };
    assert_eq!(inventory.encode_to_vec(), vec![0x2a, 3, 1, 2, 3]);
    assert_eq!(InventoryRuntimeResponse::decode_from_slice(&inventory.encode_to_vec())
        .unwrap().present_stop_cleanup_candidates_v1, vec![vec![1, 2, 3]]);
}

#[test]
fn runtime_stop_residual_is_an_explicit_optional_field_seven() {
    use aos_sandbox_api::aos::sandbox::local::v1::RuntimeObservation;
    use buffa::Message as _;

    let ordinary = RuntimeObservation::default();
    assert!(ordinary.encode_to_vec().is_empty());

    let extended = RuntimeObservation {
        capture_stop_residual_v4: vec![1, 2, 3].into(),
        ..Default::default()
    };
    assert_eq!(extended.encode_to_vec(), vec![0x3a, 3, 1, 2, 3]);
}

#[test]
fn host_argument_v2_generated_fields_keep_their_explicit_wire_tags() {
    use aos_sandbox_api::aos::sandbox::local::v1::{AcceptHostExecutionArgumentRequestV2,
        AcceptHostExecutionArgumentResponseV2, BrokerMethod, PrepareHostExecutionArgumentRequestV2};

    let prepare = PrepareHostExecutionArgumentRequestV2 {
        proposed_attempt: vec![1].into(), ..Default::default()
    };
    let accept = AcceptHostExecutionArgumentRequestV2 {
        canonical_attempt: vec![2].into(), canonical_preparation: vec![3].into(),
        ..Default::default()
    };
    let response = AcceptHostExecutionArgumentResponseV2 {
        canonical_receipt: vec![4].into(), ..Default::default()
    };

    assert_eq!(BrokerMethod::BROKER_METHOD_HOST_PREPARE_EXECUTION_ARGUMENT_V2 as i32, 58);
    assert_eq!(BrokerMethod::BROKER_METHOD_HOST_ACCEPT_EXECUTION_ARGUMENT_V2 as i32, 59);
    assert_eq!(prepare.encode_to_vec(), vec![0x12, 1, 1]);
    assert_eq!(accept.encode_to_vec(), vec![0x12, 1, 2, 0x1a, 1, 3]);
    assert_eq!(response.encode_to_vec(), vec![0x0a, 1, 4]);
}

#[test]
fn physical_capture_reserve_generated_source_and_original_body_keep_distinct_wire_tags() {
    use aos_sandbox_api::aos::sandbox::local::v1::ReserveStorageExecutionCaptureRequestV1;

    // This pins generated field numbers only. These short DATA values are
    // deliberately not valid sources, signed requests or physical permits.
    let request = ReserveStorageExecutionCaptureRequestV1 {
        canonical_grant_source: vec![2],
        canonical_original_storage_output_request: vec![46],
        ..Default::default()
    };
    let encoded = request.encode_to_vec();
    assert_eq!(encoded, vec![0x12, 1, 2, 0x1a, 1, 46]);

    let decoded = ReserveStorageExecutionCaptureRequestV1::decode_from_slice(&encoded).unwrap();
    assert_eq!(decoded.canonical_grant_source, vec![2]);
    assert_eq!(decoded.canonical_original_storage_output_request, vec![46]);
}

#[test]
fn physical_capture_complete_keeps_status_and_full_record_tag_explicit() {
    use aos_sandbox_api::aos::sandbox::local::v1::{StorageExecutionCaptureAttemptStatusV1,
        StorageExecutionCaptureAttemptV1};
    let response = StorageExecutionCaptureAttemptV1 {
        status: StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_COMPLETE.into(),
        canonical_complete_result: vec![1, 2],
        ..Default::default()
    };
    assert_eq!(response.encode_to_vec(), vec![8, 3, 74, 2, 1, 2]);
    let response = StorageExecutionCaptureAttemptV1 {
        effective_deadline_boottime_nanoseconds: 9,
        ..response
    };
    assert_eq!(response.encode_to_vec(), vec![8, 3, 74, 2, 1, 2, 80, 9]);
}


#[test]
fn current_publication_v2_keeps_immutable_and_current_wire_tags_distinct() {
    use aos_sandbox_api::aos::sandbox::local::v1::{
        PopulateStorageGuestRootResponseV1, RuntimePlan, StorageWorkspaceInventoryRecord,
    };

    // These short values pin generated field numbers only. They are deliberately
    // invalid physical/current proofs and confer no native or signing authority.
    let plan = RuntimePlan {
        workspace_handle: vec![1],
        current_guest_root_publication_v2: vec![2],
        ..Default::default()
    };
    assert_eq!(plan.encode_to_vec(), vec![0x12, 1, 1, 0x52, 1, 2]);

    let response = PopulateStorageGuestRootResponseV1 {
        publication_proof: vec![1],
        current_publication_v2: vec![2],
        ..Default::default()
    };
    let response_bytes = response.encode_to_vec();
    assert_eq!(response_bytes, vec![0x0a, 1, 1, 0x12, 1, 2]);
    let decoded = PopulateStorageGuestRootResponseV1::decode_from_slice(&response_bytes).unwrap();
    assert_eq!(decoded.publication_proof, vec![1]);
    assert_eq!(decoded.current_publication_v2, vec![2]);

    let workspace = StorageWorkspaceInventoryRecord {
        guest_root_publication_proof: vec![1],
        current_guest_root_publication_v2: vec![2],
        ..Default::default()
    };
    assert_eq!(workspace.encode_to_vec(), vec![0x62, 1, 1, 0x6a, 1, 2]);
}
