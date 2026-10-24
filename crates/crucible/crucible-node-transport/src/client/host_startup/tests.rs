//! Exercises the real SDK constructor and closed Hello guard without a Child.
//!
//! These model data controls supply no Source grant, private key, executable
//! measurement or native admission. The installed holder's real action is
//! tested separately in the daemon caller.

use super::*;
use crate::{
    envelope::Envelope,
    handshake::{EXTENSION_NEGOTIATION_V1, HelloResult},
    reference_packet::{
        PacketEvent, PacketProgramDefinition,
        service::{PacketConnectedSourceProgram, PacketNative5StorageLimits},
    },
};
use crucible_node_format::{Bytes, U64, canonical};
use serde_json::{Value, json};

pub(super) struct Inputs {
    launch: PacketNative5SourceLaunch,
    registration: Vec<u8>,
    content: BTreeMap<ContentRef, Vec<u8>>,
    executable: ContentRef,
    hello_id: Id,
}

impl Inputs {
    pub(super) fn borrowed(&self) -> PacketNativeHostStartupInputs<'_> {
        PacketNativeHostStartupInputs {
            launch: &self.launch,
            registration: &self.registration,
            content: &self.content,
            executable: &self.executable,
        }
    }
}

pub(super) fn fixture() -> Inputs {
    let (_, authority, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
    let mut features = authority.selected_features().clone();
    features.push(Id::new(EXTENSION_NEGOTIATION_V1).unwrap());
    features.sort();
    features.dedup();
    let registration = canonical::canonical_json(&json!({
        "schema": "source-owned.packet-canonical-ack-registration/5",
        "role": "controller", "connection_id": authority.connection_id(),
        "session_id": authority.session_id(), "incarnation_id": authority.incarnation_id(),
        "limits": authority.limits(), "features": features, "extensions": [],
        "envelope_extensions": authority.envelope_extensions(),
    }))
    .unwrap();
    let events: Vec<PacketEvent> = serde_json::from_value(json!([
        {"id":"host-startup-event-one", "evaluation":{"time_ps":"10","microstep":"0","phase":3},
         "completion":{"time_ps":"10","microstep":"1","phase":3},"payload":null},
        {"id":"host-startup-event-two", "evaluation":{"time_ps":"20","microstep":"0","phase":3},
         "completion":{"time_ps":"20","microstep":"1","phase":3},"payload":null}
    ]))
    .unwrap();
    let executable = canonical::content_ref(
        b"host constructor model executable",
        "application/octet-stream",
    )
    .unwrap();
    let content = BTreeMap::from([(
        coordinator.reference.clone(),
        coordinator.bytes.as_slice().to_vec(),
    )]);
    let launch = PacketNative5SourceLaunch {
        schema_version: 5, selection,
        program: PacketConnectedSourceProgram::Producer { program: PacketProgramDefinition {
            schema: "source-owned.packet-program.v1".into(), events,
        } },
        controller_pid: U64::new(u64::from(std::process::id())),
        controller_uid: U64::new(u64::from(rustix::process::geteuid().as_raw())),
        controller_executable: executable.clone(), admission_token: Bytes::new(vec![7; 32]),
        initial_coordinator: coordinator, limits: authority.limits(),
        storage: PacketNative5StorageLimits {
            snapshot_bytes: U64::new(65536), control_snapshot_bytes: U64::new(16384),
            protocol_snapshot_bytes: U64::new(262144), frame_bank_bytes: U64::new(262144),
            frames_per_direction: U64::new(64), hello_bytes: U64::new(131080),
            settlement_bytes: U64::new(65536),
        },
        capture_profile: PacketNative5CaptureProfile::OriginalArrays6,
        confirmation_selection: Some(crate::reference_packet::service::PacketNative5ConfirmationSelection::AfterProtocolPoll5),
        ack_emitter_selection: Some(crate::reference_packet::service::PacketNative5AckEmitterSelection::CanonicalSdkBlob5),
        native_codec_metadata_extent: Some(crate::client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB),
        protocol_metadata_limits: None, complete_restore_selection: None,
        restore_input_emitter_selection: None, capture_allocation_selection: None,
        fresh_restore_allocation_selection: None,
        effects: std::path::PathBuf::from("/tmp/aos-host-startup-data-only-unused"),
    };
    Inputs {
        launch,
        registration,
        content,
        executable,
        hello_id: Id::new("host-startup-hello").unwrap(),
    }
}

#[test]
fn original_host_constructor_exact_quote_and_one_short_preserve_original_inputs() {
    let inputs = fixture();
    let before = inputs.registration.clone();
    let bodies = inputs.content.clone();
    let quote =
        original_packet_host_startup_storage_data(&inputs.borrowed(), &inputs.hello_id).unwrap();
    let peak = quote.requested_peak_data().unwrap();
    assert!(peak > 0);
    assert_eq!(
        quote.declared_counter_scratch_bytes(),
        original_packet_host_startup_counter_scratch_data()
    );
    let mut refused = None;
    assert!(
        OriginalPacketHostStartup::prepare_into(
            &inputs.borrowed(),
            &[3; 32],
            &inputs.hello_id,
            peak - 1,
            &mut refused
        )
        .is_err()
    );
    assert!(refused.is_none());
    assert_eq!(inputs.registration, before);
    assert_eq!(inputs.content, bodies);

    let mut completed = None;
    OriginalPacketHostStartup::prepare_into(
        &inputs.borrowed(),
        &[3; 32],
        &inputs.hello_id,
        peak,
        &mut completed,
    )
    .unwrap();
    let original = completed.as_ref().unwrap();
    assert!(original.prepared);
    assert!(original.controller.is_none());
    assert!(
        original.retained_requested_storage_data(None).unwrap() <= quote.retained_requested_bytes()
    );
    assert!(
        OriginalPacketHostStartup::prepare_into(
            &inputs.borrowed(),
            &[3; 32],
            &inputs.hello_id,
            peak,
            &mut completed
        )
        .is_err()
    );
    assert_eq!(inputs.registration, before);
    assert_eq!(inputs.content, bodies);
}

#[test]
fn original_host_constructor_keeps_partial_content_after_real_hash_refusal() {
    let mut inputs = fixture();
    let bytes = inputs.content.values_mut().next().unwrap();
    bytes[0] ^= 1;
    let quote =
        original_packet_host_startup_storage_data(&inputs.borrowed(), &inputs.hello_id).unwrap();
    let mut completed = None;
    assert!(
        OriginalPacketHostStartup::prepare_into(
            &inputs.borrowed(),
            &[3; 32],
            &inputs.hello_id,
            quote.requested_peak_data().unwrap(),
            &mut completed
        )
        .is_err()
    );
    let original = completed.as_ref().unwrap();
    let (reference, actual) = original.pending_content.as_ref().unwrap();
    assert_eq!(inputs.content.get(reference), Some(actual));
    assert!(original.failure.is_some());
    assert!(original.retained_requested_storage_data(None).is_err());
    assert!(
        OriginalPacketHostStartup::prepare_into(
            &inputs.borrowed(),
            &[3; 32],
            &inputs.hello_id,
            quote.requested_peak_data().unwrap(),
            &mut completed
        )
        .is_err()
    );
}

#[test]
fn original_host_hello_guard_rejects_foreign_provider_and_extra_decoded_fields() {
    let inputs = fixture();
    let registration = hello::Registration::decode(&inputs.registration).unwrap();
    let request =
        hello::request(&inputs.launch, &registration, &[3; 32], &inputs.hello_id).unwrap();
    let result = HelloResult {
        version: "CNP/1".into(),
        session_id: registration.session_id.clone(),
        incarnation_id: registration.incarnation_id.clone(),
        controller_nonce: Bytes::new(vec![3; 32]),
        provider_nonce: Bytes::new(vec![5; 32]),
        selected_features: registration.features.clone(),
        limits: registration.limits,
        resume_token: crate::envelope::Nullable(None),
        provider_identity: inputs.launch.selection.provider.clone(),
        resumed_operations: Vec::new(),
    };
    let raw = json!({
        "protocol":"CNP/1", "message":"response", "session_id":null,
        "incarnation_id":registration.incarnation_id, "node_id":null, "execution_owner_id":null,
        "capture_owner_id":null, "operation_id":null, "request_id":inputs.hello_id,
        "sequence":"1", "method":"hello",
        "body":{"status":"completed","operation_state":"completed","result":result,"extensions":{}},
        "extensions":{(EXTENSION_NEGOTIATION_V1):{"format":"1","selected":[]}},
    });
    let guard = hello::ResponseGuard {
        selection: &inputs.launch.selection,
        registration: &registration,
        request: &request,
        executable: &inputs.executable,
    };
    guard.authenticate(&raw).unwrap();
    Envelope::decode(
        &canonical::canonical_json(&raw).unwrap(),
        hello::MAXIMUM_HELLO_BYTES,
    )
    .unwrap();

    let mut foreign = raw.clone();
    foreign["body"]["result"]["provider_identity"]["implementation"]["version"] =
        Value::String("foreign".into());
    assert!(guard.authenticate(&foreign).is_err());
    let mut extended = raw.clone();
    extended["body"]["result"]["unexpected"] = Value::String("still-bounded".into());
    assert!(guard.authenticate(&extended).is_err());
    let mut resumed = raw.clone();
    resumed["body"]["result"]["resume_token"] = Value::String("foreign-resume".into());
    assert!(guard.authenticate(&resumed).is_err());
    guard.authenticate(&raw).unwrap();
}

#[test]
fn original_host_peer_path_uses_complete_actual_pid_spellings() {
    assert!(hello::PeerExecutablePath::new(0).is_err());
    for pid in [1, 10, 999_999, u32::MAX] {
        let path = hello::PeerExecutablePath::new(pid).unwrap();
        assert_eq!(
            path.as_path().unwrap(),
            std::path::Path::new(&format!("/proc/{pid}/exe"))
        );
    }
}

pub(super) fn prepared_initial_model() -> (Inputs, OriginalPacketHostStartup) {
    prepare_initial_model(fixture())
}

pub(super) fn prepared_initial_lifecycle_model() -> (Inputs, OriginalPacketHostStartup) {
    let mut inputs = fixture();
    // Hello-only construction fits the smaller fixture bank. The full lifecycle
    // also retains two proof uploads; use the same bank as the complete caller
    // fixture rather than changing the production quote's capacity guards.
    inputs.launch.storage.frame_bank_bytes = U64::new(1024 * 1024);
    prepare_initial_model(inputs)
}

fn prepare_initial_model(inputs: Inputs) -> (Inputs, OriginalPacketHostStartup) {
    let mut original = None;
    let quote =
        original_packet_host_startup_storage_data(&inputs.borrowed(), &inputs.hello_id).unwrap();
    OriginalPacketHostStartup::prepare_into(
        &inputs.borrowed(),
        &[3; 32],
        &inputs.hello_id,
        quote.requested_peak_data().unwrap(),
        &mut original,
    )
    .unwrap();
    (inputs, original.unwrap())
}
