//! Exercises fresh family DATA against real finite model and receipt producers.
//!
//! Fixtures construct no Source/Boot/Window/read token, native grant or restored
//! private adopter. Scope/ref DTOs are only operands for finite demand bounds.

use super::*;
use crate::envelope::Nullable;
use crate::reference_packet::{
    connected::PacketConnectedNativeRecord,
    control::{NativeProgram, PacketNativeRecord},
    service::complete_restore::activation::tests as activation_fixture,
};
use crucible_node_format::Bytes;
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) struct Fixture {
    pub(super) launch: PacketNative5SourceLaunch,
    pub(super) scope: PacketRestorationActivationScope,
    pub(super) first: ContentRef,
    pub(super) current: ContentRef,
    pub(super) record: PacketNativeRestoredRecord,
    pub(super) model: PacketNative5UnderlyingRecord,
    pub(super) capture: Id,
}

impl Fixture {
    pub(super) fn new(reactive: bool) -> Result<Self, ProviderError> {
        let mut control =
            crate::reference_packet::control::native5::current_control17_fixture_data(reactive)?;
        let (_, _, _, coordinator) =
            crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
        // This DTO is not claimed to pass full native17 service selection; it
        // supplies actual closed limits/configuration to the inert geometry.
        let launch:PacketNative5SourceLaunch=serde_json::from_value(json!({
            "schema_version":5,"selection":control.selection.clone(),
            "program":{"kind":"producer","program":{"schema":"source-owned.packet-program.v1","events":[]}},
            "controller_pid":"1","controller_uid":"0","controller_executable":coordinator.reference,
            "admission_token":Bytes::new(vec![7;32]),"initial_coordinator":coordinator,
            "limits":{"frame_bytes":"65536","nesting":"64","requests":"256","journal_entries":"256","blob_chunk_bytes":"4096"},
            "storage":{"snapshot_bytes":"16384","control_snapshot_bytes":"8192","protocol_snapshot_bytes":"65536",
                "frame_bank_bytes":"65536","frames_per_direction":"256","hello_bytes":"131080","settlement_bytes":"65536"},
            "effects":"/not-opened-by-data-control"
        })).map_err(|_|refused())?;
        control.bind_complete_original_storage(launch.storage.clone(), launch.limits)?;
        let mut original = crate::envelope::tests::request();
        original.method = Method::Observe;
        let model = match &control.program {
            NativeProgram::OutputOnly(program) => {
                PacketNative5UnderlyingRecord::Producer(Box::new(PacketNativeRecord {
                    schema: "source-owned.packet-native/2".into(),
                    native_pid: U64::new(u64::from(std::process::id())),
                    original: original.clone(),
                    inventory: program.inventory(),
                    grant: None,
                }))
            }
            NativeProgram::Connected(program) => {
                PacketNative5UnderlyingRecord::Reactive(Box::new(PacketConnectedNativeRecord {
                    schema: "source-owned.packet-native/4".into(),
                    native_pid: U64::new(u64::from(std::process::id())),
                    original: original.clone(),
                    inventory: program.inventory()?,
                    grant: None,
                }))
            }
            NativeProgram::RestorationInProgress => return Err(refused()),
        };
        let encoded = match &model {
            PacketNative5UnderlyingRecord::Producer(model) => canonical::canonical_json(
                &serde_json::to_value(model.as_ref()).map_err(ContractError::from)?,
            )?,
            PacketNative5UnderlyingRecord::Reactive(model) => canonical::canonical_json(
                &serde_json::to_value(model.as_ref()).map_err(ContractError::from)?,
            )?,
        };
        let native_ref = canonical::content_ref(&encoded, "application/json")?;
        let receipt = control.original_complete_receipt_data(&original, native_ref)?;
        let mut scope = activation_fixture::request()?.scope;
        let binding = &launch.selection.realization.bindings[0];
        scope.target.native_pid = receipt.native_pid;
        scope.target.session = binding.authority.session_id.clone();
        scope.target.incarnation = binding.authority.incarnation_id.clone();
        scope.target.node = binding.compatibility.node_id.clone();
        scope.target.owner = launch.selection.realization.owner_bindings[0]
            .owner
            .id
            .clone();
        scope.target.world = launch.selection.world.clone();
        scope.target.prepared_token = launch.selection.prepared_token.clone();
        scope.target.gate = launch.selection.gate.clone();
        scope.target.admission = launch.selection.admission.clone();
        scope.target.transaction = launch.selection.transaction.clone();
        scope.target.binding_hash = receipt.binding_hash.clone();
        scope.target.owner_generation = receipt.owner_generation;
        let record = PacketNativeRestoredRecord {
            schema: "source-owned.packet-restored-native/12".into(),
            native_receipt: receipt,
            captured_owner_state: scope.restoration.captured_owner_state.clone(),
            captured_journal: scope.restoration.captured_journal.clone(),
            mapping: scope.restoration.mapping.clone(),
            restore_commit: scope.restoration.commit_request.clone(),
            restore_response: scope.restoration.commit_response.clone(),
            context_digest: scope.restoration.context_digest.clone(),
            physical_gate_held: false,
        };
        let current = canonical::content_ref(
            &canonical::canonical_json(
                &serde_json::to_value(&record).map_err(ContractError::from)?,
            )?,
            "application/json",
        )?;
        Ok(Self {
            launch,
            scope,
            first: canonical::content_ref(b"first-data", "application/json")?,
            current,
            record,
            model,
            capture: Id::new("actual-requested-capture")?,
        })
    }

    fn inputs(&self) -> PacketRestoredSettledCaptureControlFutureInputs<'_> {
        PacketRestoredSettledCaptureControlFutureInputs {
            launch: &self.launch,
            scope: &self.scope,
            first_observation: &self.first,
            current_record_reference: &self.current,
            current_record: &self.record,
            current_model: &self.model,
            capture_id: &self.capture,
            cut: Position::new(
                U64::new(0),
                U64::new(0),
                crucible_node_format::Phase::Reaction,
            ),
            event_ordinal: U64::new(0),
        }
    }
}

#[test]
fn both_real_model_families_have_exact_complete_bound_and_sum_every_axis() -> TestResult {
    for reactive in [false, true] {
        let fixture = Fixture::new(reactive)?;
        let input = fixture.inputs();
        let value = restored_settled_capture_control_future_storage_data(&input, usize::MAX)?;
        let exact = usize::try_from(value.complete_family_axes_data().requested_peak_data()?)?;
        assert_eq!(
            restored_settled_capture_control_future_storage_data(&input, exact)?,
            value
        );
        assert!(restored_settled_capture_control_future_storage_data(&input, exact - 1).is_err());
        let phases = [
            value.registration_axes_data(),
            value.checkpoint_axes_data(),
            value.terminal_axes_data(),
            value.confirmation_axes_data(),
        ];
        for axis in 0..3 {
            let total = phases.into_iter().try_fold(0u64, |sum, row| {
                sum.checked_add(match axis {
                    0 => row.retained_requested_bytes.get(),
                    1 => row.maximum_simultaneous_transient_bytes.get(),
                    _ => row.declared_counter_scratch_bytes.get(),
                })
                .ok_or_else(exhausted)
            })?;
            let row = value.complete_family_axes_data();
            assert_eq!(
                total,
                match axis {
                    0 => row.retained_requested_bytes.get(),
                    1 => row.maximum_simultaneous_transient_bytes.get(),
                    _ => row.declared_counter_scratch_bytes.get(),
                }
            );
        }
    }
    Ok(())
}

#[test]
fn changed_tuple_and_missing_owner_refuse_without_fabricating_a_current_model() -> TestResult {
    let mut fixture = Fixture::new(false)?;
    fixture.scope.target.node = Id::new("foreign-node")?;
    assert!(restored_settled_capture_control_future_prequote_data(&fixture.inputs()).is_err());
    let mut fixture = Fixture::new(false)?;
    fixture.launch.selection.realization.owner_bindings.clear();
    assert!(restored_settled_capture_control_future_prequote_data(&fixture.inputs()).is_err());
    let mut fixture = Fixture::new(false)?;
    if let PacketNative5UnderlyingRecord::Producer(model) = &mut fixture.model {
        model.original.operation_id = Nullable(Some(Id::new("changed-original")?));
    }
    assert!(restored_settled_capture_control_future_prequote_data(&fixture.inputs()).is_err());
    Ok(())
}

#[test]
fn actual_typed_bytes_formatter_is_prepaid_and_raw_vec_banks_are_not_invented() -> TestResult {
    let fixture = Fixture::new(false)?;
    let (work, scratch) = restored_settled_capture_control_future_prequote_data(&fixture.inputs())?;
    assert!(work >= 43);
    assert_eq!(
        scratch,
        PacketRestoredSettledCaptureControlFutureStorageData::counter_scratch_data()
    );
    let mut observer = MetadataObserver::new();
    observer.observe(&fixture.record)?;
    match &fixture.model {
        PacketNative5UnderlyingRecord::Producer(model) => observer.observe(model.as_ref())?,
        PacketNative5UnderlyingRecord::Reactive(model) => observer.observe(model.as_ref())?,
    }
    assert!(
        work >= observer
            .ordinary_bytes_formatter_data()
            .maximum_temporary_requested_bytes_data()?
    );
    Ok(())
}

#[test]
fn actual_larger_roster_increases_successful_family_before_unchanged_frame_refusal() -> TestResult {
    let mut fixture = Fixture::new(false)?;
    let before =
        restored_settled_capture_control_future_storage_data(&fixture.inputs(), usize::MAX)?;
    fixture.launch.selection.realization.owner_bindings[0]
        .owner
        .participant_ids
        .push(Id::new("additional-source-participant")?);
    let after =
        restored_settled_capture_control_future_storage_data(&fixture.inputs(), usize::MAX)?;
    assert!(
        after.registration_axes_data().retained_requested_bytes
            > before.registration_axes_data().retained_requested_bytes
    );
    fixture.launch.limits.frame_bytes = U64::new(64);
    assert!(
        restored_settled_capture_control_future_storage_data(&fixture.inputs(), usize::MAX)
            .is_err()
    );
    Ok(())
}

#[test]
fn full_closed_capture_confirmation_and_normative_identity_fit_their_future_shapes() -> TestResult {
    use crate::bodies::BeginKind;
    use crate::envelope::MessageKind;
    use crate::reference_packet::service::{
        complete_restore::activation::PacketRestorationActivationProof,
        restored_settled_capture::{
            PacketRestoredSettledCaptureArtifact, restored_settled_capture_proof_layout_data,
        },
        restored_settled_confirmation::{
            PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE,
            PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_RECEIPT_SCHEMA,
            PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_REQUEST_SCHEMA,
            PacketRestoredSettledAfterConfirmationReceipt,
            PacketRestoredSettledAfterConfirmationRequest,
        },
    };
    let fixture = Fixture::new(false)?;
    let input = fixture.inputs();
    let (binding, owner) = fields(&input)?;
    let shapes = projection::shapes(&input, binding, owner, usize::MAX)?;
    let reference = |name: &str| canonical::content_ref(name.as_bytes(), "application/json");
    let arguments = CaptureArguments {
        capture_id: fixture.capture.clone(),
        participant_ids: owner.owner.participant_ids.clone(),
        cut_id: Id::new("actual-generated-cut")?,
        cut: input.cut,
        event_ordinal: input.event_ordinal,
        ordering_profile: "superdense-v1".into(),
        preservation_contract: Id::new(
            crate::reference_packet::continuation_contracts::PACKET_COMPLETE_LINEAGE_PROFILE,
        )?,
    };
    let begin = BeginRequest {
        kind: BeginKind::Capture,
        binding_hash: owner.identity()?,
        owner_generation: fixture.scope.target.owner_generation,
        activation_id: Nullable(Some(fixture.scope.target.activation.clone())),
        world_generation: fixture.scope.target.generation,
        arguments: serde_json::to_value(&arguments)?
            .as_object()
            .ok_or_else(refused)?
            .clone(),
        extensions: Extensions::new(),
    };
    let native_allocation = PacketNativeStartupAllocationRow {
        retained_requested_bytes: U64::new(100),
        maximum_simultaneous_transient_bytes: U64::new(200),
        declared_counter_scratch_bytes: U64::new(300),
    };
    let request=PacketRestoredSettledCaptureRequest {
        schema:crate::reference_packet::service::restored_settled_capture::RESTORED_SETTLED_CAPTURE_REQUEST.into(),scope:fixture.scope.clone(),
        capture:arguments.clone(),capture_owner:binding.compatibility.capture_owner.id.clone(),capture_operation:Id::new("actual-operation")?,
        runtime_object:canonical::content_ref(b"runtime","application/vnd.crucible.runtime-original-lineage+json;version=7")?,
        coordinator_checkpoint:canonical::content_ref(b"coordinator","application/vnd.crucible.coordinator-commitment-checkpoint+json;version=17")?,
        parent_archive:canonical::content_ref(b"archive","application/vnd.crucible.native-signed-index-body.v3+json")?,
        first_observation:fixture.first.clone(),current_record:fixture.current.clone(),current_model:fixture.record.native_receipt.native_record.clone(),
        history_prefix:reference("prefix")?,history_next_sequence:U64::new(17),native_schema:reference("native-schema")?,native_allocation,
    };
    let (schema, algorithm, digest, mac) = restored_settled_capture_proof_layout_data();
    let artifact = PacketRestoredSettledCaptureArtifact {
        request,
        proof: PacketRestorationActivationProof {
            schema: schema.into(),
            algorithm: algorithm.into(),
            context_digest: Bytes::new(vec![7; digest]),
            mac: Bytes::new(vec![8; mac]),
        },
    };
    // Arbitrary proof bytes intentionally claim no MAC/native authorization.
    let mut capture = crate::envelope::tests::request();
    capture.method = Method::Begin;
    capture.execution_owner_id = Nullable(None);
    capture.capture_owner_id = Nullable(Some(binding.compatibility.capture_owner.id.clone()));
    capture.node_id = Nullable(Some(binding.compatibility.node_id.clone()));
    capture.session_id = Nullable(Some(binding.authority.session_id.clone()));
    capture.incarnation_id = Nullable(Some(binding.authority.incarnation_id.clone()));
    capture.operation_id = Nullable(Some(artifact.request.capture_operation.clone()));
    capture.body = serde_json::to_value(&begin)?
        .as_object()
        .ok_or_else(refused)?
        .clone();
    capture.extensions.insert(
        RESTORED_SETTLED_CAPTURE_FEATURE.into(),
        serde_json::to_value(&artifact)?,
    );
    let actual = actual_serialization_storage_data(&capture, Default::default(), usize::MAX)?;
    within(&actual, &shapes.capture)?;
    let actual = actual_serialization_storage_data(
        &crate::reference_packet::control::capture::StartupRequestIdentity(&capture),
        Default::default(),
        usize::MAX,
    )?;
    within(&actual, &shapes.capture_identity)?;
    let mut actual =
        actual_serialization_storage_data(&artifact.request, Default::default(), usize::MAX)?;
    actual.serializer_temporary_requested_bytes = 43;
    within(&actual, &shapes.request)?;
    within(
        &actual_serialization_storage_data(&begin, Default::default(), usize::MAX)?,
        &shapes.begin,
    )?;
    within(
        &actual_serialization_storage_data(&arguments, Default::default(), usize::MAX)?,
        &shapes.arguments,
    )?;
    let snapshot = reference("snapshot")?;
    let control = reference("control")?;
    let anchor = reference("anchor")?;
    let result = terminal::CaptureCompleted17 {
        status: "completed",
        operation_state: OperationState::Completed,
        result: terminal::CaptureResult17 {
            capture_manifest: &snapshot,
            owner_state_refs: [&control],
            unchanged_cut_receipt: &anchor,
        },
        extensions: Extensions::new(),
    };
    let mut terminal = capture.clone();
    terminal.message = MessageKind::Response;
    terminal.sequence = U64::new(22);
    terminal.extensions.clear();
    terminal.body = serde_json::to_value(result)?
        .as_object()
        .ok_or_else(refused)?
        .clone();
    within(
        &actual_serialization_storage_data(&terminal, Default::default(), usize::MAX)?,
        &shapes.terminal,
    )?;
    let quote_control =
        crate::reference_packet::control::native5::current_control17_fixture_data(false)?;
    let actual_terminal = quote_control.quote_capture17_terminal_data(&capture, usize::MAX)?;
    let family = restored_settled_capture_control_future_storage_data(&input, usize::MAX)?;
    family
        .terminal_axes_data()
        .authenticate_actual_data(&actual_terminal.row_data())?;
    let capture_encoded = canonical::canonical_json(&serde_json::to_value(&capture)?)?;
    let terminal_encoded = canonical::canonical_json(&serde_json::to_value(&terminal)?)?;
    let confirmation = PacketRestoredSettledAfterConfirmationRequest {
        schema: PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_REQUEST_SCHEMA.into(),
        capture_request_id: capture.request_id.0.as_ref().ok_or_else(refused)?.clone(),
        capture_request_hash: capture.request_hash(crate::envelope::RequestOrigin::Controller)?,
        capture_operation_id: artifact.request.capture_operation,
        capture_terminal_hash: canonical::hash(
            PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN,
            &terminal_encoded,
        )?,
        capture_terminal_sequence: terminal.sequence,
        settled_capture_request: canonical::content_ref(&capture_encoded, "application/json")?,
        native_snapshot_ref: snapshot,
        native_control_ref: control,
        native_anchor_ref: anchor,
    };
    let mut poll = capture.clone();
    poll.method = Method::Poll;
    poll.sequence = U64::new(23);
    poll.extensions.clear();
    poll.body = serde_json::from_value(json!({"after_observation_sequence":"0","extensions":{}}))?;
    poll.extensions.insert(
        PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE.into(),
        serde_json::to_value(&confirmation)?,
    );
    within(
        &actual_serialization_storage_data(&poll, Default::default(), usize::MAX)?,
        &shapes.confirmation,
    )?;
    within(
        &actual_serialization_storage_data(
            &crate::reference_packet::control::capture::StartupRequestIdentity(&poll),
            Default::default(),
            usize::MAX,
        )?,
        &shapes.confirmation_identity,
    )?;
    let receipt = PacketRestoredSettledAfterConfirmationReceipt {
        schema: PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_RECEIPT_SCHEMA.into(),
        capture: confirmation,
        native_after_ref: reference("after")?,
        native_after_capacity: U64::new(1024),
    };
    let mut confirmed = poll.clone();
    confirmed.message = MessageKind::Response;
    confirmed.sequence = U64::new(30);
    confirmed.body = serde_json::from_value(
        json!({"status":"completed","operation_state":"completed","result":{
        "operation_id":poll.operation_id,"operation_state":"completed","outcome":terminal.body,"observations":[],"next_observation_sequence":"1"},"extensions":{}}),
    )?;
    confirmed.extensions.clear();
    confirmed.extensions.insert(
        PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE.into(),
        serde_json::to_value(&receipt)?,
    );
    within(
        &actual_serialization_storage_data(&receipt, Default::default(), usize::MAX)?,
        &shapes.confirmation_receipt,
    )?;
    within(
        &actual_serialization_storage_data(&confirmed.body, Default::default(), usize::MAX)?,
        &shapes.confirmation_result,
    )?;
    within(
        &actual_serialization_storage_data(&confirmed, Default::default(), usize::MAX)?,
        &shapes.confirmation_terminal,
    )?;
    Ok(())
}

#[test]
fn opaque_fixed_model_data_preserves_all_components_and_refuses_each_larger_actual_axis()
-> TestResult {
    let fixture = Fixture::new(false)?;
    let data = restored_settled_capture_control_future_storage_data(&fixture.inputs(), usize::MAX)?
        .model_future_data();
    data.authenticate_actual_model_data(&data)?;
    assert_eq!(pack(&unpack(data.model)), data.model);
    assert_eq!(pack(&unpack(data.restored)), data.restored);
    assert_eq!(pack(&unpack(data.prior)), data.prior);
    let identity = |value: &PacketRestoredSettledCaptureControlModelFutureData| {
        let mut hash = blake3::Hasher::new();
        value.bind_identity_data(&mut hash);
        *hash.finalize().as_bytes()
    };
    let baseline = identity(&data);
    for family in 0..3 {
        for field in 0..11 {
            let mut changed = data;
            let fields = match family {
                0 => &mut changed.model,
                1 => &mut changed.restored,
                _ => &mut changed.prior,
            };
            fields[field] = fields[field].checked_add(1).ok_or_else(exhausted)?;
            assert!(data.authenticate_actual_model_data(&changed).is_err());
            assert_ne!(baseline, identity(&changed));
        }
    }
    let mut changed = data;
    changed.formatter = changed.formatter.checked_add(1).ok_or_else(exhausted)?;
    assert!(data.authenticate_actual_model_data(&changed).is_err());
    assert_ne!(baseline, identity(&changed));
    Ok(())
}

#[test]
fn runtime_current_geometry_cannot_become_a_prebirth_reservation() -> TestResult {
    let fixture = Fixture::new(false)?;
    let actual =
        restored_settled_capture_control_future_storage_data(&fixture.inputs(), usize::MAX)?
            .model_future_data();

    assert!(
        restored_settled_capture_control_future_from_model_data(
            &fixture.launch,
            b"actual raw launch DATA",
            &actual,
            usize::MAX
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn fixed_model_identity_covers_actual_import_and_actual_new_launch() -> TestResult {
    let fixture = Fixture::new(false)?;
    let actual =
        restored_settled_capture_control_future_storage_data(&fixture.inputs(), usize::MAX)?
            .model_future_data();
    let identity = |value: &PacketRestoredSettledCaptureControlModelFutureData| {
        let mut hash = blake3::Hasher::new();
        value.bind_identity_data(&mut hash);
        *hash.finalize().as_bytes()
    };
    // This private DATA construction checks only the defining commitment. It
    // grants no import custody, native row or successful public birth factory.
    let fixed = PacketRestoredSettledCaptureControlModelFutureData::supported_from_shapes(
        &unpack(actual.model),
        &unpack(actual.restored),
        &unpack(actual.prior),
        actual.formatter,
        [7; 32],
        b"actual raw launch DATA",
    );
    let mut changed_import = fixed;
    if let ModelGeometryClass::SupportedInitial15 { import, .. } = &mut changed_import.class {
        import[31] ^= 1;
    }
    let mut changed_launch = fixed;
    if let ModelGeometryClass::SupportedInitial15 { launch, .. } = &mut changed_launch.class {
        *launch = launch_identity(b"changed raw launch DATA");
    }

    assert_ne!(identity(&actual), identity(&fixed));
    assert_ne!(identity(&fixed), identity(&changed_import));
    assert_ne!(identity(&fixed), identity(&changed_launch));
    assert!(
        restored_settled_capture_control_future_from_model_data(
            &fixture.launch,
            b"changed raw launch DATA",
            &fixed,
            usize::MAX
        )
        .is_err()
    );
    Ok(())
}
