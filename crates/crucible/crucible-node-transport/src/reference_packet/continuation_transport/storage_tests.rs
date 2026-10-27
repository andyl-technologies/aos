//! Checks actual current Observe association and prospective multiwindow layouts.
//!
//! Constructed Capture/Poll replies below are data fixtures only; these tests
//! neither grant a Capture ticket nor publish native effects or archive state.

// crucible-lint: allow panic-shortcut -- Assertion panics are the data-control verdict.

use super::*;
use crate::handshake::{ConnectionAuthority, Handshake};
use crate::retained_metadata::{
    MetadataObserver,
    serialization_storage::{OriginalSerializationStorageData, actual_serialization_storage_data},
};
use crucible_node_format::{Extensions, Phase, Position, Tick, U64, canonical};
use serde_json::{Map, Value};
use std::{
    cell::RefCell,
    io::{Cursor, Read, Write},
    rc::Rc,
};

const MAXIMUM: usize = 512 * 1024 * 1024;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct Memory {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Read for Memory {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(bytes)
    }
}

impl Write for Memory {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ProviderStream for Memory {
    fn fence(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Supervisor(RefCell<Vec<ConnectionIncident>>);

impl ConnectionSupervisor for Supervisor {
    fn quarantine(&self, incident: ConnectionIncident) {
        self.0.borrow_mut().push(incident);
    }
}

struct Uninstalled;

impl BodySchemaVerifier for Uninstalled {
    fn verify(
        &self,
        _: &ConnectionAuthority,
        _: &Envelope,
        _: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        Err(ProviderError::Correlation("uninstalled fixture verifier"))
    }
}

fn object(value: &impl serde::Serialize) -> Result<Map<String, Value>, ProviderError> {
    match serde_json::to_value(value).map_err(crucible_node_format::ContractError::from)? {
        Value::Object(value) => Ok(value),
        _ => Err(ProviderError::Frame("fixture object")),
    }
}

fn envelope(authority: &ConnectionAuthority, method: Method) -> Result<Envelope, ProviderError> {
    Ok(Envelope {
        protocol: "CNP/1".to_owned(),
        message: MessageKind::Request,
        session_id: Nullable(Some(authority.session_id().clone())),
        incarnation_id: Nullable(Some(authority.incarnation_id().clone())),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(Id::new("original-observe")?)),
        operation_id: Nullable(None),
        sequence: U64::new(2),
        method,
        body: Map::new(),
        extensions: Extensions::new(),
    })
}

fn fixture() -> Result<(Handshake, Connection<Memory>, Envelope), Box<dyn std::error::Error>> {
    fixture_with_capture(false, None)
}

fn fixture_with_capture(
    append_capture: bool,
    identity_suffix: Option<&str>,
) -> Result<(Handshake, Connection<Memory>, Envelope), Box<dyn std::error::Error>> {
    let (handshake, authority, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope_with_identity_suffix(identity_suffix);
    let policy = crate::reference_packet::service::prepared_blob_proof_codec_for_test(
        selection,
        coordinator,
    )?;
    let mut request = envelope(&authority, Method::Observe)?;
    request.body = object(&ObserveRequest {
        binding_hash: canonical::hash("cnp.owner-binding.v1", b"fixture binding data")?,
        owner_generation: U64::new(1),
        after_observation_sequence: U64::new(0),
        maximum_items: U64::new(16),
        extensions: Extensions::new(),
    })?;
    let bytes = canonical::canonical_json(&serde_json::to_value(&request)?)?;
    let mut input = Vec::new();
    input.extend_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
    input.extend_from_slice(&bytes);
    if append_capture {
        let capture = capture_original(&request)?;
        let bytes = canonical::canonical_json(&serde_json::to_value(capture)?)?;
        input.extend_from_slice(&u32::try_from(bytes.len())?.to_be_bytes());
        input.extend_from_slice(&bytes);
    }
    let mut connection = Connection::new(
        Memory {
            input: Cursor::new(input),
            ..Memory::default()
        },
        authority,
        Rc::new(Supervisor(RefCell::new(Vec::new()))),
        Rc::new(Uninstalled),
        EndpointRole::Provider,
    )?;
    let mut bank = Some(
        crate::transport::original_frames::OriginalFrameReservation::reserve(1024 * 1024, 64)?,
    );
    connection.install_native5_native_codec(&mut bank, policy)?;
    let received = connection.receive()?.ok_or("fixture original absent")?;
    assert_eq!(received.envelope, request);
    Ok((handshake, connection, request))
}

fn capture_original(observe: &Envelope) -> Result<Envelope, ProviderError> {
    let mut original = observe.clone();
    original.method = Method::Begin;
    original.sequence = U64::new(3);
    original.node_id = Nullable(Some(Id::new("actual-data-node")?));
    original.capture_owner_id = Nullable(Some(Id::new("actual-data-capture-owner")?));
    original.operation_id = Nullable(Some(Id::new("actual-data-operation")?));
    original.request_id = Nullable(Some(Id::new("actual-data-capture-request")?));
    original.body = object(&BeginRequest {
        kind: BeginKind::Capture,
        binding_hash: canonical::hash("cnp.owner-binding.v1", b"fixture binding data")?,
        owner_generation: U64::new(1),
        activation_id: Nullable(Some(Id::new("actual-data-activation")?)),
        world_generation: U64::new(1),
        arguments: object(&CaptureArguments {
            capture_id: Id::new("actual-data-capture")?,
            participant_ids: vec![Id::new("actual-data-node")?],
            cut_id: Id::new("actual-data-cut")?,
            cut: Position::new(Tick::new(6), U64::new(1), Phase::Publication),
            event_ordinal: U64::new(1),
            ordering_profile: "superdense-v1".to_owned(),
            preservation_contract: Id::new("source-owned.packet-complete-original-lineage/5")?,
        })?,
        extensions: Extensions::new(),
    })?;
    Ok(original)
}

fn receive_capture(
    connection: &mut Connection<Memory>,
    observe: &Envelope,
) -> Result<Envelope, Box<dyn std::error::Error>> {
    let mut response = observe.clone();
    response.message = MessageKind::Response;
    response.body = object(&serde_json::json!({
        "status":"completed", "operation_state":"completed", "extensions":{},
        "result": ObserveResult {
            observations: Vec::new(), next_sequence: U64::new(0), complete: true,
            inventory_hash: canonical::hash("cnp.packet-inventory.v5", b"fixture inventory")?,
        },
    }))?;
    connection.send(response)?;
    let received = connection.receive()?.ok_or("actual Capture absent")?;
    assert_eq!(received.envelope, capture_original(observe)?);
    assert!(
        matches!(&received.body, ReceivedBody::Request(body) if matches!(body.as_ref(), RequestBody::Begin(_)))
    );
    Ok(received.envelope)
}

fn capture_source(original_observe: &Envelope) -> Result<CaptureSource, ProviderError> {
    let snapshot = vec![7; 5000];
    let anchor = b"independent unchanged anchor".to_vec();
    let control = vec![9; 4097];
    let snapshot_ref = canonical::content_ref(&snapshot, "application/json")?;
    let anchor_ref = canonical::content_ref(&anchor, "application/json")?;
    let control_ref = canonical::content_ref(&control, "application/json")?;
    let mut response = original_observe.clone();
    response.message = MessageKind::Response;
    response.method = Method::Begin;
    response.node_id = Nullable(Some(Id::new("actual-data-node")?));
    response.capture_owner_id = Nullable(Some(Id::new("actual-data-capture-owner")?));
    response.operation_id = Nullable(Some(Id::new("actual-data-operation")?));
    response.request_id = Nullable(Some(Id::new("actual-data-capture-request")?));
    response.body = object(&serde_json::json!({
        "status":"completed", "operation_state":"completed", "extensions":{},
        "result": CaptureResult {
            capture_manifest: snapshot_ref.clone(),
            owner_state_refs: vec![control_ref.clone()],
            unchanged_cut_receipt: anchor_ref.clone(),
        },
    }))?;
    Ok(CaptureSource {
        response,
        snapshot: (snapshot_ref, snapshot),
        anchor: (anchor_ref, anchor),
        control: Some((control_ref, control)),
    })
}

fn source_for_capture(original: &Envelope) -> Result<CaptureSource, ProviderError> {
    let mut source = capture_source(original)?;
    source.response.sequence = original.sequence;
    source.response.node_id = original.node_id.clone();
    source.response.execution_owner_id = original.execution_owner_id.clone();
    source.response.capture_owner_id = original.capture_owner_id.clone();
    source.response.operation_id = original.operation_id.clone();
    source.response.request_id = original.request_id.clone();
    Ok(source)
}

fn terminal_bound(response: &Envelope) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut terminal = response.clone();
    terminal.sequence = U64::new(u64::MAX);
    // The actual raw Envelope has no custom Bytes serializer. Native future
    // production uses the independent field projection rather than this clone.
    actual_serialization_storage_data(&terminal, Default::default(), MAXIMUM)
}

fn capture_quote<S: ProviderStream>(
    connection: &Connection<S>,
    original_observe: &Envelope,
    source: &CaptureSource,
    maximum: usize,
) -> Result<OriginalContinuationPrefixStorageData, ProviderError> {
    capture_quote_for_original(
        connection,
        original_observe,
        source,
        original_observe,
        maximum,
    )
}

fn capture_quote_for_original<S: ProviderStream>(
    connection: &Connection<S>,
    original_observe: &Envelope,
    source: &CaptureSource,
    future_capture: &Envelope,
    maximum: usize,
) -> Result<OriginalContinuationPrefixStorageData, ProviderError> {
    let control = source
        .control
        .as_ref()
        .ok_or(ProviderError::Conflict("test control absent"))?;
    let terminal = terminal_bound(&source.response)?;
    connection.quote_original_continuation_prefix_storage_data(
        2,
        original_observe,
        OriginalContinuationPrefixStorageInput {
            kind: OriginalContinuationPrefixKind::Capture,
            terminal: &terminal,
            original: &terminal_bound(future_capture)?,
            objects: &[
                OriginalContinuationContentExtent {
                    maximum_payload_bytes: source.snapshot.1.len(),
                    media_type: &source.snapshot.0.media_type,
                },
                OriginalContinuationContentExtent {
                    maximum_payload_bytes: source.anchor.1.len(),
                    media_type: &source.anchor.0.media_type,
                },
                OriginalContinuationContentExtent {
                    maximum_payload_bytes: control.1.len(),
                    media_type: &control.0.media_type,
                },
            ],
            maximum_requested_bytes: maximum,
        },
    )
}

#[test]
fn actual_complete_capture_plan_fits_projected_windows_children_and_wire() -> TestResult {
    let (_handshake, mut connection, original) = fixture()?;
    let source = capture_source(&original)?;
    let quote = capture_quote(&connection, &original, &source, MAXIMUM)?;
    let authority = connection.provider_authority()?;
    let plan = frames::plan(authority, &source)?;
    let originals = plan.windows.iter().map(Vec::len).sum::<usize>();
    let requests = plan
        .windows
        .iter()
        .flatten()
        .filter(|frame| frame.message == MessageKind::Request)
        .count();
    assert_eq!(originals, quote.exchange.frames);
    assert_eq!(requests, quote.exchange.requests);
    assert_eq!(plan.windows.len(), quote.windows);
    assert!(plan.windows.len() > 1);
    assert!(plan.charged_bytes <= quote.exchange.new_transport_credit_bytes);
    assert_eq!(quote.exchange.incoming_framed_bytes, requests * (65536 + 4));
    assert!(plan.windows.iter().all(|window| {
        window
            .iter()
            .filter(|frame| frame.message == MessageKind::Request)
            .count()
            <= quote.simultaneous_requests
    }));
    assert_eq!(
        plan.windows.back().ok_or("terminal window absent")?.len(),
        1
    );

    let mut observer = MetadataObserver::new();
    observer.observe(&source.response)?;
    for (reference, bytes) in [&source.snapshot, &source.anchor]
        .into_iter()
        .chain(source.control.iter())
    {
        observer.observe(reference)?;
        observer.observe(bytes)?;
    }
    observer.vector::<Vec<Envelope>>(plan.windows.capacity())?;
    for window in &plan.windows {
        observer.observe(window)?;
    }
    observer.observe(&plan.contents)?;
    quote.reconcile_owner_metadata_data(&observer.finish())?;
    Ok(())
}

#[test]
fn future_complete_prefix_exact_heap_limit_and_one_short_are_independent_data_checks() -> TestResult
{
    let (_handshake, connection, original) = fixture()?;
    let source = capture_source(&original)?;
    let quote = capture_quote(&connection, &original, &source, MAXIMUM)?;
    let exact = quote.requested_bytes()?;
    assert_eq!(
        capture_quote(&connection, &original, &source, exact)?.requested_bytes()?,
        exact
    );
    assert!(capture_quote(&connection, &original, &source, exact - 1).is_err());
    // Raw ACK and flat/window storage are separate, neither is inferred from
    // original encoded payload or counted as a fresh existing bank allocation.
    assert!(quote.flat_plan_requested_bytes > 0);
    assert!(quote.windows_requested_bytes > 0);
    assert!(quote.exchange.one_open_ack_requested_bytes > 65536);
    assert!(quote.source_owner_requested_bytes > quote.exchange.evidence_payload_bytes);
    Ok(())
}

#[test]
fn changed_terminal_refuses_before_frames_and_retains_same_supplied_source() -> TestResult {
    let (_handshake, mut connection, observe) = fixture_with_capture(true, None)?;
    let future = capture_original(&observe)?;
    let mut source = source_for_capture(&future)?;
    let quote = capture_quote_for_original(&connection, &observe, &source, &future, MAXIMUM)?;
    let actual = receive_capture(&mut connection, &observe)?;
    assert_eq!(actual, future);
    let control = source.control.as_ref().ok_or("control absent")?;
    quote.authenticate_actual_inputs(
        &connection,
        &source.response,
        &[
            (&source.snapshot.0, &source.snapshot.1),
            (&source.anchor.0, &source.anchor.1),
            (&control.0, &control.1),
        ],
    )?;
    quote.authenticate_terminal_storage_data(&source.response)?;
    source.response.body.insert(
        "unadmitted_changed_reply".to_owned(),
        Value::String("x".repeat(40000)),
    );
    assert!(
        quote
            .authenticate_terminal_storage_data(&source.response)
            .is_err()
    );
    let CaptureSource {
        response,
        snapshot,
        anchor,
        control,
    } = source;
    let mut prefix = PacketCapturePrefix::new(connection);
    assert!(
        prefix
            .prepare_complete_with_storage_data(
                response,
                snapshot,
                anchor,
                control.ok_or("control absent")?,
                &quote
            )
            .is_err()
    );
    assert!(prefix.windows.is_empty());
    assert!(prefix.records.is_empty());
    assert!(prefix.incomplete_window().is_none());
    assert!(
        prefix
            .source
            .as_ref()
            .ok_or("moved source lost")?
            .response
            .body
            .contains_key("unadmitted_changed_reply")
    );
    assert!(matches!(
        prefix.transport,
        Some(CaptureTransport::Connected(_))
    ));
    Ok(())
}

#[test]
fn future_prefix_rejects_wrong_current_original_shape_and_frame_population() -> TestResult {
    let (_handshake, connection, original) = fixture()?;
    let source = capture_source(&original)?;
    let mut changed = original.clone();
    changed.request_id = Nullable(Some(Id::new("different-current-original")?));
    assert!(capture_quote(&connection, &changed, &source, MAXIMUM).is_err());
    let terminal = terminal_bound(&source.response)?;
    let objects = [
        OriginalContinuationContentExtent {
            maximum_payload_bytes: 8 * 1024 * 1024 + 1,
            media_type: "application/json",
        },
        OriginalContinuationContentExtent {
            maximum_payload_bytes: 1,
            media_type: "application/json",
        },
        OriginalContinuationContentExtent {
            maximum_payload_bytes: 1,
            media_type: "application/json",
        },
    ];
    assert!(
        connection
            .quote_original_continuation_prefix_storage_data(
                2,
                &original,
                OriginalContinuationPrefixStorageInput {
                    kind: OriginalContinuationPrefixKind::Capture,
                    terminal: &terminal,
                    original: &terminal_bound(&original)?,
                    objects: &objects,
                    maximum_requested_bytes: MAXIMUM
                }
            )
            .is_err()
    );
    let too_many = [OriginalContinuationContentExtent {
        maximum_payload_bytes: 4096 * 4096,
        media_type: "application/json",
    }];
    assert!(
        connection
            .quote_original_continuation_prefix_storage_data(
                2,
                &original,
                OriginalContinuationPrefixStorageInput {
                    kind: OriginalContinuationPrefixKind::AfterConfirmation,
                    terminal: &terminal,
                    original: &terminal_bound(&original)?,
                    objects: &too_many,
                    maximum_requested_bytes: MAXIMUM
                }
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn prospective_authority_clone_counts_only_independently_cloned_children() -> TestResult {
    let (_handshake, mut connection, _original) = fixture()?;
    let authority = connection.provider_authority()?;
    let mut full = MetadataObserver::new();
    authority.observe_retained_metadata(&mut full)?;
    let full = full.finish();
    let mut clone = MetadataObserver::new();
    authority.observe_prospective_clone_metadata(&mut clone)?;
    let clone = clone.finish();
    assert!(clone.string_capacity_bytes <= full.string_capacity_bytes);
    assert!(clone.string_capacity_bytes > 0);
    assert_eq!(clone.tree_entries, full.tree_entries);
    assert_eq!(clone.shared_backing_views, 0);
    assert!(full.shared_backing_views >= 2);
    Ok(())
}

#[test]
fn actual_confirmation_plan_fits_full_scoped_proof_and_receipt_projection() -> TestResult {
    use crate::reference_packet::service::confirmation::{
        PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION, PacketNativeAfterConfirmationReceipt,
        PacketNativeAfterConfirmationRequest,
    };
    let (_handshake, mut connection, original) = fixture()?;
    let source = capture_source(&original)?;
    let control = source.control.as_ref().ok_or("control absent")?;
    let after = vec![13; 8193];
    let reference = canonical::content_ref(&after, "application/json")?;
    let receipt = PacketNativeAfterConfirmationReceipt {
        schema: "source-owned.packet-native-after-confirmation-receipt/5".to_owned(),
        capture: PacketNativeAfterConfirmationRequest {
            schema: "source-owned.packet-native-after-confirmation-request/5".to_owned(),
            capture_request_id: Id::new("capture-original")?,
            capture_operation_id: Id::new("capture-operation")?,
            capture_request_hash: canonical::hash(
                "cnp.request.v1",
                b"actual fixture capture data",
            )?,
            capture_terminal_hash: canonical::hash(
                "source-owned.packet-native-capture-terminal/5",
                b"actual fixture terminal data",
            )?,
            capture_terminal_sequence: U64::new(12),
            native_snapshot_ref: source.snapshot.0.clone(),
            native_control_ref: control.0.clone(),
            native_anchor_ref: source.anchor.0.clone(),
        },
        native_after_ref: reference.clone(),
        native_after_capacity: U64::new(after.len() as u64),
    };
    receipt.validate_data()?;
    let capture_outcome = source.response.body.clone();
    let mut response = source.response;
    response.method = Method::Poll;
    response.body = object(&serde_json::json!({
        "status":"completed", "operation_state":"completed", "extensions":{},
        "result":PollResult {
            operation_id:Id::new("capture-operation")?,
            operation_state:OperationState::Completed,
            outcome:Nullable(Some(capture_outcome)), observations:Vec::new(),
            next_observation_sequence:U64::new(0),
        },
    }))?;
    response.extensions.insert(
        PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION.to_owned(),
        serde_json::to_value(&receipt)?,
    );
    let terminal = terminal_bound(&response)?;
    let quote = connection.quote_original_continuation_prefix_storage_data(
        2,
        &original,
        OriginalContinuationPrefixStorageInput {
            kind: OriginalContinuationPrefixKind::AfterConfirmation,
            terminal: &terminal,
            original: &terminal_bound(&original)?,
            objects: &[OriginalContinuationContentExtent {
                maximum_payload_bytes: after.len(),
                media_type: &reference.media_type,
            }],
            maximum_requested_bytes: MAXIMUM,
        },
    )?;
    let authority = connection.provider_authority()?;
    let plan = confirmation_frames::confirmation_plan(
        authority,
        &response,
        &receipt,
        (&reference, &after),
        after.len(),
    )?;
    assert_eq!(
        plan.windows.iter().map(Vec::len).sum::<usize>(),
        quote.exchange.frames
    );
    assert_eq!(plan.windows.len(), quote.windows);
    assert!(plan.charged_bytes <= quote.exchange.new_transport_credit_bytes);
    assert!(quote.authority_clone_requested_bytes > 0);
    assert!(
        plan.windows
            .iter()
            .flatten()
            .filter(|frame| frame.message == MessageKind::Request)
            .all(|frame| frame.capture_owner_id == response.capture_owner_id
                && frame.operation_id == response.operation_id
                && frame.node_id == response.node_id)
    );
    assert_eq!(plan.windows.back().ok_or("terminal absent")?.len(), 1);
    Ok(())
}

#[test]
fn wrong_planner_data_retains_original_moved_capture_bodies_before_refusal() -> TestResult {
    let (_handshake, connection, original) = fixture()?;
    let source = capture_source(&original)?;
    let terminal = terminal_bound(&source.response)?;
    // Deliberately inconsistent phase data cannot authorize the Capture owner.
    let quote = connection.quote_original_continuation_prefix_storage_data(
        2,
        &original,
        OriginalContinuationPrefixStorageInput {
            kind: OriginalContinuationPrefixKind::AfterConfirmation,
            terminal: &terminal,
            original: &terminal_bound(&original)?,
            objects: &[OriginalContinuationContentExtent {
                maximum_payload_bytes: source.snapshot.1.len(),
                media_type: &source.snapshot.0.media_type,
            }],
            maximum_requested_bytes: MAXIMUM,
        },
    )?;
    let CaptureSource {
        response,
        snapshot,
        anchor,
        control,
    } = source;
    let mut prefix = PacketCapturePrefix::new(connection);
    assert!(
        prefix
            .prepare_complete_with_storage_data(
                response,
                snapshot,
                anchor,
                control.ok_or("control absent")?,
                &quote
            )
            .is_err()
    );
    let retained = prefix.source.as_ref().ok_or("original source discarded")?;
    assert_eq!(retained.snapshot.1.len(), 5000);
    assert_eq!(
        retained
            .control
            .as_ref()
            .ok_or("original control discarded")?
            .1
            .len(),
        4097
    );
    assert!(prefix.windows.is_empty());
    assert!(matches!(
        prefix.transport,
        Some(CaptureTransport::Connected(_))
    ));
    Ok(())
}

#[test]
fn actual_current_capture_prepares_and_reconciles_the_same_quoted_source() -> TestResult {
    let (_handshake, mut connection, observe) = fixture_with_capture(true, None)?;
    let future = capture_original(&observe)?;
    let source = source_for_capture(&future)?;
    let quote = capture_quote_for_original(&connection, &observe, &source, &future, MAXIMUM)?;
    receive_capture(&mut connection, &observe)?;
    let CaptureSource {
        response,
        snapshot,
        anchor,
        control,
    } = source;
    let mut prefix = PacketCapturePrefix::new(connection);
    prefix.prepare_complete_with_storage_data(
        response,
        snapshot,
        anchor,
        control.ok_or("control absent")?,
        &quote,
    )?;
    assert!(prefix.state == PrefixState::Prepared);
    assert!(prefix.incomplete_window().is_some());
    prefix.reconcile_storage_data(&quote)?;
    Ok(())
}

#[test]
fn actual_current_capture_refuses_spare_source_capacity_before_any_frame() -> TestResult {
    let (_handshake, mut connection, observe) = fixture_with_capture(true, None)?;
    let future = capture_original(&observe)?;
    let mut source = source_for_capture(&future)?;
    let quote = capture_quote_for_original(&connection, &observe, &source, &future, MAXIMUM)?;
    receive_capture(&mut connection, &observe)?;
    let mut observer = MetadataObserver::new();
    source.observe_storage_data(&mut observer)?;
    quote.authenticate_source_owner_storage_data(&observer.finish())?;
    let control = source.control.as_ref().ok_or("control absent")?;
    quote.authenticate_actual_inputs(
        &connection,
        &source.response,
        &[
            (&source.snapshot.0, &source.snapshot.1),
            (&source.anchor.0, &source.anchor.1),
            (&control.0, &control.1),
        ],
    )?;

    source
        .snapshot
        .1
        .try_reserve_exact(quote.source_owner_requested_bytes)?;
    let actual_capacity = source.snapshot.1.capacity();
    let mut observer = MetadataObserver::new();
    source.observe_storage_data(&mut observer)?;
    assert!(
        quote
            .authenticate_source_owner_storage_data(&observer.finish())
            .is_err()
    );
    let CaptureSource {
        response,
        snapshot,
        anchor,
        control,
    } = source;
    let mut prefix = PacketCapturePrefix::new(connection);
    assert!(matches!(
        prefix.prepare_complete_with_storage_data(
            response,
            snapshot,
            anchor,
            control.ok_or("control absent")?,
            &quote
        ),
        Err(ProviderError::ResourceExhausted(_))
    ));
    assert!(prefix.windows.is_empty());
    assert!(prefix.records.is_empty());
    assert!(prefix.incomplete_window().is_none());
    assert_eq!(
        prefix
            .source
            .as_ref()
            .ok_or("moved source lost")?
            .snapshot
            .1
            .capacity(),
        actual_capacity
    );
    Ok(())
}

#[test]
fn current_authority_reprojection_refuses_a_foreign_short_header_quote() -> TestResult {
    let (_short_handshake, short, short_observe) = fixture_with_capture(false, None)?;
    let short_capture = capture_original(&short_observe)?;
    let source = source_for_capture(&short_capture)?;
    let short_quote =
        capture_quote_for_original(&short, &short_observe, &source, &short_capture, MAXIMUM)?;
    let (_long_handshake, long, long_observe) =
        fixture_with_capture(false, Some("independently-admitted-long-identities"))?;
    let long_capture = capture_original(&long_observe)?;
    let source = source_for_capture(&long_capture)?;
    let long_quote =
        capture_quote_for_original(&long, &long_observe, &source, &long_capture, MAXIMUM)?;
    short_quote.authenticate_current_shape_data(&short)?;
    long_quote.authenticate_current_shape_data(&long)?;
    assert!(long_quote.exchange.outgoing_framed_bytes > short_quote.exchange.outgoing_framed_bytes);
    assert!(short_quote.authenticate_current_shape_data(&long).is_err());
    Ok(())
}
