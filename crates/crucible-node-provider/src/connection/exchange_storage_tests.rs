//! Checks actual closed plans and independent prefix-storage refusal boundaries.

use super::*;
use crate::{bodies::*, envelope::Nullable, handshake::Handshake};
use crucible_node_contract::{Bytes, Extensions};
use std::{cell::RefCell, io::Cursor};

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
    match serde_json::to_value(value).map_err(crucible_node_contract::ContractError::from)? {
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
    let (handshake, authority, selection, coordinator) =
        crate::reference_packet::coordinator::original_canonical_ack_controller_scope();
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

#[test]
fn actual_response_and_chunk_encodings_fit_the_closed_prebuild_projection() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let body = serde_json::json!({"status": "completed", "result": {"escaped": "\n\u{0}\"\\"}})
        .as_object()
        .ok_or("fixture object")?
        .clone();
    let projection = frame_projection(
        &connection.authority,
        Some(&request),
        2,
        Method::Observe,
        Body::Response(&body),
        MAXIMUM,
    )?;
    let mut actual = request.clone();
    actual.message = MessageKind::Response;
    actual.body = body;
    let encoded = canonical::canonical_json(&serde_json::to_value(&actual)?)?;
    assert!(encoded.len() <= projection.maximum_encoded_bytes);

    let bytes = vec![0xff; 4096];
    let encoded_bytes = 4 * bytes.len().div_ceil(3);
    let transfer = Id::new("packet-transfer-3")?;
    let projection = frame_projection(
        &connection.authority,
        None,
        4,
        Method::BlobChunk,
        Body::Chunk(transfer.as_str().len(), 4096, encoded_bytes),
        MAXIMUM,
    )?;
    actual.message = MessageKind::Request;
    actual.sequence = U64::new(4);
    actual.request_id = Nullable(Some(Id::new("packet-proof-4")?));
    actual.method = Method::BlobChunk;
    actual.body = object(&BlobChunkRequest {
        transfer_id: transfer,
        offset: U64::new(4096),
        bytes: Bytes::new(bytes),
        extensions: Extensions::new(),
    })?;
    let encoded = canonical::canonical_json(&serde_json::to_value(&actual)?)?;
    assert!(encoded.len() <= projection.maximum_encoded_bytes);
    assert!(projection.maximum_encoded_bytes < 8192);
    Ok(())
}

#[test]
fn same_current_prefix_exact_heap_limit_and_one_short_are_data_checks() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let body = Map::new();
    let bytes = b"actual original proof".to_vec();
    let evidence = vec![(canonical::content_ref(&bytes, "application/json")?, bytes)];
    let quote = connection
        .quote_original_packet_prefix_storage_data(2, &request, &body, &evidence, MAXIMUM)?;
    let total = quote.requested_bytes()?;

    assert_eq!(quote.frames, 4);
    assert_eq!(quote.requests, 3);
    assert_eq!(quote.evidence_payload_bytes, evidence[0].1.len());
    assert_eq!(quote.original_slots_required, 7);
    assert_eq!(
        quote.original_literal_required_bytes,
        quote.outgoing_framed_bytes + quote.incoming_framed_bytes
    );
    assert!(quote.one_open_ack_requested_bytes > quote.successful_ack_cache_requested_bytes);
    assert_eq!(
        connection
            .quote_original_packet_prefix_storage_data(2, &request, &body, &evidence, total)?
            .requested_bytes()?,
        total
    );
    assert!(
        connection
            .quote_original_packet_prefix_storage_data(2, &request, &body, &evidence, total - 1)
            .is_err()
    );
    assert!(connection.reader.stream_ref().output.is_empty());
    assert_eq!(connection.guard.incoming_requests().count(), 1);
    Ok(())
}

#[test]
fn quote_refuses_changed_original_wire_nofit_and_old_transport_credit() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let body = Map::new();
    let mut changed = request.clone();
    changed.request_id = Nullable(Some(Id::new("another-observe")?));
    assert!(
        connection
            .quote_original_packet_prefix_storage_data(2, &changed, &body, &[], MAXIMUM)
            .is_err()
    );
    assert!(
        connection
            .quote_original_packet_prefix_storage_data(u64::MAX, &request, &body, &[], MAXIMUM)
            .is_err()
    );

    let quote =
        connection.quote_original_packet_prefix_storage_data(2, &request, &body, &[], MAXIMUM)?;
    assert_eq!(quote.one_open_ack_requested_bytes, 0);
    assert_eq!(quote.requests, 0);
    let limit = crate::reference_packet::endpoint::MAXIMUM_PACKET_TRANSPORT_BYTES;
    quote.preflight_transport_credit_data(limit - quote.new_transport_credit_bytes)?;
    assert!(
        quote
            .preflight_transport_credit_data(limit - quote.new_transport_credit_bytes + 1)
            .is_err()
    );

    let mut large = body;
    large.insert("too_large".into(), Value::String("x".repeat(65_536)));
    assert!(
        connection
            .quote_original_packet_prefix_storage_data(2, &request, &large, &[], MAXIMUM)
            .is_err()
    );
    assert!(connection.reader.stream_ref().output.is_empty());
    Ok(())
}

#[test]
fn one_open_ack_bound_covers_nested_arrays_and_numeric_error_details() -> TestResult {
    let mut details = Value::Null;
    for _ in 0..32 {
        details = Value::Array(vec![details]);
    }
    let value = serde_json::json!({"nested": details, "number": 1.23456789012345e-20, "escaped": "\u{0}\n"});
    let encoded = canonical::canonical_json(&value)?;
    let mut observer = MetadataObserver::new();
    observer.observe(&value)?;
    let actual = actual_serialization_storage_data(&value, observer.finish(), MAXIMUM)?;
    assert!(acknowledgements::open_ack_storage(encoded.len())? >= actual.requested_total()?);
    assert!(acknowledgements::open_ack_storage(usize::MAX).is_err());
    Ok(())
}

#[test]
fn actual_preparation_reconciles_capacities_and_refuses_a_foreign_bank() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let body = object(&ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result: object(&ObserveResult {
            observations: Vec::new(),
            next_sequence: U64::new(0),
            complete: true,
            inventory_hash: canonical::hash("cnp.packet-inventory.v5", b"fixture inventory data")?,
        })?,
        extensions: Extensions::new(),
    })?;
    let quote =
        connection.quote_original_packet_prefix_storage_data(2, &request, &body, &[], MAXIMUM)?;
    let mut response = request.clone();
    response.message = MessageKind::Response;
    response.body = body;
    let mut exchange = connection.unprepared_exchange(vec![response]);

    exchange.reconcile_original_packet_prefix_storage_data(&quote)?;
    exchange.prepare_in_place()?;
    exchange.reconcile_original_packet_prefix_storage_data(&quote)?;
    assert!(exchange.connection.reader.stream_ref().output.is_empty());

    let (_other_handshake, other, _) = fixture()?;
    let foreign = other
        .original_frames
        .as_ref()
        .ok_or("foreign bank absent")?
        .clone();
    let original = exchange
        .record
        .original_actor
        .as_mut()
        .ok_or("actor absent")?;
    original.1 = foreign;
    assert!(
        exchange
            .reconcile_original_packet_prefix_storage_data(&quote)
            .is_err()
    );
    Ok(())
}

#[test]
fn actual_decoded_success_cache_fits_the_closed_ack_owner_bound() -> TestResult {
    let (_handshake, connection, _) = fixture()?;
    let id = Id::new("x".repeat(128))?;
    let mut content = canonical::content_ref(b"original source proof", &"m".repeat(128))?;
    content.length = U64::new(u64::MAX);
    let request = RequestBody::BlobFinish(BlobFinishRequest {
        transfer_id: id.clone(),
        extensions: Extensions::new(),
    });
    let result = BlobFinishResult {
        transfer_id: id.clone(),
        content,
    };
    let body = object(&ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result: object(&result)?,
        extensions: Extensions::new(),
    })?;
    let mut envelope = envelope(&connection.authority, Method::BlobFinish)?;
    envelope.message = MessageKind::Response;
    envelope.body = body;
    envelope.node_id = Nullable(Some(id.clone()));
    envelope.execution_owner_id = Nullable(Some(id.clone()));
    envelope.capture_owner_id = Nullable(Some(id.clone()));
    envelope.operation_id = Nullable(Some(id.clone()));
    envelope.request_id = Nullable(Some(id));
    let bytes = canonical::canonical_json(&serde_json::to_value(&envelope)?)?;
    let envelope = Envelope::decode(&bytes, bytes.len())?;
    let decoded = decode_response(&request, &envelope.body)?;

    let mut observer = MetadataObserver::new();
    observer.observe(&envelope)?;
    observer.boxed_value(&decoded)?;
    let ResponseShape::Completed {
        result, extensions, ..
    } = &decoded.shape
    else {
        return Err("actual completed response absent".into());
    };
    observer.observe(result)?;
    observer.observe(extensions)?;
    let Some(MethodResult::BlobFinish(result)) = &decoded.result else {
        return Err("actual BlobFinish result absent".into());
    };
    observer.observe(&result.transfer_id)?;
    observer.observe(&result.content)?;

    assert!(requested_facts(&observer.finish())? <= acknowledgements::successful_ack_storage()?);
    Ok(())
}

#[test]
fn changed_underquoted_inputs_refuse_before_the_owning_plan_is_constructed() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let original_body = Map::new();
    let original_bytes = b"actual proof".to_vec();
    let evidence = vec![(
        canonical::content_ref(&original_bytes, "application/json")?,
        original_bytes,
    )];
    let quote = connection.quote_original_packet_prefix_storage_data(
        2,
        &request,
        &original_body,
        &evidence,
        MAXIMUM,
    )?;
    connection.authenticate_requoted_original_packet_prefix_storage_data(
        2,
        &request,
        &original_body,
        &evidence,
        &quote,
    )?;

    let mut larger_body = original_body.clone();
    larger_body.insert("changed".to_owned(), Value::String("x".repeat(8192)));
    assert!(
        connection
            .authenticate_requoted_original_packet_prefix_storage_data(
                2,
                &request,
                &larger_body,
                &evidence,
                &quote,
            )
            .is_err()
    );
    let larger_bytes = vec![0; 8192];
    let changed_evidence = vec![(
        canonical::content_ref(&larger_bytes, "application/json")?,
        larger_bytes,
    )];
    assert!(
        connection
            .authenticate_requoted_original_packet_prefix_storage_data(
                2,
                &request,
                &original_body,
                &changed_evidence,
                &quote,
            )
            .is_err()
    );
    assert!(
        connection
            .authenticate_requoted_original_packet_prefix_storage_data(
                3,
                &request,
                &original_body,
                &evidence,
                &quote,
            )
            .is_err()
    );
    assert!(connection.reader.stream_ref().output.is_empty());
    assert_eq!(connection.guard.pending_requests().count(), 0);
    assert_eq!(connection.guard.incoming_requests().count(), 1);
    Ok(())
}

#[path = "exchange_observe_lifetime_tests.rs"]
mod observe_lifetime;

#[path = "exchange_packet_projection_tests.rs"]
mod packet_projection;

#[path = "exchange_native_observe_prepare_tests.rs"]
mod native_observe_preparation;

#[test]
fn selected_input_hash_work_survives_the_actual_complete_request_quote() -> TestResult {
    let (_handshake, connection, request) = fixture()?;
    let body = object(&ResponseShape::Completed {
        operation_state: OperationState::Completed,
        result: Map::new(),
        extensions: Extensions::new(),
    })?;
    let bytes = br#"{"retained":"actual content bank"}"#.to_vec();
    let evidence = vec![(canonical::content_ref(&bytes, "application/json")?, bytes)];
    let legacy = connection
        .quote_original_packet_prefix_storage_data(2, &request, &body, &evidence, MAXIMUM)?;
    // The same complete accounting tail runs after the live Input17 entry
    // authenticates its separate admission/class. This DATA control supplies
    // only its named validation phase, never a fake native permission.
    let quote = |maximum| {
        connection.quote_original_packet_prefix_accounting_data(
            2, &request, &body, &evidence, maximum, true,
        )
    };
    let mut selected = quote(MAXIMUM)?;
    let validation_transient = restored_input17::validation_transient_storage_data();
    let validation_scratch = restored_input17::counter_scratch_data();
    assert!(validation_transient > 0);
    assert!(validation_scratch > 0);
    assert_eq!(
        selected.construction_transient_requested_bytes,
        legacy.construction_transient_requested_bytes + validation_transient
    );
    assert_eq!(
        selected.declared_quote_scratch_bytes,
        legacy.declared_quote_scratch_bytes + validation_scratch
    );
    let exact = selected.requested_bytes()?;
    assert_eq!(
        exact,
        legacy.requested_bytes()? + validation_transient + validation_scratch
    );
    assert_eq!(quote(exact)?.requested_bytes()?, exact);
    assert!(quote(exact - 1).is_err());

    // Every retained owner, literal bank and other independently accounted
    // component stays identical; the added temporary is not hidden in R.
    selected.construction_transient_requested_bytes -= validation_transient;
    selected.declared_quote_scratch_bytes -= validation_scratch;
    assert_eq!(selected, legacy);
    assert!(connection.reader.stream_ref().output.is_empty());
    assert_eq!(connection.guard.incoming_requests().count(), 1);
    Ok(())
}
